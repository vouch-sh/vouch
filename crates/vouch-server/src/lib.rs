// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch identity server library.
//!
//! This crate provides the Vouch identity server with OIDC provider,
//! WebAuthn authentication, and credential issuance.

// Prevent test-utils from being enabled in any release build of this
// library. The feature exposes `test_utils` (helpers that bypass FIDO2
// and construct `GrantProof::TestingOnly` / `TestCoseVerifier`) — none
// of which should ever reach production code. Release builds disable
// `debug_assertions`, so this guard fires for `cargo build --release
// --features test-utils` on either the binary or any consumer.
#[cfg(all(feature = "test-utils", not(debug_assertions)))]
compile_error!("test-utils feature must not be enabled in release builds");

pub(crate) mod attestation;
pub mod config;
pub mod crypto;
pub mod db;
pub(crate) mod error;
pub mod filters;
pub(crate) mod geo;
pub(crate) mod handlers;
pub mod infra;
pub mod services;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

use arc_swap::ArcSwap;
use axum::{
    Router,
    extract::State,
    http::{Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use db::Pool;
use std::sync::Arc;

/// Redact an email address for safe logging.
///
/// Preserves the first character of the local part and the full domain
/// (since domain is not PII), but hides the rest of the username.
///
/// # Examples
/// - `"john.doe@example.com"` → `"j***@example.com"`
/// - `"a@example.com"` → `"a***@example.com"`
/// - `"not-an-email"` → `"n***"`
#[must_use]
pub(crate) fn redact_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first_char = local.chars().next().unwrap_or('*');
            format!("{first_char}***@{domain}")
        }
        None => {
            // Not a valid email, redact anyway
            let first_char = email.chars().next().unwrap_or('*');
            format!("{first_char}***")
        }
    }
}

/// Shared application state.
pub struct AppState {
    /// Database connection pool (kept for migrations).
    pub db: Pool,
    /// Encrypted document store for domain data.
    pub store: db::store::DocumentStore,
    /// Audit event store.
    pub audit: db::audit::AuditStore,
    /// Server configuration (wrapped in ArcSwap for lock-free dynamic updates).
    pub config: Arc<ArcSwap<config::ServerConfig>>,
    /// WebAuthn instance.
    pub webauthn: webauthn_rs::Webauthn,
    /// SSH Certificate Authority (optional, None if disabled).
    pub(crate) ssh_ca: Option<crypto::ssh_ca::SshCa>,
    /// ES256 OIDC signing key (always present, used for access tokens).
    pub(crate) oidc_key: crypto::keys::OidcSigningKey,
    /// OIDC RSA signing key for RS256 ID token signing (optional).
    pub(crate) oidc_rsa_key: Option<crypto::keys::OidcRsaSigningKey>,
    /// State token signer (Local HS256 or KMS HMAC-SHA256).
    pub(crate) state_signer: crypto::jwt::StateTokenSigner,
    /// GitHub App for credential issuance (optional, None if not configured).
    pub github_app: Option<std::sync::Arc<services::integrations::github::GitHubApp>>,
    /// Shared HTTP client for outbound server-side API calls (no redirects).
    pub http_client: reqwest::Client,
    /// Session lookup cache (30s TTL).
    pub session_cache: db::SessionCache,
    /// Per-org issuer signing key cache (60s TTL).
    pub org_keys_cache: services::oidc::OrgKeysCache,
    /// Configured upstream identity providers (OIDC and/or SAML), in the order
    /// operators listed them in `VOUCH_IDPS` (or the S3 `idps` array). Order
    /// controls login page button order; `id` is the lookup key at callback time.
    pub idps: Vec<services::idp::ConfiguredIdp>,
}

impl AppState {
    /// Get current config snapshot (lock-free).
    ///
    /// Returns an `Arc<ServerConfig>` that provides a consistent view of
    /// the configuration at the time of the call. The returned config
    /// remains valid even if the underlying config is updated.
    #[must_use]
    pub fn config(&self) -> arc_swap::Guard<Arc<config::ServerConfig>> {
        self.config.load()
    }

    /// Look up an IdP by slug. Returns `None` if not configured.
    #[must_use]
    pub fn idp(&self, id: &str) -> Option<&services::idp::ConfiguredIdp> {
        self.idps.iter().find(|i| i.id() == id)
    }
}

/// Build the HTTP->HTTPS redirect router.
///
/// Security features:
/// - Validates Host header against `rp_id` to prevent injection attacks
/// - Uses 308 Permanent Redirect to preserve HTTP method
/// - Allows `/health` endpoint for load balancer health checks
pub fn build_redirect_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .fallback(redirect_to_https)
        .with_state(state)
}

async fn redirect_to_https(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
) -> Response {
    let config = state.config.load();
    let uri = request.uri().clone();

    // Extract Host header
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // Extract hostname without port
    let hostname = host.rsplit_once(':').map_or(host, |(h, _)| h);

    // Validate Host header against configured rp_id
    // This prevents Host header injection attacks
    if !is_valid_host(hostname, &config.rp_id) {
        tracing::debug!(
            target: "security",
            host = %hostname,
            expected = %config.rp_id,
            "Rejected HTTP redirect with invalid Host header"
        );
        return (StatusCode::MISDIRECTED_REQUEST, "Invalid Host header").into_response();
    }

    // Build HTTPS redirect URL using validated rp_id (not untrusted Host)
    let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
    let https_uri = format!("https://{}{}", config.rp_id, path);

    tracing::debug!(from_host = %hostname, to = %https_uri, "HTTP to HTTPS redirect");

    // Return 308 Permanent Redirect (preserves HTTP method, unlike 301)
    (
        StatusCode::PERMANENT_REDIRECT,
        [(header::LOCATION, https_uri)],
    )
        .into_response()
}

/// Check if the provided hostname is valid for this server.
fn is_valid_host(hostname: &str, rp_id: &str) -> bool {
    hostname.eq_ignore_ascii_case(rp_id) || vouch_common::is_loopback_host(hostname)
}

#[cfg(test)]
mod redirect_tests {
    // Tests are allowed to use unwrap/expect for convenience
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panic on assertion failure is acceptable"
    )]

    use super::*;
    use crate::crypto::keys::OidcSigningKey;
    use axum::body::Body;
    use axum::http::Request;
    use secrecy::SecretString;
    use tower::ServiceExt;

    fn test_app_state_with_rp_id(rp_id: &str) -> AppState {
        let config = config::ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            database_url: "sqlite::memory:".to_string(),
            rp_id: rp_id.to_string(),
            rp_name: "Test RP".to_string(),
            jwt_secret: SecretString::from("test_jwt_secret_must_be_at_least_32_characters_long"),
            session_hours: 8,
            idps: Vec::new(),
            base_url: format!("https://{rp_id}"),
            device_code_expires_seconds: 600,
            device_poll_interval_seconds: 5,
            allowed_domains: None,
            org_name: None,
            resource_name: None,
            resource_documentation: None,
            resource_policy_uri: None,
            resource_tos_uri: None,
            cli_download_macos: None,
            cli_download_linux: None,
            cli_download_windows: None,
            ssh_ca_key_path: None,
            ssh_ca_key: None,
            ssh_ca_kms_key_id: None,
            oidc_signing_key: None,
            oidc_signing_kms_key_id: None,
            oidc_rsa_signing_key: None,
            oidc_rsa_signing_kms_key_id: None,
            jwt_hmac_kms_key_id: None,
            kms_account_id: None,
            mtls_port: 8443,
            dpop_max_age_seconds: 300,
            cleanup_interval_minutes: 0,
            auth_events_retention_days: 90,
            oauth_events_retention_days: 30,
            cors_origins: None,
            github_app_id: None,
            github_app_name: None,
            github_app_key: None,
            github_webhook_secret: None,
            github_app_client_id: None,
            github_app_client_secret: None,
            tls_cert: None,
            tls_key: None,
            s3_config_bucket: None,
            s3_config_key: "config/vouch-server.json".to_string(),
            s3_config_region: None,
            s3_config_poll_interval: 60,
            aws_region: None,
            aws_az: None,
            aws_partition: None,
            aws_use_fips_endpoint: None,
            jwt_assertion_max_lifetime_seconds: 300,
            allowed_aaguids: vouch_common::AaguidPolicy::Any,
            require_attestation_cert: false,
            log_format: config::LogFormat::Text,
            trusted_proxies: Vec::new(),
            metrics_bearer_token: None,
            certification_test_token: None,
            extra_ca_certs: None,
            pool_config: crate::db::pool::PoolConfig::default(),
            session_cache_max_capacity: 10_000,
            session_cache_ttl_secs: 30,
        };
        let webauthn = webauthn_rs::WebauthnBuilder::new(
            rp_id,
            &url::Url::parse(&format!("https://{rp_id}")).unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();

        let pool = Pool::new_test();
        let crypto: std::sync::Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            std::sync::Arc::new(crate::crypto::document_crypto::PlaintextDocumentCrypto);
        let store = db::store::DocumentStore::new(pool.clone(), crypto.clone());
        let audit = db::audit::AuditStore::new(pool.clone(), crypto);

        AppState {
            db: pool,
            store,
            audit,
            config: Arc::new(ArcSwap::from_pointee(config)),
            webauthn,
            ssh_ca: None,
            oidc_key: OidcSigningKey::generate().unwrap(),
            oidc_rsa_key: None,
            state_signer: crypto::jwt::StateTokenSigner::local(
                b"test_jwt_secret_must_be_at_least_32_characters_long".to_vec(),
            ),
            github_app: None,
            http_client: reqwest::Client::new(),
            session_cache: db::SessionCache::new(10_000, 30),
            org_keys_cache: Default::default(),
            idps: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_redirect_valid_host() {
        let state = Arc::new(test_app_state_with_rp_id("vouch.sh"));
        let app = build_redirect_router(state);

        let req = Request::builder()
            .uri("/path?query=1")
            .header("host", "vouch.sh")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "https://vouch.sh/path?query=1"
        );
    }

    #[tokio::test]
    async fn test_redirect_rejects_invalid_host() {
        let state = Arc::new(test_app_state_with_rp_id("vouch.sh"));
        let app = build_redirect_router(state);

        let req = Request::builder()
            .uri("/login")
            .header("host", "attacker.com")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
    }

    #[tokio::test]
    async fn test_health_allowed_on_http() {
        let state = Arc::new(test_app_state_with_rp_id("vouch.sh"));
        let app = build_redirect_router(state);

        let req = Request::builder()
            .uri("/health")
            .header("host", "vouch.sh")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_redirect_localhost_allowed() {
        let state = Arc::new(test_app_state_with_rp_id("vouch.sh"));
        let app = build_redirect_router(state);

        let req = Request::builder()
            .uri("/login")
            .header("host", "localhost")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
        // Note: redirect still uses rp_id, not localhost
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "https://vouch.sh/login"
        );
    }

    #[tokio::test]
    async fn test_redirect_127_0_0_1_allowed() {
        let state = Arc::new(test_app_state_with_rp_id("vouch.sh"));
        let app = build_redirect_router(state);

        let req = Request::builder()
            .uri("/login")
            .header("host", "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    }
}

#[cfg(test)]
mod redact_tests {
    use super::*;

    #[test]
    fn test_redact_standard_email() {
        assert_eq!(redact_email("john.doe@example.com"), "j***@example.com");
    }

    #[test]
    fn test_redact_single_char_local() {
        assert_eq!(redact_email("a@example.com"), "a***@example.com");
    }

    #[test]
    fn test_redact_preserves_domain() {
        assert_eq!(redact_email("user@acme.corp.co"), "u***@acme.corp.co");
    }

    #[test]
    fn test_redact_no_at_sign() {
        assert_eq!(redact_email("notanemail"), "n***");
    }

    #[test]
    fn test_redact_empty_string() {
        assert_eq!(redact_email(""), "****");
    }
}
