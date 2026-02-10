// SPDX-License-Identifier: BUSL-1.1
//! Vouch identity server library.
//!
//! This crate provides the Vouch identity server with OIDC provider,
//! WebAuthn authentication, and credential issuance.

pub mod cleanup;
pub mod config;
pub mod db;
pub mod encrypt_config;
pub mod extractors;
pub mod handlers;
pub mod pem;
pub mod s3_config;
pub mod services;
pub mod ssh_ca;
pub mod tls;
pub mod tpm_decrypt;
pub mod webauthn_verify;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// Re-export main types
pub use config::ServerConfig;
pub use db::User;
pub use webauthn_verify::{CoseVerifier, RealCoseVerifier, VerificationResult, VerifyError};

#[cfg(any(test, feature = "test-utils"))]
pub use webauthn_verify::TestCoseVerifier;

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
pub fn redact_email(email: &str) -> String {
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
    /// Database connection pool.
    pub db: Pool,
    /// Server configuration (wrapped in ArcSwap for lock-free dynamic updates).
    pub config: Arc<ArcSwap<ServerConfig>>,
    /// WebAuthn instance.
    pub webauthn: webauthn_rs::Webauthn,
    /// SSH Certificate Authority (optional, None if disabled).
    pub ssh_ca: Option<ssh_ca::SshCa>,
    /// RFC 9449 DPoP state (nonce manager, JTI cache).
    pub dpop: services::oidc::dpop::DpopState,
    /// OIDC signing key for ES256 JWT signing.
    pub oidc_key: services::oidc::OidcSigningKey,
    /// GitHub App for credential issuance (optional, None if not configured).
    pub github_app: Option<std::sync::Arc<services::integrations::github::GitHubApp>>,
}

impl AppState {
    /// Get current config snapshot (lock-free).
    ///
    /// Returns an `Arc<ServerConfig>` that provides a consistent view of
    /// the configuration at the time of the call. The returned config
    /// remains valid even if the underlying config is updated.
    #[must_use]
    pub fn config(&self) -> arc_swap::Guard<Arc<ServerConfig>> {
        self.config.load()
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
        tracing::warn!(
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
    hostname.eq_ignore_ascii_case(rp_id)
        || hostname.eq_ignore_ascii_case("localhost")
        || hostname == "127.0.0.1"
}

#[cfg(test)]
mod redirect_tests {
    // Tests are allowed to use unwrap/expect for convenience
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::services::oidc::OidcSigningKey;
    use axum::body::Body;
    use axum::http::Request;
    use secrecy::SecretString;
    use tower::ServiceExt;

    fn test_app_state_with_rp_id(rp_id: &str) -> AppState {
        let config = ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            database_url: "sqlite::memory:".to_string(),
            rp_id: rp_id.to_string(),
            rp_name: "Test RP".to_string(),
            jwt_secret: SecretString::from("test_jwt_secret_must_be_at_least_32_characters_long"),
            session_hours: 8,
            oidc_issuer_url: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            base_url: format!("https://{rp_id}"),
            device_code_expires_seconds: 600,
            device_poll_interval_seconds: 5,
            allowed_domains: None,
            org_name: None,
            cli_download_macos: None,
            cli_download_linux: None,
            cli_download_windows: None,
            ssh_ca_key_path: None,
            ssh_ca_key: None,
            oidc_signing_key: None,
            dpop_enabled: true,
            dpop_nonce_required: false,
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
        };
        let webauthn = webauthn_rs::WebauthnBuilder::new(
            rp_id,
            &url::Url::parse(&format!("https://{rp_id}")).unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();

        AppState {
            db: Pool::new_test(),
            config: Arc::new(ArcSwap::from_pointee(config)),
            webauthn,
            ssh_ca: None,
            dpop: crate::services::oidc::dpop::DpopState::new(),
            oidc_key: OidcSigningKey::generate().unwrap(),
            github_app: None,
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
