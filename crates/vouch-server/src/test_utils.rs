// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Test utilities for RFC compliance testing.
//!
//! This module provides shared test infrastructure for handler tests.

// Tests are allowed to use expect/unwrap on failures
#![expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use arc_swap::ArcSwap;
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use secrecy::SecretString;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

use crate::crypto::alg::JwsAlgorithm;
use crate::crypto::document_crypto::{HpkeDocumentCrypto, PlaintextDocumentCrypto};
use crate::db::audit::AuditStore;
use crate::db::store::DocumentStore;
use crate::db::{CreateOAuthClientParams, Pool, RegistrationSource};
use crate::infra::router::build_app;

use crate::AppState;
use crate::config::{IdpConfig, OidcProviderConfig, ServerConfig};
use crate::crypto::keys::OidcSigningKey;

/// Create an in-memory SQLite database with migrations for testing.
pub async fn test_db() -> Pool {
    let pool = Pool::connect("sqlite::memory:", &crate::db::pool::PoolConfig::default())
        .await
        .expect("Failed to create test database");

    // Run migrations based on database type
    match &pool {
        Pool::Sqlite(p) => sqlx::migrate!("./migrations/sqlite")
            .run(p)
            .await
            .expect("Failed to run migrations"),
        Pool::Postgres(p) => sqlx::migrate!("./migrations/postgres")
            .run(p)
            .await
            .expect("Failed to run migrations"),
    }

    pool
}

/// Create a test configuration with sensible defaults.
pub fn test_config() -> ServerConfig {
    ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        database_url: "sqlite::memory:".to_string(),
        rp_id: "test.example.com".to_string(),
        rp_name: "Test RP".to_string(),
        jwt_secret: SecretString::from("test_jwt_secret_must_be_at_least_32_characters_long"),
        session_hours: 8,
        idps: vec![IdpConfig::Oidc(OidcProviderConfig {
            id: "google".to_string(),
            issuer_url: "https://accounts.google.com".to_string(),
            client_id: "test-client-id".to_string(),
            client_secret: SecretString::from("test-client-secret"),
        })],
        base_url: crate::config::BaseUrl::new("https://test.example.com"),
        device_code_expires_seconds: 600,
        device_poll_interval_seconds: 5,
        allowed_domains: Some(vec!["example.com".to_string()]),
        org_name: Some("Test Org".to_string()),
        resource_name: Some("Vouch".to_string()),
        resource_documentation: Some("https://vouch.sh/docs/".to_string()),
        resource_policy_uri: Some("https://vouch.sh/privacy/".to_string()),
        resource_tos_uri: Some("https://vouch.sh/terms/".to_string()),
        security_contact: "security@vouch.sh".to_string(),
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
        cleanup_interval_minutes: 0, // Disabled for tests
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
        log_format: crate::config::LogFormat::Text,
        trusted_proxies: Vec::new(),
        metrics_bearer_token: None,
        certification_test_token: None,
        extra_ca_certs: None,
        pool_config: crate::db::pool::PoolConfig::default(),
        session_cache_max_capacity: 10_000,
        session_cache_ttl_secs: 30,
    }
}

/// Create a test AppState with in-memory database.
pub async fn test_app_state() -> Arc<AppState> {
    test_app_state_with_idps(Vec::new()).await
}

/// Create a test AppState seeded with the given upstream IdPs.
///
/// Used by tests that exercise multi-IdP code paths (chooser rendering,
/// provider slug validation, etc.) without standing up real IdP metadata.
pub async fn test_app_state_with_idps(
    idps: Vec<crate::services::idp::ConfiguredIdp>,
) -> Arc<AppState> {
    build_test_app_state(idps, |_| {}).await
}

/// Build an [`AppState`] for tests, invoking `configure_store` on the document
/// store before it is wired into state.
///
/// Lets handler-level tests install the `modify` test hook
/// ([`DocumentStore::set_modify_test_hook`]) to deterministically reproduce
/// OCC races through the full axum router, without each test reconstructing
/// the entire state by hand.
pub async fn build_test_app_state<F>(
    idps: Vec<crate::services::idp::ConfiguredIdp>,
    configure_store: F,
) -> Arc<AppState>
where
    F: FnOnce(&mut DocumentStore),
{
    let pool = test_db().await;
    let config = test_config();

    let rp_origin = url::Url::parse(&config.base_url).expect("Invalid RP origin");
    let webauthn = webauthn_rs::WebauthnBuilder::new(&config.rp_id, &rp_origin)
        .expect("Failed to create WebauthnBuilder")
        .rp_name(&config.rp_name)
        .build()
        .expect("Failed to build Webauthn");

    // Generate OIDC signing key for tests
    let oidc_key = OidcSigningKey::generate().expect("Failed to generate test OIDC key");

    let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
        Arc::new(PlaintextDocumentCrypto);
    let mut store = DocumentStore::new(pool.clone(), crypto.clone());
    configure_store(&mut store);
    let audit = AuditStore::new(pool.clone(), crypto);

    // Register the first-party client whose JWKS holds the shared test signing
    // key, so transparently-signed `/v1/*` test requests verify.
    register_test_httpsig_client(&store, &config.base_url).await;

    Arc::new(AppState {
        db: pool,
        store,
        audit,
        config: Arc::new(ArcSwap::from_pointee(config)),
        webauthn,
        ssh_ca: None,
        oidc_key,
        oidc_rsa_key: None,
        state_signer: crate::crypto::jwt::StateTokenSigner::local(
            b"test_jwt_secret_must_be_at_least_32_characters_long".to_vec(),
        ),
        github_app: None,
        http_client: reqwest::Client::new(),
        session_cache: crate::db::SessionCache::new(10_000, 30),
        org_keys_cache: Default::default(),
        policy: Default::default(),
        idps,
    })
}

/// Create a test AppState with an RSA signing key provisioned.
///
/// Used by tests that exercise the RS256 `id_token_hint` verification branch.
/// Mirrors `test_app_state_with_idps` but sets `oidc_rsa_key` to a freshly
/// generated RSA-3072 key pair.
pub async fn test_app_state_with_rsa_key() -> Arc<AppState> {
    use crate::crypto::keys::OidcRsaSigningKey;

    let pool = test_db().await;
    let config = test_config();

    let rp_origin = url::Url::parse(&config.base_url).expect("Invalid RP origin");
    let webauthn = webauthn_rs::WebauthnBuilder::new(&config.rp_id, &rp_origin)
        .expect("Failed to create WebauthnBuilder")
        .rp_name(&config.rp_name)
        .build()
        .expect("Failed to build Webauthn");

    let oidc_key = OidcSigningKey::generate().expect("Failed to generate test OIDC key");
    let oidc_rsa_key = OidcRsaSigningKey::generate().expect("Failed to generate test RSA key");

    let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
        Arc::new(PlaintextDocumentCrypto);
    let store = DocumentStore::new(pool.clone(), crypto.clone());
    let audit = AuditStore::new(pool.clone(), crypto);

    register_test_httpsig_client(&store, &config.base_url).await;

    Arc::new(AppState {
        db: pool,
        store,
        audit,
        config: Arc::new(ArcSwap::from_pointee(config)),
        webauthn,
        ssh_ca: None,
        oidc_key,
        oidc_rsa_key: Some(oidc_rsa_key),
        state_signer: crate::crypto::jwt::StateTokenSigner::local(
            b"test_jwt_secret_must_be_at_least_32_characters_long".to_vec(),
        ),
        github_app: None,
        http_client: reqwest::Client::new(),
        session_cache: crate::db::SessionCache::new(10_000, 30),
        org_keys_cache: Default::default(),
        policy: Default::default(),
        idps: Vec::new(),
    })
}

/// Create a test AppState whose document store **encrypts at rest** (HPKE).
///
/// `is_encrypted()` is `true`, so per-org issuer signing keys are created and
/// exercised — unlike the default `PlaintextDocumentCrypto` state, where the
/// feature falls back to the shared key. Includes a shared RSA key so the
/// non-per-org RS256 fallback also works.
pub async fn test_app_state_encrypted() -> Arc<AppState> {
    use crate::crypto::keys::OidcRsaSigningKey;

    let pool = test_db().await;
    let config = test_config();

    let rp_origin = url::Url::parse(&config.base_url).expect("Invalid RP origin");
    let webauthn = webauthn_rs::WebauthnBuilder::new(&config.rp_id, &rp_origin)
        .expect("Failed to create WebauthnBuilder")
        .rp_name(&config.rp_name)
        .build()
        .expect("Failed to build Webauthn");

    let oidc_key = OidcSigningKey::generate().expect("Failed to generate test OIDC key");
    let oidc_rsa_key = OidcRsaSigningKey::generate().expect("Failed to generate test RSA key");

    let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
        Arc::new(HpkeDocumentCrypto::generate_for_test());
    let store = DocumentStore::new(pool.clone(), crypto.clone());
    let audit = AuditStore::new(pool.clone(), crypto);

    register_test_httpsig_client(&store, &config.base_url).await;

    Arc::new(AppState {
        db: pool,
        store,
        audit,
        config: Arc::new(ArcSwap::from_pointee(config)),
        webauthn,
        ssh_ca: None,
        oidc_key,
        oidc_rsa_key: Some(oidc_rsa_key),
        state_signer: crate::crypto::jwt::StateTokenSigner::local(
            b"test_jwt_secret_must_be_at_least_32_characters_long".to_vec(),
        ),
        github_app: None,
        http_client: reqwest::Client::new(),
        session_cache: crate::db::SessionCache::new(10_000, 30),
        org_keys_cache: Default::default(),
        policy: Default::default(),
        idps: Vec::new(),
    })
}

/// Create test app (router + state) for handler testing.
pub async fn test_app() -> (Router, Arc<AppState>) {
    let state = test_app_state().await;
    let config = state.config();
    let router = build_app(state.clone(), &config).expect("Failed to build test app router");
    (router, state)
}

/// Create a test app whose document store is configured via `configure_store`
/// before the router is built.
///
/// Lets handler tests install [`DocumentStore::set_modify_test_hook`] to
/// deterministically drive the OCC race window through the full router.
pub async fn test_app_with_modify_hook<F>(configure_store: F) -> (Router, Arc<AppState>)
where
    F: FnOnce(&mut DocumentStore),
{
    let state = build_test_app_state(Vec::new(), configure_store).await;
    let config = state.config();
    let router = build_app(state.clone(), &config).expect("Failed to build test app router");
    (router, state)
}

/// Create test app (router + state) with the given upstream IdPs seeded.
pub async fn test_app_with_idps(
    idps: Vec<crate::services::idp::ConfiguredIdp>,
) -> (Router, Arc<AppState>) {
    let state = test_app_state_with_idps(idps).await;
    let config = state.config();
    let router = build_app(state.clone(), &config).expect("Failed to build test app router");
    (router, state)
}

/// Create test app with the certification test-mode endpoint enabled.
///
/// The certification token is set to a fixed value for testing.
pub async fn test_app_with_certification() -> (Router, Arc<AppState>) {
    use secrecy::SecretString;
    let state = test_app_state().await;
    // Override config with certification token set
    let mut config = (**state.config()).clone();
    config.certification_test_token = Some(SecretString::from("test-cert-token-32bytes-padding!!"));
    state.config.store(Arc::new(config.clone()));
    let router = build_app(state.clone(), &config).expect("Failed to build test app router");
    (router, state)
}

/// Fixed `kid` for the process-wide test HTTP message-signing key.
const TEST_HTTPSIG_KID: &str = "vouch-test-httpsig-key";

/// Process-wide P-256 key used to sign `/v1/*` test requests, plus the JWKS
/// document registered for the first-party test client.
struct TestHttpSig {
    signer: vouch_httpsig::algorithm::ecdsa_p256::EcdsaP256Signer,
    jwks: serde_json::Value,
}

static TEST_HTTPSIG: std::sync::LazyLock<TestHttpSig> = std::sync::LazyLock::new(|| {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use vouch_httpsig::algorithm::ecdsa_p256::EcdsaP256Signer;

    let signer = EcdsaP256Signer::generate(TEST_HTTPSIG_KID).expect("generate test httpsig key");
    // Uncompressed SEC1 point: 0x04 || x(32) || y(32).
    let pk = signer.public_key_bytes();
    let x = URL_SAFE_NO_PAD.encode(pk.get(1..33).expect("x coordinate"));
    let y = URL_SAFE_NO_PAD.encode(pk.get(33..65).expect("y coordinate"));
    let jwks = serde_json::json!({
        "keys": [{ "kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": TEST_HTTPSIG_KID }]
    });
    TestHttpSig { signer, jwks }
});

/// Register the first-party OAuth client used by test sessions.
///
/// [`create_test_session_with`] mints tokens whose `client_id` is the server
/// `base_url` unless the spec names one. The `/v1/*` routes require an RFC 9421 signature, and the
/// server resolves the verifying key from the token client's registered JWKS.
/// Registering a client keyed to `base_url` with the shared test signing key
/// lets [`build_test_request`] transparently sign `/v1/*` requests so existing
/// handler tests keep exercising the full router.
async fn register_test_httpsig_client(store: &DocumentStore, base_url: &str) {
    use crate::db::documents::oauth::{
        FapiProfile, OAuthClientDoc, OAuthClientType, TokenEndpointAuthMethod,
    };

    let doc = OAuthClientDoc {
        user_id: None,
        client_id: base_url.to_string(),
        name: "Test First-Party Client".to_string(),
        description: None,
        application_type: OAuthClientType::Native,
        redirect_uris: Vec::new(),
        active: true,
        access_scope: crate::db::AccessScope::Public,
        org_id: None,
        resource_uris: Vec::new(),
        jwks: Some(TEST_HTTPSIG.jwks.clone()),
        jwks_uri: None,
        token_endpoint_auth_method: TokenEndpointAuthMethod::default(),
        request_object_signing_alg: None,
        require_signed_request_object: None,
        fapi_profile: FapiProfile::default(),
        dpop_bound_access_tokens: false,
        grant_types: None,
        response_types: None,
        software_id: None,
        software_version: None,
        registration_source: Some(RegistrationSource::Manual),
        registration_access_token_hash: None,
        registration_metadata: None,
        id_token_signed_response_alg: JwsAlgorithm::Es256,
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        tls_client_auth_san_ip: None,
        tls_client_auth_san_email: None,
        tls_client_certificate_bound_access_tokens: false,
        authorization_signed_response_alg: None,
        introspection_signed_response_alg: None,
        userinfo_signed_response_alg: None,
        request_uris: None,
        post_logout_redirect_uris: None,
    };
    store
        .insert(&doc)
        .await
        .expect("register first-party test httpsig client");
}

/// Whether a request to `uri` carrying these `headers` should be auto-signed.
///
/// Signs authenticated `/v1/*` requests (those with an `Authorization` header)
/// except the soft `/v1/auth/status` probe, mirroring the production
/// enforcement scope so unsigned/unauthenticated tests still see their 401s.
fn should_auto_sign(uri: &str, headers: &[(&str, &str)]) -> bool {
    let path = uri.split('?').next().unwrap_or(uri);
    if !path.starts_with("/v1/") || path == "/v1/auth/status" {
        return false;
    }
    headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
}

/// Compute RFC 9421 signature headers for a `/v1/*` test request using the
/// shared test signing key.
///
/// `uri` may be a path (`/v1/keys`) or a full URL; the signature covers
/// `@method` and `@path` (plus `content-digest` for bodies). Exposed so the
/// integration harness signs `/v1/*` requests with the same shared key whose
/// JWKS is registered for the first-party test client.
pub fn test_signature_headers(
    method: &str,
    uri: &str,
    body: Option<&[u8]>,
) -> Vec<(String, String)> {
    let has_body = body.is_some_and(|b| !b.is_empty());
    let body_bytes = body.unwrap_or_default();
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .body(body_bytes.to_vec())
        .expect("build signing request");

    if has_body {
        vouch_httpsig::digest::set_content_digest(
            req.headers_mut(),
            body_bytes,
            vouch_httpsig::DigestAlgorithm::Sha256,
        )
        .expect("set content-digest");
    }

    let mut sig_builder = vouch_httpsig::SignatureBuilder::new("sig1")
        .method()
        .path()
        .created_now();
    if has_body {
        sig_builder = sig_builder.field("content-digest");
    }
    sig_builder
        .sign_request(&mut req, &TEST_HTTPSIG.signer)
        .expect("sign test request");

    let mut out = Vec::new();
    for name in ["signature-input", "signature", "content-digest"] {
        if let Some(v) = req.headers().get(name)
            && let Ok(s) = v.to_str()
        {
            out.push((name.to_string(), s.to_string()));
        }
    }
    out
}

/// Build a request with standard test extensions (no mTLS cert).
fn build_test_request(
    method: &str,
    uri: &str,
    body: Option<String>,
    headers: &[(&str, &str)],
) -> Request<Body> {
    let mut req_builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        req_builder = req_builder.header(*name, *value);
    }
    if should_auto_sign(uri, headers) {
        let body_ref = body.as_deref().map(str::as_bytes);
        for (name, value) in test_signature_headers(method, uri, body_ref) {
            req_builder = req_builder.header(name, value);
        }
    }
    let body = match body {
        Some(b) => Body::from(b),
        None => Body::empty(),
    };
    let request = req_builder.body(body).expect("Failed to build request");
    let (mut parts, body) = request.into_parts();
    parts
        .extensions
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    Request::from_parts(parts, body)
}

/// Generate a self-signed P-256 certificate DER for testing.
pub fn make_test_cert_der(cn: &str) -> Vec<u8> {
    use der::{Decode as _, Encode, asn1::Utf8StringRef};
    use p256::ecdsa::SigningKey;
    use spki::EncodePublicKey as _;
    use x509_cert::builder::{Builder as _, CertificateBuilder, Profile};
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;

    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    let cn_oid = der::oid::ObjectIdentifier::new_unwrap("2.5.4.3");
    let cn_value = Utf8StringRef::new(cn).expect("valid CN");
    let atv = x509_cert::attr::AttributeTypeAndValue {
        oid: cn_oid,
        value: der::asn1::Any::from(cn_value),
    };
    let mut rdn_set = der::asn1::SetOfVec::new();
    rdn_set.insert(atv).expect("insert RDN");
    let subject =
        x509_cert::name::RdnSequence(vec![x509_cert::name::RelativeDistinguishedName(rdn_set)]);

    let validity = Validity::from_now(core::time::Duration::from_secs(86400)).expect("validity");
    let serial = SerialNumber::new(&[1u8]).expect("serial");
    let spki_der = key.verifying_key().to_public_key_der().expect("spki DER");
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_ref()).expect("parse spki");

    let builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        serial,
        validity,
        subject,
        spki,
        &key,
    )
    .expect("cert builder");

    let cert = builder
        .build::<p256::ecdsa::DerSignature>()
        .expect("build cert");
    cert.to_der().expect("DER encode")
}

/// Build a request with an injected mTLS client certificate DER.
///
/// Injects `ConnectInfo<PeerClientCert>` so `OptionalClientCert` extracts it.
fn build_test_request_with_cert(
    method: &str,
    uri: &str,
    body: Option<String>,
    headers: &[(&str, &str)],
    cert_der: Option<Vec<u8>>,
) -> Request<Body> {
    use crate::infra::mtls_listener::PeerClientCert;

    let mut req_builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        req_builder = req_builder.header(*name, *value);
    }
    let body = match body {
        Some(b) => Body::from(b),
        None => Body::empty(),
    };
    let request = req_builder.body(body).expect("Failed to build request");
    let (mut parts, body) = request.into_parts();
    parts
        .extensions
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    parts
        .extensions
        .insert(ConnectInfo(PeerClientCert(cert_der)));
    Request::from_parts(parts, body)
}

/// Helper for making test HTTP requests.
pub async fn http_request(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<String>,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let request = build_test_request(method, uri, body, headers);

    let response: axum::response::Response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("Failed to read response body");
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    (status, body_str)
}

/// Full response from an HTTP request, including headers.
pub struct HttpResponse {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response body as a string.
    pub body: String,
    /// Response headers.
    pub headers: axum::http::HeaderMap,
}

/// Helper for making test HTTP requests that returns full response including headers.
pub async fn http_request_full(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<String>,
    headers: &[(&str, &str)],
) -> HttpResponse {
    let mut req_builder = Request::builder().method(method).uri(uri);

    for (name, value) in headers {
        req_builder = req_builder.header(*name, *value);
    }

    if should_auto_sign(uri, headers) {
        let body_ref = body.as_deref().map(str::as_bytes);
        for (name, value) in test_signature_headers(method, uri, body_ref) {
            req_builder = req_builder.header(name, value);
        }
    }

    let body = match body {
        Some(b) => Body::from(b),
        None => Body::empty(),
    };

    let request = req_builder.body(body).expect("Failed to build request");
    let (mut parts, body) = request.into_parts();
    parts
        .extensions
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    let request = Request::from_parts(parts, body);

    let response: axum::response::Response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    let status = response.status();
    let response_headers = response.headers().clone();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("Failed to read response body");
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    HttpResponse {
        status,
        body: body_str,
        headers: response_headers,
    }
}

/// Helper for making GET requests.
pub async fn http_get(app: &Router, uri: &str, headers: &[(&str, &str)]) -> (StatusCode, String) {
    http_request(app, "GET", uri, None, headers).await
}

/// Helper for making GET requests that returns full response including headers.
pub async fn http_get_full(app: &Router, uri: &str, headers: &[(&str, &str)]) -> HttpResponse {
    http_request_full(app, "GET", uri, None, headers).await
}

/// Helper for making POST requests with form body.
pub async fn http_post_form(
    app: &Router,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut all_headers = vec![("Content-Type", "application/x-www-form-urlencoded")];
    all_headers.extend_from_slice(headers);
    http_request(app, "POST", uri, Some(body.to_string()), &all_headers).await
}

/// Helper for making POST requests with form body that returns full response including headers.
pub async fn http_post_form_full(
    app: &Router,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> HttpResponse {
    let mut all_headers = vec![("Content-Type", "application/x-www-form-urlencoded")];
    all_headers.extend_from_slice(headers);
    http_request_full(app, "POST", uri, Some(body.to_string()), &all_headers).await
}

/// Helper for making POST requests with JSON body.
pub async fn http_post_json(
    app: &Router,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut all_headers = vec![("Content-Type", "application/json")];
    all_headers.extend_from_slice(headers);
    http_request(app, "POST", uri, Some(body.to_string()), &all_headers).await
}

/// Helper for making PUT requests with JSON body.
pub async fn http_put_json(
    app: &Router,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut all_headers = vec![("Content-Type", "application/json")];
    all_headers.extend_from_slice(headers);
    http_request(app, "PUT", uri, Some(body.to_string()), &all_headers).await
}

/// Helper for making DELETE requests.
pub async fn http_delete(
    app: &Router,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    http_request(app, "DELETE", uri, None, headers).await
}

/// Helper for making DELETE requests that returns full response including headers.
pub async fn http_delete_full(app: &Router, uri: &str, headers: &[(&str, &str)]) -> HttpResponse {
    http_request_full(app, "DELETE", uri, None, headers).await
}

/// Helper for making POST form requests with an injected mTLS client certificate.
///
/// Mirrors [`http_post_form`] but injects the certificate via
/// `ConnectInfo<PeerClientCert>` so [`OptionalClientCert`] extracts it in the
/// handler. Pass `None` for `cert_der` to simulate a connection where no client
/// certificate was presented.
pub async fn http_post_form_with_cert(
    app: &Router,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
    cert_der: Option<Vec<u8>>,
) -> (StatusCode, String) {
    let mut all_headers = vec![("Content-Type", "application/x-www-form-urlencoded")];
    all_headers.extend_from_slice(headers);
    let request =
        build_test_request_with_cert("POST", uri, Some(body.to_string()), &all_headers, cert_der);
    let response: axum::response::Response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("Failed to read response body");
    (status, String::from_utf8_lossy(&body_bytes).to_string())
}

/// Helper for making POST JSON requests with an injected mTLS client certificate.
///
/// Mirrors [`http_post_json`] but injects the certificate via
/// `ConnectInfo<PeerClientCert>` so [`OptionalClientCert`] extracts it in the
/// handler. Pass `None` for `cert_der` to simulate a connection where no client
/// certificate was presented.
pub async fn http_post_json_with_cert(
    app: &Router,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
    cert_der: Option<Vec<u8>>,
) -> (StatusCode, String) {
    let mut all_headers = vec![("Content-Type", "application/json")];
    all_headers.extend_from_slice(headers);
    let request =
        build_test_request_with_cert("POST", uri, Some(body.to_string()), &all_headers, cert_der);
    let response: axum::response::Response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("Failed to read response body");
    (status, String::from_utf8_lossy(&body_bytes).to_string())
}

/// Helper for making GET requests with an injected mTLS client certificate.
///
/// The `cert_der` is injected via `ConnectInfo<PeerClientCert>` so that
/// `OptionalClientCert` extracts it in the handler. Pass `None` to simulate
/// a connection where no client certificate was presented.
pub async fn http_get_with_cert(
    app: &Router,
    uri: &str,
    headers: &[(&str, &str)],
    cert_der: Option<Vec<u8>>,
) -> (StatusCode, String) {
    let request = build_test_request_with_cert("GET", uri, None, headers, cert_der);
    let response: axum::response::Response = app
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("Failed to read response body");
    (status, String::from_utf8_lossy(&body_bytes).to_string())
}

/// Create a test user in the database.
pub async fn create_test_user(store: &DocumentStore, email: &str) -> crate::db::User {
    let (user_id, _created) = crate::db::upsert_user(store, email, Some("Test User"))
        .await
        .expect("Failed to create test user");
    crate::db::get_user_by_id(store, &user_id)
        .await
        .expect("Failed to fetch test user")
        .expect("Test user not found after creation")
}

/// Create a test organization in the database.
pub async fn create_test_org(store: &DocumentStore, domain: &str) -> crate::db::Organization {
    crate::db::create_organization(store, domain, Some("Test Org"), None)
        .await
        .expect("Failed to create test org")
}

/// Create a test user with organization membership.
pub async fn create_test_user_in_org(
    store: &DocumentStore,
    email: &str,
    org_id: &str,
    is_admin: bool,
) -> crate::db::User {
    let (user_id, _created) =
        crate::db::upsert_user_with_org(store, email, Some("Test User"), Some(org_id), is_admin)
            .await
            .expect("Failed to create test user in org");
    crate::db::get_user_by_id(store, &user_id)
        .await
        .expect("Failed to fetch test user")
        .expect("Test user not found after creation")
}

/// Delete a test authenticator, cascading to its sessions.
///
/// `db::delete_authenticator` takes a transaction so its cascade cannot land
/// half-applied; tests that just need a key gone go through here rather than
/// repeating begin/commit at each call site.
pub async fn remove_test_authenticator(store: &DocumentStore, authenticator_id: &str) {
    let mut tx = store.begin().await.expect("Failed to start transaction");
    crate::db::delete_authenticator(&mut tx, authenticator_id)
        .await
        .expect("Failed to delete authenticator");
    tx.commit().await.expect("Failed to commit deletion");
}

/// Create a test authenticator for a user.
pub async fn create_test_authenticator(store: &DocumentStore, user_id: &str) -> String {
    crate::db::create_authenticator(
        store,
        &crate::db::CreateAuthenticatorParams {
            user_id,
            user_email: "test@example.com",
            name: "Test Key",
            credential_id: format!("test-cred-{}", uuid::Uuid::now_v7()).as_bytes(),
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: Some(user_id.as_bytes()),
            attestation_verified: false,
        },
    )
    .await
    .expect("Failed to create authenticator")
}

/// Resolve the session-time `hardware_aaguid` / `org_domain` snapshot the way
/// production call sites do — by fetching the authenticator and the user's
/// organization domain. Used by every test session helper so tests exercise
/// the same denormalization path the server uses.
async fn resolve_session_snapshot(
    state: &AppState,
    user_id: &str,
    auth_id: Option<&str>,
) -> (Option<String>, Option<String>) {
    let hardware_aaguid = match auth_id {
        Some(id) => crate::db::get_authenticator_by_id(&state.store, id)
            .await
            .ok()
            .flatten()
            .and_then(|a| a.aaguid),
        None => None,
    };
    let org_domain = match crate::db::get_user_by_id(&state.store, user_id).await {
        Ok(Some(u)) => match u.org_id {
            Some(org_id) => crate::db::get_organization_domain(&state.store, &org_id)
                .await
                .unwrap_or(None),
            None => None,
        },
        _ => None,
    };
    (hardware_aaguid, org_domain)
}

/// How a test session's access token is bound to the party that may present
/// it, named the way a fixture site knows it: by thumbprint.
///
/// The production `TokenBinding` takes a
/// `ValidatedDpopProof` witness rather than a bare `jkt`, so a sender-constrained
/// token cannot be minted from a string that never passed proof validation.
/// [`create_test_session_with`] stands that witness up.
pub enum TestBinding<'a> {
    /// A bearer token: whoever holds it may present it.
    Bearer,
    /// RFC 9449 §6: `cnf.jkt` set to this JWK thumbprint.
    Dpop(&'a str),
    /// RFC 8705 §3.1: `cnf.x5t#S256` set to this certificate thumbprint.
    Mtls(&'a crate::services::oidc::mtls::CertThumbprint),
}

/// The authentication assurance a test session's token claims.
///
/// The first two variants map onto `HardwareVerification` and travel the
/// ordinary issuance path. The third does not — see its docs.
pub enum TestVerification {
    /// A FIDO2 assertion happened: `hardware_verified: true`, `amr: [hwk, pin,
    /// user]`, `acr: aal3`. `auth_time` is when it happened; `None` models
    /// verification inherited from another token (RFC 8693 token exchange runs
    /// no ceremony of its own).
    Verified {
        /// When the assertion happened, in Unix seconds.
        auth_time: Option<i64>,
    },
    /// No FIDO2 assertion: `hardware_verified: false`, no `auth_time`, no
    /// `amr`/`acr`. The enrollment-bootstrap shape in `handlers/enroll.rs` —
    /// a real user and a persisted session minted right after upstream IdP
    /// sign-in.
    NotVerified,
    /// A token this deployment's issuer cannot produce: `hardware_verified`
    /// false alongside an `auth_time` a freshness gate would read as recent
    /// FIDO2. `HardwareVerification::NotVerified` has nowhere to put a
    /// timestamp, so the combination is unrepresentable by design (issue
    /// #1114) and this variant reaches it by mutating a minted token's claims
    /// and re-signing.
    ///
    /// That is the point: it produces what an older server's token, or a
    /// future regression, would put in front of the key handlers. Every claim
    /// other than `auth_time` and `jti` is whatever the production issuer
    /// produced, so a claim added later travels here automatically instead of
    /// silently diverging.
    ///
    /// Leaves two session rows for the user: the base token's and the mutated
    /// one's. [`create_test_session_with`] returns the mutated token.
    NotVerifiedForgedAuthTime {
        /// The `auth_time` to stamp on a session that ran no ceremony.
        auth_time: i64,
    },
}

/// Knobs that test-session fixture sites actually vary.
///
/// The canonical way to build a session; [`create_test_session_with`] is the
/// only place a `CreateOAuthTokenParams` literal is spelled out for tests.
/// `Default` supplies the ordinary hardware-verified bearer session, so a test
/// names only the axis it is about:
///
/// ```rust,ignore
/// let token = create_test_session_with(&state, TestSessionSpec {
///     user_id: &user.id,
///     email: &user.email,
///     auth_id: Some(&auth_id),
///     binding: TestBinding::Dpop(&jkt),
///     ..Default::default()
/// })
/// .await;
/// ```
pub struct TestSessionSpec<'a> {
    /// Subject of the token. Required — the default is empty and rejected.
    pub user_id: &'a str,
    /// Email claim and session-row email. Required — the default is empty and
    /// rejected.
    pub email: &'a str,
    /// Authenticator establishing the session, recorded server-side on the
    /// session row and used to resolve the `hardware_aaguid` snapshot.
    /// Default: `None`, the shape of a session minted before any key exists.
    pub auth_id: Option<&'a str>,
    /// OAuth client the token is issued to. Default: `None`, meaning this
    /// deployment's own `base_url` (first-party CLI/UI sessions).
    pub client_id: Option<&'a str>,
    /// RFC 8707 resource / RFC 8693 audience narrowing. Default: `None`,
    /// meaning `aud == client_id`.
    pub audience: Option<&'a str>,
    /// Sender-constraining. Default: [`TestBinding::Bearer`].
    pub binding: TestBinding<'a>,
    /// Authentication assurance. Default: [`TestVerification::Verified`] with
    /// `auth_time` now.
    pub verification: TestVerification,
}

impl Default for TestSessionSpec<'_> {
    fn default() -> Self {
        Self {
            user_id: "",
            email: "",
            auth_id: Option::None,
            client_id: Option::None,
            audience: Option::None,
            binding: TestBinding::Bearer,
            verification: TestVerification::Verified {
                auth_time: Some(jiff::Timestamp::now().as_second()),
            },
        }
    }
}

/// Create a test session with an OAuth access token stored in the database.
///
/// Returns the raw access token string. Uses the real `create_oauth_access_token`
/// service function with ES256 signing so the token validates through the full
/// token validation pipeline, and resolves the `hardware_aaguid` / `org_domain`
/// snapshot the way production call sites do.
pub async fn create_test_session_with(state: &AppState, spec: TestSessionSpec<'_>) -> String {
    use crate::assurance::HardwareVerification;
    use crate::services::auth::{
        ClientAuthProof, CreateOAuthTokenParams, GrantProof, SenderConstraintProof, TokenBinding,
        TokenIssuanceProof, create_oauth_access_token,
    };
    use crate::services::oidc::{ScopeSet, ValidatedDpopProof};
    use secrecy::ExposeSecret;

    assert!(
        !spec.user_id.is_empty() && !spec.email.is_empty(),
        "TestSessionSpec requires user_id and email; struct-update syntax defaults them to empty"
    );

    let (hardware_aaguid, org_domain) =
        resolve_session_snapshot(state, spec.user_id, spec.auth_id).await;

    let config = state.config();
    let client_id = spec.client_id.unwrap_or(&config.base_url);

    // Fixtures name a DPoP binding by thumbprint, so stand up the witness the
    // issuance path requires. Only reachable under `cfg(test)` /
    // `feature = "test-utils"`.
    let dpop_witness = match spec.binding {
        TestBinding::Dpop(jkt) => Some(ValidatedDpopProof::for_testing(
            jkt.to_string(),
            format!("test-jti-{jkt}"),
            Option::None,
        )),
        TestBinding::Bearer | TestBinding::Mtls(_) => Option::None,
    };
    let mtls_thumbprint = match spec.binding {
        TestBinding::Mtls(thumbprint) => Some(thumbprint),
        TestBinding::Bearer | TestBinding::Dpop(_) => Option::None,
    };

    let hardware_verification = match spec.verification {
        TestVerification::Verified { auth_time } => HardwareVerification::Verified { auth_time },
        // The forged variant mints an unverified token and mutates it below;
        // the issuer has no way to stamp the `auth_time` it wants.
        TestVerification::NotVerified | TestVerification::NotVerifiedForgedAuthTime { .. } => {
            HardwareVerification::NotVerified
        }
    };

    let result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id: spec.user_id,
            email: spec.email,
            authenticator_id: spec.auth_id,
            client_id,
            scope: Some(ScopeSet::all()),
            binding: TokenBinding::new(dpop_witness.as_ref(), mtls_thumbprint),
            act: Option::None,
            audience: spec.audience,
            hardware_verification,
            session_purpose: crate::db::SessionPurpose::OAuthAccessToken,
            authorization_details: Option::None,
            hardware_aaguid: hardware_aaguid.as_deref(),
            org_domain: org_domain.as_deref(),
            source_code_hash: Option::None,
        },
        TokenIssuanceProof {
            grant: GrantProof::TestingOnly,
            client_auth: ClientAuthProof::NoAuth(
                crate::services::auth::NoClientAuth::internal_endpoint(),
            ),
            sender_constraint: SenderConstraintProof::no_registered_client(),
        },
    )
    .await
    .expect("Failed to create test session");

    let token = result.token.expose_secret().to_string();

    let TestVerification::NotVerifiedForgedAuthTime { auth_time } = spec.verification else {
        return token;
    };
    forge_auth_time(state, &spec, &token, auth_time).await
}

/// Re-sign `base` with `auth_time` stamped onto claims the issuer produced
/// without one, and persist a session row for the result.
///
/// Split out because it is the whole of
/// [`TestVerification::NotVerifiedForgedAuthTime`]: derive from a real token,
/// change the single field under test, leave everything else alone.
async fn forge_auth_time(
    state: &AppState,
    spec: &TestSessionSpec<'_>,
    base: &str,
    auth_time: i64,
) -> String {
    use crate::services::auth::{DecodedToken, decode_token};

    let DecodedToken::AccessToken(mut claims) =
        decode_token(base, &state.oidc_key, &state.config().base_url)
            .expect("the token this deployment just minted must decode");

    assert!(
        !claims.hardware_verified,
        "the base token must be unverified for this fixture to mean anything"
    );
    claims.auth_time = Some(auth_time);
    claims.jti = uuid::Uuid::now_v7().to_string();

    let token = state
        .oidc_key
        .sign_access_token_jwt(&claims)
        .await
        .expect("Failed to sign the forged-auth_time access token");

    let (hardware_aaguid, org_domain) =
        resolve_session_snapshot(state, spec.user_id, spec.auth_id).await;
    let expires_at = jiff::Timestamp::from_second(claims.exp).expect("valid expiry");
    crate::db::create_session(
        &state.store,
        &crate::db::CreateSessionParams {
            user_id: spec.user_id,
            user_email: spec.email,
            token_hash: &crate::crypto::hash_token(&token),
            authenticator_id: Option::None,
            expires_at,
            session_type: crate::db::SessionPurpose::OAuthAccessToken,
            authorization_details: Option::None,
            hardware_aaguid: hardware_aaguid.as_deref(),
            org_domain: org_domain.as_deref(),
            source_code_hash: Option::None,
        },
    )
    .await
    .expect("Failed to persist the forged-auth_time session");

    token
}

/// Create an org with an admin user, a FIDO2-verified session, and return
/// the admin plus the session's raw access token.
pub async fn create_test_org_admin(state: &AppState) -> (crate::db::User, String) {
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;
    let token = create_test_session_with(
        state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    (admin, token)
}

/// Create an organization API token for testing, bound to the given org,
/// with an explicit scope set. Shared primitive behind
/// [`create_test_scim_token`] (default SCIM scopes) and
/// [`create_test_audit_token`] (`audit:read` only, no SCIM scopes).
///
/// `authenticate_scim` rejects tokens without an `org_id`, so every
/// test that authenticates via SCIM (or the audit events API's org-token
/// path) must supply one.
pub async fn create_test_org_token_with_scope(
    store: &DocumentStore,
    description: &str,
    org_id: &str,
    scope: crate::db::ScimScopeSet,
) -> String {
    use aws_lc_rs::digest::{self, SHA256};
    use aws_lc_rs::rand as aws_rand;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Generate random token
    let mut bytes = [0u8; 32];
    aws_rand::fill(&mut bytes).expect("RNG failure");
    let token = URL_SAFE_NO_PAD.encode(bytes);

    // Hash for storage
    let token_hash = hex::encode(digest::digest(&SHA256, token.as_bytes()));

    // Token creation enforces the per-org cap against the organization row, so
    // the org must exist. Tests pass opaque ids like "test-org" rather than
    // building an org first, so seed one on demand.
    if store
        .get::<crate::db::documents::organization::OrganizationDoc>(org_id)
        .await
        .expect("look up test org")
        .is_none()
    {
        store
            .insert_with_id(
                org_id,
                &crate::db::documents::organization::OrganizationDoc {
                    // ".example" alone is a reserved TLD (RESERVED_TLDS) and
                    // is rejected by `normalize_domain`, which SCIM user
                    // creation now runs the candidate email's domain
                    // through — use the RFC 2606 second-level reservation
                    // instead so per-org_id domains stay both valid and
                    // collision-free.
                    domain: format!("{org_id}.example.com"),
                    name: Some(org_id.to_string()),
                    created_by_user_id: None,
                    additional_domains: Vec::new(),
                    subdomain: None,
                },
            )
            .await
            .expect("seed test org");
    }

    // Store in database with org_id so authenticate_scim accepts it
    crate::db::create_scim_token(
        store,
        &crate::db::CreateScimTokenParams {
            org_id,
            token_hash: &token_hash,
            description: Some(description),
            expires_at: None,
            scope,
        },
    )
    .await
    .expect("Failed to create SCIM token");

    token
}

/// Create a SCIM bearer token for testing, bound to the given org, with
/// the four default SCIM provisioning scopes (no `audit:read`).
pub async fn create_test_scim_token(
    store: &DocumentStore,
    description: &str,
    org_id: &str,
) -> String {
    create_test_org_token_with_scope(
        store,
        description,
        org_id,
        crate::db::ScimScopeSet::default(),
    )
    .await
}

/// Create an organization API token for testing with the `audit:read`
/// scope (and no SCIM scopes) — the token flavor
/// `GET /api/v1/org/audit-events` accepts from unattended pollers.
pub async fn create_test_audit_token(
    store: &DocumentStore,
    description: &str,
    org_id: &str,
) -> String {
    create_test_org_token_with_scope(
        store,
        description,
        org_id,
        crate::db::ScimScopeSet::from_scopes(vec![crate::db::ScimScope::AuditRead]),
    )
    .await
}

/// What JWKS, if any, a test OAuth client is created with.
#[derive(Default)]
pub enum TestJwks {
    /// No JWKS registered (DB column stays NULL). Default — preserves the
    /// current `create_test_oauth_client` behavior and keeps the ~4 tests
    /// that assert `jwks IS NONE` and the ~8 private_key_jwt tests that
    /// register their own key.
    #[default]
    None,
    /// The process-wide shared test signing key (`TEST_HTTPSIG.jwks`). Opts
    /// a custom client into transparently-signed `/v1/*` request verification
    /// using the key registered for the first-party test client.
    Shared,
    /// A caller-supplied JWKS document (e.g. a per-test `ClientKey` public JWK
    /// for negative/key-mismatch tests).
    Custom(serde_json::Value),
}

/// Knobs that test-client fixture sites actually vary.
///
/// All fields have `Default` values that reproduce the behavior of the old
/// `create_test_oauth_client` exactly (see the mapping table in the
/// `impl Default` below).  Use struct-update syntax to override only what the
/// test needs:
///
/// ```rust,ignore
/// create_test_client(&store, &user.id, TestClientSpec {
///     jwks: TestJwks::Shared,
///     ..Default::default()
/// }).await
/// ```
pub struct TestClientSpec {
    /// OAuth client display name. Default: `"Test App"`.
    pub name: String,
    /// Client application type. Default: `OAuthClientType::Web`.
    pub application_type: crate::db::OAuthClientType,
    /// Registered redirect URIs. Default: `["https://example.com/callback"]`.
    pub redirect_uris: Vec<String>,
    /// Access scope (Personal vs Public). Default: `AccessScope::Public`.
    pub access_scope: crate::db::AccessScope,
    /// Organisation the client belongs to. Default: `None`.
    pub org_id: Option<String>,
    /// Permitted resource URIs (RAR). Default: empty.
    pub resource_uris: Vec<String>,
    /// Token endpoint auth method override. Default: `None` (→ ClientSecretBasic).
    pub token_endpoint_auth_method: Option<crate::db::TokenEndpointAuthMethod>,
    /// JWKS to register with the client. Default: `TestJwks::None`.
    pub jwks: TestJwks,
    /// Remote JWKS URI to register. Default: `None`. Required for clients whose
    /// keys are resolved through the JWKS cache, which is only ever populated
    /// by fetching this URI.
    pub jwks_uri: Option<String>,
    /// Require DPoP-bound access tokens. Default: `false`.
    pub dpop_bound_access_tokens: bool,
    /// Allowed grant types override. Default: `None`.
    pub grant_types: Option<Vec<String>>,
    /// FAPI security profile. Default: `None` (→ FapiProfile::None).
    pub fapi_profile: Option<crate::db::FapiProfile>,
    /// ID-token signing algorithm. Default: `JwsAlgorithm::Rs256`.
    pub id_token_signed_response_alg: crate::crypto::alg::JwsAlgorithm,
    /// mTLS subject DN for `tls_client_auth`. Default: `None`.
    pub tls_client_auth_subject_dn: Option<String>,
    /// Bind issued tokens to the mTLS certificate. Default: `false`.
    pub tls_client_certificate_bound_access_tokens: bool,
    /// UserInfo JWT signing algorithm override. Default: `None`.
    pub userinfo_signed_response_alg: Option<crate::crypto::alg::JwsAlgorithm>,
    /// Introspection JWT signing algorithm override. Default: `None`.
    pub introspection_signed_response_alg: Option<crate::crypto::alg::JwsAlgorithm>,
    /// JARM response signing algorithm override. Default: `None` (ES256).
    pub authorization_signed_response_alg: Option<crate::crypto::alg::JwsAlgorithm>,
    /// Whether to mint a client secret. `false` for public/SPA clients. Default: `true`.
    pub with_secret: bool,
    /// Restrict request-object signing algorithm. Default: `None`.
    pub request_object_signing_alg: Option<crate::crypto::alg::JwsAlgorithm>,
    /// Require a signed request object (JAR). Default: `None`.
    pub require_signed_request_object: Option<bool>,
    /// Registered post-logout redirect URIs (RP-Initiated Logout). Default: empty.
    pub post_logout_redirect_uris: Vec<String>,
    /// RFC 7592 registration access token hash. Default: `None` (no RFC 7592
    /// management access — `lookup_and_verify_registration_token` treats a
    /// client with no stored hash as `invalid_token`). Set this to exercise
    /// the RFC 7592 GET/PUT/DELETE endpoints against a client built through
    /// this factory rather than through `/oauth/register`.
    pub registration_access_token_hash: Option<String>,
}

impl Default for TestClientSpec {
    fn default() -> Self {
        Self {
            name: "Test App".to_string(),
            application_type: crate::db::OAuthClientType::Web,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            // Intentionally Public, not AccessScope::default() which is Personal.
            access_scope: crate::db::AccessScope::Public,
            org_id: Option::None,
            resource_uris: vec![],
            token_endpoint_auth_method: Option::None,
            jwks: TestJwks::None,
            jwks_uri: Option::None,
            dpop_bound_access_tokens: false,
            grant_types: Option::None,
            fapi_profile: Option::None,
            id_token_signed_response_alg: crate::crypto::alg::JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: Option::None,
            tls_client_certificate_bound_access_tokens: false,
            userinfo_signed_response_alg: Option::None,
            introspection_signed_response_alg: Option::None,
            authorization_signed_response_alg: Option::None,
            with_secret: true,
            request_object_signing_alg: Option::None,
            require_signed_request_object: Option::None,
            post_logout_redirect_uris: vec![],
            registration_access_token_hash: Option::None,
        }
    }
}

/// Result of creating a test OAuth client with credentials.
pub struct TestOAuthClient {
    /// The internal application ID (database primary key).
    pub app_id: String,
    /// The client_id.
    pub client_id: String,
    /// The plaintext client secret.
    pub client_secret: String,
}

impl TestOAuthClient {
    /// Build a `Basic` authorization header value for this client.
    pub fn basic_auth_header(&self) -> String {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        let creds = format!("{}:{}", self.client_id, self.client_secret);
        format!("Basic {}", STANDARD.encode(creds))
    }
}

/// Create a test OAuth client from a [`TestClientSpec`].
///
/// This is the canonical factory. All other `create_test_*_oauth_client`
/// helpers delegate here.
pub async fn create_test_client(
    store: &DocumentStore,
    user_id: &str,
    spec: TestClientSpec,
) -> TestOAuthClient {
    use aws_lc_rs::rand as aws_rand;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Resolve the JWKS value from the spec variant.
    let jwks_value: Option<serde_json::Value> = match spec.jwks {
        TestJwks::None => Option::None,
        TestJwks::Shared => Some(TEST_HTTPSIG.jwks.clone()),
        TestJwks::Custom(v) => Some(v),
    };

    // `TestClientSpec` still offers the two knobs separately; pairing them here
    // is what a caller setting both would trip on, which mirrors the endpoints.
    let client_keys = crate::db::ClientKeys::from_stored(jwks_value, spec.jwks_uri.clone())
        .expect("test spec sets jwks or jwks_uri, never both");

    let (client, client_id) = crate::db::create_oauth_client(
        store,
        &CreateOAuthClientParams {
            user_id: Some(user_id),
            name: &spec.name,
            description: Option::None,
            application_type: spec.application_type,
            redirect_uris: &spec.redirect_uris,
            access_scope: spec.access_scope,
            org_id: spec.org_id.as_deref(),
            resource_uris: &spec.resource_uris,
            token_endpoint_auth_method: spec.token_endpoint_auth_method.unwrap_or_default(),
            keys: client_keys.as_ref(),
            fapi_profile: spec.fapi_profile,
            dpop_bound_access_tokens: if spec.dpop_bound_access_tokens {
                Some(true)
            } else {
                Option::None
            },
            grant_types: spec.grant_types.as_deref(),
            response_types: Option::None,
            software_id: Option::None,
            software_version: Option::None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: spec.registration_access_token_hash.as_deref(),
            registration_metadata: Option::None,
            id_token_signed_response_alg: spec.id_token_signed_response_alg,
            tls_client_auth_subject_dn: spec.tls_client_auth_subject_dn.as_deref(),
            tls_client_auth_san_dns: Option::None,
            tls_client_auth_san_uri: Option::None,
            tls_client_auth_san_ip: Option::None,
            tls_client_auth_san_email: Option::None,
            tls_client_certificate_bound_access_tokens: if spec
                .tls_client_certificate_bound_access_tokens
            {
                Some(true)
            } else {
                Option::None
            },
            authorization_signed_response_alg: spec.authorization_signed_response_alg,
            introspection_signed_response_alg: spec.introspection_signed_response_alg,
            request_object_signing_alg: spec.request_object_signing_alg,
            require_signed_request_object: spec.require_signed_request_object,
            userinfo_signed_response_alg: spec.userinfo_signed_response_alg,
            request_uris: Option::None,
            post_logout_redirect_uris: if spec.post_logout_redirect_uris.is_empty() {
                Option::None
            } else {
                Some(spec.post_logout_redirect_uris.clone())
            },
        },
    )
    .await
    .expect("Failed to create test OAuth client");

    // Mint a client secret when requested (secret clients only).
    let secret = if spec.with_secret {
        let mut secret_bytes = [0u8; 32];
        aws_rand::fill(&mut secret_bytes).expect("RNG failure");
        let raw = URL_SAFE_NO_PAD.encode(secret_bytes);
        let secret_hash = crate::handlers::hash_token(&raw);
        crate::db::create_oauth_client_secret(store, &client.id, &secret_hash, Some("test"), None)
            .await
            .expect("Failed to create test OAuth client secret");
        raw
    } else {
        String::new()
    };

    TestOAuthClient {
        app_id: client.id,
        client_id,
        client_secret: secret,
    }
}

/// Create a test OAuth client with a secret for use in tests.
pub async fn create_test_oauth_client(store: &DocumentStore, user_id: &str) -> TestOAuthClient {
    create_test_client(store, user_id, TestClientSpec::default()).await
}

/// Spec for a pending OAuth authorization — the record the deferred authorize
/// flow parks between the first `/oauth/authorize` leg and `/login`. The
/// default is the ordinary case: `openid` scope, query response mode, no
/// forced re-auth.
#[derive(Default)]
pub struct TestPendingAuthSpec<'a> {
    /// Client the authorization belongs to. Required — the default is empty.
    pub client_id: &'a str,
    /// Space-delimited OIDC prompt set stored on the request. Default: `None`.
    pub prompt: Option<&'a str>,
    /// RFC 9470 maximum authentication age. Default: `None`.
    pub max_age: Option<i64>,
}

/// Store a pending OAuth authorization and return its id.
pub async fn create_test_pending_auth(
    store: &DocumentStore,
    spec: TestPendingAuthSpec<'_>,
) -> String {
    crate::db::create_pending_oauth_authorization(
        store,
        crate::db::CreatePendingOAuthParams {
            client_id: spec.client_id,
            redirect_uri: "https://example.com/callback",
            response_type: "code",
            state: None,
            scope: Some("openid"),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            max_age: spec.max_age,
            prompt: spec.prompt,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: Default::default(),
            par_request_uri: None,
        },
    )
    .await
    .expect("create pending oauth authorization")
}

/// Create a public OAuth client (no client secret, `token_endpoint_auth_method=none`).
pub async fn create_test_public_oauth_client(
    store: &DocumentStore,
    user_id: &str,
) -> TestOAuthClient {
    create_test_client(
        store,
        user_id,
        TestClientSpec {
            name: "Public Test App".to_string(),
            application_type: crate::db::OAuthClientType::Spa,
            token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::None),
            with_secret: false,
            ..Default::default()
        },
    )
    .await
}

// ============================================================================
// JWT Test Helpers (shared between crypto::jwt and services::auth tests)
// ============================================================================

/// JWT secret for unit tests. NOT a real secret.
pub const TEST_JWT_SECRET: &[u8] = b"test-jwt-secret-for-unit-tests-only";

/// Issuer URL for unit tests.
pub const TEST_ISSUER: &str = "https://example.com";

/// Generate a fresh OIDC signing key for tests.
/// Fuzzing entry: run arbitrary policy text through the production
/// validation path (compose + lower + validate against the embedded Vouch
/// schema). Must never panic — admin-supplied policy text reaches this
/// path, and the release profile is `panic = "abort"`.
pub fn fuzz_validate_policy_text(text: &str) {
    let _result = crate::services::policy::validate_policy_text(text);
}

/// Fuzzing entry: run arbitrary history-event shapes through the runtime
/// evaluation path (`Authorizer::is_authorized` over a replayed trace) with
/// every temporal policy active. This is the path that executes on each
/// login and token exchange, and it must never panic — the release profile
/// is `panic = "abort"`, so a panic here takes down every org on the
/// replica, not just the triggering request.
///
/// `rows` are `(event_type, user_id, data_json, secs_offset)` tuples, mapped
/// through the same ingestion the production path uses.
pub fn fuzz_evaluate_history(rows: &[(String, String, String, i64)]) {
    crate::services::policy::fuzz_evaluate_history(rows);
}

pub fn make_test_oidc_key() -> OidcSigningKey {
    OidcSigningKey::generate().expect("generate key")
}

/// Create a test ES256 access token signed by the given OIDC key.
pub async fn make_test_access_token(key: &OidcSigningKey) -> String {
    use crate::services::auth::AccessTokenClaims;
    use crate::services::oidc::ScopeSet;

    let claims = AccessTokenClaims {
        iss: TEST_ISSUER.to_string(),
        sub: "user-123".to_string(),
        aud: "client-abc".to_string(),
        exp: 9_999_999_999,
        iat: 1_000_000_000,
        nbf: None,
        jti: "jti-1".to_string(),
        client_id: "client-abc".to_string(),
        scope: Some(ScopeSet::parse("openid email")),
        email: Some("test@example.com".to_string()),
        email_verified: Some(true),
        hardware_verified: true,
        cnf: None,
        auth_time: None,
        act: None,
        amr: None,
        acr: None,
    };
    key.sign_access_token_jwt(&claims).await.expect("sign")
}

/// Build a JWT assertion for `private_key_jwt` client auth (RFC 7523
/// Section 2.2), signed ES256 with `kid: "test-key-1"`.
///
/// `jti: None` generates a fresh UUID so repeated calls do not trip replay
/// protection; pass `Some(..)` to exercise replay handling deliberately.
#[must_use]
pub fn build_client_assertion(
    client_id: &str,
    audience: &str,
    pkcs8_bytes: &[u8],
    jti: Option<&str>,
) -> String {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes)
        .expect("parse ES256 key");

    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": "test-key-1" });
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now.saturating_add(60),
        "jti": jti.map_or_else(|| uuid::Uuid::now_v7().to_string(), str::to_string)
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("encode header"));
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("encode claims"));
    let signing_input = format!("{header_b64}.{claims_b64}");

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("sign assertion");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    format!("{header_b64}.{claims_b64}.{sig_b64}")
}
