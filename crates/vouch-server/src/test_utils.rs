// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Test utilities for RFC compliance testing.
//!
//! This module provides shared test infrastructure for handler tests.

// Tests are allowed to use expect/unwrap on failures
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

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

use crate::crypto::document_crypto::PlaintextDocumentCrypto;
use crate::db::audit::AuditStore;
use crate::db::store::DocumentStore;
use crate::db::{CreateOAuthClientParams, JwsAlgorithm, Pool, RegistrationSource};
use crate::infra::router::build_app;

use crate::AppState;
use crate::config::ServerConfig;
use crate::services::oidc::OidcSigningKey;

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
        oidc_issuer_url: Some("https://accounts.google.com".to_string()),
        oidc_client_id: Some("test-client-id".to_string()),
        oidc_client_secret: Some(SecretString::from("test-client-secret")),
        saml_idp_metadata_url: None,
        saml_sp_entity_id: None,
        saml_email_attribute: None,
        saml_domain_attribute: None,
        base_url: "https://test.example.com".to_string(),
        device_code_expires_seconds: 600,
        device_poll_interval_seconds: 5,
        allowed_domains: Some(vec!["example.com".to_string()]),
        org_name: Some("Test Org".to_string()),
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
        jwt_assertion_max_lifetime_seconds: 300,
        allowed_aaguids: vouch_common::AaguidPolicy::Any,
        require_attestation_cert: false,
        log_format: crate::config::LogFormat::Text,
        trusted_proxies: Vec::new(),
        metrics_bearer_token: None,
        certification_test_token: None,
        pool_config: crate::db::pool::PoolConfig::default(),
        session_cache_max_capacity: 10_000,
        session_cache_ttl_secs: 30,
    }
}

/// Create a test AppState with in-memory database.
pub async fn test_app_state() -> Arc<AppState> {
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
    let store = DocumentStore::new(pool.clone(), crypto.clone());
    let audit = AuditStore::new(pool.clone(), crypto);

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
        upstream_idp: None,
    })
}

/// Create test app (router + state) for handler testing.
pub async fn test_app() -> (Router, Arc<AppState>) {
    let state = test_app_state().await;
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

/// Create a test authenticator for a user.
pub async fn create_test_authenticator(store: &DocumentStore, user_id: &str) -> String {
    crate::db::create_authenticator(
        store,
        user_id,
        "test@example.com",
        "Test Key",
        format!("test-cred-{}", uuid::Uuid::now_v7()).as_bytes(),
        &[0u8; 32],
        None,
        Some(user_id.as_bytes()),
        false,
    )
    .await
    .expect("Failed to create authenticator")
}

/// Create a test session with an OAuth access token stored in the database.
///
/// Returns the raw access token string. Uses the real `create_oauth_access_token`
/// service function with ES256 signing so the token validates through the full
/// token validation pipeline.
pub async fn create_test_session(
    state: &AppState,
    user_id: &str,
    email: &str,
    auth_id: &str,
) -> String {
    use crate::services::auth::{CreateOAuthTokenParams, create_oauth_access_token};
    use crate::services::oidc::ScopeSet;
    use secrecy::ExposeSecret;

    let result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id,
            email,
            authenticator_id: Some(auth_id),
            client_id: &state.config().base_url,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: Some(jiff::Timestamp::now().as_second()),
            amr: None,
            acr: None,
            hardware_verified: true,
            session_purpose: crate::db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
        },
    )
    .await
    .expect("Failed to create test session");

    result.token.expose_secret().to_string()
}

/// Create a test session with a custom `iat`-equivalent auth_time.
///
/// Used for step-up authentication tests (RFC 9470) where the auth_time
/// relative to now determines whether the operation is allowed.
pub async fn create_test_session_with_iat(
    state: &AppState,
    user_id: &str,
    email: &str,
    auth_id: &str,
    iat: i64,
) -> String {
    use crate::services::auth::{CreateOAuthTokenParams, create_oauth_access_token};
    use crate::services::oidc::ScopeSet;
    use secrecy::ExposeSecret;

    let result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id,
            email,
            authenticator_id: Some(auth_id),
            client_id: &state.config().base_url,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: Some(iat),
            amr: None,
            acr: None,
            hardware_verified: true,
            session_purpose: crate::db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
        },
    )
    .await
    .expect("Failed to create test session");

    result.token.expose_secret().to_string()
}

/// Create a test session bound to a specific OAuth client.
///
/// Used for tests that require the token's `client_id` to match a specific
/// OAuth client (e.g., introspection cross-client checks).
pub async fn create_test_session_for_client(
    state: &AppState,
    user_id: &str,
    email: &str,
    auth_id: &str,
    client_id: &str,
) -> String {
    use crate::services::auth::{CreateOAuthTokenParams, create_oauth_access_token};
    use crate::services::oidc::ScopeSet;
    use secrecy::ExposeSecret;

    let result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id,
            email,
            authenticator_id: Some(auth_id),
            client_id,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: Some(jiff::Timestamp::now().as_second()),
            amr: None,
            acr: None,
            hardware_verified: true,
            session_purpose: crate::db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
        },
    )
    .await
    .expect("Failed to create test session");

    result.token.expose_secret().to_string()
}

/// Create a test session with a DPoP binding (sender-constrained token).
///
/// The token will have a `cnf.jkt` claim, making it a sender-constrained
/// token that requires DPoP proof for validation.
pub async fn create_test_session_with_dpop(
    state: &AppState,
    user_id: &str,
    email: &str,
    auth_id: &str,
    dpop_jkt: &str,
) -> String {
    use crate::services::auth::{CreateOAuthTokenParams, create_oauth_access_token};
    use crate::services::oidc::ScopeSet;
    use secrecy::ExposeSecret;

    let result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id,
            email,
            authenticator_id: Some(auth_id),
            client_id: &state.config().base_url,
            scope: Some(ScopeSet::all()),
            dpop_jkt: Some(dpop_jkt),
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: Some(jiff::Timestamp::now().as_second()),
            amr: None,
            acr: None,
            hardware_verified: true,
            session_purpose: crate::db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
        },
    )
    .await
    .expect("Failed to create DPoP-bound test session");

    result.token.expose_secret().to_string()
}

/// Create an mTLS certificate-bound access token for testing.
///
/// The token includes `cnf.x5t#S256` set to `mtls_cert_thumbprint`, binding it to
/// the certificate identified by that thumbprint per RFC 8705 Section 3.1.
pub async fn create_test_session_with_mtls(
    state: &AppState,
    user_id: &str,
    email: &str,
    auth_id: &str,
    mtls_cert_thumbprint: &str,
) -> String {
    use crate::services::auth::{CreateOAuthTokenParams, create_oauth_access_token};
    use crate::services::oidc::ScopeSet;
    use secrecy::ExposeSecret;

    let result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id,
            email,
            authenticator_id: Some(auth_id),
            client_id: &state.config().base_url,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            mtls_cert_thumbprint: Some(mtls_cert_thumbprint),
            act: None,
            audience: None,
            auth_time: Some(jiff::Timestamp::now().as_second()),
            amr: None,
            acr: None,
            hardware_verified: true,
            session_purpose: crate::db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
        },
    )
    .await
    .expect("Failed to create mTLS-bound test session");

    result.token.expose_secret().to_string()
}

/// Create a SCIM bearer token for testing.
pub async fn create_test_scim_token(store: &DocumentStore, description: &str) -> String {
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

    // Store in database
    crate::db::create_scim_token(store, &token_hash, Some(description), None, None, None)
        .await
        .expect("Failed to create SCIM token");

    token
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

/// Create a test OAuth client with a secret for use in tests.
pub async fn create_test_oauth_client(store: &DocumentStore, user_id: &str) -> TestOAuthClient {
    use aws_lc_rs::rand as aws_rand;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let (client, client_id) = crate::db::create_oauth_client(
        store,
        &CreateOAuthClientParams {
            user_id: Some(user_id),
            name: "Test App",
            description: None,
            application_type: crate::db::OAuthClientType::Web,
            redirect_uris: &["https://example.com/callback".to_string()],
            access_scope: crate::db::AccessScope::Public,
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
        },
    )
    .await
    .expect("Failed to create test OAuth client");

    // Generate a secret
    let mut secret_bytes = [0u8; 32];
    aws_rand::fill(&mut secret_bytes).expect("RNG failure");
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let secret_hash = crate::handlers::hash_token(&secret);

    crate::db::create_oauth_client_secret(store, &client.id, &secret_hash, Some("test"), None)
        .await
        .expect("Failed to create test OAuth client secret");

    TestOAuthClient {
        app_id: client.id,
        client_id,
        client_secret: secret,
    }
}

/// Create a test OAuth client with custom access scope and resource URIs.
pub async fn create_test_oauth_client_with_options(
    store: &DocumentStore,
    user_id: &str,
    access_scope: crate::db::AccessScope,
    org_id: Option<&str>,
    resource_uris: &[String],
) -> TestOAuthClient {
    use aws_lc_rs::rand as aws_rand;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let (client, client_id) = crate::db::create_oauth_client(
        store,
        &CreateOAuthClientParams {
            user_id: Some(user_id),
            name: "Test App",
            description: None,
            application_type: crate::db::OAuthClientType::Web,
            redirect_uris: &["https://example.com/callback".to_string()],
            access_scope,
            org_id,
            resource_uris,
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
        },
    )
    .await
    .expect("Failed to create test OAuth client");

    // Generate a secret
    let mut secret_bytes = [0u8; 32];
    aws_rand::fill(&mut secret_bytes).expect("RNG failure");
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let secret_hash = crate::handlers::hash_token(&secret);

    crate::db::create_oauth_client_secret(store, &client.id, &secret_hash, Some("test"), None)
        .await
        .expect("Failed to create test OAuth client secret");

    TestOAuthClient {
        app_id: client.id,
        client_id,
        client_secret: secret,
    }
}

/// Create a test OAuth client with `userinfo_signed_response_alg` set.
///
/// The returned client will have a client secret for token endpoint auth.
/// Used to verify signed userinfo responses (OIDC Core Section 5.3.4).
pub async fn create_test_oauth_client_with_signed_userinfo(
    store: &DocumentStore,
    user_id: &str,
    alg: JwsAlgorithm,
) -> TestOAuthClient {
    use aws_lc_rs::rand as aws_rand;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let (client, client_id) = crate::db::create_oauth_client(
        store,
        &CreateOAuthClientParams {
            user_id: Some(user_id),
            name: "Signed UserInfo Test App",
            description: None,
            application_type: crate::db::OAuthClientType::Web,
            redirect_uris: &["https://example.com/callback".to_string()],
            access_scope: crate::db::AccessScope::Public,
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Es256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: Some(alg),
        },
    )
    .await
    .expect("Failed to create test OAuth client with signed userinfo");

    // Generate a secret
    let mut secret_bytes = [0u8; 32];
    aws_rand::fill(&mut secret_bytes).expect("RNG failure");
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let secret_hash = crate::handlers::hash_token(&secret);

    crate::db::create_oauth_client_secret(store, &client.id, &secret_hash, Some("test"), None)
        .await
        .expect("Failed to create test OAuth client secret");

    TestOAuthClient {
        app_id: client.id,
        client_id,
        client_secret: secret,
    }
}

/// Create a public OAuth client (no client secret, `token_endpoint_auth_method=none`).
pub async fn create_test_public_oauth_client(
    store: &DocumentStore,
    user_id: &str,
) -> TestOAuthClient {
    let (client, client_id) = crate::db::create_oauth_client(
        store,
        &CreateOAuthClientParams {
            user_id: Some(user_id),
            name: "Public Test App",
            description: None,
            application_type: crate::db::OAuthClientType::Spa,
            redirect_uris: &["https://example.com/callback".to_string()],
            access_scope: crate::db::AccessScope::Public,
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::None),
            jwks: None,
            jwks_uri: None,
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
        },
    )
    .await
    .expect("Failed to create test public OAuth client");

    TestOAuthClient {
        app_id: client.id,
        client_id,
        client_secret: String::new(),
    }
}

// ============================================================================
// JWT Test Helpers (shared between crypto::jwt and services::auth tests)
// ============================================================================

/// JWT secret for unit tests. NOT a real secret.
pub const TEST_JWT_SECRET: &[u8] = b"test-jwt-secret-for-unit-tests-only";

/// Issuer URL for unit tests.
pub const TEST_ISSUER: &str = "https://example.com";

/// Generate a fresh OIDC signing key for tests.
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
