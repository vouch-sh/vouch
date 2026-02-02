// SPDX-License-Identifier: BUSL-1.1
//! Test utilities for RFC compliance testing.
//!
//! This module provides shared test infrastructure for handler tests.

// Tests are allowed to panic on failures
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::{delete, get, post},
};
use secrecy::SecretString;
use std::sync::Arc;
use tower::ServiceExt;

use crate::db::Pool;

use crate::AppState;
use crate::config::ServerConfig;
use crate::dpop::DpopState;
use crate::handlers;
use crate::oidc_key::OidcSigningKey;

/// Create an in-memory SQLite database with migrations for testing.
pub async fn test_db() -> Pool {
    let pool = Pool::connect("sqlite::memory:")
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
        verification_base_url: "https://test.example.com".to_string(),
        device_code_expires_seconds: 600,
        device_poll_interval_seconds: 5,
        allowed_domains: Some(vec!["example.com".to_string()]),
        org_name: Some("Test Org".to_string()),
        cli_download_macos: None,
        cli_download_linux: None,
        cli_download_windows: None,
        ssh_ca_key_path: None,
        ssh_ca_key: None,
        oidc_signing_key: None,
        dpop_enabled: true,
        dpop_nonce_required: false,
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
    }
}

/// Create a test AppState with in-memory database.
pub async fn test_app_state() -> Arc<AppState> {
    let pool = test_db().await;
    let config = test_config();

    let rp_origin = url::Url::parse(&config.verification_base_url).expect("Invalid RP origin");
    let webauthn = webauthn_rs::WebauthnBuilder::new(&config.rp_id, &rp_origin)
        .expect("Failed to create WebauthnBuilder")
        .rp_name(&config.rp_name)
        .build()
        .expect("Failed to build Webauthn");

    // Generate OIDC signing key for tests
    let oidc_key = OidcSigningKey::generate().expect("Failed to generate test OIDC key");

    Arc::new(AppState {
        db: pool,
        config,
        webauthn,
        ssh_ca: None,
        dpop: DpopState::new(),
        oidc_key,
        github_app: None,
    })
}

/// Build test router with all routes.
pub fn test_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health check
        .route("/health", get(|| async { "ok" }))
        // OIDC Provider endpoints
        .route(
            "/.well-known/openid-configuration",
            get(handlers::oidc::discovery),
        )
        .route("/oauth/jwks", get(handlers::oidc::jwks))
        .route("/oauth/authorize", get(handlers::oidc::authorize))
        .route("/oauth/userinfo", get(handlers::oidc::userinfo))
        .route("/oauth/revoke", post(handlers::oidc::revoke))
        .route("/oauth/introspect", post(handlers::oidc::introspect))
        .route("/oauth/token", post(handlers::oidc::token))
        // Device Authorization Grant (RFC 8628)
        .route("/oauth/device/code", post(handlers::device::device_code))
        // Legacy auth endpoints
        .route(
            "/v1/auth/register/start",
            post(handlers::auth::register_start),
        )
        .route(
            "/v1/auth/register/complete",
            post(handlers::auth::register_complete),
        )
        .route("/v1/auth/login/start", post(handlers::auth::login_start))
        .route(
            "/v1/auth/login/complete",
            post(handlers::auth::login_complete),
        )
        .route("/v1/auth/status", get(handlers::auth::status))
        // Browser-based enrollment
        .route("/device", get(handlers::enroll::device_verify_page))
        .route("/device", post(handlers::enroll::device_verify_submit))
        .route("/oauth/callback", get(handlers::enroll::oidc_callback))
        .route("/logout", post(handlers::auth::logout))
        .route(
            "/enroll/webauthn/start",
            post(handlers::enroll::browser_register_start),
        )
        .route(
            "/enroll/webauthn/complete",
            post(handlers::enroll::browser_register_complete),
        )
        // Key management
        .route("/v1/keys", get(handlers::keys::list_keys))
        .route("/v1/keys/{id}", delete(handlers::keys::delete_key))
        // Credential issuance
        .route(
            "/v1/credentials/ssh",
            post(handlers::credentials::issue_ssh_certificate),
        )
        .route(
            "/v1/credentials/ssh/ca",
            get(handlers::credentials::get_ssh_ca_public_key),
        )
        .route(
            "/v1/credentials/aws/token",
            get(handlers::credentials::get_aws_token),
        )
        // Org admin API (JSON, JWT Bearer auth)
        .route(
            "/api/v1/org/auth-events",
            get(handlers::admin::list_auth_events),
        )
        .route(
            "/api/v1/org/scim-tokens",
            get(handlers::admin::list_scim_tokens).post(handlers::admin::create_scim_token),
        )
        .route(
            "/api/v1/org/scim-tokens/{id}",
            delete(handlers::admin::delete_scim_token),
        )
        // SCIM 2.0 endpoints (RFC 7643/7644)
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(handlers::scim::service_provider_config),
        )
        .route("/scim/v2/Schemas", get(handlers::scim::schemas))
        .route(
            "/scim/v2/ResourceTypes",
            get(handlers::scim::resource_types),
        )
        .route(
            "/scim/v2/Users",
            get(handlers::scim::list_users).post(handlers::scim::create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(handlers::scim::get_user)
                .patch(handlers::scim::patch_user)
                .delete(handlers::scim::delete_user),
        )
        // OAuth Application Registration Portal
        .route(
            "/applications",
            get(handlers::applications::list_applications_page),
        )
        .route(
            "/applications/new",
            get(handlers::applications::create_application_page)
                .post(handlers::applications::create_application_form),
        )
        .route(
            "/applications/{id}",
            get(handlers::applications::detail_application_page)
                .post(handlers::applications::update_application_form),
        )
        .route(
            "/applications/{id}/delete",
            post(handlers::applications::delete_application_form),
        )
        .route(
            "/applications/{id}/rotate",
            post(handlers::applications::rotate_secret_form),
        )
        // Applications API (JSON)
        .route(
            "/api/v1/applications",
            get(handlers::applications::list_applications_api)
                .post(handlers::applications::create_application_api),
        )
        .route(
            "/api/v1/applications/{id}",
            get(handlers::applications::get_application_api)
                .patch(handlers::applications::update_application_api)
                .delete(handlers::applications::delete_application_api),
        )
        .route(
            "/api/v1/applications/{id}/rotate",
            post(handlers::applications::rotate_secret_api),
        )
        .route(
            "/api/v1/applications/{id}/revoke",
            post(handlers::applications::revoke_tokens_api),
        )
        // Cloud integration config API
        .route(
            "/v1/integrations/gcp",
            get(handlers::integrations::get_gcp_integration)
                .put(handlers::integrations::set_gcp_integration)
                .delete(handlers::integrations::delete_gcp_integration),
        )
        .route(
            "/v1/integrations/aws",
            get(handlers::integrations::get_aws_integration)
                .put(handlers::integrations::set_aws_integration)
                .delete(handlers::integrations::delete_aws_integration),
        )
        // GCP token endpoint
        .route(
            "/v1/credentials/gcp/token",
            get(handlers::credentials::get_gcp_token),
        )
        // Kubernetes token endpoint
        .route(
            "/v1/credentials/k8s/token",
            get(handlers::credentials::get_k8s_token),
        )
        .with_state(state)
}

/// Create test app (router + state) for handler testing.
pub async fn test_app() -> (Router, Arc<AppState>) {
    let state = test_app_state().await;
    let router = test_router(state.clone());
    (router, state)
}

/// Helper for making test HTTP requests.
pub async fn http_request(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<String>,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut req_builder = Request::builder().method(method).uri(uri);

    for (name, value) in headers {
        req_builder = req_builder.header(*name, *value);
    }

    let body = match body {
        Some(b) => Body::from(b),
        None => Body::empty(),
    };

    let request = req_builder.body(body).expect("Failed to build request");

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

/// Helper for making GET requests.
pub async fn http_get(app: &Router, uri: &str, headers: &[(&str, &str)]) -> (StatusCode, String) {
    http_request(app, "GET", uri, None, headers).await
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

/// Create a valid test JWT session token.
pub fn create_test_token(state: &AppState, user_id: &str, email: &str, auth_id: &str) -> String {
    use jiff::{Span, Timestamp};
    use jsonwebtoken::{EncodingKey, Header, encode};

    let now = Timestamp::now();
    let exp = now
        .checked_add(Span::new().hours(8))
        .map(|t| t.as_second())
        .unwrap_or(now.as_second() + 28800);

    let claims = crate::handlers::auth::SessionClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        authenticator_id: Some(auth_id.to_string()),
        iat: now.as_second(),
        exp,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret_bytes()),
    )
    .expect("Failed to encode test token")
}

/// Create an expired test JWT session token.
#[allow(dead_code)]
pub fn create_expired_token(state: &AppState, user_id: &str, email: &str, auth_id: &str) -> String {
    use jiff::Timestamp;
    use jsonwebtoken::{EncodingKey, Header, encode};

    let now = Timestamp::now();

    let claims = crate::handlers::auth::SessionClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        authenticator_id: Some(auth_id.to_string()),
        iat: now.as_second() - 36000, // 10 hours ago
        exp: now.as_second() - 3600,  // 1 hour ago (expired)
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret_bytes()),
    )
    .expect("Failed to encode test token")
}

/// Create a test user in the database.
pub async fn create_test_user(pool: &Pool, email: &str) -> crate::db::User {
    crate::db::upsert_user(pool, email, Some("Test User"))
        .await
        .expect("Failed to create test user")
}

/// Create a test organization in the database.
pub async fn create_test_org(pool: &Pool, domain: &str) -> crate::db::Organization {
    crate::db::create_organization(pool, domain, Some("Test Org"), None)
        .await
        .expect("Failed to create test org")
}

/// Create a test user with organization membership.
pub async fn create_test_user_in_org(
    pool: &Pool,
    email: &str,
    org_id: &str,
    is_admin: bool,
) -> crate::db::User {
    crate::db::upsert_user_with_org(pool, email, Some("Test User"), Some(org_id), is_admin)
        .await
        .expect("Failed to create test user in org")
}

/// Create a test authenticator for a user.
pub async fn create_test_authenticator(pool: &Pool, user_id: &str) -> String {
    crate::db::create_authenticator(
        pool,
        user_id,
        "Test Key",
        format!("test-cred-{}", uuid::Uuid::now_v7()).as_bytes(),
        &[0u8; 32],
        None,
        Some(user_id.as_bytes()),
    )
    .await
    .expect("Failed to create authenticator")
}

/// Create a test session with token stored in the database.
pub async fn create_test_session(
    state: &AppState,
    user_id: &str,
    email: &str,
    auth_id: &str,
) -> String {
    use aws_lc_rs::digest::{self, SHA256};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jiff::{Span, Timestamp};

    let token = create_test_token(state, user_id, email, auth_id);

    // Hash the token for database storage
    let hash = digest::digest(&SHA256, token.as_bytes());
    let token_hash = URL_SAFE_NO_PAD.encode(hash.as_ref());

    // Calculate expiration
    let now = Timestamp::now();
    let expires = now.checked_add(Span::new().hours(8)).unwrap_or(now);

    // Store session in database
    crate::db::create_session(
        &state.db,
        user_id,
        &token_hash,
        Some(auth_id),
        &expires.to_string(),
    )
    .await
    .expect("Failed to create session");

    token
}

/// Create a SCIM bearer token for testing.
pub async fn create_test_scim_token(pool: &Pool, description: &str) -> String {
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
    crate::db::create_scim_token(pool, &token_hash, Some(description), None, None)
        .await
        .expect("Failed to create SCIM token");

    token
}
