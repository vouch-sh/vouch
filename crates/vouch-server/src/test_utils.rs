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

use arc_swap::ArcSwap;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::{delete, get, post},
};
use secrecy::SecretString;
use std::sync::Arc;
use tower::ServiceExt;

use crate::db::{CreateOAuthClientParams, Pool, RegistrationSource};

use crate::AppState;
use crate::config::ServerConfig;
use crate::handlers;
use crate::services::oidc::OidcSigningKey;

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
        oidc_signing_key: None,
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

    Arc::new(AppState {
        db: pool,
        config: Arc::new(ArcSwap::from_pointee(config)),
        webauthn,
        ssh_ca: None,
        oidc_key,
        github_app: None,
        http_client: reqwest::Client::new(),
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
        // RFC 8414 Section 3: OAuth Authorization Server Metadata alias
        .route(
            "/.well-known/oauth-authorization-server",
            get(handlers::oidc::discovery),
        )
        .route("/oauth/jwks", get(handlers::oidc::jwks))
        .route("/oauth/authorize", get(handlers::oidc::authorize))
        // OIDC Core Section 5.3.1: UserInfo MUST support GET and POST
        .route(
            "/oauth/userinfo",
            get(handlers::oidc::userinfo).post(handlers::oidc::userinfo),
        )
        .route("/oauth/revoke", post(handlers::oidc::revoke))
        .route("/oauth/introspect", post(handlers::oidc::introspect))
        .route("/oauth/token", post(handlers::oidc::token))
        // Pushed Authorization Request (RFC 9126)
        .route("/oauth/par", post(handlers::oidc::par))
        // Device Authorization Grant (RFC 8628)
        .route("/oauth/device", post(handlers::device::device_code))
        // RFC 7591 Dynamic Client Registration
        .route("/oauth/register", post(handlers::oidc::register))
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
            "/v1/integrations/aws",
            get(handlers::integrations::get_aws_integration)
                .put(handlers::integrations::set_aws_integration)
                .delete(handlers::integrations::delete_aws_integration),
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

/// Create a valid test JWT session token.
pub fn create_test_token(state: &AppState, user_id: &str, email: &str, auth_id: &str) -> String {
    use jiff::{Span, Timestamp};
    use jsonwebtoken::{EncodingKey, encode};

    let now = Timestamp::now();
    let exp = now
        .checked_add(Span::new().hours(8))
        .map(|t| t.as_second())
        .unwrap_or(now.as_second() + 28800);

    let base_url = state.config().base_url.clone();
    let claims = crate::services::auth::SessionClaims {
        iss: base_url.clone(),
        aud: base_url,
        sub: user_id.to_string(),
        email: email.to_string(),
        authenticator_id: Some(auth_id.to_string()),
        iat: now.as_second(),
        exp,
        purpose: crate::db::SessionPurpose::Fido2Session,
        scope: None,
    };

    encode(
        &crate::crypto::jwt::JwtType::Session.to_header(),
        &claims,
        &EncodingKey::from_secret(state.config().jwt_secret_bytes()),
    )
    .expect("Failed to encode test token")
}

/// Create a test JWT session token with a custom `iat` timestamp.
///
/// Used for step-up authentication tests (RFC 9470) where the session age
/// relative to `iat` determines whether the operation is allowed.
pub fn create_test_token_with_iat(
    state: &AppState,
    user_id: &str,
    email: &str,
    auth_id: &str,
    iat: i64,
) -> String {
    use jsonwebtoken::{EncodingKey, encode};

    let session_hours = i64::try_from(state.config().session_hours).unwrap_or(8);
    let exp = iat + session_hours * 3600;

    let base_url = state.config().base_url.clone();
    let claims = crate::services::auth::SessionClaims {
        iss: base_url.clone(),
        aud: base_url,
        sub: user_id.to_string(),
        email: email.to_string(),
        authenticator_id: Some(auth_id.to_string()),
        iat,
        exp,
        purpose: crate::db::SessionPurpose::Fido2Session,
        scope: None,
    };

    encode(
        &crate::crypto::jwt::JwtType::Session.to_header(),
        &claims,
        &EncodingKey::from_secret(state.config().jwt_secret_bytes()),
    )
    .expect("Failed to encode test token")
}

/// Create a test session with a custom `iat` timestamp stored in the database.
///
/// Like `create_test_session`, but accepts a custom `iat` value for testing
/// step-up authentication (RFC 9470) where the session must be fresh.
pub async fn create_test_session_with_iat(
    state: &AppState,
    user_id: &str,
    email: &str,
    auth_id: &str,
    iat: i64,
) -> String {
    use aws_lc_rs::digest::{self, SHA256};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jiff::Timestamp;

    let token = create_test_token_with_iat(state, user_id, email, auth_id, iat);

    // Hash the token for database storage
    let hash = digest::digest(&SHA256, token.as_bytes());
    let token_hash = URL_SAFE_NO_PAD.encode(hash.as_ref());

    // Calculate expiration from iat
    let session_hours = i64::try_from(state.config().session_hours).unwrap_or(8);
    let expires_ts = iat + session_hours * 3600;
    let expires = Timestamp::from_second(expires_ts).unwrap_or_else(|_| Timestamp::now());

    // Store session in database
    crate::db::create_session(
        &state.db,
        user_id,
        &token_hash,
        Some(auth_id),
        &expires.to_string(),
        crate::db::SessionPurpose::Fido2Session,
    )
    .await
    .expect("Failed to create session");

    token
}

/// Create an expired test JWT session token.
#[allow(dead_code)]
pub fn create_expired_token(state: &AppState, user_id: &str, email: &str, auth_id: &str) -> String {
    use jiff::Timestamp;
    use jsonwebtoken::{EncodingKey, encode};

    let now = Timestamp::now();

    let base_url = state.config().base_url.clone();
    let claims = crate::services::auth::SessionClaims {
        iss: base_url.clone(),
        aud: base_url,
        sub: user_id.to_string(),
        email: email.to_string(),
        authenticator_id: Some(auth_id.to_string()),
        iat: now.as_second() - 36000, // 10 hours ago
        exp: now.as_second() - 3600,  // 1 hour ago (expired)
        purpose: crate::db::SessionPurpose::Fido2Session,
        scope: None,
    };

    encode(
        &crate::crypto::jwt::JwtType::Session.to_header(),
        &claims,
        &EncodingKey::from_secret(state.config().jwt_secret_bytes()),
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
        crate::db::SessionPurpose::Fido2Session,
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
    crate::db::create_scim_token(pool, &token_hash, Some(description), None, None, None)
        .await
        .expect("Failed to create SCIM token");

    token
}

/// Result of creating a test OAuth client with credentials.
pub struct TestOAuthClient {
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
pub async fn create_test_oauth_client(pool: &Pool, user_id: &str) -> TestOAuthClient {
    use aws_lc_rs::rand as aws_rand;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let (client, client_id) = crate::db::create_oauth_client(
        pool,
        &CreateOAuthClientParams {
            user_id,
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
        },
    )
    .await
    .expect("Failed to create test OAuth client");

    // Generate a secret
    let mut secret_bytes = [0u8; 32];
    aws_rand::fill(&mut secret_bytes).expect("RNG failure");
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let secret_hash = crate::handlers::hash_token(&secret);

    crate::db::create_oauth_client_secret(pool, &client.id, &secret_hash, Some("test"), None)
        .await
        .expect("Failed to create test OAuth client secret");

    TestOAuthClient {
        client_id,
        client_secret: secret,
    }
}

/// Create a test OAuth client with custom access scope and resource URIs.
pub async fn create_test_oauth_client_with_options(
    pool: &Pool,
    user_id: &str,
    access_scope: crate::db::AccessScope,
    org_id: Option<&str>,
    resource_uris: &[String],
) -> TestOAuthClient {
    use aws_lc_rs::rand as aws_rand;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let (client, client_id) = crate::db::create_oauth_client(
        pool,
        &CreateOAuthClientParams {
            user_id,
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
        },
    )
    .await
    .expect("Failed to create test OAuth client");

    // Generate a secret
    let mut secret_bytes = [0u8; 32];
    aws_rand::fill(&mut secret_bytes).expect("RNG failure");
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let secret_hash = crate::handlers::hash_token(&secret);

    crate::db::create_oauth_client_secret(pool, &client.id, &secret_hash, Some("test"), None)
        .await
        .expect("Failed to create test OAuth client secret");

    TestOAuthClient {
        client_id,
        client_secret: secret,
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
pub fn make_test_access_token(key: &OidcSigningKey) -> String {
    use crate::services::auth::AccessTokenClaims;
    use crate::services::oidc::scope::ScopeSet;

    let claims = AccessTokenClaims {
        iss: TEST_ISSUER.to_string(),
        sub: "user-123".to_string(),
        aud: "client-abc".to_string(),
        exp: 9_999_999_999,
        iat: 1_000_000_000,
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
    key.sign_access_token_jwt(&claims).expect("sign")
}

/// Create a test HS256 session token.
pub fn make_test_session_token() -> String {
    use crate::services::auth::SessionClaims;
    use jsonwebtoken::{EncodingKey, encode};

    let claims = SessionClaims {
        iss: TEST_ISSUER.to_string(),
        aud: TEST_ISSUER.to_string(),
        sub: "user-456".to_string(),
        email: "session@example.com".to_string(),
        authenticator_id: Some("auth-1".to_string()),
        iat: 1_000_000_000,
        exp: 9_999_999_999,
        purpose: crate::db::SessionPurpose::Fido2Session,
        scope: None,
    };
    encode(
        &crate::crypto::jwt::JwtType::Session.to_header(),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET),
    )
    .expect("encode")
}
