// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7591 — OAuth 2.0 Dynamic Client Registration tests.
//!
//! Tests for the `POST /oauth/register` endpoint, including authentication
//! requirements, happy paths for confidential/public/service clients,
//! metadata echoing, cache headers, validation error codes, and discovery.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc7591>

use super::helpers::*;

// ========================================================================
// Helper
// ========================================================================

/// Create a user + authenticator + session and return a `Bearer <token>` header value.
async fn bearer_token(app_state: &std::sync::Arc<crate::AppState>) -> String {
    let user = create_test_user(&app_state.store, "rfc7591-test@example.com").await;
    let auth_id = create_test_authenticator(&app_state.store, &user.id).await;
    let token = create_test_session(app_state, &user.id, &user.email, &auth_id).await;
    format!("Bearer {token}")
}

/// Create a user with a unique email and return a `Bearer <token>` header value.
async fn bearer_token_unique(app_state: &std::sync::Arc<crate::AppState>, suffix: &str) -> String {
    let email = format!("rfc7591-{suffix}@example.com");
    let user = create_test_user(&app_state.store, &email).await;
    let auth_id = create_test_authenticator(&app_state.store, &user.id).await;
    let token = create_test_session(app_state, &user.id, &user.email, &auth_id).await;
    format!("Bearer {token}")
}

// ========================================================================
// Authentication
// ========================================================================

#[tokio::test]
async fn test_rfc7591_open_registration_succeeds_without_bearer() {
    // RFC 7591 "open registration": POST /oauth/register without a Bearer token
    // succeeds because we allow unauthenticated registration. The resulting
    // client_id alone grants zero access — FIDO2 auth is still required for tokens.
    let (app, _state) = test_app().await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "My App"
    });

    let (status, body) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Open registration should succeed: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        json.get("client_id").is_some(),
        "Response must include client_id"
    );
}

#[tokio::test]
async fn test_rfc7591_rejects_nul_in_software_id() {
    // Postgres/DSQL reject 0x00 in text columns while SQLite stores it; the
    // document store refuses it up front so open (unauthenticated)
    // registration fails identically on every backend instead of a
    // backend-dependent 500 (issue #883).
    let (app, _state) = test_app().await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "software_id": "soft\u{0}ware"
    });

    let (status, body) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "NUL in software_id must be a 400, not a 500: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
    assert!(
        json["error_description"]
            .as_str()
            .unwrap_or_default()
            .contains("software_id"),
        "error_description must name the offending field: {body}"
    );
}

#[tokio::test]
async fn test_rfc7591_register_rejects_expired_token() {
    // Simulate a revoked token by creating a real session then deleting it from the DB.
    // The token is a valid ES256 JWT but has no matching session record, so validation fails.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "rfc7591-expired@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Delete the session to simulate revocation/expiry
    let token_hash = crate::crypto::hash_token(&token);
    crate::db::delete_session_by_token_hash(&state.store, &token_hash)
        .await
        .expect("Failed to delete session");

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
    });

    let response = http_request_full(
        &app,
        "POST",
        "/oauth/register",
        Some(body.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &format!("Bearer {token}")),
        ],
    )
    .await;

    // RFC 6750 §3.1: invalid bearer tokens MUST return `invalid_token`, not
    // `invalid_client`. OAuth client libraries use this distinction to decide
    // whether to retry (invalid_token) or re-prompt (invalid_client).
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "Revoked token → 401"
    );
    let json: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_token",
        "Revoked token must return invalid_token (RFC 6750): {}",
        response.body
    );
    assert_invalid_token_challenge(&response);
}

#[tokio::test]
async fn test_rfc7591_register_rejects_invalid_jwt() {
    let (app, _state) = test_app().await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
    });

    let response = http_request_full(
        &app,
        "POST",
        "/oauth/register",
        Some(body.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer not-a-valid-jwt"),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "Invalid JWT → 401"
    );
    let json: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_token",
        "Invalid JWT must return invalid_token (RFC 6750): {}",
        response.body
    );
    assert_invalid_token_challenge(&response);
}

// ========================================================================
// Happy paths
// ========================================================================

#[tokio::test]
async fn test_rfc7591_register_minimal_confidential_client() {
    let (app, state) = test_app().await;
    let auth = bearer_token(&state).await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "Minimal App"
    });

    let resp = http_request_full(
        &app,
        "POST",
        "/oauth/register",
        Some(body.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(
        resp.status,
        StatusCode::CREATED,
        "Expected 201: {}",
        resp.body
    );

    let json: serde_json::Value = serde_json::from_str(&resp.body).expect("Valid JSON");

    // REQUIRED fields per RFC 7591 Section 3.2.1
    assert!(json["client_id"].is_string(), "client_id required");
    assert_eq!(json["token_endpoint_auth_method"], "client_secret_basic");
    assert!(json["grant_types"].is_array(), "grant_types required");
    assert!(json["response_types"].is_array(), "response_types required");

    // Defaults
    let grant_types = json["grant_types"].as_array().unwrap();
    assert!(grant_types.iter().any(|g| g == "authorization_code"));

    // Confidential client → secret
    assert!(
        json["client_secret"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "Confidential client must receive client_secret"
    );
    assert_eq!(json["client_secret_expires_at"], 0);

    // RFC 7592 prep
    assert!(
        json["registration_access_token"]
            .as_str()
            .is_some_and(|s| s.starts_with("vouch_reg_")),
        "registration_access_token must start with 'vouch_reg_'"
    );
}

#[tokio::test]
async fn test_rfc7591_register_public_native_client() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "public").await;

    let body = serde_json::json!({
        "redirect_uris": ["http://127.0.0.1:8080/callback"],
        "token_endpoint_auth_method": "none",
        "client_name": "Native CLI"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "Public client → 201");
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert_eq!(json["token_endpoint_auth_method"], "none");
    assert!(
        json.get("client_secret").is_none(),
        "Public client must not have client_secret"
    );
    assert!(
        json.get("client_secret_expires_at").is_none(),
        "Public client must not have client_secret_expires_at"
    );
}

#[tokio::test]
async fn test_rfc7591_register_service_account() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "service").await;

    let body = serde_json::json!({
        "grant_types": ["client_credentials"],
        "client_name": "CI Pipeline"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "Service account → 201: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let grant_types = json["grant_types"].as_array().unwrap();
    assert!(grant_types.iter().any(|g| g == "client_credentials"));
}

#[tokio::test]
async fn test_rfc7591_register_echoes_metadata() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "echo").await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "Echo Test App",
        "scope": "openid profile email",
        "contacts": ["admin@example.com", "security@example.com"],
        "software_id": "echo-test-id",
        "software_version": "1.2.3"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert_eq!(json["client_name"], "Echo Test App");
    assert_eq!(json["scope"], "openid profile email");
    assert_eq!(json["contacts"].as_array().unwrap().len(), 2);
    assert_eq!(json["software_id"], "echo-test-id");
    assert_eq!(json["software_version"], "1.2.3");
}

// ========================================================================
// Response headers — RFC 7591 Section 3.2.1
// ========================================================================

#[tokio::test]
async fn test_rfc7591_response_cache_headers() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "cache").await;

    let body = serde_json::json!({
        "grant_types": ["client_credentials"],
        "client_name": "Cache Test"
    });

    let resp = http_request_full(
        &app,
        "POST",
        "/oauth/register",
        Some(body.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(resp.status, StatusCode::CREATED);
    assert_eq!(
        resp.headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-cache, no-store, must-revalidate"),
        "RFC 7591 Section 3.2.1: Cache-Control: no-store"
    );
    assert_eq!(
        resp.headers.get("pragma").and_then(|v| v.to_str().ok()),
        Some("no-cache"),
        "RFC 7591 Section 3.2.1: Pragma: no-cache"
    );
}

#[tokio::test]
async fn test_rfc7591_response_content_type() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "ctype").await;

    let body = serde_json::json!({
        "grant_types": ["client_credentials"],
        "client_name": "Content Type Test"
    });

    let resp = http_request_full(
        &app,
        "POST",
        "/oauth/register",
        Some(body.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(resp.status, StatusCode::CREATED);
    let ct = resp
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok());
    assert!(
        ct.is_some_and(|s| s.contains("application/json")),
        "Response must be application/json, got: {ct:?}"
    );
}

// ========================================================================
// Additional happy paths — grant types, auth methods, redirect URIs
// ========================================================================

/// `client_secret_post` auth method should succeed and issue a secret.
#[tokio::test]
async fn test_rfc7591_register_client_secret_post() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "secret-post").await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "client_secret_post",
        "client_name": "Secret Post App"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["token_endpoint_auth_method"], "client_secret_post");
    assert!(
        json["client_secret"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "client_secret_post must receive a secret"
    );
    assert_eq!(json["client_secret_expires_at"], 0);
}

/// `private_key_jwt` with inline JWKS should succeed without a secret.
#[tokio::test]
async fn test_rfc7591_register_private_key_jwt_with_jwks() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "pkjwt-jwks").await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": {
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "use": "sig",
                "alg": "ES256"
            }]
        },
        "client_name": "PKJ App"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "private_key_jwt with JWKS → 201: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["token_endpoint_auth_method"], "private_key_jwt");
    // private_key_jwt → no client_secret
    assert!(
        json.get("client_secret").is_none(),
        "private_key_jwt must not have client_secret"
    );
    assert!(json["jwks"].is_object(), "JWKS must be echoed back");
}

/// `private_key_jwt` with `jwks_uri` should succeed.
#[tokio::test]
async fn test_rfc7591_register_private_key_jwt_with_jwks_uri() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "pkjwt-uri").await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks_uri": "https://example.com/.well-known/jwks.json",
        "client_name": "PKJ URI App"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["token_endpoint_auth_method"], "private_key_jwt");
    assert_eq!(
        json["jwks_uri"],
        "https://example.com/.well-known/jwks.json"
    );
}

/// Device code grant type should succeed without redirect URIs.
#[tokio::test]
async fn test_rfc7591_register_device_code_grant() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "device").await;

    let body = serde_json::json!({
        "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
        "response_types": [],
        "client_name": "Device App"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Device code grant → 201: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let grant_types = json["grant_types"].as_array().unwrap();
    assert!(
        grant_types
            .iter()
            .any(|g| g == "urn:ietf:params:oauth:grant-type:device_code")
    );
}

/// Multiple redirect URIs should succeed.
#[tokio::test]
async fn test_rfc7591_register_multiple_redirect_uris() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "multi-uri").await;

    let body = serde_json::json!({
        "redirect_uris": [
            "https://example.com/callback",
            "https://example.com/auth/complete",
            "https://staging.example.com/callback"
        ],
        "client_name": "Multi URI App"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let uris = json["redirect_uris"].as_array().unwrap();
    assert_eq!(uris.len(), 3, "All 3 redirect URIs must be echoed back");
}

/// Custom scheme redirect URI for native apps should succeed (RFC 8252).
#[tokio::test]
async fn test_rfc7591_register_custom_scheme_redirect_uri() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "custom-scheme").await;

    let body = serde_json::json!({
        "redirect_uris": ["com.example.myapp://auth/callback"],
        "token_endpoint_auth_method": "none",
        "client_name": "Native Custom Scheme App"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "Custom scheme → 201: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let uris = json["redirect_uris"].as_array().unwrap();
    assert!(
        uris.iter()
            .any(|u| u == "com.example.myapp://auth/callback")
    );
}

/// Public client with HTTPS redirect should be inferred as SPA type.
#[tokio::test]
async fn test_rfc7591_register_public_spa_client() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "spa").await;

    let body = serde_json::json!({
        "redirect_uris": ["https://app.example.com/callback"],
        "token_endpoint_auth_method": "none",
        "client_name": "SPA App"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["token_endpoint_auth_method"], "none");
    // Public client → no secret
    assert!(json.get("client_secret").is_none());
}

/// HTTPS metadata URI fields should be echoed back when valid.
#[tokio::test]
async fn test_rfc7591_register_with_metadata_uris() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "meta-uris").await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "URI Fields App",
        "client_uri": "https://example.com",
        "logo_uri": "https://example.com/logo.png",
        "tos_uri": "https://example.com/tos",
        "policy_uri": "https://example.com/privacy"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["client_uri"], "https://example.com");
    assert_eq!(json["logo_uri"], "https://example.com/logo.png");
    assert_eq!(json["tos_uri"], "https://example.com/tos");
    assert_eq!(json["policy_uri"], "https://example.com/privacy");
}

/// Response must include `client_id_issued_at` and `registration_client_uri`.
#[tokio::test]
async fn test_rfc7591_response_includes_issued_at_and_client_uri() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "issued-at").await;

    let body = serde_json::json!({
        "grant_types": ["client_credentials"],
        "client_name": "Issued At Test"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // client_id_issued_at must be a positive epoch timestamp
    let issued_at = json["client_id_issued_at"]
        .as_i64()
        .expect("client_id_issued_at must be an integer");
    assert!(
        issued_at > 0,
        "client_id_issued_at must be a positive epoch timestamp"
    );

    // registration_client_uri must contain the client_id
    let client_id = json["client_id"].as_str().unwrap();
    let reg_uri = json["registration_client_uri"]
        .as_str()
        .expect("registration_client_uri must be present");
    assert!(
        reg_uri.contains(client_id),
        "registration_client_uri must contain client_id: {reg_uri}"
    );
    assert!(
        reg_uri.contains("/oauth/register/"),
        "registration_client_uri must use /oauth/register/ path: {reg_uri}"
    );
}

/// Registered client must be persisted in the database.
#[tokio::test]
async fn test_rfc7591_registered_client_persisted_in_db() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "persist").await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "Persisted App",
        "software_id": "persist-test-sw",
        "software_version": "2.0.0"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let client_id = json["client_id"].as_str().unwrap();

    // Verify the client exists in the database
    let db_client = db::get_oauth_client_by_client_id(&state.store, client_id)
        .await
        .expect("DB lookup should succeed")
        .expect("Client must exist in DB");

    assert_eq!(db_client.client_id, client_id);
    assert_eq!(db_client.name, "Persisted App");
    assert_eq!(
        db_client.registration_source,
        Some(crate::db::RegistrationSource::Dynamic)
    );
    assert_eq!(db_client.software_id.as_deref(), Some("persist-test-sw"));
    assert_eq!(db_client.software_version.as_deref(), Some("2.0.0"));
    assert!(
        db_client.registration_access_token_hash.is_some(),
        "Registration access token hash must be stored"
    );
}

// ========================================================================
// Validation error cases
// ========================================================================

#[tokio::test]
async fn test_rfc7591_rejects_implicit_grant() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "implicit").await;

    let body = serde_json::json!({
        "grant_types": ["implicit"],
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7591_rejects_token_response_type() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "token-rt").await;

    let body = serde_json::json!({
        "response_types": ["token"],
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7591_rejects_unsupported_grant_type() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "password-gt").await;

    let body = serde_json::json!({
        "grant_types": ["password"],
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7591_rejects_auth_code_without_redirect_uris() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "no-redirect").await;

    let body = serde_json::json!({
        "grant_types": ["authorization_code"],
        "client_name": "No Redirect"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7591_rejects_http_non_loopback_redirect_uri() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "http-redirect").await;

    let body = serde_json::json!({
        "redirect_uris": ["http://example.com/callback"],
        "client_name": "Bad Redirect"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_redirect_uri");
}

#[tokio::test]
async fn test_rfc7591_rejects_redirect_uri_with_fragment() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "fragment").await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback#section"],
        "client_name": "Fragment App"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_redirect_uri");
}

#[tokio::test]
async fn test_rfc7591_rejects_both_jwks_and_jwks_uri() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "both-jwks").await;

    let body = serde_json::json!({
        "grant_types": ["client_credentials"],
        "jwks": {"keys": [{"kty": "RSA", "n": "abc", "e": "AQAB"}]},
        "jwks_uri": "https://example.com/.well-known/jwks.json"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7591_rejects_unknown_auth_method() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "bad-auth").await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "magic_beans"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7591_rejects_private_key_jwt_without_jwks() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "pkjwt-no-jwks").await;

    let body = serde_json::json!({
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "private_key_jwt"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7591_rejects_invalid_contact_email() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "bad-contact").await;

    let body = serde_json::json!({
        "grant_types": ["client_credentials"],
        "contacts": ["not-an-email"]
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7591_rejects_http_client_uri() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "http-uri").await;

    let body = serde_json::json!({
        "grant_types": ["client_credentials"],
        "client_uri": "http://example.com"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7591_rejects_fapi_without_private_key_jwt() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "fapi-bad").await;

    let body = serde_json::json!({
        "grant_types": ["client_credentials"],
        "dpop_bound_access_tokens": true,
        "token_endpoint_auth_method": "client_secret_basic"
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

// ========================================================================
// RFC 7591 Section 2: Unknown fields MUST be ignored
// ========================================================================

#[tokio::test]
async fn test_rfc7591_ignores_unknown_fields() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "unknown").await;

    let body = serde_json::json!({
        "grant_types": ["client_credentials"],
        "client_name": "Unknown Fields Test",
        "future_extension_field": "should be ignored",
        "another_unknown_123": {"nested": true},
        "yet_another": 42
    });

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Unknown fields must be ignored per RFC 7591 Section 2: {body}"
    );
}

// ========================================================================
// Discovery — registration_endpoint
// ========================================================================

#[tokio::test]
async fn test_rfc7591_discovery_includes_registration_endpoint() {
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let reg_endpoint = doc["registration_endpoint"]
        .as_str()
        .expect("registration_endpoint must be in discovery");
    assert!(
        reg_endpoint.ends_with("/oauth/register"),
        "registration_endpoint must end with /oauth/register, got: {reg_endpoint}"
    );
}

#[tokio::test]
async fn test_rfc7591_discovery_grant_types_include_client_credentials() {
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let grant_types = doc["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported must be an array");

    assert!(
        grant_types.iter().any(|g| g == "client_credentials"),
        "grant_types_supported must include client_credentials"
    );
    assert!(
        !grant_types.iter().any(|g| g == "refresh_token"),
        "grant_types_supported must NOT include refresh_token"
    );
}

// ========================================================================
// End-to-end: dynamically registered client completes auth code flow
// ========================================================================

/// A dynamically registered confidential client should be able to exchange
/// an authorization code for tokens, proving the client is fully functional.
#[tokio::test]
async fn test_rfc7591_e2e_registered_client_auth_code_flow() {
    let (app, state) = test_app().await;
    let auth = bearer_token_unique(&state, "e2e").await;

    // Step 1: Dynamically register a confidential client
    let reg_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "E2E Dynamic Client"
    });

    let (status, reg_response) = http_post_json(
        &app,
        "/oauth/register",
        &reg_body.to_string(),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Registration must succeed: {reg_response}"
    );
    let reg_json: serde_json::Value =
        serde_json::from_str(&reg_response).expect("Valid JSON response");

    let client_id = reg_json["client_id"].as_str().expect("client_id present");
    let client_secret = reg_json["client_secret"]
        .as_str()
        .expect("client_secret present for confidential client");

    // Build a TestOAuthClient from the registration response
    let dynamic_client = TestOAuthClient {
        app_id: String::new(),
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
    };

    // Step 2: Create a user and issue an authorization code for this client
    let user = create_test_user(&state.store, "e2e-dynamic-user@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid email");
    let code_params = AuthorizationCodeParams {
        client_id,
        redirect_uri: "https://example.com/callback",
        user_id: &user.id,
        email: &user.email,
        authenticator_id: &auth_id,
        aaguid: None,
        scope: &scope_set,
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        resource: None,
        acr_values: None,
        dpop_jkt: None,
        auth_code_lifetime_seconds:
            crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
        authorization_details: None,
        auth_time: None,
    };

    let code = issue_authorization_code(&state, code_params)
        .await
        .expect("Failed to issue authorization code");

    // Step 3: Exchange the code for tokens using the dynamic client's credentials
    let auth_header = dynamic_client.basic_auth_header();
    let (token_status, token_body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        token_status,
        StatusCode::OK,
        "Token exchange must succeed for dynamically registered client: {token_body}"
    );

    let token_json: serde_json::Value =
        serde_json::from_str(&token_body).expect("Valid JSON token response");
    let access_token = token_json["access_token"]
        .as_str()
        .expect("access_token present");
    assert!(
        token_json["id_token"].is_string(),
        "id_token must be present"
    );

    // Step 4: Use the access token at the userinfo endpoint
    let (userinfo_status, userinfo_body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {access_token}"))],
    )
    .await;

    assert_eq!(
        userinfo_status,
        StatusCode::OK,
        "UserInfo must accept token from dynamically registered client: {userinfo_body}"
    );
    let userinfo: serde_json::Value =
        serde_json::from_str(&userinfo_body).expect("Valid JSON userinfo");
    assert_eq!(userinfo["email"], "e2e-dynamic-user@example.com");
}

// ========================================================================
// RP-Initiated Logout 1.0 — post_logout_redirect_uris registration
// ========================================================================

#[tokio::test]
async fn test_rfc7591_post_logout_redirect_uris_roundtrip() {
    // RFC 7591: post_logout_redirect_uris must be echoed back in the registration response.
    let (app, _state) = test_app().await;

    let body = serde_json::json!({
        "redirect_uris": ["https://rp.example.com/callback"],
        "post_logout_redirect_uris": ["https://rp.example.com/logged-out"]
    });

    let (status, resp) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "Registration failed: {resp}");

    let json: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
    let post_logout = json
        .get("post_logout_redirect_uris")
        .and_then(|v| v.as_array())
        .expect("post_logout_redirect_uris must be echoed in the registration response");
    assert_eq!(
        post_logout.len(),
        1,
        "Expected 1 post_logout_redirect_uri, got {post_logout:?}"
    );
    assert_eq!(
        post_logout[0].as_str().unwrap(),
        "https://rp.example.com/logged-out"
    );
}

#[tokio::test]
async fn test_rfc7591_post_logout_redirect_uris_invalid_scheme_rejected() {
    // A post_logout_redirect_uri with an invalid scheme (ftp://) must be rejected.
    let (app, _state) = test_app().await;

    let body = serde_json::json!({
        "redirect_uris": ["https://rp.example.com/callback"],
        "post_logout_redirect_uris": ["ftp://rp.example.com/logged-out"]
    });

    let (status, resp) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "ftp:// post_logout_redirect_uri must be rejected: {resp}"
    );
    let json: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
    // RFC 7591 §3.2.2: registration errors use `invalid_client_metadata`.
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7591_post_logout_redirect_uris_fragment_rejected() {
    // A post_logout_redirect_uri carrying a fragment must be rejected.
    let (app, _state) = test_app().await;

    let body = serde_json::json!({
        "redirect_uris": ["https://rp.example.com/callback"],
        "post_logout_redirect_uris": ["https://rp.example.com/logged-out#section"]
    });

    let (status, resp) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "fragment in post_logout_redirect_uri must be rejected: {resp}"
    );
    let json: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
    // RFC 7591 §3.2.2: registration errors use `invalid_client_metadata`.
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7591_post_logout_redirect_uris_loopback_http_allowed() {
    // Loopback http:// is allowed for native app testing.
    let (app, _state) = test_app().await;

    let body = serde_json::json!({
        "redirect_uris": ["http://localhost:3000/callback"],
        "post_logout_redirect_uris": ["http://localhost:3000/logged-out"]
    });

    let (status, resp) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "loopback http:// post_logout_redirect_uri must be accepted: {resp}"
    );
    let json: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
    let post_logout = json["post_logout_redirect_uris"]
        .as_array()
        .expect("post_logout_redirect_uris present");
    assert_eq!(
        post_logout[0].as_str().unwrap(),
        "http://localhost:3000/logged-out"
    );
}

// ========================================================================
// RFC 8705 §3 — mTLS-bound tokens at the registration endpoint
//
// The discovery document advertises `mtls_endpoint_aliases.registration_endpoint`,
// so an mTLS-bound access token (cnf.x5t#S256) presented with its matching
// client certificate MUST authenticate at POST /oauth/register. The
// `OptionalAuthenticatedToken` extractor must extract and forward the client
// certificate, mirroring `AuthenticatedToken`.
// ========================================================================

/// RFC 8705 §3 + RFC 7591: An mTLS-bound access token presented with its
/// matching client certificate MUST authenticate at `POST /oauth/register`.
///
/// Regression test: `OptionalAuthenticatedToken` previously passed `None` for
/// `client_cert`, so even a correctly-bound token+cert pair was rejected with
/// "mTLS certificate required for certificate-bound token".
#[tokio::test]
async fn test_rfc7591_mtls_bound_token_with_matching_cert_authenticates() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rfc7591-mtls-match@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("rfc7591-mtls-match");
    let thumbprint = cert_thumbprint(&cert_der);
    let token =
        create_test_session_with_mtls(&state, &user.id, &user.email, &auth_id, &thumbprint).await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "mTLS-bound Registration"
    });

    let (status, resp) = http_post_json_with_cert(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &format!("Bearer {token}"))],
        Some(cert_der),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "mTLS-bound token with matching cert must authenticate at /oauth/register: {resp}"
    );
    let json: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
    assert!(
        json.get("client_id").is_some(),
        "Response must include client_id"
    );
    assert!(
        json["client_name"].as_str() == Some("mTLS-bound Registration"),
        "client_name must be echoed back: {resp}"
    );
}

/// RFC 8705 §3: An mTLS-bound token presented with a mismatched client
/// certificate MUST be rejected at `POST /oauth/register` with `invalid_token`.
/// Confirms the cert is now extracted AND validated, not silently ignored.
#[tokio::test]
async fn test_rfc7591_mtls_bound_token_with_wrong_cert_rejected() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rfc7591-mtls-wrong@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_a_der = make_test_cert_der("rfc7591-bound-a");
    let thumbprint_a = cert_thumbprint(&cert_a_der);
    let token =
        create_test_session_with_mtls(&state, &user.id, &user.email, &auth_id, &thumbprint_a).await;

    // Present a different certificate than the one the token is bound to.
    let cert_b_der = make_test_cert_der("rfc7591-presented-b");
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "mTLS Mismatch"
    });

    let (status, resp) = http_post_json_with_cert(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &format!("Bearer {token}"))],
        Some(cert_b_der),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "mTLS-bound token with wrong cert must be rejected: {resp}"
    );
    let json: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_token",
        "Wrong cert must return invalid_token: {resp}"
    );
}

/// RFC 8705 §3: An mTLS-bound token presented without any client certificate
/// MUST be rejected at `POST /oauth/register` with `invalid_token`. The cert
/// extraction added by the fix must not weaken this enforcement.
#[tokio::test]
async fn test_rfc7591_mtls_bound_token_without_cert_rejected() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rfc7591-mtls-nocert@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("rfc7591-nocert");
    let thumbprint = cert_thumbprint(&cert_der);
    let token =
        create_test_session_with_mtls(&state, &user.id, &user.email, &auth_id, &thumbprint).await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "mTLS No Cert"
    });

    // No client certificate injected (cert_der = None) — the request still
    // carries the Authorization header, so the extractor must validate the
    // token and reject it for lack of a binding cert.
    let (status, resp) = http_post_json_with_cert(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &format!("Bearer {token}"))],
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "mTLS-bound token without cert must be rejected: {resp}"
    );
    let json: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_token",
        "Missing cert must return invalid_token: {resp}"
    );
}

/// Regression: A plain (non-bound) Bearer token presented together with a
/// client certificate MUST still authenticate at `POST /oauth/register`. The
/// added cert extraction must not break the non-bound token path.
#[tokio::test]
async fn test_rfc7591_plain_token_with_cert_presented_still_works() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rfc7591-plain-cert@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let cert_der = make_test_cert_der("rfc7591-plain");
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "Plain Token With Cert"
    });

    let (status, resp) = http_post_json_with_cert(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &format!("Bearer {token}"))],
        Some(cert_der),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Plain token with a cert presented must still authenticate: {resp}"
    );
    let json: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
    assert!(
        json.get("client_id").is_some(),
        "Response must include client_id"
    );
}
