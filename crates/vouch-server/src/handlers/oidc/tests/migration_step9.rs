// SPDX-License-Identifier: BUSL-1.1
//! Step 9 Migration Tests — Removal of Fido2Session + Legacy Endpoints.
//!
//! This module validates the correctness of the Step 9 FAPI 2.0 migration:
//! - Dual token types (HS256 Fido2Session + ES256 OAuth) collapsed to a single
//!   unified ES256 OAuth access token (RFC 9068).
//! - Legacy `/v1/auth/register/*` backward-compat routes removed.
//! - `create_test_session_for_client` helper introduced for introspection tests.
//! - SQLite migration 013 adds 5 missing columns to `oauth_clients`.
//!
//! These tests act as regression guards so the removal can never silently revert.

use super::helpers::*;
use crate::services::auth::{DecodedToken, decode_token};

// ============================================================================
// Unified Token Type — Structural Guarantees
// ============================================================================

#[tokio::test]
async fn test_migration_unified_token_is_es256() {
    // Post-migration: all session tokens must be ES256 (not HS256).
    // Any HS256 Fido2Session token must be permanently rejected.
    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "migration-es256@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let header = jsonwebtoken::decode_header(&token).expect("valid JWT");
    assert_eq!(
        header.alg,
        jsonwebtoken::Algorithm::ES256,
        "Post-migration: all session tokens must use ES256"
    );
}

#[tokio::test]
async fn test_migration_hs256_session_token_permanently_rejected() {
    // Regression: legacy HS256 "Fido2Session" tokens must never be accepted.
    // We forge a plausible-looking HS256 token with vouch-session+jwt typ and
    // verify every token-consuming endpoint rejects it.
    let (app, state) = test_app().await;

    // Forge an HS256 JWT that mimics a pre-migration Fido2Session token.
    // The typ header "vouch-session+jwt" is the legacy value — it is no longer
    // a known JwtType variant, so from_header_str returns None.
    let user = create_test_user(&state.store, "hs256-reject@example.com").await;
    let secret = state.config().jwt_secret_bytes().to_vec();

    #[derive(serde::Serialize)]
    struct LegacySessionClaims {
        iss: String,
        sub: String,
        exp: i64,
        email: String,
    }

    let claims = LegacySessionClaims {
        iss: state.config().base_url.clone(),
        sub: user.id.clone(),
        exp: 9_999_999_999,
        email: user.email.clone(),
    };

    let header = jsonwebtoken::Header {
        typ: Some("vouch-session+jwt".to_string()),
        ..Default::default()
    };

    let legacy_token = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(&secret),
    )
    .expect("encode legacy token");

    // Endpoints that must reject the legacy token with 401
    let reject_endpoints = [("GET", "/v1/keys"), ("GET", "/oauth/userinfo")];

    for (method, path) in reject_endpoints {
        let (status, _) = http_request(
            &app,
            method,
            path,
            None,
            &[("Authorization", &format!("Bearer {legacy_token}"))],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Endpoint {method} {path} must reject legacy HS256 token"
        );
    }

    // /v1/auth/status returns 200 with authenticated=false for invalid tokens
    let (status, body) = http_get(
        &app,
        "/v1/auth/status",
        &[("Authorization", &format!("Bearer {legacy_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "/v1/auth/status must return 200");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        parsed["authenticated"], false,
        "Legacy HS256 token must show authenticated=false at status endpoint"
    );
}

#[tokio::test]
async fn test_migration_decode_token_rejects_vouch_session_typ() {
    // Unit test: decode_token must return None for any HS256 token, regardless
    // of what typ header value it carries.
    let (_app, state) = test_app().await;

    // Build an HS256 token with the legacy "vouch-session+jwt" typ
    #[derive(serde::Serialize)]
    struct Claims {
        iss: String,
        sub: String,
        exp: i64,
    }

    let config = state.config();

    let claims = Claims {
        iss: config.base_url.clone(),
        sub: "user-old".to_string(),
        exp: 9_999_999_999,
    };
    let header = jsonwebtoken::Header {
        typ: Some("vouch-session+jwt".to_string()),
        ..Default::default()
    };

    let legacy_token = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(config.jwt_secret_bytes()),
    )
    .expect("encode");

    // services::auth::decode_token must return None for any HS256 token
    let result = decode_token(
        &legacy_token,
        config.jwt_secret_bytes(),
        &state.oidc_key,
        &config.base_url,
    );

    assert!(
        result.is_none(),
        "Legacy vouch-session+jwt HS256 token must be permanently rejected by decode_token"
    );
}

// ============================================================================
// create_test_session_for_client Helper — Correctness
// ============================================================================

#[tokio::test]
async fn test_create_test_session_for_client_stores_session_in_db() {
    // Verify that create_test_session_for_client stores a session record in the
    // database, so the token can be validated end-to-end (not just as a JWT).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "sess-stored@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let token =
        create_test_session_for_client(&state, &user.id, &user.email, &auth_id, &client.client_id)
            .await;

    // Use the token at userinfo — this exercises both JWT validation AND DB lookup.
    // If the session weren't stored, the handler returns 401 even for a valid JWT.
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Token created by create_test_session_for_client must be usable at resource endpoints: {body}"
    );
}

#[tokio::test]
async fn test_create_test_session_for_client_client_id_in_jwt() {
    // The client_id embedded in the JWT must match the supplied client_id.
    // This is what allows the cross-client introspection check to work correctly.
    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "jwt-client-id@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client_a = create_test_oauth_client(&state.store, &user.id).await;
    let client_b = create_test_oauth_client(&state.store, &user.id).await;

    // Create tokens bound to different clients
    let token_a = create_test_session_for_client(
        &state,
        &user.id,
        &user.email,
        &auth_id,
        &client_a.client_id,
    )
    .await;

    let token_b = create_test_session_for_client(
        &state,
        &user.id,
        &user.email,
        &auth_id,
        &client_b.client_id,
    )
    .await;

    let config = state.config();

    let decoded_a = decode_token(
        &token_a,
        config.jwt_secret_bytes(),
        &state.oidc_key,
        &config.base_url,
    )
    .expect("token_a must decode");

    let decoded_b = decode_token(
        &token_b,
        config.jwt_secret_bytes(),
        &state.oidc_key,
        &config.base_url,
    )
    .expect("token_b must decode");

    let DecodedToken::AccessToken(claims_a) = decoded_a;
    let DecodedToken::AccessToken(claims_b) = decoded_b;

    assert_eq!(
        claims_a.client_id, client_a.client_id,
        "token_a.client_id must match client_a"
    );
    assert_eq!(
        claims_b.client_id, client_b.client_id,
        "token_b.client_id must match client_b"
    );
    assert_ne!(
        claims_a.client_id, claims_b.client_id,
        "Tokens for different clients must carry different client_id values"
    );
}

// ============================================================================
// Legacy Routes — Verified Absent
// ============================================================================

#[tokio::test]
async fn test_migration_legacy_auth_register_start_returns_404() {
    // Step 9 explicitly removed /v1/auth/register/start.
    // This test acts as a permanent regression guard.
    let (app, _state) = test_app().await;

    let (status, _) = http_request(
        &app,
        "POST",
        "/v1/auth/register/start",
        Some(r#"{"name":"k"}"#.to_string()),
        &[("Content-Type", "application/json")],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "/v1/auth/register/start must not exist post-migration"
    );
}

#[tokio::test]
async fn test_migration_legacy_auth_register_complete_returns_404() {
    // Step 9 explicitly removed /v1/auth/register/complete.
    let (app, _state) = test_app().await;

    let (status, _) = http_request(
        &app,
        "POST",
        "/v1/auth/register/complete",
        Some(r#"{"state":"x"}"#.to_string()),
        &[("Content-Type", "application/json")],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "/v1/auth/register/complete must not exist post-migration"
    );
}

// ============================================================================
// SQLite Migration 013 — Schema Completeness
// ============================================================================

#[tokio::test]
async fn test_migration_013_oauth_clients_schema_has_all_columns() {
    // Migration 013 recreated the oauth_clients table. Verify that all previously
    // missing columns are now present by exercising the DB helper that reads them.
    //
    // We create a client and check that the fields do not cause a query
    // error (which would happen if a column was missing).
    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "schema-check@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // get_oauth_client_by_client_id reads all columns including the 5 added ones.
    let result = db::get_oauth_client_by_client_id(&state.store, &client.client_id)
        .await
        .expect("DB query must succeed — migration 013 must have all columns");

    let db_client = result.expect("Client must exist in DB");
    assert_eq!(db_client.client_id, client.client_id);

    // The previously missing columns must be accessible without error.
    // Failure here indicates the migration was not applied or is incomplete.
    // (grant_types, response_types, software_id, software_version,
    //  registration_access_token_hash, registration_metadata)
    // These fields map to Option<T> and default to None for manually-created clients.
    let _ = db_client.grant_types;
    let _ = db_client.response_types;
    let _ = db_client.software_id;
    let _ = db_client.software_version;
    let _ = db_client.registration_access_token_hash;
}

#[tokio::test]
async fn test_migration_013_nullable_user_id_open_registration() {
    // Migration 013 made oauth_clients.user_id nullable to support
    // RFC 7591 open registration (no bearer token required).
    // Verify this works end-to-end: register without auth, get a client_id.
    let (app, _state) = test_app().await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "Open Reg Client",
        "grant_types": ["authorization_code"]
    });

    // No Authorization header — open registration
    let (status, resp_body) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Open registration (nullable user_id) must succeed post-migration-013: {resp_body}"
    );

    let json: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert!(
        json["client_id"].is_string(),
        "Open registration must return a client_id"
    );
    // client_id alone grants zero access — this is the security guarantee
    assert!(
        json.get("access_token").is_none(),
        "Open registration must not grant an access token"
    );
}
