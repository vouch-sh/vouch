// SPDX-License-Identifier: BUSL-1.1
//! End-to-end flows, regression tests, and scope conformance tests.

use super::helpers::*;

// ========================================================================
// Regression Tests
// ========================================================================

#[tokio::test]
async fn test_client_secret_hash_roundtrip() {
    // Regression test: client secrets hashed at creation time must match
    // hashes produced during authentication. A previous bug used hex encoding
    // at creation but base64url at validation, so authentication always failed.
    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "secret-roundtrip@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // The test helper uses hash_token() (base64url). Validate that
    // db::validate_oauth_client_credentials finds the secret when we
    // hash the plaintext secret with the same function.
    let secret_hash = crate::handlers::hash_token(&client.client_secret);
    let result =
        crate::db::validate_oauth_client_credentials(&state.store, &client.client_id, &secret_hash)
            .await
            .expect("DB query should succeed");

    assert!(
        result.is_some(),
        "Client secret round-trip must succeed: hash at creation must match hash at validation"
    );
}

// ========================================================================
// OAuth Access Token + UserInfo End-to-End Tests
// ========================================================================

#[tokio::test]
async fn test_auth_code_flow_token_works_with_userinfo() {
    // Full OIDC flow: issue auth code → exchange → call /oauth/userinfo → assert 200
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "oauth-userinfo@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Call userinfo with the OAuth access token
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "UserInfo should accept OAuth access token"
    );
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        userinfo["email"].as_str().unwrap(),
        "oauth-userinfo@example.com"
    );
    assert!(userinfo["sub"].is_string(), "sub claim must be present");
}

#[tokio::test]
async fn test_oauth_token_works_at_management_endpoints() {
    // Verify OAuth access tokens work at management endpoints
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "oauth-mgmt@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Call key listing endpoint with OAuth access token (should succeed)
    let (status, _body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "OAuth access token should work at management endpoints"
    );
}

// ========================================================================
// OIDC Scope Conformance Tests
// ========================================================================

#[tokio::test]
async fn test_userinfo_respects_openid_only_scope() {
    // OIDC Core Section 5.4: Without email scope, email claims should be omitted
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "scope-openid@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue token with only "openid" scope (no "email")
    let (access_token, _id_token) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid").await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(userinfo.get("sub").is_some(), "sub claim must be present");
    assert!(
        userinfo.get("email").is_none(),
        "email claim should be omitted without email scope"
    );
    assert!(
        userinfo.get("email_verified").is_none(),
        "email_verified should be omitted without email scope"
    );
}

#[tokio::test]
async fn test_userinfo_includes_email_with_email_scope() {
    // OIDC Core Section 5.4: With email scope, email claims should be present
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "scope-email@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue token with "openid email" scope
    let (access_token, _id_token) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid email")
            .await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(userinfo.get("sub").is_some(), "sub claim must be present");
    assert!(
        userinfo.get("email").is_some(),
        "email claim should be present with email scope"
    );
    assert_eq!(
        userinfo["email"].as_str().unwrap(),
        "scope-email@example.com"
    );
    assert_eq!(userinfo["email_verified"], true);
}

#[tokio::test]
async fn test_id_token_scope_aware() {
    // OIDC Core Section 5.4: ID token should only include email when scope grants it
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "idtoken-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue token with only "openid" scope (no email)
    let (_access_token, id_token) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid").await;

    // Decode the ID token (just decode claims, don't verify signature in test)
    let parts: Vec<&str> = id_token.split('.').collect();
    assert!(parts.len() >= 2, "ID token should have at least 2 parts");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Valid base64");
    let claims: serde_json::Value = serde_json::from_slice(&payload).expect("Valid JSON payload");

    assert!(claims.get("sub").is_some(), "ID token must have sub");
    assert!(
        claims.get("email").is_none(),
        "ID token should not have email claim without email scope"
    );
    assert!(
        claims.get("email_verified").is_none(),
        "ID token should not have email_verified without email scope"
    );
}

#[tokio::test]
async fn test_access_token_optional_scope_field() {
    // AccessTokenClaims with missing scope field should deserialize as None
    use crate::services::auth::AccessTokenClaims;
    let claims_json = r#"{"iss":"https://vouch.example.com","aud":"client-id","sub":"user-id","exp":9999999999,"iat":1700000000,"jti":"jti-1","client_id":"client-id","hardware_verified":true}"#;
    let claims: AccessTokenClaims =
        serde_json::from_str(claims_json).expect("Should deserialize without scope");
    assert!(
        claims.scope.is_none(),
        "Missing scope field should deserialize as None"
    );
}

// ========================================================================
// Step 9 Migration — Unified Token Type Tests
// ========================================================================

#[tokio::test]
async fn test_create_test_session_for_client_produces_client_bound_token() {
    // Verify the new create_test_session_for_client helper creates a token
    // whose client_id claim matches the given client_id, not the server base_url.
    // This is critical for introspection cross-client tests.
    use crate::services::auth::{DecodedToken, decode_token};

    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "client-bound@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Use the helper — token's client_id must match client.client_id
    let token =
        create_test_session_for_client(&state, &user.id, &user.email, &auth_id, &client.client_id)
            .await;

    let config = state.config();
    let decoded = decode_token(
        &token,
        config.jwt_secret_bytes(),
        &state.oidc_key,
        &config.base_url,
    )
    .expect("Token must decode successfully");

    let DecodedToken::AccessToken(claims) = decoded;
    assert_eq!(
        claims.client_id, client.client_id,
        "Token client_id must match the supplied client_id, not the server base_url"
    );
    assert_eq!(claims.sub, user.id, "Token sub must match the user_id");
}

#[tokio::test]
async fn test_unified_token_hardware_verified_claim_always_set() {
    // All unified ES256 access tokens produced by create_oauth_access_token
    // must carry hardware_verified=true (FIDO2 attestation guarantee).
    use crate::services::auth::{DecodedToken, decode_token};

    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "hw-verified@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let config = state.config();
    let decoded = decode_token(
        &token,
        config.jwt_secret_bytes(),
        &state.oidc_key,
        &config.base_url,
    )
    .expect("Token must decode successfully");

    let DecodedToken::AccessToken(claims) = decoded;
    assert!(
        claims.hardware_verified,
        "All unified access tokens must carry hardware_verified=true"
    );
}

#[tokio::test]
async fn test_unified_token_typ_header_is_at_jwt() {
    // RFC 9068 Section 2.1 + Step 9 migration: the single surviving token type
    // is ES256 with typ "at+jwt". Verify this is what create_test_session produces.
    use crate::crypto::jwt::JwtType;

    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "typ-header@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Peek at the header without full validation
    let header = jsonwebtoken::decode_header(&token).expect("Valid JWT header");
    assert_eq!(
        header.typ.as_deref(),
        Some(JwtType::AccessToken.as_header_str()),
        "Unified token must have typ=at+jwt"
    );
    assert_eq!(
        header.alg,
        jsonwebtoken::Algorithm::ES256,
        "Unified token must be signed with ES256"
    );
}

#[tokio::test]
async fn test_legacy_register_routes_removed() {
    // Step 9: /v1/auth/register/* backward-compat routes were removed.
    // Only /v1/keys/register/* remains. Verify the legacy paths return 404
    // so clients cannot accidentally rely on removed endpoints.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "legacy-route@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let auth = format!("Bearer {token}");

    // Legacy path: /v1/auth/register/start — must not exist
    let (status, _) = http_request(
        &app,
        "POST",
        "/v1/auth/register/start",
        Some(r#"{"name":"key"}"#.to_string()),
        &[
            ("Authorization", &auth),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "/v1/auth/register/start must return 404 after removal"
    );

    // Legacy path: /v1/auth/register/complete — must not exist
    let (status, _) = http_request(
        &app,
        "POST",
        "/v1/auth/register/complete",
        Some(r#"{"state":"x"}"#.to_string()),
        &[
            ("Authorization", &auth),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "/v1/auth/register/complete must return 404 after removal"
    );
}

#[tokio::test]
async fn test_current_register_routes_still_exist() {
    // Regression guard: /v1/keys/register/* routes must still exist and
    // require authentication (not 404).
    let (app, _state) = test_app().await;

    // Without auth — should be 401, not 404
    let (status, _) = http_request(
        &app,
        "POST",
        "/v1/keys/register/start",
        Some(r#"{"name":"key"}"#.to_string()),
        &[("Content-Type", "application/json")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "/v1/keys/register/start must exist and require auth (not 404)"
    );
}

#[tokio::test]
async fn test_decoded_token_enum_single_variant_destructuring() {
    // DecodedToken is now a single-variant enum. Verify that exhaustive
    // destructuring (used in introspection.rs etc.) compiles and works correctly.
    // This is a compilation + runtime correctness check.
    use crate::services::auth::{DecodedToken, decode_token};

    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "enum-destr@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let config = state.config();
    let decoded = decode_token(
        &token,
        config.jwt_secret_bytes(),
        &state.oidc_key,
        &config.base_url,
    )
    .expect("Token must decode");

    // Exhaustive destructuring of the single-variant enum — if a second variant
    // were added this would produce a compiler warning, keeping tests honest.
    let DecodedToken::AccessToken(claims) = decoded;
    assert!(!claims.sub.is_empty(), "sub must be populated");
    assert!(!claims.iss.is_empty(), "iss must be populated");
    assert!(!claims.jti.is_empty(), "jti must be populated");
}
