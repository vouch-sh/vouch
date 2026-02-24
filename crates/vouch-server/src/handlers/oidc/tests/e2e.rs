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

    let user = create_test_user(&state.db, "secret-roundtrip@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // The test helper uses hash_token() (base64url). Validate that
    // db::validate_oauth_client_credentials finds the secret when we
    // hash the plaintext secret with the same function.
    let secret_hash = crate::handlers::hash_token(&client.client_secret);
    let result =
        crate::db::validate_oauth_client_credentials(&state.db, &client.client_id, &secret_hash)
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

    let user = create_test_user(&state.db, "oauth-userinfo@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

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
async fn test_oauth_access_token_rejected_at_management_endpoints() {
    // OAuth access tokens (ES256, RFC 9068) are rejected at management endpoints
    // because the management endpoint only decodes HS256 FIDO2 session tokens.
    // The ES256 token fails HS256 decoding, returning 401 (unauthorized).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "oauth-mgmt@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Try calling key listing endpoint with OAuth access token
    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;

    // ES256 access tokens cannot be decoded by the HS256-only management
    // endpoint, so they fail at the JWT decode step with 401.
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "OAuth access token should be rejected at management endpoints: {}",
        body
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "unauthorized");
}

#[tokio::test]
async fn test_fido2_session_still_works_at_management_endpoints() {
    // Verify FIDO2 session tokens still work at management endpoints
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "fido2-mgmt@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Call key listing endpoint with FIDO2 session token (should succeed)
    let (status, _body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "FIDO2 session should work at management endpoints"
    );
}

// ========================================================================
// OIDC Scope Conformance Tests
// ========================================================================

#[tokio::test]
async fn test_userinfo_respects_openid_only_scope() {
    // OIDC Core Section 5.4: Without email scope, email claims should be omitted
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "scope-openid@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

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

    let user = create_test_user(&state.db, "scope-email@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

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

    let user = create_test_user(&state.db, "idtoken-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

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
async fn test_backward_compat_token_without_scope() {
    // JWTs without scope field should deserialize as None
    let claims_json = r#"{"iss":"https://vouch.example.com","aud":"https://vouch.example.com","sub":"user-id","email":"test@example.com","iat":1700000000,"exp":1700028800,"purpose":"fido2_session"}"#;
    let claims: crate::services::auth::SessionClaims =
        serde_json::from_str(claims_json).expect("Should deserialize without scope");
    assert!(
        claims.scope.is_none(),
        "Missing scope field should deserialize as None"
    );
}
