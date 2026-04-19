// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7009 — Token Revocation tests.

use super::helpers::*;

// ========================================================================
// Token Revocation Tests (RFC 7009)
// ========================================================================

#[tokio::test]
async fn test_revoke_valid_token() {
    // RFC 7009 Section 2.1: Successful revocation returns 200 and invalidates the token
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;
    let auth_header = client.basic_auth_header();

    // Verify token works before revocation
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Token should work before revocation"
    );

    // Revoke the token with client authentication (RFC 7009 Section 2.1)
    let (status, _body) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify token no longer works after revocation
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Token should fail after revocation"
    );
}

#[tokio::test]
async fn test_revoke_without_client_auth_returns_401() {
    // RFC 7009 §2.1: Revocation without client credentials returns 401.
    let (app, _state) = test_app().await;

    let (status, _body) =
        http_post_form(&app, "/oauth/revoke", "token=completely_invalid_token", &[]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_revoke_token_invalidates_session() {
    // After revocation, the token should not work
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke-check@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;
    let auth_header = client.basic_auth_header();

    // Verify token works before revocation
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Token should work before revocation"
    );

    // Revoke the token (requires client authentication per RFC 7009)
    let (status, _body) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify token no longer works after revocation
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Token should fail after revocation"
    );
}

#[tokio::test]
async fn test_auth_code_flow_token_revocation() {
    // Issue auth code → exchange → verify userinfo works → revoke → verify 401
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "oauth-revoke@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Verify token works before revocation
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Token should work before revocation"
    );

    // Revoke the token
    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={}", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify token no longer works after revocation
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Token should fail after revocation"
    );
}

// ========================================================================
// P2: RFC 7009 — Token Revocation
// ========================================================================

#[tokio::test]
async fn test_rfc7009_revocation_200_ok_regardless() {
    // RFC 7009 Section 2: Revocation always returns 200 OK regardless of token validity.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke-ok@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    // Revoke a nonexistent token
    let response = http_post_form_full(
        &app,
        "/oauth/revoke",
        "token=nonexistent_token_value",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "Revocation must return 200 OK regardless of token validity"
    );
    // RFC 7009 Section 2.1: Response body SHOULD be empty
    assert!(
        response.body.is_empty() || response.body == "null",
        "Revocation response body should be empty, got: {}",
        response.body
    );
}

#[tokio::test]
async fn test_rfc7009_token_type_hint_handling() {
    // RFC 7009 Section 2: token_type_hint is accepted but not required.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke-hint@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Revoke with valid token_type_hint
    let response = http_post_form_full(
        &app,
        "/oauth/revoke",
        &format!("token={}&token_type_hint=access_token", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    // Verify token is actually revoked via introspection
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        result["active"], false,
        "Revoked token should be inactive on introspection"
    );
}

#[tokio::test]
async fn test_rfc7009_invalid_hint_still_processes() {
    // RFC 7009 Section 2.1: Invalid token_type_hint should still process.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke-bad-hint@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let response = http_post_form_full(
        &app,
        "/oauth/revoke",
        "token=some_token&token_type_hint=completely_invalid_hint",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "Invalid hint should still return 200 OK"
    );
}

// ========================================================================
// Phase 2: RFC 7009 — Token Revocation Advanced Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7009_revocation_with_token_type_hint() {
    // RFC 7009 Section 2: token_type_hint is accepted but not required.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke-hint@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();

    // Revoke with token_type_hint
    let (status, _) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={access_token}&token_type_hint=access_token"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Revocation with token_type_hint should return 200"
    );
}

#[tokio::test]
async fn test_rfc7009_revocation_with_invalid_hint() {
    // RFC 7009 Section 2: Invalid hint is accepted (server ignores it).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke-bad-hint@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, _) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={access_token}&token_type_hint=invalid_type"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Revocation with invalid hint should still return 200"
    );
}

#[tokio::test]
async fn test_rfc7009_revocation_client_auth_required() {
    // RFC 7009 Section 2: Revocation requires client authentication
    // for confidential clients.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke-noauth@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Revoke WITHOUT client credentials — RFC 7009 §2.1 requires 401
    let (status, _) =
        http_post_form(&app, "/oauth/revoke", &format!("token={access_token}"), &[]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Verify token is still active via introspection
    let auth_header = client.basic_auth_header();
    let (_, intro_body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    let intro: serde_json::Value = serde_json::from_str(&intro_body).expect("Valid JSON");
    assert_eq!(
        intro["active"], true,
        "Token should still be active after unauthenticated revocation attempt"
    );
}

#[tokio::test]
async fn test_revoke_already_revoked_token_returns_200() {
    // RFC 7009 Section 2.2: "The authorization server responds with HTTP status code 200
    // for both the case where the token has been successfully revoked and the case where
    // the client submitted an invalid token."
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "double-revoke@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // First revocation — should return 200
    let (status, _) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "First revocation must return 200");

    // Second revocation of the same (now-revoked) token — must also return 200
    let (status, _) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "RFC 7009 §2.2: revoking an already-revoked token must still return 200"
    );
}

#[tokio::test]
async fn test_rfc7009_cross_client_revocation_blocked() {
    // RFC 7009 Section 2.1: Client B must NOT be able to revoke Client A's token.
    // The server must verify the token was issued to the requesting client.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke-cross@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client_a = create_test_oauth_client(&state.store, &user.id).await;
    let client_b = create_test_oauth_client(&state.store, &user.id).await;

    // Issue token for client A
    let (token_a, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client_a).await;

    // Client B tries to revoke Client A's token — returns 200 but must NOT revoke
    let auth_b = client_b.basic_auth_header();
    let (status, _) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={}", token_a),
        &[("Authorization", &auth_b)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "RFC 7009: revocation always returns 200"
    );

    // Verify token is still active — cross-client revocation must be a no-op
    let auth_a = client_a.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", token_a),
        &[("Authorization", &auth_a)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        result["active"], true,
        "Cross-client revocation must not revoke the token"
    );
}
