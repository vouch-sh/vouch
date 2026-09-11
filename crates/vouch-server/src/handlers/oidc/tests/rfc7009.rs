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

// ========================================================================
// RFC 7009 — Token Revocation
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

// ========================================================================
// RFC 7009 — Token Revocation with private_key_jwt (GH#274)
// ========================================================================

#[tokio::test]
async fn test_rfc7009_revoke_with_private_key_jwt_succeeds() {
    // RFC 7009 + RFC 7523: Revocation with private_key_jwt authentication.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke-jwt@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (jwt_client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    // Issue a token via a separate client_secret client (to have a token to revoke)
    let secret_client = create_test_oauth_client(&state.store, &user.id).await;
    let (token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &secret_client).await;

    // Revoke using private_key_jwt with aud=/oauth/revoke
    let revoke_url = format!("{}/oauth/revoke", state.config().base_url);
    let assertion = build_client_assertion(&jwt_client.client_id, &revoke_url, &pkcs8_bytes, None);

    let body = format!(
        "token={}&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        token, assertion
    );

    let (status, _) = http_post_form(&app, "/oauth/revoke", &body, &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Revocation with private_key_jwt must return 200"
    );
}

#[tokio::test]
async fn test_rfc7009_revoke_private_key_jwt_jti_replay_rejected() {
    // GH#274: Replayed JWT assertion at /oauth/revoke must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke-replay@example.com").await;
    let (jwt_client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let revoke_url = format!("{}/oauth/revoke", state.config().base_url);
    let fixed_jti = "revoke-replay-jti-001";

    // First revocation with a fixed JTI — should return 200
    let assertion1 = build_client_assertion(
        &jwt_client.client_id,
        &revoke_url,
        &pkcs8_bytes,
        Some(fixed_jti),
    );
    let body1 = format!(
        "token=some_token\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        assertion1
    );
    let (status1, _) = http_post_form(&app, "/oauth/revoke", &body1, &[]).await;
    assert_eq!(
        status1,
        StatusCode::OK,
        "First use of JTI at revoke must return 200"
    );

    // Second revocation with the SAME JTI — must be rejected (replay)
    let assertion2 = build_client_assertion(
        &jwt_client.client_id,
        &revoke_url,
        &pkcs8_bytes,
        Some(fixed_jti),
    );
    let body2 = format!(
        "token=some_other_token\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        assertion2
    );
    let (status2, _) = http_post_form(&app, "/oauth/revoke", &body2, &[]).await;
    assert_eq!(
        status2,
        StatusCode::UNAUTHORIZED,
        "Replayed JTI at revoke must be rejected with 401"
    );
}

// ========================================================================
// M2M (client_credentials) revocation blast-radius regression
// ========================================================================
//
// Bug: `revoke_token` deleted ALL of a client's sessions via
// `delete_sessions_for_user(client_id)` when revoking an M2M access token,
// because M2M sessions are keyed by `user_id == client_id`. Revoking one
// token invalidated every concurrent live M2M token for that client,
// violating RFC 7009 §2.1 ("the particular token").

/// Issue an M2M (`client_credentials`) access token via `/oauth/token`.
async fn issue_m2m_token(app: &axum::Router, client: &TestOAuthClient) -> String {
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        app,
        "/oauth/token",
        "grant_type=client_credentials",
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "client_credentials issuance must succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    response["access_token"]
        .as_str()
        .expect("access_token in response")
        .to_string()
}

/// Introspect `token` as an authenticated client, returning the parsed
/// response. Used to read the `active` flag pre- and post-revocation.
async fn introspect(
    app: &axum::Router,
    client: &TestOAuthClient,
    token: &str,
) -> serde_json::Value {
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        app,
        "/oauth/introspect",
        &format!("token={token}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "introspection must not error: {body}"
    );
    serde_json::from_str(&body).expect("Valid JSON")
}

/// Revoke `token` as an authenticated client.
async fn revoke(app: &axum::Router, client: &TestOAuthClient, token: &str) -> StatusCode {
    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        app,
        "/oauth/revoke",
        &format!("token={token}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    status
}

/// Reproduction test: revoking one M2M access token must NOT revoke the
/// client's other concurrent live M2M token (RFC 7009 §2.1 targets "the
/// particular token").
///
/// Before the fix, `revoke_token` routed every decodable token through
/// `delete_sessions_for_user(sub)`; for M2M tokens `sub == client_id`, so
/// that call deleted every M2M session for the client. This test mints two
/// distinct M2M access tokens for the same client, revokes only token A, and
/// asserts token B remains active.
#[tokio::test]
async fn repro_m2m_revoke_revokes_all_client_tokens() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "m2m-revoke@example.com").await;
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            grant_types: Some(vec!["client_credentials".to_string()]),
            ..TestClientSpec::default()
        },
    )
    .await;

    // Mint two distinct M2M access tokens for the same client.
    let token_a = issue_m2m_token(&app, &client).await;
    let token_b = issue_m2m_token(&app, &client).await;
    assert_ne!(token_a, token_b, "two grants must mint distinct tokens");

    // Pre-revoke: both tokens coexist and introspect active — this also
    // confirms the codebase permits two concurrent M2M sessions per client
    // (each grant is a fresh `store.insert` with a distinct `token_hash`).
    let intro_a = introspect(&app, &client, &token_a).await;
    assert_eq!(
        intro_a["active"], true,
        "token A must be active before revocation: {intro_a}"
    );
    let intro_b = introspect(&app, &client, &token_b).await;
    assert_eq!(
        intro_b["active"], true,
        "token B must be active before revocation: {intro_b}"
    );

    // Revoke ONLY token A (RFC 7009 §2.1: "the particular token").
    let status = revoke(&app, &client, &token_a).await;
    assert_eq!(status, StatusCode::OK, "revocation must return 200");

    // Token A is now revoked.
    let intro_a_after = introspect(&app, &client, &token_a).await;
    assert_eq!(
        intro_a_after["active"], false,
        "revoked token A must introspect as inactive: {intro_a_after}"
    );

    // Token B — never named in any revocation request — must remain active.
    // Before the fix this asserted false (`active: false`) because the bulk
    // `delete_sessions_for_user(client_id)` swept it away alongside token A.
    let intro_b_after = introspect(&app, &client, &token_b).await;
    assert_eq!(
        intro_b_after["active"], true,
        "revoking token A must NOT revoke the client's other live M2M token B: {intro_b_after}"
    );
}

/// Regression guard for the human "full logout" behavior the bulk-delete
/// branch implements and the fix must preserve. Issues two distinct human
/// access tokens for the same user (each via a separate authorization-code
/// grant with a distinct nonce to keep the single-use codes distinct even
/// within the same second), revokes only the first, and asserts BOTH are
/// now unauthorized at `/oauth/userinfo`.
#[tokio::test]
async fn repro_human_revoke_does_full_logout() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "human-revoke@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue two distinct human access tokens for the same user, each via a
    // separate authorization-code grant. Distinct nonces keep the HS256
    // authorization codes byte-distinct even when issued in the same second
    // (they carry no `jti`, only `iat`), so the two single-use codes have
    // distinct hashes and don't collide in code-replay storage.
    let token_a = issue_human_token(&app, &state, &user, &auth_id, &client, "nonce-a").await;
    let token_b = issue_human_token(&app, &state, &user, &auth_id, &client, "nonce-b").await;
    assert_ne!(token_a, token_b, "two grants must mint distinct tokens");

    // Both tokens work before revocation.
    let (status, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token A should work before revoke");
    let (status, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token_b}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token B should work before revoke");

    // Revoke ONLY token A.
    let status = revoke(&app, &client, &token_a).await;
    assert_eq!(status, StatusCode::OK, "revocation must return 200");

    // Human logout = full logout: revoking token A must invalidate token B
    // too, because both sessions belong to the same `user_id`.
    let (status_a, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(
        status_a,
        StatusCode::UNAUTHORIZED,
        "token A must be unauthorized after revoke"
    );
    let (status_b, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token_b}"))],
    )
    .await;
    assert_eq!(
        status_b,
        StatusCode::UNAUTHORIZED,
        "token B must also be unauthorized (full logout for human users)"
    );
}

/// Issue a human (authorization_code) access token with a distinct nonce so
/// two codes issued within the same second remain byte-distinct.
async fn issue_human_token(
    app: &axum::Router,
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    auth_id: &str,
    client: &TestOAuthClient,
    nonce: &str,
) -> String {
    let code = issue_code(
        state,
        user,
        auth_id,
        &client.client_id,
        TestCodeSpec {
            nonce: Some(nonce),
            ..Default::default()
        },
    )
    .await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token exchange should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    response["access_token"]
        .as_str()
        .expect("access_token present")
        .to_string()
}
