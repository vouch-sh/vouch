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

/// Issue a real access token to `jwt_client` by exchanging an authorization
/// code at `/oauth/token` using `private_key_jwt` authentication.
///
/// Each call mints a fresh authorization code (distinct `nonce`) and a fresh
/// assertion (distinct issuance `jti`) so the resulting tokens are backed by
/// independent real session rows. The token is issued *to* the JWT client, so
/// the `/oauth/revoke` ownership check (`caller_client_id == claims.client_id`)
/// passes and `svc_revoke` actually runs against the victim's session.
async fn issue_token_to_private_key_jwt_client(
    app: &axum::Router,
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    authenticator_id: &str,
    jwt_client: &TestOAuthClient,
    pkcs8_bytes: &[u8],
    issuance_jti: &str,
) -> String {
    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let code = issue_code(
        state,
        user,
        authenticator_id,
        &jwt_client.client_id,
        TestCodeSpec {
            nonce: Some(issuance_jti),
            ..Default::default()
        },
    )
    .await;
    let assertion = build_client_assertion(
        &jwt_client.client_id,
        &token_endpoint,
        pkcs8_bytes,
        Some(issuance_jti),
    );
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={redirect}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
        redirect = urlencoding::encode("https://example.com/callback"),
    );
    let (status, resp_body) = http_post_form(app, "/oauth/token", &body, &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token issuance via private_key_jwt must succeed: {resp_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON response");
    json["access_token"]
        .as_str()
        .expect("response contains access_token")
        .to_string()
}

/// Regression for the TOCTOU in the `revoke` handler: a replayed
/// `private_key_jwt` assertion MUST be rejected at `PendingJti::commit`
/// *before* `svc_revoke` runs, so the replay cannot delete the victim's
/// sessions while still returning 401.
///
/// The existing [`test_rfc7009_revoke_private_key_jwt_jti_replay_rejected`]
/// uses fake token strings (`some_token` / `some_other_token`) that match no
/// real session, so `svc_revoke` is a no-op and the 401 assertion passes
/// regardless of commit ordering — it cannot distinguish "replay prevented
/// before the business logic" from "business logic ran but was a no-op".
///
/// This test creates a **real** access token (a real session), performs a
/// legitimate first revocation that commits the JTI (which deletes all the
/// user's sessions), issues a **second** real token, then replays the same
/// JTI against the second token. Under the bug, `svc_revoke` deletes the
/// second session *before* the JTI replay is detected, so the second token
/// stops working despite the 401 replay response. Under the fix, the JTI
/// commit runs first and returns 401, `svc_revoke` never runs, and the second
/// token keeps working.
#[tokio::test]
async fn test_rfc7009_revoke_jti_replay_does_not_revoke_sessions_before_reject() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoke-toctou@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (jwt_client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    // Issue a real access token to the JWT client so the revoke-endpoint
    // ownership check passes and `svc_revoke` actually performs revocation.
    let token_first = issue_token_to_private_key_jwt_client(
        &app,
        &state,
        &user,
        &auth_id,
        &jwt_client,
        &pkcs8_bytes,
        "revoke-toctou-issue-1",
    )
    .await;

    let revoke_url = format!("{}/oauth/revoke", state.config().base_url);
    let replay_jti = "revoke-toctou-replay-jti";

    // Legitimate first revocation with `replay_jti`: commits the JTI and
    // revokes the user's (single) session. Must return 200.
    let assertion = build_client_assertion(
        &jwt_client.client_id,
        &revoke_url,
        &pkcs8_bytes,
        Some(replay_jti),
    );
    let body1 = format!(
        "token={token_first}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
    );
    let (status1, _) = http_post_form(&app, "/oauth/revoke", &body1, &[]).await;
    assert_eq!(
        status1,
        StatusCode::OK,
        "first (legitimate) revocation must return 200"
    );

    // The first revocation deleted ALL the user's sessions (human-presence
    // logout). Issue a fresh token (a new session) to replay against.
    let token_second = issue_token_to_private_key_jwt_client(
        &app,
        &state,
        &user,
        &auth_id,
        &jwt_client,
        &pkcs8_bytes,
        "revoke-toctou-issue-2",
    )
    .await;

    // Sanity: the second token is alive before the replay.
    let (status, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token_second}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "second token must work before the replay"
    );

    // Replay the SAME JTI (assertion) with the fresh token.
    let body2 = format!(
        "token={token_second}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
    );
    let (status2, _) = http_post_form(&app, "/oauth/revoke", &body2, &[]).await;
    assert_eq!(
        status2,
        StatusCode::UNAUTHORIZED,
        "replayed JTI at revoke must be rejected with 401"
    );

    // The replay MUST NOT have revoked the second token. Under the bug,
    // `svc_revoke` ran before the JTI commit and deleted the user's session,
    // so this userinfo lookup would return 401 despite the replay being
    // rejected — the session is already gone.
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token_second}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "replayed JTI must NOT delete the victim's session before the replay \
         is rejected — the second token must still work after the 401 replay \
         (got {status}: {body})"
    );
}
