// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7009 — Token Revocation tests.

use super::helpers::*;
use crate::db::User;
use crate::services::oidc::ScopeSet;

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

/// `Logout` audit events recorded for `user_id`.
async fn logout_events(state: &crate::AppState, user_id: &str) -> usize {
    state
        .audit
        .query_events(&db::AuditEventFilter {
            event_types: Some(vec![db::AuditEventKind::Logout.as_str().to_string()]),
            user_id: Some(user_id.to_string()),
            ..db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events")
        .len()
}

/// A token whose session row has expired but not been reaped no longer
/// decodes, so it is revoked by hash. The deleted row names the user, and the
/// `Logout` audit event is recorded as it is for a live token.
#[tokio::test]
async fn test_rfc7009_revoke_expired_row_records_logout() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "revoke-expired@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let (token, token_hash) = create_test_expired_session_row(
        &state,
        &user.id,
        &user.email,
        Some(&client.client_id),
        db::SessionPurpose::OAuthAccessToken,
    )
    .await;

    assert_eq!(revoke(&app, &client, &token).await, StatusCode::OK);

    assert!(
        db::find_session_by_token_hash(&state.store, &token_hash)
            .await
            .expect("find")
            .is_none(),
        "the expired row is deleted"
    );
    assert_eq!(logout_events(&state, &user.id).await, 1);
}

/// A token minted without the `email` scope carries no email claim. The
/// deleted session row supplies the email, so the `Logout` event keeps its
/// domain and stays in the org-scoped audit feed.
#[tokio::test]
async fn test_rfc7009_revoke_without_email_scope_records_org_visible_logout() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "revoke-no-email@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            client_id: Some(&client.client_id),
            scope: Some(ScopeSet::parse("openid")),
            ..Default::default()
        },
    )
    .await;

    assert_eq!(revoke(&app, &client, &token).await, StatusCode::OK);

    let events = state
        .audit
        .query_events(&db::AuditEventFilter {
            event_types: Some(vec![db::AuditEventKind::Logout.as_str().to_string()]),
            user_id: Some(user.id.clone()),
            email_domains: Some(vec!["example.com".to_string()]),
            ..db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events");
    assert_eq!(events.len(), 1, "org-visible Logout event: {events:?}");
}

// RFC 7009 §2.1: "The authorization server first validates the client
// credentials (in case of a confidential client) and then verifies whether the
// token was issued to the client making the revocation request." An expired
// token has no `client_id` claim to check, so the session row's is used.
#[tokio::test]
async fn test_rfc7009_revoke_expired_row_of_another_client_is_refused() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "revoke-expired-cross@example.com").await;
    let client_a = create_test_oauth_client(&state.store, &user.id).await;
    let client_b = create_test_oauth_client(&state.store, &user.id).await;
    let (token, token_hash) = create_test_expired_session_row(
        &state,
        &user.id,
        &user.email,
        Some(&client_a.client_id),
        db::SessionPurpose::OAuthAccessToken,
    )
    .await;

    assert_eq!(
        revoke(&app, &client_b, &token).await,
        StatusCode::OK,
        "RFC 7009: revocation always returns 200"
    );

    assert!(
        db::find_session_by_token_hash(&state.store, &token_hash)
            .await
            .expect("find")
            .is_some(),
        "client B must not delete client A's session row"
    );
    assert_eq!(logout_events(&state, &user.id).await, 0);
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
    user: &User,
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
    user: &User,
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
/// `private_key_jwt` assertion MUST be rejected during client authentication
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

// ========================================================================
// Audit categorization for M2M (`client_credentials`) revocation
// ========================================================================
//
// Bug: revoking an M2M / `client_credentials` access token — live or expired —
// recorded an auth-family `Logout` audit event whose `user_id` was the OAuth
// `client_id` (a client, not a user) and whose `email_domain` was NULL, making
// the row invisible in every org-scoped audit consumer (SIEM API + admin UI,
// which filter by `email_domains`). The correct event is the OAuth-family
// `OauthTokenRevoked` with `user_id = None`, mirroring M2M *issuance*
// (`OauthTokenIssued` with `user_id = None`) and the admin "revoke all tokens"
// path. The row was also retained 90 days (auth retention) instead of 30
// (oauth retention) and misclassified to OCSF class Authentication/LOGOFF
// instead of AuthorizeSession/OAUTH_TOKEN_REVOKED.
//
// Introduced by 1eb0b5c4: the rewritten audit block kept `AuthEventType::
// Logout` as the only event type regardless of token kind, and read `user_id`
// from `sub` / `deleted_row.user_id` — both of which hold `client_id` for M2M
// tokens. The `is_m2m` flag computed from the decoded JWT gated only the email
// lookup, never the event type, and the new `deleted_row` fallback path had
// no M2M detection at all.

/// Query `OauthTokenRevoked` audit rows matching an optional filter.
async fn oauth_token_revoked_events(
    state: &crate::AppState,
    filter: db::AuditEventFilter,
) -> Vec<db::AuditEvent> {
    state
        .audit
        .query_events(&db::AuditEventFilter {
            event_types: Some(vec![
                db::AuditEventKind::OauthTokenRevoked.as_str().to_string(),
            ]),
            ..filter
        })
        .await
        .expect("query audit events")
}

/// Build a test client authorized for the `client_credentials` grant.
async fn create_test_m2m_client(
    state: &std::sync::Arc<crate::AppState>,
    owner: &User,
    spec: TestClientSpec,
) -> TestOAuthClient {
    create_test_client(&state.store, &owner.id, spec).await
}

/// A live M2M access token revoked via `/oauth/revoke` records an
/// OAuth-family `OauthTokenRevoked` audit event with `user_id = None` (the
/// `client_id` is NOT stored in the `user_id` column), and records NO
/// auth-family `Logout` event for the `client_id`.
///
/// Before the fix this wrote a `Logout` row with `user_id = client_id` and no
/// `OauthTokenRevoked` row at all.
#[tokio::test]
async fn repro_m2m_revoke_records_oauth_token_revoked_not_logout() {
    let (app, state) = test_app().await;
    let owner = create_test_user(&state.store, "m2m-revoke-audit@example.com").await;
    let client = create_test_m2m_client(
        &state,
        &owner,
        TestClientSpec {
            grant_types: Some(vec!["client_credentials".to_string()]),
            ..Default::default()
        },
    )
    .await;

    let token = issue_m2m_token(&app, &client).await;
    assert_eq!(revoke(&app, &client, &token).await, StatusCode::OK);

    // No auth-family `Logout` event is attributed to the client_id. Before
    // the fix this was 1 — the row that made M2M revocations appear as human
    // logoffs attributed to the client.
    assert_eq!(
        logout_events(&state, &client.client_id).await,
        0,
        "M2M revocation must NOT record a Logout event for the client_id"
    );

    // The revocation is recorded as an OAuth-family event with `user_id`
    // absent — the `client_id` is not a user.
    let events = oauth_token_revoked_events(&state, db::AuditEventFilter::default()).await;
    assert_eq!(
        events.len(),
        1,
        "exactly one OauthTokenRevoked event for a live M2M revocation: {events:?}"
    );
    assert!(
        events[0].user_id.is_none(),
        "user_id must be None for M2M revocation: {:?}",
        events[0]
    );

    // The audit identifier matches the application's document id (the value
    // issuance and the admin revocation path stamp), so per-application usage
    // stats — which filter `data.oauth_client_id == app_id` — count
    // per-token revocations too.
    let data: serde_json::Value = serde_json::from_str(&events[0].data).expect("valid JSON data");
    assert_eq!(
        data["oauth_client_id"], client.app_id,
        "oauth_client_id must be the app's document id (consistent with issuance \
         and the admin revoke-all-tokens path): {data}"
    );
}

/// A revocation of an expired M2M session row (whose token no longer decodes)
/// records the same OAuth-family `OauthTokenRevoked` event with `user_id =
/// None`, not a `Logout` attributed to the client_id.
///
/// This is the regression path added by 1eb0b5c4: the expired row's `user_id`
/// is `client_id`, and the rewritten audit block read it directly into the
/// `Logout` event. The extended `is_m2m` detection (from the deleted row's
/// `session_type == M2MAccessToken`) is what routes it to the OAuth event.
#[tokio::test]
async fn repro_m2m_revoke_expired_row_records_oauth_token_revoked() {
    let (app, state) = test_app().await;
    let owner = create_test_user(&state.store, "m2m-revoke-expired@example.com").await;
    let client = create_test_m2m_client(
        &state,
        &owner,
        TestClientSpec {
            grant_types: Some(vec!["client_credentials".to_string()]),
            ..Default::default()
        },
    )
    .await;

    // Seed an expired (non-decoding) M2M session row keyed by an opaque
    // cookie, matching the shape a reaper has not yet cleaned up.
    let (token, token_hash) = create_test_expired_session_row(
        &state,
        &client.client_id,
        "",
        Some(&client.client_id),
        db::SessionPurpose::M2MAccessToken,
    )
    .await;

    assert_eq!(revoke(&app, &client, &token).await, StatusCode::OK);
    assert!(
        db::find_session_by_token_hash(&state.store, &token_hash)
            .await
            .expect("find")
            .is_none(),
        "the expired M2M row is deleted by revocation"
    );

    assert_eq!(
        logout_events(&state, &client.client_id).await,
        0,
        "expired M2M revocation must NOT record a Logout event for the client_id"
    );

    let events = oauth_token_revoked_events(&state, db::AuditEventFilter::default()).await;
    assert_eq!(
        events.len(),
        1,
        "exactly one OauthTokenRevoked event for an expired M2M revocation: {events:?}"
    );
    assert!(
        events[0].user_id.is_none(),
        "user_id must be None for expired M2M revocation: {:?}",
        events[0]
    );
}

/// An M2M token issued to an org-scoped client records an `OauthTokenRevoked`
/// event whose `email_domain` is the client's own org domain, so the row
/// appears in the org-scoped audit feed (SIEM API + admin UI), which filter
/// by `email_domains`.
///
/// Before the fix the `Logout` row had a NULL `email_domain` (no human email
/// for M2M) and was therefore invisible in every org-scoped consumer.
#[tokio::test]
async fn repro_m2m_revoke_org_scoped_event_appears_in_org_feed() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "m2m-revoke-org.example.com").await;
    let owner = create_test_user(&state.store, "m2m-revoke-org@example.com").await;
    let client = create_test_m2m_client(
        &state,
        &owner,
        TestClientSpec {
            grant_types: Some(vec!["client_credentials".to_string()]),
            org_id: Some(org.id.clone()),
            ..Default::default()
        },
    )
    .await;

    let token = issue_m2m_token(&app, &client).await;
    assert_eq!(revoke(&app, &client, &token).await, StatusCode::OK);

    // An org-scoped audit query (the SIEM API / admin UI shape) — filtering by
    // `email_domains = [org_domain]` — must find the `OauthTokenRevoked` row.
    let events = oauth_token_revoked_events(
        &state,
        db::AuditEventFilter {
            email_domains: Some(vec!["m2m-revoke-org.example.com".to_string()]),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        events.len(),
        1,
        "org-scoped audit feed must surface the M2M OauthTokenRevoked event: {events:?}"
    );
    assert!(
        events[0].user_id.is_none(),
        "user_id must be None for M2M revocation: {:?}",
        events[0]
    );
    assert_eq!(
        events[0].email_domain.as_deref(),
        Some("m2m-revoke-org.example.com"),
        "email_domain must be the client's own org domain: {:?}",
        events[0]
    );
}
