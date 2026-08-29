// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 6749 Section 10.5 — authorization-code (and device-code) replay
//! revocation precision.
//!
//! Regression for the over-broad revocation bug: when an authorization code
//! was replayed, the server revoked **every** OAuth session for the user
//! (`delete_oauth_sessions_for_user`), logging the victim out of all
//! applications. Per RFC 6749 §10.5, replay must revoke only the tokens
//! previously issued based on **that** authorization code. These tests drive
//! the full `/oauth/token` flow to confirm a replay revokes only the
//! compromised code's session while the user's other sessions survive.

use super::helpers::*;

/// Issue a fresh authorization code via the real `issue_authorization_code`
/// service, returning the opaque code string so the caller can exchange or
/// replay it. `nonce` distinguishes otherwise-identical codes issued within
/// the same second — the authorization-code JWT carries no `jti`, so two
/// calls with the same subject/client/scope/redirect in the same second would
/// otherwise mint byte-identical (and thus same-hash) codes.
async fn issue_code(
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    auth_id: &str,
    client: &TestOAuthClient,
    nonce: &str,
) -> String {
    use crate::db::ParConsumptionProof;
    use crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS;

    let scope = ScopeSet::parse("openid email");
    let params = AuthorizationCodeParams {
        client_id: &client.client_id,
        redirect_uri: "https://example.com/callback",
        user_id: &user.id,
        email: &user.email,
        authenticator_id: auth_id,
        aaguid: None,
        scope: &scope,
        nonce: Some(nonce),
        code_challenge: None,
        code_challenge_method: None,
        resource: None,
        acr_values: None,
        dpop_jkt: None,
        auth_code_lifetime_seconds: STANDARD_AUTH_CODE_LIFETIME_SECONDS,
        authorization_details: None,
        auth_time: None,
        par: ParConsumptionProof::not_pushed(),
    };
    issue_authorization_code(state, params)
        .await
        .expect("issue authorization code")
}

/// Exchange an authorization code at `/oauth/token`. Returns `(status, body)`.
async fn exchange_code(
    app: &axum::Router,
    client: &TestOAuthClient,
    code: &str,
) -> (axum::http::StatusCode, String) {
    http_post_form(
        app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}",
            "https://example.com/callback"
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await
}

/// Create an authorized device auth request directly in the DB (mirrors the
/// fapi2.rs helper) and return the plaintext `device_code` the client polls
/// with. Uses the built-in CLI flow (`client_id = None`) so no sender
/// constraint is required.
async fn setup_authorized_device(
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    auth_id: &str,
    label: &str,
) -> String {
    let device_code = format!("replay_dev_{label}");
    let device_code_hash = sha256_base64url(&device_code);
    let user_code = format!("RP{label}");
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(1))
        .expect("expiry");
    let id = crate::db::create_device_auth_request(
        &state.store,
        &device_code_hash,
        &user_code,
        None,
        expires_at,
        0,
    )
    .await
    .expect("create device auth");
    crate::db::authorize_device_auth(
        &state.store,
        crate::db::AuthorizeDeviceAuthParams {
            id: &id,
            user_id: &user.id,
            user_email: &user.email,
            authenticator_id: auth_id,
            hardware_verified: true,
        },
    )
    .await
    .expect("authorize device");
    device_code
}

fn device_token_body(device_code: &str) -> String {
    format!("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}")
}

/// Assert that a bearer token is accepted (200) at `/v1/keys`.
async fn assert_token_alive(app: &axum::Router, token: &str, label: &str) {
    let (status, body) = http_get(
        app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{label} should still be valid, got {status}: {body}"
    );
}

/// Assert that a bearer token is rejected (401) at `/v1/keys`.
async fn assert_token_revoked(app: &axum::Router, token: &str, label: &str) {
    let (status, body) = http_get(
        app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "{label} should be revoked, got {status}: {body}"
    );
}

/// Introspect a token with `client`'s credentials and return the parsed
/// `active` flag. Used for tokens whose audience is the registered client
/// (auth-code grant) — `/v1/keys` rejects those on audience grounds, so
/// introspection is the behavioral validity probe.
async fn is_active_via_introspect(
    app: &axum::Router,
    client: &TestOAuthClient,
    token: &str,
) -> bool {
    let (_status, body) = http_post_form(
        app,
        "/oauth/introspect",
        &format!("token={token}"),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;
    serde_json::from_str::<serde_json::Value>(&body)
        .expect("introspection json")
        .get("active")
        .and_then(|v| v.as_bool())
        .expect("active flag")
}

async fn assert_introspect_active(
    app: &axum::Router,
    client: &TestOAuthClient,
    token: &str,
    label: &str,
) {
    assert!(
        is_active_via_introspect(app, client, token).await,
        "{label} should be active before/after the replay"
    );
}

async fn assert_introspect_inactive(
    app: &axum::Router,
    client: &TestOAuthClient,
    token: &str,
    label: &str,
) {
    assert!(
        !is_active_via_introspect(app, client, token).await,
        "{label} should be inactive (revoked) after the replay"
    );
}

// ============================================================================
// Authorization-code grant replay
// ============================================================================

/// RFC 6749 Section 10.5: replaying an authorization code must revoke only the
/// session issued from **that** code. The user's session from a different
/// code, and a session from a grant with no single-use code (browser login),
/// must both keep working — the bugrevoked every session for the user.
#[tokio::test]
async fn test_auth_code_replay_revokes_only_the_replayed_code_session() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "replay-auth@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Code A → token A (the session we will revoke by replaying code A).
    let code_a = issue_code(&state, &user, &auth, &client, "a").await;
    let (status, body) = exchange_code(&app, &client, &code_a).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "code A exchange should succeed: {body}"
    );
    let token_a: String = serde_json::from_str::<serde_json::Value>(&body)
        .expect("json")
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("access_token")
        .to_string();

    // Code B → token B (a different authorization code for the same user).
    let code_b = issue_code(&state, &user, &auth, &client, "b").await;
    let (status, body) = exchange_code(&app, &client, &code_b).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "code B exchange should succeed: {body}"
    );
    let token_b: String = serde_json::from_str::<serde_json::Value>(&body)
        .expect("json")
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("access_token")
        .to_string();

    // Token C: a session from a grant with no single-use code (browser/FIDO2
    // style bootstrap). Replay-based revocation must never touch it.
    let token_c = create_test_session(&state, &user.id, &user.email, &auth).await;

    // Sanity: all three sessions are alive before the replay. token_a/token_b
    // are client-scoped (aud = client_id), so they are probed via introspection;
    // token_c is base_url-audience, so it is probed via /v1/keys.
    assert_introspect_active(&app, &client, &token_a, "token_a (pre-replay)").await;
    assert_introspect_active(&app, &client, &token_b, "token_b (pre-replay)").await;
    assert_token_alive(&app, &token_c, "token_c (pre-replay)").await;

    // Replay code A — must be rejected with invalid_grant.
    let (status, body) = exchange_code(&app, &client, &code_a).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replayed code A must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        error["error"], "invalid_grant",
        "replayed code must return invalid_grant: {body}"
    );

    // The compromised code's session is revoked.
    assert_introspect_inactive(&app, &client, &token_a, "token_a (replayed code)").await;
    // The user's other sessions survive — no mass logout.
    assert_introspect_active(&app, &client, &token_b, "token_b (different code)").await;
    assert_token_alive(&app, &token_c, "token_c (no single-use code)").await;
}

/// A second replay of the same already-consumed code is still rejected, and
/// still revokes nothing further (the code's session was already removed).
#[tokio::test]
async fn test_auth_code_replay_twice_still_rejects_and_revokes_nothing_new() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "replay-twice@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let code = issue_code(&state, &user, &auth, &client, "c").await;
    let (status, body) = exchange_code(&app, &client, &code).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "initial code exchange should succeed: {body}"
    );
    let token: String = serde_json::from_str::<serde_json::Value>(&body)
        .expect("json")
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("access_token")
        .to_string();

    // First replay revokes the code's session.
    let (status, _) = exchange_code(&app, &client, &code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "first replay must reject");
    assert_introspect_inactive(&app, &client, &token, "token after first replay").await;

    // Second replay is still rejected and changes nothing.
    let (status, _) = exchange_code(&app, &client, &code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "second replay must reject");
    assert_introspect_inactive(&app, &client, &token, "token after second replay").await;
}

// ============================================================================
// Device-code grant replay (RFC 8628 + RFC 6749 §10.5)
// ============================================================================

/// Replaying a consumed device code must revoke only the session issued from
/// that device code, not every session for the user.
#[tokio::test]
async fn test_device_code_replay_revokes_only_the_replayed_code_session() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "replay-device@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;

    // Device code A → token A.
    let device_code_a = setup_authorized_device(&state, &user, &auth, "a").await;
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &device_token_body(&device_code_a),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "device code A poll should succeed: {body}"
    );
    let token_a: String = serde_json::from_str::<serde_json::Value>(&body)
        .expect("json")
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("access_token")
        .to_string();

    // Device code B → token B (a separate device authorization for the user).
    let device_code_b = setup_authorized_device(&state, &user, &auth, "b").await;
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &device_token_body(&device_code_b),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "device code B poll should succeed: {body}"
    );
    let token_b: String = serde_json::from_str::<serde_json::Value>(&body)
        .expect("json")
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("access_token")
        .to_string();

    // Token C: a session from a grant with no single-use code.
    let token_c = create_test_session(&state, &user.id, &user.email, &auth).await;

    // Replay device code A — must be rejected with invalid_grant.
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &device_token_body(&device_code_a),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replayed device code A must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        error["error"], "invalid_grant",
        "replayed device code must return invalid_grant: {body}"
    );

    // Only the replayed device code's session is revoked; the others survive.
    assert_token_revoked(&app, &token_a, "device token_a (replayed code)").await;
    assert_token_alive(&app, &token_b, "device token_b (different code)").await;
    assert_token_alive(&app, &token_c, "token_c (no single-use code)").await;
}
