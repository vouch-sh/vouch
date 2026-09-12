// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8628 — Device Authorization Grant tests.

use super::helpers::*;
use crate::crypto::webauthn_verify::AuthTime;
use crate::db::DeviceApproval;

#[tokio::test]
async fn test_rfc8628_device_authorization_response_format() {
    // RFC 8628 Section 3.2: Device authorization response must include
    // required fields: device_code, user_code, verification_uri, expires_in, interval.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "device-resp@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}&scope=openid", client.client_id),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 8628 Section 3.2: REQUIRED fields
    assert!(
        response.get("device_code").is_some(),
        "Must have device_code"
    );
    assert!(response.get("user_code").is_some(), "Must have user_code");
    assert!(
        response.get("verification_uri").is_some(),
        "Must have verification_uri"
    );
    assert!(response.get("expires_in").is_some(), "Must have expires_in");
    assert!(response.get("interval").is_some(), "Must have interval");
}

#[tokio::test]
async fn test_rfc8628_verification_uri_complete() {
    // RFC 8628 Section 3.2: Response SHOULD include verification_uri_complete.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "device-complete@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}&scope=openid", client.client_id),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 8628 Section 3.2: verification_uri_complete is OPTIONAL
    // but RECOMMENDED. If present, it should contain the user_code.
    if let Some(complete_uri) = response.get("verification_uri_complete") {
        let uri_str = complete_uri
            .as_str()
            .expect("verification_uri_complete is a string");
        let user_code = response["user_code"].as_str().expect("user_code");
        assert!(
            uri_str.contains(user_code),
            "verification_uri_complete should contain the user_code"
        );
    }
    // If not present, that's acceptable per the RFC (OPTIONAL field)
}

#[tokio::test]
async fn test_rfc8628_pending_token_request() {
    // RFC 8628 Section 3.5: Polling before user authorizes returns authorization_pending.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "device-pending@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Get device code
    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}&scope=openid", client.client_id),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let device_code = response["device_code"].as_str().expect("device_code");

    // Poll token endpoint — should return authorization_pending
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
            device_code
        ),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "authorization_pending",
        "Unfinished device code should return authorization_pending"
    );
}

/// Create an approved device authorization directly in the store and return the
/// plaintext `device_code` the client polls with. `label` distinguishes
/// concurrent device authorizations within one test.
async fn setup_authorized_device(
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    authenticator_id: &str,
    label: &str,
) -> String {
    let device_code = format!("replay_dev_{label}");
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(1))
        .expect("device code expiry");
    let id = crate::db::create_device_auth_request(
        &state.store,
        &sha256_base64url(&device_code),
        &format!("RP{label}"),
        None,
        expires_at,
        0,
    )
    .await
    .expect("create device authorization request");
    crate::db::authorize_device_auth(
        &state.store,
        crate::db::AuthorizeDeviceAuthParams {
            id: &id,
            user_id: &user.id,
            user_email: &user.email,
            authenticator_id,
            verification: DeviceApproval::Observed(AuthTime::for_test(
                jiff::Timestamp::now().as_second(),
            )),
        },
    )
    .await
    .expect("approve device authorization");
    device_code
}

/// Poll `/oauth/token` with the device code grant.
async fn poll_device_token(app: &axum::Router, device_code: &str) -> (StatusCode, String) {
    http_post_form(
        app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code\
             &device_code={device_code}"
        ),
        &[],
    )
    .await
}

/// OIDC Core §2 defines `auth_time` as the "Time when the End-User
/// authentication occurred." The device-code grant issues its token in a
/// later `/oauth/token` poll, so the claim must be the ceremony instant
/// recorded at approval — stamping the poll instant instead widens the
/// key-deletion step-up freshness window by the ceremony-to-poll delay,
/// which a suspended host can stretch to the device code's lifetime.
#[tokio::test]
async fn test_device_grant_auth_time_is_ceremony_instant_not_poll_instant() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "auth-time-device@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;

    let device_code = "auth_time_dev";
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(1))
        .expect("device code expiry");
    let id = crate::db::create_device_auth_request(
        &state.store,
        &sha256_base64url(device_code),
        "AUTH-TIME",
        None,
        expires_at,
        0,
    )
    .await
    .expect("create device authorization request");

    // A ceremony that happened well before the poll.
    let ceremony_time = jiff::Timestamp::now().as_second().saturating_sub(300);
    crate::db::authorize_device_auth(
        &state.store,
        crate::db::AuthorizeDeviceAuthParams {
            id: &id,
            user_id: &user.id,
            user_email: &user.email,
            authenticator_id: &auth,
            verification: DeviceApproval::Observed(AuthTime::for_test(ceremony_time)),
        },
    )
    .await
    .expect("approve device authorization");

    let (status, body) = poll_device_token(&app, device_code).await;
    assert_eq!(status, StatusCode::OK, "device grant should issue: {body}");
    let token = serde_json::from_str::<serde_json::Value>(&body).expect("token response is JSON")
        ["access_token"]
        .as_str()
        .expect("access_token present")
        .to_string();

    let claims = decode_jwt_payload(&token);
    assert_eq!(
        claims["auth_time"], ceremony_time,
        "auth_time must be the ceremony instant recorded at approval, \
         not the later poll instant"
    );
}

/// An approval row written before the ceremony instant was recorded is
/// hardware-verified with no `auth_time`. The grant must issue it as such —
/// `hardware_verified` true, `auth_time` absent — rather than substituting
/// the poll instant, so the key-deletion freshness gate reads epoch via
/// `auth_time.unwrap_or(0)` and challenges (the rejection half is pinned by
/// `test_require_fresh_timestamp_epoch_is_rejected` in `services::keys`).
#[tokio::test]
async fn test_device_grant_preserves_absent_auth_time_on_legacy_approval() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "legacy-device@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;

    let device_code = "legacy_auth_time_dev";
    let doc = crate::db::documents::device_auth::DeviceAuthRequestDoc {
        device_code_hash: sha256_base64url(device_code),
        user_code: "LGCY-AUTH".to_string(),
        status: crate::db::DeviceAuthStatus::Authorized,
        client_id: None,
        user_id: Some(user.id.clone()),
        user_email: Some(user.email.clone()),
        authenticator_id: Some(auth),
        hardware_verified: true,
        // The legacy shape: verified, but no ceremony instant recorded.
        auth_time: None,
        expires_at: jiff::Timestamp::now()
            .checked_add(jiff::Span::new().hours(1))
            .expect("device code expiry"),
        interval_seconds: 0,
        last_poll_at: None,
        consumed_at: None,
    };
    state
        .store
        .insert(&doc)
        .await
        .expect("insert legacy-shaped approval");

    let (status, body) = poll_device_token(&app, device_code).await;
    assert_eq!(status, StatusCode::OK, "device grant should issue: {body}");
    let token = serde_json::from_str::<serde_json::Value>(&body).expect("token response is JSON")
        ["access_token"]
        .as_str()
        .expect("access_token present")
        .to_string();

    let claims = decode_jwt_payload(&token);
    assert_eq!(
        claims["hardware_verified"], true,
        "a legacy approval still proved possession"
    );
    assert!(
        claims.get("auth_time").is_none(),
        "no ceremony instant was recorded, so none may be invented: {claims}"
    );
}

/// RFC 8628 Section 3.5 defers to RFC 6749 for error semantics, and RFC 6749
/// Section 10.5 requires revocation to be scoped to the compromised code:
/// "the authorization server SHOULD attempt to revoke all access tokens
/// already granted based on the compromised authorization code." Polling with
/// an already-redeemed device code therefore revokes that code's token and
/// leaves the user's other tokens alone.
#[tokio::test]
async fn test_rfc8628_device_code_replay_revokes_only_that_code_s_token() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "replay-device@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;

    let device_code_a = setup_authorized_device(&state, &user, &auth, "a").await;
    let (status, body) = poll_device_token(&app, &device_code_a).await;
    assert_eq!(status, StatusCode::OK, "device code A poll failed: {body}");
    let token_a = serde_json::from_str::<serde_json::Value>(&body).expect("token response is JSON")
        ["access_token"]
        .as_str()
        .expect("access_token present")
        .to_string();

    let device_code_b = setup_authorized_device(&state, &user, &auth, "b").await;
    let (status, body) = poll_device_token(&app, &device_code_b).await;
    assert_eq!(status, StatusCode::OK, "device code B poll failed: {body}");
    let token_b = serde_json::from_str::<serde_json::Value>(&body).expect("token response is JSON")
        ["access_token"]
        .as_str()
        .expect("access_token present")
        .to_string();

    // A session from a grant with no single-use code.
    let token_c = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth),
            ..Default::default()
        },
    )
    .await;

    let (status, body) = poll_device_token(&app, &device_code_a).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replayed device code A must be denied: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("error response is JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "replayed device code must return invalid_grant: {body}"
    );

    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the replayed device code's token must be revoked, got {status}: {body}"
    );
    assert_token_alive(&app, &token_b, "a token from a different device code").await;
    assert_token_alive(&app, &token_c, "a token from a grant with no code").await;
}

// ========================================================================
// RFC 7591 §2 `grant_types` enforcement for the device_code grant
//
// Commit 45b8de2 (`fix(oidc): enforce grant_types for token-exchange and
// fido2-assertion`) added `is_authorized_for_grant` checks to every grant
// handler that authenticates the client at the token endpoint
// (`client_credentials`, `token_exchange`, `fido2_assertion`). The device_code
// grant authenticates by the consumed `device_code` (`ClientAuthProof::NoAuth`)
// rather than client credentials, so it was excluded — but `device_token`
// still loads the registered client from the stored `client_id` for FAPI
// sender-constraint enforcement, so the metadata needed to enforce
// `grant_types` is available. These tests pin the fix: a client restricted to
// `["authorization_code"]` (the dynamic-registration default when `grant_types`
// is omitted) MUST receive HTTP 401 `unauthorized_client` at redemption, while
// registered clients and the built-in CLI flow keep working (no regression).
// Mirrors the `grant_types` enforcement tests in `rfc7523.rs`.
// ========================================================================

/// Set (or clear) the `grant_types` of an OAuth client, mirroring the
/// `enable_grant_types` helper in `rfc7523.rs`. `None` means the client is not
/// authorized for any grant (matching `is_authorized_for_grant`'s `None`
/// semantics — a manually-managed client with no declared `grant_types`).
async fn set_grant_types(
    store: &db::store::DocumentStore,
    client_id: &str,
    grants: Option<&[&str]>,
) {
    let oauth_client = db::get_oauth_client_by_client_id(store, client_id)
        .await
        .expect("DB error")
        .expect("Client not found");
    let grants: Option<Vec<String>> = grants.map(|g| g.iter().map(|s| (*s).to_string()).collect());
    store
        .modify::<db::documents::oauth::OAuthClientDoc, _>(&oauth_client.id, |data| {
            data.grant_types = grants.clone();
        })
        .await
        .expect("Failed to update grant_types");
}

/// Like `setup_authorized_device` but stores a `client_id` on the device
/// authorization request — exercising the registered-client redemption path
/// (FAPI sender-constraint + `grant_types` enforcement). Creates the device
/// auth directly in the store so the test isolates the *redemption* gate from
/// the creation-endpoint gate.
async fn setup_authorized_device_for_client(
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    authenticator_id: &str,
    label: &str,
    client_id: &str,
) -> String {
    let device_code = format!("grant_dev_{label}");
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(1))
        .expect("device code expiry");
    let id = crate::db::create_device_auth_request(
        &state.store,
        &sha256_base64url(&device_code),
        &format!("GD{label}"),
        Some(client_id),
        expires_at,
        0,
    )
    .await
    .expect("create device authorization request");
    crate::db::authorize_device_auth(
        &state.store,
        crate::db::AuthorizeDeviceAuthParams {
            id: &id,
            user_id: &user.id,
            user_email: &user.email,
            authenticator_id,
            verification: DeviceApproval::Observed(AuthTime::for_test(
                jiff::Timestamp::now().as_second(),
            )),
        },
    )
    .await
    .expect("approve device authorization");
    device_code
}

/// RFC 7591 §2 / RFC 6749 §5.2 `unauthorized_client`: a client registered for
/// `authorization_code` only (the dynamic-registration default when
/// `grant_types` is omitted) MUST NOT be able to redeem a device code at the
/// token endpoint — the device_code grant loads the registered client from
/// the stored `client_id` and must enforce `grant_types` on the same lookup.
#[tokio::test]
async fn test_device_grant_rejects_redemption_for_client_not_registered_for_device_code() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-grant-unauth@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Restrict to authorization_code only — the default when `grant_types`
    // is omitted via dynamic registration.
    set_grant_types(
        &state.store,
        &client.client_id,
        Some(&["authorization_code"]),
    )
    .await;

    let device_code =
        setup_authorized_device_for_client(&state, &user, &auth, "unauth", &client.client_id).await;

    let (status, body) = poll_device_token(&app, &device_code).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "device_code grant must reject a client not registered for it: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "unauthorized_client",
        "rejected redemption must return unauthorized_client, not issue a token: {body}"
    );
}

/// No-regression control: a client registered for the device_code grant (the
/// `test_utils` default — all supported grants) redeems a device code and
/// receives an access token attributed to its `client_id`.
#[tokio::test]
async fn test_device_grant_redeems_for_client_registered_for_device_code() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-grant-auth@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let device_code =
        setup_authorized_device_for_client(&state, &user, &auth, "auth", &client.client_id).await;

    let (status, body) = poll_device_token(&app, &device_code).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "registered client should redeem: {body}"
    );
    let token_json: serde_json::Value =
        serde_json::from_str(&body).expect("token response is JSON");
    assert!(
        token_json.get("access_token").is_some(),
        "access_token must be issued to a client registered for device_code: {body}"
    );
}

/// The `grant_types` gate runs before `try_consume_device_auth`, so an
/// unauthorized client does not burn the single-use device code. Re-authorize
/// the client for device_code and the *same* device code must then redeem —
/// proving the rejection was the gate, not code consumption. Mirrors the
/// fido2-assertion control in `rfc7523.rs`.
#[tokio::test]
async fn test_device_grant_gate_runs_before_consume_retry_after_re_authorize() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-grant-retry@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    set_grant_types(
        &state.store,
        &client.client_id,
        Some(&["authorization_code"]),
    )
    .await;
    let device_code =
        setup_authorized_device_for_client(&state, &user, &auth, "retry", &client.client_id).await;

    // First poll: rejected by the grant_types gate. The code is NOT consumed.
    let (status, body) = poll_device_token(&app, &device_code).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "gate must reject: {body}");

    // Re-authorize the client for device_code (toggle the gate off).
    set_grant_types(
        &state.store,
        &client.client_id,
        Some(&["urn:ietf:params:oauth:grant-type:device_code"]),
    )
    .await;

    // Second poll on the SAME device code: succeeds, proving it was not burned.
    let (status, body) = poll_device_token(&app, &device_code).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same device code must redeem once the client is re-authorized: {body}"
    );
    let token_json: serde_json::Value =
        serde_json::from_str(&body).expect("token response is JSON");
    assert!(
        token_json.get("access_token").is_some(),
        "access_token must be issued after re-authorization: {body}"
    );
}

/// A manually-managed client with no declared `grant_types` (`None`) is
/// treated as not authorized for any grant by `is_authorized_for_grant`, so
/// the device_code redemption gate must reject it just like
/// `["authorization_code"]`.
#[tokio::test]
async fn test_device_grant_rejects_redemption_for_client_with_no_grant_types() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-grant-none@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    set_grant_types(&state.store, &client.client_id, None).await;
    let device_code =
        setup_authorized_device_for_client(&state, &user, &auth, "none", &client.client_id).await;

    let (status, body) = poll_device_token(&app, &device_code).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "device_code grant must reject a client with no grant_types: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "unauthorized_client",
        "expected unauthorized_client for a client with no grant_types: {body}"
    );
}

/// The built-in CLI flow carries no `client_id`, so `oauth_client` is `None`
/// and the `grant_types` gate is skipped — redemption must still succeed.
/// Pins the no-`client_id` happy path against the new gate to guard against a
/// future regression that moves the check out of the `Some(ref oc)` guard.
#[tokio::test]
async fn test_device_grant_no_client_id_builtin_flow_unaffected_by_gate() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-grant-cli@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;

    // No client_id stored on the device authorization request.
    let device_code = setup_authorized_device(&state, &user, &auth, "cli").await;

    let (status, body) = poll_device_token(&app, &device_code).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "built-in CLI flow (no client_id) must still issue a token: {body}"
    );
    let token_json: serde_json::Value =
        serde_json::from_str(&body).expect("token response is JSON");
    assert!(
        token_json.get("access_token").is_some(),
        "access_token must be issued for the no-client_id flow: {body}"
    );
}

/// Defense-in-depth (RFC 7591 §2): the device-authorization *creation*
/// endpoint rejects a `client_id` not registered for the device_code grant
/// before surfacing a usable `user_code`, so the user is never shown an
/// authorization prompt for a flow the client cannot complete.
#[tokio::test]
async fn test_device_code_creation_rejects_client_not_registered_for_device_code() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-create-unauth@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    set_grant_types(
        &state.store,
        &client.client_id,
        Some(&["authorization_code"]),
    )
    .await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}&scope=openid", client.client_id),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "device code creation must reject a client not registered for device_code: {body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        resp["error"], "unauthorized_client",
        "creation must return unauthorized_client for an unauthorized client_id: {body}"
    );
    assert!(
        resp.get("device_code").is_none(),
        "no device_code should be surfaced for an unauthorized client: {body}"
    );
}

/// End-to-end: a client registered for device_code creates a device
/// authorization via `/oauth/device`, the user approves it, and polling
/// `/oauth/token` returns an access token — verifying the full flow works
/// alongside the new `grant_types` enforcement at both endpoints.
#[tokio::test]
async fn test_device_grant_end_to_end_registered_client_flow() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-e2e@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // 1. Create the device authorization via the HTTP endpoint.
    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}&scope=openid", client.client_id),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create device auth: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let device_code = resp["device_code"]
        .as_str()
        .expect("device_code")
        .to_string();

    // 2. Approve it (look up by the hashed code, the same way the handler does).
    let request = db::get_device_auth_by_code_hash(&state.store, &sha256_base64url(&device_code))
        .await
        .expect("lookup device auth")
        .expect("device auth exists");
    crate::db::authorize_device_auth(
        &state.store,
        crate::db::AuthorizeDeviceAuthParams {
            id: &request.id,
            user_id: &user.id,
            user_email: &user.email,
            authenticator_id: &auth,
            verification: DeviceApproval::Observed(AuthTime::for_test(
                jiff::Timestamp::now().as_second(),
            )),
        },
    )
    .await
    .expect("approve device auth");

    // 3. Poll for a token.
    let (status, body) = poll_device_token(&app, &device_code).await;
    assert_eq!(status, StatusCode::OK, "end-to-end redeem: {body}");
    let token_json: serde_json::Value =
        serde_json::from_str(&body).expect("token response is JSON");
    assert!(
        token_json.get("access_token").is_some(),
        "access_token must be issued end-to-end: {body}"
    );
}
