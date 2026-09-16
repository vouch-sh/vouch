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
        &[("Authorization", client.basic_auth_header().as_str())],
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
        &[("Authorization", client.basic_auth_header().as_str())],
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
        &[("Authorization", client.basic_auth_header().as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let device_code = response["device_code"].as_str().expect("device_code");

    // Poll token endpoint — should return authorization_pending
    let (status, body) = poll_device_token(&app, device_code, &client).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "authorization_pending",
        "Unfinished device code should return authorization_pending"
    );
}

/// Create an approved device authorization for `client_id` directly in the
/// store and return the plaintext `device_code` the client polls with. `label`
/// distinguishes concurrent device authorizations within one test.
async fn setup_authorized_device(
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    authenticator_id: &str,
    label: &str,
    client_id: &str,
) -> String {
    let device_code = format!("dev_{label}");
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(1))
        .expect("device code expiry");
    let id = crate::db::create_device_auth_request(
        &state.store,
        &sha256_base64url(&device_code),
        &format!("DC{label}"),
        client_id,
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

/// A `client_secret_basic` client registered with the shared test signing
/// key, so a token issued to it passes the `/v1/*` request-signature check
/// that `assert_token_alive` relies on.
async fn signing_client(state: &std::sync::Arc<crate::AppState>, user_id: &str) -> TestOAuthClient {
    create_test_client(
        &state.store,
        user_id,
        TestClientSpec {
            jwks: TestJwks::Shared,
            ..Default::default()
        },
    )
    .await
}

/// Poll `/oauth/token` with the device code grant as `client`, which
/// authenticates with `client_secret_basic`.
async fn poll_device_token(
    app: &axum::Router,
    device_code: &str,
    client: &TestOAuthClient,
) -> (StatusCode, String) {
    http_post_form(
        app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code\
             &device_code={device_code}"
        ),
        &[("Authorization", client.basic_auth_header().as_str())],
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
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let device_code = "auth_time_dev";
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(1))
        .expect("device code expiry");
    let id = crate::db::create_device_auth_request(
        &state.store,
        &sha256_base64url(device_code),
        "AUTH-TIME",
        &client.client_id,
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

    let (status, body) = poll_device_token(&app, device_code, &client).await;
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
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let device_code = "legacy_auth_time_dev";
    let doc = crate::db::documents::device_auth::DeviceAuthRequestDoc {
        device_code_hash: sha256_base64url(device_code),
        user_code: "LGCY-AUTH".to_string(),
        status: crate::db::DeviceAuthStatus::Authorized,
        client_id: Some(client.client_id.clone()),
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

    let (status, body) = poll_device_token(&app, device_code, &client).await;
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
    let client = signing_client(&state, &user.id).await;

    let device_code_a = setup_authorized_device(&state, &user, &auth, "a", &client.client_id).await;
    let (status, body) = poll_device_token(&app, &device_code_a, &client).await;
    assert_eq!(status, StatusCode::OK, "device code A poll failed: {body}");
    let token_a = serde_json::from_str::<serde_json::Value>(&body).expect("token response is JSON")
        ["access_token"]
        .as_str()
        .expect("access_token present")
        .to_string();

    let device_code_b = setup_authorized_device(&state, &user, &auth, "b", &client.client_id).await;
    let (status, body) = poll_device_token(&app, &device_code_b, &client).await;
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

    let (status, body) = poll_device_token(&app, &device_code_a, &client).await;
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
        setup_authorized_device(&state, &user, &auth, "unauth", &client.client_id).await;

    let (status, body) = poll_device_token(&app, &device_code, &client).await;
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
        setup_authorized_device(&state, &user, &auth, "auth", &client.client_id).await;

    let (status, body) = poll_device_token(&app, &device_code, &client).await;
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
        setup_authorized_device(&state, &user, &auth, "retry", &client.client_id).await;

    // First poll: rejected by the grant_types gate. The code is NOT consumed.
    let (status, body) = poll_device_token(&app, &device_code, &client).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "gate must reject: {body}");

    // Re-authorize the client for device_code (toggle the gate off).
    set_grant_types(
        &state.store,
        &client.client_id,
        Some(&["urn:ietf:params:oauth:grant-type:device_code"]),
    )
    .await;

    // Second poll on the SAME device code: succeeds, proving it was not burned.
    let (status, body) = poll_device_token(&app, &device_code, &client).await;
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
        setup_authorized_device(&state, &user, &auth, "none", &client.client_id).await;

    let (status, body) = poll_device_token(&app, &device_code, &client).await;
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
        &[("Authorization", client.basic_auth_header().as_str())],
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
        &[("Authorization", client.basic_auth_header().as_str())],
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
    let (status, body) = poll_device_token(&app, &device_code, &client).await;
    assert_eq!(status, StatusCode::OK, "end-to-end redeem: {body}");
    let token_json: serde_json::Value =
        serde_json::from_str(&body).expect("token response is JSON");
    assert!(
        token_json.get("access_token").is_some(),
        "access_token must be issued end-to-end: {body}"
    );
}

// ========================================================================
// RFC 8628 §3.1 and §3.4 — client authentication at both device-flow endpoints
//
// §3.1 (specs/rfc/rfc8628.txt:319): "The client authentication requirements
// of Section 3.2.1 of [RFC6749] apply to requests on this endpoint, which
// means that confidential clients (those that have established client
// credentials) authenticate in the same manner as when making requests to the
// token endpoint, and public clients provide the "client_id" parameter to
// identify themselves." §3.4 (:567): "If the client was issued client
// credentials (or assigned other authentication requirements), the client
// MUST authenticate with the authorization server as described in Section
// 3.2.1 of [RFC6749]." Both make `client_id` "REQUIRED if the client is not
// authenticating".
// ========================================================================

/// A client registered with `private_key_jwt` and the PKCS#8 key that signs
/// its assertions.
async fn private_key_jwt_client(
    state: &std::sync::Arc<crate::AppState>,
    user_id: &str,
    fapi: bool,
) -> (TestOAuthClient, Vec<u8>) {
    let (pkcs8, jwk) = generate_es256_signing_key();
    let client = create_test_client(
        &state.store,
        user_id,
        TestClientSpec {
            jwks: TestJwks::Custom(serde_json::json!({ "keys": [jwk] })),
            token_endpoint_auth_method: Some(db::TokenEndpointAuthMethod::PrivateKeyJwt),
            with_secret: false,
            fapi_profile: fapi.then_some(db::FapiProfile::Fapi2Security),
            dpop_bound_access_tokens: fapi,
            ..Default::default()
        },
    )
    .await;
    (client, pkcs8)
}

/// A client registered public (`none`), which identifies itself by
/// `client_id` alone.
async fn public_client(state: &std::sync::Arc<crate::AppState>, user_id: &str) -> TestOAuthClient {
    create_test_client(
        &state.store,
        user_id,
        TestClientSpec {
            token_endpoint_auth_method: Some(db::TokenEndpointAuthMethod::None),
            with_secret: false,
            ..Default::default()
        },
    )
    .await
}

/// `/oauth/device` form body carrying a fresh assertion for `client` with
/// `audience`.
fn device_request_with_assertion(client_id: &str, audience: &str, pkcs8: &[u8]) -> String {
    let assertion = build_client_assertion(client_id, audience, pkcs8, None);
    format!(
        "client_id={client_id}&client_assertion={assertion}&client_assertion_type={}",
        vouch_common::protocol::CLIENT_ASSERTION_TYPE_JWT_BEARER
    )
}

/// The request a CLI before 2026.9.4 sends: the `private_key_jwt` client's
/// `client_id` with no assertion. RFC 8628 §3.1 applies RFC 6749 §3.2.1, so
/// it is refused and no device authorization is created.
#[tokio::test]
async fn test_device_code_rejects_private_key_jwt_client_without_assertion() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-noassert@example.com").await;
    let (client, _pkcs8) = private_key_jwt_client(&state, &user.id, false).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}", client.client_id),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_client", "{body}");
    assert!(error.get("device_code").is_none(), "{body}");
}

/// RFC 8628 §3.1: a `private_key_jwt` client authenticates with an assertion.
/// The assertion's JTI is committed, so the same assertion cannot start a
/// second flow.
#[tokio::test]
async fn test_device_code_accepts_assertion_once() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-assert@example.com").await;
    let (client, pkcs8) = private_key_jwt_client(&state, &user.id, false).await;
    let body = device_request_with_assertion(&client.client_id, &state.config().base_url, &pkcs8);

    let (status, resp) = http_post_form(&app, "/oauth/device", &body, &[]).await;
    assert_eq!(status, StatusCode::OK, "{resp}");

    let (status, resp) = http_post_form(&app, "/oauth/device", &body, &[]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "replayed assertion: {resp}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_client", "{resp}");
}

/// RFC 6749 §2.3.1 `client_secret_post` authenticates at `/oauth/device`;
/// a wrong `client_secret_basic` secret is refused, and per RFC 6749 §5.2 the
/// 401 carries `WWW-Authenticate: Basic` because the client used the
/// `Authorization` header.
#[tokio::test]
async fn test_device_code_client_secret_post_and_wrong_basic() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-secret@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!(
            "client_id={}&client_secret={}",
            client.client_id, client.client_secret
        ),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "client_secret_post: {body}");

    let wrong = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:not-the-secret", client.client_id));
    let response = http_post_form_full(
        &app,
        "/oauth/device",
        "scope=openid",
        &[("Authorization", &format!("Basic {wrong}"))],
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        response.body
    );
    assert_eq!(
        response
            .headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok()),
        Some("Basic"),
        "{}",
        response.body
    );
}

/// RFC 8628 §3.1 makes `client_id` "REQUIRED if the client is not
/// authenticating": a request with neither is refused.
#[tokio::test]
async fn test_device_code_rejects_request_with_no_client() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(&app, "/oauth/device", "scope=openid", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_client", "{body}");
}

/// RFC 8628 §3.1: "public clients provide the "client_id" parameter to
/// identify themselves." RFC 6749 §2.3: the server "MUST NOT rely on public
/// client authentication for the purpose of identifying the client", so a
/// stray `client_secret` is ignored rather than relied on.
#[tokio::test]
async fn test_device_code_public_client_identifies_by_client_id() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-public@example.com").await;
    let client = public_client(&state, &user.id).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}", client.client_id),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}&client_secret=ignored", client.client_id),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "stray secret on a public client: {body}"
    );
}

/// RFC 7523 §3: the assertion's `aud` must identify the authorization server;
/// "The token endpoint URL of the authorization server MAY be used". A
/// non-FAPI client may name the device authorization endpoint; FAPI 2.0
/// §5.3.2.1 restricts FAPI clients to the issuer.
#[tokio::test]
async fn test_device_code_assertion_audience_may_be_device_endpoint() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-aud@example.com").await;
    let device_endpoint = format!("{}/oauth/device", state.config().base_url);

    let (client, pkcs8) = private_key_jwt_client(&state, &user.id, false).await;
    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &device_request_with_assertion(&client.client_id, &device_endpoint, &pkcs8),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "non-FAPI client: {body}");

    let (fapi_client, fapi_pkcs8) = private_key_jwt_client(&state, &user.id, true).await;
    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &device_request_with_assertion(&fapi_client.client_id, &device_endpoint, &fapi_pkcs8),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "FAPI client: {body}");
}

/// RFC 8628 §3.4: a confidential client polling without credentials is
/// refused; the code is not consumed, so the authenticated retry redeems it.
#[tokio::test]
async fn test_device_grant_requires_client_authentication() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-grant-auth-req@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let device_code =
        setup_authorized_device(&state, &user, &auth, "authreq", &client.client_id).await;
    let form = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}\
         &client_id={}",
        client.client_id
    );

    let (status, body) = http_post_form(&app, "/oauth/token", &form, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_client", "{body}");

    let (status, body) = poll_device_token(&app, &device_code, &client).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "code must survive the refusal: {body}"
    );
}

/// RFC 6749 §5.2 `invalid_grant`: the grant "was issued to another client".
/// Two public clients, where binding is the only control: the other client
/// gets `invalid_grant`, the code is not consumed, and the owner's poll
/// interval is untouched.
#[tokio::test]
async fn test_device_grant_bound_to_issuing_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-grant-bound@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let owner = public_client(&state, &user.id).await;
    let other = public_client(&state, &user.id).await;
    let device_code =
        setup_authorized_device(&state, &user, &auth, "bound", &owner.client_id).await;
    let hash = sha256_base64url(&device_code);

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}\
             &client_id={}",
            other.client_id
        ),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant", "{body}");

    let row = db::get_device_auth_by_code_hash(&state.store, &hash)
        .await
        .expect("lookup")
        .expect("row exists");
    assert!(
        matches!(row.state, crate::db::DeviceAuthState::Authorized(_)),
        "another client's poll must not consume the code: {:?}",
        row.state
    );
    let doc = state
        .store
        .find_one::<crate::db::documents::device_auth::DeviceAuthRequestDoc>(
            "device_code_hash",
            &hash,
        )
        .await
        .expect("lookup doc")
        .expect("doc exists");
    assert!(
        doc.data.last_poll_at.is_none(),
        "another client's poll must not count against the owner's interval"
    );

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}\
             &client_id={}",
            owner.client_id
        ),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner redeems: {body}");
}

/// The binding check runs before every status arm: another client gets
/// `invalid_grant` for a consumed code without triggering replay revocation,
/// and for an expired code rather than `expired_token`.
#[tokio::test]
async fn test_device_grant_other_client_sees_only_invalid_grant() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-grant-other@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let owner = signing_client(&state, &user.id).await;
    let other = create_test_oauth_client(&state.store, &user.id).await;

    let consumed =
        setup_authorized_device(&state, &user, &auth, "consumed", &owner.client_id).await;
    let (status, body) = poll_device_token(&app, &consumed, &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = serde_json::from_str::<serde_json::Value>(&body).expect("JSON")["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    let (status, body) = poll_device_token(&app, &consumed, &other).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant", "{body}");
    assert_token_alive(
        &app,
        &token,
        "the owner's token after another client's poll",
    )
    .await;

    let expired = "expired_dev";
    let expires_at = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().hours(1))
        .expect("past expiry");
    crate::db::create_device_auth_request(
        &state.store,
        &sha256_base64url(expired),
        "EXPIRED",
        &owner.client_id,
        expires_at,
        0,
    )
    .await
    .expect("create expired row");
    let (status, body) = poll_device_token(&app, expired, &other).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant", "not expired_token: {body}");
}

/// An unauthenticated poll of a pending code is refused before any status
/// response: the caller learns nothing about the code.
#[tokio::test]
async fn test_device_grant_unauthenticated_poll_of_pending_code() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-grant-pending-anon@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}", client.client_id),
        &[("Authorization", client.basic_auth_header().as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let device_code =
        serde_json::from_str::<serde_json::Value>(&body).expect("JSON")["device_code"]
            .as_str()
            .expect("device_code")
            .to_string();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}"
        ),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_client",
        "not authorization_pending: {body}"
    );
}

/// An unauthenticated replay of a consumed code is refused as a client
/// authentication failure and revokes nothing: RFC 6749 §10.5 replay
/// revocation is reserved for the code's own client.
#[tokio::test]
async fn test_device_grant_unauthenticated_replay_revokes_nothing() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-grant-replay-anon@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let client = signing_client(&state, &user.id).await;
    let device_code =
        setup_authorized_device(&state, &user, &auth, "replayanon", &client.client_id).await;

    let (status, body) = poll_device_token(&app, &device_code, &client).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = serde_json::from_str::<serde_json::Value>(&body).expect("JSON")["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}\
             &client_id={}",
            client.client_id
        ),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_token_alive(&app, &token, "the token after an unauthenticated replay").await;
}

// ========================================================================
// RFC 8628 §3.4 — `private_key_jwt` JTI commit ordering on failed polls
//
// `device_token` commits the assertion's JTI before the device-code format,
// not-found, and cross-client `invalid_grant` early-returns, so an
// authenticated poll that fails on any of those grounds still burns the
// assertion. Without this ordering a stolen assertion whose first use is a
// failed device-code poll (wrong/unknown/non-owned code) would stay live and
// authenticate successfully once at another endpoint that accepts it
// (`/oauth/device`, `/oauth/par`, `/oauth/revoke`, `/oauth/introspect`), since
// the non-FAPI allowed-audience list is shared. See commit 54f7a8c0 which
// introduced client authentication on this endpoint and placed the commit
// after the early-returns.
// ========================================================================

/// Mint one `private_key_jwt` assertion for `client_a` (audience `base_url`,
/// valid at both `/oauth/token` and `/oauth/device` for a non-FAPI client) with
/// a fixed `jti`, so the same assertion can be sent twice to exercise replay.
fn single_use_assertion(client_a: &str, base_url: &str, pkcs8_a: &[u8], jti: &str) -> String {
    build_client_assertion(client_a, base_url, pkcs8_a, Some(jti))
}

/// The `/oauth/token` device-code poll body authenticated as `client_a` with
/// `assertion`, mirroring `fapi_device_token_body` (no `client_id` in the
/// body; the assertion's `iss`/`sub` identifies the client).
fn device_poll_body_with_assertion(device_code: &str, assertion: &str) -> String {
    format!(
        "grant_type=urn:ietf:params:oauth:grant-type:device_code\
         &device_code={device_code}&client_assertion={assertion}\
         &client_assertion_type={}",
        vouch_common::protocol::CLIENT_ASSERTION_TYPE_JWT_BEARER
    )
}

/// Reuse `assertion` at `/oauth/device` enrollment and assert it is rejected
/// as `invalid_client` (replay): the prior failed poll must have already
/// committed the assertion's JTI, so a second successful use is impossible.
async fn assert_replay_rejected_at_device(app: &axum::Router, client_a: &str, assertion: &str) {
    let body = format!(
        "client_id={client_a}&client_assertion={assertion}&client_assertion_type={}",
        vouch_common::protocol::CLIENT_ASSERTION_TYPE_JWT_BEARER
    );
    let (status, resp) = http_post_form(app, "/oauth/device", &body, &[]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "replayed assertion after a failed poll MUST be rejected (replay): {resp}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_client", "replay: {resp}");
    assert!(
        !resp.contains("device_code"),
        "no device flow may be started by a replayed assertion: {resp}"
    );
}

/// Regression for the cross-client early-return: client A authenticates with
/// `private_key_jwt` and polls a device code owned by public client B. The
/// cross-client binding check rejects the poll with `invalid_grant`. The
/// assertion's JTI must be committed before that check, so reusing the same
/// assertion at `/oauth/device` is refused as `invalid_client`. On the buggy
/// tree the reuse returned `200` with a fresh device flow.
#[tokio::test]
async fn test_device_grant_cross_client_poll_commits_jti_regression() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-jti-xclient@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let (client_a, pkcs8_a) = private_key_jwt_client(&state, &user.id, false).await;
    let client_b = public_client(&state, &user.id).await;
    let device_code =
        setup_authorized_device(&state, &user, &auth, "jti-xclient", &client_b.client_id).await;

    let base_url = state.config().base_url.clone();
    let assertion = single_use_assertion(
        &client_a.client_id,
        &base_url,
        &pkcs8_a,
        "device-jti-cross-client-fixed",
    );

    // (1) Poll /oauth/token authenticated as A with B's device code. The
    // cross-client binding check rejects this with `invalid_grant`. On the
    // buggy tree this path returned before the JTI commit, leaving the
    // assertion un-burned.
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &device_poll_body_with_assertion(&device_code, &assertion),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "cross-client poll: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant", "cross-client poll: {body}");

    // (2) Reuse the SAME assertion (same JTI) at /oauth/device. The failed
    // poll already burned the JTI, so the replay MUST be rejected.
    assert_replay_rejected_at_device(&app, &client_a.client_id, &assertion).await;

    // (3) Control: a fresh assertion for A authenticates at /oauth/device,
    // proving A is otherwise entitled to the endpoint and the rejection above
    // was the replay, not a misconfigured client.
    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &device_request_with_assertion(&client_a.client_id, &base_url, &pkcs8_a),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "fresh assertion control: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(resp.get("device_code").is_some(), "control: {body}");
}

/// The not-found early-return also runs after the JTI commit: an
/// authenticated poll for a device code that does not exist returns
/// `invalid_grant` and still burns the assertion.
#[tokio::test]
async fn test_device_grant_unknown_code_poll_commits_jti() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-jti-unknown@example.com").await;
    let (client_a, pkcs8_a) = private_key_jwt_client(&state, &user.id, false).await;

    let base_url = state.config().base_url.clone();
    let assertion = single_use_assertion(
        &client_a.client_id,
        &base_url,
        &pkcs8_a,
        "device-jti-unknown-fixed",
    );

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &device_poll_body_with_assertion("dev_does_not_exist", &assertion),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown code poll: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant", "unknown code poll: {body}");

    assert_replay_rejected_at_device(&app, &client_a.client_id, &assertion).await;
}

/// The format early-return also runs after the JTI commit: an authenticated
/// poll for an over-length device code returns `invalid_grant` and still
/// burns the assertion. This is the defense-in-depth direction the commit-first
/// ordering provides (a stolen assertion spent probing a garbage code is
/// burned rather than left live).
#[tokio::test]
async fn test_device_grant_malformed_code_poll_commits_jti() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "device-jti-malformed@example.com").await;
    let (client_a, pkcs8_a) = private_key_jwt_client(&state, &user.id, false).await;

    let base_url = state.config().base_url.clone();
    let assertion = single_use_assertion(
        &client_a.client_id,
        &base_url,
        &pkcs8_a,
        "device-jti-malformed-fixed",
    );

    let long_code = "a".repeat(200);
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &device_poll_body_with_assertion(&long_code, &assertion),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "malformed code poll: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "malformed code poll: {body}"
    );

    assert_replay_rejected_at_device(&app, &client_a.client_id, &assertion).await;
}
