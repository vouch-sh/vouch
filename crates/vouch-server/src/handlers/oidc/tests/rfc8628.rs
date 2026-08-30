// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8628 — Device Authorization Grant tests.

use super::helpers::*;

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
            hardware_verified: true,
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
    let token_c = create_test_session(&state, &user.id, &user.email, &auth).await;

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
