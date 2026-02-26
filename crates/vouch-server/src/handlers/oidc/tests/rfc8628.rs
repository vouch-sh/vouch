// SPDX-License-Identifier: BUSL-1.1
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
