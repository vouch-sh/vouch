// SPDX-License-Identifier: BUSL-1.1
//! RFC 6749 — Token endpoint basics and error format tests.

use super::helpers::*;

// ========================================================================
// P0: RFC 6749 — Token Endpoint
// ========================================================================

#[tokio::test]
async fn test_token_invalid_grant_type() {
    // RFC 6749 Section 5.2: unsupported_grant_type error
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=invalid_grant_type&code=test",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_token_missing_code() {
    // RFC 6749 Section 5.2: invalid_request when code is missing
    let (app, _state) = test_app().await;

    let (status, body) =
        http_post_form(&app, "/oauth/token", "grant_type=authorization_code", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_token_invalid_code() {
    // RFC 6749 Section 5.2: invalid_grant for invalid authorization code
    let (app, state) = test_app().await;

    // Create a test user and OAuth client for authentication
    let user = create_test_user(&state.store, "invalid-code@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=invalid_code&redirect_uri=https://example.com/callback",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn test_rfc6749_token_error_response_format() {
    // RFC 6749 Section 5.2: Token endpoint errors must include `error` field
    // and optional `error_description`, with correct HTTP status.
    let (app, _state) = test_app().await;

    let (status, body) =
        http_post_form(&app, "/oauth/token", "grant_type=authorization_code", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 6749 Section 5.2: REQUIRED error field
    assert!(
        error.get("error").is_some(),
        "Token error must include 'error' field"
    );
    let error_code = error["error"].as_str().expect("error is a string");
    assert!(!error_code.is_empty(), "Error code must not be empty");

    // error_description is optional but recommended
    if let Some(desc) = error.get("error_description") {
        assert!(desc.is_string(), "error_description must be a string");
    }
}

#[tokio::test]
async fn test_rfc6749_unsupported_grant_type() {
    // RFC 6749 Section 5.2: Unsupported grant_type returns specific error.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(&app, "/oauth/token", "grant_type=password", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "unsupported_grant_type",
        "Unknown grant type must return unsupported_grant_type"
    );
}

#[tokio::test]
async fn test_rfc6749_client_credentials_requires_auth() {
    // RFC 6749 Section 4.4.2: Client authentication is REQUIRED.
    let (app, _state) = test_app().await;

    let (status, body) =
        http_post_form(&app, "/oauth/token", "grant_type=client_credentials", &[]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_client",
        "Unauthenticated client_credentials must return invalid_client"
    );
}
