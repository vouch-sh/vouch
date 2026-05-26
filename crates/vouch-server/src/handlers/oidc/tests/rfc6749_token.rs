// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 6749 — Token endpoint basics and error format tests.
//!
//! GH#272 regression tests are also housed here: an authorization code whose
//! authenticator has been deleted must return `invalid_grant` at the token
//! endpoint instead of issuing a token.

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

// ========================================================================
// RFC 6749 Section 5.1 — Successful Token Response
// ========================================================================

#[tokio::test]
async fn test_rfc6749_successful_authorization_code_exchange() {
    // RFC 6749 Section 5.1: Successful token response must contain
    // access_token, token_type, and expires_in.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "success-exchange@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid email");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
        },
    )
    .await
    .expect("Failed to issue authorization code");

    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Successful token exchange must return 200: {body}"
    );

    let response: serde_json::Value =
        serde_json::from_str(&body).expect("Response must be valid JSON");

    // RFC 6749 Section 5.1: REQUIRED fields
    assert!(
        response.get("access_token").is_some(),
        "Response must contain access_token"
    );
    assert!(
        response.get("token_type").is_some(),
        "Response must contain token_type"
    );
    assert!(
        response.get("expires_in").is_some(),
        "Response must contain expires_in"
    );

    let token_type = response["token_type"]
        .as_str()
        .expect("token_type must be a string");
    assert!(
        token_type == "Bearer" || token_type == "DPoP",
        "token_type must be Bearer or DPoP, got: {token_type}"
    );

    assert!(
        response["expires_in"].is_number(),
        "expires_in must be a number"
    );

    // OIDC: id_token must be present when scope includes "openid"
    assert!(
        response.get("id_token").is_some(),
        "id_token must be present when scope includes openid"
    );
}

#[tokio::test]
async fn test_rfc6749_token_response_no_error_field_on_success() {
    // RFC 6749 Section 5.1 vs 5.2: Success responses must NOT contain
    // the error field — success and error formats are mutually exclusive.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "no-error-field@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // If we got here, the exchange was successful.
    // Verify the token works (proving the exchange was genuine).
    let claims = decode_jwt_payload(&access_token);
    assert!(
        claims.get("sub").is_some(),
        "Access token must contain sub claim"
    );

    // The issue_oauth_access_token helper already validates success,
    // but let's explicitly verify via a fresh exchange.
    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert!(
        response.get("error").is_none(),
        "RFC 6749 §5.1: Successful response must NOT contain 'error' field"
    );
    assert!(
        response.get("error_description").is_none(),
        "RFC 6749 §5.1: Successful response must NOT contain 'error_description'"
    );
}

// ========================================================================
// GH#272 — Revoked authenticator blocks code exchange
// ========================================================================

/// Regression test for GH#272: an authorization code that embeds an
/// `authenticator_id` for an authenticator that has since been
/// deleted/revoked must return `invalid_grant` at the token endpoint.
///
/// Before the fix, `exchange_authorization_code` looked up the user and
/// enforced single-use but never verified that the authenticator still
/// existed.  An attacker (or a stale code in flight) could therefore redeem
/// a code issued for a revoked key and receive a live access token.
#[tokio::test]
async fn test_token_exchange_rejects_revoked_authenticator() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoked-auth@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid email");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
        },
    )
    .await
    .expect("Failed to issue authorization code");

    // Revoke the authenticator between code issuance and code exchange.
    db::delete_authenticator(&state.store, &auth_id)
        .await
        .expect("Failed to delete authenticator");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Revoked authenticator must return 400, got: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Revoked authenticator must return invalid_grant, got: {body}"
    );
}

/// RFC 6749 §2.3.1: A confidential client may authenticate by sending
/// `client_id` and `client_secret` in the request body as form parameters
/// (`client_secret_post`) instead of HTTP Basic. The token endpoint must
/// accept this and return a successful token response.
///
/// Covers vouch-conformance TOKEN_TEST_HANDOFF scenario
/// `auth=client_secret_post grant=authorization_code → 200`.
#[tokio::test]
async fn test_rfc6749_token_client_secret_post_succeeds() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "csp-token@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let scope = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    // Credentials in the form body (NO Authorization header).
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}\
         &client_id={}&client_secret={}",
        urlencoding::encode("https://example.com/callback"),
        client.client_id,
        client.client_secret,
    );

    let (status, response_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "client_secret_post auth must succeed: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert!(
        json.get("access_token")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "Response must contain access_token"
    );
    assert_eq!(json["token_type"].as_str(), Some("Bearer"));
}
