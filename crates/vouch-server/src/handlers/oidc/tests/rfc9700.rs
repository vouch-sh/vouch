// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9700 — OAuth 2.0 Security Best Current Practice tests.

use super::helpers::*;

// ============================================================================
// RFC 9700 — PKCE Enforcement
// ============================================================================

#[tokio::test]
async fn test_rfc9700_pkce_required_for_public_clients() {
    // RFC 9700: Public clients (token_endpoint_auth_method=none) MUST provide PKCE.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "pkce-required@example.com").await;
    let client = create_test_public_oauth_client(&state.store, &user.id).await;

    // Authorize request without code_challenge — should redirect with error
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test123",
            client.client_id,
            urlencoding::encode("https://example.com/callback")
        ),
        &[],
    )
    .await;

    // Should be a redirect (302) with error in the location
    assert_eq!(
        response.status,
        StatusCode::SEE_OTHER,
        "Should redirect with error: {}",
        response.body
    );
    let location = response
        .headers
        .get("Location")
        .expect("Should have Location header")
        .to_str()
        .expect("Valid header");
    assert!(
        location.contains("error="),
        "Redirect should contain error parameter: {}",
        location
    );
    assert!(
        location.contains("state=test123"),
        "Error redirect should preserve state parameter: {}",
        location
    );
}

#[tokio::test]
async fn test_rfc9700_pkce_optional_for_confidential_clients() {
    // Confidential clients (client_secret_basic, Web type) do not require PKCE.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "pkce-optional@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Authorize request without code_challenge — should NOT get PKCE error
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test123",
            client.client_id,
            urlencoding::encode("https://example.com/callback")
        ),
        &[],
    )
    .await;

    // Should proceed past PKCE check (gets redirect to login, not an error redirect)
    // Either 200 (login page) or 303 (redirect to login) — but NOT an error=invalid_request
    if response.status == StatusCode::SEE_OTHER {
        let location = response
            .headers
            .get("Location")
            .expect("Should have Location header")
            .to_str()
            .expect("Valid header");
        assert!(
            !location.contains("error=invalid_request"),
            "Confidential client should not get PKCE error: {}",
            location
        );
    }
}

// ============================================================================
// RFC 9700 — Token Endpoint Security
// ============================================================================

#[tokio::test]
async fn test_rfc9700_client_id_matching_at_token_endpoint() {
    // RFC 9700 Section 2.2: client_id at token endpoint must match authorization.
    // Code issued to client A cannot be exchanged by client B.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "client-mismatch@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client_a = create_test_oauth_client(&state.store, &user.id).await;
    let client_b = create_test_oauth_client(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client_a.client_id,
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
            par: crate::db::ParConsumptionProof::not_pushed(),
        },
    )
    .await
    .expect("Failed to issue code");

    // Try to exchange with client_b credentials — must fail
    let auth_header_b = client_b.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header_b)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Code for client A should not be exchangeable by client B"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn test_rfc9700_redirect_uri_exact_match_at_token() {
    // RFC 9700 / RFC 6749 Section 4.1.3: redirect_uri at token endpoint must
    // exactly match the one used during authorization.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "redirect-mismatch@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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
            par: crate::db::ParConsumptionProof::not_pushed(),
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();

    // Use a different redirect_uri at token endpoint — must fail
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback/different",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Mismatched redirect_uri must fail"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn test_rfc9700_redirect_uri_required_when_present_in_auth() {
    // RFC 6749 Section 4.1.3: If redirect_uri was present in auth request,
    // it MUST be present at token request too.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "redirect-required@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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
            par: crate::db::ParConsumptionProof::not_pushed(),
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();

    // Omit redirect_uri at token endpoint — must fail
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!("grant_type=authorization_code&code={}", code),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Missing redirect_uri must fail when it was in the authorization request"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error["error"] == "invalid_request" || error["error"] == "invalid_grant",
        "Should return error for missing redirect_uri"
    );
}

// ============================================================================
// RFC 9700 — Authorization Code Security
// ============================================================================

#[tokio::test]
async fn test_rfc9700_authorization_code_single_use() {
    // RFC 9700 Section 2.1 / RFC 6749 Section 10.5:
    // Using the same authorization code twice must fail.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "single-use@example.com").await;
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
            par: crate::db::ParConsumptionProof::not_pushed(),
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();

    // First use — should succeed
    let (status, _body) = http_post_form(
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
        "First use of authorization code should succeed"
    );

    // Second use — must fail per RFC 6749 Section 10.5
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
        "Second use of authorization code must fail"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn test_rfc9700_authorize_pkce_required_for_public_client_without_challenge() {
    // RFC 9700: Public clients MUST provide PKCE.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-nopkce@example.com").await;
    let client = create_test_public_oauth_client(&state.store, &user.id).await;
    let state_param = "teststate-nopkce";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            state_param,
        ),
        &[],
    )
    .await;

    // Must redirect with error=invalid_request (PKCE required)
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Missing PKCE must redirect with error, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("error=invalid_request"),
        "Redirect must include error=invalid_request for missing PKCE: {location}"
    );

    // State must be echoed even in error
    assert!(
        location.contains(&format!("state={state_param}")),
        "Error redirect must echo state parameter: {location}"
    );
}

// ============================================================================
// RFC 9700 — Code Challenge Method Validation
// ============================================================================

#[tokio::test]
async fn test_rfc9700_pkce_plain_method_rejected() {
    // RFC 9700 Section 2.1.1: Only S256 code_challenge_method is acceptable.
    // The "plain" method MUST be rejected as it provides no security benefit.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "pkce-plain@example.com").await;
    let client = create_test_public_oauth_client(&state.store, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
             &code_challenge_method=plain&state=plain-test",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await;

    // Should redirect with error (not succeed)
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "plain code_challenge_method must produce an error redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("error="),
        "Redirect must contain error parameter for plain PKCE method: {location}"
    );
}
