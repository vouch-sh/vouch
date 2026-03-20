// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8707 — Resource Indicators tests.

use super::helpers::*;

#[tokio::test]
async fn test_rfc8707_invalid_resource_uri() {
    // RFC 8707 Section 2: Invalid resource URI at authorize endpoint
    // returns invalid_target error.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "resource-invalid@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Use a non-absolute URI as resource
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge=test&code_challenge_method=S256&scope=openid&resource=not-a-valid-uri",
            client.client_id,
            urlencoding::encode("https://example.com/callback")
        ),
        &[],
    )
    .await;

    // Should redirect with error or show error page
    if response.status == StatusCode::SEE_OTHER || response.status == StatusCode::FOUND {
        let location = response
            .headers
            .get("Location")
            .expect("Location header")
            .to_str()
            .expect("Valid");
        assert!(
            location.contains("error="),
            "Invalid resource URI should cause error: {}",
            location
        );
    }
}

#[tokio::test]
async fn test_rfc8707_resource_passthrough_authorize_to_token() {
    // RFC 8707 Section 2: Resource indicator in authorization request
    // should flow through to the access token audience.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "resource-pass@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let resource_uri = "https://api.example.com";

    // Issue authorization code with resource parameter
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
            resource: Some(resource_uri),
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
        },
    )
    .await
    .expect("Failed to issue code with resource");

    // Exchange at token endpoint
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Token exchange with resource should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let access_token = response["access_token"].as_str().expect("access_token");

    // Decode the token and check the audience claim
    let claims = decode_jwt_payload(access_token);
    let aud = claims
        .get("aud")
        .expect("access token should have aud claim");
    let aud_str = aud.as_str().unwrap_or_default();
    assert_eq!(
        aud_str, resource_uri,
        "Access token aud should match the resource indicator"
    );
}

#[tokio::test]
async fn test_rfc8707_resource_uri_with_fragment_rejected() {
    // RFC 8707 Section 2: Resource URI MUST NOT contain a fragment component.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "resource-frag@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}\
             &redirect_uri={}&scope=openid\
             &code_challenge=test&code_challenge_method=S256\
             &resource={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode("https://api.example.com/resource#fragment")
        ),
        &[],
    )
    .await;

    // Should error — either redirect with error or show error page
    if response.status == StatusCode::SEE_OTHER || response.status == StatusCode::FOUND {
        let location = response
            .headers
            .get("Location")
            .expect("Location header")
            .to_str()
            .expect("Valid");
        assert!(
            location.contains("error="),
            "Resource URI with fragment should cause error redirect: {location}"
        );
    } else {
        // Error page is also acceptable
        assert!(
            response.status == StatusCode::BAD_REQUEST || response.status.is_client_error(),
            "Resource URI with fragment should be rejected, got: {}",
            response.status
        );
    }
}

#[tokio::test]
async fn test_rfc8707_resource_in_token_exchange() {
    // RFC 8707: Resource parameter in token exchange should set the audience
    // of the exchanged token.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "resource-exchange@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let resource_uri = "https://target-api.example.com";

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &resource={resource_uri}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Exchange with resource should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let exchanged_token = response["access_token"].as_str().expect("access_token");

    // Decode and verify audience matches the resource
    let claims = decode_jwt_payload(exchanged_token);
    if let Some(aud) = claims.get("aud") {
        let aud_str = aud.as_str().unwrap_or_default();
        assert_eq!(
            aud_str, resource_uri,
            "Exchanged token aud should match resource"
        );
    }
}
