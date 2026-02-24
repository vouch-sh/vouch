// SPDX-License-Identifier: BUSL-1.1
//! RFC 8725 — JWT Best Current Practices tests.

use super::helpers::*;

#[tokio::test]
async fn test_rfc8725_cross_type_token_substitution() {
    // RFC 8725 Section 3.11: Access token (at+jwt) cannot be used where
    // session token (vouch-session+jwt) is expected and vice versa.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "cross-type@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Get an OAuth access token (ES256, typ=at+jwt)
    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Try using the access token at a management endpoint that expects a
    // FIDO2 session token (HS256, typ=vouch-session+jwt) — should fail
    let (status, _body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Access token (at+jwt) should not be accepted where session token is expected"
    );

    // Get a FIDO2 session token (HS256, typ=vouch-session+jwt)
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Session token should work at management endpoints
    let (status, _body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", session_token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Session token should work at management endpoints"
    );
}

#[tokio::test]
async fn test_rfc8725_required_claims_validation() {
    // RFC 8725 Section 3.4: Missing required claims causes rejection.
    // Forge a JWT missing the `iss` claim and verify it's rejected.
    let (app, _state) = test_app().await;

    // Create a JWT with no claims at all (will fail validation)
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[(
            "Authorization",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6InZvdWNoLXNlc3Npb24rand0In0.e30.invalid",
        )],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "JWT without required claims must be rejected"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_token");
}

#[tokio::test]
async fn test_rfc8725_jwe_envelope_rejection() {
    // RFC 8725 Section 3.2: Encrypted JWT (5-part) must be rejected.
    // JWE has 5 Base64url-encoded parts separated by dots.
    let (app, _state) = test_app().await;

    let fake_jwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo.48V1_ALb6US04.5eym8TW_c8SuK0ltJ3rpYIzOeDQz.XFBoMYUZodetZdvTiFvSkQ";

    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", fake_jwe))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "JWE (5-part JWT) must be rejected at validation endpoints"
    );
}
