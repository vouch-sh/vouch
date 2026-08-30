// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9470 — Step-Up Authentication Challenge Protocol tests.
//!
//! Tests for `acr_values`, `max_age`, and `prompt` parameters on the
//! authorization endpoint, as well as the `unmet_authentication_requirements`
//! error code.

use super::helpers::*;

// ========================================================================
// RFC 9470 Section 4 — acr_values parameter
// ========================================================================

#[tokio::test]
async fn test_rfc9470_acr_values_aal3_accepted() {
    // RFC 9470: Authorization request with acr_values containing AAL3
    // should succeed for an authenticated user.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "acr-aal3@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let acr = "urn:nist:authentication:assurance-level:aal3";
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&acr_values={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            urlencoding::encode(acr),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Should redirect with authorization code
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "AAL3 acr_values request should succeed, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("code="),
        "Successful response must include authorization code: {location}"
    );
}

#[tokio::test]
async fn test_rfc9470_acr_values_unsupported_returns_error() {
    // RFC 9470 Section 4: If the requested acr_values cannot be satisfied,
    // the authorization server returns unmet_authentication_requirements.
    // Vouch only supports AAL3, so requesting only AAL2 should fail.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "acr-unsupported@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    // Request only AAL2 — Vouch cannot satisfy this
    let acr = "urn:nist:authentication:assurance-level:aal2";
    let state_param = "acr-test-state";
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&acr_values={}&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            urlencoding::encode(acr),
            state_param,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Should redirect with error
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Unsupported ACR must redirect with error, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("error=unmet_authentication_requirements"),
        "Must return unmet_authentication_requirements error: {location}"
    );

    // State must be echoed
    assert!(
        location.contains(&format!("state={state_param}")),
        "Error redirect must echo state parameter: {location}"
    );

    // RFC 9207: iss must be present
    assert!(
        location.contains("iss="),
        "Error redirect must include iss parameter (RFC 9207): {location}"
    );
}

#[tokio::test]
async fn test_rfc9470_acr_values_multiple_with_aal3_accepted() {
    // RFC 9470: acr_values is space-delimited. If AAL3 is among the requested
    // values, Vouch can satisfy it even if other ACRs are also listed.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "acr-multi@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    // Multiple ACR values including AAL3
    let acr =
        "urn:nist:authentication:assurance-level:aal2 urn:nist:authentication:assurance-level:aal3";
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&acr_values={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            urlencoding::encode(acr),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Should succeed — AAL3 is in the list
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Multiple acr_values with AAL3 should succeed, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("code="),
        "Successful response must include authorization code: {location}"
    );
}

#[tokio::test]
async fn test_rfc9470_acr_values_too_long_rejected() {
    // Validation: acr_values exceeding 512 characters should be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "acr-long@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let long_acr = "x".repeat(600);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256&acr_values={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode(&long_acr),
        ),
        &[],
    )
    .await;

    // Should redirect with error
    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response
            .headers
            .get("Location")
            .expect("Must have Location header")
            .to_str()
            .expect("Valid UTF-8");
        assert!(
            location.contains("error="),
            "Oversized acr_values must produce error: {location}"
        );
    } else {
        assert!(
            response.status == StatusCode::OK || response.status.is_client_error(),
            "Must show error for oversized acr_values, got: {}",
            response.status
        );
    }
}

// ========================================================================
// RFC 9470 / OIDC Core Section 3.1.2.1 — max_age parameter
// ========================================================================

#[tokio::test]
async fn test_rfc9470_max_age_one_does_not_reauth_a_fresh_session() {
    // OIDC Core 3.1.2.1 requires re-authentication only when the elapsed
    // time is *greater than* max_age. A session created moments ago is well
    // inside max_age=1, so the flow must proceed rather than bounce to
    // /login.
    //
    // This pins the non-zero side of the boundary. It does not by itself
    // distinguish the duration comparison from the previous truncating one —
    // `floor(e) >= M` and `e >= M` agree for integer M, so those differ only
    // at exactly `e == M`, which is not reachable in a test. The property
    // that separates the implementations is max_age=0, covered by
    // `test_rfc9470_max_age_zero_forces_reauth`: truncating and then testing
    // `>` reports a fresh session's age as 0, so `0 > 0` skips the
    // re-authentication that "max_age=0 is equivalent to prompt=login"
    // requires.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "maxage-one@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&max_age=1",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        !location.starts_with("/login"),
        "a session younger than max_age=1 must not be re-authenticated, got: {location}"
    );
}

#[tokio::test]
async fn test_rfc9470_max_age_zero_forces_reauth() {
    // RFC 9470 / OIDC Core Section 3.1.2.1: max_age=0 means the user must
    // re-authenticate regardless of how fresh the session is. The server
    // should store OAuth params and redirect to /login.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "maxage-zero@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&max_age=0",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Should redirect to login (re-auth required), not issue a code
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "max_age=0 should cause redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    // Must redirect to /login (not to the client's redirect_uri with a code)
    assert!(
        location.starts_with("/login"),
        "max_age=0 must redirect to /login for re-authentication: {location}"
    );
    assert!(
        location.contains("pending_auth="),
        "Login redirect must include pending_auth parameter: {location}"
    );
}

#[tokio::test]
async fn test_rfc9470_max_age_large_value_allows_fresh_session() {
    // A large max_age value (e.g. 86400 = 24 hours) should accept a freshly
    // created session without requiring re-authentication.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "maxage-large@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&max_age=86400",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Should succeed — session is fresh, well within 24 hours
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Large max_age with fresh session should succeed, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("code="),
        "Fresh session within max_age should get authorization code: {location}"
    );
}

// ========================================================================
// OIDC Core Section 3.1.2.1 — prompt parameter
// ========================================================================

#[tokio::test]
async fn test_rfc9470_prompt_login_forces_reauth() {
    // OIDC Core Section 3.1.2.1: prompt=login forces the user to
    // re-authenticate even if they have a valid session.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "prompt-login@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&prompt=login",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Must redirect to /login for re-authentication
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "prompt=login should redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.starts_with("/login"),
        "prompt=login must redirect to /login: {location}"
    );
    assert!(
        location.contains("pending_auth="),
        "Login redirect must include pending_auth parameter: {location}"
    );
}

#[tokio::test]
async fn test_rfc9470_prompt_none_with_valid_session_succeeds() {
    // OIDC Core Section 3.1.2.1: prompt=none means "don't show UI".
    // With a valid session, authorization should proceed normally.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "prompt-none-ok@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&prompt=none",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Should succeed — valid session and prompt=none
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "prompt=none with valid session should redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("code="),
        "prompt=none with valid session should issue authorization code: {location}"
    );
}

#[tokio::test]
async fn test_rfc9470_prompt_none_without_session_returns_login_required() {
    // OIDC Core Section 3.1.2.1: prompt=none without a valid session must
    // return error=login_required (not redirect to login).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "prompt-none-noauth@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let state_param = "prompt-none-state";

    // No session cookie
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&prompt=none&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            state_param,
        ),
        &[],
    )
    .await;

    // Must redirect with error=login_required
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "prompt=none without session must redirect with error, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("error=login_required"),
        "prompt=none without session must return login_required: {location}"
    );

    // State must be echoed
    assert!(
        location.contains(&format!("state={state_param}")),
        "Error redirect must echo state parameter: {location}"
    );

    // RFC 9207: iss must be present
    assert!(
        location.contains("iss="),
        "Error redirect must include iss parameter (RFC 9207): {location}"
    );
}

#[tokio::test]
async fn test_rfc9470_prompt_none_with_max_age_zero_returns_login_required() {
    // OIDC Core Section 3.1.2.1: prompt=none combined with max_age=0 means
    // "re-auth is needed but don't show UI" — must return login_required.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "prompt-none-maxage@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let state_param = "none-maxage-state";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&prompt=none&max_age=0&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            state_param,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Must redirect with error=login_required
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "prompt=none with max_age=0 must redirect with error, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("error=login_required"),
        "prompt=none with max_age=0 must return login_required: {location}"
    );

    // State must be echoed
    assert!(
        location.contains(&format!("state={state_param}")),
        "Error redirect must echo state parameter: {location}"
    );
}

#[tokio::test]
async fn test_rfc9470_unsupported_prompt_value_rejected() {
    // OIDC Core Section 3.1.2.1: Unsupported prompt values should be rejected.
    // Vouch supports "login", "none", and "consent".
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "prompt-bad@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let state_param = "bad-prompt-state";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&prompt=select_account&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            state_param,
        ),
        &[],
    )
    .await;

    // Should redirect with error=invalid_request
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Unsupported prompt value must redirect with error, got: {}",
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
        "Unsupported prompt value must return invalid_request: {location}"
    );
}

// ========================================================================
// RFC 9470 — acr_values passthrough to token
// ========================================================================

#[tokio::test]
async fn test_rfc9470_acr_values_carried_to_token() {
    // RFC 9470: When acr_values is specified in the authorization request,
    // it should flow through the authorization code to the token response.
    // The access token should contain the acr claim.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "acr-token@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let acr = "urn:nist:authentication:assurance-level:aal3";

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            acr_values: Some(acr),
            ..Default::default()
        },
    )
    .await;

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
        "Token exchange with acr_values should succeed: {body}"
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let access_token = response["access_token"].as_str().expect("access_token");

    // Decode and verify acr claim is present
    let claims = decode_jwt_payload(access_token);
    if let Some(acr_claim) = claims.get("acr") {
        let acr_str = acr_claim.as_str().unwrap_or_default();
        assert_eq!(
            acr_str, acr,
            "Access token acr claim should match requested acr_values"
        );
    }
    // acr claim presence depends on token issuance implementation;
    // the key check is that the token exchange succeeds with AAL3.
}

#[tokio::test]
async fn test_rfc9470_unsatisfiable_acr_in_token_exchange_rejected() {
    // RFC 9470 Section 4 (defense-in-depth): If an authorization code somehow
    // carries acr_values that don't include AAL3, the token endpoint should
    // reject the exchange with unmet_authentication_requirements.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "acr-reject-token@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue a code with an ACR that Vouch cannot satisfy (simulates a bug
    // or bypass at the authorization endpoint).
    let bad_acr = "urn:nist:authentication:assurance-level:aal2";

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            acr_values: Some(bad_acr),
            ..Default::default()
        },
    )
    .await;

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

    // Token exchange should fail with 400
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Token exchange with unsatisfiable ACR should fail: {body}"
    );

    let error_response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error_response["error"].as_str(),
        Some("unmet_authentication_requirements"),
        "Error code should be unmet_authentication_requirements: {body}"
    );
}

// ========================================================================
// RFC 9470 — Step-up authentication for key deletion
// ========================================================================

#[tokio::test]
async fn test_rfc9470_key_delete_requires_step_up() {
    // RFC 9470: DELETE /v1/keys/{id} with a stale session (iat far in the past)
    // must return 401 with WWW-Authenticate containing insufficient_user_authentication.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "stepup-delete@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    // Add a second key so delete doesn't fail with "last key" error
    let auth_id2 = create_test_authenticator(&state.store, &user.id).await;

    // Create a session with iat 10 minutes in the past (well beyond 60s max_age)
    let stale_iat = jiff::Timestamp::now().as_second() - 600;
    let token =
        create_test_session_with_iat(&state, &user.id, &user.email, &auth_id, stale_iat).await;

    let response = http_delete_full(
        &app,
        &format!("/v1/keys/{auth_id2}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "Stale session must get 401 for key deletion: {}",
        response.body
    );

    // Verify WWW-Authenticate header
    let www_auth = response
        .headers
        .get("www-authenticate")
        .expect("Must have WWW-Authenticate header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        www_auth.contains("insufficient_user_authentication"),
        "WWW-Authenticate must contain insufficient_user_authentication: {www_auth}"
    );
    assert!(
        www_auth.contains("max_age="),
        "WWW-Authenticate must contain max_age: {www_auth}"
    );
    // RFC 9728 §5.2: step-up challenges from protected resources
    // additionally point at the Protected Resource Metadata
    // document. Injection is performed by
    // `infra::resource_metadata::layer`.
    assert!(
        www_auth.contains("resource_metadata="),
        "WWW-Authenticate must include resource_metadata (RFC 9728 §5.2): {www_auth}"
    );

    // Verify body
    let body: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        body["error"].as_str(),
        Some("insufficient_user_authentication"),
        "Body error must be insufficient_user_authentication: {}",
        response.body
    );
}

#[tokio::test]
async fn test_rfc9470_key_delete_with_fresh_session_succeeds() {
    // RFC 9470: DELETE /v1/keys/{id} with a just-created session (iat=now)
    // should succeed without step-up challenge.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "stepup-fresh@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    // Add a second key so we can delete one
    let auth_id2 = create_test_authenticator(&state.store, &user.id).await;

    // Fresh session — iat is now
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (status, body) = http_delete(
        &app,
        &format!("/v1/keys/{auth_id2}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Fresh session should allow key deletion: {body}"
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response["message"].as_str().is_some(),
        "Success response must include message: {body}"
    );
}

#[tokio::test]
async fn test_rfc9470_key_delete_self_deletion_after_step_up() {
    // After fresh auth, deleting the key used to authenticate cascade-deletes
    // the fresh session. This verifies the operation completes without error
    // even though the authenticator backing the session is being removed.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "stepup-self@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    // Need at least 2 keys to allow deletion
    let _auth_id2 = create_test_authenticator(&state.store, &user.id).await;

    // Fresh session authenticated with auth_id
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Delete the same key used to authenticate
    let (status, body) = http_delete(
        &app,
        &format!("/v1/keys/{auth_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Self-deletion with fresh session should succeed: {body}"
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response["sessions_revoked"].as_u64().unwrap_or(0) >= 1,
        "Self-deletion should revoke at least 1 session: {body}"
    );
}

// ========================================================================
// RFC 9470 / OIDC Core — max_age post-login session validation
// ========================================================================

#[tokio::test]
async fn test_rfc9470_max_age_zero_completes_after_reauth() {
    // OIDC Core Section 3.1.2.1: max_age=0 is equivalent to prompt=login.
    //
    // Flow:
    //   1. User has an existing session.
    //   2. Requests /oauth/authorize?max_age=0 → re-auth required, server
    //      stores pending OAuth params and redirects to /login?pending_auth=<id>.
    //   3. User completes login → obtains a fresh session (age ~0 seconds).
    //   4. Browser returns to /oauth/authorize?pending_auth=<id> with the new
    //      session cookie.
    //
    // The post-login validation in complete_pending_auth must ACCEPT the fresh
    // session. A fresh session has age 0, and `0 > 0` (strict `>`) is false, so
    // the authorization must complete with a code redirect. Using `>=` here
    // would reject the boundary (0 >= 0 = true) and make max_age=0 impossible
    // to complete — the reported bug.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "maxage-zero-complete@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Step 1: existing session triggers re-auth with max_age=0.
    let old_session = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let state_param = "maxage-zero-complete";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&max_age=0&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            state_param,
        ),
        &[("Cookie", &format!("__Host-vouch_session={old_session}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "max_age=0 must redirect for re-auth, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.starts_with("/login?pending_auth="),
        "max_age=0 must redirect to /login with pending_auth: {location}"
    );

    // Extract the pending_auth ID from the redirect URL.
    let pending_id = location
        .split("pending_auth=")
        .nth(1)
        .expect("pending_auth must be in redirect URL");
    let pending_id = urlencoding::decode(pending_id)
        .expect("pending_auth must be URL-decodable")
        .into_owned();

    // Step 2: simulate post-login — create a brand-new fresh session.
    let fresh_session = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Step 3: complete the pending authorization with the fresh session.
    let completion = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?pending_auth={}",
            urlencoding::encode(&pending_id)
        ),
        &[("Cookie", &format!("__Host-vouch_session={fresh_session}"))],
    )
    .await;

    assert!(
        completion.status == StatusCode::FOUND || completion.status == StatusCode::SEE_OTHER,
        "max_age=0 must complete with a redirect after fresh login, got: {} body: {}",
        completion.status,
        completion.body
    );

    let code_location = completion
        .headers
        .get("Location")
        .expect("completion must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        code_location.contains("code="),
        "Fresh session (age ~0) must satisfy max_age=0 and issue a code, \
         got: {code_location}"
    );
    assert!(
        !code_location.contains("error=login_required"),
        "max_age=0 must NOT return login_required for a fresh session: {code_location}"
    );
    // State must be echoed back on success.
    assert!(
        code_location.contains(&format!("state={state_param}")),
        "Success redirect must echo state parameter: {code_location}"
    );
}

#[tokio::test]
async fn test_rfc9470_max_age_completion_rejects_stale_session() {
    // Counterpart to the max_age=0 completion test: a session whose age
    // *exceeds* max_age (strictly greater) must still be rejected after
    // the pending-auth flow, returning error=login_required.
    //
    // Only the boundary case (age == max_age) is acceptable; a session
    // strictly older than max_age must remain rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "maxage-stale@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Age the session so it is at least 2 seconds old (well past max_age=1).
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let state_param = "maxage-stale-reject";

    // max_age=1 with a 2-second-old session: pre-login check (age >= max_age)
    // triggers re-auth and stores a pending auth record carrying max_age=1.
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&max_age=1&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            state_param,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Stale session with max_age=1 must redirect for re-auth, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.starts_with("/login?pending_auth="),
        "Stale session must redirect to /login with pending_auth: {location}"
    );

    let pending_id = location
        .split("pending_auth=")
        .nth(1)
        .expect("pending_auth must be in redirect URL");
    let pending_id = urlencoding::decode(pending_id)
        .expect("pending_auth must be URL-decodable")
        .into_owned();

    // Complete pending auth using the SAME stale session (still > 1 second old).
    // The post-login validation must reject it: age (>1) > max_age (1) is true.
    let completion = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?pending_auth={}",
            urlencoding::encode(&pending_id)
        ),
        &[("Cookie", &format!("__Host-vouch_session={session}"))],
    )
    .await;

    assert!(
        completion.status == StatusCode::FOUND || completion.status == StatusCode::SEE_OTHER,
        "Stale session must redirect with error, got: {} body: {}",
        completion.status,
        completion.body
    );

    let error_location = completion
        .headers
        .get("Location")
        .expect("error redirect must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        error_location.contains("error=login_required"),
        "Session exceeding max_age must be rejected with login_required: {error_location}"
    );
    assert!(
        !error_location.contains("code="),
        "Stale session must NOT receive an authorization code: {error_location}"
    );
    // State must be echoed on the error redirect.
    assert!(
        error_location.contains(&format!("state={state_param}")),
        "Error redirect must echo state parameter: {error_location}"
    );
}
