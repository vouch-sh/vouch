// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 6749 Section 4.1.2 — Authorization endpoint redirect tests.

use super::helpers::*;

// ========================================================================
// RFC 6749 Section 4.1.2 — Authorization Endpoint Redirect Tests
// ========================================================================

#[tokio::test]
async fn test_rfc6749_authorize_authenticated_user_redirects_with_code() {
    // RFC 6749 Section 4.1.2: Authenticated user must receive a 302/303 redirect
    // to the redirect_uri with code and state parameters.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-authed@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Create a valid session stored in the DB (cookie-based auth)
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Build a valid PKCE challenge
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let state_param = "teststate-rfc6749";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            state_param,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Must redirect (302 or 303)
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Authenticated authorize request must redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Location must be valid UTF-8");

    // RFC 6749 Section 4.1.2: code parameter must be present
    assert!(
        location.contains("code="),
        "Location must include authorization code: {location}"
    );

    // RFC 6749 Section 4.1.2: state must be echoed unchanged
    assert!(
        location.contains(&format!("state={state_param}")),
        "Location must echo state parameter unchanged: {location}"
    );

    // RFC 9207 Section 2: iss parameter must be present
    assert!(
        location.contains("iss="),
        "Location must include iss parameter (RFC 9207): {location}"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_unknown_client_shows_error_page() {
    // RFC 6749 Section 4.1.2.1: If client_id is unknown, the server MUST NOT
    // redirect to the redirect_uri — it must show an error page.
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/authorize?response_type=code&client_id=nonexistent-client-xyz\
         &redirect_uri=https://example.com/callback&scope=openid\
         &code_challenge=dummychallenge&code_challenge_method=S256",
        &[],
    )
    .await;

    // Must show an error page (200 HTML), NOT redirect to the unregistered URI
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Unknown client must produce error page, not redirect, got: {}",
        response.status
    );

    // Specifically must NOT redirect (no Location header pointing to callback)
    if let Some(location) = response.headers.get("Location") {
        let loc_str = location.to_str().unwrap_or("");
        assert!(
            !loc_str.contains("example.com/callback"),
            "Must not redirect to unregistered URI for unknown client: {loc_str}"
        );
    }
}

#[tokio::test]
async fn test_rfc6749_authorize_unregistered_redirect_uri_shows_error_page() {
    // RFC 6749 Section 10.6: If redirect_uri is not registered, the server MUST NOT
    // redirect — it must display an error to the user.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-badredir@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    // Note: client is registered with https://example.com/callback

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}\
             &redirect_uri={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://evil.example.com/steal")
        ),
        &[],
    )
    .await;

    // Must show error page, NOT redirect to the evil URI
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Unregistered redirect_uri must produce error page, not redirect, got: {}",
        response.status
    );

    if let Some(location) = response.headers.get("Location") {
        let loc_str = location.to_str().unwrap_or("");
        assert!(
            !loc_str.contains("evil.example.com"),
            "Must not redirect to unregistered URI: {loc_str}"
        );
    }
}

#[tokio::test]
async fn test_rfc6749_authorize_missing_response_type_redirects_with_error() {
    // RFC 6749 Section 4.1.2.1: Missing response_type must produce error=invalid_request
    // redirected back to the registered redirect_uri.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-nort@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let response = http_get_full(
        &app,
        // No response_type parameter
        &format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://example.com/callback")
        ),
        &[],
    )
    .await;

    // Must redirect with error OR show error page
    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response
            .headers
            .get("Location")
            .expect("Redirect must have Location")
            .to_str()
            .expect("Valid UTF-8");
        assert!(
            location.contains("error=invalid_request") || location.contains("error="),
            "Redirect must include error parameter: {location}"
        );
    } else {
        // Error page is also acceptable for this case
        assert!(
            response.status == StatusCode::OK || response.status.is_client_error(),
            "Must show error for missing response_type, got: {}",
            response.status
        );
    }
}

// ========================================================================
// RFC 6749 Section 4.1.2.1 — Authorization Endpoint Error Conditions
// ========================================================================

#[tokio::test]
async fn test_rfc6749_authorize_empty_redirect_uri_shows_error_page() {
    // RFC 6749 Section 4.1.2.1: If the redirect_uri is missing or invalid,
    // the server MUST NOT redirect and MUST display an error to the user.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-noredir@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256",
            client.client_id,
        ),
        &[],
    )
    .await;

    // Must show an error page, not redirect
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Missing redirect_uri must produce error page, not redirect, got: {}",
        response.status
    );

    // Body must indicate redirect_uri is required
    assert!(
        response.body.contains("redirect_uri"),
        "Error page should mention redirect_uri: {}",
        response.body
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_unsupported_response_type_redirects_with_error() {
    // RFC 6749 Section 4.1.2.1: If response_type is unsupported, the server
    // MUST redirect to the redirect_uri with error=unsupported_response_type.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-badrt@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let state_param = "teststate-badrt";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=token&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            state_param,
        ),
        &[],
    )
    .await;

    // Must redirect with error
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Unsupported response_type must redirect with error, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    // RFC 6749 Section 4.1.2.1: error=unsupported_response_type
    assert!(
        location.contains("error=unsupported_response_type"),
        "Redirect must include error=unsupported_response_type: {location}"
    );

    // RFC 6749 Section 4.1.2.1: State must be echoed unchanged
    assert!(
        location.contains(&format!("state={state_param}")),
        "Error redirect must echo state parameter: {location}"
    );

    // RFC 9207 Section 2: iss must be present even in error responses
    assert!(
        location.contains("iss="),
        "Error redirect must include iss parameter (RFC 9207): {location}"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_unauthenticated_user_redirects_to_login() {
    // RFC 6749 Section 4.1.1: If the user is not authenticated, the server
    // must redirect to a login page. Vouch stores OAuth params and redirects
    // to /login with pending_auth.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-noauth@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    // No session cookie — user is not authenticated
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&state=loginstate",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[],
    )
    .await;

    // Must redirect to login
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Unauthenticated user must be redirected to login, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    // Must redirect to /login with pending_auth parameter
    assert!(
        location.starts_with("/login"),
        "Redirect must target /login: {location}"
    );
    assert!(
        location.contains("pending_auth="),
        "Login redirect must include pending_auth parameter: {location}"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_access_denied_personal_scope() {
    // RFC 6749 Section 4.1.2.1: If the user does not have access, the server
    // must deny the request. For Personal scope apps, only the creator can authorize.
    let (app, state) = test_app().await;

    // Create user who owns the app
    let owner = create_test_user(&state.store, "authorize-owner@example.com").await;
    // Create a Personal scope app
    let client = create_test_oauth_client_with_options(
        &state.store,
        &owner.id,
        crate::db::AccessScope::Personal,
        None,
        &[],
    )
    .await;

    // Create a different user who will try to authorize
    let other_user = create_test_user(&state.store, "authorize-other@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &other_user.id).await;
    let session_token =
        create_test_session(&state, &other_user.id, &other_user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Must show error page (denied template), NOT redirect with code
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Access denied must produce error page, got: {}",
        response.status
    );

    // Must not have a Location header with an auth code
    if let Some(location) = response.headers.get("Location") {
        let loc_str = location.to_str().unwrap_or("");
        assert!(
            !loc_str.contains("code="),
            "Must not issue authorization code to unauthorized user: {loc_str}"
        );
    }

    // Body should indicate access denied
    assert!(
        response.body.contains("access")
            || response.body.contains("denied")
            || response.body.contains("don"),
        "Error page should explain access denial"
    );
}

#[tokio::test]
async fn test_rfc8707_authorize_invalid_resource_redirects_with_error() {
    // RFC 8707 Section 2: If the resource parameter is not registered for the client,
    // the server MUST return error=invalid_target.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-badres@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Create a client with a specific resource URI
    let client = create_test_oauth_client_with_options(
        &state.store,
        &user.id,
        crate::db::AccessScope::Public,
        None,
        &["https://api.example.com".to_string()],
    )
    .await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let state_param = "teststate-badres";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&state={}\
             &resource={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            state_param,
            urlencoding::encode("https://unregistered.example.com"),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Must redirect with error=invalid_target
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Invalid resource must redirect with error, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("error=invalid_target"),
        "Redirect must include error=invalid_target (RFC 8707): {location}"
    );

    // RFC 6749 Section 4.1.2.1: State must be echoed
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
async fn test_rfc6749_authorize_missing_client_id_shows_error_page() {
    // RFC 6749 Section 4.1.2.1: If client_id is missing, the server MUST NOT
    // redirect and MUST display an error page.
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/authorize?response_type=code\
         &redirect_uri=https://example.com/callback&scope=openid\
         &code_challenge=dummychallenge&code_challenge_method=S256",
        &[],
    )
    .await;

    // Must show error page — no redirect
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Missing client_id must produce error page, got: {}",
        response.status
    );

    // Must not redirect to the callback
    if let Some(location) = response.headers.get("Location") {
        let loc_str = location.to_str().unwrap_or("");
        assert!(
            !loc_str.contains("example.com/callback"),
            "Must not redirect when client_id is missing: {loc_str}"
        );
    }
}

#[tokio::test]
async fn test_rfc6749_authorize_pending_auth_expired_shows_error_page() {
    // When returning from login with an invalid or expired pending_auth ID,
    // the server must show an error page since the authorization context is lost.
    let (app, _state) = test_app().await;

    // Use a nonexistent pending_auth ID
    let response = http_get_full(
        &app,
        "/oauth/authorize?pending_auth=nonexistent-pending-id-12345",
        &[],
    )
    .await;

    // Must show error page
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Expired/invalid pending_auth must produce error page, got: {}",
        response.status
    );

    // Body should indicate the session expired
    assert!(
        response.body.contains("expired") || response.body.contains("try again"),
        "Error page should mention expiration or retry"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_state_preserved_across_redirect() {
    // RFC 6749 Section 4.1.2: The state parameter MUST be returned unchanged
    // in the authorization response. This tests a complex state value with
    // special characters that must survive URL encoding round-trip.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-state@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    // State value with characters that need URL encoding
    let state_param = "state_with-special.chars~123";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            urlencoding::encode(state_param),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Authenticated request must redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    // Parse the redirect URL and verify state is preserved
    let url = url::Url::parse(location).expect("Location must be a valid URL");
    let state_values: Vec<String> = url
        .query_pairs()
        .filter(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .collect();

    assert_eq!(
        state_values.len(),
        1,
        "Must have exactly one state parameter"
    );
    assert_eq!(
        state_values[0], state_param,
        "State parameter must be echoed unchanged"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_param_length_validation() {
    // The authorization endpoint must reject parameters that exceed
    // maximum allowed lengths to prevent abuse.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-longparam@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // state has max length of 512 — send 600 chars
    let long_state = "x".repeat(600);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            long_state,
        ),
        &[],
    )
    .await;

    // Must redirect with error=invalid_request or show error page
    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response
            .headers
            .get("Location")
            .expect("Must have Location header")
            .to_str()
            .expect("Valid UTF-8");
        assert!(
            location.contains("error="),
            "Oversized parameter must produce error: {location}"
        );
    } else {
        assert!(
            response.status == StatusCode::OK || response.status.is_client_error(),
            "Must show error for oversized parameter, got: {}",
            response.status
        );
    }
}

#[tokio::test]
async fn test_rfc6749_authorize_code_redirect_to_registered_uri_only() {
    // RFC 6749 Section 10.6: The authorization code must be delivered only
    // to the redirect_uri that was registered for the client. This verifies
    // that the successful redirect goes to the correct URI.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-reguri@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Must redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    // Redirect must go to the registered URI
    assert!(
        location.starts_with("https://example.com/callback?"),
        "Redirect must target the registered redirect_uri: {location}"
    );

    // Must contain the authorization code
    assert!(
        location.contains("code="),
        "Redirect must contain authorization code: {location}"
    );
}

// ========================================================================
// P1: RFC 6749 — Authorization Endpoint Additional Tests
// ========================================================================

#[tokio::test]
async fn test_rfc6749_error_page_for_unknown_client_id() {
    // RFC 6749 Section 4.1.2.1: Invalid client_id must show error page,
    // NOT redirect to an unregistered URI.
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/authorize?response_type=code&client_id=nonexistent-client&redirect_uri=https://evil.com/callback&code_challenge=abc&code_challenge_method=S256",
        &[],
    )
    .await;

    // Should show an error page (200 with HTML), NOT redirect to evil.com
    assert_ne!(
        response.status,
        StatusCode::SEE_OTHER,
        "Unknown client_id must NOT cause redirect to unregistered URI"
    );
    assert_ne!(
        response.status,
        StatusCode::FOUND,
        "Unknown client_id must NOT cause redirect to unregistered URI"
    );
    // Should either be 200 (error page) or 400
    assert!(
        response.status == StatusCode::OK || response.status == StatusCode::BAD_REQUEST,
        "Should show error page for unknown client_id, got: {}",
        response.status
    );
}

#[tokio::test]
async fn test_rfc6749_redirect_uri_validation_against_registered() {
    // RFC 6749 Section 10.6: Authorize endpoint rejects unregistered redirect URIs.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "redirect-unregistered@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge=abc&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://evil.com/steal-code")
        ),
        &[],
    )
    .await;

    // Must NOT redirect to the unregistered URI
    if let Some(location) = response.headers.get("Location") {
        let loc = location.to_str().unwrap_or("");
        assert!(
            !loc.starts_with("https://evil.com"),
            "Must not redirect to unregistered URI: {}",
            loc
        );
    }
    // Should show error page instead
    assert!(
        response.status == StatusCode::OK || response.status == StatusCode::BAD_REQUEST,
        "Should show error page for unregistered redirect_uri, got: {}",
        response.status
    );
}

#[tokio::test]
async fn test_rfc6749_state_parameter_passthrough() {
    // RFC 6749 Section 4.1.2: State sent in authorize request must appear
    // unchanged in the error redirect response.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "state-passthrough@example.com").await;
    let client = create_test_public_oauth_client(&state.store, &user.id).await;

    let unique_state = "unique-state-value-12345";

    // This will fail validation (no code_challenge for public client) and redirect with error + state
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&state={}&scope=openid",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            unique_state
        ),
        &[],
    )
    .await;

    if response.status == StatusCode::SEE_OTHER || response.status == StatusCode::FOUND {
        let location = response
            .headers
            .get("Location")
            .expect("Should have Location header")
            .to_str()
            .expect("Valid header");

        // Parse the redirect URL and check for state parameter
        let redirect_url = url::Url::parse(location).expect("Valid URL");
        let state_param: Option<String> = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string());

        assert_eq!(
            state_param.as_deref(),
            Some(unique_state),
            "State parameter must be preserved unchanged in redirect"
        );
    }
}

#[tokio::test]
async fn test_response_mode_form_post_returns_html_form() {
    // OAuth 2.0 Form Post Response Mode: response_mode=form_post must return HTTP 200
    // with an HTML form auto-submit body instead of a 302 redirect.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "form-post-test@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&state=form-post-state\
             &response_mode=form_post",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // form_post delivers via HTTP 200 with an HTML body, not a redirect
    assert_eq!(
        response.status,
        StatusCode::OK,
        "form_post response must be 200 OK, not a redirect: {}",
        response.body
    );

    // Must contain a form with method="post" targeting the redirect_uri
    assert!(
        response.body.contains(r#"method="post""#),
        "form_post body must contain a POST form"
    );
    assert!(
        response.body.contains("https://example.com/callback"),
        "form_post form must target the redirect_uri"
    );

    // Authorization code must be in a hidden input
    assert!(
        response.body.contains(r#"name="code""#),
        "form_post body must contain a hidden 'code' input"
    );

    // iss parameter (RFC 9207) must be present
    assert!(
        response.body.contains(r#"name="iss""#),
        "form_post body must contain a hidden 'iss' input (RFC 9207)"
    );

    // State must be echoed
    assert!(
        response.body.contains("form-post-state"),
        "form_post body must echo the state parameter"
    );
}
