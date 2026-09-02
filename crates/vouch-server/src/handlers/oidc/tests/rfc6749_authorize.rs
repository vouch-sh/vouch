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
    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

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
async fn test_rfc6749_authorize_missing_redirect_uri_single_uri_auto_selects() {
    // OIDC Core 3.1.2.1: When redirect_uri is absent and the client has exactly
    // one registered URI, the server MUST use that URI (auto-select).
    // The request proceeds normally — user gets redirected to login.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-noredir-single@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    // create_test_oauth_client registers exactly one redirect URI

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

    // Auto-select proceeds — server redirects to login
    assert!(
        response.status == StatusCode::SEE_OTHER || response.status == StatusCode::FOUND,
        "Single-URI client missing redirect_uri should auto-select and redirect to login, got: {}",
        response.status
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_missing_redirect_uri_multi_uri_shows_error_page() {
    // OIDC Core 3.1.2.1: When redirect_uri is absent and the client has multiple
    // registered URIs, the server MUST show an error page (cannot determine which URI).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-noredir-multi@example.com").await;
    // Create a client with two redirect URIs
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            name: "Multi-URI App".to_string(),
            redirect_uris: vec![
                "https://example.com/callback".to_string(),
                "https://example.com/callback2".to_string(),
            ],
            with_secret: false,
            ..Default::default()
        },
    )
    .await;

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
        "Multi-URI client missing redirect_uri must produce error page, got: {}",
        response.status
    );

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
    let client = create_test_client(
        &state.store,
        &owner.id,
        TestClientSpec {
            access_scope: crate::db::AccessScope::Personal,
            org_id: None,
            resource_uris: vec![],
            ..Default::default()
        },
    )
    .await;

    // Create a different user who will try to authorize
    let other_user = create_test_user(&state.store, "authorize-other@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &other_user.id).await;
    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &other_user.id,
            email: &other_user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

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
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            access_scope: crate::db::AccessScope::Public,
            org_id: None,
            resource_uris: vec!["https://api.example.com".to_string()],
            ..Default::default()
        },
    )
    .await;

    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

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

    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

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

    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

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
// RFC 6749 — Authorization Endpoint Additional Tests
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
    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

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

#[tokio::test]
async fn test_rfc6749_deactivated_client_shows_error_page() {
    // RFC 6749 Section 4.1.2.1: A deactivated client must not receive an
    // authorization code. The server shows an error page — it must NOT redirect
    // to the redirect_uri with an error code because that would still pass client
    // identity to the redirect target.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "deactivated-client@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Deactivate the client
    let oauth_client = db::get_oauth_client_by_client_id(&state.store, &client.client_id)
        .await
        .expect("DB error")
        .expect("Client not found");
    db::set_oauth_client_active(&state.store, &oauth_client.id, false)
        .await
        .expect("Failed to deactivate client");

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await;

    // Must show an error page (not redirect)
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Deactivated client must produce error page, not redirect, got: {}",
        response.status
    );

    // Must not redirect to the callback
    if let Some(location) = response.headers.get("Location") {
        let loc = location.to_str().unwrap_or("");
        assert!(
            !loc.contains("example.com/callback"),
            "Must not redirect to callback for deactivated client: {loc}"
        );
    }

    // Error page must mention deactivation
    assert!(
        response.body.contains("deactivated") || response.body.contains("This application"),
        "Error page should describe deactivation: {}",
        response.body
    );
}

#[tokio::test]
async fn test_request_uri_non_https_non_urn_shows_error_page() {
    // OIDC Core Section 6.2 / RFC 9126: request_uri must be either a PAR URN
    // (urn:ietf:params:oauth:request_uri:*) or an HTTPS URL.
    // An HTTP URL, javascript: URI, or other scheme must be rejected with an error page.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "bad-request-uri@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client.client_id,
            urlencoding::encode("http://evil.example.com/request-object"),
        ),
        &[],
    )
    .await;

    // Must show error page — no redirect
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Non-HTTPS/non-URN request_uri must produce error page, got: {}",
        response.status
    );

    // Error message should indicate invalid format
    assert!(
        response.body.contains("request_uri")
            || response.body.contains("Invalid")
            || response.body.contains("invalid"),
        "Error page should describe the invalid request_uri"
    );
}

#[tokio::test]
async fn test_request_uri_missing_client_id_shows_error_page() {
    // request_uri without client_id is always an error — cannot look up client.
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?request_uri={}",
            urlencoding::encode("https://example.com/request-object.jwt"),
        ),
        &[],
    )
    .await;

    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "request_uri without client_id must produce error page, got: {}",
        response.status
    );
}

#[tokio::test]
async fn test_form_post_error_delivers_html_form() {
    // OAuth 2.0 Form Post Response Mode: When response_mode=form_post and an
    // error occurs (e.g. unsupported response_type), the error MUST be delivered
    // via an HTTP 200 HTML form targeting the redirect_uri — not a redirect.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "form-post-error@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=token&client_id={}&redirect_uri={}&scope=openid\
             &state=error-state&response_mode=form_post",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await;

    // Must return 200 with HTML form — not a redirect
    assert_eq!(
        response.status,
        StatusCode::OK,
        "form_post error must be HTTP 200, not redirect: {}",
        response.body
    );

    // Must contain an HTML form targeting the redirect_uri
    assert!(
        response.body.contains(r#"method="post""#),
        "form_post error must contain a POST form"
    );
    assert!(
        response.body.contains("https://example.com/callback"),
        "form_post error form must target the redirect_uri"
    );

    // Must carry an error parameter
    assert!(
        response.body.contains(r#"name="error""#),
        "form_post error form must contain a hidden 'error' input"
    );

    // Must include iss (RFC 9207)
    assert!(
        response.body.contains(r#"name="iss""#),
        "form_post error must contain a hidden 'iss' input (RFC 9207)"
    );

    // State must be echoed
    assert!(
        response.body.contains("error-state"),
        "form_post error must echo the state parameter"
    );
}

/// RFC 6749 §3.1 carries the same parameter rules as §3.2 for the
/// authorization endpoint: "Parameters sent without a value MUST be treated as
/// if they were omitted from the request." Checked on the query string, which
/// is how this endpoint receives them, and on `prompt`, where the two cases
/// diverge: `Prompt::parse("")` is `None`, so an empty `prompt` used to be
/// rejected as an unsupported value while an omitted one requests nothing.
#[tokio::test]
async fn test_rfc6749_authorize_empty_parameter_is_treated_as_omitted() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "authorize-empty@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let base = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri=https://example.com/callback",
        client.client_id
    );

    // Both answers are redirects, so the Location header is where they differ:
    // an unsupported prompt redirects to the client with `error=`, while an
    // omitted one continues the flow.
    let empty = http_get_full(&app, &format!("{base}&prompt="), &[]).await;
    let omitted = http_get_full(&app, &base, &[]).await;

    let location = |r: &crate::test_utils::HttpResponse| {
        r.headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };

    // Each answer carries a fresh `pending_auth` id, so compare the target
    // rather than the whole URL.
    let target = |r: &crate::test_utils::HttpResponse| {
        location(r)
            .split('?')
            .next()
            .unwrap_or_default()
            .to_string()
    };

    assert_eq!(empty.status, omitted.status);
    assert_eq!(
        target(&empty),
        target(&omitted),
        "`prompt=` must answer exactly as an omitted `prompt`"
    );
    assert!(
        !location(&empty).contains("error="),
        "`prompt=` must not be rejected as an unsupported value: {}",
        location(&empty)
    );
}

// ========================================================================
// response_mode — unrecognized values
//
// OAuth 2.0 Multiple Response Type Encoding Practices §2.1 defines
// `response_mode` and says what an absent one means — "If `response_mode` is
// not present in a request, the default Response Mode mechanism specified by
// the Response Type is used" — but is silent on an unrecognized value. The
// choice is therefore ours, and substituting the default is the one answer
// that cannot be right: a client asking for `form_post` or `jwt` is not
// listening on a query redirect, so it would receive an authorization
// response it never reads. The PAR endpoint has always rejected these; these
// tests hold the authorization endpoint to the same answer.
// ========================================================================

#[tokio::test]
async fn test_authorize_rejects_unrecognized_response_mode() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "bad-response-mode@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={challenge}&code_challenge_method=S256\
             &response_mode=formpost&state=rm-state",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    let location = response
        .headers
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    assert!(
        !location.contains("code="),
        "an unrecognized response_mode must not issue an authorization code: {location}"
    );
    assert!(
        location.contains("error=invalid_request"),
        "an unrecognized response_mode must be rejected: {} {location}",
        response.status
    );
    // RFC 6749 §4.1.2.1: the error response carries the request's `state`.
    assert!(
        location.contains("state=rm-state"),
        "the error response must echo state: {location}"
    );
}

#[tokio::test]
async fn test_authorize_accepts_every_advertised_response_mode() {
    // The rejection above must not cost a mode the discovery document
    // advertises: `response_modes_supported` and the parser read one table.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "good-response-mode@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let advertised = doc["response_modes_supported"]
        .as_array()
        .expect("discovery must advertise response_modes_supported");
    assert!(!advertised.is_empty(), "discovery must list some mode");

    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    for mode in advertised {
        let mode = mode.as_str().expect("response mode must be a string");
        let response = http_get_full(
            &app,
            &format!(
                "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
                 &code_challenge={challenge}&code_challenge_method=S256&response_mode={}",
                client.client_id,
                urlencoding::encode("https://example.com/callback"),
                urlencoding::encode(mode),
            ),
            &[],
        )
        .await;

        let location = response
            .headers
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            !location.contains("error=invalid_request"),
            "advertised response_mode {mode:?} must be accepted: {location}"
        );
    }
}

// ========================================================================
// RFC 6749 Section 4.1.2.1 — a failed session lookup is `server_error`
//
// A store failure while checking the session says nothing about whether the
// user is authenticated. Collapsing it into the "not authenticated" branch
// reports a server fault as `login_required` (or walks the user into a login
// form whose pending-authorization write hits the same broken store).
//
// The `SessionCache::inject_fault` seam faults only the session token's own
// hash, so client resolution and request validation still run against the
// live pool and the failure is isolated to the lookup under test.
// ========================================================================

#[tokio::test]
async fn test_rfc6749_authorize_session_store_error_returns_server_error() {
    // RFC 6749 Section 4.1.2.1: `server_error` is "an unexpected condition
    // that prevented it from fulfilling the request. (This error code is
    // needed because a 500 Internal Server Error HTTP status code cannot be
    // returned to the client via an HTTP redirect.)" — which is exactly a
    // store failure during the session lookup. `login_required` would instead
    // tell the client to retry interactively against the broken store.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-store-fault@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    state
        .session_cache
        .inject_fault(crate::crypto::hash_token(&session_token));

    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    let state_param = "store-fault-state";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={challenge}&code_challenge_method=S256&prompt=none&state={state_param}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "store failure must still be reported over the redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("error=server_error"),
        "store failure during the session lookup must return server_error: {location}"
    );
    assert!(
        !location.contains("error=login_required"),
        "store failure must not be reported as login_required: {location}"
    );
    assert!(
        location.contains(&format!("state={state_param}")),
        "Error redirect must echo state parameter: {location}"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_session_store_error_does_not_redirect_to_login() {
    // Without prompt=none the pre-fix code sent the user to /login, where
    // storing the pending authorization would fail against the same store.
    // The client must learn the request failed instead.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-store-fault-ui@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    state
        .session_cache
        .inject_fault(crate::crypto::hash_token(&session_token));

    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={challenge}&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    let location = response
        .headers
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    assert!(
        !location.starts_with("/login"),
        "store failure must not be masked as a login redirect: {location}"
    );
    assert!(
        location.contains("error=server_error"),
        "store failure must return server_error to the client: {location}"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_pending_auth_store_error_is_not_auth_failure() {
    // Returning from /login, a store failure must not render "Authentication
    // failed" — the sign-in was never the problem, and that message invites
    // the user to repeat a ceremony that cannot help.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "pending-store-fault@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    // Unauthenticated first leg: stores the pending authorization and hands
    // back its id in the /login redirect.
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={challenge}&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await;
    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8")
        .to_string();
    let pending_id = location
        .split("pending_auth=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("login redirect must carry pending_auth");

    // Second leg: the user now has a session, but its lookup faults.
    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    state
        .session_cache
        .inject_fault(crate::crypto::hash_token(&session_token));

    let (status, body) = http_get(
        &app,
        &format!("/oauth/authorize?pending_auth={pending_id}"),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the denied page is rendered inline, got: {status}"
    );
    assert!(
        !body.contains("Authentication failed"),
        "store failure must not be reported as a failed authentication: {body}"
    );
    assert!(
        body.contains("could not complete the request"),
        "store failure must render the server-error message: {body}"
    );
}

// ========================================================================
// Session assurance at the authorization endpoint
//
// An enrollment bootstrap session — upstream IdP sign-in, no FIDO2 — carries
// an `authenticator_id` for any returning user, so gating this endpoint on
// authenticator presence let it issue a code. The resulting tokens claim
// `acr: aal3` and `amr: [hwk, pin, user]`, because the authorization-code
// grant stamps `HardwareVerification::Verified` unconditionally. Same unsound
// inference as issue #1114, different path.
// ========================================================================

/// Build a valid authorize URL for `client`, with PKCE.
fn authorize_url(client_id: &str, state_param: &str) -> String {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
         &code_challenge={}&code_challenge_method=S256&state={}",
        client_id,
        urlencoding::encode("https://example.com/callback"),
        challenge,
        state_param,
    )
}

#[tokio::test]
async fn test_authorize_refuses_bootstrap_session_and_issues_no_code() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "authorize-bootstrap@example.com").await;
    // A returning user: the key on record is what gives the bootstrap session
    // its `authenticator_id`.
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            verification: TestVerification::NotVerified,
            ..Default::default()
        },
    )
    .await;

    let response = http_get_full(
        &app,
        &authorize_url(&client.client_id, "teststate-bootstrap"),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    let location = response
        .headers
        .get("Location")
        .and_then(|l| l.to_str().ok())
        .unwrap_or_default();
    assert!(
        !location.contains("code="),
        "a session that never asserted must not receive an authorization code, \
         got redirect to: {location}"
    );
    assert!(
        location.starts_with("/login"),
        "the user must be sent to assert with their key, got: {location}"
    );
}

/// The companion success case. Without it the assertion above would pass even
/// if the endpoint refused every session.
#[tokio::test]
async fn test_authorize_still_issues_a_code_for_a_verified_session() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "authorize-verified@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

    let response = http_get_full(
        &app,
        &authorize_url(&client.client_id, "teststate-verified"),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    let location = response
        .headers
        .get("Location")
        .and_then(|l| l.to_str().ok())
        .unwrap_or_default();
    assert!(
        location.contains("code="),
        "a hardware-verified session must still receive a code, got: {location}"
    );
}

#[tokio::test]
async fn test_pending_auth_with_bootstrap_session_returns_to_login_and_preserves_pending() {
    // Issue #1168: a bootstrap (NotVerified) session arriving with a pending
    // auth id used to have the id consumed before the session gate ran, so
    // the user saw a dead-end denial and every retry saw "session expired".
    // The unacceptable session must instead go back to /login with the
    // single-use id unspent, and /login — consulting the same gate — must
    // render the assertion form rather than bounce back.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "pending-bootstrap@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            verification: TestVerification::NotVerified,
            ..Default::default()
        },
    )
    .await;
    let cookie = format!("__Host-vouch_session={session_token}");

    let pending_id = create_test_pending_auth(
        &state.store,
        TestPendingAuthSpec {
            client_id: &client.client_id,
            ..Default::default()
        },
    )
    .await;

    // Second leg: return from login with the bootstrap session.
    let response = http_get_full(
        &app,
        &format!("/oauth/authorize?pending_auth={pending_id}"),
        &[("Cookie", &cookie)],
    )
    .await;
    assert!(
        response.status.is_redirection(),
        "an unverified session must be sent back to /login, got: {}",
        response.status
    );
    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");
    assert!(
        location.starts_with("/login?pending_auth=") && location.contains(&pending_id),
        "must return to /login carrying the same pending id, got: {location}"
    );
    assert!(
        crate::db::get_pending_oauth_authorization(&state.store, &pending_id)
            .await
            .expect("pending lookup")
            .is_some(),
        "the refused session must not spend the single-use pending id"
    );

    // Third leg: /login consults the same gate and renders the form —
    // the flow converges instead of looping or dead-ending.
    let login = http_get_full(
        &app,
        &format!("/login?pending_auth={pending_id}"),
        &[("Cookie", &cookie)],
    )
    .await;
    assert_eq!(
        login.status,
        StatusCode::OK,
        "/login must render the assertion form for the unverified session, \
         got {} with location {:?}",
        login.status,
        login.headers.get("Location")
    );
}

#[tokio::test]
async fn test_pending_auth_without_session_returns_to_login_and_preserves_pending() {
    // A pending auth id presented with no session at all (expired cookie,
    // cleared cookies mid-flow) is recoverable: send the user to /login with
    // the id unspent instead of consuming it and dead-ending.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "pending-nosession@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let pending_id = create_test_pending_auth(
        &state.store,
        TestPendingAuthSpec {
            client_id: &client.client_id,
            ..Default::default()
        },
    )
    .await;

    let response = http_get_full(
        &app,
        &format!("/oauth/authorize?pending_auth={pending_id}"),
        &[],
    )
    .await;
    assert!(
        response.status.is_redirection(),
        "a sessionless return must be sent back to /login, got: {}",
        response.status
    );
    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");
    assert!(
        location.starts_with("/login?pending_auth=") && location.contains(&pending_id),
        "must return to /login carrying the same pending id, got: {location}"
    );
    assert!(
        crate::db::get_pending_oauth_authorization(&state.store, &pending_id)
            .await
            .expect("pending lookup")
            .is_some(),
        "the sessionless return must not spend the single-use pending id"
    );
}
