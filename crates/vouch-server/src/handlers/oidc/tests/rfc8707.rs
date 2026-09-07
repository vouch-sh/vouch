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
    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            resource: Some(resource_uri),
            ..Default::default()
        },
    )
    .await;

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

// ========================================================================
// RFC 8707 §2.1 — registered-set restriction on the pending-auth resume path
//
// `/oauth/authorize` has two continuation paths that issue an authorization
// code: the authenticated no-re-auth path (`issue_code_after_reauth_check`),
// which runs `is_valid_resource_uri` (Step 6), and the pending-auth resume
// path (`complete_pending_auth`) reached both when an unauthenticated user
// must log in AND when an already-authenticated user's session exceeds
// `max_age` / sends `prompt=login`. Before the fix the pending path skipped
// Step 6, so an unregistered `resource` escaped into a minted access token's
// `aud`. The shared `validate_code_request_constraints` helper now applies
// the guard on both paths.
// ========================================================================

/// Build a client with a registered `resource_uris` set, plus an existing
/// session, returning `(client, old_session, verifier, challenge)`.
async fn rfc8707_client_with_resource_set(
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    auth_id: &str,
    resource_uris: Vec<String>,
) -> (TestOAuthClient, String, String, String) {
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            access_scope: crate::db::AccessScope::Public,
            org_id: None,
            resource_uris,
            ..Default::default()
        },
    )
    .await;

    let session = create_test_session_with(
        state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(auth_id),
            ..Default::default()
        },
    )
    .await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string();
    let challenge = sha256_base64url(&verifier);
    (client, session, verifier, challenge)
}

/// Extract the `pending_auth` id from a `/login?pending_auth=…` redirect.
fn pending_id_from_login_redirect(location: &str) -> String {
    let raw = location
        .split("pending_auth=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("login redirect must carry pending_auth");
    urlencoding::decode(raw)
        .expect("pending_auth must be URL-decodable")
        .into_owned()
}

#[tokio::test]
async fn test_rfc8707_pending_path_rejects_unregistered_resource_reauth() {
    // RFC 8707 §2.1: an unregistered `resource` MUST be rejected with
    // `error=invalid_target` at the authorization endpoint on BOTH
    // continuation paths. The re-auth route — `max_age=0` with an existing
    // session — stores the pending request and dispatches to /login; before
    // the fix the resume (`complete_pending_auth`) bypassed Step 6 and minted
    // a token whose `aud` was the unregistered URI. The two paths must now
    // answer identically for the same client, resource, and user.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "pend-badres-reauth@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, old_session, _verifier, challenge) = rfc8707_client_with_resource_set(
        &state,
        &user,
        &auth_id,
        vec!["https://api.example.com".to_string()],
    )
    .await;
    let state_param = "pend-badres-reauth";

    // Step 1: existing session + max_age=0 → re-auth → pending row + /login.
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={challenge}&code_challenge_method=S256&max_age=0&state={state_param}\
             &resource={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode("https://unregistered.example.com"),
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
        "max_age=0 must redirect to /login?pending_auth=: {location}"
    );
    let pending_id = pending_id_from_login_redirect(location);

    // Step 2: fresh session (simulate post-login).
    let fresh_session = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

    // Step 3: resume — must reject the unregistered resource with
    // error=invalid_target (RFC 8707 §2.1), NOT issue a code.
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
        "resume must redirect with the authorization error, got: {} body: {}",
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
        code_location.contains("error=invalid_target"),
        "pending resume must reject unregistered resource with error=invalid_target \
         (RFC 8707 §2.1): {code_location}"
    );
    assert!(
        !code_location.contains("code="),
        "pending resume must NOT issue a code for an unregistered resource: {code_location}"
    );
    // RFC 6749 §4.1.2.1: state must be echoed on the error redirect.
    assert!(
        code_location.contains(&format!("state={state_param}")),
        "error redirect must echo state parameter: {code_location}"
    );
}

#[tokio::test]
async fn test_rfc8707_pending_path_rejects_unregistered_resource_needs_auth() {
    // RFC 8707 §2.1: same registered-set restriction reached via the
    // NeedsAuth (no session) pending-path creation route. The two pending
    // creation routes (NeedsAuth and needs_reauth) converge on
    // `complete_pending_auth`, so the guard must fire on both.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "pend-badres-needsauth@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
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

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let state_param = "pend-badres-needsauth";

    // No session cookie: NeedsAuth path stores pending + redirects to /login.
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={challenge}&code_challenge_method=S256&state={state_param}\
             &resource={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode("https://unregistered.example.com"),
        ),
        &[],
    )
    .await;
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "unauthenticated authorize must redirect to /login, got: {}",
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
        "NeedsAuth must redirect to /login?pending_auth=: {location}"
    );
    let pending_id = pending_id_from_login_redirect(location);

    // Simulate login: create a session.
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

    // Resume — must reject the unregistered resource.
    let completion = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?pending_auth={}",
            urlencoding::encode(&pending_id)
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        completion.status == StatusCode::FOUND || completion.status == StatusCode::SEE_OTHER,
        "resume must redirect with the authorization error, got: {} body: {}",
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
        code_location.contains("error=invalid_target"),
        "pending resume must reject unregistered resource with error=invalid_target: {code_location}"
    );
    assert!(
        !code_location.contains("code="),
        "pending resume must NOT issue a code for an unregistered resource: {code_location}"
    );
    assert!(
        code_location.contains(&format!("state={state_param}")),
        "error redirect must echo state parameter: {code_location}"
    );
}

#[tokio::test]
async fn test_rfc8707_pending_path_accepts_registered_resource_reauth() {
    // RFC 8707: a REGISTERED `resource` on the pending path must still issue
    // a code, and the exchanged access token's `aud` must equal that
    // resource. Guards against an over-restrictive fix blocking valid
    // requests. Uses max_age=0 to force the re-auth pending path.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "pend-goodres-reauth@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let resource_uri = "https://api.example.com";
    let (client, old_session, verifier, challenge) =
        rfc8707_client_with_resource_set(&state, &user, &auth_id, vec![resource_uri.to_string()])
            .await;
    let state_param = "pend-goodres-reauth";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={challenge}&code_challenge_method=S256&max_age=0&state={state_param}\
             &resource={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode(resource_uri),
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
    let pending_id = pending_id_from_login_redirect(location);

    let fresh_session = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

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
        "registered resource must complete with a redirect, got: {} body: {}",
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
        "registered resource on pending path must issue a code: {code_location}"
    );
    assert!(
        !code_location.contains("error="),
        "registered resource must not produce an error: {code_location}"
    );

    // Exchange and verify the access token's `aud` equals the registered
    // resource (RFC 8707 §2.2 / RFC 9068 §3).
    let code = code_location
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("redirect must carry code=");
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}&code_verifier={verifier}",
            urlencoding::encode("https://example.com/callback"),
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "token exchange for a registered resource must succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let access_token = response["access_token"].as_str().expect("access_token");
    let claims = decode_jwt_payload(access_token);
    let aud = claims
        .get("aud")
        .expect("access token should have aud claim");
    assert_eq!(
        aud.as_str().unwrap_or_default(),
        resource_uri,
        "access token aud must match the registered resource indicator"
    );
}

#[tokio::test]
async fn test_rfc8707_pending_path_rejects_unsupported_acr_reauth() {
    // RFC 9470: an unsupported `acr_values` must be rejected at the
    // authorization endpoint. The authenticated no-re-auth path already does
    // so in `issue_code_after_reauth_check` (Step 5); the shared helper now
    // applies the same check on the pending resume, so the error is delivered
    // as an authorization-endpoint redirect
    // (error=unmet_authentication_requirements) instead of a doomed code that
    // the token endpoint would reject later. Demonstrates that the two paths
    // now share one error-delivery route for ACR.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "pend-badacr-reauth@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let old_session = create_test_session_with(
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
    let state_param = "pend-badacr-reauth";

    // Only ACR_AAL3 (urn:nist:authentication:assurance-level:aal3) is
    // supported; aal1 is unsupported.
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={challenge}&code_challenge_method=S256&max_age=0&state={state_param}\
             &acr_values={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode("urn:nist:authentication:assurance-level:aal1"),
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
    let pending_id = pending_id_from_login_redirect(location);

    let fresh_session = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

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
        "resume must redirect with the authorization error, got: {} body: {}",
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
        code_location.contains("error=unmet_authentication_requirements"),
        "pending resume must reject unsupported acr_values with \
         error=unmet_authentication_requirements: {code_location}"
    );
    assert!(
        !code_location.contains("code="),
        "pending resume must NOT issue a code for an unsupported ACR: {code_location}"
    );
}
