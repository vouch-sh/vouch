// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Access-token audience enforcement at resource endpoints
//! (RFC 8707 / RFC 8725 §3.9 / RFC 9068).
//!
//! A token narrowed to an explicit resource (`aud != client_id`) is only
//! accepted at endpoints its audience covers; tokens with the default
//! audience (`aud == client_id`) remain deployment-wide. Authorization-server
//! endpoints (userinfo, introspection, revocation, token exchange) stay
//! audience-agnostic per their RFCs.

use super::helpers::*;

/// Narrowed token accepted at exactly the resource its audience names,
/// including sub-paths at segment boundaries.
#[tokio::test]
async fn test_narrowed_token_accepted_at_named_resource() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "aud-named@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let base_url = state.config().base_url.clone();
    let audience = format!("{base_url}/v1/keys");
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&base_url),
            audience: Some(&audience),
            ..Default::default()
        },
    )
    .await;

    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Token narrowed to /v1/keys must be accepted at /v1/keys: {body}"
    );
}

/// The issue's exact complaint: a token audience-scoped to resource A must
/// be rejected at resource B with a spec-conformant 401.
///
/// RFC 9700 §2.3 states the resource server's half of audience restriction:
/// "every resource server is obliged to verify, for every request, whether
/// the access token sent with that request was meant to be used for that
/// particular resource server. If it was not, the resource server MUST refuse
/// to serve the respective request."
#[tokio::test]
async fn test_narrowed_token_rejected_at_other_resource() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "aud-cross@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let base_url = state.config().base_url.clone();
    let audience = format!("{base_url}/api/v1/applications");
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&base_url),
            audience: Some(&audience),
            ..Default::default()
        },
    )
    .await;

    // Accepted at the named resource…
    let (status, body) = http_get(
        &app,
        "/api/v1/applications",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "named resource must accept: {body}");

    // …rejected everywhere else, with WWW-Authenticate carrying the
    // RFC 9728 protected-resource-metadata pointer.
    let response = http_get_full(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "cross-resource replay must be rejected: {}",
        response.body
    );
    assert!(
        response.body.contains("invalid_token"),
        "401 must use the invalid_token error code, got: {}",
        response.body
    );
    let www_auth = response
        .headers
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        www_auth.contains("resource_metadata="),
        "WWW-Authenticate must carry the RFC 9728 metadata pointer, got: {www_auth}"
    );
}

/// A segment-boundary sibling (`/v1/keysextra`-style) is not covered; only
/// true sub-paths of the audience are.
#[tokio::test]
async fn test_narrowed_token_covers_subpath_not_sibling() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "aud-subpath@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let base_url = state.config().base_url.clone();
    let audience = format!("{base_url}/v1/keys");
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&base_url),
            audience: Some(&audience),
            ..Default::default()
        },
    )
    .await;
    let auth = format!("Bearer {token}");

    // Sub-path of the audience: covered (route exists and requires a body,
    // so anything but 401 shows the audience gate passed).
    let (status, _body) = http_post_json(
        &app,
        "/v1/keys/register/start",
        "{}",
        &[("Authorization", &auth)],
    )
    .await;
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "sub-path of audience must pass the audience gate"
    );

    // Sibling resource: not covered.
    let (status, _body) = http_get(
        &app,
        "/v1/credentials/aws/token",
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "sibling resource must be rejected"
    );
}

/// An audience naming the deployment root (the RFC 9728 `resource={base_url}`
/// registration) covers every resource endpoint.
#[tokio::test]
async fn test_root_scoped_audience_accepted_everywhere() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "aud-root@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let base_url = state.config().base_url.clone();
    // Trailing slash: differs from client_id byte-wise (so the enforcement
    // path runs) but still names the deployment root.
    let audience = format!("{base_url}/");
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&base_url),
            audience: Some(&audience),
            ..Default::default()
        },
    )
    .await;
    let auth = format!("Bearer {token}");

    let (status, body) = http_get(&app, "/v1/keys", &[("Authorization", &auth)]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "root-scoped aud at /v1/keys: {body}"
    );

    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "root-scoped aud at /api/v1/applications: {body}"
    );
}

/// Tokens narrowed to an external resource server are useless at vouch's
/// own endpoints, regardless of the DB session being valid.
#[tokio::test]
async fn test_external_audience_rejected_at_resource_endpoints() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "aud-external@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let base_url = state.config().base_url.clone();
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&base_url),
            audience: Some("https://api.example.com"),
            ..Default::default()
        },
    )
    .await;
    let auth = format!("Bearer {token}");

    for path in [
        "/v1/keys",
        "/api/v1/applications",
        "/v1/credentials/aws/token",
    ] {
        let (status, body) = http_get(&app, path, &[("Authorization", &auth)]).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "externally narrowed token must be rejected at {path}: {body}"
        );
    }
}

/// Non-URI logical audiences (RFC 8693 `audience=kubernetes`-style) cannot
/// name this resource server.
#[tokio::test]
async fn test_logical_audience_rejected_at_resource_endpoints() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "aud-logical@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let base_url = state.config().base_url.clone();
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&base_url),
            audience: Some("kubernetes"),
            ..Default::default()
        },
    )
    .await;

    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "logical audience must be rejected at resource endpoints: {body}"
    );
}

/// Authorization-server endpoints stay audience-agnostic: userinfo accepts
/// tokens from any client (aud is not a resource there), and introspection
/// answers about the AS's own tokens regardless of audience.
#[tokio::test]
async fn test_external_audience_exempt_at_userinfo_and_introspect() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "aud-exempt@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    // Bind to the registered client so the RFC 7662 cross-client check passes.
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&client.client_id),
            audience: Some("https://api.example.com"),
            ..Default::default()
        },
    )
    .await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "userinfo must remain audience-agnostic: {body}"
    );

    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={token}"),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        response["active"], true,
        "introspection must remain audience-agnostic: {body}"
    );
    assert_eq!(
        response["aud"], "https://api.example.com",
        "introspection should echo the narrowed audience"
    );
}

/// Fast-path pin: tokens with the default audience (`aud == client_id`,
/// i.e. never resource-narrowed) are deployment-wide, exactly as before.
#[tokio::test]
async fn test_default_audience_token_accepted_everywhere() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "aud-default@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = format!("Bearer {token}");

    let (status, body) = http_get(&app, "/v1/keys", &[("Authorization", &auth)]).await;
    assert_eq!(status, StatusCode::OK, "default token at /v1/keys: {body}");

    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "default token at /api/v1/applications: {body}"
    );
}

/// A token narrowed via RFC 8693 token exchange (`resource` parameter) is
/// enforced identically to one narrowed at the authorization endpoint.
#[tokio::test]
async fn test_exchange_narrowed_token_enforced() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "aud-exchange@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    // Shared JWKS so the transparently-signed `/v1/*` requests verify against
    // this client's registration (the exchanged token carries its client_id).
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            jwks: TestJwks::Shared,
            ..Default::default()
        },
    )
    .await;

    let (subject_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let base_url = state.config().base_url.clone();
    let resource_uri = format!("{base_url}/v1/keys");
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={subject_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &resource={resource_uri}"
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "exchange should succeed: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let exchanged = response["access_token"].as_str().expect("access_token");
    let auth = format!("Bearer {exchanged}");

    let (status, body) = http_get(&app, "/v1/keys", &[("Authorization", &auth)]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exchanged token must work at its named resource: {body}"
    );

    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "exchanged token must be rejected at other resources: {body}"
    );
}

/// Cookie-only extraction paths (browser UI handlers pass an empty request
/// path) accept only deployment-root audiences; narrowed tokens smuggled
/// into the session cookie are rejected.
#[tokio::test]
async fn test_cookie_only_path_rejects_narrowed_token() {
    use axum_extra::extract::CookieJar;
    use axum_extra::extract::cookie::Cookie;

    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "aud-cookie@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let base_url = state.config().base_url.clone();

    let narrowed = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&base_url),
            audience: Some(&format!("{base_url}/v1/keys")),
            ..Default::default()
        },
    )
    .await;
    let jar = CookieJar::new().add(Cookie::new(vouch_common::SESSION_COOKIE_NAME, narrowed));
    let result = crate::handlers::extract_session_from_cookie(&state, &jar).await;
    assert!(
        result.is_err(),
        "narrowed token must be rejected on cookie-only paths"
    );

    let root_scoped = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&base_url),
            audience: Some(&format!("{base_url}/")),
            ..Default::default()
        },
    )
    .await;
    let jar = CookieJar::new().add(Cookie::new(vouch_common::SESSION_COOKIE_NAME, root_scoped));
    let result = crate::handlers::extract_session_from_cookie(&state, &jar).await;
    assert!(
        result.is_ok(),
        "deployment-root audience must be accepted on cookie-only paths: {result:?}"
    );
}
