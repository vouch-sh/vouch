// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Access-token audience enforcement at resource endpoints
//! (RFC 8707 / RFC 8725 §3.9 / RFC 9068).
//!
//! A token narrowed to an explicit resource (`aud != client_id`) is only
//! accepted at endpoints its audience covers; tokens with the default
//! audience (`aud == client_id`) remain deployment-wide. Userinfo,
//! introspection, and revocation stay audience-agnostic per their RFCs; token
//! exchange accepts a narrowed subject but keeps it narrowed. The session
//! cookie holds only a browser session token.

use super::helpers::*;
use crate::db::User;
use crate::handlers;

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
    let result = handlers::extract_session_from_cookie(&state, &jar, test_arrival()).await;
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
    let result = handlers::extract_session_from_cookie(&state, &jar, test_arrival()).await;
    assert!(
        result.is_ok(),
        "deployment-root audience must be accepted on cookie-only paths: {:?}",
        result.as_ref().err()
    );
}

// ========================================================================
// The session cookie holds only a Vouch browser session
// ========================================================================
//
// RFC 8725 §3.9: "if the audience value is not present or not associated
// with the recipient, it MUST reject the JWT." The cookie's recipient is the
// Vouch UI itself, so only a token issued to this deployment and covering it
// whole stands in the cookie. Browser sign-in, enrollment, and certification
// all mint that shape; a token issued to an OAuth client, or narrowed to a
// resource, is not a sign-in to Vouch.

/// The three non-browser token shapes the cookie paths must refuse, each
/// minted verified and unbound so that only its client or audience differs
/// from a browser session.
async fn non_browser_tokens(
    state: &crate::AppState,
    user: &User,
    auth_id: &str,
) -> Vec<(&'static str, String)> {
    let mut tokens = Vec::new();
    for (label, client_id, audience) in [
        (
            "issued to a third-party client",
            Some("third-party-client"),
            None,
        ),
        (
            "narrowed to an external resource",
            None,
            Some("https://rs.example"),
        ),
    ] {
        let token = create_test_session_with(
            state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(auth_id),
                client_id,
                audience,
                ..Default::default()
            },
        )
        .await;
        tokens.push((label, token));
    }
    tokens
}

#[tokio::test]
async fn test_cookie_extractor_refuses_non_browser_session_tokens() {
    use axum_extra::extract::CookieJar;
    use axum_extra::extract::cookie::Cookie;

    let (_app, state) = test_app().await;
    let user = create_test_user(&state.store, "cookie-shape@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    for (label, token) in non_browser_tokens(&state, &user, &auth_id).await {
        let jar = CookieJar::new().add(Cookie::new(vouch_common::SESSION_COOKIE_NAME, token));
        let result = handlers::extract_session_from_cookie(&state, &jar, test_arrival()).await;
        assert!(
            result.is_err(),
            "a token {label} must not be a browser session"
        );
    }

    let browser = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let jar = CookieJar::new().add(Cookie::new(vouch_common::SESSION_COOKIE_NAME, browser));
    let result = handlers::extract_session_from_cookie(&state, &jar, test_arrival()).await;
    assert!(
        result.is_ok(),
        "a browser session token is accepted: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_cookie_ui_page_refuses_third_party_client_token() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "cookie-ui@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    for (label, token) in non_browser_tokens(&state, &user, &auth_id).await {
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
        let (status, body) = http_get(&app, "/applications", &[("Cookie", &cookie)]).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a token {label} must not open the user's Vouch UI: {body}"
        );
    }
}

#[tokio::test]
async fn test_authorize_session_check_refuses_non_browser_session_tokens() {
    use crate::services::oidc::authorization::{
        AuthorizationSessionState, check_session_for_authorization,
    };

    let (_app, state) = test_app().await;
    let user = create_test_user(&state.store, "authorize-shape@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    for (label, token) in non_browser_tokens(&state, &user, &auth_id).await {
        let session = check_session_for_authorization(&state, Some(&token), test_arrival())
            .await
            .expect("session check");
        assert!(
            matches!(session, AuthorizationSessionState::NeedsAuth),
            "a token {label} in the cookie must send the user to sign in"
        );
    }

    let browser = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let session = check_session_for_authorization(&state, Some(&browser), test_arrival())
        .await
        .expect("session check");
    assert!(
        matches!(session, AuthorizationSessionState::Authenticated { .. }),
        "a verified browser session authorizes without a sign-in"
    );
}

// ========================================================================
// The DPoP scheme at /v1 requires a DPoP-bound token
// ========================================================================
//
// RFC 9449 §7.1 states the checks for a DPoP-bound token and is silent on an
// unbound token presented with the DPoP scheme. `/oauth/userinfo` refuses
// it, and `/v1/*` does the same, so the scheme always means a checked proof.

#[tokio::test]
async fn test_v1_dpop_scheme_refuses_unbound_token() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "dpop-unbound@example.com").await;
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
    let dpop_auth = format!("DPoP {token}");

    for headers in [
        vec![("Authorization", dpop_auth.as_str()), ("DPoP", "not-a-jwt")],
        vec![("Authorization", dpop_auth.as_str())],
    ] {
        let (status, body) = http_get(&app, "/v1/keys", &headers).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert!(body.contains("not DPoP-bound"), "{body}");
    }

    let bearer = format!("Bearer {token}");
    let (status, body) = http_get(&app, "/v1/keys", &[("Authorization", &bearer)]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same token works as Bearer: {body}"
    );
}

// ========================================================================
// Token exchange keeps a narrowed subject narrowed
// ========================================================================
//
// A token narrowed to an external resource "can only be spent at the
// external service it names" (docs/src/operations/sessions.md). Exchange
// still accepts it, since re-scoping is its purpose, but the issued token
// may not name this server or the exchanging client, which every Vouch
// resource would accept. A refusal is `invalid_request` per RFC 8693
// §2.2.2: a subject token "unacceptable based on policy".

/// Exchange `subject` as `client`, with `extra` appended to the form.
async fn exchange_as(
    app: &axum::Router,
    client: &TestOAuthClient,
    subject: &str,
    extra: &str,
) -> (StatusCode, serde_json::Value) {
    let (status, body) = http_post_form(
        app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={subject}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token{extra}"
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;
    let json = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn test_exchange_keeps_narrowed_subject_narrowed() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "exchange-narrowed@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let other_owner = create_test_user(&state.store, "exchange-other@example.com").await;
    let client_b = create_test_client(
        &state.store,
        &other_owner.id,
        TestClientSpec {
            jwks: TestJwks::Shared,
            ..Default::default()
        },
    )
    .await;
    let subject = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some("client-a"),
            audience: Some("https://rs.example"),
            ..Default::default()
        },
    )
    .await;

    // No audience requested: the issued token keeps the subject's audience,
    // so Vouch's own resources still refuse it.
    let (status, json) = exchange_as(&app, &client_b, &subject, "").await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let issued = json["access_token"].as_str().expect("access_token");
    assert_eq!(decode_jwt_payload(issued)["aud"], "https://rs.example");
    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {issued}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // An audience Vouch would accept is refused.
    let base_url = state.config().base_url.clone();
    for audience in [
        client_b.client_id.to_string(),
        base_url.to_string(),
        format!("{base_url}/v1/keys"),
    ] {
        let (status, json) = exchange_as(
            &app,
            &client_b,
            &subject,
            &format!("&audience={}", urlencoding::encode(&audience)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "audience {audience}: {json}"
        );
        assert_eq!(json["error"], "invalid_request", "audience {audience}");
    }

    // Re-scoping to another external audience still works.
    let (status, json) = exchange_as(
        &app,
        &client_b,
        &subject,
        "&audience=https%3A%2F%2Fdownstream.example",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let issued = json["access_token"].as_str().expect("access_token");
    assert_eq!(
        decode_jwt_payload(issued)["aud"],
        "https://downstream.example"
    );
}

/// The narrowing rule governs issued access tokens only. An ID token
/// federates with an external relying party and takes the requested
/// audience as is, defaulting to the issuer, whatever the subject's `aud`.
#[tokio::test]
async fn test_id_token_exchange_ignores_subject_narrowing() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "exchange-narrowed-idt@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let other_owner = create_test_user(&state.store, "exchange-other-idt@example.com").await;
    let client_b = create_test_client(
        &state.store,
        &other_owner.id,
        TestClientSpec {
            jwks: TestJwks::Shared,
            ..Default::default()
        },
    )
    .await;
    let subject = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some("client-a"),
            audience: Some("https://rs.example"),
            ..Default::default()
        },
    )
    .await;
    let id_token = "&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token";

    let (status, json) = exchange_as(&app, &client_b, &subject, id_token).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let claims = decode_jwt_payload(json["access_token"].as_str().expect("id token"));
    assert_eq!(
        claims["aud"], claims["iss"],
        "the default audience is the issuer"
    );

    let (status, json) = exchange_as(
        &app,
        &client_b,
        &subject,
        &format!("{id_token}&audience={}", client_b.client_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let issued = json["access_token"].as_str().expect("id token");
    assert_eq!(
        decode_jwt_payload(issued)["aud"],
        client_b.client_id.as_str()
    );
}
