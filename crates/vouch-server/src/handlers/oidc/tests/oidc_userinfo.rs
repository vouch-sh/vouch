// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC Core 1.0 Section 5.3 — UserInfo + RFC 6750 WWW-Authenticate tests.

use super::helpers::*;

// ========================================================================
// UserInfo Endpoint Tests (OIDC Core 1.0 Section 5.3)
// ========================================================================

#[tokio::test]
async fn test_userinfo_requires_bearer_token() {
    // OIDC Core 1.0 Section 5.3.1: UserInfo requires bearer token
    let (app, _state) = test_app().await;

    // No token — RFC 6750 Section 3.1: bare Bearer challenge, no body
    let response = http_get_full(&app, "/oauth/userinfo", &[]).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 must include WWW-Authenticate header");
    assert_eq!(
        www_auth.to_str().expect("valid header value"),
        "Bearer",
        "No-auth case must return bare Bearer challenge with no error attributes"
    );

    // Invalid token format
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "NotBearer token")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_userinfo_returns_sub_claim() {
    // OIDC Core 1.0 Section 5.3.2: Response must include 'sub' claim
    let (app, state) = test_app().await;

    // Create a test user and OAuth access token session (includes email scope)
    let user = create_test_user(&state.store, "userinfo@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        userinfo.get("sub").is_some(),
        "UserInfo must contain 'sub' claim"
    );
    // OAuth access token created with ScopeSet::all() includes email scope
    assert_eq!(
        userinfo["email"].as_str(),
        Some("userinfo@example.com"),
        "Email should be present when email scope is granted"
    );
}

#[tokio::test]
async fn test_userinfo_invalid_token() {
    // Invalid token should return 401
    let (app, _state) = test_app().await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "Bearer invalid_token_here")],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_token");
}

// ========================================================================
// WWW-Authenticate Header Tests (RFC 6750 Section 3)
// ========================================================================

#[tokio::test]
async fn test_userinfo_401_includes_www_authenticate() {
    // RFC 6750 Section 3: 401 responses MUST include WWW-Authenticate header.
    // RFC 6750 Section 3.1: When no auth info is present, the challenge MUST NOT
    // include an error code — return a bare "Bearer" challenge.
    let (app, _state) = test_app().await;

    // No token — should get 401 with bare WWW-Authenticate: Bearer
    let response = http_get_full(&app, "/oauth/userinfo", &[]).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 response must include WWW-Authenticate header");
    let www_auth_str = www_auth
        .to_str()
        .expect("WWW-Authenticate should be a string");
    assert_eq!(
        www_auth_str, "Bearer",
        "No-auth case must return bare Bearer challenge without error attributes, got: {}",
        www_auth_str
    );
}

#[tokio::test]
async fn test_userinfo_invalid_token_includes_www_authenticate() {
    // RFC 6750 Section 3.1: invalid_token error with WWW-Authenticate
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "Bearer invalid_token_here")],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 response must include WWW-Authenticate header");
    let www_auth_str = www_auth
        .to_str()
        .expect("WWW-Authenticate should be a string");
    assert!(
        www_auth_str.contains("invalid_token"),
        "WWW-Authenticate should include invalid_token error, got: {}",
        www_auth_str
    );
}

#[tokio::test]
async fn test_userinfo_unsupported_scheme_includes_www_authenticate() {
    // RFC 6750 Section 3: Unsupported auth scheme should return 401 with WWW-Authenticate
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "NotBearer token")],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 response must include WWW-Authenticate header");
    let www_auth_str = www_auth
        .to_str()
        .expect("WWW-Authenticate should be a string");
    assert!(
        www_auth_str.starts_with("Bearer"),
        "WWW-Authenticate should use Bearer scheme"
    );
}

// ========================================================================
// POST Body Access Token Tests (RFC 6750 Section 2.2)
// ========================================================================

#[tokio::test]
async fn test_userinfo_post_body_access_token() {
    // RFC 6750 Section 2.2: Access token in POST body (Bearer only)
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "postbody@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/userinfo",
        &format!("access_token={token}"),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(userinfo.get("sub").is_some(), "Must contain 'sub' claim");
    assert_eq!(userinfo["email"].as_str(), Some("postbody@example.com"));
}

#[tokio::test]
async fn test_userinfo_post_body_without_token() {
    // RFC 6750 Section 2.2: POST with empty body and no Authorization header → 401.
    // RFC 6750 Section 3.1: No auth info present → bare Bearer challenge, no body.
    let (app, _state) = test_app().await;

    let response = http_post_form_full(&app, "/oauth/userinfo", "", &[]).await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 must include WWW-Authenticate header");
    assert_eq!(
        www_auth.to_str().expect("valid header value"),
        "Bearer",
        "No-auth POST must return bare Bearer challenge"
    );
}

#[tokio::test]
async fn test_userinfo_get_body_ignored() {
    // RFC 6750 Section 2.2: Only POST body is accepted, not GET.
    // RFC 6750 Section 3.1: No auth info in headers → bare Bearer challenge, no body.
    let (app, _state) = test_app().await;

    // GET with no Authorization header returns bare Bearer challenge even if
    // query string carries an access_token (query params are not a valid method)
    let response = http_get_full(&app, "/oauth/userinfo?access_token=sometoken", &[]).await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 must include WWW-Authenticate header");
    assert_eq!(
        www_auth.to_str().expect("valid header value"),
        "Bearer",
        "No-auth GET must return bare Bearer challenge"
    );
}

#[tokio::test]
async fn test_userinfo_post_body_with_auth_header() {
    // RFC 6750 Section 2.3: When Authorization header is present, body token is ignored
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authheader@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Authorization header takes precedence; body token is ignored
    let (status, body) = http_post_form(
        &app,
        "/oauth/userinfo",
        "access_token=bogus_body_token",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(userinfo["email"].as_str(), Some("authheader@example.com"));
}

// ========================================================================
// Signed UserInfo (OIDC Core Section 5.3.4)
// ========================================================================

#[tokio::test]
async fn test_userinfo_plain_json_when_no_signed_alg_configured() {
    // OIDC Core Section 5.3.4: Default (no userinfo_signed_response_alg) returns
    // plain application/json.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "plain-userinfo@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    // Token bound to this client (client has no userinfo_signed_response_alg)
    let token =
        create_test_session_for_client(&state, &user.id, &user.email, &auth_id, &client.client_id)
            .await;

    let response = http_request_full(
        &app,
        "GET",
        "/oauth/userinfo",
        None,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    let content_type = response
        .headers
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "Default userinfo must return application/json, got: {content_type}"
    );
    // Body must parse as JSON with a sub claim
    let userinfo: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert!(userinfo.get("sub").is_some(), "userinfo must contain sub");
}

#[tokio::test]
async fn test_userinfo_signed_jwt_when_es256_configured() {
    // OIDC Core Section 5.3.4: When userinfo_signed_response_alg=ES256, the endpoint
    // returns application/jwt with a signed JWT containing iss, sub, aud, iat, exp.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "signed-userinfo@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Create a client with userinfo_signed_response_alg=ES256
    let (client_doc, client_id_str) = db::create_oauth_client(
        &state.store,
        &db::CreateOAuthClientParams {
            user_id: Some(&user.id),
            name: "Signed UserInfo Test Client",
            description: None,
            application_type: db::OAuthClientType::Web,
            redirect_uris: &["https://example.com/callback".to_string()],
            access_scope: db::AccessScope::Public,
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: db::RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: db::JwsAlgorithm::Es256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: Some(db::JwsAlgorithm::Es256),
            request_uris: None,
        },
    )
    .await
    .expect("Failed to create signed-userinfo test client");
    let _ = client_doc;

    // Token bound to this client so client_id is populated in the access token
    let token =
        create_test_session_for_client(&state, &user.id, &user.email, &auth_id, &client_id_str)
            .await;

    let response = http_request_full(
        &app,
        "GET",
        "/oauth/userinfo",
        None,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK, "body: {}", response.body);

    let content_type = response
        .headers
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        content_type, "application/jwt",
        "Signed userinfo must return application/jwt, got: {content_type}"
    );

    // Decode the JWT payload and verify required claims
    let jwt_claims = decode_jwt_payload(&response.body);
    assert!(
        jwt_claims.get("iss").is_some(),
        "Signed userinfo JWT must contain iss"
    );
    assert!(
        jwt_claims.get("sub").is_some(),
        "Signed userinfo JWT must contain sub"
    );
    assert!(
        jwt_claims.get("aud").is_some(),
        "Signed userinfo JWT must contain aud"
    );
    assert!(
        jwt_claims.get("iat").is_some(),
        "Signed userinfo JWT must contain iat"
    );
    assert!(
        jwt_claims.get("exp").is_some(),
        "Signed userinfo JWT must contain exp"
    );
    // aud must identify the client
    assert_eq!(
        jwt_claims["aud"].as_str(),
        Some(client_id_str.as_str()),
        "Signed userinfo aud must equal the client_id"
    );
}

#[tokio::test]
async fn test_id_token_does_not_contain_hardware_claims() {
    // OIDC compliance: standard OIDC id_tokens must not contain hardware_verified
    // or hardware_aaguid after the compliance update.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "hw-claims-idtoken@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue an actual authorization code flow to get a real id_token
    let (_access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let id_token_claims = decode_jwt_payload(&id_token);

    assert!(
        id_token_claims.get("hardware_verified").is_none(),
        "OIDC id_token must not contain hardware_verified (OIDC conformance)"
    );
    assert!(
        id_token_claims.get("hardware_aaguid").is_none(),
        "OIDC id_token must not contain hardware_aaguid (OIDC conformance)"
    );
}
