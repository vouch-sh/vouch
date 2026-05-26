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

    // No token — RFC 6750 Section 3.1: Bearer challenge, no error
    // attributes. RFC 9728 §5.2 additionally appends
    // `resource_metadata="…"` via the middleware.
    let response = http_get_full(&app, "/oauth/userinfo", &[]).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 must include WWW-Authenticate header")
        .to_str()
        .expect("valid header value");
    assert!(www_auth.starts_with("Bearer"), "got: {www_auth}");
    assert!(
        !www_auth.contains("error="),
        "No-auth case must not include an error parameter, got: {www_auth}"
    );
    assert!(
        www_auth.contains("resource_metadata="),
        "RFC 9728 §5.2: resource_metadata must be present, got: {www_auth}"
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
async fn test_userinfo_no_email_when_scope_is_none() {
    // Regression for #390: an access token with `scope: None` (produced by
    // token exchange when the requested scope set has an empty intersection
    // with the available scopes) was previously interpreted by userinfo as
    // "full access" via a backward-compat fallback, returning the user's
    // email without the email scope. Must now return only `sub`.
    use crate::services::auth::{
        ClientAuthProof, CreateOAuthTokenParams, GrantProof, HardwareVerification,
        NoClientAuth, TokenIssuanceProof, create_oauth_access_token,
    };
    use secrecy::ExposeSecret;

    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "no-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let result = create_oauth_access_token(
        &state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: Some(&auth_id),
            client_id: &state.config().base_url,
            scope: None,
            dpop_jkt: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: Some(jiff::Timestamp::now().as_second()),
            hardware_verification: HardwareVerification::Verified,
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
        },
        TokenIssuanceProof {
            grant: GrantProof::TestingOnly,
            client_auth: ClientAuthProof::NoAuth(NoClientAuth::internal_endpoint()),
        },
    )
    .await
    .expect("issue token");
    let token = result.token.expose_secret().to_string();

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(userinfo.get("sub").is_some(), "sub must be present");
    assert!(
        userinfo.get("email").is_none(),
        "email must NOT be present when token has no granted scope; got: {body}"
    );
    assert!(
        userinfo.get("email_verified").is_none(),
        "email_verified must NOT be present when token has no granted scope"
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

    // No token — should get 401 with a Bearer challenge. RFC 9728
    // §5.2 additionally adds a `resource_metadata` parameter, so the
    // header is `Bearer resource_metadata="…"` (no `error=…` because
    // RFC 6750 §3.1 forbids an error when no auth info was sent).
    let response = http_get_full(&app, "/oauth/userinfo", &[]).await;
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
        "No-auth case must use Bearer scheme, got: {www_auth_str}"
    );
    assert!(
        !www_auth_str.contains("error="),
        "No-auth case MUST NOT include an error parameter (RFC 6750 §3.1), got: {www_auth_str}"
    );
    assert!(
        www_auth_str.contains("resource_metadata="),
        "RFC 9728 §5.2: resource_metadata must be present, got: {www_auth_str}"
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
    let v = www_auth.to_str().expect("valid header value");
    // RFC 6750 §3.1 + RFC 9728 §5.2: Bearer, no `error=…`, with
    // `resource_metadata=` attached by the middleware.
    assert!(v.starts_with("Bearer"), "got: {v}");
    assert!(!v.contains("error="), "got: {v}");
    assert!(v.contains("resource_metadata="), "got: {v}");
}

#[tokio::test]
async fn test_userinfo_get_body_ignored() {
    // RFC 6750 Section 2.2: Only POST body is accepted, not GET.
    // RFC 6750 Section 3.1: No auth info in headers → bare Bearer challenge, no body.
    let (app, _state) = test_app().await;

    // GET with no Authorization header returns a Bearer challenge
    // even if the query string carries an access_token (query params
    // are not a valid method). RFC 9728 §5.2 adds `resource_metadata`.
    let response = http_get_full(&app, "/oauth/userinfo?access_token=sometoken", &[]).await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 must include WWW-Authenticate header");
    let v = www_auth.to_str().expect("valid header value");
    assert!(v.starts_with("Bearer"), "got: {v}");
    assert!(!v.contains("error="), "got: {v}");
    assert!(v.contains("resource_metadata="), "got: {v}");
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
async fn test_userinfo_rs256_without_rsa_key_returns_500() {
    // OIDC Core Section 5.3.4: When a client requests RS256 signed userinfo but
    // the server has no RSA key configured, it must return 500 (not silently fall
    // back to ES256 or omit the signature). test_app() uses test_app_state() which
    // has oidc_rsa_key: None.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rs256-no-key@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Create a client with userinfo_signed_response_alg=ES256 first (valid),
    // then override it to RS256 directly via the DB to bypass registration checks.
    let (client_doc, client_id_str) = db::create_oauth_client(
        &state.store,
        &db::CreateOAuthClientParams {
            user_id: Some(&user.id),
            name: "RS256 No Key Test Client",
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
            userinfo_signed_response_alg: None,
            request_uris: None,
        },
    )
    .await
    .expect("Failed to create RS256-no-key test client");

    // Override userinfo_signed_response_alg to RS256 directly — registration would
    // reject RS256 when no RSA key is available, but direct DB write is needed here.
    db::set_oauth_client_userinfo_alg(&state.store, &client_doc.id, Some(db::JwsAlgorithm::Rs256))
        .await
        .expect("Failed to set RS256 alg");

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

    // Must return 500 — RS256 key is unavailable. Must NOT fall back to ES256.
    assert_eq!(
        response.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "RS256 userinfo without RSA key must return 500, got: {} — {}",
        response.status,
        response.body
    );

    let error: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        error["error"], "server_error",
        "Error code must be server_error"
    );
}

#[tokio::test]
async fn test_userinfo_unsupported_signing_algorithm_returns_500() {
    // OIDC Core Section 5.3.4 / build_signed_userinfo_response: When a client's
    // userinfo_signed_response_alg is set to an algorithm not supported by the
    // server (e.g. PS256, EdDSA), the endpoint must return 500 server_error.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "unsupported-alg@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let (client_doc, client_id_str) = db::create_oauth_client(
        &state.store,
        &db::CreateOAuthClientParams {
            user_id: Some(&user.id),
            name: "Unsupported Alg Test Client",
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
            userinfo_signed_response_alg: None,
            request_uris: None,
        },
    )
    .await
    .expect("Failed to create unsupported-alg test client");

    // Inject PS256 directly — registration correctly rejects it, but a client
    // record could have it from a future schema change or manual edit.
    db::set_oauth_client_userinfo_alg(&state.store, &client_doc.id, Some(db::JwsAlgorithm::Ps256))
        .await
        .expect("Failed to set PS256 alg");

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

    // Must return 500 — PS256 is not a supported userinfo signing algorithm.
    assert_eq!(
        response.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "Unsupported userinfo signing alg must return 500, got: {} — {}",
        response.status,
        response.body
    );

    let error: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        error["error"], "server_error",
        "Error code must be server_error"
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
