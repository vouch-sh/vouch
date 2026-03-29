// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9126 — OAuth 2.0 Pushed Authorization Requests (PAR) tests.
//!
//! Tests for the PAR endpoint (`POST /oauth/par`), `request_uri` resolution
//! at the authorization endpoint, discovery metadata, single-use enforcement,
//! client binding, and parameter validation.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc9126>

use super::helpers::*;

// ========================================================================
// RFC 9126 Section 5 — Discovery Metadata
// ========================================================================

#[tokio::test]
async fn test_rfc9126_discovery_includes_par_endpoint() {
    // RFC 9126 Section 5: The discovery document MUST include
    // `pushed_authorization_request_endpoint`.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        doc["pushed_authorization_request_endpoint"].is_string(),
        "Discovery must include pushed_authorization_request_endpoint"
    );

    let par_endpoint = doc["pushed_authorization_request_endpoint"]
        .as_str()
        .unwrap();
    assert!(
        par_endpoint.ends_with("/oauth/par"),
        "PAR endpoint should end with /oauth/par, got: {par_endpoint}"
    );
}

#[tokio::test]
async fn test_rfc9126_discovery_includes_require_par_field() {
    // RFC 9126 Section 5: The discovery document MUST include
    // `require_pushed_authorization_requests`.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        doc["require_pushed_authorization_requests"].is_boolean(),
        "Discovery must include require_pushed_authorization_requests"
    );
    assert_eq!(
        doc["require_pushed_authorization_requests"], false,
        "PAR should not be required by default"
    );
}

#[tokio::test]
async fn test_rfc9126_discovery_par_endpoint_matches_issuer() {
    // The PAR endpoint URL should be rooted at the issuer URL.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let issuer = doc["issuer"].as_str().unwrap();
    let par_endpoint = doc["pushed_authorization_request_endpoint"]
        .as_str()
        .unwrap();

    assert!(
        par_endpoint.starts_with(issuer),
        "PAR endpoint {par_endpoint} should start with issuer {issuer}"
    );
}

// ========================================================================
// RFC 9126 Section 2 — Client Authentication
// ========================================================================

#[tokio::test]
async fn test_rfc9126_par_requires_client_authentication() {
    // RFC 9126 Section 2: Client authentication is REQUIRED.
    let (app, _state) = test_app().await;

    let body = "response_type=code\
                &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
                &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
                &code_challenge_method=S256";

    let (status, response_body) = http_post_form(&app, "/oauth/par", body, &[]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "PAR without client auth should return 401: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn test_rfc9126_par_accepts_basic_auth() {
    // RFC 9126 Section 2: client_secret_basic authentication.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-basic@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let body = format!(
        "response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &code_challenge={}\
         &code_challenge_method=S256\
         &scope=openid",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
        challenge,
    );

    let auth_header = client.basic_auth_header();

    let (status, response_body) = http_post_form(
        &app,
        "/oauth/par",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "PAR with valid Basic auth should return 201: {response_body}"
    );

    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert!(json["request_uri"].is_string());
    assert!(json["expires_in"].is_number());
}

#[tokio::test]
async fn test_rfc9126_par_accepts_post_body_auth() {
    // RFC 9126 Section 2: client_secret_post authentication.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-post@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let body = format!(
        "response_type=code\
         &client_id={}\
         &client_secret={}\
         &redirect_uri={}\
         &code_challenge={}\
         &code_challenge_method=S256\
         &scope=openid",
        client.client_id,
        urlencoding::encode(&client.client_secret),
        urlencoding::encode("https://example.com/callback"),
        challenge,
    );

    let (status, response_body) = http_post_form(&app, "/oauth/par", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "PAR with valid post body auth should return 201: {response_body}"
    );
}

#[tokio::test]
async fn test_rfc9126_par_rejects_invalid_client_secret() {
    // RFC 9126 Section 2: Invalid client credentials MUST be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-badsecret@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let wrong_creds = format!("{}:wrong-secret", client.client_id);
    let encoded = base64::engine::general_purpose::STANDARD.encode(wrong_creds.as_bytes());
    let bad_auth = format!("Basic {encoded}");

    let body = format!(
        "response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
         &code_challenge_method=S256",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
    );

    let (status, response_body) =
        http_post_form(&app, "/oauth/par", &body, &[("Authorization", &bad_auth)]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "PAR with bad secret should return 401: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn test_rfc9126_par_rejects_unknown_client() {
    // RFC 9126 Section 2: Unknown client_id MUST be rejected.
    let (app, _state) = test_app().await;

    let fake_creds = "nonexistent-client:some-secret";
    let encoded = base64::engine::general_purpose::STANDARD.encode(fake_creds.as_bytes());
    let bad_auth = format!("Basic {encoded}");

    let body = "client_id=nonexistent-client\
                &response_type=code\
                &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
                &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
                &code_challenge_method=S256";

    let (status, _body) =
        http_post_form(&app, "/oauth/par", body, &[("Authorization", &bad_auth)]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "PAR with unknown client should return 401"
    );
}

// ========================================================================
// RFC 9126 Section 2.2 — Response Format
// ========================================================================

#[tokio::test]
async fn test_rfc9126_par_returns_201_created() {
    // RFC 9126 Section 2.2: Successful PAR returns 201 Created.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-201@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let body = format!(
        "response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &code_challenge={}\
         &code_challenge_method=S256\
         &scope=openid",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
        challenge,
    );

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/par",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn test_rfc9126_par_returns_request_uri_with_correct_prefix() {
    // RFC 9126 Section 2.2: The request_uri MUST start with
    // "urn:ietf:params:oauth:request_uri:".
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-prefix@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let body = format!(
        "response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &code_challenge={}\
         &code_challenge_method=S256\
         &scope=openid",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
        challenge,
    );

    let auth_header = client.basic_auth_header();
    let (status, response_body) = http_post_form(
        &app,
        "/oauth/par",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    let request_uri = json["request_uri"].as_str().unwrap();

    assert!(
        request_uri.starts_with("urn:ietf:params:oauth:request_uri:"),
        "request_uri must start with urn:ietf:params:oauth:request_uri:, got: {request_uri}"
    );
}

#[tokio::test]
async fn test_rfc9126_par_returns_expires_in() {
    // RFC 9126 Section 2.2: The response MUST include expires_in.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-expires@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let body = format!(
        "response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &code_challenge={}\
         &code_challenge_method=S256\
         &scope=openid",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
        challenge,
    );

    let auth_header = client.basic_auth_header();
    let (status, response_body) = http_post_form(
        &app,
        "/oauth/par",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");

    let expires_in = json["expires_in"]
        .as_i64()
        .expect("expires_in must be a number");
    assert!(
        expires_in > 0 && expires_in <= 600,
        "expires_in should be between 1 and 600 seconds, got: {expires_in}"
    );
}

#[tokio::test]
async fn test_rfc9126_par_generates_unique_request_uris() {
    // Each PAR request MUST generate a unique request_uri.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-unique@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let auth_header = client.basic_auth_header();

    let body = format!(
        "response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &code_challenge={}\
         &code_challenge_method=S256\
         &scope=openid",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
        challenge,
    );

    let (_, resp1) = http_post_form(
        &app,
        "/oauth/par",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;
    let (_, resp2) = http_post_form(
        &app,
        "/oauth/par",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;

    let json1: serde_json::Value = serde_json::from_str(&resp1).unwrap();
    let json2: serde_json::Value = serde_json::from_str(&resp2).unwrap();

    assert_ne!(
        json1["request_uri"], json2["request_uri"],
        "Each PAR request should produce a unique request_uri"
    );
}

// ========================================================================
// RFC 9126 Section 2.1 — Parameter Validation
// ========================================================================

#[tokio::test]
async fn test_rfc9126_par_rejects_request_containing_request_uri() {
    // RFC 9126 Section 2.1: The PAR request MUST NOT contain request_uri.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-recursive@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let body = format!(
        "response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
         &code_challenge_method=S256\
         &request_uri=urn:ietf:params:oauth:request_uri:some-previous-uri",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
    );

    let auth_header = client.basic_auth_header();
    let (status, response_body) = http_post_form(
        &app,
        "/oauth/par",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "PAR with request_uri should be rejected: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn test_rfc9126_par_rejects_missing_response_type() {
    // response_type is required at the authorization endpoint per RFC 6749.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-nort@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let body = format!(
        "client_id={}\
         &redirect_uri={}\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
         &code_challenge_method=S256",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
    );

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/par",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "PAR without response_type should be rejected"
    );
}

#[tokio::test]
async fn test_rfc9126_par_allows_missing_pkce_for_confidential_client() {
    // Confidential clients (client_secret_basic) do not require PKCE at PAR.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-nopkce@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let body = format!(
        "response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &scope=openid",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
    );

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/par",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Confidential client PAR without PKCE should succeed"
    );
}

#[tokio::test]
async fn test_rfc9126_par_rejects_unregistered_redirect_uri() {
    // redirect_uri must be registered for the client.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-baduri@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let body = format!(
        "response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &code_challenge={}\
         &code_challenge_method=S256",
        client.client_id,
        urlencoding::encode("https://evil.com/callback"),
        challenge,
    );

    let auth_header = client.basic_auth_header();
    let (status, response_body) = http_post_form(
        &app,
        "/oauth/par",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "PAR with unregistered redirect_uri should be rejected: {response_body}"
    );
}

// ========================================================================
// RFC 9126 Section 4 — Authorization Endpoint with request_uri
// ========================================================================

/// Helper: create a PAR request and return the request_uri.
async fn create_par_request(app: &axum::Router, client: &TestOAuthClient) -> String {
    create_par_request_with_prompt(app, client, None).await
}

/// Helper: create a PAR request with an optional `prompt` parameter, returning the request_uri.
async fn create_par_request_with_prompt(
    app: &axum::Router,
    client: &TestOAuthClient,
    prompt: Option<&str>,
) -> String {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let prompt_param = prompt
        .map(|p| format!("&prompt={}", urlencoding::encode(p)))
        .unwrap_or_default();

    let body = format!(
        "response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &code_challenge={}\
         &code_challenge_method=S256\
         &scope=openid{prompt_param}",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
        challenge,
    );

    let auth_header = client.basic_auth_header();
    let (status, response_body) =
        http_post_form(app, "/oauth/par", &body, &[("Authorization", &auth_header)]).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "PAR creation failed: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).unwrap();
    json["request_uri"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn test_rfc9126_authorize_resolves_request_uri() {
    // RFC 9126 Section 4: The authorization endpoint resolves
    // request_uri to the stored PAR parameters.
    // Use prompt=none so the existing session auto-authorizes without a login redirect.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-resolve@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let request_uri = create_par_request_with_prompt(&app, &client, Some("none")).await;

    // Use request_uri at the authorization endpoint
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client.client_id,
            urlencoding::encode(&request_uri),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Should redirect with authorization code
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Authorization with request_uri should succeed, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .unwrap();

    assert!(
        location.contains("code="),
        "Successful response must include authorization code: {location}"
    );
}

#[tokio::test]
async fn test_rfc9126_authorize_rejects_unknown_request_uri() {
    // RFC 9126 Section 4: An unknown or invalid request_uri MUST be rejected.
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id=some-client&request_uri={}",
            urlencoding::encode("urn:ietf:params:oauth:request_uri:nonexistent"),
        ),
        &[],
    )
    .await;

    // Should return an error page (200 with error HTML, not a redirect)
    assert_eq!(
        response.status,
        StatusCode::OK,
        "Unknown request_uri should return error page"
    );
    assert!(
        response.body.contains("expired")
            || response.body.contains("Invalid")
            || response.body.contains("error"),
        "Response should indicate the request_uri is invalid"
    );
}

#[tokio::test]
async fn test_rfc9126_authorize_requires_client_id_with_request_uri() {
    // RFC 9126 Section 4: client_id is REQUIRED alongside request_uri.
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?request_uri={}",
            urlencoding::encode("urn:ietf:params:oauth:request_uri:something"),
        ),
        &[],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "Missing client_id with request_uri should return error page"
    );
    assert!(
        response.body.contains("client_id") || response.body.contains("Invalid"),
        "Response should mention client_id is required"
    );
}

// ========================================================================
// RFC 9126 Section 2.3 — Single-Use Enforcement
// ========================================================================

#[tokio::test]
async fn test_rfc9126_request_uri_is_single_use() {
    // RFC 9126 Section 2.3: request_uri MUST be consumed on first use (code issued).
    // Use prompt=none so the first visit auto-authorizes and issues a code, consuming
    // the PAR. The second visit must then return an error page.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-single@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let request_uri = create_par_request_with_prompt(&app, &client, Some("none")).await;

    // First use should succeed
    let response1 = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client.client_id,
            urlencoding::encode(&request_uri),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response1.status == StatusCode::FOUND || response1.status == StatusCode::SEE_OTHER,
        "First use should succeed, got: {}",
        response1.status
    );

    // Second use should fail
    let response2 = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client.client_id,
            urlencoding::encode(&request_uri),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert_eq!(
        response2.status,
        StatusCode::OK,
        "Second use of request_uri should return error page"
    );
    assert!(
        response2.body.contains("expired")
            || response2.body.contains("Invalid")
            || response2.body.contains("error"),
        "Response should indicate the request_uri was already consumed"
    );
}

// ========================================================================
// RFC 9126 Section 2.3 — Client Binding
// ========================================================================

#[tokio::test]
async fn test_rfc9126_request_uri_is_client_bound() {
    // RFC 9126 Section 2.3: request_uri is bound to the client_id that
    // created it. A different client MUST NOT be able to use it.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-binding@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client_a = create_test_oauth_client(&state.store, &user.id).await;
    let client_b = create_test_oauth_client(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Create PAR with client_a
    let request_uri = create_par_request(&app, &client_a).await;

    // Try to use it with client_b — should fail
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client_b.client_id,
            urlencoding::encode(&request_uri),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "Wrong client should get error page"
    );
    assert!(
        response.body.contains("expired")
            || response.body.contains("Invalid")
            || response.body.contains("error"),
        "Response should indicate the request_uri is invalid for this client"
    );
}

#[tokio::test]
async fn test_rfc9126_client_binding_failure_does_not_consume() {
    // A failed client binding attempt should NOT consume the request_uri.
    // The original client should still be able to use it.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-nocon@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client_a = create_test_oauth_client(&state.store, &user.id).await;
    let client_b = create_test_oauth_client(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let request_uri = create_par_request(&app, &client_a).await;

    // Attempt with wrong client — should fail but not consume
    let _response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client_b.client_id,
            urlencoding::encode(&request_uri),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Now use with the correct client — should succeed
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client_a.client_id,
            urlencoding::encode(&request_uri),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Correct client should still be able to use the request_uri after wrong-client attempt, got: {}",
        response.status
    );
}
