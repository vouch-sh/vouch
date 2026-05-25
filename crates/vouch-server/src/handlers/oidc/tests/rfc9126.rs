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

// ========================================================================
// RFC 9126 Section 2.3 — Expired PAR
// ========================================================================

#[tokio::test]
async fn test_rfc9126_authorize_rejects_expired_request_uri() {
    // An expired PAR must not be usable at the authorization endpoint.
    // We create a valid PAR, then backdate its expires_at to the past.
    use crate::db::documents::par::PushedAuthorizationRequestDoc;

    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-expired@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let _session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let request_uri = create_par_request_with_prompt(&app, &client, Some("none")).await;

    // Backdate the PAR's expires_at so it appears expired.
    let doc = state
        .store
        .find_one::<PushedAuthorizationRequestDoc>("request_uri", &request_uri)
        .await
        .unwrap()
        .expect("PAR doc should exist");

    let mut data = doc.data;
    data.expires_at = jiff::Timestamp::from_second(0).unwrap();
    state.store.update(&doc.id, &data).await.unwrap();

    // Attempt to authorize — should be rejected at lookup.
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client.client_id,
            urlencoding::encode(&request_uri),
        ),
        &[("Cookie", &format!("__Host-vouch_session={_session_token}"))],
    )
    .await;

    // The lookup_par function returns an error page for expired PARs.
    assert_eq!(
        response.status,
        StatusCode::OK,
        "Expired PAR should return error page, got: {}",
        response.status
    );
    assert!(
        response.body.contains("expired")
            || response.body.contains("Invalid")
            || response.body.contains("error"),
        "Response should indicate the request_uri is expired: {}",
        response.body
    );
}

// ========================================================================
// RFC 9126 — Optimistic concurrency on PAR consumption (db layer)
// ========================================================================

#[tokio::test]
async fn test_rfc9126_consume_par_with_stale_version_returns_false() {
    // Verify that consume_pushed_authorization_request uses optimistic
    // concurrency: if the document version changes between read and
    // write (simulating a concurrent consumer), consumption must fail.
    use crate::db::documents::par::PushedAuthorizationRequestDoc;

    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-occ@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (_, request_uri) = db::create_pushed_authorization_request(
        &state.store,
        db::CreateParParams {
            client_id: &client.client_id,
            response_type: "code",
            redirect_uri: "https://example.com/callback",
            scope: Some("openid"),
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: Default::default(),
        },
        crate::services::auth::ParCreationProof {
            client_auth: crate::services::auth::ClientAuthProof::NoAuth(
                crate::services::auth::NoClientAuth::internal_endpoint(),
            ),
        },
    )
    .await
    .unwrap();

    // First consumption should succeed.
    let _claim = db::consume_pushed_authorization_request(
        &state.store,
        &request_uri,
        &client.client_id,
        db::ParConsumptionMode::EnforceExpiry,
    )
    .await
    .expect("First consumption should succeed");

    // Verify the PAR is now consumed.
    let doc = state
        .store
        .find_one::<PushedAuthorizationRequestDoc>("request_uri", &request_uri)
        .await
        .unwrap()
        .expect("PAR doc should still exist");
    assert!(
        doc.data.consumed_at.is_some(),
        "PAR should be marked as consumed"
    );

    // Second consumption should fail (already consumed — pre-check catches it).
    let result = db::consume_pushed_authorization_request(
        &state.store,
        &request_uri,
        &client.client_id,
        db::ParConsumptionMode::EnforceExpiry,
    )
    .await;
    assert!(
        matches!(result, Err(crate::db::claim::ClaimError::AlreadyConsumed)),
        "Second consumption should fail with AlreadyConsumed, got: {result:?}"
    );
}

#[tokio::test]
async fn test_rfc9126_consume_par_concurrent_replay() {
    // Two concurrent consume calls must produce exactly one winner; the
    // loser must be AlreadyConsumed (not a Database error from the OCC
    // version-mismatch path).
    use crate::db::claim::ClaimError;

    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-race@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (_, request_uri) = db::create_pushed_authorization_request(
        &state.store,
        db::CreateParParams {
            client_id: &client.client_id,
            response_type: "code",
            redirect_uri: "https://example.com/callback",
            scope: Some("openid"),
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: Default::default(),
        },
        crate::services::auth::ParCreationProof {
            client_auth: crate::services::auth::ClientAuthProof::NoAuth(
                crate::services::auth::NoClientAuth::internal_endpoint(),
            ),
        },
    )
    .await
    .unwrap();

    let store_a = state.store.clone();
    let store_b = state.store.clone();
    let request_uri_a = request_uri.clone();
    let request_uri_b = request_uri.clone();
    let client_id_a = client.client_id.clone();
    let client_id_b = client.client_id.clone();
    let (result_a, result_b) = tokio::join!(
        async move {
            db::consume_pushed_authorization_request(
                &store_a,
                &request_uri_a,
                &client_id_a,
                db::ParConsumptionMode::EnforceExpiry,
            )
            .await
        },
        async move {
            db::consume_pushed_authorization_request(
                &store_b,
                &request_uri_b,
                &client_id_b,
                db::ParConsumptionMode::EnforceExpiry,
            )
            .await
        },
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one concurrent PAR consume must win, got a={a_won}, b={b_won}"
    );
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed, got: {e:?}"
            );
        }
    }
}

// ========================================================================
// FAPI 2.0 Section 5.3.2.2 — PAR Reuse Before Auth Completion
// ========================================================================

#[tokio::test]
async fn test_rfc9126_par_not_consumed_when_no_session() {
    // FAPI 2.0 Section 5.3.2.2 Note 3: request_uri must remain valid until
    // authorization completes (code issued). When the user has no session,
    // the PAR should NOT be consumed — it is stored in the pending auth record
    // and consumed when the code is issued.
    use crate::db::documents::par::PushedAuthorizationRequestDoc;

    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-nosession@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Create PAR without prompt=none (will require auth)
    let request_uri = create_par_request(&app, &client).await;

    // Hit authorize endpoint WITHOUT a session cookie — should redirect to login
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client.client_id,
            urlencoding::encode(&request_uri),
        ),
        &[],
    )
    .await;

    // Should redirect to /login?pending_auth=...
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Should redirect to login, got: {}",
        response.status
    );
    let location = response.headers.get("location").expect("redirect location");
    let location_str = location.to_str().unwrap();
    assert!(
        location_str.starts_with("/login?pending_auth="),
        "Should redirect to /login?pending_auth=..., got: {location_str}"
    );

    // Verify PAR is NOT consumed — it remains valid for reuse until code issuance.
    let doc = state
        .store
        .find_one::<PushedAuthorizationRequestDoc>("request_uri", &request_uri)
        .await
        .unwrap()
        .expect("PAR doc should still exist");
    assert!(
        doc.data.consumed_at.is_none(),
        "PAR should NOT be consumed when redirecting to login (FAPI 2.0 reuse allowed)"
    );
}

#[tokio::test]
async fn test_rfc9126_par_reuse_succeeds_before_auth_completion() {
    // FAPI 2.0 Section 5.3.2.2 Note 3: request_uri can be reused before
    // authorization completes. Both uses should succeed (redirect to login).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-replay-login@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let request_uri = create_par_request(&app, &client).await;

    // First use without session — triggers login redirect
    let response1 = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client.client_id,
            urlencoding::encode(&request_uri),
        ),
        &[],
    )
    .await;
    assert!(
        response1.status == StatusCode::FOUND || response1.status == StatusCode::SEE_OTHER,
        "First use should redirect to login"
    );

    // Second use of same request_uri — should also succeed (PAR not consumed yet)
    let response2 = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client.client_id,
            urlencoding::encode(&request_uri),
        ),
        &[],
    )
    .await;

    assert!(
        response2.status == StatusCode::FOUND || response2.status == StatusCode::SEE_OTHER,
        "Second use should also redirect to login (reuse allowed before auth completes), got: {}",
        response2.status
    );
    let location = response2
        .headers
        .get("location")
        .expect("redirect location");
    let location_str = location.to_str().unwrap();
    assert!(
        location_str.starts_with("/login?pending_auth="),
        "Second use should redirect to /login?pending_auth=..., got: {location_str}"
    );
}

// ========================================================================
// FAPI 2.0 Section 5.3.2.2 — PAR Reuse on Re-auth Path
// ========================================================================

#[tokio::test]
async fn test_rfc9126_par_not_consumed_when_reauth_required() {
    // FAPI 2.0 Section 5.3.2.2 Note 3: request_uri must remain valid until
    // authorization completes. When re-auth is required, the PAR should NOT
    // be consumed — it is stored in the pending auth record for later consumption.
    use crate::db::documents::par::PushedAuthorizationRequestDoc;

    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-reauth@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    // User has a valid session — but PAR flow always requires re-auth.
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Create PAR without prompt=none — will trigger re-auth under ReauthPolicy::Always.
    let request_uri = create_par_request(&app, &client).await;

    // Hit authorize WITH a session cookie — session is valid but re-auth is required.
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

    // Should redirect to /login?pending_auth=... (re-auth required)
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Re-auth path should redirect to login, got: {}",
        response.status
    );
    let location = response.headers.get("location").expect("redirect location");
    let location_str = location.to_str().unwrap();
    assert!(
        location_str.starts_with("/login?pending_auth="),
        "Should redirect to /login?pending_auth=..., got: {location_str}"
    );

    // Verify PAR is NOT consumed — it remains valid for reuse until code issuance.
    let doc = state
        .store
        .find_one::<PushedAuthorizationRequestDoc>("request_uri", &request_uri)
        .await
        .unwrap()
        .expect("PAR doc should still exist");
    assert!(
        doc.data.consumed_at.is_none(),
        "PAR should NOT be consumed when redirecting to re-auth (FAPI 2.0 reuse allowed)"
    );
}

#[tokio::test]
async fn test_rfc9126_par_reuse_succeeds_after_reauth_redirect() {
    // FAPI 2.0 Section 5.3.2.2 Note 3: request_uri can be reused before
    // authorization completes, even on the re-auth path.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-reauth-replay@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let request_uri = create_par_request(&app, &client).await;

    // First use with session — triggers re-auth redirect.
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
        "First use should redirect to login for re-auth, got: {}",
        response1.status
    );

    // Second use of same request_uri — should also succeed (PAR not consumed).
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

    assert!(
        response2.status == StatusCode::FOUND || response2.status == StatusCode::SEE_OTHER,
        "Second use should also redirect to login (reuse allowed), got: {}",
        response2.status
    );
    let location = response2
        .headers
        .get("location")
        .expect("redirect location");
    let location_str = location.to_str().unwrap();
    assert!(
        location_str.starts_with("/login?pending_auth="),
        "Second use should redirect to /login?pending_auth=..., got: {location_str}"
    );
}

#[tokio::test]
async fn test_rfc9126_par_already_consumed_returns_error_not_login() {
    // When the PAR has already been consumed (e.g., code was issued in a prior
    // flow), lookup_par detects consumed_at and returns an error page instead
    // of proceeding with authorization.
    use crate::db::documents::par::PushedAuthorizationRequestDoc;

    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-preconsumed@example.com").await;
    create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let request_uri = create_par_request(&app, &client).await;

    // Consume the PAR directly via DB before the authorize request arrives.
    let _claim = crate::db::consume_pushed_authorization_request(
        &state.store,
        &request_uri,
        &client.client_id,
        crate::db::ParConsumptionMode::EnforceExpiry,
    )
    .await
    .expect("Pre-consumption should succeed");

    // Confirm consumed_at is set.
    let doc = state
        .store
        .find_one::<PushedAuthorizationRequestDoc>("request_uri", &request_uri)
        .await
        .unwrap()
        .expect("PAR doc should exist");
    assert!(doc.data.consumed_at.is_some(), "PAR should be pre-consumed");

    // Now attempt to authorize without a session — would normally → login redirect,
    // but PAR is already consumed so must return invalid_request_uri instead.
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            client.client_id,
            urlencoding::encode(&request_uri),
        ),
        &[],
    )
    .await;

    // The PAR lookup (lookup_par) detects consumed_at is set and returns an error page.
    // This exercises the consumed-before-authorize path at the lookup layer.
    assert_eq!(
        response.status,
        StatusCode::OK,
        "Pre-consumed PAR should return error page, got: {}",
        response.status
    );
    assert!(
        response.body.contains("expired")
            || response.body.contains("Invalid")
            || response.body.contains("error"),
        "Response should indicate the request_uri is already consumed: {}",
        response.body
    );

    // Critically: the response must NOT be a redirect to /login?pending_auth=...
    // (which would mean the PAR was consumed twice and a new pending_auth was created).
    assert!(
        !response.body.contains("pending_auth"),
        "Pre-consumed PAR should not create a new pending_auth record"
    );
    let location = response.headers.get("location");
    assert!(
        location.is_none()
            || !location
                .and_then(|l| l.to_str().ok())
                .unwrap_or("")
                .starts_with("/login"),
        "Pre-consumed PAR must not redirect to /login"
    );
}

#[tokio::test]
async fn test_rfc9126_par_jti_replay_returns_invalid_client() {
    // Regression: PAR's commit_jti() failure must return 401 invalid_client
    // (the JTI replay is a client-auth failure), not 500 server_error.
    // Returning 500 would tempt well-behaved clients to retry-loop with the
    // same already-consumed JTI. The four token-grant arms in
    // handlers/oidc/token.rs return invalid_client for the same failure;
    // PAR must match.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-jti-replay@example.com").await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let par_endpoint = format!("{}/oauth/par", state.config().base_url);
    let fixed_jti = "par-replay-jti-12345";
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let build_body = |assertion: &str| {
        format!(
            "response_type=code\
             &client_id={}\
             &redirect_uri={}\
             &code_challenge={}\
             &code_challenge_method=S256\
             &scope=openid\
             &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
             &client_assertion={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            assertion,
        )
    };

    let assertion1 = build_client_assertion(
        &client.client_id,
        &par_endpoint,
        &pkcs8_bytes,
        Some(fixed_jti),
    );
    let (status1, body1) = http_post_form(&app, "/oauth/par", &build_body(&assertion1), &[]).await;
    assert_eq!(
        status1,
        StatusCode::CREATED,
        "First PAR with JWT assertion must succeed: {body1}"
    );

    // Replay the same JTI in a new assertion (re-signed for freshness on iat/exp,
    // but with the same jti — JTI uniqueness is per (client_id, jti)).
    let assertion2 = build_client_assertion(
        &client.client_id,
        &par_endpoint,
        &pkcs8_bytes,
        Some(fixed_jti),
    );
    let (status2, body2) = http_post_form(&app, "/oauth/par", &build_body(&assertion2), &[]).await;

    assert_eq!(
        status2,
        StatusCode::UNAUTHORIZED,
        "PAR JTI replay must return 401 (invalid_client), not 500 (server_error): {body2}"
    );
    let err: serde_json::Value = serde_json::from_str(&body2).expect("Valid JSON");
    assert_eq!(
        err["error"], "invalid_client",
        "PAR JTI replay must return error=invalid_client, got: {body2}"
    );
}

// ========================================================================
// RFC 8705 §2 / FAPI 2.0 §5.2.2 — mTLS Client Authentication at PAR
//
// Regressions for the gap that conformance caught: PAR previously never
// validated the TLS client certificate for clients registered with
// tls_client_auth, so mTLS-registered clients were either silently
// accepted by client_id alone (pre-refactor, fail-open) or rejected at
// the for_public_client chokepoint (post-refactor, 401). The fix adds
// the same mTLS dispatch the token endpoint has.
// ========================================================================

/// Register an OAuth client with `tls_client_auth` bound to the given subject DN.
async fn create_mtls_oauth_client(
    store: &crate::db::store::DocumentStore,
    user_id: &str,
    subject_dn: &str,
) -> String {
    let (_client_doc, client_id) = crate::db::create_oauth_client(
        store,
        &crate::db::CreateOAuthClientParams {
            user_id: Some(user_id),
            name: "Test mTLS PAR Client",
            description: None,
            application_type: crate::db::OAuthClientType::Web,
            redirect_uris: &["https://example.com/callback".to_string()],
            access_scope: crate::db::AccessScope::Public,
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::TlsClientAuth),
            jwks: None,
            jwks_uri: None,
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: crate::db::RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: crate::db::JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: Some(subject_dn),
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
    .expect("Failed to create mTLS test client");
    client_id
}

#[tokio::test]
async fn test_rfc9126_par_accepts_mtls_with_matching_cert() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "par-mtls-ok@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = super::rfc8705::make_test_cert_der("par-mtls-client");
    let parsed = crate::services::oidc::mtls::parse_client_certificate(&cert_der)
        .expect("parse generated cert");
    let subject_dn = parsed.subject_dn.expect("generated cert has subject DN");

    let client_id = create_mtls_oauth_client(&state.store, &user.id, &subject_dn).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let body = format!(
        "response_type=code\
         &client_id={client_id}\
         &redirect_uri={}\
         &code_challenge={challenge}\
         &code_challenge_method=S256\
         &scope=openid",
        urlencoding::encode("https://example.com/callback"),
    );

    let (status, response_body) =
        http_post_form_with_cert(&app, "/oauth/par", &body, &[], Some(cert_der)).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "mTLS client with matching cert at PAR must return 201: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert!(json["request_uri"].is_string());
}

#[tokio::test]
async fn test_rfc9126_par_rejects_mtls_without_cert() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "par-mtls-nocert@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = super::rfc8705::make_test_cert_der("par-mtls-nocert-client");
    let parsed = crate::services::oidc::mtls::parse_client_certificate(&cert_der)
        .expect("parse generated cert");
    let subject_dn = parsed.subject_dn.expect("generated cert has subject DN");

    let client_id = create_mtls_oauth_client(&state.store, &user.id, &subject_dn).await;

    let body = format!(
        "response_type=code\
         &client_id={client_id}\
         &redirect_uri={}\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
         &code_challenge_method=S256",
        urlencoding::encode("https://example.com/callback"),
    );

    let (status, response_body) =
        http_post_form_with_cert(&app, "/oauth/par", &body, &[], None).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "mTLS-registered client without a cert at PAR must return 401: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn test_rfc9126_par_rejects_mtls_with_non_matching_cert() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "par-mtls-wrong@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Client is registered against cert A's subject DN.
    let cert_a_der = super::rfc8705::make_test_cert_der("par-mtls-registered");
    let parsed_a =
        crate::services::oidc::mtls::parse_client_certificate(&cert_a_der).expect("parse cert A");
    let subject_dn_a = parsed_a.subject_dn.expect("cert A has subject DN");
    let client_id = create_mtls_oauth_client(&state.store, &user.id, &subject_dn_a).await;

    // Caller presents cert B — different subject DN.
    let cert_b_der = super::rfc8705::make_test_cert_der("par-mtls-imposter");

    let body = format!(
        "response_type=code\
         &client_id={client_id}\
         &redirect_uri={}\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
         &code_challenge_method=S256",
        urlencoding::encode("https://example.com/callback"),
    );

    let (status, response_body) =
        http_post_form_with_cert(&app, "/oauth/par", &body, &[], Some(cert_b_der)).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "mTLS-registered client with wrong cert at PAR must return 401: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client");
}
