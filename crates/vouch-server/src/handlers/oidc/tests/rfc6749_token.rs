// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 6749 — Token endpoint basics and error format tests.
//!
//! GH#272 regression tests are also housed here: an authorization code whose
//! authenticator has been deleted must return `invalid_grant` at the token
//! endpoint instead of issuing a token.

use super::helpers::*;

// ========================================================================
// RFC 6749 — Token Endpoint
// ========================================================================

#[tokio::test]
async fn test_token_invalid_grant_type() {
    // RFC 6749 Section 5.2: unsupported_grant_type error
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=invalid_grant_type&code=test",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_token_missing_code() {
    // RFC 6749 Section 5.2: invalid_request when code is missing
    let (app, _state) = test_app().await;

    let (status, body) =
        http_post_form(&app, "/oauth/token", "grant_type=authorization_code", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_token_invalid_code() {
    // RFC 6749 Section 5.2: invalid_grant for invalid authorization code
    let (app, state) = test_app().await;

    // Create a test user and OAuth client for authentication
    let user = create_test_user(&state.store, "invalid-code@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=invalid_code&redirect_uri=https://example.com/callback",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn test_rfc6749_token_error_response_format() {
    // RFC 6749 Section 5.2: Token endpoint errors must include `error` field
    // and optional `error_description`, with correct HTTP status.
    let (app, _state) = test_app().await;

    let (status, body) =
        http_post_form(&app, "/oauth/token", "grant_type=authorization_code", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 6749 Section 5.2: REQUIRED error field
    assert!(
        error.get("error").is_some(),
        "Token error must include 'error' field"
    );
    let error_code = error["error"].as_str().expect("error is a string");
    assert!(!error_code.is_empty(), "Error code must not be empty");

    // error_description is optional but recommended
    if let Some(desc) = error.get("error_description") {
        assert!(desc.is_string(), "error_description must be a string");
    }
}

#[tokio::test]
async fn test_rfc6749_unsupported_grant_type() {
    // RFC 6749 Section 5.2: Unsupported grant_type returns specific error.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(&app, "/oauth/token", "grant_type=password", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "unsupported_grant_type",
        "Unknown grant type must return unsupported_grant_type"
    );
}

#[tokio::test]
async fn test_rfc6749_client_credentials_requires_auth() {
    // RFC 6749 Section 4.4.2: Client authentication is REQUIRED.
    let (app, _state) = test_app().await;

    let (status, body) =
        http_post_form(&app, "/oauth/token", "grant_type=client_credentials", &[]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_client",
        "Unauthenticated client_credentials must return invalid_client"
    );
}

// ========================================================================
// RFC 6749 Section 5.1 — Successful Token Response
// ========================================================================

#[tokio::test]
async fn test_rfc6749_successful_authorization_code_exchange() {
    // RFC 6749 Section 5.1: Successful token response must contain
    // access_token, token_type, and expires_in.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "success-exchange@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec::default(),
    )
    .await;

    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Successful token exchange must return 200: {body}"
    );

    let response: serde_json::Value =
        serde_json::from_str(&body).expect("Response must be valid JSON");

    // RFC 6749 Section 5.1: REQUIRED fields
    assert!(
        response.get("access_token").is_some(),
        "Response must contain access_token"
    );
    assert!(
        response.get("token_type").is_some(),
        "Response must contain token_type"
    );
    assert!(
        response.get("expires_in").is_some(),
        "Response must contain expires_in"
    );

    let token_type = response["token_type"]
        .as_str()
        .expect("token_type must be a string");
    assert!(
        token_type == "Bearer" || token_type == "DPoP",
        "token_type must be Bearer or DPoP, got: {token_type}"
    );

    assert!(
        response["expires_in"].is_number(),
        "expires_in must be a number"
    );

    // OIDC: id_token must be present when scope includes "openid"
    assert!(
        response.get("id_token").is_some(),
        "id_token must be present when scope includes openid"
    );
}

#[tokio::test]
async fn test_rfc6749_token_response_no_error_field_on_success() {
    // RFC 6749 Section 5.1 vs 5.2: Success responses must NOT contain
    // the error field — success and error formats are mutually exclusive.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "no-error-field@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // If we got here, the exchange was successful.
    // Verify the token works (proving the exchange was genuine).
    let claims = decode_jwt_payload(&access_token);
    assert!(
        claims.get("sub").is_some(),
        "Access token must contain sub claim"
    );

    // The issue_oauth_access_token helper already validates success,
    // but let's explicitly verify via a fresh exchange.
    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            ..Default::default()
        },
    )
    .await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert!(
        response.get("error").is_none(),
        "RFC 6749 §5.1: Successful response must NOT contain 'error' field"
    );
    assert!(
        response.get("error_description").is_none(),
        "RFC 6749 §5.1: Successful response must NOT contain 'error_description'"
    );
}

// ========================================================================
// GH#272 — Revoked authenticator blocks code exchange
// ========================================================================

/// Regression test for GH#272: an authorization code that embeds an
/// `authenticator_id` for an authenticator that has since been
/// deleted/revoked must return `invalid_grant` at the token endpoint.
///
/// Before the fix, `exchange_authorization_code` looked up the user and
/// enforced single-use but never verified that the authenticator still
/// existed.  An attacker (or a stale code in flight) could therefore redeem
/// a code issued for a revoked key and receive a live access token.
#[tokio::test]
async fn test_token_exchange_rejects_revoked_authenticator() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "revoked-auth@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec::default(),
    )
    .await;

    // Revoke the authenticator between code issuance and code exchange.
    crate::test_utils::remove_test_authenticator(&state.store, &auth_id).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Revoked authenticator must return 400, got: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Revoked authenticator must return invalid_grant, got: {body}"
    );
}

/// RFC 6749 §2.3.1: A confidential client may authenticate by sending
/// `client_id` and `client_secret` in the request body as form parameters
/// (`client_secret_post`) instead of HTTP Basic. The token endpoint must
/// accept this and return a successful token response.
///
/// Covers vouch-conformance TOKEN_TEST_HANDOFF scenario
/// `auth=client_secret_post grant=authorization_code → 200`.
#[tokio::test]
async fn test_rfc6749_token_client_secret_post_succeeds() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "csp-token@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            ..Default::default()
        },
    )
    .await;

    // Credentials in the form body (NO Authorization header).
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}\
         &client_id={}&client_secret={}",
        urlencoding::encode("https://example.com/callback"),
        client.client_id,
        client.client_secret,
    );

    let (status, response_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "client_secret_post auth must succeed: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert!(
        json.get("access_token")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "Response must contain access_token"
    );
    assert_eq!(json["token_type"].as_str(), Some("Bearer"));
}

// ========================================================================
// Token endpoint — client lookup: DB error vs not-found vs inactive
//
// A DB error on client lookup must surface as a 500, not as invalid_client.
// A missing or inactive client must still return invalid_client.
// ========================================================================

/// A non-existent client_id presented without a secret must return
/// `invalid_client` — confirms the lookup split did not break the
/// not-found rejection path.
#[tokio::test]
async fn test_token_unknown_client_id_returns_invalid_client() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&client_id=no-such-client&code=any",
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Unknown client_id must return 401/invalid_client, got: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_client",
        "Unknown client_id must produce invalid_client error, got: {body}"
    );
}

/// An inactive (deactivated) client presented without a secret must return
/// `invalid_client` — same as "not found" from the caller's perspective.
#[tokio::test]
async fn test_token_inactive_client_returns_invalid_client() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "inactive-client-token@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Deactivate the client.
    let oauth_client = db::get_oauth_client_by_client_id(&state.store, &client.client_id)
        .await
        .expect("DB must not error")
        .expect("client must exist");
    db::set_oauth_client_active(&state.store, &oauth_client.id, false)
        .await
        .expect("deactivate client");

    // Present the client_id without a secret (no secret → falls through to the plain client lookup).
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&client_id={}&code=any",
            client.client_id
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Inactive client must return 401/invalid_client, got: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_client",
        "Inactive client must produce invalid_client error, got: {body}"
    );
}

/// A DB error on client lookup must return 500, not `invalid_client`.
///
/// Closing the pool before the request causes the in-flight `find_one` inside
/// `get_oauth_client_by_client_id` to return an `Err`. The `map_err` block in
/// the token handler must catch that and return 500 — not collapse it into
/// `invalid_client` as the old `.ok().flatten()` chain did.
///
/// Without this test, reverting `map_err(…ServiceError::Internal…)?` back to
/// `.ok().flatten()` leaves the two existing not-found/inactive tests green
/// while the DB-error path goes unguarded.
#[tokio::test]
async fn test_token_db_error_on_client_lookup_returns_internal_server_error() {
    let (app, state) = test_app().await;

    // Close the pool so the next DB call returns Err.
    state.db.close().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&client_id=any-client&code=any",
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "DB error must return 500, not invalid_client; got: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_ne!(
        json["error"], "invalid_client",
        "DB error must not be reported as invalid_client: {body}"
    );
}

#[test]
fn test_token_response_wire_shape_with_and_without_id_token() {
    // RFC 6749 Section 5.1 responses without an ID token (client
    // credentials, refresh) serialize `id_token: null`, and the token
    // values serialize as plain strings. Pins the wire shape across the
    // SecretString field migration: the explicit serializers must produce
    // exactly what the bare `String`/`Option<String>` fields did.
    let with = crate::handlers::oidc::token::TokenResponse {
        access_token: "at-secret".into(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        id_token: Some("idt-secret".into()),
        scope: None,
        email: None,
        authorization_details: None,
    };
    let json = serde_json::to_value(&with).expect("serialize TokenResponse");
    assert_eq!(json["access_token"], "at-secret");
    assert_eq!(json["id_token"], "idt-secret");

    let without = crate::handlers::oidc::token::TokenResponse {
        access_token: "at-secret".into(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        id_token: None,
        scope: None,
        email: None,
        authorization_details: None,
    };
    let json = serde_json::to_value(&without).expect("serialize TokenResponse");
    assert!(
        json["id_token"].is_null() && json.get("id_token").is_some(),
        "id_token must serialize as an explicit null when absent: {json}"
    );
}

#[test]
fn test_token_request_debug_never_prints_credential_material() {
    // Every credential-bearing field must be absent from `{:?}` output —
    // the manual Debug impl prints [REDACTED] and the SecretString fields
    // self-redact even if a future impl prints them directly.
    let request = crate::handlers::oidc::token::TokenRequestForm {
        grant_type: "authorization_code".to_string(),
        code: Some("visible-code".to_string()),
        redirect_uri: None,
        client_id: Some("client-1".to_string()),
        client_secret: Some("secret-cs".into()),
        code_verifier: Some("secret-cv".to_string()),
        device_code: None,
        subject_token: Some("secret-st".into()),
        subject_token_type: None,
        actor_token: Some("secret-at".into()),
        actor_token_type: None,
        audience: None,
        scope: None,
        requested_token_type: None,
        resource: None,
        client_assertion: Some("secret-ca".into()),
        client_assertion_type: None,
        assertion: Some("secret-a".into()),
        authorization_details: None,
    };
    let debug = format!("{request:?}");
    for secret in [
        "secret-cs",
        "secret-cv",
        "secret-st",
        "secret-at",
        "secret-ca",
        "secret-a",
    ] {
        assert!(
            !debug.contains(secret),
            "{secret} leaked into Debug: {debug}"
        );
    }
    assert!(debug.contains("[REDACTED]"), "{debug}");
    assert!(
        debug.contains("client-1"),
        "non-secrets stay visible: {debug}"
    );
}

// ========================================================================
// RFC 6749 Section 5.2 — `invalid_client` challenge on header auth
// ========================================================================
//
// `specs/rfc/rfc6749.txt:2493-2498`:
//
// > If the client attempted to authenticate via the "Authorization"
// > request header field, the authorization server MUST respond with an
// > HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate"
// > response header field matching the authentication scheme used by the
// > client.
//
// The MUST has two conjuncts. The status half was already satisfied by
// `OAuthErrorCode::status_code`; these cover the header half, and pin the
// condition so the challenge does not leak onto body-authenticated
// clients (for whom the RFC requires nothing).

#[tokio::test]
async fn test_token_basic_auth_failure_challenges_with_basic() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "tok-basic-challenge@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let encoded = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:wrong-secret", client.client_id).as_bytes());
    let auth = format!("Basic {encoded}");

    let response = http_post_form_full(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=irrelevant\
         &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback",
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "bad client_secret_basic must be 401: {}",
        response.body
    );
    assert_eq!(
        www_authenticate(&response),
        "Basic",
        "a 401 for a client that used the Authorization header MUST carry a \
         matching WWW-Authenticate challenge"
    );
}

#[tokio::test]
async fn test_token_body_auth_failure_has_no_challenge() {
    // The client authenticated via `client_secret_post`, not the
    // Authorization header, so RFC 6749 Section 5.2 requires no challenge.
    // Emitting one would advertise a scheme the client did not use.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "tok-post-challenge@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let body = format!(
        "grant_type=authorization_code&code=irrelevant\
         &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
         &client_id={}&client_secret=wrong-secret",
        client.client_id
    );

    let response = http_post_form_full(&app, "/oauth/token", &body, &[]).await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "bad client_secret_post must still be 401: {}",
        response.body
    );
    assert_eq!(
        www_authenticate(&response),
        "",
        "client_secret_post failure must not advertise a Basic challenge"
    );
}

#[tokio::test]
async fn test_token_malformed_basic_header_challenges_with_basic() {
    // RFC 6749 Section 5.2 binds on the client having *attempted* header
    // authentication. A header that fails to base64-decode is still an
    // attempt, so the challenge is owed.
    let (app, _state) = test_app().await;

    let response = http_post_form_full(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=irrelevant\
         &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback",
        &[("Authorization", "Basic !!!not-base64!!!")],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "malformed Basic credentials must be 401: {}",
        response.body
    );
    assert_eq!(
        www_authenticate(&response),
        "Basic",
        "an unparseable Authorization header is still an authentication attempt"
    );
}

#[tokio::test]
async fn test_fido2_grant_basic_auth_failure_challenges_with_basic() {
    // The fido2-assertion grant requires `private_key_jwt`, so a client that
    // presents Basic credentials is rejected as `invalid_client`. It attempted
    // header authentication, so the same MUST binds: 401 plus a challenge.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fido2-basic-challenge@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let encoded = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:wrong-secret", client.client_id).as_bytes());
    let auth = format!("Basic {encoded}");

    let response = http_post_form_full(
        &app,
        "/oauth/token",
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
         &assertion=aXJyZWxldmFudA",
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "a client that used the Authorization header must get 401: {}",
        response.body
    );
    assert_eq!(
        www_authenticate(&response),
        "Basic",
        "a 401 for a client that used the Authorization header MUST carry a \
         matching WWW-Authenticate challenge"
    );
}

#[tokio::test]
async fn test_par_basic_auth_failure_challenges_with_basic() {
    // PAR reaches the failure through `complete_client_auth` rather than the
    // token endpoint's own path, so it needs its own coverage.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-basic-challenge@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let encoded = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:wrong-secret", client.client_id).as_bytes());
    let auth = format!("Basic {encoded}");

    let body = format!(
        "response_type=code&client_id={}\
         &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
         &code_challenge_method=S256",
        client.client_id
    );

    let response =
        http_post_form_full(&app, "/oauth/par", &body, &[("Authorization", &auth)]).await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "bad client_secret_basic at PAR must be 401: {}",
        response.body
    );
    assert_eq!(
        www_authenticate(&response),
        "Basic",
        "PAR must carry the same challenge as the token endpoint"
    );
}

// ── no credentials at all ────────────────────────────────────────────────
//
// RFC 6749 Section 5.2, `specs/rfc/rfc6749.txt:2490-2492`:
//
// > The authorization server MAY return an HTTP 401 (Unauthorized) status
// > code to indicate which HTTP authentication schemes are supported.
//
// A MAY, so any of these endpoints could stay silent and still conform. They
// answer alike instead, so a client discovering one learns the same thing at
// all four. `Basic` is the only method that has an HTTP auth-scheme token;
// the rest are discoverable through RFC 8414 metadata.

/// Each endpoint requiring client authentication, and a body that reaches its
/// client-auth check without credentials.
fn no_credential_requests() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "/oauth/token",
            "grant_type=authorization_code&code=irrelevant\
             &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback",
        ),
        (
            "/oauth/par",
            "response_type=code&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
             &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
             &code_challenge_method=S256",
        ),
        ("/oauth/revoke", "token=irrelevant"),
        ("/oauth/introspect", "token=irrelevant"),
    ]
}

#[tokio::test]
async fn test_no_credentials_challenges_uniformly_across_endpoints() {
    let (app, _state) = test_app().await;

    for (path, body) in no_credential_requests() {
        let response = http_post_form_full(&app, path, body, &[]).await;

        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{path} must reject a request carrying no client credentials: {}",
            response.body
        );
        assert!(
            www_authenticate(&response).starts_with("Basic"),
            "{path} must advertise Basic when no credentials were presented, got: {:?}",
            www_authenticate(&response)
        );
    }
}

#[tokio::test]
async fn test_introspect_no_credentials_keeps_resource_metadata_pointer() {
    // Introspection is a protected resource, so its challenge also carries the
    // RFC 9728 pointer. The uniform `Basic` must not displace it.
    let (app, _state) = test_app().await;

    let response = http_post_form_full(&app, "/oauth/introspect", "token=irrelevant", &[]).await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let challenge = www_authenticate(&response);
    assert!(
        challenge.contains("resource_metadata="),
        "introspection must keep its RFC 9728 pointer, got: {challenge:?}"
    );
}

// ========================================================================
// RFC 6749 Section 3.2 — Token endpoint parameter rules
// ========================================================================
//
// > Parameters sent without a value MUST be treated as if they were omitted
// > from the request.  The authorization server MUST ignore unrecognized
// > request parameters.  Request and response parameters MUST NOT be included
// > more than once.
//
// The three cases below are that paragraph, one test each, checked at the
// endpoint rather than against the request type: they are properties of what
// the wire produces, and the wire is what a client sees.

/// An empty-valued parameter must produce the same response as omitting it.
/// `subject_token=` previously deserialized to `Some("")` and reached the
/// decoder, which answered `invalid_grant` where an omitted `subject_token`
/// answers `invalid_request`.
#[tokio::test]
async fn test_rfc6749_empty_parameter_is_treated_as_omitted() {
    let (app, _state) = test_app().await;

    let exchange = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
                    &subject_token_type=urn:ietf:params:oauth:token-type:access_token";

    let (empty_status, empty_body) = http_post_form(
        &app,
        "/oauth/token",
        &format!("{exchange}&subject_token="),
        &[],
    )
    .await;
    let (omitted_status, omitted_body) = http_post_form(&app, "/oauth/token", exchange, &[]).await;

    assert_eq!(empty_status, omitted_status);
    assert_eq!(
        empty_body, omitted_body,
        "`subject_token=` must answer exactly as an omitted `subject_token`"
    );
    assert_eq!(empty_status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&empty_body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

/// A repeated parameter is `invalid_request` under RFC 6749 §5.2 ("includes a
/// parameter more than once"), reported in the OAuth error envelope. Axum's
/// own rejection answered `422` with a `text/plain` body, which a client
/// parsing `error`/`error_description` cannot read.
#[tokio::test]
async fn test_rfc6749_duplicate_parameter_is_rejected_in_the_oauth_envelope() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token=a&subject_token=b\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value =
        serde_json::from_str(&body).expect("rejection must be the JSON OAuth envelope");
    assert_eq!(error["error"], "invalid_request");
}

/// An unrecognized parameter must be ignored, including when repeated: the
/// "MUST ignore unrecognized request parameters" sentence covers it, and the
/// duplicate rule must not be read as overriding that.
#[tokio::test]
async fn test_rfc6749_unrecognized_parameters_are_ignored() {
    let (app, _state) = test_app().await;

    let (baseline_status, baseline_body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=nonexistent",
        &[],
    )
    .await;
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=nonexistent&surprise=1&surprise=2",
        &[],
    )
    .await;

    assert_eq!(status, baseline_status);
    assert_eq!(
        body, baseline_body,
        "an unrecognized parameter must not change the response"
    );
}

/// A parameter this server implements for a *different* grant is recognized
/// but foreign: it is unreachable from the handler and, like an unrecognized
/// one, does not change the response.
#[tokio::test]
async fn test_rfc6749_another_grants_parameter_is_ignored() {
    let (app, _state) = test_app().await;

    let (baseline_status, baseline_body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=nonexistent",
        &[],
    )
    .await;
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=nonexistent\
         &device_code=dc&subject_token=st&assertion=as",
        &[],
    )
    .await;

    assert_eq!(status, baseline_status);
    assert_eq!(
        body, baseline_body,
        "another grant's parameters must not change this grant's response"
    );
}

// ========================================================================
// RFC 6749 Section 10.5 — Scope of replay revocation
// ========================================================================

/// Exchange an authorization code at `/oauth/token`. Returns `(status, body)`.
async fn exchange_code(
    app: &axum::Router,
    client: &TestOAuthClient,
    code: &str,
) -> (StatusCode, String) {
    http_post_form(
        app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await
}

/// Exchange `code` and return the access token it issues.
async fn token_from_code(app: &axum::Router, client: &TestOAuthClient, code: &str) -> String {
    let (status, body) = exchange_code(app, client, code).await;
    assert_eq!(status, StatusCode::OK, "code exchange failed: {body}");
    serde_json::from_str::<serde_json::Value>(&body)
        .expect("token response is JSON")["access_token"]
        .as_str()
        .expect("access_token present")
        .to_string()
}

/// Probe a client-audience access token at `/oauth/userinfo`, which accepts it
/// where `/v1/keys` would reject it on audience grounds. 200 means the session
/// is live, 401 means it has been revoked.
async fn userinfo_status(app: &axum::Router, token: &str) -> StatusCode {
    let (status, _body) = http_get(
        app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    status
}

/// RFC 6749 Section 10.5: "If the authorization server observes multiple
/// attempts to exchange an authorization code for an access token, the
/// authorization server SHOULD attempt to revoke all access tokens already
/// granted based on the compromised authorization code."
///
/// `rfc9700::test_rfc9700_code_replay_revokes_the_tokens_it_issued` covers the
/// revocation itself; this covers its scope. Only the replayed code's token is
/// revoked, so a token from a second code and a token from a grant that has no
/// single-use code both keep working.
#[tokio::test]
async fn test_rfc6749_code_replay_revocation_is_scoped_to_that_code() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "replay-scope@example.com").await;
    let auth = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let code_a = issue_code(
        &state,
        &user,
        &auth,
        &client.client_id,
        TestCodeSpec {
            nonce: Some("a"),
            ..Default::default()
        },
    )
    .await;
    let token_a = token_from_code(&app, &client, &code_a).await;
    let code_b = issue_code(
        &state,
        &user,
        &auth,
        &client.client_id,
        TestCodeSpec {
            nonce: Some("b"),
            ..Default::default()
        },
    )
    .await;
    let token_b = token_from_code(&app, &client, &code_b).await;
    // A session from a grant with no single-use code. It carries the server's
    // own audience, so `/v1/keys` is its probe.
    let token_c = create_test_session(&state, &user.id, &user.email, &auth).await;

    assert_eq!(
        userinfo_status(&app, &token_b).await,
        StatusCode::OK,
        "token B must be live before the replay"
    );
    assert_token_alive(&app, &token_c, "token C").await;

    let (status, body) = exchange_code(&app, &client, &code_a).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replayed code A must be denied: {body}"
    );

    assert_eq!(
        userinfo_status(&app, &token_a).await,
        StatusCode::UNAUTHORIZED,
        "the replayed code's own token must be revoked"
    );
    assert_eq!(
        userinfo_status(&app, &token_b).await,
        StatusCode::OK,
        "a token issued from a different code must survive the replay"
    );
    assert_token_alive(&app, &token_c, "token C after the replay").await;
}
