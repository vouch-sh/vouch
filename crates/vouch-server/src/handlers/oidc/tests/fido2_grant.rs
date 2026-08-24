// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 assertion grant flow tests.
//!
//! Tests cover the challenge endpoint and the token endpoint error paths for the
//! `urn:ietf:params:oauth:grant-type:fido2-assertion` grant type. Full happy-path
//! assertion verification requires a physical YubiKey and has no automated
//! coverage; it is exercised by running `vouch login` against a real device.

use super::helpers::*;

// ========================================================================
// Challenge endpoint — POST /oauth/fido2/challenge
// ========================================================================

#[tokio::test]
async fn test_fido2_challenge_endpoint_exists() {
    // The challenge endpoint must return 200 with a JSON body containing
    // "challenge", "rp_id", and "state" fields. No authentication required.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(&app, "/oauth/fido2/challenge", "", &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Challenge endpoint must return 200: {body}"
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Response must be JSON");
    assert!(
        response["challenge"].is_string(),
        "Response must contain 'challenge' string field"
    );
    assert!(
        response["rp_id"].is_string(),
        "Response must contain 'rp_id' string field"
    );
    assert!(
        response["state"].is_string(),
        "Response must contain 'state' JWT field"
    );
}

#[tokio::test]
async fn test_fido2_challenge_response_has_no_cache_headers() {
    // Challenge responses must not be cached — they contain one-time-use material.
    let (app, _state) = test_app().await;

    let resp = http_post_form_full(&app, "/oauth/fido2/challenge", "", &[]).await;

    assert_eq!(resp.status, StatusCode::OK);
    let cache_control = resp
        .headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cache_control.contains("no-store"),
        "Challenge response must have Cache-Control: no-store, got: {cache_control}"
    );
}

#[tokio::test]
async fn test_fido2_challenge_state_is_valid_jwt() {
    // The state field must be a three-part dot-separated JWT string.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(&app, "/oauth/fido2/challenge", "", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let state_jwt = response["state"].as_str().expect("state must be a string");

    let parts: Vec<&str> = state_jwt.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "State must be a three-part JWT, got: {state_jwt}"
    );
}

// ========================================================================
// Token endpoint — FIDO2 assertion grant error paths
// ========================================================================

#[tokio::test]
async fn test_fido2_token_missing_assertion_rejected() {
    // The assertion parameter is REQUIRED per the grant spec.
    // A request with grant_type but no assertion must return invalid_request.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion",
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Missing assertion must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Missing assertion must return invalid_request, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_missing_client_auth_rejected() {
    // The FIDO2 grant requires private_key_jwt client authentication.
    // A request with assertion but no client auth must return invalid_client.
    let (app, _state) = test_app().await;

    let garbage_assertion = URL_SAFE_NO_PAD.encode(b"not-a-real-assertion");

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={garbage_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Missing client auth must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_client",
        "Missing client auth must return invalid_client, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_assertion_encoding_rejected() {
    // An assertion that is not valid base64url must return invalid_grant.
    // We submit a properly-authenticated client but a garbage assertion value.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fido2-bad-b64@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    // "!not-base64url!" is not valid base64url
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion=%21not-base64url%21\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid base64 in assertion must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid base64 assertion must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_assertion_json_rejected() {
    // An assertion that decodes from base64url but is not valid JSON must
    // return invalid_grant (not a server error).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fido2-bad-json@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    // Valid base64url but not JSON
    let garbage_assertion = URL_SAFE_NO_PAD.encode(b"this-is-not-json{{{");

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={garbage_assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Non-JSON assertion must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Non-JSON assertion must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_state_jwt_rejected() {
    // A well-formed assertion JSON with a tampered/invalid state JWT must
    // return invalid_grant (state JWT verification fails).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fido2-bad-state@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    // Build a structurally valid assertion payload but with a tampered state JWT.
    // The state JWT signature is wrong so the server must reject it.
    let tampered_state = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
        .eyJjaGFsbGVuZ2UiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsInJwX2lkIjoidGFtcGVyZWQiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0\
        .tampered_signature_invalid";

    let assertion_payload = serde_json::json!({
        "state": tampered_state,
        "credential_id": URL_SAFE_NO_PAD.encode(b"fake-credential-id"),
        "authenticator_data": URL_SAFE_NO_PAD.encode(b"fake-auth-data"),
        "signature": URL_SAFE_NO_PAD.encode(b"fake-signature"),
        "client_data_json": URL_SAFE_NO_PAD.encode(b"fake-client-data"),
        "user_handle": URL_SAFE_NO_PAD.encode(b"fake-user-handle")
    });

    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Tampered state JWT must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Tampered state JWT must return invalid_grant, got: {}",
        error["error"]
    );
}

// ========================================================================
// Negative: Individual field encoding validation
// ========================================================================

/// Helper: get a real state JWT from the challenge endpoint.
async fn get_real_state_jwt(app: &axum::Router) -> String {
    let (status, body) = http_post_form(app, "/oauth/fido2/challenge", "", &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Challenge endpoint must return 200: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    response["state"]
        .as_str()
        .expect("state must be a string")
        .to_string()
}

#[tokio::test]
async fn test_fido2_token_invalid_credential_id_encoding_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-cred-id@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": "!!!invalid!!!",
        "authenticator_data": placeholder,
        "signature": placeholder,
        "client_data_json": placeholder,
        "user_handle": placeholder,
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid credential_id encoding must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid credential_id encoding must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_authenticator_data_encoding_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-auth-data@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": placeholder,
        "authenticator_data": "!!!invalid!!!",
        "signature": placeholder,
        "client_data_json": placeholder,
        "user_handle": placeholder,
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid authenticator_data encoding must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid authenticator_data encoding must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_signature_encoding_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-sig@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": placeholder,
        "authenticator_data": placeholder,
        "signature": "!!!invalid!!!",
        "client_data_json": placeholder,
        "user_handle": placeholder,
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid signature encoding must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid signature encoding must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_client_data_json_encoding_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-cdj@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": placeholder,
        "authenticator_data": placeholder,
        "signature": placeholder,
        "client_data_json": "!!!invalid!!!",
        "user_handle": placeholder,
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid client_data_json encoding must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid client_data_json encoding must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_user_handle_encoding_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-uh-enc@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": placeholder,
        "authenticator_data": placeholder,
        "signature": placeholder,
        "client_data_json": placeholder,
        "user_handle": "!!!invalid!!!",
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid user_handle encoding must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid user_handle encoding must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_user_handle_uuid_rejected() {
    // user_handle decodes successfully from base64url but is only 8 bytes —
    // not a valid UUID (which requires exactly 16 bytes).
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-uh-uuid@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    // 8 bytes decodes fine from base64url but cannot be a UUID (needs 16 bytes)
    let short_user_handle = URL_SAFE_NO_PAD.encode(b"8bytesok");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": placeholder,
        "authenticator_data": placeholder,
        "signature": placeholder,
        "client_data_json": placeholder,
        "user_handle": short_user_handle,
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Non-UUID user_handle must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Non-UUID user_handle must return invalid_grant, got: {}",
        error["error"]
    );
}

// ========================================================================
// Positive: Challenge endpoint properties
// ========================================================================

#[tokio::test]
async fn test_fido2_challenge_returns_unique_challenges() {
    let (app, _state) = test_app().await;

    let (status1, body1) = http_post_form(&app, "/oauth/fido2/challenge", "", &[]).await;
    let (status2, body2) = http_post_form(&app, "/oauth/fido2/challenge", "", &[]).await;

    assert_eq!(
        status1,
        StatusCode::OK,
        "First challenge must return 200: {body1}"
    );
    assert_eq!(
        status2,
        StatusCode::OK,
        "Second challenge must return 200: {body2}"
    );

    let resp1: serde_json::Value = serde_json::from_str(&body1).expect("Valid JSON");
    let resp2: serde_json::Value = serde_json::from_str(&body2).expect("Valid JSON");

    let challenge1 = resp1["challenge"]
        .as_str()
        .expect("challenge1 must be a string");
    let challenge2 = resp2["challenge"]
        .as_str()
        .expect("challenge2 must be a string");

    assert_ne!(
        challenge1, challenge2,
        "Each challenge must be unique — replay attack prevention requires different nonces"
    );
}

#[tokio::test]
async fn test_fido2_challenge_rp_id_matches_config() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(&app, "/oauth/fido2/challenge", "", &[]).await;
    assert_eq!(status, StatusCode::OK, "Challenge must return 200: {body}");

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let rp_id = response["rp_id"].as_str().expect("rp_id must be a string");

    assert_eq!(
        rp_id, "test.example.com",
        "rp_id in challenge response must match server configuration"
    );
}

// ========================================================================
// Negative: Replay protection
// ========================================================================

#[tokio::test]
async fn test_client_assertion_jti_committed_on_success_and_rejected_on_replay() {
    // RFC 7523 §4: Each JWT assertion MUST have a unique JTI. The server commits
    // the JTI only when a grant succeeds (by design, so retryable errors like
    // use_dpop_nonce can be retried with the same assertion). Two successful
    // authorization_code exchanges with the same client assertion JTI must result
    // in the second being rejected with invalid_client.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "jti-replay-ac@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;

    let fixed_jti = "fixed-jti-replay-test-value";
    let audience = "https://test.example.com/oauth/token";

    let scope_set = ScopeSet::parse("openid email");

    // First exchange: commit the JTI.
    let code1 = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
            par: crate::db::ParConsumptionProof::not_pushed(),
        },
    )
    .await
    .expect("Failed to issue auth code 1");

    let assertion1 = build_client_assertion(&client.client_id, audience, &pkcs8, Some(fixed_jti));
    let (status1, body1) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code\
             &code={code1}\
             &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={assertion1}"
        ),
        &[],
    )
    .await;
    assert_eq!(
        status1,
        StatusCode::OK,
        "First exchange must succeed (commits JTI): {body1}"
    );

    // Second exchange: same JTI must be rejected as a replay.
    let code2 = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
            par: crate::db::ParConsumptionProof::not_pushed(),
        },
    )
    .await
    .expect("Failed to issue auth code 2");

    let assertion2 = build_client_assertion(&client.client_id, audience, &pkcs8, Some(fixed_jti));
    let (status2, body2) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code\
             &code={code2}\
             &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={assertion2}"
        ),
        &[],
    )
    .await;

    // RFC 6749 Section 5.2: invalid_client errors SHOULD use 401.
    assert!(
        status2 == StatusCode::BAD_REQUEST || status2 == StatusCode::UNAUTHORIZED,
        "Replayed JTI must return 400 or 401, got {status2}: {body2}"
    );
    let error: serde_json::Value = serde_json::from_str(&body2).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_client",
        "Replayed client assertion JTI must return invalid_client, got: {}",
        error["error"]
    );
}

// ========================================================================
// Helpers local to this module
// ========================================================================
