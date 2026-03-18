// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 assertion grant flow tests.
//!
//! Tests cover the challenge endpoint and the token endpoint error paths for the
//! `urn:ietf:params:oauth:grant-type:fido2-assertion` grant type. Full happy-path
//! assertion verification requires a physical YubiKey and is covered by the
//! `yubikey-tests` feature flag.

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
// Helpers local to this module
// ========================================================================

/// Create a test OAuth client configured for `private_key_jwt` with inline JWKS.
/// Returns (TestOAuthClient, pkcs8_bytes).
async fn create_test_jwt_client(
    store: &db::store::DocumentStore,
    user_id: &str,
) -> (TestOAuthClient, Vec<u8>) {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("Failed to generate key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .expect("Failed to parse key");

    let pub_bytes = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);

    let jwk = serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": x, "y": y,
        "use": "sig", "alg": "ES256", "kid": "test-key-1"
    });
    let jwks_value = serde_json::json!({ "keys": [jwk] });

    let client = create_test_oauth_client(store, user_id).await;
    let oauth_client = db::get_oauth_client_by_client_id(store, &client.client_id)
        .await
        .expect("DB error")
        .expect("Client not found");

    db::update_oauth_client_jwks(store, &oauth_client.id, &jwks_value)
        .await
        .expect("Failed to set JWKS");
    db::update_oauth_client_auth_method(store, &oauth_client.id, "private_key_jwt")
        .await
        .expect("Failed to set auth method");

    (client, pkcs8.as_ref().to_vec())
}

/// Build a `private_key_jwt` client assertion for the token endpoint.
fn build_client_assertion(
    client_id: &str,
    audience: &str,
    pkcs8_bytes: &[u8],
    jti: Option<&str>,
) -> String {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes)
        .expect("Failed to parse key");

    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": "test-key-1" });
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + 60,
        "jti": jti.map(str::to_string).unwrap_or_else(|| uuid::Uuid::now_v7().to_string())
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    format!("{header_b64}.{claims_b64}.{sig_b64}")
}
