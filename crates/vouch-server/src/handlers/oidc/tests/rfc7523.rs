// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7523 §2.2 / 7521 — JWT client authentication assertion tests.

use super::helpers::*;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

// ========================================================================
// JWT-specific helper functions (used only in this module)
// ========================================================================

fn generate_es256_signing_key() -> (Vec<u8>, serde_json::Value) {
    use aws_lc_rs::signature::KeyPair;

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("Failed to generate key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .expect("Failed to parse key");

    let pub_bytes = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);

    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "use": "sig",
        "alg": "ES256",
        "kid": "test-key-1"
    });

    (pkcs8.as_ref().to_vec(), jwk)
}

/// Sign a JWT assertion with an ES256 key (pkcs8 bytes).
fn sign_jwt_assertion(
    pkcs8_bytes: &[u8],
    header: &serde_json::Value,
    claims: &serde_json::Value,
) -> String {
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes)
        .expect("Failed to parse key");

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    format!("{header_b64}.{claims_b64}.{sig_b64}")
}

/// Create a test OAuth client configured for `private_key_jwt` auth with inline JWKS.
/// Returns (TestOAuthClient, pkcs8_bytes) where pkcs8_bytes is the ES256 signing key.
async fn create_test_jwt_client(
    store: &db::store::DocumentStore,
    user_id: &str,
) -> (TestOAuthClient, Vec<u8>) {
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();

    // Create the client first
    let client = create_test_oauth_client(store, user_id).await;

    // Get the internal ID for the client
    let oauth_client = db::get_oauth_client_by_client_id(store, &client.client_id)
        .await
        .expect("DB error")
        .expect("Client not found");

    // Set inline JWKS
    let jwks_value = serde_json::json!({
        "keys": [jwk]
    });
    db::update_oauth_client_jwks(store, &oauth_client.id, &jwks_value)
        .await
        .expect("Failed to set JWKS");

    // Set auth method to private_key_jwt
    db::update_oauth_client_auth_method(store, &oauth_client.id, "private_key_jwt")
        .await
        .expect("Failed to set auth method");

    (client, pkcs8_bytes)
}

/// Build a JWT assertion for private_key_jwt client auth (RFC 7523 Section 2.2).
fn build_client_assertion(
    client_id: &str,
    audience: &str,
    pkcs8_bytes: &[u8],
    jti: Option<&str>,
) -> String {
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "test-key-1"
    });
    let mut claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + 60
    });
    if let Some(jti_val) = jti {
        claims["jti"] = serde_json::json!(jti_val);
    } else {
        claims["jti"] = serde_json::json!(uuid::Uuid::now_v7().to_string());
    }
    sign_jwt_assertion(pkcs8_bytes, &header, &claims)
}

// ========================================================================
// P1: RFC 7523 §2.2 — JWT Profile for Client Authentication
//
// The §2.1 authorization grant (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`)
// has been removed. The lock-in test below asserts the token endpoint rejects it.
// ========================================================================

#[tokio::test]
async fn test_jwt_bearer_grant_returns_unsupported_grant_type() {
    // §2.1 grant is removed: requests with this grant_type must be rejected
    // as unsupported_grant_type per RFC 6749 §5.2.
    let (app, _state) = test_app().await;

    let body = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer\
                &assertion=eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ4In0.sig";
    let (status, resp_body) = http_post_form(&app, "/oauth/token", body, &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp_body}");
    let err: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(err["error"], "unsupported_grant_type");
}

// ========================================================================
// RFC 7521 — Assertion Framework for OAuth 2.0
// ========================================================================

#[tokio::test]
async fn test_rfc7521_mutual_exclusion_of_client_auth() {
    // RFC 7521 Section 4.2: Sending both client_secret and client_assertion must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "mutual-excl@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code=test&client_id={}&client_secret={}&client_assertion=fake.jwt.assertion&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client.client_id, client.client_secret
        ),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Combining auth methods must be rejected"
    );
}

#[tokio::test]
async fn test_rfc7521_basic_auth_and_assertion_mutual_exclusion() {
    // RFC 7521 Section 4.2: Basic auth header + client_assertion must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "basic-assert@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=test&client_assertion=fake.jwt.assertion&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Basic auth + client_assertion must be rejected"
    );
}

#[tokio::test]
async fn test_rfc7521_wrong_assertion_type() {
    // RFC 7521 Section 4.2: Wrong client_assertion_type must be rejected.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=test&subject_token_type=urn:ietf:params:oauth:token-type:access_token&client_assertion=fake.jwt.assertion&client_assertion_type=wrong:assertion:type",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Wrong assertion type must be rejected"
    );
}

// ========================================================================
// Phase 2: RFC 7523 — JWT Bearer Handler Integration Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7523_private_key_jwt_client_auth_full_flow() {
    // RFC 7523 Section 2.2: Full handler integration test for private_key_jwt
    // client authentication combined with authorization_code grant.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jwt-auth-full@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    // Issue an authorization code
    let scope_set = ScopeSet::parse("openid email");
    let code = issue_authorization_code(
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
        },
    )
    .await
    .expect("Failed to issue authorization code");

    // Exchange code with private_key_jwt client assertion
    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let assertion = build_client_assertion(&client.client_id, &token_endpoint, &pkcs8_bytes, None);

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "private_key_jwt auth should succeed: {resp_body}"
    );
    let response: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert!(
        response.get("access_token").is_some(),
        "Response should contain access_token"
    );
}

#[tokio::test]
async fn test_rfc7523_private_key_jwt_jti_replay_rejected() {
    // RFC 7523 Section 3: JTI replay must be rejected at the handler level.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jwt-replay@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let fixed_jti = "replay-test-jti-12345";

    // First request: issue code and exchange with JWT assertion
    let scope_set = ScopeSet::parse("openid");
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
        },
    )
    .await
    .expect("Failed to issue code");

    let assertion1 = build_client_assertion(
        &client.client_id,
        &token_endpoint,
        &pkcs8_bytes,
        Some(fixed_jti),
    );

    let body1 = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code1,
        urlencoding::encode("https://example.com/callback"),
        assertion1
    );

    let (status1, resp1) = http_post_form(&app, "/oauth/token", &body1, &[]).await;
    assert_eq!(status1, StatusCode::OK, "First use of JTI should succeed");
    let resp1_json: serde_json::Value = serde_json::from_str(&resp1).expect("Valid JSON");
    let access_token = resp1_json["access_token"].as_str().expect("access_token");

    // Second request with same JTI: use token exchange (avoids auth code reissue)
    let assertion2 = build_client_assertion(
        &client.client_id,
        &token_endpoint,
        &pkcs8_bytes,
        Some(fixed_jti),
    );

    let body2 = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token={access_token}\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        assertion2
    );

    let (status2, resp_body) = http_post_form(&app, "/oauth/token", &body2, &[]).await;
    assert!(
        status2 == StatusCode::UNAUTHORIZED || status2 == StatusCode::BAD_REQUEST,
        "Replayed JTI should be rejected, got {status2}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_private_key_jwt_expired_assertion_rejected() {
    // RFC 7523 Section 3: Expired JWT assertion must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jwt-expired@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
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
        },
    )
    .await
    .expect("Failed to issue code");

    // Build an expired assertion (iat and exp in the past)
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": client.client_id,
        "sub": client.client_id,
        "aud": format!("{}/oauth/token", state.config().base_url),
        "iat": now - 600,
        "exp": now - 300,
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Expired assertion should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_private_key_jwt_wrong_audience() {
    // RFC 7523 Section 3: JWT assertion with wrong audience must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jwt-wrong-aud@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
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
        },
    )
    .await
    .expect("Failed to issue code");

    // Build assertion with wrong audience
    let assertion = build_client_assertion(
        &client.client_id,
        "https://wrong-audience.example.com/token",
        &pkcs8_bytes,
        None,
    );

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Wrong audience should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_private_key_jwt_wrong_key() {
    // RFC 7523 Section 3: JWT assertion signed with wrong key must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jwt-wrong-key@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, _correct_pkcs8) = create_test_jwt_client(&state.store, &user.id).await;

    // Generate a different key pair (not the one registered with the client)
    let (wrong_pkcs8, _wrong_jwk) = generate_es256_signing_key();

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
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
        },
    )
    .await
    .expect("Failed to issue code");

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let assertion = build_client_assertion(&client.client_id, &token_endpoint, &wrong_pkcs8, None);

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Wrong signing key should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_private_key_jwt_iss_sub_mismatch() {
    // RFC 7523 Section 3: For client auth, iss MUST equal sub.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jwt-iss-sub@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
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
        },
    )
    .await
    .expect("Failed to issue code");

    // Build assertion where iss != sub
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": client.client_id,
        "sub": "different-subject",
        "aud": format!("{}/oauth/token", state.config().base_url),
        "iat": now,
        "exp": now + 60,
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "iss != sub should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7521_mutual_exclusion_secret_and_assertion() {
    // RFC 7521 Section 4.2: client_assertion cannot be combined with
    // client_secret or Basic auth.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jwt-mutual-excl@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
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
        },
    )
    .await
    .expect("Failed to issue code");

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let assertion = build_client_assertion(&client.client_id, &token_endpoint, &pkcs8_bytes, None);

    // Send both client_secret and client_assertion — must be rejected
    let auth_header = client.basic_auth_header();
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(
        &app,
        "/oauth/token",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Combining Basic auth with client_assertion must be rejected: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

// ========================================================================
// FAPI 2.0 Section 5.3.2.1-8: JWT assertion audience validation
//
// FAPI clients MUST use the issuer URL (base_url) as the audience.
// Non-FAPI clients accept both issuer and endpoint URLs.
// These tests prevent the regression where the CLI sent aud=token_endpoint_url
// which the server rejected after enforcing FAPI 2.0 compliance.
// ========================================================================

/// Create a FAPI-profiled OAuth client for testing.
async fn create_test_fapi_jwt_client(
    store: &db::store::DocumentStore,
    user_id: &str,
) -> (TestOAuthClient, Vec<u8>) {
    let (client, pkcs8_bytes) = create_test_jwt_client(store, user_id).await;

    let oauth_client = db::get_oauth_client_by_client_id(store, &client.client_id)
        .await
        .expect("DB error")
        .expect("Client not found");

    db::update_oauth_client_fapi_settings(
        store,
        &oauth_client.id,
        db::FapiProfile::Fapi2Security,
        true,
    )
    .await
    .expect("Failed to set FAPI profile");

    (client, pkcs8_bytes)
}

#[tokio::test]
async fn test_fapi_client_rejects_token_endpoint_audience() {
    // FAPI 2.0 Section 5.3.2.1-8: FAPI clients MUST NOT accept the token
    // endpoint URL as audience. Only the issuer URL is allowed.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fapi-aud-reject@example.com").await;
    let (client, pkcs8_bytes) = create_test_fapi_jwt_client(&state.store, &user.id).await;

    let base_url = &state.config().base_url;
    let token_endpoint_url = format!("{base_url}/oauth/token");

    // Build assertion with aud = token endpoint URL (wrong for FAPI)
    let assertion =
        build_client_assertion(&client.client_id, &token_endpoint_url, &pkcs8_bytes, None);

    let body = format!(
        "grant_type=client_credentials\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        assertion
    );

    let (status, _resp) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "FAPI client with aud=token_endpoint_url must be rejected"
    );
}

#[tokio::test]
async fn test_fapi_client_accepts_issuer_audience() {
    // FAPI 2.0 Section 5.3.2.1-8: FAPI clients MUST accept the issuer URL.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fapi-aud-accept@example.com").await;
    let (client, pkcs8_bytes) = create_test_fapi_jwt_client(&state.store, &user.id).await;

    let base_url = &state.config().base_url;

    // Build assertion with aud = issuer URL (correct for FAPI)
    let assertion = build_client_assertion(&client.client_id, base_url, &pkcs8_bytes, None);

    let body = format!(
        "grant_type=client_credentials\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    // Client auth must succeed. The grant itself may fail (unauthorized_client)
    // because the test client isn't configured for client_credentials, but
    // that's fine — invalid_client would mean auth itself failed.
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_ne!(
        error["error"], "invalid_client",
        "FAPI client with aud=issuer_url must pass client auth (status={status}): {resp_body}"
    );
}

#[tokio::test]
async fn test_non_fapi_client_accepts_token_endpoint_audience() {
    // RFC 7523 Section 3: Non-FAPI clients accept the token endpoint URL.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "nonfapi-aud@example.com").await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let base_url = &state.config().base_url;
    let token_endpoint_url = format!("{base_url}/oauth/token");

    // Build assertion with aud = token endpoint URL (valid for non-FAPI)
    let assertion =
        build_client_assertion(&client.client_id, &token_endpoint_url, &pkcs8_bytes, None);

    let body = format!(
        "grant_type=client_credentials\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    // Client auth must succeed. The grant may fail (unauthorized_client) but
    // invalid_client would mean client auth itself failed.
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_ne!(
        error["error"], "invalid_client",
        "Non-FAPI client with aud=token_endpoint_url must pass client auth (status={status}): {resp_body}"
    );
}

// ========================================================================
// Issue #391 — concurrent JTI replay must not produce multiple tokens.
//
// Before the fix, `commit_jti()` ran AFTER `exchange_*()`, so N concurrent
// requests with the same JWT assertion could each persist a token before any
// of them committed the JTI. One won the JTI insert and returned 200; the
// others returned `invalid_client` but their tokens remained valid in the DB.
//
// The fix moves `commit_jti()` to immediately before `exchange_*()`, so the
// atomic `(jti, client_id)` insert is the serialization point. Concurrent
// replayers either win the JTI and proceed to exchange, or lose and return
// `invalid_client` before any token is persisted.
//
// Each test below fires N concurrent requests with the same JWT assertion
// (fixed `jti`) and asserts that AT MOST one HTTP 200 is returned and AT MOST
// one session (token) ends up in the DB.
// ========================================================================

const CONCURRENT_N: usize = 8;

/// Fan out N identical POSTs to `/oauth/token` and return the response status
/// for each. The body and headers are constant across all requests.
async fn fan_out_token_requests(
    app: &axum::Router,
    body: &str,
    headers: &[(&str, &str)],
    n: usize,
) -> Vec<(StatusCode, String)> {
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..n {
        let app = app.clone();
        let body = body.to_string();
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        set.spawn(async move {
            let header_refs: Vec<(&str, &str)> = headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            http_post_form(&app, "/oauth/token", &body, &header_refs).await
        });
    }
    let mut results = Vec::with_capacity(n);
    while let Some(res) = set.join_next().await {
        results.push(res.expect("Task panicked"));
    }
    results
}

/// Enable a list of grant types on an OAuth client.
async fn enable_grant_types(store: &db::store::DocumentStore, client_id: &str, grants: &[&str]) {
    let oauth_client = db::get_oauth_client_by_client_id(store, client_id)
        .await
        .expect("DB error")
        .expect("Client not found");
    let grants: Vec<String> = grants.iter().map(|s| (*s).to_string()).collect();
    store
        .modify::<crate::db::documents::oauth::OAuthClientDoc, _>(&oauth_client.id, |data| {
            data.grant_types = Some(grants.clone());
        })
        .await
        .expect("Failed to update grant_types");
}

/// Count `SessionDoc` rows indexed under a given user_id. For client_credentials
/// grants the session's `user_id` is the client_id; for authorization_code it
/// is the actual user's id.
async fn count_sessions_for_user(store: &db::store::DocumentStore, user_id: &str) -> i64 {
    store
        .count::<crate::db::documents::session::SessionDoc>("user_id", user_id)
        .await
        .expect("count must not error")
}

#[tokio::test]
async fn test_jwt_assertion_jti_concurrent_replay_client_credentials() {
    // Strongest of the four concurrent-replay tests: no per-request resource
    // (no auth code) to gate concurrency. Without the fix, every concurrent
    // request reaches `exchange_client_credentials` and persists a session
    // before any of them commits the JTI.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jti-race-cc@example.com").await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;
    enable_grant_types(&state.store, &client.client_id, &["client_credentials"]).await;

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let fixed_jti = "race-cc-jti-12345";
    let assertion = build_client_assertion(
        &client.client_id,
        &token_endpoint,
        &pkcs8_bytes,
        Some(fixed_jti),
    );

    let body = format!(
        "grant_type=client_credentials\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}"
    );

    let results = fan_out_token_requests(&app, &body, &[], CONCURRENT_N).await;

    let successes = results.iter().filter(|(s, _)| *s == StatusCode::OK).count();
    assert!(
        successes <= 1,
        "At most one concurrent replay may succeed, got {successes}. \
         Responses: {results:?}"
    );

    // The session's `user_id` field for a client_credentials grant is the
    // client_id (RFC 9068 Section 2.2). At most one session must exist.
    let session_count = count_sessions_for_user(&state.store, &client.client_id).await;
    assert!(
        session_count <= 1,
        "At most one access-token session may be persisted, got {session_count}"
    );
}

#[tokio::test]
async fn test_jwt_assertion_jti_concurrent_replay_authorization_code() {
    // Concurrent replay against the authorization_code grant. The auth code
    // itself is single-use, so even without the JTI fix you'd see at most one
    // success — but you'd see multiple persisted sessions if the JTI race were
    // the only protection. The combined check below verifies both invariants.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jti-race-ac@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
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
        },
    )
    .await
    .expect("Failed to issue authorization code");

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let fixed_jti = "race-ac-jti-12345";
    let assertion = build_client_assertion(
        &client.client_id,
        &token_endpoint,
        &pkcs8_bytes,
        Some(fixed_jti),
    );

    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
        urlencoding::encode("https://example.com/callback")
    );

    let results = fan_out_token_requests(&app, &body, &[], CONCURRENT_N).await;

    let successes = results.iter().filter(|(s, _)| *s == StatusCode::OK).count();
    assert!(
        successes <= 1,
        "At most one concurrent replay may succeed, got {successes}. \
         Responses: {results:?}"
    );

    let session_count = count_sessions_for_user(&state.store, &user.id).await;
    assert!(
        session_count <= 1,
        "At most one access-token session may be persisted, got {session_count}"
    );
}

#[tokio::test]
async fn test_jwt_assertion_jti_concurrent_replay_token_exchange() {
    // Concurrent replay against the token-exchange grant. The subject_token
    // can be reused across exchanges, so the JTI uniqueness is the sole
    // serialization point.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jti-race-tx@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;
    // Allow both grants on the same client: authorization_code to seed the
    // subject_token, token-exchange for the replay.
    enable_grant_types(
        &state.store,
        &client.client_id,
        &[
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
    )
    .await;

    // Seed an access token to use as subject_token via a one-shot
    // authorization_code exchange (single-use, unique JTI).
    let scope_set = ScopeSet::parse("openid");
    let seed_code = issue_authorization_code(
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
        },
    )
    .await
    .expect("Failed to issue seed code");

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let seed_assertion =
        build_client_assertion(&client.client_id, &token_endpoint, &pkcs8_bytes, None);
    let seed_body = format!(
        "grant_type=authorization_code&code={seed_code}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={seed_assertion}",
        urlencoding::encode("https://example.com/callback")
    );
    let (seed_status, seed_resp) = http_post_form(&app, "/oauth/token", &seed_body, &[]).await;
    assert_eq!(
        seed_status,
        StatusCode::OK,
        "seed token must issue: {seed_resp}"
    );
    let seed_json: serde_json::Value = serde_json::from_str(&seed_resp).expect("Valid JSON");
    let subject_token = seed_json["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    // Sessions persisted so far: the one from the seed exchange.
    let baseline_sessions = count_sessions_for_user(&state.store, &user.id).await;

    let fixed_jti = "race-tx-jti-12345";
    let replay_assertion = build_client_assertion(
        &client.client_id,
        &token_endpoint,
        &pkcs8_bytes,
        Some(fixed_jti),
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token={subject_token}\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={replay_assertion}"
    );

    let results = fan_out_token_requests(&app, &body, &[], CONCURRENT_N).await;

    let successes = results.iter().filter(|(s, _)| *s == StatusCode::OK).count();
    assert!(
        successes <= 1,
        "At most one concurrent replay may succeed, got {successes}. \
         Responses: {results:?}"
    );

    let new_sessions = count_sessions_for_user(&state.store, &user.id).await - baseline_sessions;
    assert!(
        new_sessions <= 1,
        "At most one new exchanged-token session may be persisted, got {new_sessions}"
    );
}

#[tokio::test]
async fn test_jwt_assertion_jti_concurrent_replay_fido2_assertion() {
    // The fido2-assertion grant requires a real WebAuthn signature, which
    // can't be faked in unit tests. We use a garbage assertion so that
    // `exchange_fido2_assertion` will fail with `invalid_grant` for any
    // request that reaches it. The point of THIS test is to prove that
    // `commit_jti` runs BEFORE `exchange_fido2_assertion`: with the fix, at
    // most one of N concurrent requests can pass the JTI commit, so at most
    // one can reach (and fail at) the exchange step, returning `invalid_grant`.
    // The other N-1 lose the JTI race and return `invalid_client`.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jti-race-fido2@example.com").await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let fixed_jti = "race-fido2-jti-12345";
    let assertion = build_client_assertion(
        &client.client_id,
        &token_endpoint,
        &pkcs8_bytes,
        Some(fixed_jti),
    );

    // Garbage FIDO2 assertion — base64url of empty JSON object will fail at
    // state-JWT verification, returning invalid_grant from exchange_fido2_assertion.
    let garbage_assertion = URL_SAFE_NO_PAD.encode(b"{}");

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:fido2-assertion\
         &assertion={garbage_assertion}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}"
    );

    let results = fan_out_token_requests(&app, &body, &[], CONCURRENT_N).await;

    // No request can succeed (garbage assertion), but the SHAPE of errors
    // tells us where the JTI commit sat:
    //   - With the fix: at most one `invalid_grant` (reached exchange), the
    //     rest `invalid_client` (lost JTI race).
    //   - Without the fix: all N would return `invalid_grant` because every
    //     request reaches exchange before any one of them tries to commit,
    //     and exchange fails for all of them on the garbage assertion before
    //     `commit_jti` ever runs.
    let invalid_grants = results
        .iter()
        .filter_map(|(_, body)| serde_json::from_str::<serde_json::Value>(body).ok())
        .filter(|j| j["error"] == "invalid_grant")
        .count();
    assert!(
        invalid_grants <= 1,
        "At most one concurrent replay may reach exchange_fido2_assertion (and fail), \
         got {invalid_grants} `invalid_grant` responses out of {}. Responses: {results:?}",
        results.len()
    );
}

// ========================================================================
// Issue #391 — DPoP nonce retry MUST still leave the JTI unconsumed.
//
// The fix moves `commit_jti()` to before `exchange_*()`, but DPoP nonce
// validation runs even earlier in the handler. If a request is rejected
// with `use_dpop_nonce` (RFC 9449 §4.3), the JTI must NOT have been
// committed — so the client can retry with the same JWT assertion and a
// DPoP proof that carries the new nonce.
//
// The pre-existing `test_rfc9449_dpop_nonce_required_retry_with_nonce_succeeds`
// covers this for basic_auth clients. This test seals the contract for the
// `private_key_jwt` (JWT-assertion) client auth path.
// ========================================================================

fn generate_dpop_key_pair() -> (EcdsaKeyPair, serde_json::Value) {
    use aws_lc_rs::signature::KeyPair;

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("Failed to generate DPoP key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .expect("Failed to parse DPoP key");

    let pub_bytes = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
    let jwk = serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y });
    (key_pair, jwk)
}

fn create_dpop_proof(
    key_pair: &EcdsaKeyPair,
    jwk: &serde_json::Value,
    method: &str,
    uri: &str,
    nonce: Option<&str>,
) -> String {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk,
    });
    let now = jiff::Timestamp::now().as_second();
    let mut claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": method,
        "htu": uri,
        "iat": now,
    });
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::json!(n);
    }
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("JSON encode"));
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("JSON encode"));
    let signing_input = format!("{header_b64}.{claims_b64}");
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign DPoP proof");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
    format!("{header_b64}.{claims_b64}.{sig_b64}")
}

#[tokio::test]
async fn test_jwt_assertion_dpop_use_nonce_retry_succeeds() {
    // Setup: private_key_jwt client + authorization_code grant + DPoP.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jti-dpop-retry@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
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
        },
    )
    .await
    .expect("Failed to issue authorization code");

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // The SAME JTI is used for both attempts. If `commit_jti` ran before
    // DPoP validation, the second attempt would be rejected as a replay.
    let fixed_jti = "dpop-retry-jti-12345";
    let assertion = build_client_assertion(
        &client.client_id,
        &token_endpoint,
        &pkcs8_bytes,
        Some(fixed_jti),
    );

    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
        urlencoding::encode("https://example.com/callback")
    );

    // Step 1: DPoP proof without nonce. Server returns use_dpop_nonce + a
    // DPoP-Nonce header. The JTI must NOT be committed at this point.
    let no_nonce_proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_endpoint, None);
    let first =
        http_post_form_full(&app, "/oauth/token", &body, &[("DPoP", &no_nonce_proof)]).await;
    assert!(
        first.status == StatusCode::BAD_REQUEST || first.status == StatusCode::UNAUTHORIZED,
        "First DPoP request without nonce must be rejected, got {} : {}",
        first.status,
        first.body
    );
    let server_nonce = first
        .headers
        .get("DPoP-Nonce")
        .expect("DPoP-Nonce header must be present in use_dpop_nonce response")
        .to_str()
        .expect("DPoP-Nonce must be valid UTF-8")
        .to_string();

    // Step 2: Retry with the server-provided nonce, SAME JWT assertion
    // (same jti). If `commit_jti` had run on the first attempt, this would
    // fail with `invalid_client` (replay). With the fix, the JTI is committed
    // only after DPoP validation, so the retry succeeds.
    let nonce_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &token_endpoint,
        Some(&server_nonce),
    );
    let second = http_post_form_full(&app, "/oauth/token", &body, &[("DPoP", &nonce_proof)]).await;
    assert_eq!(
        second.status,
        StatusCode::OK,
        "DPoP-nonce retry with same JWT assertion must succeed: {}",
        second.body
    );
    let token_resp: serde_json::Value = serde_json::from_str(&second.body).expect("Valid JSON");
    assert!(
        token_resp.get("access_token").is_some(),
        "Successful retry must return access_token: {}",
        second.body
    );
}
