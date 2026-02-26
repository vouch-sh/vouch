// SPDX-License-Identifier: BUSL-1.1
//! RFC 7523/7521 — JWT client authentication and bearer grant tests.

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
    let jwks_json = serde_json::to_string(&serde_json::json!({
        "keys": [jwk]
    }))
    .unwrap();
    db::update_oauth_client_jwks(store, &oauth_client.id, &jwks_json)
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
// P1: RFC 7523 — JWT Profile for Client Auth and Authorization Grants
// ========================================================================

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_missing_assertion() {
    // RFC 7523 Section 2.1: jwt-bearer grant requires assertion parameter.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_invalid_assertion() {
    // RFC 7523 Section 3: Invalid JWT assertion signature returns error.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=invalid.jwt.token",
        &[],
    )
    .await;

    // Should fail with an error status (400 or 401 depending on implementation)
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Invalid JWT assertion should be rejected, got status: {}",
        status
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error["error"] == "invalid_grant"
            || error["error"] == "invalid_client"
            || error["error"] == "invalid_request",
        "Invalid JWT assertion should be rejected, got: {}",
        error["error"]
    );
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
// RFC 7523 — JWT Bearer Grant with Trusted Issuers
// ========================================================================

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_with_trusted_issuer() {
    // RFC 7523 Section 2.1: Full JWT bearer grant flow with a real trusted issuer.
    // We create a trusted issuer, pre-populate its JWKS cache, sign a JWT
    // assertion, and exchange it at /oauth/token.
    let (app, state) = test_app().await;

    // Create user that the JWT subject will map to
    let user = create_test_user(&state.store, "jwt-bearer-user@example.com").await;

    // Generate ES256 key pair for the trusted issuer
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();

    // Create trusted issuer
    let issuer_url = "https://trusted-issuer.example.com";
    let issuer = db::create_trusted_jwt_issuer(
        &state.store,
        issuer_url,
        "Test Trusted Issuer",
        None,
        "https://trusted-issuer.example.com/.well-known/jwks.json",
        Some("email"), // Map sub claim to email
        Some("openid email"),
        Some(3600),
    )
    .await
    .expect("Failed to create trusted issuer");

    // Pre-populate JWKS cache so we don't need an actual HTTP server
    let jwks_json = serde_json::to_string(&serde_json::json!({
        "keys": [jwk]
    }))
    .unwrap();
    db::update_issuer_jwks_cache(&state.store, &issuer.id, &jwks_json)
        .await
        .expect("Failed to update JWKS cache");

    // Build JWT assertion for the bearer grant
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": issuer_url,
        "sub": user.email,
        "aud": state.config().base_url,
        "iat": now,
        "exp": now + 60,
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer\
         &assertion={}&scope=openid email",
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "JWT bearer grant should succeed: {resp_body}"
    );
    let response: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert!(
        response.get("access_token").is_some(),
        "Response should contain access_token"
    );
    assert_eq!(response["token_type"], "Bearer");
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_jti_replay() {
    // RFC 7523 Section 3: JTI replay detection for JWT bearer grants.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jwt-bearer-replay@example.com").await;
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();

    let issuer_url = "https://replay-issuer.example.com";
    let issuer = db::create_trusted_jwt_issuer(
        &state.store,
        issuer_url,
        "Replay Test Issuer",
        None,
        "https://replay-issuer.example.com/jwks",
        Some("email"),
        Some("openid"),
        Some(3600),
    )
    .await
    .expect("Failed to create issuer");

    let jwks_json = serde_json::to_string(&serde_json::json!({ "keys": [jwk] })).unwrap();
    db::update_issuer_jwks_cache(&state.store, &issuer.id, &jwks_json)
        .await
        .expect("Failed to update cache");

    let fixed_jti = "bearer-replay-jti-99";
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "JWT", "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": issuer_url,
        "sub": user.email,
        "aud": state.config().base_url,
        "iat": now,
        "exp": now + 60,
        "jti": fixed_jti
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={}",
        assertion
    );

    // First use should succeed
    let (status1, resp1) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert_eq!(
        status1,
        StatusCode::OK,
        "First JWT bearer grant should succeed: {resp1}"
    );

    // Replay with same JTI should fail
    let (status2, resp2) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status2 == StatusCode::BAD_REQUEST || status2 == StatusCode::UNAUTHORIZED,
        "JWT bearer grant JTI replay should be rejected, got {status2}: {resp2}"
    );
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_unknown_issuer() {
    // RFC 7523: JWT bearer grant from an unknown issuer should be rejected.
    let (app, _state) = test_app().await;

    let (pkcs8_bytes, _jwk) = generate_es256_signing_key();

    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "JWT", "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": "https://unknown-issuer.example.com",
        "sub": "someone@example.com",
        "aud": "https://test.example.com",
        "iat": now,
        "exp": now + 60,
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={}",
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Unknown issuer should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_user_not_found() {
    // RFC 7523: JWT bearer grant with valid issuer but unmapped user should fail.
    let (app, state) = test_app().await;

    let (pkcs8_bytes, jwk) = generate_es256_signing_key();

    let issuer_url = "https://no-user-issuer.example.com";
    let issuer = db::create_trusted_jwt_issuer(
        &state.store,
        issuer_url,
        "No User Issuer",
        None,
        "https://no-user-issuer.example.com/jwks",
        Some("email"),
        Some("openid"),
        Some(3600),
    )
    .await
    .expect("Failed to create issuer");

    let jwks_json = serde_json::to_string(&serde_json::json!({ "keys": [jwk] })).unwrap();
    db::update_issuer_jwks_cache(&state.store, &issuer.id, &jwks_json)
        .await
        .expect("Failed to update cache");

    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "JWT", "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": issuer_url,
        "sub": "nonexistent@example.com",
        "aud": state.config().base_url,
        "iat": now,
        "exp": now + 60,
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={}",
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Unmapped user should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_missing_assertion_handler() {
    // RFC 7523: JWT bearer grant without assertion parameter should be rejected.
    let (app, _state) = test_app().await;

    let body = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer";

    let (status, resp_body) = http_post_form(&app, "/oauth/token", body, &[]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Missing assertion should be rejected: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_lifetime_exceeded() {
    // RFC 7523 Section 3: JWT assertion lifetime exceeding issuer max must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jwt-bearer-long@example.com").await;
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();

    let issuer_url = "https://short-lifetime-issuer.example.com";
    let issuer = db::create_trusted_jwt_issuer(
        &state.store,
        issuer_url,
        "Short Lifetime Issuer",
        None,
        "https://short-lifetime-issuer.example.com/jwks",
        Some("email"),
        Some("openid"),
        Some(60), // Max 60 seconds
    )
    .await
    .expect("Failed to create issuer");

    let jwks_json = serde_json::to_string(&serde_json::json!({ "keys": [jwk] })).unwrap();
    db::update_issuer_jwks_cache(&state.store, &issuer.id, &jwks_json)
        .await
        .expect("Failed to update cache");

    // Build assertion that exceeds max lifetime (iat to exp > 60s)
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "JWT", "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": issuer_url,
        "sub": user.email,
        "aud": state.config().base_url,
        "iat": now,
        "exp": now + 600, // 10 minutes > max 60 seconds
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={}",
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Excessive lifetime should be rejected, got {status}: {resp_body}"
    );
}
