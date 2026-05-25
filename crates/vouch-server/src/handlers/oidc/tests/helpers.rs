// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared test helpers and re-exported imports for OIDC test modules.

pub(super) use crate::db;
pub(super) use crate::services::oidc::ScopeSet;
pub(super) use crate::services::oidc::authorization::{
    AuthorizationCodeParams, CodeChallengeMethod, issue_authorization_code,
};
pub(super) use crate::test_utils::*;
pub(super) use aws_lc_rs::digest::SHA256;
pub(super) use axum::http::StatusCode;
pub(super) use base64::Engine;
pub(super) use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Create an authorization code and exchange it at `/oauth/token` to get an access token.
/// Returns `(access_token, id_token)`.
pub(super) async fn issue_oauth_access_token(
    app: &axum::Router,
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    auth_id: &str,
    client: &TestOAuthClient,
) -> (String, String) {
    issue_oauth_access_token_with_scope(app, state, user, auth_id, client, "openid email").await
}

/// Create an authorization code with a specific scope and exchange it at `/oauth/token`.
/// Uses the real `issue_authorization_code()` service function to exercise the full
/// code path including server-side code storage for single-use enforcement.
/// Returns `(access_token, id_token)`.
pub(super) async fn issue_oauth_access_token_with_scope(
    app: &axum::Router,
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    auth_id: &str,
    client: &TestOAuthClient,
    scope: &str,
) -> (String, String) {
    use crate::services::oidc::authorization::{AuthorizationCodeParams, issue_authorization_code};

    let scope_set = ScopeSet::parse(scope);

    let code_params = AuthorizationCodeParams {
        client_id: &client.client_id,
        redirect_uri: "https://example.com/callback",
        user_id: &user.id,
        email: &user.email,
        authenticator_id: auth_id,
        aaguid: None,
        scope: &scope_set,
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        resource: None,
        acr_values: None,
        dpop_jkt: None,
        // Use standard lifetime for test helpers; FAPI enforcement tested separately.
        auth_code_lifetime_seconds:
            crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
        authorization_details: None,
        auth_time: None,
    };

    let code = issue_authorization_code(state, code_params)
        .await
        .expect("Failed to issue authorization code");

    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Token exchange should succeed: {}",
        body
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let access_token = response["access_token"]
        .as_str()
        .expect("access_token present")
        .to_string();
    let id_token = response["id_token"]
        .as_str()
        .expect("id_token present")
        .to_string();

    (access_token, id_token)
}

// ========================================================================
// JWT Client Authentication Helpers (shared across rfc7009, rfc7523, rfc7662)
// ========================================================================

pub(super) use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

/// Generate an ES256 signing key pair. Returns (pkcs8_bytes, JWK public key).
pub(super) fn generate_es256_signing_key() -> (Vec<u8>, serde_json::Value) {
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
pub(super) fn sign_jwt_assertion(
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
pub(super) async fn create_test_jwt_client(
    store: &db::store::DocumentStore,
    user_id: &str,
) -> (TestOAuthClient, Vec<u8>) {
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();

    let client = create_test_oauth_client(store, user_id).await;

    let oauth_client = db::get_oauth_client_by_client_id(store, &client.client_id)
        .await
        .expect("DB error")
        .expect("Client not found");

    let jwks_value = serde_json::json!({
        "keys": [jwk]
    });
    db::update_oauth_client_jwks(store, &oauth_client.id, &jwks_value)
        .await
        .expect("Failed to set JWKS");

    db::update_oauth_client_auth_method(store, &oauth_client.id, "private_key_jwt")
        .await
        .expect("Failed to set auth method");

    (client, pkcs8_bytes)
}

/// Build a JWT assertion for `private_key_jwt` client auth (RFC 7523 Section 2.2).
pub(super) fn build_client_assertion(
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

/// Build a JWT assertion for `private_key_jwt` client auth, deliberately
/// omitting the `jti` claim. RFC 7523 §3 makes `jti` OPTIONAL for non-FAPI
/// clients; this helper exercises that path. Use only with non-FAPI clients —
/// FAPI 2.0 §5.3.2.1 requires `jti`.
pub(super) fn build_client_assertion_omit_jti(
    client_id: &str,
    audience: &str,
    pkcs8_bytes: &[u8],
) -> String {
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + 60
    });
    sign_jwt_assertion(pkcs8_bytes, &header, &claims)
}

/// Decode a JWT payload (middle part) without signature verification.
pub(super) fn decode_jwt_payload(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert!(parts.len() >= 2, "JWT should have at least 2 parts");
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).expect("Valid base64");
    serde_json::from_slice(&payload).expect("Valid JSON")
}

/// Compute SHA-256 of `input` and encode as base64url (no padding).
pub(super) fn sha256_base64url(input: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&SHA256, input.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}
