// SPDX-License-Identifier: BUSL-1.1
//! RFC 9449 — DPoP (Demonstration of Proof of Possession) tests.

use super::helpers::*;

// ========================================================================
// DPoP Helper Functions
// ========================================================================

/// Helper: Generate an EC P-256 key pair and return (signing_key, DPoP JWK header fields).
fn generate_dpop_key_pair() -> (aws_lc_rs::signature::EcdsaKeyPair, serde_json::Value) {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("Failed to generate key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .expect("Failed to parse key");

    // Extract x/y coordinates from uncompressed public key (65 bytes: 0x04 || x || y)
    let pub_bytes = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);

    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y
    });

    (key_pair, jwk)
}

/// Helper: Create and sign a DPoP proof JWT for the given method and URI.
fn create_dpop_proof(
    key_pair: &aws_lc_rs::signature::EcdsaKeyPair,
    jwk: &serde_json::Value,
    method: &str,
    uri: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
) -> String {
    use aws_lc_rs::digest;

    // Build header
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());

    // Build claims
    let jti = uuid::Uuid::now_v7().to_string();
    let now = jiff::Timestamp::now().as_second();
    let mut claims = serde_json::json!({
        "jti": jti,
        "htm": method,
        "htu": uri,
        "iat": now
    });

    if let Some(n) = nonce {
        claims["nonce"] = serde_json::json!(n);
    }

    if let Some(token) = access_token {
        // Compute ath (access token hash)
        let hash = digest::digest(&digest::SHA256, token.as_bytes());
        let ath = URL_SAFE_NO_PAD.encode(hash.as_ref());
        claims["ath"] = serde_json::json!(ath);
    }

    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());

    // Sign with ES256
    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign DPoP proof");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    format!("{}.{}.{}", header_b64, claims_b64, sig_b64)
}

/// Helper: Acquire a DPoP nonce by submitting a proof without one to the token endpoint.
///
/// Nonces are always required (RFC 9449 Section 8). This helper performs the
/// `use_dpop_nonce` round-trip and returns the server-provided nonce.
async fn acquire_dpop_nonce(
    app: &axum::Router,
    dpop_key: &aws_lc_rs::signature::EcdsaKeyPair,
    dpop_jwk: &serde_json::Value,
    method: &str,
    uri: &str,
) -> String {
    let proof = create_dpop_proof(dpop_key, dpop_jwk, method, uri, None, None);

    // Submit a token exchange request that will fail with use_dpop_nonce.
    // The specific grant_type body doesn't matter — DPoP validation happens first.
    let response = http_post_form_full(
        app,
        "/oauth/token",
        "grant_type=authorization_code&code=dummy",
        &[("DPoP", &proof)],
    )
    .await;

    response
        .headers
        .get("DPoP-Nonce")
        .expect("Server must return DPoP-Nonce header")
        .to_str()
        .expect("DPoP-Nonce must be valid UTF-8")
        .to_string()
}

// ========================================================================
// DPoP Integration Tests (RFC 9449)
// ========================================================================

#[tokio::test]
async fn test_dpop_token_exchange_with_proof() {
    // RFC 9449: Token endpoint should accept DPoP proof and return DPoP-bound token
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-exchange@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Generate DPoP key pair and acquire nonce
    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;

    let dpop_proof =
        create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let auth_header = client.basic_auth_header();

    // Token exchange with DPoP proof
    let response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[
            ("Authorization", &auth_header),
            ("DPoP", &dpop_proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "DPoP token exchange should succeed: {}",
        response.body
    );
    let body: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert!(
        body.get("access_token").is_some(),
        "Should return access_token"
    );

    // RFC 9449 Section 5: token_type should be "DPoP" when DPoP was used
    let token_type = body["token_type"].as_str().unwrap_or("");
    assert_eq!(
        token_type, "DPoP",
        "Token type should be DPoP when DPoP proof is provided"
    );
}

#[tokio::test]
async fn test_dpop_userinfo_with_dpop_scheme() {
    // RFC 9449 Section 7.1: UserInfo with DPoP-bound token and DPoP authorization scheme
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-userinfo@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Generate DPoP key pair
    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let token_uri = format!("{}/oauth/token", state.config().base_url);

    // Get an access token with DPoP binding via token exchange
    let (subject_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Acquire nonce for token endpoint
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;

    let dpop_proof =
        create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let auth_header = client.basic_auth_header();

    let exchange_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            subject_token
        ),
        &[
            ("Authorization", &auth_header),
            ("DPoP", &dpop_proof),
        ],
    )
    .await;

    assert_eq!(
        exchange_response.status,
        StatusCode::OK,
        "Exchange should succeed: {}",
        exchange_response.body
    );
    let exchange_body: serde_json::Value =
        serde_json::from_str(&exchange_response.body).expect("Valid JSON");
    let dpop_bound_token = exchange_body["access_token"]
        .as_str()
        .expect("access_token present");

    // Acquire nonce for userinfo endpoint
    let userinfo_uri = format!("{}/oauth/userinfo", state.config().base_url);
    let userinfo_nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "GET", &userinfo_uri).await;

    // Now use the DPoP-bound token at userinfo with DPoP scheme
    let userinfo_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        &userinfo_uri,
        Some(&userinfo_nonce),
        Some(dpop_bound_token),
    );

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {}", dpop_bound_token)),
            ("DPoP", &userinfo_proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "UserInfo with DPoP scheme should succeed: {}",
        response.body
    );
    let userinfo: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert!(userinfo.get("sub").is_some(), "sub claim must be present");
}

#[tokio::test]
async fn test_dpop_userinfo_key_mismatch_rejected() {
    // RFC 9449 Section 7.1: DPoP proof made with a different key than the token binding
    // should be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-mismatch@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Generate two different DPoP key pairs
    let (dpop_key1, dpop_jwk1) = generate_dpop_key_pair();
    let (dpop_key2, dpop_jwk2) = generate_dpop_key_pair();

    // Get a DPoP-bound token using key1
    let (subject_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key1, &dpop_jwk1, "POST", &token_uri).await;

    let dpop_proof1 = create_dpop_proof(
        &dpop_key1,
        &dpop_jwk1,
        "POST",
        &token_uri,
        Some(&nonce),
        None,
    );

    let auth_header = client.basic_auth_header();

    let exchange_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            subject_token
        ),
        &[
            ("Authorization", &auth_header),
            ("DPoP", &dpop_proof1),
        ],
    )
    .await;

    assert_eq!(exchange_response.status, StatusCode::OK);
    let exchange_body: serde_json::Value =
        serde_json::from_str(&exchange_response.body).expect("Valid JSON");
    let dpop_bound_token = exchange_body["access_token"]
        .as_str()
        .expect("access_token present");

    // Acquire nonce for key2 at userinfo endpoint
    let userinfo_uri = format!("{}/oauth/userinfo", state.config().base_url);
    let userinfo_nonce =
        acquire_dpop_nonce(&app, &dpop_key2, &dpop_jwk2, "GET", &userinfo_uri).await;

    // Try to use the token with key2 (different key) — should fail
    let bad_proof = create_dpop_proof(
        &dpop_key2,
        &dpop_jwk2,
        "GET",
        &userinfo_uri,
        Some(&userinfo_nonce),
        Some(dpop_bound_token),
    );

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {}", dpop_bound_token)),
            ("DPoP", &bad_proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "DPoP with mismatched key should be rejected: {}",
        response.body
    );
}

#[tokio::test]
async fn test_dpop_scheme_without_proof_rejected() {
    // RFC 9449: Using DPoP authorization scheme without a DPoP proof header should fail
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-noproof@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("DPoP {}", token))],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "DPoP scheme without proof should be rejected: {}",
        response.body
    );
}

#[tokio::test]
async fn test_dpop_non_bound_token_with_dpop_scheme_rejected() {
    // RFC 9449 Section 7.1: Using DPoP scheme with a non-DPoP-bound token should fail
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-nonbound@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Get a regular (non-DPoP-bound) access token
    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let dpop_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        &format!("{}/oauth/userinfo", state.config().base_url),
        None,
        Some(&access_token),
    );

    // Use DPoP scheme with non-DPoP-bound token
    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {}", access_token)),
            ("DPoP", &dpop_proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "Non-DPoP-bound token with DPoP scheme should be rejected: {}",
        response.body
    );
}

// ========================================================================
// RFC 9449 — DPoP Edge Cases
// ========================================================================

#[tokio::test]
async fn test_rfc9449_jti_replay_prevention() {
    // RFC 9449 Section 10: Replaying a DPoP proof with same jti must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-replay@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let token_uri = format!("{}/oauth/token", state.config().base_url);

    // Acquire nonce and create a DPoP proof with it
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;
    let dpop_proof =
        create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let auth_header = client.basic_auth_header();

    // First use — should succeed
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &dpop_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "First DPoP proof use should succeed"
    );

    // Replay same proof (same jti) — must be rejected
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &dpop_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Replayed DPoP proof must be rejected: {}",
        body
    );
}

#[tokio::test]
async fn test_rfc9449_wrong_typ_header() {
    // RFC 9449 Section 4.1: DPoP proof with wrong typ (JWT instead of dpop+jwt) must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-typ@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Manually construct a DPoP proof with wrong typ
    let header = serde_json::json!({
        "typ": "JWT",  // Wrong! Should be "dpop+jwt"
        "alg": "ES256",
        "jwk": dpop_jwk
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());

    let jti = uuid::Uuid::now_v7().to_string();
    let now = jiff::Timestamp::now().as_second();
    let claims = serde_json::json!({
        "jti": jti,
        "htm": "POST",
        "htu": format!("{}/oauth/token", state.config().base_url),
        "iat": now
    });
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());

    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = dpop_key
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
    let bad_proof = format!("{}.{}.{}", header_b64, claims_b64, sig_b64);

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &bad_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "DPoP proof with wrong typ must be rejected"
    );
}

#[tokio::test]
async fn test_rfc9449_htm_method_mismatch() {
    // RFC 9449 Section 4.2: DPoP proof with wrong HTTP method must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-htm@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Create a proof with GET method for a POST endpoint
    let bad_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET", // Wrong! Token endpoint uses POST
        &format!("{}/oauth/token", state.config().base_url),
        None,
        None,
    );

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &bad_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "DPoP proof with wrong HTTP method must be rejected"
    );
}

#[tokio::test]
async fn test_rfc9449_htu_uri_mismatch() {
    // RFC 9449 Section 4.2: DPoP proof for a different URI must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-htu@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Create a proof for /oauth/userinfo but use it at /oauth/token
    let bad_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{}/oauth/userinfo", state.config().base_url), // Wrong URI!
        None,
        None,
    );

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &bad_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "DPoP proof for wrong URI must be rejected"
    );
}

#[tokio::test]
async fn test_rfc9449_expired_dpop_proof() {
    // RFC 9449 Section 4.2: DPoP proof with old iat must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-expired@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Manually construct a proof with iat set to 1 hour ago
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": dpop_jwk
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());

    let old_iat = jiff::Timestamp::now().as_second() - 3600; // 1 hour ago
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": "POST",
        "htu": format!("{}/oauth/token", state.config().base_url),
        "iat": old_iat
    });
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());

    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = dpop_key
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
    let expired_proof = format!("{}.{}.{}", header_b64, claims_b64, sig_b64);

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &expired_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expired DPoP proof must be rejected"
    );
}

#[tokio::test]
async fn test_rfc9449_ath_mismatch() {
    // RFC 9449 Section 7.1: DPoP proof with wrong access token hash must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-ath@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Get a DPoP-bound token
    let (subject_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;

    let dpop_proof =
        create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let auth_header = client.basic_auth_header();
    let exchange_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            subject_token
        ),
        &[
            ("Authorization", &auth_header),
            ("DPoP", &dpop_proof),
        ],
    )
    .await;

    assert_eq!(exchange_response.status, StatusCode::OK);
    let exchange_body: serde_json::Value =
        serde_json::from_str(&exchange_response.body).expect("Valid JSON");
    let dpop_bound_token = exchange_body["access_token"]
        .as_str()
        .expect("access_token present");

    // Acquire nonce for userinfo endpoint, then create a proof with wrong ath
    let userinfo_uri = format!("{}/oauth/userinfo", state.config().base_url);
    let userinfo_nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "GET", &userinfo_uri).await;

    let wrong_ath_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        &userinfo_uri,
        Some(&userinfo_nonce),
        Some("completely-wrong-token"),
    );

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {}", dpop_bound_token)),
            ("DPoP", &wrong_ath_proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "DPoP proof with wrong ath must be rejected: {}",
        response.body
    );
}

// ========================================================================
// Phase 2: Additional DPoP Tests
// ========================================================================

#[tokio::test]
async fn test_rfc9449_dpop_symmetric_algorithm_rejected() {
    // RFC 9449 Section 4.1: DPoP proof signed with symmetric algorithm (HS256)
    // must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-symm@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Build a DPoP proof with HS256 header (symmetric — must be rejected)
    let fake_jwk = serde_json::json!({
        "kty": "oct",
        "k": URL_SAFE_NO_PAD.encode(b"symmetric-key-for-testing-12345678")
    });
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "HS256",
        "jwk": fake_jwk
    });
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": "GET",
        "htu": format!("{}/oauth/userinfo", state.config().base_url),
        "iat": jiff::Timestamp::now().as_second()
    });

    // We can't actually sign this properly since DPoP requires asymmetric keys,
    // but the header declares HS256 which should be caught before signature verification.
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let fake_proof = format!("{header_b64}.{claims_b64}.fakesignature");

    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {access_token}")),
            ("DPoP", &fake_proof),
        ],
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Symmetric algorithm DPoP proof should be rejected, got: {status}"
    );
}

#[tokio::test]
async fn test_rfc9449_dpop_wrong_typ_header() {
    // RFC 9449 Section 4.1: DPoP proof with wrong typ (JWT instead of dpop+jwt)
    // must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-badtyp@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Build proof with wrong typ header
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "ES256",
        "jwk": dpop_jwk
    });
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": "GET",
        "htu": format!("{}/oauth/userinfo", state.config().base_url),
        "iat": jiff::Timestamp::now().as_second()
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = dpop_key.sign(&rng, signing_input.as_bytes()).expect("sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
    let proof = format!("{header_b64}.{claims_b64}.{sig_b64}");

    let (status, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {access_token}")),
            ("DPoP", &proof),
        ],
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Wrong typ header should be rejected, got: {status}"
    );
}

#[tokio::test]
async fn test_rfc9449_dpop_htm_mismatch() {
    // RFC 9449 Section 4.2: DPoP proof with wrong HTTP method must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-htm@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Create proof with POST method but use it on a GET request
    let proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST", // Wrong method for GET /oauth/userinfo
        &format!("{}/oauth/userinfo", state.config().base_url),
        None,
        Some(&access_token),
    );

    let (status, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {access_token}")),
            ("DPoP", &proof),
        ],
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "HTM mismatch should be rejected, got: {status}"
    );
}

#[tokio::test]
async fn test_rfc9449_dpop_htu_mismatch() {
    // RFC 9449 Section 4.2: DPoP proof for wrong URI must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-htu@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Create proof for /oauth/token but use it on /oauth/userinfo
    let proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        &format!("{}/oauth/token", state.config().base_url), // Wrong URI
        None,
        Some(&access_token),
    );

    let (status, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {access_token}")),
            ("DPoP", &proof),
        ],
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "HTU mismatch should be rejected, got: {status}"
    );
}

#[tokio::test]
async fn test_rfc9449_dpop_expired_proof() {
    // RFC 9449 Section 4.2: DPoP proof with old iat should be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-expired@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Build proof with old iat (older than max_age_seconds=300)
    let old_iat = jiff::Timestamp::now().as_second() - 600; // 10 minutes ago
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": dpop_jwk
    });
    let ath_hash = aws_lc_rs::digest::digest(&SHA256, access_token.as_bytes());
    let ath = URL_SAFE_NO_PAD.encode(ath_hash.as_ref());
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": "GET",
        "htu": format!("{}/oauth/userinfo", state.config().base_url),
        "iat": old_iat,
        "ath": ath
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = dpop_key.sign(&rng, signing_input.as_bytes()).expect("sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
    let proof = format!("{header_b64}.{claims_b64}.{sig_b64}");

    let (status, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {access_token}")),
            ("DPoP", &proof),
        ],
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Expired DPoP proof should be rejected, got: {status}"
    );
}

// ========================================================================
// RFC 9449 Section 4.3 — DPoP Nonce Required at Token Endpoint
// ========================================================================

#[tokio::test]
async fn test_rfc9449_dpop_nonce_required_token_endpoint_returns_nonce_header() {
    // RFC 9449 Section 4.3: The token endpoint MUST return error=use_dpop_nonce
    // AND a DPoP-Nonce response header when a DPoP proof without a nonce is submitted.
    // Nonces are always required per RFC 9449 Section 8.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-nonce-req@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue authorization code (no PKCE, no DPoP needed here)
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
    .expect("Failed to issue authorization code");

    // Build DPoP proof WITHOUT a nonce
    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let dpop_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{}/oauth/token", state.config().base_url),
        None, // no nonce
        None,
    );

    let auth_header = client.basic_auth_header();
    let response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &auth_header), ("DPoP", &dpop_proof)],
    )
    .await;

    // Must be an error status
    assert!(
        response.status == StatusCode::BAD_REQUEST || response.status == StatusCode::UNAUTHORIZED,
        "Token endpoint must reject DPoP proof without nonce when nonce required, got: {}",
        response.status
    );

    // Must include error=use_dpop_nonce in the body
    let error: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        error["error"], "use_dpop_nonce",
        "Error must be use_dpop_nonce when nonce is required, got: {error}"
    );

    // RFC 9449 Section 4.3: Server MUST include DPoP-Nonce response header
    assert!(
        response.headers.get("DPoP-Nonce").is_some(),
        "Server must include DPoP-Nonce header when use_dpop_nonce error is returned"
    );
}

#[tokio::test]
async fn test_rfc9449_dpop_nonce_required_retry_with_nonce_succeeds() {
    // RFC 9449 Section 4.3: After receiving use_dpop_nonce, the client MUST
    // retry with the nonce from the DPoP-Nonce response header.
    // Nonces are always required per RFC 9449 Section 8.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-nonce-retry@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue authorization code
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
    .expect("Failed to issue authorization code");

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let auth_header = client.basic_auth_header();
    let token_uri = format!("{}/oauth/token", state.config().base_url);

    // Step 1: Request without nonce — capture the DPoP-Nonce header
    let no_nonce_proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, None, None);
    let first_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &auth_header), ("DPoP", &no_nonce_proof)],
    )
    .await;

    // Should get use_dpop_nonce error with DPoP-Nonce header
    assert!(
        first_response.status == StatusCode::BAD_REQUEST
            || first_response.status == StatusCode::UNAUTHORIZED,
        "First request must be rejected: {}",
        first_response.status
    );
    let server_nonce = first_response
        .headers
        .get("DPoP-Nonce")
        .expect("DPoP-Nonce header must be present in error response")
        .to_str()
        .expect("DPoP-Nonce must be valid UTF-8")
        .to_string();

    // DPoP validation fails BEFORE code exchange, so the original code is NOT consumed.
    // Reuse the same code for the retry with the server-provided nonce.

    // Step 2: Retry with the nonce from the response header
    let nonce_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &token_uri,
        Some(&server_nonce),
        None,
    );
    let second_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &auth_header), ("DPoP", &nonce_proof)],
    )
    .await;

    assert_eq!(
        second_response.status,
        StatusCode::OK,
        "Retry with server-provided nonce must succeed: {}",
        second_response.body
    );
    let token_response: serde_json::Value =
        serde_json::from_str(&second_response.body).expect("Valid JSON");
    assert!(
        token_response.get("access_token").is_some(),
        "Successful retry must return access_token"
    );
}

// ========================================================================
// DPoP at Resource Endpoints WITHOUT Nonce (CLI Pattern)
// ========================================================================

#[tokio::test]
async fn test_dpop_resource_endpoint_without_nonce() {
    // This test replicates the exact pattern the CLI uses after login:
    // 1. Obtain a DPoP-bound access token (via token exchange with nonce)
    // 2. Use the token at a resource endpoint with DPoP proof but NO nonce
    //
    // The CLI never acquires nonces for resource endpoint requests.
    // RFC 9449 allows this: nonces are required at the token endpoint
    // (precomputation defense) but optional at resource endpoints
    // (ath provides token binding).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-no-nonce@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Step 1: Get a DPoP-bound access token
    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let token_uri = format!("{}/oauth/token", state.config().base_url);

    let (subject_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Acquire nonce for token endpoint (required there)
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;

    let dpop_proof =
        create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let auth_header = client.basic_auth_header();

    let exchange_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={subject_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header), ("DPoP", &dpop_proof)],
    )
    .await;

    assert_eq!(
        exchange_response.status,
        StatusCode::OK,
        "Token exchange should succeed: {}",
        exchange_response.body
    );
    let exchange_body: serde_json::Value =
        serde_json::from_str(&exchange_response.body).expect("Valid JSON");
    let dpop_bound_token = exchange_body["access_token"]
        .as_str()
        .expect("access_token present");
    assert_eq!(
        exchange_body["token_type"].as_str().unwrap_or(""),
        "DPoP",
        "Token type should be DPoP"
    );

    // Step 2: Use DPoP-bound token at userinfo WITHOUT a nonce
    // This is exactly what the CLI does for resource endpoint requests
    let userinfo_uri = format!("{}/oauth/userinfo", state.config().base_url);
    let resource_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        &userinfo_uri,
        None, // NO nonce — this is the CLI pattern
        Some(dpop_bound_token),
    );

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {dpop_bound_token}")),
            ("DPoP", &resource_proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "DPoP at resource endpoint without nonce should succeed: {}",
        response.body
    );
    let userinfo: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert!(userinfo.get("sub").is_some(), "sub claim must be present");
}

#[tokio::test]
async fn test_dpop_resource_endpoint_post_json_without_nonce() {
    // Same as above but with POST + JSON body (matches SSH cert endpoint pattern).
    // The SSH cert endpoint uses extract_resource_token, not userinfo's custom handler.
    // Since SSH CA is not configured in test_app, we expect 503 NOT 401.
    // Getting 503 means DPoP validation passed (401 would mean it failed).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-post-nonce@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Step 1: Get a DPoP-bound access token
    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let token_uri = format!("{}/oauth/token", state.config().base_url);

    let (subject_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;

    let dpop_proof =
        create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let auth_header = client.basic_auth_header();

    let exchange_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={subject_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header), ("DPoP", &dpop_proof)],
    )
    .await;

    assert_eq!(exchange_response.status, StatusCode::OK);
    let exchange_body: serde_json::Value =
        serde_json::from_str(&exchange_response.body).expect("Valid JSON");
    let dpop_bound_token = exchange_body["access_token"]
        .as_str()
        .expect("access_token present");

    // Step 2: Use DPoP-bound token at POST /v1/credentials/ssh (no nonce)
    let ssh_uri = format!("{}/v1/credentials/ssh", state.config().base_url);
    let resource_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &ssh_uri,
        None, // NO nonce
        Some(dpop_bound_token),
    );

    let (status, body) = http_post_json(
        &app,
        "/v1/credentials/ssh",
        r#"{"public_key":"ssh-ed25519 AAAA test@example.com"}"#,
        &[
            ("Authorization", &format!("DPoP {dpop_bound_token}")),
            ("DPoP", &resource_proof),
        ],
    )
    .await;

    // SSH CA is not configured in tests, so we expect 503 (SERVICE_UNAVAILABLE).
    // The critical assertion: NOT 401 (which would mean DPoP validation failed).
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "DPoP validation should pass (expect 503 for missing SSH CA, not 401): {body}"
    );
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "Should fail with SSH CA not configured, not auth error: {body}"
    );
}
