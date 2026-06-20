// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FAPI 2.0 Security Profile integration tests.
//!
//! Tests for Financial-grade API Security Profile 2.0 compliance, covering:
//! - DPoP authorization code binding (`dpop_jkt`)
//! - PAR requirement for FAPI clients
//! - `private_key_jwt` requirement for FAPI clients
//! - DPoP requirement at the token endpoint for FAPI clients
//! - Discovery document algorithm lists (RS256 excluded)
//! - `x-fapi-interaction-id` header propagation
//!
//! Reference: <https://openid.net/specs/fapi-security-profile-2_0-final.html>

use super::helpers::*;
use crate::db::TokenEndpointAuthMethod;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

// ========================================================================
// FAPI Helper Functions
// ========================================================================

/// Generate an ES256 signing key for use as a client authentication key.
///
/// Returns `(pkcs8_bytes, jwk)` where `jwk` includes the public key in JWK
/// format with `"use": "sig"` and `"alg": "ES256"`.
fn generate_es256_signing_key() -> (Vec<u8>, serde_json::Value) {
    use aws_lc_rs::signature::KeyPair;

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("Failed to generate key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .expect("Failed to parse key");

    // Uncompressed public key: 0x04 || x (32 bytes) || y (32 bytes)
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

/// Sign a JWT with an ES256 key.
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

/// Build a `private_key_jwt` client assertion (RFC 7523 Section 2.2).
///
/// Per RFC 7523, the audience must be the token endpoint URL even when the
/// assertion is used at the PAR endpoint.
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
    claims["jti"] = serde_json::json!(jti.unwrap_or(&uuid::Uuid::now_v7().to_string()));
    sign_jwt_assertion(pkcs8_bytes, &header, &claims)
}

/// Build a signed JAR Request Object JWT (RFC 9101).
fn build_request_object(
    client_id: &str,
    redirect_uri: &str,
    audience: &str,
    pkcs8_bytes: &[u8],
) -> String {
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": client_id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + 60,
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "code_challenge": sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "code_challenge_method": "S256"
    });
    sign_jwt_assertion(pkcs8_bytes, &header, &claims)
}

/// Generate an EC P-256 DPoP key pair.
///
/// Returns `(key_pair, jwk)` where the JWK contains the public key fields
/// suitable for embedding in a DPoP proof header.
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

    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y
    });

    (key_pair, jwk)
}

/// Create and sign a DPoP proof JWT.
fn create_dpop_proof(
    key_pair: &EcdsaKeyPair,
    jwk: &serde_json::Value,
    method: &str,
    uri: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
) -> String {
    use aws_lc_rs::digest;

    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());

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
        let hash = digest::digest(&digest::SHA256, token.as_bytes());
        let ath = URL_SAFE_NO_PAD.encode(hash.as_ref());
        claims["ath"] = serde_json::json!(ath);
    }

    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign DPoP proof");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    format!("{header_b64}.{claims_b64}.{sig_b64}")
}

/// Acquire a DPoP nonce by performing a probe request that will fail with
/// `use_dpop_nonce`. Returns the nonce from the `DPoP-Nonce` response header.
async fn acquire_dpop_nonce(
    app: &axum::Router,
    dpop_key: &EcdsaKeyPair,
    dpop_jwk: &serde_json::Value,
    method: &str,
    uri: &str,
) -> String {
    let proof = create_dpop_proof(dpop_key, dpop_jwk, method, uri, None, None);

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
        .expect("Server must return DPoP-Nonce header on probe request")
        .to_str()
        .expect("DPoP-Nonce must be valid UTF-8")
        .to_string()
}

/// Compute a JWK thumbprint (RFC 7638) for an EC P-256 key.
///
/// The canonical form for EC keys is `{"crv":"...","kty":"...","x":"...","y":"..."}`.
fn compute_jwk_thumbprint(jwk: &serde_json::Value) -> String {
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk["crv"].as_str().unwrap(),
        jwk["kty"].as_str().unwrap(),
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap(),
    );
    sha256_base64url(&canonical)
}

/// Create a FAPI 2.0-compliant test OAuth client.
///
/// Upgrades a standard test client to FAPI 2.0 by:
/// 1. Generating an ES256 key pair
/// 2. Setting the inline JWKS
/// 3. Setting `token_endpoint_auth_method = private_key_jwt`
/// 4. Setting `fapi_profile = Fapi2Security`
///
/// Returns `(TestOAuthClient, pkcs8_bytes)`.
async fn create_fapi_test_client(
    store: &db::store::DocumentStore,
    user_id: &str,
) -> (TestOAuthClient, Vec<u8>) {
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();
    let jwks_value = serde_json::json!({ "keys": [jwk] });

    let client = create_test_client(
        store,
        user_id,
        TestClientSpec {
            jwks: TestJwks::Custom(jwks_value),
            token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::PrivateKeyJwt),
            ..Default::default()
        },
    )
    .await;

    db::update_oauth_client_fapi_settings(
        store,
        &client.app_id,
        db::FapiProfile::Fapi2Security,
        true,
    )
    .await
    .expect("Failed to set FAPI profile on FAPI client");

    (client, pkcs8_bytes)
}

// ========================================================================
// CRITICAL — DPoP Code Binding
// ========================================================================

#[tokio::test]
async fn test_fapi2_dpop_code_binding_matching_key() {
    // FAPI 2.0: An auth code issued with dpop_jkt can be exchanged using the
    // same DPoP key. The token endpoint must accept the request.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-match@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_fapi_test_client(&state.store, &user.id).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let jkt = compute_jwk_thumbprint(&dpop_jwk);

    // Issue an auth code with the DPoP key thumbprint bound to it
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
            dpop_jkt: Some(&jkt),
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::FAPI_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
        },
    )
    .await
    .expect("Failed to issue auth code with dpop_jkt");

    // Acquire DPoP nonce
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;

    // Exchange code with matching DPoP key + nonce + private_key_jwt
    // aud must be the issuer URL (base_url), not the token endpoint URL
    let dpop_proof =
        create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);
    let assertion = build_client_assertion(
        &client.client_id,
        &state.config().base_url,
        &pkcs8_bytes,
        None,
    );

    let body = format!(
        "grant_type=authorization_code\
         &code={}\
         &redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion,
    );

    let response = http_post_form_full(&app, "/oauth/token", &body, &[("DPoP", &dpop_proof)]).await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "FAPI 2.0 token exchange with matching DPoP key must succeed: {}",
        response.body
    );
    let token_response: serde_json::Value =
        serde_json::from_str(&response.body).expect("Valid JSON");
    assert!(
        token_response.get("access_token").is_some(),
        "Response must contain access_token"
    );
}

#[tokio::test]
async fn test_fapi2_dpop_code_binding_mismatching_key() {
    // FAPI 2.0: An auth code issued with dpop_jkt from key A cannot be
    // exchanged using DPoP key B. Expect `invalid_grant`.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-mismatch@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_fapi_test_client(&state.store, &user.id).await;

    // Key A is bound to the auth code
    let (_key_a, jwk_a) = generate_dpop_key_pair();
    let jkt_a = compute_jwk_thumbprint(&jwk_a);

    // Key B will be used at the token endpoint
    let (dpop_key_b, dpop_jwk_b) = generate_dpop_key_pair();

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
            dpop_jkt: Some(&jkt_a),
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::FAPI_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
        },
    )
    .await
    .expect("Failed to issue auth code");

    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key_b, &dpop_jwk_b, "POST", &token_uri).await;

    // Exchange code with key B (wrong key)
    // aud must be the issuer URL (base_url), not the token endpoint URL
    let dpop_proof = create_dpop_proof(
        &dpop_key_b,
        &dpop_jwk_b,
        "POST",
        &token_uri,
        Some(&nonce),
        None,
    );
    let assertion = build_client_assertion(
        &client.client_id,
        &state.config().base_url,
        &pkcs8_bytes,
        None,
    );

    let body = format!(
        "grant_type=authorization_code\
         &code={}\
         &redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion,
    );

    let response = http_post_form_full(&app, "/oauth/token", &body, &[("DPoP", &dpop_proof)]).await;

    assert!(
        response.status == StatusCode::BAD_REQUEST || response.status == StatusCode::UNAUTHORIZED,
        "Mismatched DPoP key must be rejected, got: {} — {}",
        response.status,
        response.body
    );

    let error: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Error must be invalid_grant for DPoP key mismatch, got: {}",
        error
    );
}

#[tokio::test]
async fn test_fapi2_dpop_code_binding_missing_dpop_at_token() {
    // FAPI 2.0: Auth code with dpop_jkt set cannot be exchanged without a DPoP
    // header at the token endpoint.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-nodpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_fapi_test_client(&state.store, &user.id).await;

    let (_dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let jkt = compute_jwk_thumbprint(&dpop_jwk);

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
            dpop_jkt: Some(&jkt),
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::FAPI_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
        },
    )
    .await
    .expect("Failed to issue auth code with dpop_jkt");

    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let assertion = build_client_assertion(&client.client_id, &token_uri, &pkcs8_bytes, None);

    // Exchange WITHOUT any DPoP header
    let body = format!(
        "grant_type=authorization_code\
         &code={}\
         &redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion,
    );

    let (status, body_str) = http_post_form(&app, "/oauth/token", &body, &[]).await;

    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Token exchange without DPoP for FAPI client must be rejected, got: {status} — {body_str}"
    );
}

// ========================================================================
// HIGH — FAPI Rejection Scenarios
// ========================================================================

#[tokio::test]
async fn test_fapi2_authorize_rejects_without_par() {
    // FAPI 2.0 Section 5.2.2: FAPI clients MUST use PAR.
    // A direct GET /oauth/authorize without request_uri must return an error page.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-nopar@example.com").await;
    let (client, _pkcs8_bytes) = create_fapi_test_client(&state.store, &user.id).await;

    // Send a direct authorize request without request_uri
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}\
         &code_challenge_method=S256&scope=openid",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
        challenge,
    );

    let (status, body) = http_get(&app, &uri, &[]).await;

    // FAPI 2.0 validation failure shows an error page (HTML) or redirect with error.
    // The response should NOT be a successful 200 OK consent page.
    assert!(
        status != StatusCode::OK
            || body.contains("error")
            || body.contains("invalid_request")
            || body.contains("PAR"),
        "FAPI client without PAR must not succeed, got {status}: first 200 chars: {}",
        &body.chars().take(200).collect::<String>()
    );
}

#[tokio::test]
async fn test_fapi2_par_accepts_private_key_jwt() {
    // FAPI 2.0 Section 5.2.2: FAPI clients must use private_key_jwt.
    // Verify that a FAPI client using the correct private_key_jwt authentication
    // is accepted at the PAR endpoint.
    //
    // NOTE: FAPI now requires aud = issuer URL (base_url), not the token endpoint URL.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-par-pkjwt@example.com").await;
    let (client, pkcs8_bytes) = create_fapi_test_client(&state.store, &user.id).await;

    // JWT assertion audience must be the issuer URL (base_url)
    let assertion = build_client_assertion(
        &client.client_id,
        &state.config().base_url,
        &pkcs8_bytes,
        None,
    );

    let redirect_uri = "https://example.com/callback";
    let request_object = build_request_object(
        &client.client_id,
        redirect_uri,
        &state.config().base_url,
        &pkcs8_bytes,
    );

    let body = format!(
        "client_id={}\
         &request={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        client.client_id,
        urlencoding::encode(&request_object),
        assertion,
    );

    let (status, response_body) = http_post_form(&app, "/oauth/par", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "FAPI client with private_key_jwt at PAR must be accepted: {response_body}"
    );

    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert!(
        json["request_uri"].is_string(),
        "Response must include request_uri"
    );
    assert!(
        json["expires_in"].is_number(),
        "Response must include expires_in"
    );
}

#[tokio::test]
async fn test_fapi2_token_rejects_without_dpop() {
    // FAPI 2.0 Section 5.2.2: Sender-constrained tokens are required.
    // A FAPI client that authenticates with private_key_jwt but omits the
    // DPoP header must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-token-nodpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_fapi_test_client(&state.store, &user.id).await;

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
            // No DPoP binding on the code itself
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::FAPI_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
        },
    )
    .await
    .expect("Failed to issue auth code");

    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let assertion = build_client_assertion(&client.client_id, &token_uri, &pkcs8_bytes, None);

    // No DPoP header
    let body = format!(
        "grant_type=authorization_code\
         &code={}\
         &redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion,
    );

    let (status, response_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;

    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "FAPI token request without DPoP must be rejected, got: {status} — {response_body}"
    );
}

#[tokio::test]
async fn test_fapi2_non_fapi_client_standard_flow() {
    // Regression guard: A standard (non-FAPI) client can still use PAR +
    // authorization code flow without DPoP.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-std-flow@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Use PAR to obtain a request_uri
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let par_body = format!(
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
    let (par_status, par_body_str) = http_post_form(
        &app,
        "/oauth/par",
        &par_body,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        par_status,
        StatusCode::CREATED,
        "Standard client PAR should succeed: {par_body_str}"
    );

    // Issue an auth code via the service (simulating a completed authorization)
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
    .expect("Failed to issue auth code");

    // Exchange without DPoP (standard client does not require it)
    let (status, response_body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Standard client token exchange without DPoP must succeed: {response_body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert!(
        resp.get("access_token").is_some(),
        "Response must have access_token"
    );
}

#[tokio::test]
async fn test_fapi2_non_fapi_client_secret_basic() {
    // Regression guard: A standard (non-FAPI) client can authenticate at PAR
    // using client_secret_basic.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-std-basic@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let par_body = format!(
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
        &par_body,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Standard client with Basic auth at PAR must succeed: {response_body}"
    );

    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert!(
        json["request_uri"].is_string(),
        "Response must include request_uri"
    );
    assert!(
        json["expires_in"].is_number(),
        "Response must include expires_in"
    );
}

// ========================================================================
// HIGH — Discovery & Headers
// ========================================================================

#[tokio::test]
async fn test_fapi2_discovery_excludes_rs256() {
    // FAPI 2.0 Section 5.2.2: RS256 must NOT appear in any algorithm list.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // FAPI 2.0 Section 5.2.2 restricts RS256 from DPoP and token endpoint auth signing.
    // request_object_signing_alg_values_supported intentionally includes RS256 to support
    // OIDC Basic Profile conformance (oidcc-request-uri-signed-rs256). The JAR validator
    // enforces PS256/ES256/EdDSA for FAPI clients at runtime via validate_fapi_algorithm().
    let alg_fields = [
        "token_endpoint_auth_signing_alg_values_supported",
        "dpop_signing_alg_values_supported",
    ];

    for field in &alg_fields {
        if let Some(arr) = doc[field].as_array() {
            assert!(
                !arr.iter().any(|v| v.as_str() == Some("RS256")),
                "RS256 must not appear in {field}: {:?}",
                arr
            );
        }
    }
}

#[tokio::test]
async fn test_fapi2_discovery_includes_fapi_algorithms() {
    // FAPI 2.0 Section 5.2.2: PS256, ES256, EdDSA must be in signing algorithm lists.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let required_algs = ["PS256", "ES256", "EdDSA"];

    // DPoP and token endpoint signing alg lists must include FAPI algorithms
    let checked_fields = [
        "dpop_signing_alg_values_supported",
        "token_endpoint_auth_signing_alg_values_supported",
    ];

    for field in &checked_fields {
        if let Some(arr) = doc[field].as_array() {
            let arr_strs: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            for alg in &required_algs {
                assert!(
                    arr_strs.contains(alg),
                    "Algorithm {alg} must appear in {field}: {:?}",
                    arr_strs
                );
            }
        }
    }
}

#[tokio::test]
async fn test_fapi2_discovery_tls_client_certificate_field() {
    // FAPI 2.0: Discovery must include `tls_client_certificate_bound_access_tokens`.
    // Currently we support DPoP but not mTLS, so the value should be false.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert!(
        doc["tls_client_certificate_bound_access_tokens"].is_boolean(),
        "Discovery must include tls_client_certificate_bound_access_tokens"
    );
    assert_eq!(
        doc["tls_client_certificate_bound_access_tokens"], false,
        "tls_client_certificate_bound_access_tokens must be false (DPoP only)"
    );
}

#[tokio::test]
async fn test_fapi2_interaction_id_header_generated() {
    // FAPI 2.0: Server must include `x-fapi-interaction-id` in all responses.
    // This test uses a router with the production request ID middleware applied.
    let (app, _state) = test_app().await;

    let response = http_get_full(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(response.status, StatusCode::OK);
    assert!(
        response.headers.get("x-fapi-interaction-id").is_some(),
        "Response must include x-fapi-interaction-id header"
    );

    // Must be a non-empty value (server-generated UUID)
    let id = response
        .headers
        .get("x-fapi-interaction-id")
        .unwrap()
        .to_str()
        .expect("x-fapi-interaction-id must be valid UTF-8");
    assert!(!id.is_empty(), "x-fapi-interaction-id must not be empty");
}

#[tokio::test]
async fn test_fapi2_interaction_id_header_echoed() {
    // FAPI 2.0: If the client sends `x-fapi-interaction-id`, the server must
    // echo the same value in the response.
    // This test uses a router with the production request ID middleware applied.
    let (app, _state) = test_app().await;

    let client_id = "test-interaction-id-12345-abcde";

    let response = http_get_full(
        &app,
        "/.well-known/openid-configuration",
        &[("x-fapi-interaction-id", client_id)],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);

    let echoed = response
        .headers
        .get("x-fapi-interaction-id")
        .expect("x-fapi-interaction-id must be present in response")
        .to_str()
        .expect("x-fapi-interaction-id must be valid UTF-8");

    assert_eq!(
        echoed, client_id,
        "Server must echo the client-provided x-fapi-interaction-id"
    );
}

#[tokio::test]
async fn test_discovery_mtls_aliases_absent_without_tls() {
    // When TLS is not configured, mtls_endpoint_aliases must be absent
    // from the discovery document (test_app() has no TLS cert).
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    assert!(
        doc.get("mtls_endpoint_aliases").is_none(),
        "mtls_endpoint_aliases must be absent when TLS is not configured, got: {:?}",
        doc.get("mtls_endpoint_aliases")
    );
    assert_eq!(
        doc["tls_client_certificate_bound_access_tokens"], false,
        "tls_client_certificate_bound_access_tokens must be false when TLS is not configured"
    );
}

#[tokio::test]
async fn test_discovery_tls_client_auth_in_auth_methods_with_tls() {
    // When TLS is configured, token_endpoint_auth_methods_supported must include
    // tls_client_auth and self_signed_tls_client_auth, and mtls_endpoint_aliases
    // must be present.
    //
    // Build a fresh AppState with a TLS cert set — test_app() has tls_cert: None.
    use crate::services::oidc::discovery::build_discovery_document;
    use crate::test_utils::{test_config, test_db};
    use arc_swap::ArcSwap;
    use std::sync::Arc;

    let pool = test_db().await;
    let mut config = test_config();
    // Set a placeholder TLS cert to enable mTLS discovery advertisement.
    config.tls_cert = Some("placeholder-cert".to_string());

    let rp_origin = url::Url::parse(&config.base_url).expect("base_url");
    let webauthn = webauthn_rs::WebauthnBuilder::new(&config.rp_id, &rp_origin)
        .expect("WebauthnBuilder")
        .rp_name(&config.rp_name)
        .build()
        .expect("Webauthn");

    let oidc_key = crate::services::oidc::OidcSigningKey::generate().expect("oidc key");

    let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
        Arc::new(crate::crypto::document_crypto::PlaintextDocumentCrypto);
    let store = crate::db::store::DocumentStore::new(pool.clone(), crypto.clone());
    let audit = crate::db::audit::AuditStore::new(pool.clone(), crypto);

    let state = Arc::new(crate::AppState {
        db: pool,
        store,
        audit,
        config: Arc::new(ArcSwap::from_pointee(config)),
        webauthn,
        ssh_ca: None,
        oidc_key,
        oidc_rsa_key: None,
        state_signer: crate::crypto::jwt::StateTokenSigner::local(
            b"test_jwt_secret_must_be_at_least_32_characters_long".to_vec(),
        ),
        github_app: None,
        http_client: reqwest::Client::new(),
        session_cache: crate::db::SessionCache::new(10_000, 30),
        idps: Vec::new(),
    });

    let doc = build_discovery_document(&state);

    assert!(
        doc.tls_client_certificate_bound_access_tokens,
        "tls_client_certificate_bound_access_tokens must be true when TLS is configured"
    );
    assert!(
        doc.token_endpoint_auth_methods_supported
            .contains(&TokenEndpointAuthMethod::TlsClientAuth),
        "tls_client_auth must appear in token_endpoint_auth_methods_supported"
    );
    assert!(
        doc.token_endpoint_auth_methods_supported
            .contains(&TokenEndpointAuthMethod::SelfSignedTlsClientAuth),
        "self_signed_tls_client_auth must appear in token_endpoint_auth_methods_supported"
    );
    assert!(
        doc.mtls_endpoint_aliases.is_some(),
        "mtls_endpoint_aliases must be present when TLS is configured"
    );
}
