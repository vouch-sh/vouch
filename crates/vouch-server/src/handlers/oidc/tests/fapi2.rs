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
    vouch_common::jwk::JwkThumbprintKey::from_json(jwk)
        .expect("test JWK carries the required members")
        .thumbprint()
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
            fapi_profile: Some(db::FapiProfile::Fapi2Security),
            dpop_bound_access_tokens: true,
            ..Default::default()
        },
    )
    .await;

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
            par: crate::db::ParConsumptionProof::not_pushed(),
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
            par: crate::db::ParConsumptionProof::not_pushed(),
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
            par: crate::db::ParConsumptionProof::not_pushed(),
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
    // FAPI 2.0 Section 5.3.2.2: FAPI clients MUST use PAR.
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
        body.chars().take(200).collect::<String>()
    );
}

#[tokio::test]
async fn test_fapi2_par_accepts_private_key_jwt() {
    // FAPI 2.0 Section 5.3.2.1: FAPI clients must use private_key_jwt.
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

/// FAPI 2.0 Section 5.3.2.1: the auth-method gate must judge the method the
/// request ACTUALLY authenticated with, not the registered one. A stale
/// client secret on a client registered as private_key_jwt must be
/// rejected at PAR (#706).
#[tokio::test]
async fn test_fapi2_par_rejects_client_secret_for_private_key_jwt_client() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-par-stale-secret@example.com").await;
    let (client, _pkcs8_bytes) = create_fapi_test_client(&state.store, &user.id).await;

    // Authenticate with the (stale) client secret instead of a JWT assertion.
    let body = format!(
        "client_id={}\
         &client_secret={}\
         &redirect_uri={}\
         &response_type=code\
         &scope=openid",
        client.client_id,
        urlencoding::encode(&client.client_secret),
        urlencoding::encode("https://example.com/callback"),
    );

    let (status, response_body) = http_post_form(&app, "/oauth/par", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "FAPI client authenticating with a secret must be rejected at PAR: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client", "{json}");
}

/// FAPI clients presenting only a client_id (public-client arm, no
/// credential at all) must also fail the actual-method gate at PAR.
#[tokio::test]
async fn test_fapi2_par_rejects_client_id_only_for_private_key_jwt_client() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-par-id-only@example.com").await;
    let (client, _pkcs8_bytes) = create_fapi_test_client(&state.store, &user.id).await;

    let body = format!(
        "client_id={}\
         &redirect_uri={}\
         &response_type=code\
         &scope=openid",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
    );

    let (status, response_body) = http_post_form(&app, "/oauth/par", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "FAPI client with no credential must be rejected at PAR: {response_body}"
    );
}

#[tokio::test]
async fn test_fapi2_token_rejects_without_dpop() {
    // FAPI 2.0 Section 5.3.2.1: Sender-constrained tokens are required.
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
            par: crate::db::ParConsumptionProof::not_pushed(),
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
            par: crate::db::ParConsumptionProof::not_pushed(),
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
async fn test_fapi2_discovery_dpop_excludes_rs256() {
    // FAPI 2.0 Section 5.4.1: RS256 must NOT appear in FAPI-only algorithm lists.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // dpop_signing_alg_values_supported is FAPI-scoped only (every DPoP proof is
    // validated against JwsAlgorithm::FAPI_ALLOWED, not per-client), so RS256 stays
    // excluded there. request_object_signing_alg_values_supported and
    // token_endpoint_auth_signing_alg_values_supported both intentionally include
    // RS256 for non-FAPI clients: OIDC Discovery 1.0 Section 3
    // (<https://openid.net/specs/openid-connect-discovery-1_0.html>) and RFC 8414
    // Section 2 (<https://www.rfc-editor.org/rfc/rfc8414>) both describe
    // token_endpoint_auth_signing_alg_values_supported with "Servers SHOULD support
    // RS256." The JAR and jwt_bearer validators still enforce PS256/ES256/EdDSA per
    // FAPI-profile client at runtime via validate_fapi_algorithm() /
    // FapiProfile::client_assertion_algorithms().
    let alg_fields = ["dpop_signing_alg_values_supported"];

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
    // FAPI 2.0 Section 5.4.1: PS256, ES256, EdDSA must be in signing algorithm lists.
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

/// A partial TLS config (cert without key) never starts the TLS or mTLS
/// listeners, so discovery must not advertise mTLS either — otherwise
/// clients registering with tls_client_auth are locked out (#708).
#[tokio::test]
async fn test_discovery_mtls_absent_with_partial_tls_config() {
    let (app, state) = test_app().await;

    let mut new_config = (**state.config()).clone();
    new_config.tls_cert = Some("/tmp/fake-cert.pem".to_string());
    new_config.tls_key = None;
    state.config.store(std::sync::Arc::new(new_config));

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    assert!(
        doc.get("mtls_endpoint_aliases").is_none(),
        "mtls_endpoint_aliases must be absent with cert-only TLS config"
    );
    assert_eq!(doc["tls_client_certificate_bound_access_tokens"], false);
    let methods = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("auth methods array");
    assert!(
        !methods.iter().any(|m| m == "tls_client_auth"),
        "tls_client_auth must not be advertised with cert-only TLS config"
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
    // Set placeholder TLS cert and key to enable mTLS discovery
    // advertisement (requires full TLS configuration).
    config.tls_cert = Some("placeholder-cert".to_string());
    config.tls_key = Some(secrecy::SecretString::from("placeholder-key".to_string()));

    let rp_origin = url::Url::parse(&config.base_url).expect("base_url");
    let webauthn = webauthn_rs::WebauthnBuilder::new(&config.rp_id, &rp_origin)
        .expect("WebauthnBuilder")
        .rp_name(&config.rp_name)
        .build()
        .expect("Webauthn");

    let oidc_key = crate::crypto::keys::OidcSigningKey::generate().expect("oidc key");

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
        org_keys_cache: Default::default(),
        policy: Default::default(),
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

// ============================================================================
// FAPI 2.0 Device Authorization Grant (RFC 8628) — Sender Constraints
//
// FAPI 2.0 Section 5.3.2.1 requires sender-constrained access tokens. The
// device code grant must enforce this for FAPI clients, consistent with the
// authorization code and FIDO2 assertion grants.
// ============================================================================

/// Create an authorized device auth request directly in the DB for a given
/// client_id and user. Returns the plaintext `device_code` the client polls
/// with. The code hash is SHA-256 base64url (same algorithm as
/// `device::hash_device_code`).
async fn setup_authorized_device(
    state: &std::sync::Arc<crate::AppState>,
    client_id: Option<&str>,
    user: &crate::db::User,
    auth_id: &str,
    label: &str,
) -> String {
    let device_code = format!("fapi2_dev_{label}");
    let device_code_hash = sha256_base64url(&device_code);
    let user_code = format!("D2{label}");

    let now = jiff::Timestamp::now();
    let expires_at = now.checked_add(jiff::Span::new().hours(1)).unwrap();

    let id = crate::db::create_device_auth_request(
        &state.store,
        &device_code_hash,
        &user_code,
        client_id,
        expires_at,
        0, // no rate limit for test
    )
    .await
    .expect("create device auth");

    crate::db::authorize_device_auth(
        &state.store,
        crate::db::AuthorizeDeviceAuthParams {
            id: &id,
            user_id: &user.id,
            user_email: &user.email,
            authenticator_id: auth_id,
            hardware_verified: true,
        },
    )
    .await
    .expect("authorize device");

    device_code
}

/// Build the device_code token-endpoint form body.
fn device_token_body(device_code: &str) -> String {
    format!(
        "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
        device_code
    )
}

/// FAPI 2.0 Section 5.3.2.1: A FAPI client completing device flow without a
/// sender constraint (DPoP or mTLS) must be rejected with `invalid_request`.
/// The device code must NOT be consumed so the client can retry with a proof.
#[tokio::test]
async fn test_fapi2_device_flow_rejects_without_dpop() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-dev-nodpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, _pkcs8) = create_fapi_test_client(&state.store, &user.id).await;

    let device_code =
        setup_authorized_device(&state, Some(&client.client_id), &user, &auth_id, "nodpop").await;

    let (status, resp_body) =
        http_post_form(&app, "/oauth/token", &device_token_body(&device_code), &[]).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "FAPI device flow without DPoP must be rejected: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "FAPI device flow without sender constraint must return invalid_request"
    );

    // The device code must NOT be consumed — retry with a valid DPoP proof
    // must still succeed (not invalid_grant/already_consumed).
    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;
    let proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let (status, resp_body) = http_post_form(
        &app,
        "/oauth/token",
        &device_token_body(&device_code),
        &[("DPoP", &proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Retry with DPoP must succeed (device code not consumed): {resp_body}"
    );
}

/// FAPI 2.0: A FAPI client completing device flow with a valid DPoP proof
/// (including nonce) receives a DPoP-bound access token whose `cnf.jkt`
/// matches the DPoP proof key thumbprint.
#[tokio::test]
async fn test_fapi2_device_flow_with_dpop_issues_bound_token() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-dev-dpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, _pkcs8) = create_fapi_test_client(&state.store, &user.id).await;

    let device_code =
        setup_authorized_device(&state, Some(&client.client_id), &user, &auth_id, "dpop").await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let expected_jkt = compute_jwk_thumbprint(&dpop_jwk);
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;
    let proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let (status, resp_body) = http_post_form(
        &app,
        "/oauth/token",
        &device_token_body(&device_code),
        &[("DPoP", &proof)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "FAPI device flow with DPoP must succeed: {resp_body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(
        resp["token_type"].as_str(),
        Some("DPoP"),
        "a DPoP-bound token must be advertised as token_type=DPoP: {resp_body}"
    );
    let access_token = resp["access_token"].as_str().expect("access_token");

    // The token MUST be DPoP-bound (cnf.jkt matches the proof key).
    let claims = decode_jwt_payload(access_token);
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(expected_jkt.as_str()),
        "cnf.jkt must match the DPoP proof key thumbprint"
    );
}

/// RFC 9449 Section 4.3: A DPoP proof without a nonce at the token endpoint
/// must return `use_dpop_nonce` with a `DPoP-Nonce` header. The device code
/// must NOT be consumed so the client can retry with the nonce.
#[tokio::test]
async fn test_fapi2_device_flow_dpop_without_nonce_returns_use_dpop_nonce() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-dev-nonce@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, _pkcs8) = create_fapi_test_client(&state.store, &user.id).await;

    let device_code =
        setup_authorized_device(&state, Some(&client.client_id), &user, &auth_id, "nonce").await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    // Proof WITHOUT a nonce — server must require one.
    let proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, None, None);

    let response = http_post_form_full(
        &app,
        "/oauth/token",
        &device_token_body(&device_code),
        &[("DPoP", &proof)],
    )
    .await;

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        json["error"], "use_dpop_nonce",
        "DPoP without nonce must return use_dpop_nonce: {}",
        response.body
    );
    assert!(
        response.headers.contains_key("dpop-nonce"),
        "Response must include DPoP-Nonce header"
    );

    // Device code not consumed — retry with the nonce must succeed.
    let nonce = response
        .headers
        .get("dpop-nonce")
        .expect("DPoP-Nonce header")
        .to_str()
        .expect("nonce UTF-8")
        .to_string();
    let proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);
    let (status, _) = http_post_form(
        &app,
        "/oauth/token",
        &device_token_body(&device_code),
        &[("DPoP", &proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Retry with nonce must succeed (device code not consumed)"
    );
}

/// An invalid DPoP proof must be rejected with `invalid_dpop_proof`. The
/// device code must NOT be consumed so the client can retry with a valid proof.
#[tokio::test]
async fn test_fapi2_device_flow_invalid_dpop_proof_rejected() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-dev-badproof@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, _pkcs8) = create_fapi_test_client(&state.store, &user.id).await;

    let device_code =
        setup_authorized_device(&state, Some(&client.client_id), &user, &auth_id, "badproof").await;

    let (status, resp_body) = http_post_form(
        &app,
        "/oauth/token",
        &device_token_body(&device_code),
        &[("DPoP", "not-a-valid-jwt")],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid DPoP proof must be rejected: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_dpop_proof",
        "Invalid DPoP proof must return invalid_dpop_proof"
    );

    // Code not consumed — retry with valid DPoP must succeed.
    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;
    let proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);
    let (status, _) = http_post_form(
        &app,
        "/oauth/token",
        &device_token_body(&device_code),
        &[("DPoP", &proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Retry with valid DPoP must succeed (device code not consumed)"
    );
}

/// Non-FAPI clients must continue to receive bearer tokens via device flow
/// without DPoP (no regression from the FAPI enforcement).
#[tokio::test]
async fn test_fapi2_device_flow_non_fapi_client_succeeds_without_dpop() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-dev-std@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_client(&state.store, &user.id, TestClientSpec::default()).await;

    let device_code =
        setup_authorized_device(&state, Some(&client.client_id), &user, &auth_id, "std").await;

    let (status, resp_body) =
        http_post_form(&app, "/oauth/token", &device_token_body(&device_code), &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Non-FAPI device flow must succeed without DPoP: {resp_body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert!(resp.get("access_token").is_some(), "must have access_token");

    // Token must NOT be DPoP-bound (no cnf.jkt).
    let access_token = resp["access_token"].as_str().expect("access_token");
    let claims = decode_jwt_payload(access_token);
    assert!(
        claims.get("cnf").is_none() || claims["cnf"].get("jkt").is_none(),
        "Non-FAPI token without DPoP must not have cnf.jkt"
    );
}

/// A non-FAPI client that voluntarily sends a DPoP proof receives a
/// DPoP-bound token (sender constraint is optional but honored).
#[tokio::test]
async fn test_fapi2_device_flow_non_fapi_client_with_dpop_issues_bound_token() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-dev-opt@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_client(&state.store, &user.id, TestClientSpec::default()).await;

    let device_code =
        setup_authorized_device(&state, Some(&client.client_id), &user, &auth_id, "opt").await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let expected_jkt = compute_jwk_thumbprint(&dpop_jwk);
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;
    let proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let (status, resp_body) = http_post_form(
        &app,
        "/oauth/token",
        &device_token_body(&device_code),
        &[("DPoP", &proof)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Non-FAPI device flow with DPoP must succeed: {resp_body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(
        resp["token_type"].as_str(),
        Some("DPoP"),
        "a DPoP-bound token must be advertised as token_type=DPoP: {resp_body}"
    );
    let access_token = resp["access_token"].as_str().expect("access_token");
    let claims = decode_jwt_payload(access_token);
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(expected_jkt.as_str()),
        "cnf.jkt must match DPoP key thumbprint (optional DPoP honored)"
    );
}

/// The built-in CLI flow (no registered client_id) must continue to work
/// without DPoP — FAPI constraints only apply to registered FAPI clients.
#[tokio::test]
async fn test_fapi2_device_flow_no_client_id_succeeds_without_dpop() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-dev-builtin@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let device_code = setup_authorized_device(&state, None, &user, &auth_id, "builtin").await;

    let (status, resp_body) =
        http_post_form(&app, "/oauth/token", &device_token_body(&device_code), &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Built-in device flow (no client_id) must succeed without DPoP: {resp_body}"
    );
}

/// A device request whose client_id no longer resolves (client deleted
/// mid-flow) must be rejected with `invalid_client`, not fall through with
/// FAPI enforcement disabled and issue an unbound token.
#[tokio::test]
async fn test_fapi2_device_flow_unknown_client_id_rejected() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-dev-ghost@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let device_code = setup_authorized_device(
        &state,
        Some("ghost-client-deleted-mid-flow"),
        &user,
        &auth_id,
        "ghost",
    )
    .await;

    let (status, resp_body) =
        http_post_form(&app, "/oauth/token", &device_token_body(&device_code), &[]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Unresolvable client_id must be rejected: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_client");
}

// ============================================================================
// FAPI 2.0 Token Exchange (RFC 8693) — Sender Constraints
//
// FAPI 2.0 Section 5.3.2.1 applies to every grant a FAPI client can use.
// Without enforcement here, a FAPI client could exchange a DPoP-bound
// subject_token for an unbound access token, undoing the sender constraint
// in one hop.
// ============================================================================

/// A FAPI client performing token exchange without any sender constraint
/// (no DPoP proof, no mTLS certificate) must be rejected.
#[tokio::test]
async fn test_fapi2_token_exchange_rejects_unbound_fapi_client() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-exchange-unbound@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let subject_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let (client, pkcs8_bytes) = create_fapi_test_client(&state.store, &user.id).await;

    let assertion = build_client_assertion(
        &client.client_id,
        &state.config().base_url,
        &pkcs8_bytes,
        None,
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token={subject_token}\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "FAPI token exchange without sender constraint must be rejected: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "FAPI token exchange without DPoP/mTLS must return invalid_request: {resp_body}"
    );
}

/// A FAPI client performing token exchange with a valid DPoP proof receives
/// a DPoP-bound access token (`cnf.jkt` matches the proof key thumbprint).
#[tokio::test]
async fn test_fapi2_token_exchange_with_dpop_issues_bound_token() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-exchange-dpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let subject_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let (client, pkcs8_bytes) = create_fapi_test_client(&state.store, &user.id).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let expected_jkt = compute_jwk_thumbprint(&dpop_jwk);
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;
    let proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let assertion = build_client_assertion(
        &client.client_id,
        &state.config().base_url,
        &pkcs8_bytes,
        None,
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token={subject_token}\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
    );

    let (status, resp_body) =
        http_post_form(&app, "/oauth/token", &body, &[("DPoP", &proof)]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "FAPI token exchange with DPoP must succeed: {resp_body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    let access_token = resp["access_token"].as_str().expect("access_token");
    let claims = decode_jwt_payload(access_token);
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(expected_jkt.as_str()),
        "exchanged token must carry cnf.jkt bound to the DPoP proof key"
    );
}

// ============================================================================
// FAPI 2.0 Client Credentials (RFC 6749 §4.4) — Sender Constraints
//
// FAPI 2.0 Section 5.3.2.1 applies to every grant a FAPI client can reach.
// The client_credentials grant is reachable by any registered client — the
// token endpoint does not gate grants by the client's registered
// `grant_types` — so it must enforce sender-constraining like the others.
// ============================================================================

/// Create a FAPI client registered for the `client_credentials` grant.
async fn create_fapi_client_credentials_client(
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
            fapi_profile: Some(db::FapiProfile::Fapi2Security),
            grant_types: Some(vec!["client_credentials".to_string()]),
            ..Default::default()
        },
    )
    .await;

    (client, pkcs8_bytes)
}

/// A FAPI client using the `client_credentials` grant without any sender
/// constraint (no DPoP proof, no mTLS certificate) must be rejected rather
/// than issued a plain bearer token.
#[tokio::test]
async fn test_fapi2_client_credentials_rejects_unbound_fapi_client() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-cc-unbound@example.com").await;
    let (client, pkcs8_bytes) = create_fapi_client_credentials_client(&state.store, &user.id).await;

    let assertion = build_client_assertion(
        &client.client_id,
        &state.config().base_url,
        &pkcs8_bytes,
        None,
    );
    let body = format!(
        "grant_type=client_credentials\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "FAPI client_credentials without a sender constraint must be rejected: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "must return invalid_request: {resp_body}"
    );
}

/// A FAPI client presenting a valid DPoP proof on the `client_credentials`
/// grant receives a DPoP-bound token: `cnf.jkt` matches the proof key and
/// `token_type` is `DPoP` (RFC 9449 Section 5).
#[tokio::test]
async fn test_fapi2_client_credentials_with_dpop_issues_bound_token() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fapi2-cc-dpop@example.com").await;
    let (client, pkcs8_bytes) = create_fapi_client_credentials_client(&state.store, &user.id).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let expected_jkt = compute_jwk_thumbprint(&dpop_jwk);
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;
    let proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let assertion = build_client_assertion(
        &client.client_id,
        &state.config().base_url,
        &pkcs8_bytes,
        None,
    );
    let body = format!(
        "grant_type=client_credentials\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
    );

    let (status, resp_body) =
        http_post_form(&app, "/oauth/token", &body, &[("DPoP", &proof)]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "FAPI client_credentials with DPoP must succeed: {resp_body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(
        resp["token_type"], "DPoP",
        "a DPoP-bound token must be advertised as token_type=DPoP: {resp_body}"
    );
    let access_token = resp["access_token"].as_str().expect("access_token");
    let claims = decode_jwt_payload(access_token);
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(expected_jkt.as_str()),
        "client_credentials token must carry cnf.jkt bound to the DPoP proof key"
    );
}

/// A client that registered `dpop_bound_access_tokens` must present a DPoP
/// proof on the client_credentials grant, exactly as on the authorization-code
/// and device grants. mTLS does not substitute: the client asked for a
/// `cnf.jkt` binding specifically.
#[tokio::test]
async fn test_client_credentials_rejects_dpop_bound_client_without_proof() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "cc-dpop-bound@example.com").await;
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            jwks: TestJwks::Custom(serde_json::json!({ "keys": [jwk] })),
            token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::PrivateKeyJwt),
            // Not a FAPI client: the binding flag alone must be enforced.
            dpop_bound_access_tokens: true,
            grant_types: Some(vec!["client_credentials".to_string()]),
            ..Default::default()
        },
    )
    .await;

    let assertion = build_client_assertion(
        &client.client_id,
        &state.config().base_url,
        &pkcs8_bytes,
        None,
    );
    let body = format!(
        "grant_type=client_credentials\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a dpop_bound_access_tokens client must not receive an unbound token: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request", "body: {resp_body}");
}
