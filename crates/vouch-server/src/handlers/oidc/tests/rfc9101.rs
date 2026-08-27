// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9101 — JWT-Secured Authorization Request (JAR) tests.
//!
//! Tests for the `request` parameter at the authorization endpoint,
//! Request Object validation, PAR + JAR integration, discovery metadata,
//! `require_signed_request_object` enforcement, and error handling.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc9101>

use super::helpers::*;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

// ========================================================================
// Helper functions
// ========================================================================

fn generate_es256_signing_key() -> (Vec<u8>, serde_json::Value) {
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
        "kid": "jar-test-key-1"
    });

    (pkcs8.as_ref().to_vec(), jwk)
}

/// Sign a JWT with the given header and claims using ES256.
fn sign_jwt(pkcs8_bytes: &[u8], header: &serde_json::Value, claims: &serde_json::Value) -> String {
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

/// Create a test OAuth client with JWKS configured for JAR.
async fn create_test_jar_client(
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
            ..Default::default()
        },
    )
    .await;

    (client, pkcs8_bytes)
}

/// Build a valid Request Object JWT for testing.
fn build_request_object(client_id: &str, issuer: &str, pkcs8_bytes: &[u8]) -> String {
    let now = jiff::Timestamp::now().as_second();
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "jar-test-key-1"
    });

    let claims = serde_json::json!({
        "iss": client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "state": "jar-test-state",
        "nonce": "jar-test-nonce",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    sign_jwt(pkcs8_bytes, &header, &claims)
}

/// Build a Request Object with custom claims.
fn build_request_object_with_claims(claims: &serde_json::Value, pkcs8_bytes: &[u8]) -> String {
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "jar-test-key-1"
    });

    sign_jwt(pkcs8_bytes, &header, claims)
}

// ========================================================================
// RFC 9101 — Discovery Metadata
// ========================================================================

#[tokio::test]
async fn test_rfc9101_discovery_includes_request_parameter_supported() {
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        doc["request_parameter_supported"].is_boolean(),
        "Discovery must include request_parameter_supported"
    );
}

#[tokio::test]
async fn test_rfc9101_discovery_includes_request_object_signing_alg_values_supported() {
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let algs = doc["request_object_signing_alg_values_supported"]
        .as_array()
        .expect("Must be an array");
    assert!(
        algs.len() >= 4,
        "Must support at least RS256, ES256, PS256, and EdDSA"
    );

    let alg_strs: Vec<&str> = algs.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(alg_strs.contains(&"ES256"), "Must support ES256");
    assert!(alg_strs.contains(&"PS256"), "Must support PS256");
    assert!(alg_strs.contains(&"EdDSA"), "Must support EdDSA");
    // RS256 is advertised for non-FAPI clients (OIDC Basic Profile conformance).
    // Vouch deliberately advertises RS256 for JAR request objects while the JAR
    // validator enforces the FAPI 2.0 Section 5.4.1 set (PS256/ES256/EdDSA) for
    // FAPI clients at runtime.
    assert!(
        alg_strs.contains(&"RS256"),
        "RS256 must be advertised for OIDC Basic Profile conformance (oidcc-request-uri-signed-rs256)"
    );
}

#[tokio::test]
async fn test_rfc9101_discovery_request_parameter_supported_is_true() {
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        doc["request_parameter_supported"], true,
        "request_parameter_supported should be true"
    );
    assert_eq!(
        doc["require_signed_request_object"], false,
        "require_signed_request_object should be false by default"
    );
}

// ========================================================================
// RFC 9101 — Authorize Endpoint with Request Object
// ========================================================================

#[tokio::test]
async fn test_rfc9101_authorize_with_valid_request_parameter_es256() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-es256@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let issuer = &state.config().base_url;
    let request_jwt = build_request_object(&client.client_id, issuer, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request={}",
            client.client_id,
            urlencoding::encode(&request_jwt),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Valid JAR request should succeed, got: {} body: {}",
        response.status,
        response.body,
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
async fn test_rfc9101_authorize_request_object_with_pkce() {
    // Verify PKCE parameters from the Request Object are used.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-pkce@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let issuer = &state.config().base_url;
    let request_jwt = build_request_object(&client.client_id, issuer, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request={}",
            client.client_id,
            urlencoding::encode(&request_jwt),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "JAR with PKCE should succeed, got: {}",
        response.status,
    );
}

// ========================================================================
// RFC 9101 — Authorize Error Cases
// ========================================================================

#[tokio::test]
async fn test_rfc9101_authorize_request_parameter_invalid_signature() {
    // A Request Object signed with a different key should be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-badsig@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, _pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    // Sign with a DIFFERENT key (not registered in JWKS)
    let (wrong_pkcs8, _) = generate_es256_signing_key();
    let issuer = &state.config().base_url;
    let request_jwt = build_request_object(&client.client_id, issuer, &wrong_pkcs8);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&request={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode(&request_jwt),
        ),
        &[],
    )
    .await;

    // Should get an error redirect or error page
    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request_object"),
            "Invalid signature should return invalid_request_object, got: {location}"
        );
    } else {
        // Error page
        assert_eq!(response.status, StatusCode::OK);
        assert!(
            response.body.contains("Invalid") || response.body.contains("Request Object"),
            "Error page should mention invalid Request Object"
        );
    }
}

#[tokio::test]
async fn test_rfc9101_authorize_request_parameter_expired() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-expired@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now - 3600,  // Expired 1 hour ago
        "iat": now - 7200,
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&request={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode(&request_jwt),
        ),
        &[],
    )
    .await;

    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request_object"),
            "Expired Request Object should return error, got: {location}"
        );
    }
}

#[tokio::test]
async fn test_rfc9101_authorize_request_parameter_wrong_iss() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-wrongiss@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    let claims = serde_json::json!({
        "iss": "wrong-client-id",  // Wrong issuer
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&request={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode(&request_jwt),
        ),
        &[],
    )
    .await;

    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request_object"),
            "Wrong iss should return error, got: {location}"
        );
    }
}

#[tokio::test]
async fn test_rfc9101_authorize_request_parameter_wrong_aud() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-wrongaud@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let now = jiff::Timestamp::now().as_second();
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://wrong-issuer.example.com",  // Wrong audience
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&request={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode(&request_jwt),
        ),
        &[],
    )
    .await;

    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request_object"),
            "Wrong aud should return error, got: {location}"
        );
    }
}

// ========================================================================
// RFC 9101 — Client ID Binding
// ========================================================================

#[tokio::test]
async fn test_rfc9101_authorize_missing_client_id_query_returns_error() {
    // client_id is required in the query string when using the request parameter.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-nocid@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let issuer = &state.config().base_url;
    let request_jwt = build_request_object(&client.client_id, issuer, &pkcs8_bytes);

    // No client_id in query
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?request={}",
            urlencoding::encode(&request_jwt),
        ),
        &[],
    )
    .await;

    // Should return error page
    assert_eq!(
        response.status,
        StatusCode::OK,
        "Missing client_id should return error page"
    );
    assert!(
        response.body.contains("client_id") || response.body.contains("Invalid"),
        "Error should mention client_id is required"
    );
}

// ========================================================================
// RFC 9101 — Mutual Exclusion
// ========================================================================

#[tokio::test]
async fn test_rfc9101_authorize_both_request_and_request_uri_rejected() {
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id=test&request={}&request_uri={}",
            urlencoding::encode("some.jwt.here"),
            urlencoding::encode("urn:ietf:params:oauth:request_uri:something"),
        ),
        &[],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "Both request and request_uri should return error page"
    );
    assert!(
        response.body.contains("mutually exclusive") || response.body.contains("Invalid"),
        "Error should mention mutual exclusion"
    );
}

#[tokio::test]
async fn test_rfc9101_authorize_request_uri_in_jwt_payload_rejected() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-nesteduri@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "request_uri": "https://evil.example.com/request"  // Nested!
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&request={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode(&request_jwt),
        ),
        &[],
    )
    .await;

    // Should get an error (either redirect or page)
    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request_object"),
            "Nested request_uri should be rejected, got: {location}"
        );
    } else {
        assert_eq!(response.status, StatusCode::OK);
    }
}

#[tokio::test]
async fn test_rfc9101_authorize_request_in_jwt_payload_rejected() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-nestedreq@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "request": "nested-jwt-string"  // Nested!
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&request={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode(&request_jwt),
        ),
        &[],
    )
    .await;

    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request_object"),
            "Nested request should be rejected, got: {location}"
        );
    } else {
        assert_eq!(response.status, StatusCode::OK);
    }
}

// ========================================================================
// RFC 9101 — require_signed_request_object Enforcement
// ========================================================================

#[tokio::test]
async fn test_rfc9101_require_signed_request_object_rejects_plain_params() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-required@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (_pkcs8_bytes, jwk) = generate_es256_signing_key();
    let jwks_value = serde_json::json!({ "keys": [jwk] });
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            jwks: TestJwks::Custom(jwks_value),
            require_signed_request_object: Some(true),
            ..Default::default()
        },
    )
    .await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    // Plain request without `request` parameter
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&response_type=code\
             &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=openid",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    // Should be rejected — redirect with error
    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request"),
            "Plain params when JAR required should return error, got: {location}"
        );
        assert!(
            location.contains("signed+Request+Object")
                || location.contains("signed%20Request%20Object")
                || location.contains("Request+Object")
                || location.contains("Request%20Object"),
            "Error should mention Request Object requirement, got: {location}"
        );
    }
}

#[tokio::test]
async fn test_rfc9101_require_signed_request_object_accepts_valid_jar() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-reqok@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (pkcs8_bytes, jwk) = generate_es256_signing_key();
    let jwks_value = serde_json::json!({ "keys": [jwk] });
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            jwks: TestJwks::Custom(jwks_value),
            require_signed_request_object: Some(true),
            ..Default::default()
        },
    )
    .await;

    let issuer = &state.config().base_url;
    let request_jwt = build_request_object(&client.client_id, issuer, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request={}",
            client.client_id,
            urlencoding::encode(&request_jwt),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Valid JAR when required should succeed, got: {} body: {}",
        response.status,
        response.body,
    );
}

// ========================================================================
// RFC 9101 — PAR + JAR Integration
// ========================================================================

#[tokio::test]
async fn test_rfc9101_par_accepts_request_object_in_body() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-par@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let issuer = &state.config().base_url;
    let request_jwt = build_request_object(&client.client_id, issuer, &pkcs8_bytes);

    let body = format!(
        "request={}&client_id={}&client_secret={}",
        urlencoding::encode(&request_jwt),
        urlencoding::encode(&client.client_id),
        urlencoding::encode(&client.client_secret),
    );

    let (status, response_body) = http_post_form(&app, "/oauth/par", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "PAR with JAR should return 201: {response_body}"
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
async fn test_rfc9101_par_request_object_invalid_signature_rejected() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-parbad@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, _pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    // Sign with wrong key
    let (wrong_pkcs8, _) = generate_es256_signing_key();
    let issuer = &state.config().base_url;
    let request_jwt = build_request_object(&client.client_id, issuer, &wrong_pkcs8);

    let body = format!(
        "request={}&client_id={}&client_secret={}",
        urlencoding::encode(&request_jwt),
        urlencoding::encode(&client.client_id),
        urlencoding::encode(&client.client_secret),
    );

    let (status, response_body) = http_post_form(&app, "/oauth/par", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "PAR with bad JAR signature should return 400: {response_body}"
    );
}

#[tokio::test]
async fn test_rfc9101_par_request_object_client_id_mismatch_rejected() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-parcid@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let issuer = &state.config().base_url;
    let now = jiff::Timestamp::now().as_second();
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    // Use client_id in JWT that doesn't match the authenticated client
    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": "different-client-id",  // Mismatch!
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    let body = format!(
        "request={}&client_id={}&client_secret={}",
        urlencoding::encode(&request_jwt),
        urlencoding::encode(&client.client_id),
        urlencoding::encode(&client.client_secret),
    );

    let (status, response_body) = http_post_form(&app, "/oauth/par", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "PAR with client_id mismatch should return 400: {response_body}"
    );
}

// ========================================================================
// RFC 9101 — Error Code Tests
// ========================================================================

#[tokio::test]
async fn test_rfc9101_invalid_request_object_error_code_returned() {
    // The invalid_request_object error code should be used for JAR errors.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-errcode@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, _pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    // Completely invalid JWT string
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&request=not.a.valid.jwt",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await;

    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request_object") || location.contains("invalid_request"),
            "Invalid JWT should return an error code, got: {location}"
        );
    }
}

#[tokio::test]
async fn test_rfc9101_invalid_request_object_http_status_is_400() {
    // When returning as JSON (PAR endpoint), the HTTP status should be 400.
    use crate::error::OAuthErrorCode;
    assert_eq!(
        OAuthErrorCode::InvalidRequestObject.status_code(),
        StatusCode::BAD_REQUEST,
    );
}

// ========================================================================
// RFC 9101 — request_object_signing_alg Client Metadata Enforcement
// ========================================================================

#[tokio::test]
async fn test_rfc9101_client_signing_alg_es256_rejects_rs256_jwt() {
    // If the client has request_object_signing_alg = "ES256", a JWT signed
    // with RS256 (even if otherwise valid) must be rejected.
    // We test this at the PAR endpoint using an ES256 client where we submit
    // a JWT with an RS256 header (which will fail signature verification
    // due to algorithm mismatch before key lookup).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-algenforce@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;

    let (pkcs8_bytes, jwk) = generate_es256_signing_key();
    let jwks_value = serde_json::json!({ "keys": [jwk] });
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            jwks: TestJwks::Custom(jwks_value),
            request_object_signing_alg: Some(db::JwsAlgorithm::Es256),
            require_signed_request_object: Some(false),
            ..Default::default()
        },
    )
    .await;

    // Build a JWT that claims to be RS256 in the header (but is signed with ES256 key)
    // The server should reject it because the header alg (RS256) != required alg (ES256)
    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    // Sign with a header claiming RS256 (the algorithm check happens before signature verification)
    let rs256_header = serde_json::json!({
        "alg": "RS256",
        "typ": "oauth-authz-req+jwt",
        "kid": "jar-test-key-1"
    });
    let request_jwt = sign_jwt(&pkcs8_bytes, &rs256_header, &claims);

    let body = format!(
        "request={}&client_id={}&client_secret={}",
        urlencoding::encode(&request_jwt),
        urlencoding::encode(&client.client_id),
        urlencoding::encode(&client.client_secret),
    );

    let (status, response_body) = http_post_form(&app, "/oauth/par", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "RS256 JWT when client requires ES256 should return 400: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_request_object",
        "Error code must be invalid_request_object, got: {response_body}"
    );
}

#[tokio::test]
async fn test_rfc9101_client_signing_alg_es256_accepts_es256_jwt() {
    // If the client has request_object_signing_alg = "ES256", a JWT signed
    // with ES256 must be accepted.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-algok@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (pkcs8_bytes, jwk) = generate_es256_signing_key();
    let jwks_value = serde_json::json!({ "keys": [jwk] });
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            jwks: TestJwks::Custom(jwks_value),
            request_object_signing_alg: Some(db::JwsAlgorithm::Es256),
            require_signed_request_object: Some(false),
            ..Default::default()
        },
    )
    .await;

    let issuer = &state.config().base_url;
    let request_jwt = build_request_object(&client.client_id, issuer, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request={}",
            client.client_id,
            urlencoding::encode(&request_jwt),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "ES256 JWT when client requires ES256 should succeed, got: {} body: {}",
        response.status,
        response.body,
    );
}

// ========================================================================
// RFC 9101 — Required Claims Enforcement
// ========================================================================

#[tokio::test]
async fn test_rfc9101_authorize_missing_response_type_in_request_object_rejected() {
    // The Request Object must contain a 'response_type' claim.
    // When it's missing, the server must return an error.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-nort@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    // Build claims without response_type
    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        // response_type intentionally omitted
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&request={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode(&request_jwt),
        ),
        &[],
    )
    .await;

    // Should get an error (either redirect with error code or error page)
    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request_object") || location.contains("invalid_request"),
            "Missing response_type should return an error, got: {location}"
        );
    } else {
        // Error page is also acceptable
        assert_eq!(
            response.status,
            StatusCode::OK,
            "Expected error page or redirect error, got: {}",
            response.status
        );
    }
}

#[tokio::test]
async fn test_rfc9101_authorize_missing_redirect_uri_in_request_object_rejected() {
    // The Request Object must contain a 'redirect_uri' claim.
    // When it's missing, the server must return an error.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-noredir@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    // Build claims without redirect_uri
    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client.client_id,
        // redirect_uri intentionally omitted
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request={}",
            client.client_id,
            urlencoding::encode(&request_jwt),
        ),
        &[],
    )
    .await;

    // Should get an error
    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request_object") || location.contains("invalid_request"),
            "Missing redirect_uri should return an error, got: {location}"
        );
    } else {
        assert_eq!(
            response.status,
            StatusCode::OK,
            "Expected error page or redirect error, got: {}",
            response.status
        );
    }
}

// ========================================================================
// RFC 9101 — State Parameter Preservation
// ========================================================================

#[tokio::test]
async fn test_rfc9101_state_from_request_object_preserved_in_response() {
    // The state parameter from the Request Object must be echoed back
    // in the authorization response redirect (RFC 6749 Section 4.1.2).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-state@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    let unique_state = "jar-unique-state-value-xyz789";

    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "state": unique_state,
        "nonce": "jar-state-nonce",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&request={}",
            client.client_id,
            urlencoding::encode(&request_jwt),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Valid JAR with state should succeed, got: {} body: {}",
        response.status,
        response.body,
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
    assert!(
        location.contains(unique_state),
        "State from Request Object must be echoed in redirect, got: {location}"
    );
}

// ========================================================================
// RFC 9101 — FAPI 2.0 Parameter Consistency
// ========================================================================

#[tokio::test]
async fn test_rfc9101_fapi2_response_type_mismatch_rejected() {
    // FAPI 2.0 Section 5.3.2: If response_type appears in both the query string
    // and the JWT, they must match. A mismatch must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-fapi-rt@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    // JWT has response_type=code
    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    // Query string has response_type=token — this should mismatch
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&response_type=token&redirect_uri={}&request={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode(&request_jwt),
        ),
        &[],
    )
    .await;

    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request_object") || location.contains("invalid_request"),
            "response_type mismatch should return error, got: {location}"
        );
    } else {
        // Error page is also acceptable
        assert_eq!(
            response.status,
            StatusCode::OK,
            "Expected error page or redirect with error, got: {} body: {}",
            response.status,
            response.body
        );
    }
}

#[tokio::test]
async fn test_rfc9101_fapi2_scope_mismatch_rejected() {
    // FAPI 2.0 Section 5.3.2: If scope appears in both the query string and
    // the JWT, they must match. A mismatch must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-fapi-scope@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    // JWT has scope=openid
    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    // Query string has scope=openid profile — this should mismatch with JWT's "openid"
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&scope={}&redirect_uri={}&request={}",
            client.client_id,
            urlencoding::encode("openid profile"),
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode(&request_jwt),
        ),
        &[],
    )
    .await;

    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response.headers.get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("invalid_request_object") || location.contains("invalid_request"),
            "scope mismatch should return error, got: {location}"
        );
    } else {
        assert_eq!(
            response.status,
            StatusCode::OK,
            "Expected error page or redirect with error, got: {} body: {}",
            response.status,
            response.body
        );
    }
}

#[tokio::test]
async fn test_rfc9101_fapi2_matching_query_params_accepted() {
    // FAPI 2.0: When query params match the JWT values, the request is accepted.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-fapi-match@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "state": "fapi-match-state",
        "nonce": "fapi-match-nonce",
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    // Query params match the JWT values exactly
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?client_id={}&response_type=code&scope=openid&request={}",
            client.client_id,
            urlencoding::encode(&request_jwt),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Matching FAPI 2.0 params should succeed, got: {} body: {}",
        response.status,
        response.body,
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

// ========================================================================
// RFC 9101 — Malformed JWT Handling
// ========================================================================

#[tokio::test]
async fn test_rfc9101_authorize_completely_malformed_jwt_handled_gracefully() {
    // An entirely malformed JWT (not even proper base64) should be handled
    // gracefully without panicking, returning an appropriate error.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-malformed@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, _pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    // This is not valid base64 or a valid JWT format
    let malformed_values = &[
        "!!!not-base64!!!",
        "not.a.jwt.at.all.because.it.has.too.many.dots",
        "",
        "just_one_part",
        "two..parts.with.empty",
        "\x00\x01\x02",
    ];

    for malformed in malformed_values {
        let response = http_get_full(
            &app,
            &format!(
                "/oauth/authorize?client_id={}&redirect_uri={}&request={}",
                client.client_id,
                urlencoding::encode("https://example.com/callback"),
                urlencoding::encode(malformed),
            ),
            &[],
        )
        .await;

        // Should NOT panic — must return either an error redirect or error page
        assert!(
            response.status == StatusCode::OK
                || response.status == StatusCode::FOUND
                || response.status == StatusCode::SEE_OTHER,
            "Malformed JWT '{malformed}' should not crash the server, got: {}",
            response.status
        );

        // If it's a redirect, must contain an error
        if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
            let location = response.headers.get("Location").unwrap().to_str().unwrap();
            assert!(
                location.contains("error="),
                "Malformed JWT redirect must contain error param, got: {location}"
            );
        }
    }
}

#[tokio::test]
async fn test_rfc9101_par_completely_malformed_jwt_returns_400() {
    // A completely malformed JWT at the PAR endpoint should return 400.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-par-mal@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, _pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let body = format!(
        "request={}&client_id={}&client_secret={}",
        urlencoding::encode("!!!not-a-jwt-at-all!!!"),
        urlencoding::encode(&client.client_id),
        urlencoding::encode(&client.client_secret),
    );

    let (status, response_body) = http_post_form(&app, "/oauth/par", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "PAR with malformed JWT should return 400: {response_body}"
    );

    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    // The shared parse_assertion_header function uses invalid_client for structural JWT errors.
    // For the PAR endpoint, any RFC 6749 error code is acceptable as long as the HTTP status is 400.
    assert!(
        json["error"] == "invalid_request_object"
            || json["error"] == "invalid_request"
            || json["error"] == "invalid_client",
        "Error code must indicate an error for malformed JWT, got: {response_body}"
    );
    assert!(
        json["error_description"].is_string(),
        "Must include error_description, got: {response_body}"
    );
}

// ========================================================================
// RFC 9101 — PAR + JAR: Nested Request Claim Rejected
// ========================================================================

#[tokio::test]
async fn test_rfc9101_par_request_object_with_nested_request_claim_rejected() {
    // RFC 9101 Section 3: A Request Object must not contain a 'request' claim.
    // This applies at the PAR endpoint as well as the authorize endpoint.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jar-par-nested@example.com").await;
    let _auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jar_client(&state.store, &user.id).await;

    let now = jiff::Timestamp::now().as_second();
    let issuer = &state.config().base_url;
    let challenge = sha256_base64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    // Build a Request Object with a nested 'request' claim
    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "request": "nested-jwt-value"  // Nested! Must be rejected per RFC 9101
    });

    let request_jwt = build_request_object_with_claims(&claims, &pkcs8_bytes);

    let body = format!(
        "request={}&client_id={}&client_secret={}",
        urlencoding::encode(&request_jwt),
        urlencoding::encode(&client.client_id),
        urlencoding::encode(&client.client_secret),
    );

    let (status, response_body) = http_post_form(&app, "/oauth/par", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "PAR with nested 'request' claim should return 400: {response_body}"
    );

    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_request_object",
        "Error code must be invalid_request_object, got: {response_body}"
    );
}

// ========================================================================
// RFC 9101 — Discovery: require_signed_request_object Default
// ========================================================================

#[tokio::test]
async fn test_rfc9101_discovery_require_signed_request_object_is_false_by_default() {
    // RFC 9101: require_signed_request_object defaults to false.
    // Servers that require JAR by default must advertise this.
    // Our server does not require it by default.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);

    let doc: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert!(
        doc["require_signed_request_object"].is_boolean(),
        "Discovery must include require_signed_request_object as a boolean"
    );
    assert_eq!(
        doc["require_signed_request_object"], false,
        "require_signed_request_object must be false by default, got: {}",
        doc["require_signed_request_object"]
    );
}

// ========================================================================
// RFC 9101 — Write-time key/algorithm usability
//
// `request_object_signing_alg` pins the algorithm every Request Object from
// this client must carry, and the runtime verifier selects a key by that
// algorithm's key type. Key material that holds no such key leaves the
// client permanently unable to authorize, so every path that writes either
// half of the pair checks them against each other.
// ========================================================================

/// A JWKS holding only an RSA key, for a client that pins ES256. The runtime
/// matcher selects `kty` `EC` for ES256, so no key in this set can ever
/// verify one of its Request Objects.
fn rsa_only_jwks() -> serde_json::Value {
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\
                  VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9y\
                  BXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgd\
                  AZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksI\
                  NHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "use": "sig",
            "kid": "rsa-key-1"
        }]
    })
}

/// Register a JAR client that pins ES256 and holds a usable EC key, then
/// confirm it can authorize. Returns the client_id, its registration access
/// token, and the signing key behind its JWKS.
async fn register_working_jar_client(
    app: &axum::Router,
    state: &std::sync::Arc<crate::AppState>,
    session_token: &str,
    client_name: &str,
) -> (String, String, Vec<u8>) {
    let (pkcs8_bytes, ec_jwk) = generate_es256_signing_key();

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "client_secret_basic",
        "request_object_signing_alg": "ES256",
        "require_signed_request_object": true,
        "jwks": { "keys": [ec_jwk] },
        "client_name": client_name
    });
    let (reg_status, reg_body) = http_post_json(
        app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &format!("Bearer {session_token}"))],
    )
    .await;
    assert_eq!(reg_status, StatusCode::CREATED, "setup: {reg_body}");

    let reg: serde_json::Value = serde_json::from_str(&reg_body).expect("valid JSON");
    let client_id = reg["client_id"].as_str().expect("client_id").to_string();
    let reg_token = reg["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    let issuer = &state.config().base_url;
    let before = http_get_full(
        app,
        &format!(
            "/oauth/authorize?client_id={}&request={}",
            client_id,
            urlencoding::encode(&build_request_object(&client_id, issuer, &pkcs8_bytes)),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;
    assert!(
        before
            .headers
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|l| l.contains("code=")),
        "setup: the client must be able to authorize before its JWKS is replaced"
    );

    (client_id, reg_token, pkcs8_bytes)
}

#[tokio::test]
async fn test_rfc9101_registration_rejects_pinned_alg_without_usable_key() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "jar-unusable-reg@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "client_secret_basic",
        "request_object_signing_alg": "ES256",
        "require_signed_request_object": true,
        "jwks": rsa_only_jwks(),
        "client_name": "Unusable JAR Key App"
    });

    let (status, resp) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &format!("Bearer {session_token}"))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "registering request_object_signing_alg ES256 against an RSA-only JWKS must be \
         rejected as invalid_client_metadata; the client is otherwise accepted and then \
         unable to authorize at all. Got {status}: {resp}"
    );
}

#[tokio::test]
async fn test_rfc9101_registration_rejects_required_signing_without_any_key() {
    // `require_signed_request_object` commits the client to signing without
    // necessarily naming an algorithm, so it needs key material even when
    // `request_object_signing_alg` is absent.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "jar-no-keys-reg@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "client_secret_basic",
        "require_signed_request_object": true,
        "client_name": "Signed JAR Without Keys"
    });

    let (status, resp) = http_post_json(
        &app,
        "/oauth/register",
        &body.to_string(),
        &[("Authorization", &format!("Bearer {session_token}"))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "require_signed_request_object with no jwks or jwks_uri leaves the client with \
         nothing to verify its Request Objects against. Got {status}: {resp}"
    );
}

#[tokio::test]
async fn test_rfc9101_update_rejects_jwks_without_key_for_pinned_alg() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "jar-unusable-put@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (client_id, reg_token, _pkcs8) =
        register_working_jar_client(&app, &state, &session_token, "JAR PUT App").await;

    let put_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_id": client_id,
        "jwks": rsa_only_jwks(),
    });
    let (put_status, put_resp) = http_put_json(
        &app,
        &format!("/oauth/register/{client_id}"),
        &put_body.to_string(),
        &[("Authorization", &format!("Bearer {reg_token}"))],
    )
    .await;

    assert_eq!(
        put_status,
        StatusCode::BAD_REQUEST,
        "replacing the JWKS with a set holding no key usable for the client's pinned \
         ES256 must be rejected; it otherwise succeeds and silently breaks every \
         subsequent authorization request. Got {put_status}: {put_resp}"
    );
}

#[tokio::test]
async fn test_rfc9101_update_accepts_jwks_with_key_for_pinned_alg() {
    // The rotation the check must not block: a new EC key, same pinned alg.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "jar-rotate-put@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (client_id, reg_token, _pkcs8) =
        register_working_jar_client(&app, &state, &session_token, "JAR Rotate App").await;

    let (_new_pkcs8, new_ec_jwk) = generate_es256_signing_key();
    let put_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_id": client_id,
        "jwks": { "keys": [new_ec_jwk] },
    });
    let (put_status, put_resp) = http_put_json(
        &app,
        &format!("/oauth/register/{client_id}"),
        &put_body.to_string(),
        &[("Authorization", &format!("Bearer {reg_token}"))],
    )
    .await;

    assert_eq!(
        put_status,
        StatusCode::OK,
        "rotating to another ES256-usable key must still be accepted. \
         Got {put_status}: {put_resp}"
    );
}

#[tokio::test]
async fn test_rfc9101_admin_update_rejects_jwks_without_key_for_pinned_alg() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "jar-admin-patch@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let auth = format!("Bearer {session_token}");

    let (client_id, _reg_token, _pkcs8) =
        register_working_jar_client(&app, &state, &session_token, "Admin JAR App").await;

    // The admin API is keyed by the stored document id, not the client_id.
    let app_id = crate::db::get_oauth_client_by_client_id(&state.store, &client_id)
        .await
        .expect("lookup ok")
        .expect("client exists")
        .id;

    // `jwks` on this endpoint is a JSON string, not an object.
    let patch_body = serde_json::json!({ "jwks": rsa_only_jwks().to_string() }).to_string();
    let (patch_status, patch_resp) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{app_id}"),
        Some(patch_body),
        &[
            ("Authorization", &auth),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(
        patch_status,
        StatusCode::BAD_REQUEST,
        "the admin API must reject a JWKS holding no key usable for the client's pinned \
         ES256; it otherwise succeeds and silently breaks every subsequent authorization \
         request. Got {patch_status}: {patch_resp}"
    );
}

#[tokio::test]
async fn test_rfc9101_admin_update_form_rejects_jwks_without_key_for_pinned_alg() {
    // The admin UI form writes the same field through the same validator as
    // the JSON API, so it carries the same rule.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "jar-admin-form@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (client_id, _reg_token, _pkcs8) =
        register_working_jar_client(&app, &state, &session_token, "Admin JAR Form App").await;

    let app_id = crate::db::get_oauth_client_by_client_id(&state.store, &client_id)
        .await
        .expect("lookup ok")
        .expect("client exists")
        .id;

    let form_body = format!(
        "name=Admin+JAR+Form+App&redirect_uris={}&jwks={}",
        urlencoding::encode("https://example.com/callback"),
        urlencoding::encode(&rsa_only_jwks().to_string()),
    );
    let (status, resp) = http_request(
        &app,
        "POST",
        &format!("/applications/{app_id}"),
        Some(form_body),
        &[
            ("Cookie", &format!("__Host-vouch_session={session_token}")),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
    )
    .await;

    assert!(
        resp.contains("ES256") || status == StatusCode::BAD_REQUEST,
        "the admin form must refuse a JWKS with no key usable for the pinned ES256. \
         Got {status}: {resp}"
    );
}
