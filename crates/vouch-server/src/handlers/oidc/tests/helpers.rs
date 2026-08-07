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

    (client, pkcs8_bytes)
}

pub(super) use crate::test_utils::build_client_assertion;

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

// ========================================================================
// mTLS Certificate Helpers (shared across rfc8705, rfc7523, rfc9449)
// ========================================================================

/// Generate a self-signed P-256 certificate DER for testing.
pub(super) fn make_test_cert_der(cn: &str) -> Vec<u8> {
    use der::{Decode as _, Encode, asn1::Utf8StringRef};
    use p256::ecdsa::SigningKey;
    use spki::EncodePublicKey as _;
    use x509_cert::builder::{Builder as _, CertificateBuilder, Profile};
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;

    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    let cn_oid = der::oid::ObjectIdentifier::new_unwrap("2.5.4.3");
    let cn_value = Utf8StringRef::new(cn).expect("valid CN");
    let atv = x509_cert::attr::AttributeTypeAndValue {
        oid: cn_oid,
        value: der::asn1::Any::from(cn_value),
    };
    let mut rdn_set = der::asn1::SetOfVec::new();
    rdn_set.insert(atv).expect("insert RDN");
    let subject =
        x509_cert::name::RdnSequence(vec![x509_cert::name::RelativeDistinguishedName(rdn_set)]);

    let validity = Validity::from_now(core::time::Duration::from_secs(86400)).expect("validity");
    let serial = SerialNumber::new(&[1u8]).expect("serial");
    let spki_der = key.verifying_key().to_public_key_der().expect("spki DER");
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_ref()).expect("parse spki");

    let builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        serial,
        validity,
        subject,
        spki,
        &key,
    )
    .expect("cert builder");

    let cert = builder
        .build::<p256::ecdsa::DerSignature>()
        .expect("build cert");
    cert.to_der().expect("DER encode")
}

/// Compute the base64url SHA-256 thumbprint of DER bytes.
pub(super) fn cert_thumbprint(der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(&SHA256, der).as_ref())
}

// ========================================================================
// DPoP Helpers (shared across rfc9449, rfc8705, rfc7523)
// ========================================================================

/// Generate an EC P-256 key pair and return (signing_key, DPoP JWK header fields).
pub(super) fn generate_dpop_key_pair() -> (EcdsaKeyPair, serde_json::Value) {
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
        "y": y
    });

    (key_pair, jwk)
}

/// Compute the RFC 7638 JWK thumbprint for a DPoP JWK (lexicographic JSON
/// of the required members: crv, kty, x, y).
pub(super) fn dpop_jkt(jwk: &serde_json::Value) -> String {
    let canonical = serde_json::json!({
        "crv": jwk["crv"],
        "kty": jwk["kty"],
        "x": jwk["x"],
        "y": jwk["y"]
    });
    let bytes = serde_json::to_vec(&canonical).expect("serialize JWK");
    let digest = aws_lc_rs::digest::digest(&SHA256, &bytes);
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// Create and sign a DPoP proof JWT for the given method and URI.
pub(super) fn create_dpop_proof(
    key_pair: &EcdsaKeyPair,
    jwk: &serde_json::Value,
    method: &str,
    uri: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
) -> String {
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
        let hash = aws_lc_rs::digest::digest(&SHA256, token.as_bytes());
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

/// Acquire a DPoP nonce by submitting a proof without one to the token endpoint.
///
/// Nonces are always required (RFC 9449 Section 8). This helper performs the
/// `use_dpop_nonce` round-trip and returns the server-provided nonce.
pub(super) async fn acquire_dpop_nonce(
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
        .expect("Server must return DPoP-Nonce header")
        .to_str()
        .expect("DPoP-Nonce must be valid UTF-8")
        .to_string()
}

/// The response's `WWW-Authenticate` value, or `""` when absent.
pub(super) fn www_authenticate(response: &HttpResponse) -> &str {
    response
        .headers
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// RFC 6750 §3.1: a 401 for a request carrying an invalid, expired, or
/// revoked token must challenge with `error="invalid_token"`.
pub(super) fn assert_invalid_token_challenge(response: &HttpResponse) {
    let www_auth = www_authenticate(response);
    assert!(
        www_auth.contains("invalid_token"),
        "WWW-Authenticate must contain error=\"invalid_token\": {www_auth}"
    );
}

/// RFC 6750 §3.1 + RFC 9728 §5.2: a 401 for a request with no credentials
/// at all is a bare `Bearer` challenge — no error information — that still
/// advertises the `resource_metadata` pointer for client discovery.
pub(super) fn assert_bare_bearer_challenge(response: &HttpResponse) {
    let www_auth = www_authenticate(response);
    assert!(
        www_auth.starts_with("Bearer"),
        "WWW-Authenticate must be a Bearer challenge: {www_auth}"
    );
    assert!(
        !www_auth.contains("error="),
        "missing credentials must not include an error parameter: {www_auth}"
    );
    assert!(
        www_auth.contains("resource_metadata="),
        "missing credentials must still advertise resource_metadata (RFC 9728 §5.2): {www_auth}"
    );
}
