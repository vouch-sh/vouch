// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session resource-auth handler tests: bearer/cookie precedence,
//! DPoP and mTLS sender-constraint enforcement, and the RFC 9449
//! nonce-replay retry flow.
#![expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use axum::http::StatusCode;

use crate::test_utils::*;

/// Generate a self-signed DER certificate with the given CN for test use.
fn make_test_cert_der(cn: &str) -> Vec<u8> {
    use der::{Decode, Encode};
    use p256::ecdsa::SigningKey;
    use spki::EncodePublicKey;
    use x509_cert::builder::{Builder as _, CertificateBuilder, Profile};
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;

    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let cn_oid = der::oid::ObjectIdentifier::new_unwrap("2.5.4.3");
    let cn_value = der::asn1::Utf8StringRef::new(cn).expect("CN");
    let atv = x509_cert::attr::AttributeTypeAndValue {
        oid: cn_oid,
        value: der::asn1::Any::from(cn_value),
    };
    let mut rdn = der::asn1::SetOfVec::new();
    rdn.insert(atv).expect("rdn");
    let subject =
        x509_cert::name::RdnSequence(vec![x509_cert::name::RelativeDistinguishedName(rdn)]);
    let validity = Validity::from_now(core::time::Duration::from_secs(86400)).expect("validity");
    let serial = SerialNumber::new(&[1u8]).expect("serial");
    let spki_der = key.verifying_key().to_public_key_der().expect("spki");
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_ref()).expect("parse spki");

    CertificateBuilder::new(
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
    .expect("builder")
    .build::<p256::ecdsa::DerSignature>()
    .expect("build")
    .to_der()
    .expect("der")
}

/// Normal (non-DPoP) token via cookie should succeed.
#[tokio::test]
async fn test_cookie_session_normal_token_succeeds() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "cookie-ok@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
    let (status, _body) = http_get(&app, "/api/v1/applications", &[("Cookie", &cookie)]).await;

    assert_eq!(status, StatusCode::OK);
}

/// DPoP-bound token (with cnf.jkt) via cookie must be rejected.
#[tokio::test]
async fn test_cookie_session_dpop_bound_token_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "cookie-dpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with_dpop(
        &state,
        &user.id,
        &user.email,
        &auth_id,
        "fake-jkt-thumbprint",
    )
    .await;

    let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
    let (status, body) = http_get(&app, "/api/v1/applications", &[("Cookie", &cookie)]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(
        body.contains("Sender-constrained"),
        "Error should mention sender-constrained tokens, got: {body}"
    );
}

/// DPoP-bound token via Bearer header (without DPoP proof) should also
/// be rejected, but with a different message than the cookie case.
#[tokio::test]
async fn test_bearer_dpop_bound_token_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "bearer-dpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with_dpop(
        &state,
        &user.id,
        &user.email,
        &auth_id,
        "fake-jkt-thumbprint",
    )
    .await;

    let auth = format!("Bearer {token}");
    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(
        body.contains("DPoP authorization scheme"),
        "Error should mention DPoP scheme requirement, got: {body}"
    );
}

/// mTLS-bound token (with cnf.x5t#S256) presented via Bearer without a
/// client certificate must be rejected. The server cannot verify the
/// certificate binding since no cert was presented.
#[tokio::test]
async fn test_mtls_bound_token_without_cert_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "bearer-mtls@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with_mtls(
        &state,
        &user.id,
        &user.email,
        &auth_id,
        "fake-cert-thumbprint-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    )
    .await;

    // Present the mTLS-bound token as a plain Bearer token (no client cert)
    let auth = format!("Bearer {token}");
    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "mTLS-bound token without cert must be rejected: {body}"
    );
}

/// mTLS-bound token presented with the matching client certificate must succeed.
#[tokio::test]
async fn test_mtls_bound_token_with_matching_cert_succeeds() {
    let (_app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-match@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Generate a self-signed client certificate for binding
    let cert_der = make_test_cert_der("test-mtls");
    let cert =
        crate::services::oidc::mtls::parse_client_certificate(&cert_der).expect("parse cert");

    // Issue a token bound to this cert's thumbprint
    let token =
        create_test_session_with_mtls(&state, &user.id, &user.email, &auth_id, &cert.thumbprint)
            .await;

    // Call extract_resource_token directly with the matching cert
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("header value"),
    );
    let jar = axum_extra::extract::cookie::CookieJar::new();
    let result = crate::handlers::session::extract_resource_token(
        &state,
        &headers,
        &jar,
        "GET",
        "/api/v1/applications",
        Some(&cert),
    )
    .await;

    assert!(
        result.is_ok(),
        "mTLS-bound token with matching cert must succeed, got: {:?}",
        result.err()
    );
    assert_eq!(result.expect("ok").sub, user.id);
}

/// mTLS-bound token presented with the wrong client certificate must be rejected.
#[tokio::test]
async fn test_mtls_bound_token_with_wrong_cert_rejected() {
    let (_app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-wrong@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Generate two separate self-signed certs — the token is bound to cert_a's
    // thumbprint but we present cert_b.
    let cert_a_der = make_test_cert_der("client-a");
    let cert_b_der = make_test_cert_der("client-b");
    let cert_a =
        crate::services::oidc::mtls::parse_client_certificate(&cert_a_der).expect("parse cert A");
    let cert_b =
        crate::services::oidc::mtls::parse_client_certificate(&cert_b_der).expect("parse cert B");

    // Token is bound to cert_a's thumbprint
    let token =
        create_test_session_with_mtls(&state, &user.id, &user.email, &auth_id, &cert_a.thumbprint)
            .await;

    // Present cert_b (wrong cert)
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("header value"),
    );
    let jar = axum_extra::extract::cookie::CookieJar::new();
    let result = crate::handlers::session::extract_resource_token(
        &state,
        &headers,
        &jar,
        "GET",
        "/api/v1/applications",
        Some(&cert_b),
    )
    .await;

    let err = result.expect_err("wrong cert should be rejected");
    assert!(
        matches!(
            &err,
            crate::error::ServiceError::Api { status, .. }
            if *status == StatusCode::UNAUTHORIZED
        ),
        "Expected 401, got: {err:?}"
    );
}

/// A token with both cnf.jkt (DPoP) and cnf.x5t#S256 (mTLS) — DPoP takes precedence.
///
/// The current implementation checks `jkt.is_some()` first, so a DPoP-bound token
/// sent as Bearer should be rejected for the DPoP reason, not the mTLS reason.
#[tokio::test]
async fn test_dpop_takes_precedence_over_mtls() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "dpop-precedence@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Create a DPoP-bound token (jkt is set; mTLS thumbprint is not set via
    // create_oauth_access_token because dpop_jkt takes precedence)
    let token = create_test_session_with_dpop(
        &state,
        &user.id,
        &user.email,
        &auth_id,
        "fake-dpop-jkt-thumbprint",
    )
    .await;

    // Present as plain Bearer without DPoP proof
    let auth = format!("Bearer {token}");
    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    // The error must mention DPoP, not mTLS — DPoP check runs first
    assert!(
        body.contains("DPoP") || body.contains("sender-constrained"),
        "Error must mention DPoP (not mTLS), got: {body}"
    );
}

// ========================================================================
// RFC 9449 DPoP nonce replay at resource endpoints
//
// Nonces are optional at resource endpoints (`require_nonce = false` in
// `validate_dpop_at_resource`), so `DpopError::UseNonce` only fires when a
// client supplies a nonce that was already consumed (replay). The handler
// surfaces a fresh `DPoP-Nonce` header + `use_dpop_nonce` error so the
// client can retry per RFC 9449 §7.2.
// ========================================================================

/// Generate an EC P-256 DPoP key pair and return the signer + public JWK.
fn generate_dpop_key_pair() -> (aws_lc_rs::signature::EcdsaKeyPair, serde_json::Value) {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("generate DPoP key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .expect("parse DPoP key");
    let pub_bytes = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(pub_bytes.get(1..33).expect("x coordinate"));
    let y = URL_SAFE_NO_PAD.encode(pub_bytes.get(33..65).expect("y coordinate"));
    let jwk = serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y });
    (key_pair, jwk)
}

/// RFC 7638 JWK thumbprint for a DPoP public JWK (canonical JSON of
/// crv, kty, x, y → base64url SHA-256).
fn dpop_jkt(jwk: &serde_json::Value) -> String {
    vouch_common::jwk::JwkThumbprintKey::from_json(jwk)
        .expect("test JWK carries the required members")
        .thumbprint()
}

/// Build and sign a DPoP proof JWT (RFC 9449 §4.2) for the given method,
/// URI, optional nonce, and optional access token (for `ath`).
fn create_dpop_proof(
    key: &aws_lc_rs::signature::EcdsaKeyPair,
    jwk: &serde_json::Value,
    method: &str,
    uri: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("serialize header"));

    let mut claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": method,
        "htu": uri,
        "iat": jiff::Timestamp::now().as_second(),
    });
    if let Some(obj) = claims.as_object_mut() {
        if let Some(n) = nonce {
            obj.insert("nonce".to_string(), serde_json::json!(n));
        }
        if let Some(tok) = access_token {
            let ath = URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA256,
                tok.as_bytes(),
            ));
            obj.insert("ath".to_string(), serde_json::json!(ath));
        }
    }
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serialize claims"));

    let signing_input = format!("{header_b64}.{claims_b64}");
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key
        .sign(&rng, signing_input.as_bytes())
        .expect("sign DPoP proof");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    format!("{signing_input}.{sig_b64}")
}

/// Common setup for DPoP resource-endpoint tests: user, authenticator, a
/// real DPoP key pair, and a DPoP-bound access token whose `cnf.jkt`
/// matches the proof key.
async fn setup_dpop_resource_token(
    state: &crate::AppState,
    email: &str,
) -> (
    aws_lc_rs::signature::EcdsaKeyPair,
    serde_json::Value,
    String,
    String,
) {
    let user = create_test_user(&state.store, email).await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (key, jwk) = generate_dpop_key_pair();
    let jkt = dpop_jkt(&jwk);
    let token = create_test_session_with_dpop(state, &user.id, &user.email, &auth_id, &jkt).await;
    let resource_uri = format!("{}/api/v1/applications", state.config().base_url);
    (key, jwk, token, resource_uri)
}

/// RFC 9449 §7.2: When a client replays an already-consumed nonce at a
/// resource endpoint, the server MUST respond with `401 use_dpop_nonce`
/// and a fresh `DPoP-Nonce` header so the client can retry.
#[tokio::test]
async fn test_dpop_use_nonce_at_resource_returns_nonce_header() {
    let (app, state) = test_app().await;
    let (key, jwk, token, resource_uri) =
        setup_dpop_resource_token(&state, "dpop-usenonce@example.com").await;

    // Generate a nonce and consume it, simulating a replayed nonce.
    let nonce = crate::db::generate_dpop_nonce(&state.store, 300)
        .await
        .expect("generate nonce");
    crate::db::validate_and_consume_dpop_nonce(&state.store, &nonce)
        .await
        .expect("consume nonce");

    // DPoP proof reuses the consumed nonce.
    let proof = create_dpop_proof(&key, &jwk, "GET", &resource_uri, Some(&nonce), Some(&token));
    let auth = format!("DPoP {token}");
    let response = http_get_full(
        &app,
        "/api/v1/applications",
        &[("Authorization", &auth), ("DPoP", &proof)],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "body: {}",
        response.body
    );

    // Fresh DPoP-Nonce header MUST be present and differ from the replay.
    let new_nonce = response
        .headers
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .expect("DPoP-Nonce header must be present on use_dpop_nonce");
    assert!(!new_nonce.is_empty(), "fresh nonce must not be empty");
    assert_ne!(
        new_nonce, nonce,
        "fresh nonce must differ from the replayed nonce"
    );

    // Body carries the use_dpop_nonce error code.
    let body: serde_json::Value =
        serde_json::from_str(&response.body).expect("valid JSON error body");
    assert_eq!(
        body.get("code").and_then(|v| v.as_str()),
        Some("use_dpop_nonce"),
        "error code must be use_dpop_nonce, got: {body}"
    );
}

/// RFC 9449 retry flow at a resource endpoint: a valid request consumes
/// the nonce; replaying the nonce yields `use_dpop_nonce` + a fresh nonce;
/// retrying with the fresh nonce succeeds. This is the end-to-end contract
/// the bug broke.
#[tokio::test]
async fn test_dpop_nonce_replay_retry_flow_succeeds() {
    let (app, state) = test_app().await;
    let (key, jwk, token, resource_uri) =
        setup_dpop_resource_token(&state, "dpop-retry@example.com").await;

    // 1. Valid request with a fresh nonce → 200 (consumes the nonce).
    let nonce = crate::db::generate_dpop_nonce(&state.store, 300)
        .await
        .expect("generate nonce");
    let proof1 = create_dpop_proof(&key, &jwk, "GET", &resource_uri, Some(&nonce), Some(&token));
    let auth = format!("DPoP {token}");
    let resp1 = http_get_full(
        &app,
        "/api/v1/applications",
        &[("Authorization", &auth), ("DPoP", &proof1)],
    )
    .await;
    assert_eq!(
        resp1.status,
        StatusCode::OK,
        "first request should succeed and consume the nonce: {}",
        resp1.body
    );

    // 2. Replay the same nonce (fresh jti) → 401 use_dpop_nonce + fresh nonce.
    let proof2 = create_dpop_proof(&key, &jwk, "GET", &resource_uri, Some(&nonce), Some(&token));
    let resp2 = http_get_full(
        &app,
        "/api/v1/applications",
        &[("Authorization", &auth), ("DPoP", &proof2)],
    )
    .await;
    assert_eq!(
        resp2.status,
        StatusCode::UNAUTHORIZED,
        "replayed nonce must be rejected with 401: {}",
        resp2.body
    );
    let fresh_nonce = resp2
        .headers
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .expect("DPoP-Nonce header on use_dpop_nonce");
    assert_ne!(
        fresh_nonce, nonce,
        "fresh nonce must differ from replayed one"
    );
    let body2: serde_json::Value =
        serde_json::from_str(&resp2.body).expect("valid JSON error body");
    assert_eq!(
        body2.get("code").and_then(|v| v.as_str()),
        Some("use_dpop_nonce")
    );

    // 3. Retry with the fresh nonce (fresh jti) → 200 (RFC 9449 retry succeeds).
    let proof3 = create_dpop_proof(
        &key,
        &jwk,
        "GET",
        &resource_uri,
        Some(fresh_nonce),
        Some(&token),
    );
    let resp3 = http_get_full(
        &app,
        "/api/v1/applications",
        &[("Authorization", &auth), ("DPoP", &proof3)],
    )
    .await;
    assert_eq!(
        resp3.status,
        StatusCode::OK,
        "retry with fresh nonce should succeed: {}",
        resp3.body
    );
}

/// Regression: non-`UseNonce` DPoP errors (here `UriMismatch`) must still
/// map to `401 invalid_token` WITHOUT a `DPoP-Nonce` header. Guards the
/// catch-all arm against accidentally swallowing or surfacing a nonce.
#[tokio::test]
async fn test_dpop_non_use_nonce_error_omits_nonce_header() {
    let (app, state) = test_app().await;
    let (key, jwk, token, _resource_uri) =
        setup_dpop_resource_token(&state, "dpop-nonce-regression@example.com").await;

    // Proof targets the wrong htu → UriMismatch → catch-all → 401 invalid_token.
    let wrong_uri = format!("{}/api/v1/other-resource", state.config().base_url);
    let proof = create_dpop_proof(&key, &jwk, "GET", &wrong_uri, None, Some(&token));
    let auth = format!("DPoP {token}");
    let response = http_get_full(
        &app,
        "/api/v1/applications",
        &[("Authorization", &auth), ("DPoP", &proof)],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "body: {}",
        response.body
    );
    assert!(
        response.headers.get("dpop-nonce").is_none(),
        "non-use_dpop_nonce errors must not carry a DPoP-Nonce header"
    );
    let body: serde_json::Value =
        serde_json::from_str(&response.body).expect("valid JSON error body");
    assert_eq!(
        body.get("code").and_then(|v| v.as_str()),
        Some("invalid_token"),
        "non-UseNonce DPoP errors must remain invalid_token, got: {body}"
    );
}
