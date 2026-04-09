// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8705 Section 3 — mTLS certificate-bound access tokens at the userinfo endpoint.

use super::helpers::*;

// ========================================================================
// Certificate Helper
// ========================================================================

/// Generate a self-signed P-256 certificate DER for testing.
fn make_test_cert_der(cn: &str) -> Vec<u8> {
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
fn cert_thumbprint(der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der).as_ref())
}

// ========================================================================
// RFC 8705 Section 3 — mTLS Token Binding Tests
// ========================================================================

/// RFC 8705 Section 3: A certificate-bound token MUST be rejected when no
/// client certificate is presented.
#[tokio::test]
async fn test_userinfo_mtls_bound_token_without_cert_returns_401() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "mtls-no-cert@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("client-a");
    let thumbprint = cert_thumbprint(&cert_der);

    let token =
        create_test_session_with_mtls(&state, &user.id, &user.email, &auth_id, &thumbprint).await;

    // No client certificate — should be rejected.
    let (status, body) = http_get_with_cert(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
        None, // no cert
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"].as_str(),
        Some("invalid_token"),
        "Must return invalid_token when cert-bound token presented without cert"
    );
}

/// RFC 8705 Section 3: A certificate-bound token MUST be rejected when the
/// presented client certificate does not match the bound thumbprint.
#[tokio::test]
async fn test_userinfo_mtls_bound_token_with_wrong_cert_returns_401() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "mtls-wrong-cert@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Token is bound to cert A's thumbprint.
    let cert_a_der = make_test_cert_der("client-a");
    let thumbprint_a = cert_thumbprint(&cert_a_der);
    let token =
        create_test_session_with_mtls(&state, &user.id, &user.email, &auth_id, &thumbprint_a).await;

    // Present cert B — a different certificate.
    let cert_b_der = make_test_cert_der("client-b");
    let (status, body) = http_get_with_cert(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
        Some(cert_b_der),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"].as_str(),
        Some("invalid_token"),
        "Must return invalid_token when presented cert thumbprint does not match token binding"
    );
}

/// RFC 8705 Section 3: A certificate-bound token MUST be accepted when the
/// presented client certificate matches the bound thumbprint.
#[tokio::test]
async fn test_userinfo_mtls_bound_token_with_matching_cert_succeeds() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "mtls-match@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("client-match");
    let thumbprint = cert_thumbprint(&cert_der);

    let token =
        create_test_session_with_mtls(&state, &user.id, &user.email, &auth_id, &thumbprint).await;

    // Present the correct certificate.
    let (status, body) = http_get_with_cert(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
        Some(cert_der),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Matching cert should allow access: {body}"
    );
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        userinfo["email"].as_str(),
        Some("mtls-match@example.com"),
        "UserInfo must include the correct email"
    );
}

/// Tokens without `cnf.x5t#S256` must work without a client certificate.
#[tokio::test]
async fn test_userinfo_non_mtls_token_works_without_cert() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "mtls-none@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Plain token — no cert binding.
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // No client certificate — should succeed because token is not cert-bound.
    let (status, body) = http_get_with_cert(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Non-cert-bound token must work without cert: {body}"
    );
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(userinfo["email"].as_str(), Some("mtls-none@example.com"));
}

// ========================================================================
// RFC 8705 Section 3 — Token Structure Validation
// ========================================================================

/// RFC 8705 Section 3: The cnf claim in an mTLS-bound token must contain
/// x5t#S256 matching the bound certificate's SHA-256 thumbprint.
#[tokio::test]
async fn test_rfc8705_cnf_claim_present_in_mtls_bound_token() {
    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "mtls-cnf@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("client-cnf");
    let thumbprint = cert_thumbprint(&cert_der);

    let token =
        create_test_session_with_mtls(&state, &user.id, &user.email, &auth_id, &thumbprint).await;

    // Decode the JWT and inspect the cnf claim
    let claims = decode_jwt_payload(&token);

    let cnf = claims
        .get("cnf")
        .expect("RFC 8705: mTLS-bound token must contain cnf claim");

    let x5t = cnf
        .get("x5t#S256")
        .expect("RFC 8705: cnf must contain x5t#S256")
        .as_str()
        .expect("x5t#S256 must be a string");

    assert_eq!(
        x5t, thumbprint,
        "RFC 8705: x5t#S256 in cnf must match the certificate thumbprint"
    );
}
