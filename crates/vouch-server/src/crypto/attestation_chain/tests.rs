// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Tests for x5c attestation certificate chain validation.
//!
//! The WebAuthn Level 2 citations here are quoted from
//! `specs/w3c/webauthn-2.txt`, sections 8.2 and 8.2.1.
//!
//! [`validate_attestation_chain`] refuses any chain that does not terminate at
//! a pinned Yubico root, and no test can mint a certificate under those roots.
//! So the requirements that apply to the leaf are exercised against
//! [`check_attestation_cert_requirements`] and [`extract_aaguid_from_cert`]
//! directly, and the synthetic whole-chain tests assert the outcomes reachable
//! without a trusted signature — ordering, and the rejection itself.
//!
//! The exception is the "Real hardware" section at the end, which runs a
//! captured YubiKey attestation through the full function. It is the only
//! coverage of a successful chain, and therefore the only test that fails if a
//! pinned root is dropped or corrupted.

#![expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;

// ============================================================================
// Whole-chain behavior
// ============================================================================

#[test]
fn test_empty_chain() {
    let result = validate_attestation_chain(&[], None);
    assert!(
        matches!(result, Err(AttestationChainError::EmptyChain)),
        "Expected EmptyChain, got {result:?}"
    );
}

#[test]
fn test_self_signed_rejected() {
    // A self-signed certificate not from Yubico should be rejected
    // Use one of the pinned roots itself — it is self-signed but
    // would need to be IN the chain AND trusted. A single cert
    // that isn't signed by a pinned root should fail.
    let key = new_key();
    let bogus_cert = build_cert(&key, &key, &CertOptions::default());
    let result = validate_attestation_chain(&[bogus_cert], None);
    assert!(
        matches!(
            result,
            Err(AttestationChainError::UntrustedRoot)
                | Err(AttestationChainError::SignatureInvalid(_))
        ),
        "Expected UntrustedRoot or SignatureInvalid, got {result:?}"
    );
}

#[test]
fn test_pinned_roots_parse() {
    assert_eq!(PINNED_ROOTS.len(), 3, "Should parse all three root CAs");
}

/// WebAuthn L2 §8.2, on the `x5c` member of a packed attestation statement:
/// "The attestation certificate attestnCert MUST be the first element in the
/// array."
///
/// The chain walk therefore reads element 0 as the subject and element 1 as
/// its issuer. Feeding it a correctly ordered pair gets as far as the trusted
/// root check; reversing the same two certificates breaks the very first
/// signature link instead, which is how this test tells the two apart.
#[test]
fn test_x5c_is_read_leaf_first() {
    let issuer_key = new_key();
    let leaf_key = new_key();
    let issuer = build_cert(&issuer_key, &issuer_key, &CertOptions::default());
    let leaf = build_cert(&leaf_key, &issuer_key, &CertOptions::default());

    let ordered = validate_attestation_chain(&[leaf.clone(), issuer.clone()], None);
    assert!(
        matches!(ordered, Err(AttestationChainError::UntrustedRoot)),
        "leaf-first chain should verify its link and fail only at the root, got {ordered:?}"
    );

    let reversed = validate_attestation_chain(&[issuer, leaf], None);
    assert!(
        matches!(reversed, Err(AttestationChainError::SignatureInvalid(_))),
        "issuer-first chain should fail the leaf-to-issuer link, got {reversed:?}"
    );
}

// ============================================================================
// WebAuthn L2 §8.2.1 — attestation certificate requirements
// ============================================================================

/// WebAuthn L2 §8.2.1: "The attestation certificate MUST have the following
/// fields/extensions: • Version MUST be set to 3 (which is indicated by an
/// ASN.1 INTEGER with value 2)."
#[test]
fn test_attestation_cert_version_must_be_v3() {
    let key = new_key();
    let v3 = build_cert(&key, &key, &CertOptions::default());
    let v3 = Certificate::from_der(&v3).expect("v3 cert parses");
    assert!(
        check_attestation_cert_requirements(&v3).is_ok(),
        "a version 3 certificate meets the version requirement"
    );

    let v1 = build_cert(
        &key,
        &key,
        &CertOptions {
            version_v3: false,
            ..CertOptions::default()
        },
    );
    let v1 = Certificate::from_der(&v1).expect("v1 cert parses");
    let err = check_attestation_cert_requirements(&v1).expect_err("v1 must be rejected");
    assert!(
        matches!(err, AttestationChainError::CertRequirements(ref m) if m.contains("version")),
        "got {err:?}"
    );
}

/// WebAuthn L2 §8.2.1: "The Basic Constraints extension MUST have the CA
/// component set to false."
#[test]
fn test_attestation_cert_basic_constraints_ca_must_be_false() {
    let key = new_key();
    let ca_cert = build_cert(
        &key,
        &key,
        &CertOptions {
            basic_constraints_ca: Some(true),
            ..CertOptions::default()
        },
    );
    let ca_cert = Certificate::from_der(&ca_cert).expect("cert parses");
    let err = check_attestation_cert_requirements(&ca_cert)
        .expect_err("a CA certificate is not a valid attestation certificate");
    assert!(
        matches!(err, AttestationChainError::CertRequirements(ref m) if m.contains("CA")),
        "got {err:?}"
    );

    let leaf = build_cert(
        &key,
        &key,
        &CertOptions {
            basic_constraints_ca: Some(false),
            ..CertOptions::default()
        },
    );
    let leaf = Certificate::from_der(&leaf).expect("cert parses");
    assert!(check_attestation_cert_requirements(&leaf).is_ok());
}

/// RFC 5280 §4.2.1.9 defines the field as `cA BOOLEAN DEFAULT FALSE`, so a
/// certificate carrying no Basic Constraints extension already asserts
/// `cA = false` and satisfies WebAuthn L2 §8.2.1. Yubico's U2F end-entity
/// certificates omit the extension, and rejecting them would lock out the
/// hardware this server is built around.
#[test]
fn test_attestation_cert_without_basic_constraints_is_accepted() {
    let key = new_key();
    let cert = build_cert(
        &key,
        &key,
        &CertOptions {
            basic_constraints_ca: None,
            ..CertOptions::default()
        },
    );
    let cert = Certificate::from_der(&cert).expect("cert parses");
    assert!(check_attestation_cert_requirements(&cert).is_ok());
}

/// WebAuthn L2 §8.2.1, on `id-fido-gen-ce-aaguid`: "The extension MUST NOT be
/// marked as critical."
#[test]
fn test_aaguid_extension_must_not_be_critical() {
    let key = new_key();
    let cert = build_cert(
        &key,
        &key,
        &CertOptions {
            aaguid: Some(AaguidExt {
                value: wrapped_aaguid(&SAMPLE_AAGUID),
                critical: true,
            }),
            ..CertOptions::default()
        },
    );
    let cert = Certificate::from_der(&cert).expect("cert parses");
    let err = extract_aaguid_from_cert(&cert).expect_err("critical AAGUID extension is rejected");
    assert!(
        matches!(err, AttestationChainError::CertRequirements(ref m) if m.contains("critical")),
        "got {err:?}"
    );
}

/// WebAuthn L2 §8.2.1: "Note that an X.509 Extension encodes the DER-encoding
/// of the value in an OCTET STRING. Thus, the AAGUID MUST be wrapped in two
/// OCTET STRINGS to be valid."
///
/// The section prints the encoding it means, and this test uses that sample:
/// the inner `04 10` header followed by the sixteen AAGUID bytes.
#[test]
fn test_aaguid_must_be_wrapped_in_two_octet_strings() {
    let key = new_key();

    let wrapped = build_cert(
        &key,
        &key,
        &CertOptions {
            aaguid: Some(AaguidExt {
                value: wrapped_aaguid(&SAMPLE_AAGUID),
                critical: false,
            }),
            ..CertOptions::default()
        },
    );
    let wrapped = Certificate::from_der(&wrapped).expect("cert parses");
    assert_eq!(
        extract_aaguid_from_cert(&wrapped).expect("well-formed AAGUID decodes"),
        Some("cd8c395c-26ed-eede-653b-00797d03ca3c".to_string())
    );

    // The same sixteen bytes without the inner OCTET STRING. Accepting this
    // would also mean accepting a certificate AAGUID that never gets
    // cross-checked against authData.
    let bare = build_cert(
        &key,
        &key,
        &CertOptions {
            aaguid: Some(AaguidExt {
                value: SAMPLE_AAGUID.to_vec(),
                critical: false,
            }),
            ..CertOptions::default()
        },
    );
    let bare = Certificate::from_der(&bare).expect("cert parses");
    let err = extract_aaguid_from_cert(&bare).expect_err("a single wrap is not valid");
    assert!(
        matches!(err, AttestationChainError::CertRequirements(ref m) if m.contains("OCTET STRING")),
        "got {err:?}"
    );
}

/// WebAuthn L2 §8.2.1 makes the extension conditional: "If the related
/// attestation root certificate is used for multiple authenticator models,
/// the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be
/// present". A certificate without it is well-formed, and carries no AAGUID
/// to cross-check.
#[test]
fn test_aaguid_extension_is_optional() {
    let key = new_key();
    let cert = build_cert(&key, &key, &CertOptions::default());
    let cert = Certificate::from_der(&cert).expect("cert parses");
    assert_eq!(
        extract_aaguid_from_cert(&cert).expect("no extension is not an error"),
        None
    );
}

#[test]
fn test_format_aaguid() {
    let bytes = [
        0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39, 0x93, 0xec, 0x0a, 0x27, 0x29, 0xa1, 0x54,
        0xa8,
    ];
    let result = format_aaguid(&bytes);
    assert_eq!(result, "cb69481e-8ff7-4039-93ec-0a2729a154a8");
}

#[test]
fn test_format_aaguid_wrong_length() {
    let result = format_aaguid(&[0u8; 8]);
    assert!(result.is_empty());
}

// ============================================================================
// Certificate fixtures
// ============================================================================

/// The AAGUID printed in the WebAuthn L2 §8.2.1 sample extension:
/// `cd 8c 39 5c 26 ed ee de 65 3b 00 79 7d 03 ca 3c`.
const SAMPLE_AAGUID: [u8; 16] = [
    0xcd, 0x8c, 0x39, 0x5c, 0x26, 0xed, 0xee, 0xde, 0x65, 0x3b, 0x00, 0x79, 0x7d, 0x03, 0xca, 0x3c,
];

/// Wrap an AAGUID in the inner OCTET STRING that §8.2.1 requires.
fn wrapped_aaguid(aaguid: &[u8]) -> Vec<u8> {
    der_wrap(0x04, aaguid)
}

/// The `id-fido-gen-ce-aaguid` extension carried by a test certificate.
struct AaguidExt {
    /// The contents of the extension's outer OCTET STRING.
    value: Vec<u8>,
    /// Whether the extension is marked critical.
    critical: bool,
}

/// What to put in a generated test certificate.
struct CertOptions {
    /// Emit an X.509 v3 certificate; false emits v1 (no version field).
    version_v3: bool,
    /// Emit a Basic Constraints extension with this `cA` value.
    basic_constraints_ca: Option<bool>,
    /// Emit an `id-fido-gen-ce-aaguid` extension.
    aaguid: Option<AaguidExt>,
}

impl Default for CertOptions {
    fn default() -> Self {
        Self {
            version_v3: true,
            basic_constraints_ca: None,
            aaguid: None,
        }
    }
}

fn new_key() -> aws_lc_rs::rsa::KeyPair {
    aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).expect("RSA keygen")
}

/// Build an X.509 DER certificate for `subject_key`, signed by `issuer_key`.
///
/// RSA-2048 with SHA-256 throughout, which is one of the algorithms
/// [`verify_cert_signature`] accepts, so a generated pair links as a real
/// chain would.
fn build_cert(
    subject_key: &aws_lc_rs::rsa::KeyPair,
    issuer_key: &aws_lc_rs::rsa::KeyPair,
    opts: &CertOptions,
) -> Vec<u8> {
    use aws_lc_rs::signature::KeyPair;

    // sha256WithRSAEncryption, with NULL parameters.
    let alg_oid = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    ];
    let alg_params = &[0x05, 0x00];
    let alg_id = der_sequence(&[alg_oid, alg_params]);

    // Version (v3 = 2, explicit tag [0]). A v1 certificate omits the field.
    let version: &[u8] = if opts.version_v3 {
        &[0xa0, 0x03, 0x02, 0x01, 0x02]
    } else {
        &[]
    };

    let serial = der_integer(&[0x01]);

    // Issuer/Subject: CN=Test
    let cn_oid = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let cn_value = &[0x0c, 0x04, b'T', b'e', b's', b't'];
    let attr_type_and_value = der_sequence(&[cn_oid, cn_value]);
    let rdn_set = der_set(&[&attr_type_and_value]);
    let name = der_sequence(&[&rdn_set]);

    // Validity: not before/not after (UTCTime)
    // UTCTime: years 00-49 → 2000-2049, years 50-99 → 1950-1999
    let not_before: &[u8] = b"\x17\x0d240101000000Z";
    let not_after: &[u8] = b"\x17\x0d490101000000Z";
    let validity = der_sequence(&[not_before, not_after]);

    let pk_der = subject_key.public_key().as_ref();
    let spki = der_sequence(&[&alg_id, &der_bit_string(pk_der)]);

    let extensions = build_extensions(opts);

    let tbs = der_sequence(&[
        version,
        &serial,
        &alg_id,
        &name, // issuer
        &validity,
        &name, // subject
        &spki,
        &extensions,
    ]);

    let mut sig_buf = vec![0u8; issuer_key.public_modulus_len()];
    let rng = aws_lc_rs::rand::SystemRandom::new();
    issuer_key
        .sign(
            &aws_lc_rs::signature::RSA_PKCS1_SHA256,
            &rng,
            &tbs,
            &mut sig_buf,
        )
        .expect("sign");

    der_sequence(&[&tbs, &alg_id, &der_bit_string(&sig_buf)])
}

/// Build the `[3] EXPLICIT Extensions` field, or nothing when there is none.
fn build_extensions(opts: &CertOptions) -> Vec<u8> {
    let mut items: Vec<Vec<u8>> = Vec::new();

    if let Some(ca) = opts.basic_constraints_ca {
        // id-ce-basicConstraints (2.5.29.19).
        let oid = &[0x06, 0x03, 0x55, 0x1d, 0x13];
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }.
        // DER omits a field at its default, so `cA = false` is an empty
        // SEQUENCE.
        let value = if ca {
            der_sequence(&[&[0x01, 0x01, 0xff]])
        } else {
            der_sequence(&[])
        };
        items.push(der_sequence(&[oid, &der_wrap(0x04, &value)]));
    }

    if let Some(ext) = opts.aaguid.as_ref() {
        // id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4), as encoded in the
        // sample extension printed in WebAuthn L2 §8.2.1.
        let oid = &[
            0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04,
        ];
        let mut fields: Vec<Vec<u8>> = vec![oid.to_vec()];
        if ext.critical {
            fields.push(vec![0x01, 0x01, 0xff]);
        }
        fields.push(der_wrap(0x04, &ext.value));
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        items.push(der_sequence(&refs));
    }

    if items.is_empty() {
        return Vec::new();
    }

    let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    der_wrap(0xa3, &der_sequence(&refs))
}

fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    der_wrap(0x30, &content)
}

fn der_set(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    der_wrap(0x31, &content)
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    der_wrap(0x02, value)
}

fn der_bit_string(value: &[u8]) -> Vec<u8> {
    // BIT STRING: tag 0x03, length, 0x00 (no unused bits), value
    let mut content = vec![0x00];
    content.extend_from_slice(value);
    der_wrap(0x03, &content)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "DER short-form length: each `as u8` is guarded by an explicit branch bound"
)]
fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(content);
    out
}

// ============================================================================
// Real hardware
//
// Everything above builds certificates with a freshly generated key, which by
// construction cannot chain to `PINNED_ROOTS`. These two tests use a capture
// from a physical YubiKey 5C Nano FIPS (Enterprise) and are the only ones that
// exercise a pinned root, so they are what fails if one is dropped, reordered,
// or corrupted. See `fixtures/README.md` for provenance and how to regenerate.
// ============================================================================

/// AAGUID of the YubiKey the fixture was captured from.
const FIXTURE_AAGUID: &str = "28969c24-0487-4a46-be39-37bc6337a24f";

/// Decode the fixture and return its x5c chain plus the authData AAGUID.
fn real_attestation_fixture() -> (Vec<Vec<u8>>, String) {
    use base64::Engine as _;

    let b64 = include_str!("fixtures/yubikey-5c-nano-fips-enterprise.attestation.b64");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.trim())
        .expect("fixture is valid base64url");

    let value: ciborium::Value = ciborium::from_reader(raw.as_slice()).expect("fixture is CBOR");
    let map = value.as_map().expect("attestation object is a CBOR map");

    let auth_data = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("authData"))
        .and_then(|(_, v)| v.as_bytes())
        .expect("fixture has authData");
    let aaguid =
        vouch_common::extract_aaguid_from_auth_data(auth_data).expect("authData carries an AAGUID");

    let certs = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("attStmt"))
        .and_then(|(_, v)| v.as_map())
        .expect("fixture has attStmt")
        .iter()
        .find(|(k, _)| k.as_text() == Some("x5c"))
        .and_then(|(_, v)| v.as_array())
        .expect("fixture has x5c")
        .iter()
        .map(|c| c.as_bytes().expect("x5c element is a byte string").clone())
        .collect();

    (certs, aaguid)
}

/// A genuine YubiKey attestation chains to a pinned root, and the leaf's
/// `id-fido-gen-ce-aaguid` extension names the model. This is the end-to-end
/// evidence that the shipped root list matches real hardware.
#[test]
fn real_yubikey_chain_validates_against_a_pinned_root() {
    let (certs, auth_data_aaguid) = real_attestation_fixture();
    assert_eq!(
        auth_data_aaguid, FIXTURE_AAGUID,
        "fixture authData AAGUID drifted"
    );

    let proof = validate_attestation_chain(&certs, Some(&auth_data_aaguid))
        .expect("a genuine YubiKey chain must validate against the pinned roots");

    assert_eq!(
        proof.cert_aaguid(),
        Some(FIXTURE_AAGUID),
        "the leaf certificate must name the authenticator model"
    );
}

/// WebAuthn Level 2 section 8.2, verification procedure step 2: "If attestnCert
/// contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
/// verify that the value of this extension matches the aaguid in
/// authenticatorData." A forged authData AAGUID must not survive a real chain.
#[test]
fn real_yubikey_chain_rejects_mismatched_auth_data_aaguid() {
    let (certs, _) = real_attestation_fixture();
    let forged = "73bb0cd4-e502-49b8-9c6f-b59445bf720b";
    assert_ne!(forged, FIXTURE_AAGUID);

    let err = validate_attestation_chain(&certs, Some(forged))
        .expect_err("an authData AAGUID the certificate does not vouch for must be rejected");

    assert!(
        matches!(err, AttestationChainError::AaguidMismatch { .. }),
        "expected AaguidMismatch, got {err:?}"
    );
}
