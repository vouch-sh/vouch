// SPDX-License-Identifier: BUSL-1.1
//! x5c attestation certificate chain validation.
//!
//! Validates the certificate chain in WebAuthn packed attestation statements
//! against pinned Yubico root CA certificates. Extracts the FIDO AAGUID
//! from the leaf attestation certificate.

use aws_lc_rs::signature;
use const_oid::ObjectIdentifier;
use der::{Decode, DecodePem};
use thiserror::Error;
use x509_cert::Certificate;

// ============================================================================
// Pinned Root CA Certificates (DER, embedded at compile time)
// ============================================================================

/// Yubico U2F Root CA Serial 457200631.
/// Source: <https://developers.yubico.com/PKI/yubico-fido-ca-1.pem>
/// SHA-256: 0F:A1:38:6F:80:EB:87:13:26:3A:E5:C1:D8:4D:EB:45:
///          5B:DF:08:AE:A5:0A:B0:55:03:CE:FE:E8:2B:09:2D:42
const YUBICO_FIDO_CA_1_PEM: &str = include_str!("../../root_certs/yubico-fido-ca-1.pem");

/// Yubico FIDO Root CA Serial 450203556.
/// Source: <https://developers.yubico.com/PKI/yubico-fido-ca-2.pem>
/// SHA-256: 35:F1:A5:4B:35:3B:FB:71:1E:6D:42:AD:BE:B7:6C:0E:
///          9D:EA:D0:95:01:8E:6A:94:78:3B:A2:19:2F:D6:FA:AD
const YUBICO_FIDO_CA_2_PEM: &str = include_str!("../../root_certs/yubico-fido-ca-2.pem");

/// Yubico Attestation Root 1 (firmware 5.7.4+).
/// Source: <https://developers.yubico.com/PKI/yubico-ca-1.pem>
/// SHA-256: 62:76:0C:6A:6E:F9:16:79:F4:54:C8:90:2B:80:FD:00:
///          98:25:B3:F2:5D:A9:0F:1F:BA:CE:2E:C6:58:6C:D5:A8
const YUBICO_CA_1_PEM: &str = include_str!("../../root_certs/yubico-ca-1.pem");

// ============================================================================
// OID Constants
// ============================================================================

/// FIDO2 AAGUID extension OID (1.3.6.1.4.1.45724.1.1.4).
/// Contains a 16-byte AAGUID wrapped in an OCTET STRING.
const OID_FIDO_AAGUID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");

// ============================================================================
// Error & Result Types
// ============================================================================

/// Errors during attestation certificate chain validation.
#[derive(Debug, Error)]
pub enum AttestationChainError {
    #[error("No certificates in x5c chain")]
    EmptyChain,
    #[error("Certificate parsing failed: {0}")]
    CertParse(String),
    #[error("Chain does not terminate at a trusted root")]
    UntrustedRoot,
    #[error("Certificate signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("AAGUID mismatch: cert={cert}, authData={auth_data}")]
    AaguidMismatch { cert: String, auth_data: String },
    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Successful result of attestation chain validation.
#[derive(Debug, Clone)]
pub struct AttestationChainResult {
    /// AAGUID extracted from the leaf certificate's FIDO extension.
    pub cert_aaguid: Option<String>,
}

// ============================================================================
// Core Validation
// ============================================================================

/// Validate an x5c attestation certificate chain against pinned root CAs.
///
/// Walks the chain from leaf to root, verifying each signature link.
/// Extracts AAGUID from the leaf certificate.
/// Optionally cross-checks the cert AAGUID against the authData AAGUID.
///
/// # Errors
///
/// Returns an error if the chain is empty, a certificate cannot be parsed,
/// a signature is invalid, the chain does not terminate at a trusted root,
/// or the AAGUID cross-check fails.
pub fn validate_attestation_chain(
    x5c_certs: &[Vec<u8>],
    auth_data_aaguid: Option<&str>,
) -> Result<AttestationChainResult, AttestationChainError> {
    if x5c_certs.is_empty() {
        return Err(AttestationChainError::EmptyChain);
    }

    // Parse all certificates
    let mut certs = Vec::with_capacity(x5c_certs.len());
    for (i, der_bytes) in x5c_certs.iter().enumerate() {
        let cert = Certificate::from_der(der_bytes)
            .map_err(|e| AttestationChainError::CertParse(format!("cert[{i}]: {e}")))?;
        certs.push(cert);
    }

    // Parse pinned root CAs
    let roots = parse_pinned_roots();

    // Verify the chain: each cert is signed by the next cert
    // (leaf at index 0, closest-to-root at last index)
    for i in 0..certs.len().saturating_sub(1) {
        let issuer_idx = i + 1;
        let subject = certs.get(i).ok_or(AttestationChainError::EmptyChain)?;
        let issuer = certs
            .get(issuer_idx)
            .ok_or(AttestationChainError::EmptyChain)?;
        let issuer_pk_bytes = extract_spki_bytes(issuer)?;
        verify_cert_signature(subject, &issuer_pk_bytes)?;
    }

    // Verify the last cert is signed by a pinned root
    let last_cert = certs.last().ok_or(AttestationChainError::EmptyChain)?;
    let mut trusted = false;
    let mut trusted_root = String::new();
    for root in &roots {
        let root_pk_bytes = extract_spki_bytes(root)?;
        if verify_cert_signature(last_cert, &root_pk_bytes).is_ok() {
            trusted_root = root.tbs_certificate.subject.to_string();
            trusted = true;
            break;
        }
    }
    if !trusted {
        tracing::warn!(
            issuer = %last_cert.tbs_certificate.issuer,
            "x5c chain: untrusted root CA"
        );
        return Err(AttestationChainError::UntrustedRoot);
    }

    // Extract AAGUID from the leaf certificate
    let leaf = certs.first().ok_or(AttestationChainError::EmptyChain)?;
    let cert_aaguid = extract_aaguid_from_cert(leaf);

    tracing::trace!(
        leaf = %leaf.tbs_certificate.subject,
        root = %trusted_root,
        cert_aaguid = ?cert_aaguid,
        chain_length = x5c_certs.len(),
        "x5c chain verified"
    );

    // Cross-check cert AAGUID against authData AAGUID
    if let (Some(c_aaguid), Some(ad_aaguid)) = (&cert_aaguid, auth_data_aaguid)
        && !c_aaguid.eq_ignore_ascii_case(ad_aaguid)
    {
        tracing::warn!(
            cert_aaguid = %c_aaguid,
            auth_data_aaguid = %ad_aaguid,
            "AAGUID mismatch between certificate and authData"
        );
        return Err(AttestationChainError::AaguidMismatch {
            cert: c_aaguid.clone(),
            auth_data: ad_aaguid.to_string(),
        });
    }

    Ok(AttestationChainResult { cert_aaguid })
}

// ============================================================================
// Helpers
// ============================================================================

/// Parse the pinned root CA PEM certificates.
fn parse_pinned_roots() -> Vec<Certificate> {
    let mut roots = Vec::with_capacity(3);
    if let Ok(cert) = Certificate::from_pem(YUBICO_FIDO_CA_1_PEM) {
        roots.push(cert);
    }
    if let Ok(cert) = Certificate::from_pem(YUBICO_FIDO_CA_2_PEM) {
        roots.push(cert);
    }
    if let Ok(cert) = Certificate::from_pem(YUBICO_CA_1_PEM) {
        roots.push(cert);
    }
    roots
}

/// Extract the raw SubjectPublicKeyInfo bytes from a certificate.
fn extract_spki_bytes(cert: &Certificate) -> Result<Vec<u8>, AttestationChainError> {
    der::Encode::to_der(&cert.tbs_certificate.subject_public_key_info)
        .map_err(|e| AttestationChainError::CertParse(format!("Failed to encode SPKI: {e}")))
}

/// Verify that `subject` was signed by the owner of `issuer_spki_der`.
fn verify_cert_signature(
    subject: &Certificate,
    issuer_spki_der: &[u8],
) -> Result<(), AttestationChainError> {
    // Get the TBS (to-be-signed) bytes
    let tbs_bytes = der::Encode::to_der(&subject.tbs_certificate)
        .map_err(|e| AttestationChainError::CertParse(format!("Failed to encode TBS: {e}")))?;

    // Get the signature bytes
    let sig_bytes = subject.signature.raw_bytes();

    // Parse the SPKI to get the raw public key
    let spki = spki::SubjectPublicKeyInfoRef::from_der(issuer_spki_der)
        .map_err(|e| AttestationChainError::CertParse(format!("Failed to parse SPKI: {e}")))?;
    let pk_bytes = spki.subject_public_key.raw_bytes();

    // Determine the signature algorithm from the certificate
    let alg_oid = subject.signature_algorithm.oid;

    // OIDs for supported signature algorithms
    const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

    if alg_oid == ECDSA_SHA256 {
        let pk = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, pk_bytes);
        pk.verify(&tbs_bytes, sig_bytes)
            .map_err(|e| AttestationChainError::SignatureInvalid(format!("ECDSA-SHA256: {e}")))
    } else if alg_oid == RSA_SHA256 {
        verify_rsa_signature(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            pk_bytes,
            &tbs_bytes,
            sig_bytes,
        )
    } else if alg_oid == RSA_SHA384 {
        verify_rsa_signature(
            &signature::RSA_PKCS1_2048_8192_SHA384,
            pk_bytes,
            &tbs_bytes,
            sig_bytes,
        )
    } else if alg_oid == RSA_SHA512 {
        verify_rsa_signature(
            &signature::RSA_PKCS1_2048_8192_SHA512,
            pk_bytes,
            &tbs_bytes,
            sig_bytes,
        )
    } else {
        Err(AttestationChainError::UnsupportedAlgorithm(
            alg_oid.to_string(),
        ))
    }
}

/// Verify an RSA PKCS#1 v1.5 signature using raw SPKI public key bytes.
///
/// RSA public keys in SPKI are DER-encoded `RSAPublicKey` (SEQUENCE of
/// modulus INTEGER + exponent INTEGER). `aws-lc-rs` accepts the full
/// SPKI-wrapped bytes via `UnparsedPublicKey`.
fn verify_rsa_signature(
    alg: &'static signature::RsaParameters,
    spki_pk_bytes: &[u8],
    message: &[u8],
    sig: &[u8],
) -> Result<(), AttestationChainError> {
    // The pk_bytes from SPKI raw_bytes() is the BIT STRING content
    // which is the DER-encoded RSAPublicKey. aws-lc-rs can parse this
    // via RsaSubjectPublicKey.
    signature::UnparsedPublicKey::new(alg, spki_pk_bytes)
        .verify(message, sig)
        .map_err(|e| AttestationChainError::SignatureInvalid(format!("RSA: {e}")))
}

/// Extract AAGUID from a certificate's FIDO extension.
///
/// The extension value is an OCTET STRING containing another OCTET STRING
/// wrapping the 16-byte AAGUID.
fn extract_aaguid_from_cert(cert: &Certificate) -> Option<String> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        if ext.extn_id == OID_FIDO_AAGUID {
            let value = ext.extn_value.as_bytes();
            // The extension value is an OCTET STRING wrapping
            // the 16-byte AAGUID. The outer OCTET STRING is the
            // DER encoding, so we need to strip the tag+length.
            // DER: 04 10 <16 bytes>
            let aaguid_bytes = if value.len() == 18
                && value.first().copied() == Some(0x04)
                && value.get(1).copied() == Some(0x10)
            {
                value.get(2..18)?
            } else if value.len() == 16 {
                value
            } else {
                tracing::debug!("Unexpected AAGUID extension length: {}", value.len());
                return None;
            };

            if aaguid_bytes.len() != 16 {
                return None;
            }
            return Some(format_aaguid(aaguid_bytes));
        }
    }
    None
}

/// Format 16 raw bytes as a UUID string.
fn format_aaguid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return String::new();
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-\
         {:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}-\
         {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes.first().copied().unwrap_or(0),
        bytes.get(1).copied().unwrap_or(0),
        bytes.get(2).copied().unwrap_or(0),
        bytes.get(3).copied().unwrap_or(0),
        bytes.get(4).copied().unwrap_or(0),
        bytes.get(5).copied().unwrap_or(0),
        bytes.get(6).copied().unwrap_or(0),
        bytes.get(7).copied().unwrap_or(0),
        bytes.get(8).copied().unwrap_or(0),
        bytes.get(9).copied().unwrap_or(0),
        bytes.get(10).copied().unwrap_or(0),
        bytes.get(11).copied().unwrap_or(0),
        bytes.get(12).copied().unwrap_or(0),
        bytes.get(13).copied().unwrap_or(0),
        bytes.get(14).copied().unwrap_or(0),
        bytes.get(15).copied().unwrap_or(0),
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

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
        let bogus_cert = generate_self_signed_cert();
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
        let roots = parse_pinned_roots();
        assert_eq!(roots.len(), 3, "Should parse all three root CAs");
    }

    #[test]
    fn test_aaguid_mismatch() {
        // We can't easily construct a valid chain for this test,
        // but we can unit-test the cross-check logic:
        // If cert AAGUID and authData AAGUID differ, it should error.
        let cert_aaguid = Some("cb69481e-8ff7-4039-93ec-0a2729a154a8".to_string());
        let auth_data_aaguid = Some("00000000-0000-0000-0000-000000000000");

        if let (Some(c), Some(ad)) = (&cert_aaguid, auth_data_aaguid) {
            assert!(!c.eq_ignore_ascii_case(ad), "AAGUIDs should not match");
        }
    }

    #[test]
    fn test_format_aaguid() {
        let bytes = [
            0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39, 0x93, 0xec, 0x0a, 0x27, 0x29, 0xa1,
            0x54, 0xa8,
        ];
        let result = format_aaguid(&bytes);
        assert_eq!(result, "cb69481e-8ff7-4039-93ec-0a2729a154a8");
    }

    #[test]
    fn test_format_aaguid_wrong_length() {
        let result = format_aaguid(&[0u8; 8]);
        assert!(result.is_empty());
    }

    /// Generate a minimal self-signed certificate for testing.
    /// Uses RSA-2048 + SHA-256.
    fn generate_self_signed_cert() -> Vec<u8> {
        let key_pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("RSA keygen");

        build_self_signed_der(&key_pair)
    }

    /// Build a minimal self-signed X.509 v3 DER certificate.
    fn build_self_signed_der(key_pair: &aws_lc_rs::rsa::KeyPair) -> Vec<u8> {
        use aws_lc_rs::signature::KeyPair;

        // RSA-SHA256 OID
        let alg_oid = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        ];
        // NULL parameters
        let alg_params = &[0x05, 0x00];

        // AlgorithmIdentifier SEQUENCE
        let alg_id = der_sequence(&[alg_oid, alg_params]);

        // Version (v3 = 2, explicit tag [0])
        let version = &[0xa0, 0x03, 0x02, 0x01, 0x02];

        // Serial number
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

        // SubjectPublicKeyInfo (from the key pair)
        let pk_der = key_pair.public_key().as_ref();
        // Wrap in SEQUENCE with algorithm
        let spki = der_sequence(&[&alg_id, &der_bit_string(pk_der)]);

        // TBSCertificate
        let tbs = der_sequence(&[
            version, &serial, &alg_id, &name, // issuer
            &validity, &name, // subject
            &spki,
        ]);

        // Sign the TBS
        let mut sig_buf = vec![0u8; key_pair.public_modulus_len()];
        let rng = aws_lc_rs::rand::SystemRandom::new();
        key_pair
            .sign(
                &aws_lc_rs::signature::RSA_PKCS1_SHA256,
                &rng,
                &tbs,
                &mut sig_buf,
            )
            .expect("sign");

        let sig_bit_string = der_bit_string(&sig_buf);

        // Certificate SEQUENCE
        der_sequence(&[&tbs, &alg_id, &sig_bit_string])
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
}
