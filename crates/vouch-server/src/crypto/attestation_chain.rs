// SPDX-License-Identifier: Apache-2.0 OR MIT
//! x5c attestation certificate chain validation.
//!
//! Validates the certificate chain in WebAuthn packed attestation statements
//! against pinned Yubico root CA certificates. Extracts the FIDO AAGUID
//! from the leaf attestation certificate.

use std::sync::LazyLock;

use super::oid;
use aws_lc_rs::signature;
use const_oid::ObjectIdentifier;
use der::{Decode, DecodePem};
use thiserror::Error;
use x509_cert::{Certificate, certificate::Version, ext::pkix::BasicConstraints};

// ============================================================================
// Pinned Root CA Certificates (PEM, embedded at compile time)
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

/// FIDO2 AAGUID extension OID (WebAuthn Level 2 Section 8.2.1).
const OID_FIDO_AAGUID: ObjectIdentifier = oid::extension::FIDO_GEN_CE_AAGUID;

/// Basic Constraints extension OID (RFC 5280 Section 4.2.1.9).
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = oid::extension::BASIC_CONSTRAINTS;

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
    #[error("Attestation certificate does not meet WebAuthn Section 8.2.1: {0}")]
    CertRequirements(String),
}

/// Evidence that an attestation certificate chain was validated.
///
/// Returned only by [`validate_attestation_chain`], and its field is private,
/// so a value of this type cannot be produced without having run the
/// validation. Callers therefore record attestation status as
/// `Option<AttestationProof>` and derive the stored boolean with `is_some`,
/// rather than carrying a boolean anyone can set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationProof {
    /// AAGUID extracted from the leaf certificate's FIDO extension.
    cert_aaguid: Option<String>,
}

impl AttestationProof {
    /// The AAGUID from the leaf certificate's FIDO extension, if present.
    #[must_use]
    pub fn cert_aaguid(&self) -> Option<&str> {
        self.cert_aaguid.as_deref()
    }

    /// Consume the proof, yielding the certificate AAGUID.
    #[must_use]
    pub fn into_cert_aaguid(self) -> Option<String> {
        self.cert_aaguid
    }
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
) -> Result<AttestationProof, AttestationChainError> {
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

    let roots = &*PINNED_ROOTS;

    // Verify the chain: each cert is signed by the next cert
    // (leaf at index 0, closest-to-root at last index)
    for i in 0..certs.len().saturating_sub(1) {
        let issuer_idx = i.saturating_add(1);
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
    for root in roots {
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

    // WebAuthn Level 2 Section 8.2: "Verify that attestnCert meets the
    // requirements in Section 8.2.1 Packed Attestation Statement Certificate
    // Requirements." The leaf is attestnCert -- Section 8.2 fixes its position:
    // "The attestation certificate attestnCert MUST be the first element in
    // the array."
    let leaf = certs.first().ok_or(AttestationChainError::EmptyChain)?;
    check_attestation_cert_requirements(leaf)?;

    // Extract AAGUID from the leaf certificate
    let cert_aaguid = extract_aaguid_from_cert(leaf)?;

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

    Ok(AttestationProof { cert_aaguid })
}

// ============================================================================
// Helpers
// ============================================================================

// Pinned root CAs parsed once at first use. These are compile-time-embedded
// PEM constants — a parse failure means the binary is broken, so expect is
// the correct response (fail loudly on startup, not silently at runtime).
#[expect(
    clippy::expect_used,
    reason = "embedded PEM is a build-time constant; .expect surfaces invalid build"
)]
static PINNED_ROOTS: LazyLock<Vec<Certificate>> = LazyLock::new(|| {
    vec![
        Certificate::from_pem(YUBICO_FIDO_CA_1_PEM)
            .expect("embedded yubico-fido-ca-1.pem is invalid"),
        Certificate::from_pem(YUBICO_FIDO_CA_2_PEM)
            .expect("embedded yubico-fido-ca-2.pem is invalid"),
        Certificate::from_pem(YUBICO_CA_1_PEM).expect("embedded yubico-ca-1.pem is invalid"),
    ]
});

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

    if alg_oid == oid::signature::ECDSA_SHA256 {
        let pk = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, pk_bytes);
        pk.verify(&tbs_bytes, sig_bytes)
            .map_err(|e| AttestationChainError::SignatureInvalid(format!("ECDSA-SHA256: {e}")))
    } else if alg_oid == oid::signature::RSA_SHA256 {
        verify_rsa_signature(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            pk_bytes,
            &tbs_bytes,
            sig_bytes,
        )
    } else if alg_oid == oid::signature::RSA_SHA384 {
        verify_rsa_signature(
            &signature::RSA_PKCS1_2048_8192_SHA384,
            pk_bytes,
            &tbs_bytes,
            sig_bytes,
        )
    } else if alg_oid == oid::signature::RSA_SHA512 {
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

/// Check the leaf against WebAuthn Level 2 Section 8.2.1.
///
/// Section 8.2.1 lists what an attestation certificate "MUST have"; the
/// packed verification procedure in Section 8.2 makes checking them the
/// Relying Party's job. Three of those requirements are checked here:
///
/// * "Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with
///   value 2)."
/// * "The Basic Constraints extension MUST have the CA component set to
///   false." An absent extension is accepted: RFC 5280 Section 4.2.1.9
///   defines `cA` as `BOOLEAN DEFAULT FALSE`, so absence already means false,
///   and Yubico's older U2F end-entity certificates omit the extension.
/// * "The extension MUST NOT be marked as critical", of the
///   `id-fido-gen-ce-aaguid` extension — checked in
///   [`extract_aaguid_from_cert`], which is where that extension is read.
///
/// The Subject requirement (`Subject-C` / `-O` / `-OU` / `-CN`) is not
/// checked. Yubico's U2F end-entity certificates, which chain to two of the
/// three pinned roots, carry a `CN` alone, so enforcing it would reject
/// hardware Vouch is built around. The chain must still terminate at a pinned
/// Yubico root, which is the stronger constraint.
fn check_attestation_cert_requirements(leaf: &Certificate) -> Result<(), AttestationChainError> {
    if leaf.tbs_certificate.version != Version::V3 {
        return Err(AttestationChainError::CertRequirements(format!(
            "attestation certificate version is {:?}, must be V3",
            leaf.tbs_certificate.version
        )));
    }

    if let Some(extensions) = leaf.tbs_certificate.extensions.as_ref() {
        for ext in extensions.iter() {
            if ext.extn_id != OID_BASIC_CONSTRAINTS {
                continue;
            }
            let constraints =
                BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    AttestationChainError::CertRequirements(format!(
                        "Basic Constraints extension is not parseable: {e}"
                    ))
                })?;
            if constraints.ca {
                return Err(AttestationChainError::CertRequirements(
                    "Basic Constraints has the CA component set to true".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Extract AAGUID from a certificate's FIDO extension.
///
/// WebAuthn Level 2 Section 8.2.1: "Note that an X.509 Extension encodes the
/// DER-encoding of the value in an OCTET STRING. Thus, the AAGUID MUST be
/// wrapped in two OCTET STRINGS to be valid." `extn_value` is the outer OCTET
/// STRING, so its contents must be `04 10` followed by the 16 AAGUID bytes.
///
/// Returns `Ok(None)` when the certificate carries no such extension, which is
/// permitted: the extension is required only "if the related attestation root
/// certificate is used for multiple authenticator models". A present but
/// malformed extension is an error rather than a silent `None`, because a
/// `None` would skip the AAGUID cross-check in
/// [`validate_attestation_chain`] instead of failing it.
fn extract_aaguid_from_cert(cert: &Certificate) -> Result<Option<String>, AttestationChainError> {
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(None);
    };
    for ext in extensions.iter() {
        if ext.extn_id != OID_FIDO_AAGUID {
            continue;
        }

        // WebAuthn Level 2 Section 8.2.1: "The extension MUST NOT be marked
        // as critical."
        if ext.critical {
            return Err(AttestationChainError::CertRequirements(
                "id-fido-gen-ce-aaguid extension is marked critical".to_string(),
            ));
        }

        let value = ext.extn_value.as_bytes();
        let inner = value
            .strip_prefix(&[0x04, 0x10])
            .filter(|rest| rest.len() == 16)
            .ok_or_else(|| {
                AttestationChainError::CertRequirements(format!(
                    "id-fido-gen-ce-aaguid value is not an OCTET STRING wrapping \
                     16 bytes ({} bytes)",
                    value.len()
                ))
            })?;
        return Ok(Some(format_aaguid(inner)));
    }
    Ok(None)
}

/// Format 16 raw bytes as a UUID string.
fn format_aaguid(bytes: &[u8]) -> String {
    let arr: [u8; 16] = match bytes.try_into() {
        Ok(a) => a,
        Err(_) => return String::new(),
    };
    uuid::Uuid::from_bytes(arr).as_hyphenated().to_string()
}

#[cfg(test)]
mod tests;
