// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Client Certificate Authority for issuing X.509 client certificates.
//!
//! Used by RFC 8705 mTLS: the CA signs client certificates, and the
//! mTLS listener trusts this CA for `tls_client_auth` verification.
//!
//! Mirrors the [`SshCa`](super::ssh_ca::SshCa) pattern: Local (dev)
//! or KMS (production).
//!
//! Uses `p256::ecdsa::SigningKey` for local certificate signing because
//! `x509-cert`'s `CertificateBuilder` requires the `signature::Keypair`
//! trait, which `aws-lc-rs` `EcdsaKeyPair` does not implement.

use anyhow::{Context, Result, bail};
use der::asn1::SetOfVec;
use der::{Decode, DecodePem, Encode, EncodePem, oid::ObjectIdentifier};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use spki::EncodePublicKey;
use x509_cert::builder::{Builder as _, CertificateBuilder, Profile};
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::name::RdnSequence;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use super::kms_signer::KmsSignerP256;

/// Client Certificate Authority.
///
/// Supports two modes:
/// - `Local`: Uses a local P-256 ECDSA private key
/// - `Kms`: Uses an AWS KMS P-256 key via `kms:Sign`
pub enum ClientCertCa {
    /// Local P-256 ECDSA key pair for signing certificates.
    Local {
        /// P-256 signing key (used for x509 certificate signing).
        signing_key: SigningKey,
        /// PKCS#8 DER bytes (for serialization if needed).
        pkcs8_der: Vec<u8>,
        /// Self-signed CA certificate (DER-encoded).
        ca_cert_der: Vec<u8>,
    },
    /// AWS KMS P-256 key for signing certificates.
    Kms {
        /// KMS signer that calls `kms:Sign` for each operation.
        signer: KmsSignerP256,
        /// CA certificate (DER-encoded) — provisioned externally,
        /// loaded via `VOUCH_CLIENT_CERT_CA_CERT`.
        ca_cert_der: Vec<u8>,
    },
}

impl ClientCertCa {
    /// Create a KMS-backed Client Certificate CA.
    ///
    /// The CA certificate must be provisioned externally (via
    /// `generate-client-cert-ca` subcommand) and provided as PEM.
    /// Validates that the CA cert's public key matches the KMS key.
    pub async fn from_kms(
        kms_client: aws_sdk_kms::Client,
        key_id: String,
        ca_cert_pem: &str,
    ) -> Result<Self> {
        let signer = KmsSignerP256::new(kms_client, key_id).await?;
        let ca_cert_der = decode_pem_cert(ca_cert_pem)
            .context("Failed to decode client cert CA certificate PEM")?;

        // Validate the CA cert's public key matches the KMS key
        let cert = x509_cert::Certificate::from_der(&ca_cert_der)
            .context("Failed to parse CA certificate DER")?;
        let cert_pub_key = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .context("CA certificate has invalid public key")?;

        if cert_pub_key != signer.public_key_bytes() {
            bail!(
                "CA certificate public key does not match KMS key. \
                 Regenerate the CA cert with the correct KMS key ID."
            );
        }

        Ok(Self::Kms {
            signer,
            ca_cert_der,
        })
    }

    /// Load from PEM content or generate an ephemeral CA.
    ///
    /// - If both key and cert PEM are provided: load them
    /// - If neither: generate ephemeral P-256 key + self-signed CA cert
    pub fn load_or_generate(key_pem: Option<&str>, ca_cert_pem: Option<&str>) -> Result<Self> {
        match (key_pem, ca_cert_pem) {
            (Some(key), Some(cert)) if !key.trim().is_empty() => {
                let pkcs8_der =
                    decode_pem_key(key).context("Failed to decode client cert CA key PEM")?;
                let signing_key = SigningKey::from_pkcs8_der(&pkcs8_der)
                    .map_err(|e| anyhow::anyhow!("Failed to parse client cert CA key: {e}"))?;
                let ca_cert_der =
                    decode_pem_cert(cert).context("Failed to decode client cert CA certificate")?;
                Ok(Self::Local {
                    signing_key,
                    pkcs8_der,
                    ca_cert_der,
                })
            }
            _ => {
                tracing::info!("Generating ephemeral Client Certificate CA");
                Self::generate()
            }
        }
    }

    /// Generate an ephemeral P-256 CA key + self-signed certificate.
    fn generate() -> Result<Self> {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let pkcs8_der = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&signing_key)
            .map_err(|e| anyhow::anyhow!("Failed to encode CA key to PKCS#8: {e}"))?;
        let pkcs8_bytes = pkcs8_der.as_bytes().to_vec();

        let ca_cert_der = build_ca_cert_local(&signing_key, "Vouch Client CA", 3650)?;

        Ok(Self::Local {
            signing_key,
            pkcs8_der: pkcs8_bytes,
            ca_cert_der,
        })
    }

    /// Get the CA certificate in DER format.
    ///
    /// Used to configure the rustls trust store for mTLS client
    /// verification.
    #[must_use]
    pub fn ca_cert_der(&self) -> &[u8] {
        match self {
            Self::Local { ca_cert_der, .. } | Self::Kms { ca_cert_der, .. } => ca_cert_der,
        }
    }

    /// Sign a client certificate.
    ///
    /// Creates an X.509 certificate for the given subject, signed by
    /// this CA.
    pub fn sign_client_cert(&self, subject_cn: &str, validity_days: u32) -> Result<Vec<u8>> {
        let subject = build_dn(subject_cn)?;
        let validity = build_validity(validity_days)?;
        let serial = generate_serial()?;

        match self {
            Self::Local {
                signing_key,
                ca_cert_der,
                ..
            } => {
                let issuer_cert = x509_cert::Certificate::from_der(ca_cert_der)
                    .context("Failed to parse CA certificate")?;
                sign_client_cert_local(signing_key, &issuer_cert, subject, validity, serial)
            }
            Self::Kms {
                signer,
                ca_cert_der,
            } => {
                let issuer_cert = x509_cert::Certificate::from_der(ca_cert_der)
                    .context("Failed to parse CA certificate")?;
                sign_client_cert_kms(signer, &issuer_cert, subject, validity, serial)
            }
        }
    }
}

// -----------------------------------------------------------------------
// pub(crate) helpers for generate-client-cert-ca subcommand
// -----------------------------------------------------------------------

/// Build a self-signed CA certificate using a local P-256 key.
pub(crate) fn build_ca_cert_local(
    signing_key: &SigningKey,
    cn: &str,
    validity_days: u32,
) -> Result<Vec<u8>> {
    let subject = build_dn(cn)?;
    let validity = build_validity(validity_days)?;
    let serial = generate_serial()?;
    let spki = verifying_key_to_spki(signing_key.verifying_key())?;

    let builder = CertificateBuilder::new(
        Profile::SubCA {
            issuer: subject.clone(),
            path_len_constraint: Some(0),
        },
        serial,
        validity,
        subject,
        spki,
        signing_key,
    )
    .context("Failed to create certificate builder")?;

    let cert = builder
        .build::<p256::ecdsa::DerSignature>()
        .context("Failed to build self-signed CA certificate")?;

    cert.to_der()
        .context("Failed to encode CA certificate to DER")
}

/// Build a KMS-signed self-signed CA certificate.
///
/// Constructs the TBS certificate manually and signs with KMS,
/// because `CertificateBuilder` requires `Keypair` which KMS
/// signers cannot implement (no local key material).
pub(crate) fn build_ca_cert_kms(
    signer: &KmsSignerP256,
    cn: &str,
    validity_days: u32,
) -> Result<Vec<u8>> {
    let subject = build_dn(cn)?;
    let validity = build_validity(validity_days)?;
    let serial = generate_serial()?;
    let pub_key_bytes = signer.public_key_bytes();
    let spki = build_ec_spki(pub_key_bytes)?;

    build_and_sign_cert_kms(
        signer,
        serial,
        validity,
        subject.clone(),
        subject,
        spki,
        true,
    )
}

/// Encode a DER-encoded certificate as PEM.
pub(crate) fn cert_der_to_pem(der: &[u8]) -> Result<String> {
    let cert = x509_cert::Certificate::from_der(der)
        .context("Failed to parse certificate DER for PEM encoding")?;
    cert.to_pem(der::pem::LineEnding::LF)
        .context("Failed to encode certificate as PEM")
}

/// Encode PKCS#8 DER private key bytes as PEM.
pub(crate) fn key_der_to_pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

// -----------------------------------------------------------------------
// Client certificate signing
// -----------------------------------------------------------------------

/// Sign a client certificate using a local P-256 key.
fn sign_client_cert_local(
    signing_key: &SigningKey,
    issuer_cert: &x509_cert::Certificate,
    subject: RdnSequence,
    validity: Validity,
    serial: SerialNumber,
) -> Result<Vec<u8>> {
    let client_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let client_spki = verifying_key_to_spki(client_key.verifying_key())?;

    let builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: issuer_cert.tbs_certificate.subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        serial,
        validity,
        subject,
        client_spki,
        signing_key,
    )
    .context("Failed to create client certificate builder")?;

    let cert = builder
        .build::<p256::ecdsa::DerSignature>()
        .context("Failed to build client certificate")?;

    cert.to_der()
        .context("Failed to encode client certificate to DER")
}

/// Sign a client certificate using KMS.
fn sign_client_cert_kms(
    signer: &KmsSignerP256,
    issuer_cert: &x509_cert::Certificate,
    subject: RdnSequence,
    validity: Validity,
    serial: SerialNumber,
) -> Result<Vec<u8>> {
    let client_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let client_spki = verifying_key_to_spki(client_key.verifying_key())?;

    build_and_sign_cert_kms(
        signer,
        serial,
        validity,
        issuer_cert.tbs_certificate.subject.clone(),
        subject,
        client_spki,
        false,
    )
}

// -----------------------------------------------------------------------
// Private helpers
// -----------------------------------------------------------------------

/// Convert a P-256 verifying key to SPKI for the certificate builder.
fn verifying_key_to_spki(
    vk: &p256::ecdsa::VerifyingKey,
) -> Result<spki::SubjectPublicKeyInfoOwned> {
    let spki_der = vk
        .to_public_key_der()
        .map_err(|e| anyhow::anyhow!("Failed to encode verifying key to SPKI: {e}"))?;
    spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_ref())
        .context("Failed to decode SPKI DER")
}

/// Build a Distinguished Name with a Common Name.
fn build_dn(cn: &str) -> Result<RdnSequence> {
    let cn_oid = ObjectIdentifier::new_unwrap("2.5.4.3");
    let cn_value =
        der::asn1::Utf8StringRef::new(cn).map_err(|e| anyhow::anyhow!("Invalid CN value: {e}"))?;
    let atv = x509_cert::attr::AttributeTypeAndValue {
        oid: cn_oid,
        value: der::asn1::Any::from(cn_value),
    };
    let mut rdn = SetOfVec::new();
    rdn.insert(atv)
        .map_err(|e| anyhow::anyhow!("Failed to build RDN: {e}"))?;
    Ok(RdnSequence(vec![
        x509_cert::name::RelativeDistinguishedName(rdn),
    ]))
}

/// Build a Validity period from days.
fn build_validity(days: u32) -> Result<Validity> {
    Validity::from_now(core::time::Duration::from_secs(
        u64::from(days) * 24 * 60 * 60,
    ))
    .map_err(|e| anyhow::anyhow!("Failed to create validity: {e}"))
}

/// Generate a random serial number for certificates.
fn generate_serial() -> Result<SerialNumber> {
    let mut bytes = [0u8; 16];
    aws_lc_rs::rand::fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("Failed to generate random serial"))?;
    // Ensure the high bit is clear (serial must be positive)
    if let Some(first) = bytes.first_mut() {
        *first &= 0x7F;
    }
    // Ensure non-zero
    if bytes.iter().all(|&b| b == 0)
        && let Some(last) = bytes.last_mut()
    {
        *last = 1;
    }
    SerialNumber::new(&bytes).map_err(|e| anyhow::anyhow!("Failed to create serial number: {e}"))
}

/// Build and sign a certificate manually using KMS.
///
/// Constructs `TbsCertificate`, DER-encodes it, signs with KMS,
/// and assembles the final `Certificate`.
fn build_and_sign_cert_kms(
    signer: &KmsSignerP256,
    serial: SerialNumber,
    validity: Validity,
    issuer: RdnSequence,
    subject: RdnSequence,
    subject_spki: spki::SubjectPublicKeyInfoOwned,
    is_ca: bool,
) -> Result<Vec<u8>> {
    use x509_cert::ext::Extension;

    let ecdsa_sha256_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    let sig_alg = spki::AlgorithmIdentifierOwned {
        oid: ecdsa_sha256_oid,
        parameters: None,
    };

    // Build basic constraints extension
    let bc = BasicConstraints {
        ca: is_ca,
        path_len_constraint: if is_ca { Some(0) } else { None },
    };
    let bc_der = bc.to_der().context("Failed to encode basic constraints")?;
    let bc_ext = Extension {
        extn_id: ObjectIdentifier::new_unwrap("2.5.29.19"),
        critical: true,
        extn_value: der::asn1::OctetString::new(bc_der)
            .map_err(|e| anyhow::anyhow!("Failed to wrap BC in OctetString: {e}"))?,
    };

    let tbs = x509_cert::TbsCertificate {
        version: x509_cert::certificate::Version::V3,
        serial_number: serial,
        signature: sig_alg.clone(),
        issuer,
        validity,
        subject,
        subject_public_key_info: subject_spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![bc_ext]),
    };

    let tbs_der = tbs.to_der().context("Failed to encode TBS certificate")?;

    // Sign with KMS (blocking on async — acceptable for provisioning)
    let handle = tokio::runtime::Handle::current();
    let signature_bytes = handle
        .block_on(signer.sign_raw(&tbs_der))
        .context("KMS certificate signing failed")?;

    let signature = der::asn1::BitString::from_bytes(&signature_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to encode signature: {e}"))?;

    let cert = x509_cert::Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature,
    };

    cert.to_der()
        .context("Failed to encode signed certificate to DER")
}

/// Build an EC SPKI (SubjectPublicKeyInfo) for P-256 from raw bytes.
///
/// Used for KMS path where we only have the raw uncompressed point.
fn build_ec_spki(uncompressed_point: &[u8]) -> Result<spki::SubjectPublicKeyInfoOwned> {
    let ec_public_key_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    let p256_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

    let ec_params = der::asn1::AnyRef::from(&p256_oid);
    let algorithm = spki::AlgorithmIdentifierOwned {
        oid: ec_public_key_oid,
        parameters: Some(der::asn1::Any::from(ec_params)),
    };

    Ok(spki::SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key: der::asn1::BitString::from_bytes(uncompressed_point)
            .map_err(|e| anyhow::anyhow!("Failed to encode public key: {e}"))?,
    })
}

/// Decode PEM certificate (supports base64-encoded PEM).
fn decode_pem_cert(pem_content: &str) -> Result<Vec<u8>> {
    let pem = if pem_content.trim().starts_with("-----BEGIN") {
        pem_content.trim().to_string()
    } else {
        super::pem::decode_base64_pem(pem_content).context("Failed to decode base64 PEM")?
    };
    let cert = x509_cert::Certificate::from_pem(&pem).context("Failed to parse PEM certificate")?;
    cert.to_der()
        .context("Failed to re-encode certificate to DER")
}

/// Decode PEM private key (supports base64-encoded PEM).
fn decode_pem_key(pem_content: &str) -> Result<Vec<u8>> {
    let pem = if pem_content.trim().starts_with("-----BEGIN") {
        pem_content.trim().to_string()
    } else {
        super::pem::decode_base64_pem(pem_content).context("Failed to decode base64 PEM key")?
    };
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut reader)
        .context("Failed to parse PEM private key")?
        .context("No private key found in PEM")?;
    Ok(key.secret_der().to_vec())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ephemeral_ca() {
        let ca = ClientCertCa::generate().expect("CA generation failed");
        let cert_der = ca.ca_cert_der();
        assert!(!cert_der.is_empty(), "CA cert should not be empty");

        let cert = x509_cert::Certificate::from_der(cert_der).expect("Failed to parse CA cert");
        let subject = cert.tbs_certificate.subject.to_string();
        assert!(
            subject.contains("Vouch Client CA"),
            "Subject should contain CA name, got: {subject}"
        );

        // Verify CA basic constraints extension is present
        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .expect("CA cert should have extensions");
        let bc_oid = ObjectIdentifier::new_unwrap("2.5.29.19");
        let has_bc = extensions.iter().any(|ext| ext.extn_id == bc_oid);
        assert!(has_bc, "CA cert should have basic constraints");
    }

    #[test]
    fn test_load_or_generate_ephemeral() {
        let ca =
            ClientCertCa::load_or_generate(None, None).expect("Ephemeral CA generation failed");
        assert!(!ca.ca_cert_der().is_empty(), "CA cert should not be empty");
    }

    #[test]
    fn test_sign_client_cert() {
        let ca = ClientCertCa::generate().expect("CA generation");
        let cert_der = ca
            .sign_client_cert("test-client", 365)
            .expect("Client cert signing failed");

        let cert =
            x509_cert::Certificate::from_der(&cert_der).expect("Failed to parse client cert");
        let subject = cert.tbs_certificate.subject.to_string();
        assert!(
            subject.contains("test-client"),
            "Subject should contain client name, got: {subject}"
        );

        // Client cert should NOT be a CA
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            let bc_oid = ObjectIdentifier::new_unwrap("2.5.29.19");
            for ext in extensions {
                if ext.extn_id == bc_oid {
                    let bc =
                        BasicConstraints::from_der(ext.extn_value.as_bytes()).expect("parse BC");
                    assert!(!bc.ca, "Client cert should not be CA");
                }
            }
        }
    }

    #[test]
    fn test_build_dn() {
        let dn = build_dn("Test Subject").expect("DN build");
        let s = dn.to_string();
        assert!(s.contains("Test Subject"), "DN should contain subject: {s}");
    }

    #[test]
    fn test_generate_serial_uniqueness() {
        let mut serials = std::collections::HashSet::new();
        for _ in 0..100 {
            let serial = generate_serial().expect("serial gen");
            let bytes = serial.as_bytes();
            assert!(serials.insert(bytes.to_vec()), "Serial collision detected");
        }
    }

    #[test]
    fn test_pem_roundtrip() {
        let ca = ClientCertCa::generate().expect("CA generation");
        let der = ca.ca_cert_der();
        let pem = cert_der_to_pem(der).expect("PEM encode");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));

        let decoded = decode_pem_cert(&pem).expect("PEM decode");
        assert_eq!(decoded, der);
    }
}
