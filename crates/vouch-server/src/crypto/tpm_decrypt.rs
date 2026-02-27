// SPDX-License-Identifier: BUSL-1.1
//! NitroTPM-attested KMS envelope decryption.
//!
//! This module provides optional AWS KMS envelope decryption with NitroTPM attestation.
//! When running on an EC2 instance with NitroTPM enabled, the server can decrypt
//! S3 config secrets using KMS with PCR-based key policies.
//!
//! ## How it works
//!
//! 1. Generate an ephemeral RSA-2048 key pair (via `aws-lc-rs`)
//! 2. Get a NitroTPM attestation document embedding the RSA public key
//!    (via the `nitro-tpm-attest` CLI tool from `aws-nitro-tpm-tools`)
//! 3. Call `kms:Decrypt` with a `Recipient` parameter containing the attestation document
//! 4. KMS returns `CiphertextForRecipient` — a CMS (PKCS#7) envelope with the data key
//!    encrypted to the ephemeral RSA public key
//! 5. Parse the CMS envelope and RSA-OAEP decrypt to recover the plaintext data key
//! 6. Use the data key to AES-256-GCM decrypt the config payload
//!
//! ## Fallback
//!
//! When NitroTPM is not available (dev machines, on-prem), this module is a no-op.
//! The S3 config is loaded as plain JSON (current behavior, unchanged).
//!
//! ## Dependencies
//!
//! - `aws-sdk-kms`: KMS API client
//! - `aws-lc-rs`: RSA key generation, RSA-OAEP decryption, AES-256-GCM decryption
//! - `nitro-tpm-attest` CLI: Installed on NitroTPM-enabled AMIs via `aws-nitro-tpm-tools`

use anyhow::{Context, Result};
use aws_sdk_kms::Client as KmsClient;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::ber::DerParser;

// ============================================================================
// Encrypted Envelope Format
// ============================================================================

/// Encrypted envelope wrapper for S3 config.
///
/// When the S3 config object contains a `kms_key_id` field, it is treated
/// as an encrypted envelope. Uses `kms:GenerateDataKeyPair` to produce a P-384
/// key pair. The `encrypted_private_key` field holds the KMS-encrypted private
/// key, `public_key` is the DER-encoded SPKI, and `encrypted_data` +
/// `encapped_key` form the HPKE ciphertext. The same key pair is reused for
/// `HpkeDocumentCrypto` (database-level document encryption).
#[derive(Deserialize, Serialize)]
pub struct EncryptedEnvelope {
    /// KMS key ID (key ID, not ARN — works across multi-region replicas).
    pub kms_key_id: String,

    /// Base64-encoded KMS ciphertext blob (the encrypted P-384 private key).
    pub encrypted_private_key: String,

    /// Base64-encoded DER `SubjectPublicKeyInfo` for the P-384 public key.
    pub public_key: String,

    /// Base64-encoded HPKE encapsulated key (ephemeral sender key).
    pub encapped_key: String,

    /// Base64-encoded HPKE ciphertext (RFC 9180).
    pub encrypted_data: String,

    /// Envelope format version (for future compatibility).
    #[serde(default = "default_version")]
    pub version: u32,

    /// TLS config (promoted to wrapper for hot-reload without decryption).
    pub tls: Option<crate::infra::s3_config::S3TlsConfig>,

    /// ACME config (promoted to wrapper for external certificate renewal processes).
    #[serde(rename = "_acme", default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<crate::infra::s3_config::S3AcmeConfig>,
}

// Custom Debug that redacts ciphertext fields to prevent accidental log exposure.
impl std::fmt::Debug for EncryptedEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedEnvelope")
            .field("kms_key_id", &self.kms_key_id)
            .field("encrypted_private_key", &"[REDACTED]")
            .field("public_key", &"[REDACTED]")
            .field("encapped_key", &"[REDACTED]")
            .field("encrypted_data", &"[REDACTED]")
            .field("version", &self.version)
            .field("tls", &self.tls)
            .field("acme", &self.acme)
            .finish()
    }
}

/// Key material recovered from envelope decryption.
///
/// Contains the raw P-384 key pair for use with `HpkeDocumentCrypto`.
pub struct HpkeKeyMaterial {
    /// Raw uncompressed P-384 public key (97 bytes: 0x04 || x || y).
    pub public_key: Vec<u8>,
    /// Raw P-384 private key scalar (48 bytes).
    pub private_key: Zeroizing<Vec<u8>>,
}

/// Result of decrypting an encrypted envelope.
pub struct DecryptedEnvelope {
    /// The decrypted inner S3Config JSON bytes.
    pub config_bytes: Zeroizing<Vec<u8>>,
    /// HPKE key material for `HpkeDocumentCrypto`.
    pub hpke_keys: HpkeKeyMaterial,
}

fn default_version() -> u32 {
    1
}

/// HPKE info string for config encryption (binds ciphertext to purpose).
pub const HPKE_CONFIG_INFO: &[u8] = b"vouch-s3-config";

/// Probe whether a JSON blob is an encrypted envelope (has `kms_key_id` field).
///
/// This is a lightweight check before attempting full deserialization.
#[must_use]
pub fn is_encrypted_envelope(json_bytes: &[u8]) -> bool {
    // Quick string search — avoids parsing the full JSON twice.
    // The field name is unique enough to avoid false positives.
    contains_bytes(json_bytes, b"\"kms_key_id\"")
}

/// Check if `haystack` contains the byte sequence `needle`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ============================================================================
// NitroTPM Detection
// ============================================================================

/// Path to the NitroTPM device.
const TPM_DEVICE_PATH: &str = "/dev/tpm0";

/// Name of the attestation CLI tool (from `aws-nitro-tpm-tools` package).
const ATTEST_BINARY: &str = "nitro-tpm-attest";

/// Check if NitroTPM is available on this instance.
#[must_use]
pub fn is_nitro_tpm_available() -> bool {
    std::path::Path::new(TPM_DEVICE_PATH).exists()
}

/// Check if the `nitro-tpm-attest` binary is in PATH.
///
/// Searches PATH entries directly instead of shelling out to `which`
/// (which is not POSIX and may not be present on minimal AMIs).
fn is_attest_binary_available() -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(ATTEST_BINARY).is_file()))
        .is_some_and(|found| found)
}

// ============================================================================
// RSA Key Pair Generation (for encryption/decryption, not signing)
// ============================================================================

/// Ephemeral RSA key pair for attested KMS decryption.
///
/// The public key is embedded in the NitroTPM attestation document.
/// KMS encrypts the response to this public key (RSA-OAEP-SHA256).
/// Only this instance can decrypt the response using the private key.
struct EphemeralRsaKeyPair {
    /// The RSA private decrypting key (for OAEP decryption).
    private_key: aws_lc_rs::rsa::PrivateDecryptingKey,
    /// DER-encoded SubjectPublicKeyInfo (SPKI) public key.
    public_key_der: Vec<u8>,
}

/// Generate an ephemeral RSA-2048 key pair for attested KMS calls.
fn generate_ephemeral_rsa_keypair() -> Result<EphemeralRsaKeyPair> {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};

    // Generate RSA-2048 key pair using the encryption API
    let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048)
        .map_err(|e| anyhow::anyhow!("RSA-2048 key generation failed: {e}"))?;

    // Export public key as X.509 SubjectPublicKeyInfo DER
    let public_key = private_key.public_key();
    let public_key_x509_der = public_key
        .as_der()
        .map_err(|e| anyhow::anyhow!("Failed to serialize RSA public key to DER: {e}"))?;

    Ok(EphemeralRsaKeyPair {
        public_key_der: public_key_x509_der.as_ref().to_vec(),
        private_key,
    })
}

// ============================================================================
// NitroTPM Attestation Document
// ============================================================================

/// Get a NitroTPM attestation document with the given public key embedded.
///
/// Shells out to `nitro-tpm-attest --public-key <tmpfile>` and captures
/// the raw attestation document bytes from stdout.
///
/// This runs synchronously (blocking) since it's called once at startup.
fn get_attestation_document(public_key_der: &[u8]) -> Result<Vec<u8>> {
    // Write public key to a temp file (the CLI reads from a file path)
    let tmp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let pub_key_path = tmp_dir.path().join("rsa_pub.der");
    std::fs::write(&pub_key_path, public_key_der)
        .context("Failed to write public key to temp file")?;

    let output = std::process::Command::new(ATTEST_BINARY)
        .arg("--public-key")
        .arg(&pub_key_path)
        .output()
        .context("Failed to execute nitro-tpm-attest")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Detect NV_DefineSpace size error and provide actionable context.
        // nitro-tpm-attest allocates an 8192-byte NV index for the attestation message
        // buffer. If the NitroTPM's TPM2_PT_NV_INDEX_MAX is smaller (e.g. 2048 on
        // burstable t3/t4g instances), NV_DefineSpace fails with TPM_RC_SIZE (0x2d5).
        if stderr.contains("NV_DefineSpace") || stderr.contains("0x000002d5") {
            anyhow::bail!(
                "nitro-tpm-attest failed: NV_DefineSpace rejected the 8192-byte message buffer. \
                 This instance's NitroTPM TPM2_PT_NV_INDEX_MAX is likely smaller than 8192 \
                 (burstable instance types t3/t4g have a 2048-byte limit). \
                 Use a non-burstable instance type (m5, c7g, etc.). \
                 See https://github.com/aws/NitroTPM-Tools/issues/7 \
                 stderr: {stderr}"
            );
        }

        anyhow::bail!(
            "nitro-tpm-attest failed (exit {}): {}",
            output.status,
            stderr
        );
    }

    if output.stdout.is_empty() {
        anyhow::bail!("nitro-tpm-attest returned empty attestation document");
    }

    tracing::debug!("Got attestation document ({} bytes)", output.stdout.len());

    Ok(output.stdout)
}

// ============================================================================
// KMS Attested Decrypt
// ============================================================================

/// Decrypt a KMS ciphertext blob using NitroTPM attestation.
///
/// This is the core function that:
/// 1. Generates an ephemeral RSA key pair
/// 2. Gets a NitroTPM attestation document embedding the RSA public key
/// 3. Calls `kms:Decrypt` with the `Recipient` parameter
/// 4. Decrypts `CiphertextForRecipient` with the RSA private key
///
/// Returns the plaintext data key (the original KMS plaintext).
async fn attested_kms_decrypt(
    kms_client: &KmsClient,
    key_id: &str,
    ciphertext_blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    // Step 1: Generate ephemeral RSA key pair (fast, CPU-only)
    let rsa_keypair = generate_ephemeral_rsa_keypair()?;
    tracing::debug!("Generated ephemeral RSA-2048 key pair for attested KMS call");

    // Step 2: Get attestation document on a blocking thread because
    // it shells out to nitro-tpm-attest (subprocess I/O via /dev/tpm0).
    let pub_key_der = rsa_keypair.public_key_der.clone();
    let attestation_doc =
        tokio::task::spawn_blocking(move || get_attestation_document(&pub_key_der))
            .await
            .context("Attestation task panicked")?
            .context("Failed to get attestation document")?;

    // Step 3: Call KMS Decrypt with Recipient
    let recipient = aws_sdk_kms::types::RecipientInfo::builder()
        .key_encryption_algorithm(aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256)
        .attestation_document(aws_smithy_types::Blob::new(attestation_doc))
        .build();

    let response = kms_client
        .decrypt()
        .key_id(key_id)
        .ciphertext_blob(aws_smithy_types::Blob::new(ciphertext_blob))
        .recipient(recipient)
        .send()
        .await
        .context("KMS Decrypt with attestation failed")?;

    // Step 4: Extract and decrypt CiphertextForRecipient
    let cms_blob = response
        .ciphertext_for_recipient()
        .context("KMS response missing CiphertextForRecipient (is NitroTPM attestation valid?)")?;

    let plaintext = decrypt_cms_envelope(cms_blob.as_ref(), rsa_keypair.private_key)?;

    tracing::debug!(
        "Successfully decrypted data key via attested KMS call ({} bytes)",
        plaintext.len()
    );

    Ok(plaintext)
}

// ============================================================================
// CMS Envelope Decryption
// ============================================================================

/// Decrypt a CMS (PKCS#7) EnvelopedData structure from KMS `CiphertextForRecipient`.
///
/// The CMS envelope from KMS contains:
/// - A `KeyTransRecipientInfo` with the data key RSA-OAEP encrypted to our public key
/// - An `EncryptedContentInfo` with the actual plaintext encrypted using a content encryption key
///
/// We parse the DER structure minimally to extract the encrypted key and content,
/// then use `aws-lc-rs` for RSA-OAEP decryption and AES-256-CBC decryption.
fn decrypt_cms_envelope(
    cms_der: &[u8],
    private_key: aws_lc_rs::rsa::PrivateDecryptingKey,
) -> Result<Zeroizing<Vec<u8>>> {
    // Parse the CMS EnvelopedData to extract the encrypted key and encrypted content.
    let (encrypted_key, encrypted_content, iv) = parse_cms_enveloped_data(cms_der)
        .context("Failed to parse CMS EnvelopedData from KMS response")?;

    // RSA-OAEP decrypt the content encryption key.
    // Takes ownership of private_key (avoids cloning RSA key material).
    use aws_lc_rs::rsa::{OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey};

    let key_size = private_key.key_size_bytes();
    let oaep_key = OaepPrivateDecryptingKey::new(private_key)
        .map_err(|e| anyhow::anyhow!("Failed to create OAEP decrypting key: {e}"))?;

    let mut decrypted_key_buf = Zeroizing::new(vec![0u8; key_size]);
    let content_key = oaep_key
        .decrypt(
            &OAEP_SHA256_MGF1SHA256,
            &encrypted_key,
            &mut decrypted_key_buf,
            None,
        )
        .map_err(|e| {
            anyhow::anyhow!("RSA-OAEP decryption of content encryption key failed: {e}")
        })?;

    let content_key = Zeroizing::new(content_key.to_vec());

    // AES-256-CBC decrypt the content (KMS uses AES-256-CBC for CMS content encryption)
    let plaintext = aes_256_cbc_decrypt(&content_key, &iv, &encrypted_content)
        .context("AES-256-CBC decryption of CMS content failed")?;

    Ok(plaintext)
}

/// Maximum CMS envelope size (64 KiB). KMS responses are typically ~4 KiB.
const MAX_CMS_SIZE: usize = 64 * 1024;

/// Minimal ASN.1 DER parser to extract fields from a CMS EnvelopedData structure.
///
/// Returns `(encrypted_key, encrypted_content, iv)`.
///
/// The CMS structure from KMS is always:
/// ```text
/// SEQUENCE (ContentInfo) {
///   OID 1.2.840.113549.1.7.3 (envelopedData)
///   [0] EXPLICIT {
///     SEQUENCE (EnvelopedData) {
///       INTEGER (version = 0)
///       SET (RecipientInfos) {
///         SEQUENCE (KeyTransRecipientInfo) {
///           INTEGER (version = 0)
///           ...
///           SEQUENCE (keyEncryptionAlgorithm) { OID (rsaOAEP), ... }
///           OCTET STRING (encryptedKey)         <-- we extract this
///         }
///       }
///       SEQUENCE (EncryptedContentInfo) {
///         OID 1.2.840.113549.1.7.1 (data)
///         SEQUENCE (contentEncryptionAlgorithm) {
///           OID 2.16.840.1.101.3.4.1.42 (aes-256-cbc)
///           OCTET STRING (iv)                   <-- we extract this
///         }
///         [0] IMPLICIT OCTET STRING (encryptedContent)  <-- we extract this
///           (BER: may be constructed 0xa0 with inner OCTET STRING chunks)
///       }
///     }
///   }
/// }
/// ```
///
// Note: The parser only processes ciphertext (RSA-OAEP encrypted key,
// AES-CBC encrypted content) and non-secret parameters (IVs, OIDs).
// Plaintext key material never enters the parser -- decryption happens
// downstream in aws-lc-rs with Zeroizing wrappers.
fn parse_cms_enveloped_data(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if der.len() > MAX_CMS_SIZE {
        anyhow::bail!(
            "CMS envelope too large ({} bytes, max {})",
            der.len(),
            MAX_CMS_SIZE
        );
    }

    let mut parser = DerParser::new(der);

    // KMS CMS responses may use BER indefinite-length encoding on any
    // constructed type, so we use BER-aware methods throughout.

    // ContentInfo SEQUENCE
    let content_info = parser.expect_sequence_ber()?;
    let mut ci_parser = DerParser::new(content_info);

    // OID (envelopedData) — skip
    ci_parser.skip_tlv_ber()?;

    // [0] EXPLICIT wrapper
    let explicit_0 = ci_parser.expect_context_explicit_ber(0)?;
    let mut e0_parser = DerParser::new(explicit_0);

    // EnvelopedData SEQUENCE
    let enveloped_data = e0_parser.expect_sequence_ber()?;
    let mut ed_parser = DerParser::new(enveloped_data);

    // version INTEGER — skip (always definite length)
    ed_parser.skip_tlv()?;

    // RecipientInfos SET
    let recipient_infos = ed_parser.expect_set_ber()?;
    let mut ri_parser = DerParser::new(recipient_infos);

    // KeyTransRecipientInfo SEQUENCE
    let ktri = ri_parser.expect_sequence_ber()?;
    let mut ktri_parser = DerParser::new(ktri);

    // version INTEGER — skip
    ktri_parser.skip_tlv()?;
    // rid (issuerAndSerialNumber or subjectKeyIdentifier) — skip
    ktri_parser.skip_tlv_ber()?;
    // keyEncryptionAlgorithm SEQUENCE — skip
    ktri_parser.skip_tlv_ber()?;
    // encryptedKey OCTET STRING (primitive, always definite length)
    let encrypted_key = ktri_parser.expect_octet_string()?;

    // EncryptedContentInfo SEQUENCE
    let eci = ed_parser.expect_sequence_ber()?;
    let mut eci_parser = DerParser::new(eci);

    // contentType OID — skip
    eci_parser.skip_tlv()?;

    // contentEncryptionAlgorithm SEQUENCE
    let cea = eci_parser.expect_sequence_ber()?;
    let mut cea_parser = DerParser::new(cea);
    // algorithm OID — skip
    cea_parser.skip_tlv()?;
    // parameters (IV) OCTET STRING (primitive, always definite length)
    let iv = cea_parser.expect_octet_string()?;

    // encryptedContent [0] IMPLICIT OCTET STRING
    // BER may encode this as constructed (tag 0xa0, with inner OCTET STRING
    // chunks) or primitive (tag 0x80, raw bytes). KMS uses constructed form.
    let encrypted_content = eci_parser.read_implicit_octet_string_ber(0)?;

    Ok((encrypted_key.to_vec(), encrypted_content, iv.to_vec()))
}

// ============================================================================
// AES-256-CBC Decryption (for CMS content)
// ============================================================================

/// AES-256-CBC decrypt with PKCS#7 padding removal.
///
/// Used to decrypt the CMS EncryptedContentInfo payload.
/// KMS uses AES-256-CBC (not GCM) for CMS content encryption.
fn aes_256_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use aws_lc_rs::cipher::{
        AES_256, DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey,
    };
    use aws_lc_rs::iv::FixedLength;

    if key.len() != 32 {
        anyhow::bail!("AES-256-CBC requires 32-byte key, got {}", key.len());
    }

    let unbound_key = UnboundCipherKey::new(&AES_256, key)
        .map_err(|e| anyhow::anyhow!("Failed to create AES-256 key: {e}"))?;

    // Convert IV slice to FixedLength<16> (validates length is exactly 16 bytes)
    let iv_array: [u8; 16] = iv
        .try_into()
        .map_err(|_| anyhow::anyhow!("AES-256-CBC requires 16-byte IV, got {}", iv.len()))?;
    let context = DecryptionContext::Iv128(FixedLength::from(iv_array));

    let decrypting_key = PaddedBlockDecryptingKey::cbc_pkcs7(unbound_key)
        .map_err(|e| anyhow::anyhow!("Failed to create CBC decrypting key: {e}"))?;

    let mut in_out = ciphertext.to_vec();
    let plaintext = decrypting_key
        .decrypt(&mut in_out, context)
        .map_err(|e| anyhow::anyhow!("AES-256-CBC decryption failed: {e}"))?;

    Ok(Zeroizing::new(plaintext.to_vec()))
}

// ============================================================================
// HPKE Config Info/AAD
// ============================================================================

/// Build the AAD for HPKE config operations.
///
/// Encodes the envelope version as a 4-byte big-endian integer to bind the
/// ciphertext to the specific envelope format version.
pub fn build_hpke_aad(version: u32) -> Vec<u8> {
    version.to_be_bytes().to_vec()
}

// ============================================================================
// Public API: Decrypt Encrypted Envelope
// ============================================================================

/// Decrypt an encrypted S3 config envelope using NitroTPM-attested KMS.
///
/// Decrypts the P-384 private key via KMS (with NitroTPM attestation), then uses
/// HPKE open to decrypt the config payload. Returns the decrypted config and the
/// P-384 key pair for reuse with `HpkeDocumentCrypto`.
///
/// # Arguments
/// * `kms_client` - AWS KMS client (pre-configured with credentials and region)
/// * `envelope` - The parsed encrypted envelope from S3
///
/// # Returns
/// The decrypted config bytes and the P-384 HPKE key pair.
///
/// # Errors
/// Returns an error if NitroTPM is unavailable, KMS call fails, or decryption fails.
pub async fn decrypt_envelope(
    kms_client: &KmsClient,
    envelope: &EncryptedEnvelope,
) -> Result<DecryptedEnvelope> {
    use super::document_crypto::{DocumentCrypto, EncryptedDocument, HpkeDocumentCrypto};

    // Verify NitroTPM is available
    if !is_nitro_tpm_available() {
        anyhow::bail!(
            "Encrypted S3 config requires NitroTPM but /dev/tpm0 is not available. \
             Use plain JSON config for non-NitroTPM environments."
        );
    }

    if !is_attest_binary_available() {
        anyhow::bail!(
            "Encrypted S3 config requires '{ATTEST_BINARY}' binary but it is not in PATH. \
             Install the 'aws-nitro-tpm-tools' package."
        );
    }

    // Decode the encrypted private key (KMS ciphertext blob)
    let encrypted_private_key = BASE64
        .decode(&envelope.encrypted_private_key)
        .context("Failed to base64-decode encrypted_private_key")?;

    // Decrypt private key via attested KMS call
    let private_key_der =
        attested_kms_decrypt(kms_client, &envelope.kms_key_id, &encrypted_private_key)
            .await
            .context("Failed to decrypt private key via attested KMS")?;

    // Extract raw P-384 keys from DER
    let raw_private_key = Zeroizing::new(
        super::document_crypto::p384_private_key_from_der(&private_key_der)
            .context("Failed to extract P-384 private key from DER")?,
    );

    let public_key_der = BASE64
        .decode(&envelope.public_key)
        .context("Failed to base64-decode public_key")?;
    let raw_public_key = super::document_crypto::p384_public_key_from_der(&public_key_der)
        .context("Failed to extract P-384 public key from DER")?;

    // Use HpkeDocumentCrypto to decrypt the config payload
    let crypto = HpkeDocumentCrypto::new(raw_public_key.clone(), raw_private_key.to_vec())
        .context("Failed to create HPKE crypto for config decryption")?;

    let doc = EncryptedDocument {
        encapped_key: Some(envelope.encapped_key.clone()),
        data: envelope.encrypted_data.clone(),
    };

    let aad = build_hpke_aad(envelope.version);
    let config_bytes = crypto
        .open(HPKE_CONFIG_INFO, &aad, &doc)
        .context("Failed to HPKE-open config payload")?;

    let config_bytes = Zeroizing::new(config_bytes);

    tracing::info!(
        "Successfully decrypted S3 config envelope ({} bytes plaintext, HPKE key pair recovered)",
        config_bytes.len()
    );

    Ok(DecryptedEnvelope {
        config_bytes,
        hpke_keys: HpkeKeyMaterial {
            public_key: raw_public_key,
            private_key: raw_private_key,
        },
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_is_encrypted_envelope_positive() {
        let json = br#"{"kms_key_id": "mrk-abc123", "encrypted_private_key": "...", "public_key": "...", "encapped_key": "...", "encrypted_data": "..."}"#;
        assert!(is_encrypted_envelope(json));
    }

    #[test]
    fn test_is_encrypted_envelope_negative() {
        let json = br#"{"rp_id": "vouch.example.com", "base_url": "https://vouch.example.com"}"#;
        assert!(!is_encrypted_envelope(json));
    }

    #[test]
    fn test_is_encrypted_envelope_empty() {
        assert!(!is_encrypted_envelope(b"{}"));
        assert!(!is_encrypted_envelope(b""));
    }

    #[test]
    fn test_contains_bytes() {
        assert!(contains_bytes(b"hello world", b"world"));
        assert!(contains_bytes(b"hello world", b"hello"));
        assert!(!contains_bytes(b"hello world", b"xyz"));
        assert!(!contains_bytes(b"", b"x"));
        assert!(!contains_bytes(b"x", b"xy"));
    }

    #[test]
    fn test_rsa_keypair_generation() {
        let keypair = generate_ephemeral_rsa_keypair().unwrap();
        // RSA-2048 public key SPKI DER should be around 270-300 bytes
        assert!(keypair.public_key_der.len() > 200);
        assert!(keypair.public_key_der.len() < 400);
        // Key size should be 256 bytes (2048 bits)
        assert_eq!(keypair.private_key.key_size_bytes(), 256);
    }

    #[test]
    fn test_nitro_tpm_not_available_on_dev() {
        // On dev machines, /dev/tpm0 should not exist
        // This test documents expected behavior
        if !std::path::Path::new("/dev/tpm0").exists() {
            assert!(!is_nitro_tpm_available());
        }
    }

    #[test]
    fn test_aes_256_cbc_round_trip() {
        use aws_lc_rs::cipher::{AES_256, PaddedBlockEncryptingKey, UnboundCipherKey};

        let key = [0x42u8; 32];
        let plaintext = b"test plaintext data for CBC mode";

        // Encrypt
        let enc_key = UnboundCipherKey::new(&AES_256, &key).unwrap();
        let enc = PaddedBlockEncryptingKey::cbc_pkcs7(enc_key).unwrap();
        let mut in_out = plaintext.to_vec();
        let context = enc.encrypt(&mut in_out).unwrap();

        // Extract IV from context
        let iv: &[u8] = (&context).try_into().unwrap();
        let iv_vec = iv.to_vec();

        // Decrypt
        let decrypted = aes_256_cbc_decrypt(&key, &iv_vec, &in_out).unwrap();
        assert_eq!(&**decrypted, plaintext);
    }

    /// Test RSA-OAEP encrypt/decrypt round-trip (simulates CMS key transport).
    #[test]
    fn test_rsa_oaep_round_trip() {
        use aws_lc_rs::rsa::{
            OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
        };

        let keypair = generate_ephemeral_rsa_keypair().unwrap();

        // Encrypt a 32-byte "data key" with the public key
        let data_key = [0xAB; 32];
        let pub_key =
            aws_lc_rs::rsa::PublicEncryptingKey::from_der(&keypair.public_key_der).unwrap();
        let oaep_pub = OaepPublicEncryptingKey::new(pub_key).unwrap();
        let mut ciphertext = vec![0u8; oaep_pub.ciphertext_size()];
        let ct = oaep_pub
            .encrypt(&OAEP_SHA256_MGF1SHA256, &data_key, &mut ciphertext, None)
            .unwrap();

        // Decrypt with private key
        let oaep_priv = OaepPrivateDecryptingKey::new(keypair.private_key).unwrap();
        let mut plaintext_buf = vec![0u8; 256];
        let pt = oaep_priv
            .decrypt(&OAEP_SHA256_MGF1SHA256, ct, &mut plaintext_buf, None)
            .unwrap();

        assert_eq!(pt, &data_key);
    }

    /// AES-256-CBC: wrong key must not produce correct plaintext.
    #[test]
    fn test_aes_256_cbc_wrong_key() {
        use aws_lc_rs::cipher::{AES_256, PaddedBlockEncryptingKey, UnboundCipherKey};

        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = b"test plaintext data for CBC mode";

        let enc_key = UnboundCipherKey::new(&AES_256, &key).unwrap();
        let enc = PaddedBlockEncryptingKey::cbc_pkcs7(enc_key).unwrap();
        let mut in_out = plaintext.to_vec();
        let context = enc.encrypt(&mut in_out).unwrap();
        let iv: &[u8] = (&context).try_into().unwrap();

        let result = aes_256_cbc_decrypt(&wrong_key, iv, &in_out);
        if let Ok(decrypted) = result {
            assert_ne!(
                &**decrypted, plaintext,
                "wrong key must not recover original plaintext"
            );
        }
    }

    /// AES-256-CBC: wrong IV should produce wrong plaintext or fail.
    #[test]
    fn test_aes_256_cbc_wrong_iv() {
        use aws_lc_rs::cipher::{AES_256, PaddedBlockEncryptingKey, UnboundCipherKey};

        let key = [0x42u8; 32];
        let plaintext = b"test plaintext data for CBC mode";

        let enc_key = UnboundCipherKey::new(&AES_256, &key).unwrap();
        let enc = PaddedBlockEncryptingKey::cbc_pkcs7(enc_key).unwrap();
        let mut in_out = plaintext.to_vec();
        let _context = enc.encrypt(&mut in_out).unwrap();

        let wrong_iv = [0xFF; 16];
        let result = aes_256_cbc_decrypt(&key, &wrong_iv, &in_out);
        if let Ok(decrypted) = result {
            assert_ne!(&**decrypted, plaintext);
        }
    }

    /// AES-256-CBC: invalid IV length should fail.
    #[test]
    fn test_aes_256_cbc_bad_iv_length() {
        let key = [0x42u8; 32];
        let result = aes_256_cbc_decrypt(&key, &[0u8; 12], &[0u8; 32]);
        assert!(result.is_err());
    }

    /// HPKE config seal/open round-trip using HpkeDocumentCrypto.
    #[test]
    fn test_hpke_config_round_trip() {
        use super::super::document_crypto::{DocumentCrypto, HpkeDocumentCrypto};
        use rustls::crypto::hpke::Hpke;

        let sample_config =
            br#"{"rp_id":"test.example.com","base_url":"https://test.example.com"}"#;

        let suite = &rustls::crypto::aws_lc_rs::hpke::DH_KEM_P384_HKDF_SHA384_AES_256;
        let (pub_key, priv_key) = suite.generate_key_pair().unwrap();

        let crypto =
            HpkeDocumentCrypto::new(pub_key.0.clone(), priv_key.secret_bytes().to_vec()).unwrap();

        let aad = build_hpke_aad(1);
        let sealed = crypto.seal(HPKE_CONFIG_INFO, &aad, sample_config).unwrap();
        let opened = crypto.open(HPKE_CONFIG_INFO, &aad, &sealed).unwrap();

        assert_eq!(&opened, sample_config);
    }

    /// HPKE config: wrong private key must fail.
    #[test]
    fn test_hpke_config_wrong_key() {
        use super::super::document_crypto::{DocumentCrypto, HpkeDocumentCrypto};
        use rustls::crypto::hpke::Hpke;

        let sample_config = br#"{"rp_id":"test.example.com"}"#;

        let suite = &rustls::crypto::aws_lc_rs::hpke::DH_KEM_P384_HKDF_SHA384_AES_256;
        let (pub_key, _priv_key) = suite.generate_key_pair().unwrap();
        let (other_pub, other_priv) = suite.generate_key_pair().unwrap();

        let seal_crypto =
            HpkeDocumentCrypto::new(pub_key.0.clone(), other_priv.secret_bytes().to_vec())
                .unwrap();
        let open_crypto =
            HpkeDocumentCrypto::new(other_pub.0.clone(), other_priv.secret_bytes().to_vec())
                .unwrap();

        let aad = build_hpke_aad(1);
        let sealed = seal_crypto.seal(HPKE_CONFIG_INFO, &aad, sample_config).unwrap();
        let result = open_crypto.open(HPKE_CONFIG_INFO, &aad, &sealed);
        assert!(result.is_err());
    }

    /// HPKE config: wrong AAD (version) must fail.
    #[test]
    fn test_hpke_config_wrong_aad() {
        use super::super::document_crypto::{DocumentCrypto, HpkeDocumentCrypto};
        use rustls::crypto::hpke::Hpke;

        let sample_config = br#"{"rp_id":"test.example.com"}"#;

        let suite = &rustls::crypto::aws_lc_rs::hpke::DH_KEM_P384_HKDF_SHA384_AES_256;
        let (pub_key, priv_key) = suite.generate_key_pair().unwrap();

        let crypto =
            HpkeDocumentCrypto::new(pub_key.0.clone(), priv_key.secret_bytes().to_vec()).unwrap();

        let aad_seal = build_hpke_aad(1);
        let sealed = crypto.seal(HPKE_CONFIG_INFO, &aad_seal, sample_config).unwrap();

        let aad_open = build_hpke_aad(2);
        let result = crypto.open(HPKE_CONFIG_INFO, &aad_open, &sealed);
        assert!(result.is_err());
    }

    /// Round-trip test: seal -> serialize envelope -> deserialize -> open.
    #[test]
    fn test_envelope_hpke_serialize_deserialize() {
        use super::super::document_crypto::{DocumentCrypto, HpkeDocumentCrypto};
        use rustls::crypto::hpke::Hpke;

        let sample_config =
            br#"{"rp_id":"test.example.com","base_url":"https://test.example.com"}"#;

        let suite = &rustls::crypto::aws_lc_rs::hpke::DH_KEM_P384_HKDF_SHA384_AES_256;
        let (pub_key, priv_key) = suite.generate_key_pair().unwrap();

        let crypto =
            HpkeDocumentCrypto::new(pub_key.0.clone(), priv_key.secret_bytes().to_vec()).unwrap();

        let version = 1u32;
        let aad = build_hpke_aad(version);
        let sealed = crypto.seal(HPKE_CONFIG_INFO, &aad, sample_config).unwrap();

        // Build envelope
        let envelope = EncryptedEnvelope {
            kms_key_id: "mrk-test1234".to_string(),
            encrypted_private_key: BASE64.encode(priv_key.secret_bytes()),
            public_key: BASE64.encode(&pub_key.0),
            encapped_key: sealed.encapped_key.unwrap(),
            encrypted_data: sealed.data,
            version,
            tls: Some(crate::infra::s3_config::S3TlsConfig {
                cert: Some("test-cert".to_string()),
                key: Some("test-key".to_string()),
            }),
            acme: Some(crate::infra::s3_config::S3AcmeConfig {
                account_key: "acme-secret".to_string(),
                email: "acme@example.com".to_string(),
            }),
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&envelope).unwrap();

        // Verify JSON contains expected fields
        assert!(json.contains("kms_key_id"));
        assert!(json.contains("encrypted_private_key"));
        assert!(json.contains("public_key"));
        assert!(json.contains("encapped_key"));
        assert!(json.contains("encrypted_data"));
        assert!(json.contains("test-cert"));
        assert!(json.contains("_acme"));
        assert!(json.contains("acme@example.com"));

        // Deserialize back and decrypt using HpkeDocumentCrypto
        let parsed: EncryptedEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kms_key_id, "mrk-test1234");

        let doc = super::super::document_crypto::EncryptedDocument {
            encapped_key: Some(parsed.encapped_key.clone()),
            data: parsed.encrypted_data.clone(),
        };
        let aad = build_hpke_aad(parsed.version);
        let opened = crypto.open(HPKE_CONFIG_INFO, &aad, &doc).unwrap();
        assert_eq!(&opened, sample_config);
    }

    /// Verify `skip_serializing_if` omits `_acme` when `None`.
    #[test]
    fn test_envelope_serialization_omits_acme_when_none() {
        let envelope = EncryptedEnvelope {
            kms_key_id: "mrk-test".to_string(),
            encrypted_private_key: "a2V5".to_string(),
            public_key: "cHVi".to_string(),
            encapped_key: "ZW5j".to_string(),
            encrypted_data: "ZGF0YQ==".to_string(),
            version: 1,
            tls: None,
            acme: None,
        };

        let json = serde_json::to_string(&envelope).unwrap();
        assert!(
            !json.contains("_acme"),
            "JSON should not contain _acme when None"
        );
    }

    /// Verify `S3AcmeConfig` Debug impl redacts `account_key`.
    #[test]
    fn test_s3_acme_config_debug_redacts_account_key() {
        let acme = crate::infra::s3_config::S3AcmeConfig {
            account_key: "super-secret-key-material".to_string(),
            email: "admin@example.com".to_string(),
        };

        let debug_output = format!("{acme:?}");
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should contain [REDACTED]"
        );
        assert!(
            !debug_output.contains("super-secret-key-material"),
            "Debug output should not contain the actual account key"
        );
        assert!(
            debug_output.contains("admin@example.com"),
            "Debug output should contain the email"
        );
    }

    /// End-to-end CMS EnvelopedData parsing + decryption with a hand-crafted structure.
    #[test]
    fn test_cms_enveloped_data_end_to_end() {
        use aws_lc_rs::cipher::{AES_256, PaddedBlockEncryptingKey, UnboundCipherKey};
        use aws_lc_rs::rsa::{OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey};

        let keypair = generate_ephemeral_rsa_keypair().unwrap();

        let content_key = [0x42u8; 32];
        let payload = b"decrypted config payload from KMS";

        let pub_key =
            aws_lc_rs::rsa::PublicEncryptingKey::from_der(&keypair.public_key_der).unwrap();
        let oaep_pub = OaepPublicEncryptingKey::new(pub_key).unwrap();
        let mut encrypted_key_buf = vec![0u8; oaep_pub.ciphertext_size()];
        let encrypted_key = oaep_pub
            .encrypt(
                &OAEP_SHA256_MGF1SHA256,
                &content_key,
                &mut encrypted_key_buf,
                None,
            )
            .unwrap();

        let enc_unbound = UnboundCipherKey::new(&AES_256, &content_key).unwrap();
        let enc = PaddedBlockEncryptingKey::cbc_pkcs7(enc_unbound).unwrap();
        let mut cbc_out = payload.to_vec();
        let cbc_context = enc.encrypt(&mut cbc_out).unwrap();
        let iv: &[u8] = (&cbc_context).try_into().unwrap();

        fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            let len = value.len();
            if len < 0x80 {
                out.push(len as u8);
            } else if len <= 0xFF {
                out.push(0x81);
                out.push(len as u8);
            } else {
                out.push(0x82);
                out.push((len >> 8) as u8);
                out.push((len & 0xFF) as u8);
            }
            out.extend_from_slice(value);
            out
        }

        let oid_enveloped_data = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03,
        ];
        let oid_data = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
        ];
        let oid_rsa_oaep = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07,
        ];
        let oid_aes256cbc = [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a,
        ];

        let version = [0x02, 0x01, 0x00];
        let rid = der_tlv(0x04, &[0x00]);
        let key_enc_alg = der_tlv(0x30, &oid_rsa_oaep);
        let enc_key_octet = der_tlv(0x04, encrypted_key);

        let mut ktri_inner = Vec::new();
        ktri_inner.extend_from_slice(&version);
        ktri_inner.extend_from_slice(&rid);
        ktri_inner.extend_from_slice(&key_enc_alg);
        ktri_inner.extend_from_slice(&enc_key_octet);
        let ktri = der_tlv(0x30, &ktri_inner);
        let recipient_infos = der_tlv(0x31, &ktri);

        let iv_octet = der_tlv(0x04, iv);
        let mut cea_inner = Vec::new();
        cea_inner.extend_from_slice(&oid_aes256cbc);
        cea_inner.extend_from_slice(&iv_octet);
        let content_enc_alg = der_tlv(0x30, &cea_inner);
        let encrypted_content_implicit = der_tlv(0x80, &cbc_out);

        let mut eci_inner = Vec::new();
        eci_inner.extend_from_slice(&oid_data);
        eci_inner.extend_from_slice(&content_enc_alg);
        eci_inner.extend_from_slice(&encrypted_content_implicit);
        let encrypted_content_info = der_tlv(0x30, &eci_inner);

        let mut ed_inner = Vec::new();
        ed_inner.extend_from_slice(&version);
        ed_inner.extend_from_slice(&recipient_infos);
        ed_inner.extend_from_slice(&encrypted_content_info);
        let enveloped_data = der_tlv(0x30, &ed_inner);

        let explicit_0 = der_tlv(0xa0, &enveloped_data);

        let mut ci_inner = Vec::new();
        ci_inner.extend_from_slice(&oid_enveloped_data);
        ci_inner.extend_from_slice(&explicit_0);
        let content_info = der_tlv(0x30, &ci_inner);

        let decrypted = decrypt_cms_envelope(&content_info, keypair.private_key).unwrap();
        assert_eq!(&**decrypted, payload);
    }
}
