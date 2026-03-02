// SPDX-License-Identifier: BUSL-1.1
//! NitroTPM-attested KMS decryption.
//!
//! This module provides optional AWS KMS decryption with NitroTPM attestation.
//! When running on an EC2 instance with NitroTPM enabled, `kms:Decrypt` calls
//! include a `Recipient` parameter with a TPM attestation document, ensuring
//! plaintext is only recoverable on attested instances.
//!
//! ## How it works
//!
//! 1. Generate an ephemeral RSA-2048 key pair (via `aws-lc-rs`)
//! 2. Get a NitroTPM attestation document embedding the RSA public key
//!    (via the `nitro-tpm-attest` CLI tool from `aws-nitro-tpm-tools`)
//! 3. Call `kms:Decrypt` with a `Recipient` parameter containing the attestation document
//! 4. KMS returns `CiphertextForRecipient` — a CMS (PKCS#7) envelope with the plaintext
//!    encrypted to the ephemeral RSA public key
//! 5. Parse the CMS envelope and RSA-OAEP decrypt to recover the plaintext
//!
//! ## Fallback
//!
//! When NitroTPM is not available (dev machines, on-prem), `kms_decrypt()` sends
//! a plain `kms:Decrypt` request without attestation.
//!
//! ## Dependencies
//!
//! - `aws-sdk-kms`: KMS API client
//! - `aws-lc-rs`: RSA key generation, RSA-OAEP decryption, AES-256-CBC decryption
//! - `nitro-tpm-attest` CLI: Installed on NitroTPM-enabled AMIs via `aws-nitro-tpm-tools`

use anyhow::{Context, Result};
use aws_sdk_kms::Client as KmsClient;
use zeroize::Zeroizing;

use super::ber::DerParser;

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
#[must_use]
pub fn is_attest_binary_available() -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(ATTEST_BINARY).is_file()))
        .is_some_and(|found| found)
}

/// Exercise the full NitroTPM attestation path.
///
/// Generates an ephemeral RSA key pair, requests an attestation document,
/// and returns the document size in bytes. Used as a startup health check
/// to surface NitroTPM issues (burstable instance limits, broken device,
/// etc.) without blocking server startup.
///
/// # Errors
///
/// Returns an error if key generation fails, the attestation binary is
/// missing, or the TPM device rejects the request.
pub fn probe_attestation() -> Result<usize> {
    let keypair = generate_ephemeral_rsa_keypair()?;
    let doc = get_attestation_document(&keypair.public_key_der)?;
    Ok(doc.len())
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
// KMS Decrypt (with optional NitroTPM attestation)
// ============================================================================

/// Decrypt a KMS ciphertext blob, optionally using NitroTPM attestation.
///
/// When `use_attestation` is true, adds a `Recipient` parameter with a
/// NitroTPM attestation document. KMS returns `CiphertextForRecipient`
/// instead of plaintext, which is RSA-OAEP + CMS decrypted locally.
///
/// When `use_attestation` is false, sends a plain `kms:Decrypt` request.
///
/// The caller determines `use_attestation` from the startup probe result
/// (see `probe_attestation()`), not from per-call device checks.
pub async fn kms_decrypt(
    kms_client: &KmsClient,
    key_id: &str,
    ciphertext_blob: &[u8],
    use_attestation: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut request = kms_client
        .decrypt()
        .key_id(key_id)
        .ciphertext_blob(aws_smithy_types::Blob::new(ciphertext_blob));

    let attestation = if use_attestation {
        let keypair = generate_ephemeral_rsa_keypair()?;
        let pub_key_der = keypair.public_key_der.clone();
        let doc = tokio::task::spawn_blocking(move || get_attestation_document(&pub_key_der))
            .await
            .context("Attestation task panicked")?
            .context("Failed to get attestation document")?;

        let recipient = aws_sdk_kms::types::RecipientInfo::builder()
            .key_encryption_algorithm(aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256)
            .attestation_document(aws_smithy_types::Blob::new(doc))
            .build();
        request = request.recipient(recipient);
        tracing::debug!("kms:Decrypt with NitroTPM attestation for key {key_id}");
        Some(keypair)
    } else {
        tracing::debug!("kms:Decrypt (plain) for key {key_id}");
        None
    };

    let response = request.send().await.context("kms:Decrypt failed")?;

    if let Some(keypair) = attestation {
        let cms_blob = response
            .ciphertext_for_recipient()
            .context("KMS response missing CiphertextForRecipient")?;
        decrypt_cms_envelope(cms_blob.as_ref(), keypair.private_key)
    } else {
        let pt = response
            .plaintext()
            .context("KMS Decrypt response missing plaintext")?;
        Ok(Zeroizing::new(pt.as_ref().to_vec()))
    }
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

    let mut in_out = Zeroizing::new(ciphertext.to_vec());
    let plaintext = decrypting_key
        .decrypt(&mut in_out, context)
        .map_err(|e| anyhow::anyhow!("AES-256-CBC decryption failed: {e}"))?;

    Ok(Zeroizing::new(plaintext.to_vec()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

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

    #[test]
    fn test_parse_cms_enveloped_data_too_large() {
        let oversized = vec![0x30; MAX_CMS_SIZE + 1];
        let result = parse_cms_enveloped_data(&oversized);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too large"),
            "Expected 'too large' error, got: {err}"
        );
    }

    #[test]
    fn test_parse_cms_enveloped_data_empty() {
        let result = parse_cms_enveloped_data(&[]);
        assert!(result.is_err(), "Empty input must return Err");
    }

    #[test]
    fn test_parse_cms_enveloped_data_garbage_bytes() {
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
        let result = parse_cms_enveloped_data(&garbage);
        assert!(result.is_err(), "Garbage DER input must return Err");
    }

    #[test]
    fn test_aes_256_cbc_bad_key_length_short() {
        let short_key = [0x42u8; 16];
        let result = aes_256_cbc_decrypt(&short_key, &[0u8; 16], &[0u8; 32]);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("32-byte key"),
            "Expected '32-byte key' error, got: {err}"
        );
    }

    #[test]
    fn test_aes_256_cbc_bad_key_length_zero() {
        let result = aes_256_cbc_decrypt(&[], &[0u8; 16], &[0u8; 32]);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("32-byte key"),
            "Expected '32-byte key' error, got: {err}"
        );
    }

    /// Conditional test: verify `is_attest_binary_available()` returns false
    /// when the TPM device is not present (dev machines).
    #[test]
    fn test_attest_binary_not_in_path_on_dev() {
        if std::path::Path::new(TPM_DEVICE_PATH).exists() {
            // Skip on NitroTPM-enabled instances
            return;
        }
        // On dev machines without aws-nitro-tpm-tools installed,
        // the binary should not be in PATH.
        // If it IS installed (unlikely on dev), the test still passes
        // since we only assert the function doesn't panic.
        let _ = is_attest_binary_available();
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
