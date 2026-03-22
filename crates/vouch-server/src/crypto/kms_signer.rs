// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS KMS-backed signers for SSH CA (Ed25519) and OIDC JWT (P-256 ECDSA, RSA-3072).
//!
//! These signers call `kms:Sign` for every signing operation, keeping private
//! keys exclusively inside KMS. Public keys are fetched once at construction
//! via `kms:GetPublicKey` and cached locally.
//!
//! ## Key types
//!
//! - **Ed25519** (`ECC_NIST_EDWARDS25519`): Signs with `ED25519_SHA_512`,
//!   `MessageType::Raw`. Returns 64-byte raw Ed25519 signatures.
//! - **P-256 ECDSA** (`ECC_NIST_P256`): Signs with `ECDSA_SHA_256`,
//!   `MessageType::Raw`. Returns DER-encoded ECDSA signatures.
//! - **RSA-3072** (`RSA_3072`): Signs with `RSASSA_PKCS1_V1_5_SHA_256`,
//!   `MessageType::Digest`. Caller must pre-hash with SHA-256. Returns raw
//!   PKCS#1 v1.5 signature bytes (384 bytes for RSA-3072).

use anyhow::{Context, Result, bail};
use aws_sdk_kms::types::{KeySpec, MessageType, SigningAlgorithmSpec};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use spki::SubjectPublicKeyInfoRef;

/// OID for Ed25519: 1.3.101.112 (RFC 8410 Section 3).
const OID_ED25519: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.101.112");

/// OID for EC public key: 1.2.840.10045.2.1 (RFC 5480 Section 2.1.1).
const OID_EC_PUBLIC_KEY: spki::ObjectIdentifier =
    spki::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// OID for P-256 (prime256v1): 1.2.840.10045.3.1.7 (RFC 5480 Section 2.1.1.1).
const OID_PRIME256V1: spki::ObjectIdentifier =
    spki::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// OID for rsaEncryption: 1.2.840.113549.1.1.1 (RFC 3279 Section 2.3.1).
const OID_RSA_ENCRYPTION: spki::ObjectIdentifier =
    spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

// ---------------------------------------------------------------------------
// SPKI parsing helpers
// ---------------------------------------------------------------------------

/// Parse a SubjectPublicKeyInfo DER blob for an Ed25519 key.
///
/// Returns the 32-byte raw Ed25519 public key. Validates that the
/// algorithm OID is 1.3.101.112 (RFC 8410).
pub(crate) fn parse_spki_ed25519(der: &[u8]) -> Result<[u8; 32]> {
    let spki = SubjectPublicKeyInfoRef::try_from(der)
        .map_err(|e| anyhow::anyhow!("Failed to parse Ed25519 SPKI: {e}"))?;

    if spki.algorithm.oid != OID_ED25519 {
        bail!(
            "Expected Ed25519 OID ({}), got {}",
            OID_ED25519,
            spki.algorithm.oid
        );
    }

    let key_bytes = spki.subject_public_key.raw_bytes();
    if key_bytes.len() != 32 {
        bail!(
            "Ed25519 public key must be 32 bytes, got {}",
            key_bytes.len()
        );
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(key_bytes);
    Ok(result)
}

/// Parse a SubjectPublicKeyInfo DER blob for a P-256 key.
///
/// Returns the 65-byte uncompressed SEC1 point (`0x04 || x || y`).
/// Validates the algorithm OIDs: ecPublicKey (1.2.840.10045.2.1) with
/// parameter prime256v1 (1.2.840.10045.3.1.7) per RFC 5480.
pub(crate) fn parse_spki_p256(der: &[u8]) -> Result<Vec<u8>> {
    let spki = SubjectPublicKeyInfoRef::try_from(der)
        .map_err(|e| anyhow::anyhow!("Failed to parse P-256 SPKI: {e}"))?;

    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        bail!(
            "Expected ecPublicKey OID ({}), got {}",
            OID_EC_PUBLIC_KEY,
            spki.algorithm.oid
        );
    }

    // Validate the curve parameter is P-256
    let params = spki
        .algorithm
        .parameters_oid()
        .map_err(|e| anyhow::anyhow!("Missing or invalid EC parameters: {e}"))?;
    if params != OID_PRIME256V1 {
        bail!(
            "Expected P-256 curve OID ({}), got {}",
            OID_PRIME256V1,
            params
        );
    }

    let key_bytes = spki.subject_public_key.raw_bytes();
    if key_bytes.len() != 65 {
        bail!(
            "P-256 uncompressed point must be 65 bytes, got {}",
            key_bytes.len()
        );
    }
    if key_bytes.first() != Some(&0x04) {
        bail!("P-256 key must be uncompressed (0x04 prefix)");
    }

    Ok(key_bytes.to_vec())
}

/// Convert a DER-encoded ECDSA signature to JWT R||S format.
///
/// DER format: `SEQUENCE { INTEGER r, INTEGER s }`
/// JWT format: `r (32 bytes, zero-padded) || s (32 bytes, zero-padded)`
///
/// Uses `p256::ecdsa::Signature` for robust DER parsing and conversion.
pub(crate) fn der_ecdsa_to_jwt(der: &[u8]) -> Result<[u8; 64]> {
    let sig = p256::ecdsa::Signature::from_der(der)
        .map_err(|e| anyhow::anyhow!("Failed to parse DER ECDSA signature: {e}"))?;
    Ok(sig.to_bytes().into())
}

// ---------------------------------------------------------------------------
// KMS Ed25519 signer (for SSH CA)
// ---------------------------------------------------------------------------

/// KMS-backed Ed25519 signer for SSH certificate signing.
///
/// Caches the 32-byte public key fetched from `kms:GetPublicKey`.
/// Each `sign` call invokes `kms:Sign` with `Ed25519Sha512`.
pub struct KmsSignerEd25519 {
    kms_client: aws_sdk_kms::Client,
    key_id: String,
    public_key_bytes: [u8; 32],
}

impl KmsSignerEd25519 {
    /// Create a new Ed25519 signer by fetching the public key from KMS.
    ///
    /// Validates that the key spec is `ECC_NIST_EDWARDS25519`.
    pub(crate) async fn new(kms_client: aws_sdk_kms::Client, key_id: String) -> Result<Self> {
        let resp = kms_client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .context("kms:GetPublicKey failed for Ed25519 key")?;

        let spec = resp.key_spec();
        if spec != Some(&KeySpec::EccNistEdwards25519) {
            bail!("Expected ECC_NIST_EDWARDS25519 key spec, got {:?}", spec);
        }

        let der = resp
            .public_key()
            .context("kms:GetPublicKey returned no public key")?
            .as_ref();

        let public_key_bytes =
            parse_spki_ed25519(der).context("Failed to parse Ed25519 SPKI from KMS")?;

        tracing::debug!(
            "KMS Ed25519 signer initialized (pubkey={})",
            hex::encode(public_key_bytes.get(..8).unwrap_or(&public_key_bytes)),
        );

        Ok(Self {
            kms_client,
            key_id,
            public_key_bytes,
        })
    }

    /// Sign a message using KMS `Ed25519Sha512` (`MessageType::Raw`).
    ///
    /// `MessageType::Raw` means KMS receives the full message and performs
    /// the internal SHA-512 hash per RFC 8032. This is correct because
    /// `ssh_key::certificate::Builder` passes the raw to-be-signed data.
    ///
    /// Returns the 64-byte raw Ed25519 signature.
    pub(crate) async fn sign_raw(&self, message: &[u8]) -> Result<[u8; 64]> {
        tracing::debug!(key_id = %self.key_id, msg_len = message.len(), "kms:Sign Ed25519");

        let resp = self
            .kms_client
            .sign()
            .key_id(&self.key_id)
            .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512)
            .message_type(MessageType::Raw)
            .message(aws_smithy_types::Blob::new(message))
            .send()
            .await
            .context("kms:Sign failed for Ed25519")?;

        let sig = resp
            .signature()
            .context("kms:Sign returned no signature")?
            .as_ref();

        if sig.len() != 64 {
            bail!("Ed25519 signature must be 64 bytes, got {}", sig.len());
        }

        let mut result = [0u8; 64];
        result.copy_from_slice(sig);
        tracing::debug!("kms:Sign Ed25519 succeeded");
        Ok(result)
    }

    /// Convert to an `ssh_key::PublicKey`.
    pub(crate) fn ssh_public_key(&self) -> Result<ssh_key::PublicKey> {
        let key_data = ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
            self.public_key_bytes,
        ));
        Ok(ssh_key::PublicKey::new(key_data, ""))
    }
}

/// Implement `Signer<ssh_key::Signature>` so `KmsSignerEd25519` can be
/// passed to `ssh_key::certificate::Builder::sign()`.
///
/// Spawns a scoped OS thread that calls `Handle::block_on` to bridge
/// from sync to async. This avoids both:
/// - `block_in_place` which panics on the `current_thread` runtime
///   used by `#[tokio::test]`
/// - Calling `block_on` on a tokio worker thread, which would deadlock
///
/// # Caller contract
///
/// `try_sign` blocks the calling thread until the KMS round-trip
/// completes. Callers MUST invoke this from a `spawn_blocking` context
/// (or a non-tokio thread) to avoid blocking a tokio worker thread and
/// starving the I/O reactor.
impl signature::Signer<ssh_key::Signature> for KmsSignerEd25519 {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<ssh_key::Signature, signature::Error> {
        let handle = tokio::runtime::Handle::current();

        // Spawn a scoped OS thread to call block_on. This is
        // necessary because we're called from a sync trait impl
        // on a tokio worker thread — calling block_on directly
        // would deadlock the runtime. std::thread::scope allows
        // borrowing `self` and `msg` without 'static.
        let result: std::result::Result<[u8; 64], String> = std::thread::scope(|s| {
            s.spawn(|| {
                handle
                    .block_on(self.sign_raw(msg))
                    .map_err(|e| format!("{e:#}"))
            })
            .join()
            .unwrap_or_else(|_| Err("KMS sign thread panicked".to_string()))
        });

        match result {
            Ok(sig_bytes) => {
                let sig = ssh_key::Signature::new(ssh_key::Algorithm::Ed25519, sig_bytes.to_vec())
                    .map_err(|e| {
                        tracing::error!("Failed to construct SSH signature: {e}");
                        signature::Error::new()
                    })?;
                Ok(sig)
            }
            Err(e) => {
                tracing::error!("KMS Ed25519 signing failed: {e}");
                Err(signature::Error::new())
            }
        }
    }
}

/// Parse a SubjectPublicKeyInfo DER blob for an RSA key.
///
/// Returns `(modulus_bytes, exponent_bytes)` with leading zero padding stripped.
/// Validates that the algorithm OID is `rsaEncryption` (1.2.840.113549.1.1.1, RFC 3279).
/// Parses the inner `RSAPublicKey` (`SEQUENCE { INTEGER n, INTEGER e }`) from the BIT STRING.
pub(crate) fn parse_spki_rsa(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let spki = SubjectPublicKeyInfoRef::try_from(der)
        .map_err(|e| anyhow::anyhow!("Failed to parse RSA SPKI: {e}"))?;

    if spki.algorithm.oid != OID_RSA_ENCRYPTION {
        bail!(
            "Expected rsaEncryption OID ({}), got {}",
            OID_RSA_ENCRYPTION,
            spki.algorithm.oid
        );
    }

    // The BIT STRING payload is the inner RSAPublicKey DER:
    //   SEQUENCE { INTEGER n, INTEGER e }
    let inner = spki.subject_public_key.raw_bytes();
    parse_rsa_public_key_der(inner)
}

/// Parse a DER-encoded `RSAPublicKey` (`SEQUENCE { INTEGER n, INTEGER e }`).
///
/// Strips DER INTEGER sign-padding (leading `0x00`) from both `n` and `e`.
/// Returns `(modulus_bytes, exponent_bytes)`.
fn parse_rsa_public_key_der(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // Manual minimal DER parser for SEQUENCE { INTEGER n, INTEGER e }.
    // We do not import `der` crate for this — the structure is simple enough
    // to parse directly, matching the approach used for P-256 coordinate extraction.

    let (seq_content, _rest) = read_der_tlv(der, 0x30)
        .context("RSAPublicKey outer SEQUENCE missing or malformed")?;

    let (n_bytes, after_n) = read_der_integer(seq_content)
        .context("RSAPublicKey modulus (n) missing or malformed")?;

    let (e_bytes, _after_e) = read_der_integer(after_n)
        .context("RSAPublicKey exponent (e) missing or malformed")?;

    // Strip DER sign-padding: INTEGERs may have a leading 0x00 when the high
    // bit of the magnitude is set (to indicate a positive value in two's complement).
    let n = strip_leading_zeros(n_bytes).to_vec();
    let e = strip_leading_zeros(e_bytes).to_vec();

    if n.is_empty() {
        bail!("RSA modulus is empty after stripping zero padding");
    }
    if e.is_empty() {
        bail!("RSA exponent is empty after stripping zero padding");
    }

    Ok((n, e))
}

/// Read a DER TLV (Tag, Length, Value) element with the expected tag.
///
/// Returns `(value_bytes, remaining_input)`.
fn read_der_tlv(input: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8])> {
    let tag = input.first().copied().ok_or_else(|| anyhow::anyhow!("DER input is empty"))?;
    if tag != expected_tag {
        bail!("Expected DER tag 0x{expected_tag:02x}, got 0x{tag:02x}");
    }
    let input = input.get(1..).ok_or_else(|| anyhow::anyhow!("DER input truncated after tag"))?;
    let (length, after_length) = read_der_length(input)?;
    let value = after_length
        .get(..length)
        .ok_or_else(|| anyhow::anyhow!("DER value truncated: need {length} bytes"))?;
    let rest = after_length
        .get(length..)
        .ok_or_else(|| anyhow::anyhow!("DER input truncated after value"))?;
    Ok((value, rest))
}

/// Read a DER length field.
///
/// Returns `(length, remaining_input)`. Supports lengths up to `usize::MAX`.
fn read_der_length(input: &[u8]) -> Result<(usize, &[u8])> {
    let first = input.first().copied().ok_or_else(|| anyhow::anyhow!("DER length missing"))?;
    if first < 0x80 {
        // Short form: single-byte length
        return Ok((usize::from(first), input.get(1..).unwrap_or_default()));
    }
    // Long form: `first & 0x7f` bytes encode the length
    let num_bytes = usize::from(first & 0x7f);
    if num_bytes == 0 || num_bytes > 8 {
        bail!("Unsupported DER length encoding: {num_bytes} length bytes");
    }
    let len_bytes = input
        .get(1..=num_bytes)
        .ok_or_else(|| anyhow::anyhow!("DER length bytes truncated"))?;
    let mut length: usize = 0;
    for &b in len_bytes {
        length = length
            .checked_shl(8)
            .ok_or_else(|| anyhow::anyhow!("DER length overflow"))?
            | usize::from(b);
    }
    let rest = input.get(1 + num_bytes..).unwrap_or_default();
    Ok((length, rest))
}

/// Read a DER INTEGER and return `(integer_bytes, remaining_input)`.
fn read_der_integer(input: &[u8]) -> Result<(&[u8], &[u8])> {
    // INTEGER tag is 0x02
    read_der_tlv(input, 0x02)
}

/// Strip leading zero bytes from a DER INTEGER value.
///
/// DER INTEGERs for positive values with a high bit set include a leading `0x00`
/// sign byte. Strip those to get the magnitude bytes for use as JWK `n` and `e`.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let non_zero_start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    // Preserve at least one byte (the value 0 itself)
    bytes.get(non_zero_start..).unwrap_or(bytes)
}

/// Allow `Builder::sign()` to extract the public key from our signer.
impl From<&KmsSignerEd25519> for ssh_key::public::KeyData {
    fn from(signer: &KmsSignerEd25519) -> Self {
        ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
            signer.public_key_bytes,
        ))
    }
}

// ---------------------------------------------------------------------------
// KMS P-256 ECDSA signer (for OIDC JWT)
// ---------------------------------------------------------------------------

/// KMS-backed P-256 ECDSA signer for OIDC JWT signing.
///
/// Caches the 65-byte uncompressed SEC1 point from `kms:GetPublicKey`.
/// Each `sign` call invokes `kms:Sign` with `EcdsaSha256`.
pub struct KmsSignerP256 {
    kms_client: aws_sdk_kms::Client,
    key_id: String,
    /// 65-byte uncompressed point: `0x04 || x(32) || y(32)`.
    public_key_bytes: Vec<u8>,
}

impl KmsSignerP256 {
    /// Create a new P-256 signer by fetching the public key from KMS.
    ///
    /// Validates that the key spec is `ECC_NIST_P256`.
    pub(crate) async fn new(kms_client: aws_sdk_kms::Client, key_id: String) -> Result<Self> {
        let resp = kms_client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .context("kms:GetPublicKey failed for P-256 key")?;

        let spec = resp.key_spec();
        if spec != Some(&KeySpec::EccNistP256) {
            bail!("Expected ECC_NIST_P256 key spec, got {:?}", spec);
        }

        let der = resp
            .public_key()
            .context("kms:GetPublicKey returned no public key")?
            .as_ref();

        let public_key_bytes =
            parse_spki_p256(der).context("Failed to parse P-256 SPKI from KMS")?;

        tracing::debug!(
            "KMS P-256 signer initialized (pubkey_prefix={})",
            hex::encode(public_key_bytes.get(..8).unwrap_or(&public_key_bytes)),
        );

        Ok(Self {
            kms_client,
            key_id,
            public_key_bytes,
        })
    }

    /// Sign a message using KMS `EcdsaSha256` (`MessageType::Raw`).
    ///
    /// `MessageType::Raw` means KMS receives the full message and
    /// computes SHA-256 internally before ECDSA signing. This is correct
    /// for ES256 JWTs where the signing input is the raw
    /// `base64url(header).base64url(payload)` bytes.
    ///
    /// Returns the DER-encoded ECDSA signature.
    pub(crate) async fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        tracing::debug!(key_id = %self.key_id, msg_len = message.len(), "kms:Sign P-256 ECDSA");

        let resp = self
            .kms_client
            .sign()
            .key_id(&self.key_id)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .message_type(MessageType::Raw)
            .message(aws_smithy_types::Blob::new(message))
            .send()
            .await
            .context("kms:Sign failed for P-256 ECDSA")?;

        let sig = resp
            .signature()
            .context("kms:Sign returned no signature")?
            .as_ref();

        tracing::debug!("kms:Sign P-256 ECDSA succeeded");
        Ok(sig.to_vec())
    }

    /// Get the base64url-encoded x coordinate.
    pub(crate) fn x_b64(&self) -> String {
        use base64::Engine;
        debug_assert_eq!(
            self.public_key_bytes.len(),
            65,
            "P-256 key invariant violated: expected 65 bytes"
        );
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(self.public_key_bytes.get(1..33).unwrap_or_default())
    }

    /// Get the base64url-encoded y coordinate.
    pub(crate) fn y_b64(&self) -> String {
        use base64::Engine;
        debug_assert_eq!(
            self.public_key_bytes.len(),
            65,
            "P-256 key invariant violated: expected 65 bytes"
        );
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(self.public_key_bytes.get(33..65).unwrap_or_default())
    }

    /// Get the raw public key bytes (65-byte uncompressed point).
    pub(crate) fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }
}

// ---------------------------------------------------------------------------
// KMS RSA-3072 signer (for OIDC ID token JWT)
// ---------------------------------------------------------------------------

/// KMS-backed RSA-3072 signer for OIDC ID token signing (RS256).
///
/// Caches the modulus (`n`) and exponent (`e`) extracted from the SPKI returned
/// by `kms:GetPublicKey`. Each `sign_digest` call invokes `kms:Sign` with
/// `RSASSA_PKCS1_V1_5_SHA_256` and `MessageType::Digest` (pre-computed SHA-256 hash).
///
/// ## KMS MessageType semantics
///
/// Unlike ECDSA (`EcdsaSha256` + `MessageType::Raw`, where KMS hashes internally),
/// RSA PKCS#1 v1.5 signing with `RsassaPkcs1V15Sha256` requires the caller to
/// pre-compute the SHA-256 digest and pass `MessageType::Digest`. This is explicit
/// in the method name: `sign_digest` not `sign_raw`.
pub struct KmsSignerRsa3072 {
    kms_client: aws_sdk_kms::Client,
    key_id: String,
    /// Base64url-encoded RSA modulus (cached at construction, used for JWK).
    n_b64: String,
    /// Base64url-encoded RSA exponent (cached at construction, used for JWK).
    e_b64: String,
}

impl KmsSignerRsa3072 {
    /// Create a new RSA-3072 signer by fetching the public key from KMS.
    ///
    /// Validates that the key spec is `RSA_3072`. Parses the SPKI to extract
    /// and cache the modulus and exponent in base64url encoding.
    pub(crate) async fn new(kms_client: aws_sdk_kms::Client, key_id: String) -> Result<Self> {
        let resp = kms_client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .context("kms:GetPublicKey failed for RSA-3072 key")?;

        let spec = resp.key_spec();
        if spec != Some(&KeySpec::Rsa3072) {
            bail!("Expected RSA_3072 key spec, got {:?}", spec);
        }

        let spki_der = resp
            .public_key()
            .context("kms:GetPublicKey returned no public key")?
            .as_ref()
            .to_vec();

        let (n_bytes, e_bytes) =
            parse_spki_rsa(&spki_der).context("Failed to parse RSA-3072 SPKI from KMS")?;

        let n_b64 = URL_SAFE_NO_PAD.encode(&n_bytes);
        let e_b64 = URL_SAFE_NO_PAD.encode(&e_bytes);

        tracing::debug!(
            "KMS RSA-3072 signer initialized (n_prefix={})",
            hex::encode(n_bytes.get(..8).unwrap_or(&n_bytes)),
        );

        Ok(Self {
            kms_client,
            key_id,
            n_b64,
            e_b64,
        })
    }

    /// Sign a pre-computed SHA-256 digest using KMS `RSASSA_PKCS1_V1_5_SHA_256`.
    ///
    /// `MessageType::Digest` means KMS expects a 32-byte SHA-256 hash.
    /// The caller is responsible for hashing the signing input before calling
    /// this method. Returns raw PKCS#1 v1.5 signature bytes (384 bytes for RSA-3072).
    pub(crate) async fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        if digest.len() != 32 {
            bail!(
                "SHA-256 digest must be 32 bytes, got {} (call sha256 before sign_digest)",
                digest.len()
            );
        }

        tracing::debug!(key_id = %self.key_id, "kms:Sign RSA-3072 PKCS1v15");

        let resp = self
            .kms_client
            .sign()
            .key_id(&self.key_id)
            .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
            .message_type(MessageType::Digest)
            .message(aws_smithy_types::Blob::new(digest))
            .send()
            .await
            .context("kms:Sign failed for RSA-3072")?;

        let sig = resp
            .signature()
            .context("kms:Sign returned no signature")?
            .as_ref()
            .to_vec();

        tracing::debug!("kms:Sign RSA-3072 succeeded ({} bytes)", sig.len());
        Ok(sig)
    }

    /// Get the base64url-encoded RSA modulus (`n`).
    pub(crate) fn n_b64(&self) -> &str {
        &self.n_b64
    }

    /// Get the base64url-encoded RSA public exponent (`e`).
    pub(crate) fn e_b64(&self) -> &str {
        &self.e_b64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // RFC 8410 Appendix A — Ed25519 test vector.
    // SubjectPublicKeyInfo for the Ed25519 public key:
    //   d7 5a 98 01 82 b1 0a b7 d5 4b fe d3 c9 64 07 3a
    //   0e e1 72 f3 da a3 23 97 b1 5b bc db c4 1c e6 95
    const ED25519_SPKI_DER: [u8; 44] = [
        0x30, 0x2a, // SEQUENCE (42 bytes)
        0x30, 0x05, // SEQUENCE (5 bytes) - AlgorithmIdentifier
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x03, 0x21, // BIT STRING (33 bytes)
        0x00, // unused bits = 0
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3, 0x23, 0x97, 0xb1, 0x5b, 0xbc, 0xdb, 0xc4, 0x1c,
        0xe6, 0x95,
    ];

    // RFC 5480 Appendix A — P-256 test vector (simplified).
    // A valid SubjectPublicKeyInfo for a P-256 uncompressed point.
    const P256_SPKI_DER: [u8; 91] = [
        0x30, 0x59, // SEQUENCE (89 bytes)
        0x30, 0x13, // SEQUENCE (19 bytes) - AlgorithmIdentifier
        0x06, 0x07, // OID (7 bytes)
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1
        0x06, 0x08, // OID (8 bytes)
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7
        0x03, 0x42, // BIT STRING (66 bytes)
        0x00, // unused bits = 0
        0x04, // uncompressed point prefix
        // x coordinate (32 bytes)
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96, // y coordinate (32 bytes)
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ];

    #[test]
    fn test_parse_spki_ed25519() {
        let key = parse_spki_ed25519(&ED25519_SPKI_DER).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 0xd7);
        assert_eq!(key[31], 0x95);
    }

    #[test]
    fn test_parse_spki_ed25519_wrong_oid() {
        // Use the P-256 SPKI which has a different OID
        let err = parse_spki_ed25519(&P256_SPKI_DER);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("Ed25519 OID"), "got: {msg}");
    }

    #[test]
    fn test_parse_spki_p256() {
        let key = parse_spki_p256(&P256_SPKI_DER).unwrap();
        assert_eq!(key.len(), 65);
        assert_eq!(key[0], 0x04); // uncompressed
        assert_eq!(key[1], 0x6b); // first byte of x
    }

    #[test]
    fn test_parse_spki_p256_wrong_oid() {
        let err = parse_spki_p256(&ED25519_SPKI_DER);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("ecPublicKey"), "got: {msg}");
    }

    #[test]
    fn test_der_ecdsa_to_jwt_roundtrip() {
        // Sign a message with a real P-256 key, then verify
        // der_ecdsa_to_jwt produces a valid 64-byte R||S output
        // that round-trips back to the same DER signature.
        use p256::ecdsa::{SigningKey, signature::Signer};

        let sk = SigningKey::from_bytes(&[0x42; 32].into()).unwrap();
        let der_sig: p256::ecdsa::DerSignature = sk.sign(b"test message");
        let der_bytes = der_sig.as_bytes();

        let jwt = der_ecdsa_to_jwt(der_bytes).unwrap();
        assert_eq!(jwt.len(), 64);

        // Verify the R||S bytes match the original signature
        let reconstructed = p256::ecdsa::Signature::from_bytes(&jwt.into()).unwrap();
        let original = p256::ecdsa::Signature::from_der(der_bytes).unwrap();
        assert_eq!(reconstructed, original);
    }

    #[test]
    fn test_der_ecdsa_to_jwt_invalid() {
        assert!(der_ecdsa_to_jwt(&[0x04, 0x01, 0x00]).is_err());
        assert!(der_ecdsa_to_jwt(&[]).is_err());
    }

    #[test]
    fn test_parse_spki_rsa_generated() {
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::rsa::{KeyPair, KeySize};
        use aws_lc_rs::signature::KeyPair as _;

        // Generate a real RSA-3072 key and verify SPKI parsing extracts n and e.
        // RSA key generation is non-deterministic, so we generate at test time.
        let key_pair = KeyPair::generate(KeySize::Rsa3072).expect("RSA key generation failed");

        // Get SPKI DER (X.509 SubjectPublicKeyInfo)
        let pub_key = key_pair.public_key();
        let spki_der: aws_lc_rs::encoding::PublicKeyX509Der<'static> =
            pub_key.as_der().expect("Failed to encode public key as SPKI DER");

        let (n, e) = parse_spki_rsa(spki_der.as_ref()).expect("parse_spki_rsa should succeed");

        // RSA-3072 modulus is 384 bytes (3072 bits / 8), but may be 383 if high bit of
        // the first byte is 0. After stripping sign padding it's 383-384 bytes.
        assert!(
            n.len() >= 383 && n.len() <= 385,
            "RSA-3072 modulus should be ~384 bytes, got {}",
            n.len()
        );
        // Common exponent 65537 = 0x01_00_01 (3 bytes after stripping leading zeros)
        assert!(!e.is_empty(), "Exponent must not be empty");
    }

    #[test]
    fn test_parse_spki_rsa_rejects_ed25519() {
        let err = parse_spki_rsa(&ED25519_SPKI_DER);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("rsaEncryption") || msg.contains("1.2.840.113549.1.1.1"),
            "got: {msg}"
        );
    }

    #[test]
    fn test_parse_spki_rsa_rejects_p256() {
        let err = parse_spki_rsa(&P256_SPKI_DER);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("rsaEncryption") || msg.contains("1.2.840.113549.1.1.1"),
            "got: {msg}"
        );
    }
}
