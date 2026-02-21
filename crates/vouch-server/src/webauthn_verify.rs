// SPDX-License-Identifier: BUSL-1.1
//! Server-side WebAuthn assertion verification.
//!
//! This module provides COSE signature verification for WebAuthn assertions,
//! giving us full control over the verification process for CLI-based authentication.
//!
//! The verification process follows WebAuthn spec Section 7.2:
//! 1. Verify RP ID hash in authenticator data
//! 2. Check user presence and user verified flags
//! 3. Extract and verify signature counter
//! 4. Verify signature over authenticator_data || SHA-256(client_data_json)
//!
//! # Testability
//!
//! The [`CoseVerifier`] trait allows injecting test implementations for integration
//! testing without requiring real cryptographic keys.
//!
//! # Type Safety
//!
//! This module provides both untyped (`&[u8]`) and typed (`Encoded<T, E>`) interfaces.
//! The typed interfaces use compile-time markers to prevent mixing up different
//! binary data types (e.g., passing a credential_id where a signature is expected).

use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::signature::{self, UnparsedPublicKey};
use thiserror::Error;
use vouch_common::encoding::Raw;
use vouch_common::fido2_types::{AuthData, ClientDataJson, CoseKey, Signature};

/// Trait for COSE signature verification.
///
/// This trait abstracts the cryptographic verification of COSE signatures,
/// allowing for test implementations that can verify assertions without
/// real cryptographic operations.
pub trait CoseVerifier: Send + Sync {
    /// Verify a signature against a COSE public key.
    ///
    /// # Arguments
    ///
    /// * `cose_key` - The public key in COSE format
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Errors
    ///
    /// Returns a [`VerifyError`] if verification fails.
    fn verify(&self, cose_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), VerifyError>;
}

/// Real COSE verifier that performs actual cryptographic verification.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealCoseVerifier;

impl CoseVerifier for RealCoseVerifier {
    fn verify(&self, cose_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        verify_cose_signature(cose_key, message, signature)
    }
}

impl RealCoseVerifier {
    /// Create a new real COSE verifier.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Test COSE verifier that can be configured to succeed or fail.
///
/// This is useful for integration tests that need to test the full
/// verification flow without requiring real cryptographic keys.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone)]
pub struct TestCoseVerifier {
    /// Whether verification should succeed.
    pub should_succeed: bool,
}

#[cfg(any(test, feature = "test-utils"))]
impl TestCoseVerifier {
    /// Create a test verifier that always succeeds.
    #[must_use]
    pub fn always_succeed() -> Self {
        Self {
            should_succeed: true,
        }
    }

    /// Create a test verifier that always fails.
    #[must_use]
    pub fn always_fail() -> Self {
        Self {
            should_succeed: false,
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for TestCoseVerifier {
    fn default() -> Self {
        Self::always_succeed()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl CoseVerifier for TestCoseVerifier {
    fn verify(
        &self,
        _cose_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), VerifyError> {
        if self.should_succeed {
            Ok(())
        } else {
            Err(VerifyError::SignatureInvalid)
        }
    }
}

/// Errors during WebAuthn assertion verification.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("Invalid authenticator data length")]
    InvalidAuthDataLength,

    #[error("RP ID hash mismatch")]
    RpIdMismatch,

    #[error("User presence flag not set")]
    UserNotPresent,

    #[error("User verification required but not performed")]
    UserNotVerified,

    #[error("Invalid client data JSON: {0}")]
    InvalidClientData(String),

    #[error("Challenge mismatch")]
    ChallengeMismatch,

    #[error("Invalid origin")]
    InvalidOrigin,

    #[error("Invalid COSE key format: {0}")]
    InvalidCoseKey(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(i64),

    #[error("Signature verification failed")]
    SignatureInvalid,

    #[error("Counter not increasing (possible cloned authenticator)")]
    CounterNotIncreasing,
}

/// Result of successful assertion verification.
#[derive(Debug)]
pub struct VerificationResult {
    /// The new counter value from the authenticator.
    pub counter: u32,
    /// Whether user verification was performed.
    pub user_verified: bool,
}

/// Client data structure from WebAuthn.
#[derive(Debug, serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    #[allow(dead_code)]
    cross_origin: Option<bool>,
}

/// Verify a WebAuthn assertion using the default COSE verifier.
///
/// This is a convenience function that uses [`RealCoseVerifier`] for production use.
/// For testing, use [`verify_assertion_with_verifier`] with a custom verifier.
///
/// # Arguments
/// * `authenticator_data` - Raw authenticator data bytes
/// * `client_data_json` - Raw client data JSON bytes
/// * `signature` - The signature to verify
/// * `public_key_cose` - The public key in COSE format (from registration)
/// * `expected_rp_id` - The expected relying party ID
/// * `expected_challenge` - The expected challenge (base64url encoded)
/// * `expected_origin` - The expected origin URL
/// * `stored_counter` - The previously stored counter value
/// * `require_user_verification` - Whether to require UV flag
#[allow(clippy::too_many_arguments)]
pub fn verify_assertion(
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    public_key_cose: &[u8],
    expected_rp_id: &str,
    expected_challenge: &str,
    expected_origin: &str,
    stored_counter: u32,
    require_user_verification: bool,
) -> Result<VerificationResult, VerifyError> {
    verify_assertion_with_verifier(
        authenticator_data,
        client_data_json,
        signature,
        public_key_cose,
        expected_rp_id,
        expected_challenge,
        expected_origin,
        stored_counter,
        require_user_verification,
        &RealCoseVerifier,
    )
}

/// Verify a WebAuthn assertion with a custom COSE verifier.
///
/// This function allows injecting a custom verifier for testing purposes.
/// For production use, prefer [`verify_assertion`] which uses the default verifier.
///
/// # Arguments
/// * `authenticator_data` - Raw authenticator data bytes
/// * `client_data_json` - Raw client data JSON bytes
/// * `signature` - The signature to verify
/// * `public_key_cose` - The public key in COSE format (from registration)
/// * `expected_rp_id` - The expected relying party ID
/// * `expected_challenge` - The expected challenge (base64url encoded)
/// * `expected_origin` - The expected origin URL
/// * `stored_counter` - The previously stored counter value
/// * `require_user_verification` - Whether to require UV flag
/// * `verifier` - The COSE verifier to use for signature verification
#[allow(clippy::too_many_arguments)]
pub fn verify_assertion_with_verifier<V: CoseVerifier>(
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    public_key_cose: &[u8],
    expected_rp_id: &str,
    expected_challenge: &str,
    expected_origin: &str,
    stored_counter: u32,
    require_user_verification: bool,
    verifier: &V,
) -> Result<VerificationResult, VerifyError> {
    // 1. Verify authenticator data structure
    // Minimum length: 32 (rpIdHash) + 1 (flags) + 4 (counter) = 37 bytes
    if authenticator_data.len() < 37 {
        return Err(VerifyError::InvalidAuthDataLength);
    }

    // 2. Verify RP ID hash (first 32 bytes)
    let rp_id_hash = authenticator_data
        .get(0..32)
        .ok_or(VerifyError::InvalidAuthDataLength)?;
    let expected_rp_id_hash = digest::digest(&SHA256, expected_rp_id.as_bytes());
    if rp_id_hash != expected_rp_id_hash.as_ref() {
        return Err(VerifyError::RpIdMismatch);
    }

    // 3. Check flags (byte 32)
    let flags = *authenticator_data
        .get(32)
        .ok_or(VerifyError::InvalidAuthDataLength)?;
    let user_present = (flags & 0x01) != 0;
    let user_verified = (flags & 0x04) != 0;

    if !user_present {
        return Err(VerifyError::UserNotPresent);
    }

    if require_user_verification && !user_verified {
        return Err(VerifyError::UserNotVerified);
    }

    // 4. Extract counter (bytes 33-36, big-endian)
    let counter_bytes: [u8; 4] = authenticator_data
        .get(33..37)
        .ok_or(VerifyError::InvalidAuthDataLength)?
        .try_into()
        .map_err(|_| VerifyError::InvalidAuthDataLength)?;
    let counter = u32::from_be_bytes(counter_bytes);

    // 5. Verify counter is increasing (if not zero - some authenticators don't use counters)
    if counter != 0 && stored_counter != 0 && counter <= stored_counter {
        return Err(VerifyError::CounterNotIncreasing);
    }

    // 6. Parse and verify client data
    let client_data: ClientData = serde_json::from_slice(client_data_json)
        .map_err(|e| VerifyError::InvalidClientData(e.to_string()))?;

    // Verify type
    if client_data.type_ != "webauthn.get" {
        return Err(VerifyError::InvalidClientData(format!(
            "Expected type 'webauthn.get', got '{}'",
            client_data.type_
        )));
    }

    // Verify challenge
    if client_data.challenge != expected_challenge {
        return Err(VerifyError::ChallengeMismatch);
    }

    // Verify origin
    if client_data.origin != expected_origin {
        // Allow localhost variations for development (e.g. localhost ↔ 127.0.0.1).
        // Note: this intentionally does not compare ports — the server may listen
        // on one port while the browser constructs an origin with a different one.
        let expected_is_local = url::Url::parse(expected_origin)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .is_some_and(|h| vouch_common::is_loopback_host(&h));
        let origin_is_local = url::Url::parse(&client_data.origin)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .is_some_and(|h| vouch_common::is_loopback_host(&h));
        let is_localhost_match = expected_is_local && origin_is_local;

        if !is_localhost_match {
            return Err(VerifyError::InvalidOrigin);
        }
    }

    // 7. Build signed data: authenticator_data || SHA-256(client_data_json)
    let client_data_hash = digest::digest(&SHA256, client_data_json);
    let mut signed_data = Vec::with_capacity(authenticator_data.len() + 32);
    signed_data.extend_from_slice(authenticator_data);
    signed_data.extend_from_slice(client_data_hash.as_ref());

    // 8. Verify signature using the provided verifier
    verifier.verify(public_key_cose, &signed_data, signature)?;

    Ok(VerificationResult {
        counter,
        user_verified,
    })
}

// ============================================================================
// Type-Safe Wrappers (Phase 3)
// ============================================================================

/// Verify a WebAuthn assertion using typed parameters.
///
/// This is a type-safe wrapper around [`verify_assertion`] that uses the
/// `Encoded<T, E>` types from `vouch_common` for compile-time safety.
///
/// # Type Safety
///
/// Using typed parameters prevents accidentally swapping arguments:
/// - `AuthData<Raw>` for authenticator data
/// - `ClientDataJson<Raw>` for client data JSON
/// - `Signature<Raw>` for the signature
/// - `CoseKey<Raw>` for the public key
#[allow(clippy::too_many_arguments)]
pub fn verify_assertion_typed(
    authenticator_data: &AuthData<Raw>,
    client_data_json: &ClientDataJson<Raw>,
    signature: &Signature<Raw>,
    public_key_cose: &CoseKey<Raw>,
    expected_rp_id: &str,
    expected_challenge: &str,
    expected_origin: &str,
    stored_counter: u32,
    require_user_verification: bool,
) -> Result<VerificationResult, VerifyError> {
    verify_assertion(
        authenticator_data.as_bytes(),
        client_data_json.as_bytes(),
        signature.as_bytes(),
        public_key_cose.as_bytes(),
        expected_rp_id,
        expected_challenge,
        expected_origin,
        stored_counter,
        require_user_verification,
    )
}

/// Verify a WebAuthn assertion with a custom COSE verifier using typed parameters.
///
/// This is a type-safe wrapper around [`verify_assertion_with_verifier`].
#[allow(clippy::too_many_arguments)]
pub fn verify_assertion_typed_with_verifier<V: CoseVerifier>(
    authenticator_data: &AuthData<Raw>,
    client_data_json: &ClientDataJson<Raw>,
    signature: &Signature<Raw>,
    public_key_cose: &CoseKey<Raw>,
    expected_rp_id: &str,
    expected_challenge: &str,
    expected_origin: &str,
    stored_counter: u32,
    require_user_verification: bool,
    verifier: &V,
) -> Result<VerificationResult, VerifyError> {
    verify_assertion_with_verifier(
        authenticator_data.as_bytes(),
        client_data_json.as_bytes(),
        signature.as_bytes(),
        public_key_cose.as_bytes(),
        expected_rp_id,
        expected_challenge,
        expected_origin,
        stored_counter,
        require_user_verification,
        verifier,
    )
}

/// Verify a signature using typed COSE key and signature.
///
/// This is a type-safe wrapper for internal use.
#[allow(dead_code)]
pub fn verify_cose_signature_typed(
    cose_key: &CoseKey<Raw>,
    message: &[u8],
    signature: &Signature<Raw>,
) -> Result<(), VerifyError> {
    verify_cose_signature(cose_key.as_bytes(), message, signature.as_bytes())
}

/// Verify a signature using a COSE-encoded public key.
fn verify_cose_signature(
    cose_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    // Parse COSE key using ciborium
    let cose_map: ciborium::Value =
        ciborium::from_reader(cose_key).map_err(|e| VerifyError::InvalidCoseKey(e.to_string()))?;

    let map = match cose_map {
        ciborium::Value::Map(m) => m,
        _ => return Err(VerifyError::InvalidCoseKey("Expected COSE map".to_string())),
    };

    // Extract key type (kty) - label 1
    let kty = get_cose_int(&map, 1)?;

    // Extract algorithm (alg) - label 3
    let alg = get_cose_int(&map, 3)?;

    match (kty, alg) {
        // EC2 key with ES256 (-7)
        (2, -7) => verify_es256(&map, message, signature),
        // RSA key with RS256 (-257)
        (3, -257) => verify_rs256(&map, message, signature),
        // OKP key with EdDSA (-8)
        (1, -8) => verify_eddsa(&map, message, signature),
        _ => Err(VerifyError::UnsupportedAlgorithm(alg)),
    }
}

/// Get an integer value from a COSE map by label.
fn get_cose_int(
    map: &[(ciborium::Value, ciborium::Value)],
    label: i64,
) -> Result<i64, VerifyError> {
    for (k, v) in map {
        if let ciborium::Value::Integer(i) = k {
            let key_int: i128 = (*i).into();
            if key_int == i128::from(label)
                && let ciborium::Value::Integer(val) = v
            {
                let val_int: i128 = (*val).into();
                return i64::try_from(val_int)
                    .map_err(|_| VerifyError::InvalidCoseKey("Integer overflow".to_string()));
            }
        }
    }
    Err(VerifyError::InvalidCoseKey(format!(
        "Missing COSE key field: {label}"
    )))
}

/// Get a byte string value from a COSE map by label.
fn get_cose_bytes(
    map: &[(ciborium::Value, ciborium::Value)],
    label: i64,
) -> Result<Vec<u8>, VerifyError> {
    for (k, v) in map {
        if let ciborium::Value::Integer(i) = k {
            let key_int: i128 = (*i).into();
            if key_int == i128::from(label)
                && let ciborium::Value::Bytes(bytes) = v
            {
                return Ok(bytes.clone());
            }
        }
    }
    Err(VerifyError::InvalidCoseKey(format!(
        "Missing COSE key field: {label}"
    )))
}

/// Verify ES256 (ECDSA P-256) signature.
fn verify_es256(
    map: &[(ciborium::Value, ciborium::Value)],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    // Extract x coordinate (label -2)
    let x = get_cose_bytes(map, -2)?;
    // Extract y coordinate (label -3)
    let y = get_cose_bytes(map, -3)?;

    // Build uncompressed SEC1 point: 0x04 || x || y
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);

    // Detailed logging for debugging (debug builds only)
    #[cfg(debug_assertions)]
    {
        tracing::debug!(
            "verify_es256: x_len={}, y_len={}, point_len={}",
            x.len(),
            y.len(),
            point.len()
        );
    }

    // Try raw format first (64 bytes, r || s) - used by browser WebAuthn
    // Then try DER/ASN.1 format (70-72 bytes) - used by CTAP2/YubiKey
    if signature.len() == 64 {
        let public_key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &point);
        public_key.verify(message, signature).map_err(|e| {
            tracing::warn!("verify_es256: FIXED verification failed: {e:?}");
            VerifyError::SignatureInvalid
        })
    } else {
        // DER-encoded signature from CTAP2
        let public_key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &point);
        public_key.verify(message, signature).map_err(|e| {
            tracing::warn!("verify_es256: ASN1 verification failed: {e:?}");
            VerifyError::SignatureInvalid
        })
    }
}

/// Verify RS256 (RSA PKCS#1 v1.5 with SHA-256) signature.
fn verify_rs256(
    map: &[(ciborium::Value, ciborium::Value)],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    // Extract n (modulus) - label -1
    let n_bytes = get_cose_bytes(map, -1)?;
    // Extract e (exponent) - label -2
    let e_bytes = get_cose_bytes(map, -2)?;

    // aws-lc-rs uses RsaPublicKeyComponents for verification
    let public_key = signature::RsaPublicKeyComponents {
        n: &n_bytes,
        e: &e_bytes,
    };

    public_key
        .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
        .map_err(|_| VerifyError::SignatureInvalid)
}

/// Verify EdDSA (Ed25519) signature.
fn verify_eddsa(
    map: &[(ciborium::Value, ciborium::Value)],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Extract x (public key) - label -2
    let x = get_cose_bytes(map, -2)?;

    if x.len() != 32 {
        return Err(VerifyError::InvalidCoseKey(
            "Ed25519 public key must be 32 bytes".to_string(),
        ));
    }

    let key_bytes: [u8; 32] = x
        .try_into()
        .map_err(|_| VerifyError::InvalidCoseKey("Invalid Ed25519 key length".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| VerifyError::InvalidCoseKey(format!("Invalid Ed25519 key: {e}")))?;

    if signature.len() != 64 {
        return Err(VerifyError::SignatureInvalid);
    }

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| VerifyError::SignatureInvalid)?;

    let sig = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(message, &sig)
        .map_err(|_| VerifyError::SignatureInvalid)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use aws_lc_rs::digest::{self, SHA256};

    // =========================================================================
    // Test Helpers
    // =========================================================================

    /// Create minimal valid authenticator data
    fn make_auth_data(rp_id: &str, flags: u8, counter: u32) -> Vec<u8> {
        let rp_id_hash = digest::digest(&SHA256, rp_id.as_bytes());
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(rp_id_hash.as_ref()); // 32 bytes
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes()); // 4 bytes
        auth_data
    }

    /// Create valid client data JSON
    fn make_client_data_json(type_: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": type_,
            "challenge": challenge,
            "origin": origin
        }))
        .unwrap()
    }

    /// Create a minimal valid ES256 COSE key
    #[allow(dead_code)]
    fn make_es256_cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = EC2
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = ES256 (-7)
                ciborium::Value::Integer((-7).into()),
            ),
            (
                ciborium::Value::Integer((-1).into()), // crv = P-256 (1)
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()), // x
                ciborium::Value::Bytes(x.to_vec()),
            ),
            (
                ciborium::Value::Integer((-3).into()), // y
                ciborium::Value::Bytes(y.to_vec()),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        buf
    }

    /// Create a minimal valid EdDSA COSE key
    fn make_eddsa_cose_key(x: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = OKP
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = EdDSA (-8)
                ciborium::Value::Integer((-8).into()),
            ),
            (
                ciborium::Value::Integer((-1).into()), // crv = Ed25519 (6)
                ciborium::Value::Integer(6.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()), // x (public key)
                ciborium::Value::Bytes(x.to_vec()),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        buf
    }

    /// Create a minimal valid RS256 COSE key
    #[allow(dead_code)]
    fn make_rs256_cose_key(n: &[u8], e: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = RSA
                ciborium::Value::Integer(3.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = RS256 (-257)
                ciborium::Value::Integer((-257).into()),
            ),
            (
                ciborium::Value::Integer((-1).into()), // n (modulus)
                ciborium::Value::Bytes(n.to_vec()),
            ),
            (
                ciborium::Value::Integer((-2).into()), // e (exponent)
                ciborium::Value::Bytes(e.to_vec()),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        buf
    }

    // =========================================================================
    // Basic Tests (existing)
    // =========================================================================

    #[test]
    fn test_rp_id_hash_verification() {
        // Create minimal valid authenticator data with correct RP ID hash
        let rp_id = "example.com";
        let rp_id_hash = digest::digest(&SHA256, rp_id.as_bytes());

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(rp_id_hash.as_ref()); // 32 bytes
        auth_data.push(0x05); // flags: UP + UV
        auth_data.extend_from_slice(&[0, 0, 0, 1]); // counter = 1

        // This should pass RP ID verification
        assert_eq!(&auth_data[0..32], rp_id_hash.as_ref());
    }

    #[test]
    fn test_flags_parsing() {
        let flags_up_only: u8 = 0x01;
        let flags_up_uv: u8 = 0x05;

        assert!((flags_up_only & 0x01) != 0); // UP set
        assert!((flags_up_only & 0x04) == 0); // UV not set

        assert!((flags_up_uv & 0x01) != 0); // UP set
        assert!((flags_up_uv & 0x04) != 0); // UV set
    }

    // =========================================================================
    // COSE Key Parsing Tests
    // =========================================================================

    #[test]
    fn test_cose_key_missing_kty() {
        // Create COSE key without kty field
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![(
            ciborium::Value::Integer(3.into()), // alg only
            ciborium::Value::Integer((-7).into()),
        )]);
        ciborium::into_writer(&key, &mut buf).unwrap();

        let result = verify_cose_signature(&buf, &[], &[]);
        assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("1")));
    }

    #[test]
    fn test_cose_key_missing_alg() {
        // Create COSE key without alg field
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![(
            ciborium::Value::Integer(1.into()), // kty only
            ciborium::Value::Integer(2.into()),
        )]);
        ciborium::into_writer(&key, &mut buf).unwrap();

        let result = verify_cose_signature(&buf, &[], &[]);
        assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("3")));
    }

    #[test]
    fn test_cose_key_unsupported_algorithm() {
        // Create COSE key with unsupported algorithm (e.g., -999)
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer((-999).into()),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();

        let result = verify_cose_signature(&buf, &[], &[]);
        assert!(matches!(
            result,
            Err(VerifyError::UnsupportedAlgorithm(-999))
        ));
    }

    #[test]
    fn test_cose_key_ec2_missing_x() {
        // EC2 key missing x coordinate
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = EC2
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = ES256
                ciborium::Value::Integer((-7).into()),
            ),
            (
                ciborium::Value::Integer((-3).into()), // y only
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();

        let result = verify_cose_signature(&buf, &[], &[]);
        assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("-2")));
    }

    #[test]
    fn test_cose_key_ec2_missing_y() {
        // EC2 key missing y coordinate
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = EC2
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = ES256
                ciborium::Value::Integer((-7).into()),
            ),
            (
                ciborium::Value::Integer((-2).into()), // x only
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();

        let result = verify_cose_signature(&buf, &[], &[]);
        assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("-3")));
    }

    #[test]
    fn test_cose_key_okp_missing_x() {
        // OKP key missing x (public key)
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = OKP
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = EdDSA
                ciborium::Value::Integer((-8).into()),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();

        let result = verify_cose_signature(&buf, &[], &[]);
        assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("-2")));
    }

    #[test]
    fn test_cose_key_truncated_cbor() {
        // Truncated CBOR data
        let truncated = vec![0xA3, 0x01, 0x02]; // Start of map but incomplete
        let result = verify_cose_signature(&truncated, &[], &[]);
        assert!(matches!(result, Err(VerifyError::InvalidCoseKey(_))));
    }

    #[test]
    fn test_cose_key_not_a_map() {
        // CBOR integer instead of map
        let mut buf = Vec::new();
        ciborium::into_writer(&ciborium::Value::Integer(42.into()), &mut buf).unwrap();

        let result = verify_cose_signature(&buf, &[], &[]);
        assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("map")));
    }

    #[test]
    fn test_cose_key_eddsa_wrong_key_length() {
        // Ed25519 key with wrong length (not 32 bytes)
        let cose_key = make_eddsa_cose_key(&[0u8; 16]); // Should be 32 bytes

        let result = verify_cose_signature(&cose_key, &[], &[]);
        assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("32")));
    }

    // =========================================================================
    // Signature Verification Tests
    // =========================================================================

    #[test]
    fn test_eddsa_signature_wrong_length() {
        // Generate a real Ed25519 keypair for testing
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let cose_key = make_eddsa_cose_key(verifying_key.as_bytes());
        let message = b"test message";
        let wrong_len_sig = vec![0u8; 32]; // Should be 64 bytes

        let result = verify_cose_signature(&cose_key, message, &wrong_len_sig);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn test_eddsa_signature_valid() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let cose_key = make_eddsa_cose_key(verifying_key.as_bytes());
        let message = b"test message for EdDSA";
        let signature = signing_key.sign(message);

        let result = verify_cose_signature(&cose_key, message, &signature.to_bytes());
        assert!(result.is_ok());
    }

    #[test]
    fn test_eddsa_signature_tampered() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let cose_key = make_eddsa_cose_key(verifying_key.as_bytes());
        let message = b"test message for EdDSA";
        let mut signature = signing_key.sign(message).to_bytes();

        // Tamper with signature
        signature[0] ^= 0xFF;

        let result = verify_cose_signature(&cose_key, message, &signature);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn test_eddsa_wrong_message() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let cose_key = make_eddsa_cose_key(verifying_key.as_bytes());
        let message = b"original message";
        let signature = signing_key.sign(message);

        // Verify with different message
        let result = verify_cose_signature(&cose_key, b"different message", &signature.to_bytes());
        assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
    }

    // =========================================================================
    // Authenticator Data Tests
    // =========================================================================

    #[test]
    fn test_auth_data_minimum_length() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";

        // Too short (less than 37 bytes)
        let short_auth_data = vec![0u8; 36];
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &short_auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0,
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::InvalidAuthDataLength)));
    }

    #[test]
    fn test_auth_data_exactly_minimum_length() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 1); // 37 bytes exactly
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0,
            false,
            &verifier,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_auth_data_rp_id_mismatch() {
        let verifier = TestCoseVerifier::always_succeed();
        let auth_data = make_auth_data("wrong-rp.com", 0x05, 1);
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            "example.com", // Expected RP ID doesn't match auth_data
            "test-challenge",
            "https://example.com",
            0,
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::RpIdMismatch)));
    }

    #[test]
    fn test_auth_data_user_presence_required() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x00, 1); // No UP flag
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0,
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::UserNotPresent)));
    }

    #[test]
    fn test_auth_data_user_verification_required() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x01, 1); // UP but no UV
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0,
            true, // Require UV
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::UserNotVerified)));
    }

    #[test]
    fn test_auth_data_user_verification_not_required() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x01, 1); // UP but no UV
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0,
            false, // Don't require UV
            &verifier,
        );
        assert!(result.is_ok());
    }

    // =========================================================================
    // Counter Validation Tests (Replay Protection)
    // =========================================================================

    #[test]
    fn test_counter_must_increase() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 5); // counter = 5
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        // With stored counter 4, new counter 5 should succeed
        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            4, // stored counter
            false,
            &verifier,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().counter, 5);
    }

    #[test]
    fn test_counter_exact_match_rejected() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 5); // counter = 5
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        // Same counter = replay attack
        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            5, // Same as auth_data counter
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::CounterNotIncreasing)));
    }

    #[test]
    fn test_counter_decrease_rejected() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 3); // counter = 3
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        // Lower counter = cloned authenticator
        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            5, // stored counter is higher
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::CounterNotIncreasing)));
    }

    #[test]
    fn test_counter_zero_special_case() {
        // Some CTAP1 authenticators always return 0
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 0); // counter = 0
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        // Zero counter should be accepted (authenticator doesn't support counters)
        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0, // stored counter also 0
            false,
            &verifier,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_counter_zero_to_nonzero() {
        // First use with stored=0, new counter=1
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 1); // counter = 1
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0, // Initial stored counter
            false,
            &verifier,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_counter_u32_max_boundary() {
        // Test near u32::MAX boundary
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, u32::MAX); // Maximum counter
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            u32::MAX - 1, // stored counter just below max
            false,
            &verifier,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().counter, u32::MAX);
    }

    // =========================================================================
    // Client Data JSON Tests
    // =========================================================================

    #[test]
    fn test_client_data_invalid_json() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let invalid_json = b"not valid json{";
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            invalid_json,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0,
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::InvalidClientData(_))));
    }

    #[test]
    fn test_client_data_wrong_type() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data =
            make_client_data_json("webauthn.create", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        // Type should be "webauthn.get" for assertions
        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0,
            false,
            &verifier,
        );
        assert!(
            matches!(result, Err(VerifyError::InvalidClientData(msg)) if msg.contains("webauthn.get"))
        );
    }

    #[test]
    fn test_client_data_challenge_mismatch() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data =
            make_client_data_json("webauthn.get", "wrong-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "expected-challenge",
            "https://example.com",
            0,
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::ChallengeMismatch)));
    }

    #[test]
    fn test_client_data_origin_mismatch() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://evil.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0,
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
    }

    #[test]
    fn test_client_data_localhost_variations_allowed() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "localhost";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://127.0.0.1:8080");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        // localhost and 127.0.0.1 should be treated as equivalent
        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://localhost:8080",
            0,
            false,
            &verifier,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_data_docker_internal_to_localhost_allowed() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "host.docker.internal";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "http://localhost:3000");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        // host.docker.internal and localhost are both loopback
        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "http://host.docker.internal:3000",
            0,
            false,
            &verifier,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_data_ipv6_loopback_to_localhost_allowed() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "localhost";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "http://[::1]:3000");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        // [::1] and localhost are both loopback
        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "http://localhost:3000",
            0,
            false,
            &verifier,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_data_loopback_vs_remote_rejected() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        // Client claims localhost origin, but expected origin is remote
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "http://localhost:3000");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0,
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
    }

    #[test]
    fn test_client_data_remote_vs_loopback_rejected() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "localhost";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        // Client claims remote origin, but expected origin is loopback
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://evil.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "http://localhost:3000",
            0,
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
    }

    #[test]
    fn test_client_data_localhost_in_path_not_matched() {
        // Regression test: an origin like https://evil.com/localhost must NOT
        // be treated as loopback (the old contains() approach was vulnerable)
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "localhost";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data = make_client_data_json(
            "webauthn.get",
            "test-challenge",
            "https://evil.com/localhost",
        );
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "http://localhost:3000",
            0,
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
    }

    // =========================================================================
    // Full Assertion Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_assertion_success() {
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0,
            false,
            &verifier,
        );

        assert!(result.is_ok());
        let verification = result.unwrap();
        assert_eq!(verification.counter, 1);
        assert!(verification.user_verified);
    }

    #[test]
    fn test_verify_assertion_signature_invalid() {
        let verifier = TestCoseVerifier::always_fail();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &auth_data,
            &client_data,
            &[0u8; 64],
            &cose_key,
            rp_id,
            "test-challenge",
            "https://example.com",
            0,
            false,
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
    }

    // =========================================================================
    // Test Verifier Tests
    // =========================================================================

    #[test]
    fn test_test_cose_verifier_always_succeed() {
        let verifier = TestCoseVerifier::always_succeed();
        assert!(verifier.verify(&[], &[], &[]).is_ok());
    }

    #[test]
    fn test_test_cose_verifier_always_fail() {
        let verifier = TestCoseVerifier::always_fail();
        assert!(matches!(
            verifier.verify(&[], &[], &[]),
            Err(VerifyError::SignatureInvalid)
        ));
    }

    #[test]
    fn test_test_cose_verifier_default() {
        let verifier = TestCoseVerifier::default();
        assert!(verifier.verify(&[], &[], &[]).is_ok());
    }
}
