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

use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::signature::{self, UnparsedPublicKey};
use thiserror::Error;

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
        // Allow localhost variations for development
        let is_localhost_match = (expected_origin.contains("localhost")
            || expected_origin.contains("127.0.0.1"))
            && (client_data.origin.contains("localhost")
                || client_data.origin.contains("127.0.0.1"));

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

    // Try raw format first (64 bytes, r || s) - used by browser WebAuthn
    // Then try DER/ASN.1 format (70-72 bytes) - used by CTAP2/YubiKey
    if signature.len() == 64 {
        let public_key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &point);
        public_key
            .verify(message, signature)
            .map_err(|_| VerifyError::SignatureInvalid)
    } else {
        // DER-encoded signature from CTAP2
        let public_key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &point);
        public_key
            .verify(message, signature)
            .map_err(|_| VerifyError::SignatureInvalid)
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
#[allow(clippy::indexing_slicing)]
mod tests {
    #[test]
    fn test_rp_id_hash_verification() {
        use aws_lc_rs::digest::{self, SHA256};

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
}
