// SPDX-License-Identifier: Apache-2.0 OR MIT
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
use der::Decode;
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

    #[error("Attestation certificate chain invalid: {0}")]
    AttestationChainInvalid(String),
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
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
    cross_origin: Option<bool>,
}

/// Parameters for WebAuthn assertion verification (WebAuthn Level 2 §7.2).
///
/// Named fields prevent the positional byte-slice/string swaps an 11-argument
/// signature would invite.
#[derive(Debug, Clone, Copy)]
pub struct AssertionParams<'a> {
    /// Raw authenticator data bytes.
    pub authenticator_data: &'a [u8],
    /// Raw client data JSON bytes.
    pub client_data_json: &'a [u8],
    /// The signature to verify.
    pub signature: &'a [u8],
    /// The public key in COSE format (from registration).
    pub public_key_cose: &'a [u8],
    /// The expected relying party ID.
    pub expected_rp_id: &'a str,
    /// The expected challenge (base64url encoded).
    pub expected_challenge: &'a str,
    /// The expected origin URL.
    pub expected_origin: &'a str,
    /// The previously stored counter value.
    pub stored_counter: u32,
    /// Whether to require the UV flag.
    pub require_user_verification: bool,
    /// Whether to tolerate loopback origin variations. Development only; pass
    /// `false` in production so an origin mismatch is always rejected.
    pub allow_localhost_origin: bool,
}

/// Verify a WebAuthn assertion using the default COSE verifier.
///
/// This is a convenience function that uses [`RealCoseVerifier`] for production use.
/// For testing, use [`verify_assertion_with_verifier`] with a custom verifier.
pub fn verify_assertion(params: &AssertionParams<'_>) -> Result<VerificationResult, VerifyError> {
    verify_assertion_inner(params, &RealCoseVerifier)
}

/// Verify a WebAuthn assertion with a custom COSE verifier.
///
/// This function allows injecting a custom verifier for testing purposes.
/// For production use, prefer [`verify_assertion`] which uses the default verifier.
pub fn verify_assertion_with_verifier<V: CoseVerifier>(
    params: &AssertionParams<'_>,
    verifier: &V,
) -> Result<VerificationResult, VerifyError> {
    verify_assertion_inner(params, verifier)
}

/// Core WebAuthn assertion verification.
///
/// `params.allow_localhost_origin` gates the loopback origin-variation
/// relaxation: it must be `true` only in development (no TLS). Production
/// threads `false` so an origin mismatch is always rejected even on a
/// misconfigured loopback `rp_id`.
fn verify_assertion_inner<V: CoseVerifier>(
    params: &AssertionParams<'_>,
    verifier: &V,
) -> Result<VerificationResult, VerifyError> {
    let &AssertionParams {
        authenticator_data,
        client_data_json,
        signature,
        public_key_cose,
        expected_rp_id,
        expected_challenge,
        expected_origin,
        stored_counter,
        require_user_verification,
        allow_localhost_origin,
    } = params;

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

    // 5. Verify counter is increasing.
    //
    // Per WebAuthn Level 2 §6.1.1, a value of `authData.signCount <=
    // storedSignCount` is a cloning signal whenever *either* value is nonzero.
    // We therefore reject as soon as the *stored* counter is nonzero and the
    // presented counter does not strictly increase — including a regression to
    // zero. A credential that has ever reported a nonzero counter may never go
    // backwards (YubiKeys always increment), so a zero arriving after a nonzero
    // stored value is unambiguous evidence of cloning or forgery.
    //
    // Credentials that have only ever reported zero (counter-less
    // authenticators, e.g. some CTAP1 devices) keep `stored_counter == 0` and
    // remain accepted, preserving compatibility.
    if stored_counter != 0 && counter <= stored_counter {
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
        let is_localhost_match = allow_localhost_origin && expected_is_local && origin_is_local;

        if is_localhost_match {
            tracing::warn!(
                target: "security",
                expected = %expected_origin,
                actual = %client_data.origin,
                "Allowing localhost origin variation (development mode) -- \
                 this relaxation is disabled when TLS is configured"
            );
        } else {
            return Err(VerifyError::InvalidOrigin);
        }
    }

    // 7. Build signed data: authenticator_data || SHA-256(client_data_json)
    let client_data_hash = digest::digest(&SHA256, client_data_json);
    let mut signed_data = Vec::with_capacity(authenticator_data.len().saturating_add(32));
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
// Registration (Attestation) Verification
// ============================================================================

/// Result of successful registration (attestation) verification.
#[derive(Debug)]
pub struct RegistrationVerificationResult {
    /// The verified credential ID.
    pub credential_id: Vec<u8>,
    /// The verified COSE public key (CBOR-encoded).
    pub public_key_cose: Vec<u8>,
    /// The AAGUID from the authenticator (16 bytes, hex-encoded).
    pub aaguid: Option<String>,
    /// The counter value from registration (usually 0).
    pub counter: u32,
    /// Whether the attestation was cryptographically verified via x5c chain.
    pub attestation_verified: bool,
}

/// Verify a WebAuthn registration (attestation) response.
///
/// Implements WebAuthn Level 2 Section 7.1 verification steps:
/// 1. Parse `attestation_object` CBOR
/// 2. Verify `authData`: RP ID hash, flags (UP+UV+AT), extract credential
/// 3. Parse `clientDataJSON`: verify type=webauthn.create, challenge, origin
/// 4. For `fmt="packed"` self-attestation: verify signature
/// 5. For `fmt="none"`: accept (no attestation statement)
///
/// Returns the server-verified credential ID, public key, and AAGUID.
pub fn verify_registration(
    attestation_object: &[u8],
    client_data_json: &[u8],
    expected_rp_id: &str,
    expected_challenge: &str,
    expected_origin: &str,
    require_user_verification: bool,
) -> Result<RegistrationVerificationResult, VerifyError> {
    verify_registration_with_verifier(
        attestation_object,
        client_data_json,
        expected_rp_id,
        expected_challenge,
        expected_origin,
        require_user_verification,
        &RealCoseVerifier,
    )
}

/// Verify a WebAuthn registration with a custom COSE verifier.
///
/// This is the testable version of [`verify_registration`].
pub fn verify_registration_with_verifier<V: CoseVerifier>(
    attestation_object: &[u8],
    client_data_json: &[u8],
    expected_rp_id: &str,
    expected_challenge: &str,
    expected_origin: &str,
    require_user_verification: bool,
    verifier: &V,
) -> Result<RegistrationVerificationResult, VerifyError> {
    // 1. Parse attestation_object CBOR
    let att_obj: ciborium::Value = ciborium::from_reader(attestation_object)
        .map_err(|e| VerifyError::InvalidClientData(format!("Invalid attestation CBOR: {e}")))?;

    let att_map = match att_obj {
        ciborium::Value::Map(m) => m,
        _ => {
            return Err(VerifyError::InvalidClientData(
                "attestation_object is not a CBOR map".to_string(),
            ));
        }
    };

    // Extract fields: authData, fmt, attStmt
    let auth_data_bytes = cbor_map_get_bytes(&att_map, "authData")?;
    let fmt = cbor_map_get_text(&att_map, "fmt")?;
    let att_stmt = cbor_map_get_map(&att_map, "attStmt");

    // 2. Verify authData
    // Registration authData: rpIdHash(32) + flags(1) + counter(4) + attestedCredData(variable)
    if auth_data_bytes.len() < 37 {
        return Err(VerifyError::InvalidAuthDataLength);
    }

    // Verify RP ID hash
    let rp_id_hash = auth_data_bytes
        .get(0..32)
        .ok_or(VerifyError::InvalidAuthDataLength)?;
    let expected_hash = digest::digest(&SHA256, expected_rp_id.as_bytes());
    if rp_id_hash != expected_hash.as_ref() {
        return Err(VerifyError::RpIdMismatch);
    }

    // Check flags
    let flags = *auth_data_bytes
        .get(32)
        .ok_or(VerifyError::InvalidAuthDataLength)?;
    let user_present = (flags & 0x01) != 0;
    let user_verified = (flags & 0x04) != 0;
    let attested_credential_data = (flags & 0x40) != 0;

    if !user_present {
        return Err(VerifyError::UserNotPresent);
    }
    if require_user_verification && !user_verified {
        return Err(VerifyError::UserNotVerified);
    }
    if !attested_credential_data {
        return Err(VerifyError::InvalidClientData(
            "AT flag not set in registration authData".to_string(),
        ));
    }

    // Extract counter
    let counter_bytes: [u8; 4] = auth_data_bytes
        .get(33..37)
        .ok_or(VerifyError::InvalidAuthDataLength)?
        .try_into()
        .map_err(|_| VerifyError::InvalidAuthDataLength)?;
    let counter = u32::from_be_bytes(counter_bytes);

    // Extract attested credential data (starts at byte 37)
    // AAGUID (16 bytes) + credential ID length (2 bytes) + credential ID + COSE key
    let attested_data = auth_data_bytes
        .get(37..)
        .ok_or(VerifyError::InvalidAuthDataLength)?;

    if attested_data.len() < 18 {
        // 16 (AAGUID) + 2 (credId length)
        return Err(VerifyError::InvalidAuthDataLength);
    }

    let cred_id_len_bytes: [u8; 2] = attested_data
        .get(16..18)
        .ok_or(VerifyError::InvalidAuthDataLength)?
        .try_into()
        .map_err(|_| VerifyError::InvalidAuthDataLength)?;
    let cred_id_len = u16::from_be_bytes(cred_id_len_bytes) as usize;

    let cose_key_start = 18_usize
        .checked_add(cred_id_len)
        .ok_or(VerifyError::InvalidAuthDataLength)?;
    if attested_data.len() < cose_key_start {
        return Err(VerifyError::InvalidAuthDataLength);
    }

    let credential_id = attested_data
        .get(18..cose_key_start)
        .ok_or(VerifyError::InvalidAuthDataLength)?
        .to_vec();

    let cose_key_bytes = vouch_common::extract_public_key_from_auth_data(&auth_data_bytes)
        .ok_or(VerifyError::InvalidAuthDataLength)?;

    if cose_key_bytes.is_empty() {
        return Err(VerifyError::InvalidCoseKey(
            "Empty COSE key in authData".to_string(),
        ));
    }

    let mut aaguid = vouch_common::extract_aaguid_from_auth_data(&auth_data_bytes)
        .filter(|s| s != "00000000-0000-0000-0000-000000000000");

    // 3. Parse and verify client data
    let client_data: ClientData = serde_json::from_slice(client_data_json)
        .map_err(|e| VerifyError::InvalidClientData(e.to_string()))?;

    if client_data.type_ != "webauthn.create" {
        return Err(VerifyError::InvalidClientData(format!(
            "Expected type 'webauthn.create', got '{}'",
            client_data.type_
        )));
    }

    if client_data.challenge != expected_challenge {
        return Err(VerifyError::ChallengeMismatch);
    }

    // Verify origin (reuse the same localhost relaxation logic as assertion)
    if client_data.origin != expected_origin {
        let expected_is_local = url::Url::parse(expected_origin)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .is_some_and(|h| vouch_common::is_loopback_host(&h));
        let origin_is_local = url::Url::parse(&client_data.origin)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .is_some_and(|h| vouch_common::is_loopback_host(&h));

        if expected_is_local && origin_is_local {
            tracing::debug!(
                expected = %expected_origin,
                actual = %client_data.origin,
                "Allowing localhost origin variation for registration (development mode)"
            );
        } else {
            return Err(VerifyError::InvalidOrigin);
        }
    }

    // 4. Verify attestation statement based on format
    let mut attestation_verified = false;

    match fmt.as_str() {
        "none" => {
            // No attestation statement — accept the credential
        }
        "packed" => {
            // Packed attestation (self-attestation if no x5c certificate chain)
            if let Some(stmt_map) = att_stmt {
                let packed_result = verify_packed_attestation(
                    stmt_map,
                    &auth_data_bytes,
                    client_data_json,
                    &cose_key_bytes,
                    aaguid.as_deref(),
                    verifier,
                )?;
                if let Some(result) = packed_result {
                    attestation_verified = result.attestation_verified;
                    // If the chain provided a cert AAGUID, prefer it
                    if aaguid.is_none() {
                        aaguid = result.cert_aaguid;
                    }
                }
            }
            // No attStmt with packed format is invalid, but we're lenient
            // since the COSE key is verified through usage anyway
        }
        other => {
            // Accept other formats (fido-u2f, tpm, etc.) without verification.
            // The credential will still be verified through assertion on login.
            tracing::debug!(fmt = %other, "Accepting unverified attestation format");
        }
    }

    Ok(RegistrationVerificationResult {
        credential_id,
        public_key_cose: cose_key_bytes,
        aaguid,
        counter,
        attestation_verified,
    })
}

/// Result of packed attestation verification with x5c chain.
#[derive(Debug)]
pub struct PackedAttestationResult {
    /// Whether the attestation chain was cryptographically verified.
    pub attestation_verified: bool,
    /// AAGUID extracted from the x5c leaf certificate.
    pub cert_aaguid: Option<String>,
}

/// Verify a packed attestation statement.
///
/// When x5c is present: validates the certificate chain against pinned roots,
/// verifies the attestation signature using the leaf certificate's public key,
/// and extracts AAGUID from the leaf certificate.
///
/// When x5c is absent (self-attestation): verifies the signature using the
/// credential's own public key.
///
/// Returns `Some(PackedAttestationResult)` when x5c was validated,
/// `None` for self-attestation (signature-only).
fn verify_packed_attestation<V: CoseVerifier>(
    stmt_map: &[(ciborium::Value, ciborium::Value)],
    auth_data_bytes: &[u8],
    client_data_json: &[u8],
    cose_key_bytes: &[u8],
    auth_data_aaguid: Option<&str>,
    verifier: &V,
) -> Result<Option<PackedAttestationResult>, VerifyError> {
    // Extract x5c certificate chain if present
    let x5c_certs = extract_x5c_certs(stmt_map);

    if let Some(certs) = x5c_certs {
        // Full attestation with x5c certificate chain

        // Build signed data: authData || SHA-256(clientDataJSON)
        let client_data_hash = digest::digest(&SHA256, client_data_json);
        let mut signed_data = Vec::with_capacity(auth_data_bytes.len().saturating_add(32));
        signed_data.extend_from_slice(auth_data_bytes);
        signed_data.extend_from_slice(client_data_hash.as_ref());

        // Verify attestation signature using the leaf cert's public key
        let sig = cbor_map_get_bytes_by_text(stmt_map, "sig")?;
        verify_attestation_sig_with_leaf_cert(
            certs.first().ok_or_else(|| {
                VerifyError::AttestationChainInvalid("x5c array is empty".to_string())
            })?,
            &signed_data,
            &sig,
        )?;

        // Validate the certificate chain against pinned Yubico roots
        let chain_result =
            super::attestation_chain::validate_attestation_chain(&certs, auth_data_aaguid)
                .map_err(|e| VerifyError::AttestationChainInvalid(e.to_string()))?;

        tracing::info!(
            attestation_verified = true,
            cert_aaguid = ?chain_result.cert_aaguid,
            "x5c attestation chain validated"
        );

        return Ok(Some(PackedAttestationResult {
            attestation_verified: true,
            cert_aaguid: chain_result.cert_aaguid,
        }));
    }

    // Self-attestation: extract sig from attStmt
    let sig = cbor_map_get_bytes_by_text(stmt_map, "sig")?;

    // Build signed data: authData || SHA-256(clientDataJSON)
    let client_data_hash = digest::digest(&SHA256, client_data_json);
    let mut signed_data = Vec::with_capacity(auth_data_bytes.len().saturating_add(32));
    signed_data.extend_from_slice(auth_data_bytes);
    signed_data.extend_from_slice(client_data_hash.as_ref());

    // Verify signature using the credential's own public key (self-attestation)
    verifier.verify(cose_key_bytes, &signed_data, &sig)?;
    Ok(None)
}

/// Extract x5c DER certificate arrays from a CBOR attStmt map.
fn extract_x5c_certs(stmt_map: &[(ciborium::Value, ciborium::Value)]) -> Option<Vec<Vec<u8>>> {
    for (k, v) in stmt_map {
        if let ciborium::Value::Text(s) = k
            && s == "x5c"
            && let ciborium::Value::Array(arr) = v
        {
            let certs: Vec<Vec<u8>> = arr
                .iter()
                .filter_map(|item| {
                    if let ciborium::Value::Bytes(bytes) = item {
                        Some(bytes.clone())
                    } else {
                        None
                    }
                })
                .collect();
            if certs.is_empty() {
                return None;
            }
            return Some(certs);
        }
    }
    None
}

/// Verify the attestation signature using the leaf certificate's public key.
///
/// Parses the DER certificate to extract the public key, determines the
/// algorithm, and verifies the signature.
fn verify_attestation_sig_with_leaf_cert(
    leaf_der: &[u8],
    message: &[u8],
    sig: &[u8],
) -> Result<(), VerifyError> {
    let cert = x509_cert::Certificate::from_der(leaf_der).map_err(|e| {
        VerifyError::AttestationChainInvalid(format!("Failed to parse leaf cert: {e}"))
    })?;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pk_bytes = spki.subject_public_key.raw_bytes();

    // Determine algorithm from the certificate's public key algorithm OID
    let pk_alg_oid = spki.algorithm.oid;

    // EC public key OID: 1.2.840.10045.2.1
    const EC_PUBLIC_KEY: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    // RSA encryption OID: 1.2.840.113549.1.1.1
    const RSA_ENCRYPTION: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

    if pk_alg_oid == EC_PUBLIC_KEY {
        let pk = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, pk_bytes);
        pk.verify(message, sig).map_err(|e| {
            tracing::warn!("Leaf cert ECDSA verification failed: {e}");
            VerifyError::SignatureInvalid
        })
    } else if pk_alg_oid == RSA_ENCRYPTION {
        let pk =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, pk_bytes);
        pk.verify(message, sig).map_err(|e| {
            tracing::warn!("Leaf cert RSA verification failed: {e}");
            VerifyError::SignatureInvalid
        })
    } else {
        Err(VerifyError::AttestationChainInvalid(format!(
            "Unsupported leaf cert key algorithm: {pk_alg_oid}"
        )))
    }
}

/// Get a byte string from a CBOR map by text key.
fn cbor_map_get_bytes(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Vec<u8>, VerifyError> {
    for (k, v) in map {
        if let ciborium::Value::Text(s) = k
            && s == key
            && let ciborium::Value::Bytes(bytes) = v
        {
            return Ok(bytes.clone());
        }
    }
    Err(VerifyError::InvalidClientData(format!(
        "Missing field '{key}' in attestation object"
    )))
}

/// Get a text string from a CBOR map by text key.
fn cbor_map_get_text(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<String, VerifyError> {
    for (k, v) in map {
        if let ciborium::Value::Text(s) = k
            && s == key
            && let ciborium::Value::Text(text) = v
        {
            return Ok(text.clone());
        }
    }
    Err(VerifyError::InvalidClientData(format!(
        "Missing field '{key}' in attestation object"
    )))
}

/// Get a map value from a CBOR map by text key.
fn cbor_map_get_map<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a [(ciborium::Value, ciborium::Value)]> {
    for (k, v) in map {
        if let ciborium::Value::Text(s) = k
            && s == key
            && let ciborium::Value::Map(m) = v
        {
            return Some(m.as_slice());
        }
    }
    None
}

/// Get a byte string from a CBOR map where keys are text strings.
fn cbor_map_get_bytes_by_text(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Vec<u8>, VerifyError> {
    for (k, v) in map {
        if let ciborium::Value::Text(s) = k
            && s == key
            && let ciborium::Value::Bytes(bytes) = v
        {
            return Ok(bytes.clone());
        }
    }
    Err(VerifyError::InvalidClientData(format!(
        "Missing field '{key}' in attestation statement"
    )))
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
    let mut point = Vec::with_capacity(x.len().saturating_add(y.len()).saturating_add(1));
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);

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
#[expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
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
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
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
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
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

    /// Build a registration-style auth_data: rpIdHash(32) + flags(1) +
    /// counter(4) + aaguid(16) + credIdLen(2) + credId + cose_key.
    fn make_registration_auth_data(
        rp_id: &str,
        aaguid: [u8; 16],
        credential_id: &[u8],
        cose_key: &[u8],
    ) -> Vec<u8> {
        let mut auth_data = make_auth_data(rp_id, 0x45, 0); // UP + UV + AT
        auth_data.extend_from_slice(&aaguid);
        let cred_id_len = u16::try_from(credential_id.len()).unwrap();
        auth_data.extend_from_slice(&cred_id_len.to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(cose_key);
        auth_data
    }

    /// Wrap auth_data into a CBOR attestation object with fmt = "none".
    fn make_attestation_object_none(auth_data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let value = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".to_string()),
                ciborium::Value::Text("none".to_string()),
            ),
            (
                ciborium::Value::Text("attStmt".to_string()),
                ciborium::Value::Map(vec![]),
            ),
            (
                ciborium::Value::Text("authData".to_string()),
                ciborium::Value::Bytes(auth_data.to_vec()),
            ),
        ]);
        ciborium::into_writer(&value, &mut buf).unwrap();
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
            &AssertionParams {
                authenticator_data: &short_auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: "example.com", // Expected RP ID doesn't match auth_data
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: true, // Require UV
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false, // Don't require UV
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 4, // stored counter
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 5, // Same as auth_data counter
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 5, // stored counter is higher
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0, // stored counter also 0
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0, // Initial stored counter
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: u32::MAX - 1, // stored counter just below max
                require_user_verification: false,
                allow_localhost_origin: true,
            },
            &verifier,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().counter, u32::MAX);
    }

    #[test]
    fn test_counter_regression_to_zero_rejected() {
        // A credential that previously reported a nonzero counter must never
        // regress to zero: that is unambiguous evidence of a cloned or forged
        // authenticator (WebAuthn L2 §6.1.1). Regression test for the
        // clone-detection bypass where `counter == 0` skipped the check.
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "example.com";
        let auth_data = make_auth_data(rp_id, 0x05, 0); // counter regressed to 0
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_with_verifier(
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 5, // stored counter was nonzero
                require_user_verification: false,
                allow_localhost_origin: true,
            },
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::CounterNotIncreasing)));
    }

    // =========================================================================
    // Origin Relaxation Gating Tests (P2.2)
    // =========================================================================

    #[test]
    fn test_localhost_origin_relaxation_allowed_when_enabled() {
        // With relaxation enabled (development, no TLS), a loopback origin
        // variation (localhost vs 127.0.0.1, differing ports) is tolerated.
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "localhost";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "http://127.0.0.1:9000");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_inner(
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "http://localhost:8080",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
            &verifier,
        );
        assert!(result.is_ok(), "expected ok, got {result:?}");
    }

    #[test]
    fn test_localhost_origin_relaxation_rejected_when_disabled() {
        // With relaxation disabled (production), the same loopback origin
        // variation is rejected: production must never weaken origin binding,
        // even on a misconfigured loopback rp_id.
        let verifier = TestCoseVerifier::always_succeed();
        let rp_id = "localhost";
        let auth_data = make_auth_data(rp_id, 0x05, 1);
        let client_data =
            make_client_data_json("webauthn.get", "test-challenge", "http://127.0.0.1:9000");
        let cose_key = make_eddsa_cose_key(&[0u8; 32]);

        let result = verify_assertion_inner(
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "http://localhost:8080",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: false,
            },
            &verifier,
        );
        assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: invalid_json,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "expected-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://localhost:8080",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "http://host.docker.internal:3000",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "http://localhost:3000",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "http://localhost:3000",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "http://localhost:3000",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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
            &AssertionParams {
                authenticator_data: &auth_data,
                client_data_json: &client_data,
                signature: &[0u8; 64],
                public_key_cose: &cose_key,
                expected_rp_id: rp_id,
                expected_challenge: "test-challenge",
                expected_origin: "https://example.com",
                stored_counter: 0,
                require_user_verification: false,
                allow_localhost_origin: true,
            },
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

    // =========================================================================
    // Registration Attested-Credential-Data Parsing Tests
    // =========================================================================

    #[test]
    fn test_verify_registration_empty_cose_key_returns_invalid_cose_key() {
        let rp_id = "example.com";
        let challenge = "challenge-bytes";
        let origin = "https://example.com";
        let auth_data = make_registration_auth_data(rp_id, [1; 16], b"cred-id", &[]);
        let attestation = make_attestation_object_none(&auth_data);
        let client_data = make_client_data_json("webauthn.create", challenge, origin);

        let err = verify_registration_with_verifier(
            &attestation,
            &client_data,
            rp_id,
            challenge,
            origin,
            true,
            &TestCoseVerifier::always_succeed(),
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::InvalidCoseKey(_)), "got {err:?}");
    }

    #[test]
    fn test_verify_registration_truncated_attested_data_returns_invalid_auth_data_length() {
        let rp_id = "example.com";
        let challenge = "challenge-bytes";
        let origin = "https://example.com";
        // rpIdHash(32) + flags(1) + counter(4) + aaguid(16) + 1 byte — one byte
        // short of a complete credIdLen field.
        let mut auth_data = make_auth_data(rp_id, 0x45, 0);
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.push(0);
        let attestation = make_attestation_object_none(&auth_data);
        let client_data = make_client_data_json("webauthn.create", challenge, origin);

        let err = verify_registration_with_verifier(
            &attestation,
            &client_data,
            rp_id,
            challenge,
            origin,
            true,
            &TestCoseVerifier::always_succeed(),
        )
        .unwrap_err();

        assert!(
            matches!(err, VerifyError::InvalidAuthDataLength),
            "got {err:?}"
        );
    }
}
