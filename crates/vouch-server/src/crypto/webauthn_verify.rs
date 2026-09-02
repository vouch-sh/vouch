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
//! # Inputs are untyped byte slices
//!
//! Verification takes `&[u8]`. Every caller now holds
//! [`vouch_common::encoding::Encoded<T, E>`], whose compile-time markers keep a
//! credential ID from being passed where a signature belongs, but they unwrap
//! to bytes before calling in — this module never sees the marker. Extending
//! the typed representation inward would mean threading the markers through
//! `CoseVerifier` and the assertion structs as well.

use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::signature::{self, UnparsedPublicKey};
use der::Decode;

use super::attestation_chain::AttestationProof;
use super::{cose, oid};
use thiserror::Error;
use vouch_common::protocol;
use webauthn_rs::prelude::Passkey;

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

/// Whether loopback origin variations are tolerated when comparing the
/// client-data origin against the expected one.
///
/// Lives here because the crypto layer consumes it and may not import
/// `ServerConfig`; the conversion from configuration is in `config.rs`, which
/// is a composition root rather than a layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginPolicy {
    /// An origin mismatch is always rejected.
    Strict,
    /// Tolerate loopback variations (`localhost` vs `127.0.0.1`, port
    /// differences). Development only.
    AllowLoopbackVariations,
}

impl OriginPolicy {
    /// Whether loopback variations are tolerated.
    #[must_use]
    pub fn allows_loopback_variation(self) -> bool {
        matches!(self, Self::AllowLoopbackVariations)
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

    #[error("Attestation statement declares alg {declared}, but {subject} is {actual}")]
    AttestationAlgMismatch {
        declared: i64,
        subject: &'static str,
        actual: String,
    },
}

/// The instant a WebAuthn ceremony verified — the `auth_time` claim's value
/// (OIDC Core §2: "Time when the End-User authentication occurred").
///
/// The inner value is stamped only here, at the moment a ceremony completes,
/// and there is no public constructor. Holding one is therefore evidence
/// that a ceremony happened at that instant, which is what stops a later
/// request — a device-code poll, say — from passing off its own clock
/// reading as an authentication time (issue #1166).
#[derive(Debug, Clone, Copy)]
pub struct AuthTime(i64);

impl AuthTime {
    /// Stamp the current instant. Private: every public path to an
    /// `AuthTime` runs through a completed ceremony.
    fn stamp() -> Self {
        Self(jiff::Timestamp::now().as_second())
    }

    /// The instant a `webauthn-rs` registration ceremony completed.
    ///
    /// Registration runs through `finish_passkey_registration`, which yields
    /// a [`Passkey`] only for a verified ceremony — so holding one is the
    /// same evidence [`VerificationResult`] carries for assertions.
    #[must_use]
    pub fn from_passkey_registration(_verified: &Passkey) -> Self {
        Self::stamp()
    }

    /// Unix seconds, for the `auth_time` claim and for storage.
    #[must_use]
    pub fn as_second(self) -> i64 {
        self.0
    }

    /// Build an `AuthTime` for a specific instant in tests, standing in for
    /// a ceremony that cannot be run without hardware.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn for_test(unix_seconds: i64) -> Self {
        Self(unix_seconds)
    }
}

/// Result of successful assertion verification.
///
/// The `verified_at` field has no public constructor, so this struct cannot
/// be built outside this module — a caller holding one has been through
/// [`verify_assertion`].
#[derive(Debug)]
pub struct VerificationResult {
    /// The new counter value from the authenticator.
    pub counter: u32,
    /// Whether user verification was performed.
    pub user_verified: bool,
    /// When this assertion verified.
    pub verified_at: AuthTime,
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
    /// Whether loopback origin variations are tolerated.
    pub origin_policy: OriginPolicy,
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

/// Verify the client-data origin for both assertion and registration flows.
///
/// `origin_policy` gates the loopback origin-variation relaxation
/// (e.g. `localhost` ↔ `127.0.0.1`): it must be `true` only in development
/// (no TLS). Production threads `false` so an origin mismatch is always
/// rejected even on a misconfigured loopback `rp_id`.
///
/// Note: the relaxation intentionally does not compare ports — the server
/// may listen on one port while the browser constructs an origin with a
/// different one.
fn verify_origin(
    presented_origin: &str,
    expected_origin: &str,
    origin_policy: OriginPolicy,
    flow: &str,
) -> Result<(), VerifyError> {
    if presented_origin == expected_origin {
        return Ok(());
    }

    let expected_is_local = url::Url::parse(expected_origin)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .is_some_and(|h| vouch_common::is_loopback_host(&h));
    let origin_is_local = url::Url::parse(presented_origin)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .is_some_and(|h| vouch_common::is_loopback_host(&h));

    if origin_policy.allows_loopback_variation() && expected_is_local && origin_is_local {
        tracing::warn!(
            target: "security",
            flow,
            expected = %expected_origin,
            actual = %presented_origin,
            "Allowing localhost origin variation (development mode) -- \
             this relaxation is disabled when TLS is configured"
        );
        Ok(())
    } else {
        Err(VerifyError::InvalidOrigin)
    }
}

/// Core WebAuthn assertion verification.
///
/// `params.origin_policy` gates the loopback origin-variation
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
        origin_policy,
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
    // WebAuthn Level 2 Section 6.1.1: "In subsequent authenticatorGetAssertion
    // operations, the Relying Party compares the stored signature counter
    // value with the new signCount value returned in the assertion's
    // authenticator data. If either is non-zero, and the new signCount value
    // is less than or equal to the stored value, a cloned authenticator may
    // exist, or the authenticator may be malfunctioning."
    //
    // Rejecting is our choice, not the specification's. Section 7.2 leaves it
    // open: "Whether the Relying Party updates storedSignCount in this case,
    // or not, or fails the authentication ceremony or not, is Relying
    // Party-specific." A malfunctioning authenticator is as consistent with
    // the observation as a cloned one; we decline to distinguish them and fail
    // closed, because this is a hardware-backed credential system where a
    // counter regression should stop the ceremony rather than feed a risk
    // score.
    //
    // The condition below reads `stored_counter != 0` where the specification
    // says "either is non-zero". The two agree: the only case they treat
    // differently is a nonzero presented counter against a zero stored
    // counter, which cannot also satisfy `counter <= stored_counter`.
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
    if client_data.type_ != protocol::CLIENT_DATA_TYPE_GET {
        return Err(VerifyError::InvalidClientData(format!(
            "Expected type '{}', got '{}'",
            protocol::CLIENT_DATA_TYPE_GET,
            client_data.type_
        )));
    }

    // Verify challenge
    if client_data.challenge != expected_challenge {
        return Err(VerifyError::ChallengeMismatch);
    }

    // Verify origin
    verify_origin(
        &client_data.origin,
        expected_origin,
        origin_policy,
        "assertion",
    )?;

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
        verified_at: AuthTime::stamp(),
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
    /// The verified attestation chain, when one was validated.
    ///
    /// `Some` is only obtainable from `validate_attestation_chain`, so its
    /// presence is itself the evidence that a chain was checked.
    pub attestation: Option<AttestationProof>,
}

/// Parameters for WebAuthn registration (attestation) verification
/// (WebAuthn Level 2 §7.1).
///
/// Named fields prevent the positional byte-slice/string swaps an 8-argument
/// signature would invite.
#[derive(Debug, Clone, Copy)]
pub struct RegistrationParams<'a> {
    /// Raw attestation object bytes (CBOR).
    pub attestation_object: &'a [u8],
    /// Raw client data JSON bytes.
    pub client_data_json: &'a [u8],
    /// The expected relying party ID.
    pub expected_rp_id: &'a str,
    /// The expected challenge (base64url encoded).
    pub expected_challenge: &'a str,
    /// The expected origin URL.
    pub expected_origin: &'a str,
    /// Whether to require the UV flag.
    pub require_user_verification: bool,
    /// Whether loopback origin variations are tolerated.
    pub origin_policy: OriginPolicy,
}

/// Verify a WebAuthn registration (attestation) response.
///
/// Implements WebAuthn Level 2 Section 7.1 verification steps:
/// 1. Parse `attestation_object` CBOR
/// 2. Verify `authData`: RP ID hash, flags (UP+UV+AT), extract credential
/// 3. Parse `clientDataJSON`: verify type=webauthn.create, challenge, origin
/// 4. For `fmt="packed"`: verify the attestation signature (self or x5c)
/// 5. For `fmt="fido-u2f"`: verify `attStmt.sig` over `0x00 || rpIdHash ||
///    clientDataHash || credentialId || publicKeyU2F` with the leaf cert
/// 6. For `fmt="none"`: accept (no attestation statement)
///
/// Returns the server-verified credential ID, public key, and AAGUID.
pub fn verify_registration(
    params: &RegistrationParams<'_>,
) -> Result<RegistrationVerificationResult, VerifyError> {
    verify_registration_with_verifier(params, &RealCoseVerifier)
}

/// Verify a WebAuthn registration with a custom COSE verifier.
///
/// This is the testable version of [`verify_registration`].
#[expect(
    clippy::too_many_lines,
    reason = "single-pass WebAuthn L2 §7.1 registration verification; \
              attestation-format dispatch is the bulk of the body"
)]
pub fn verify_registration_with_verifier<V: CoseVerifier>(
    params: &RegistrationParams<'_>,
    verifier: &V,
) -> Result<RegistrationVerificationResult, VerifyError> {
    let &RegistrationParams {
        attestation_object,
        client_data_json,
        expected_rp_id,
        expected_challenge,
        expected_origin,
        require_user_verification,
        origin_policy,
    } = params;

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

    if client_data.type_ != protocol::CLIENT_DATA_TYPE_CREATE {
        return Err(VerifyError::InvalidClientData(format!(
            "Expected type '{}', got '{}'",
            protocol::CLIENT_DATA_TYPE_CREATE,
            client_data.type_
        )));
    }

    if client_data.challenge != expected_challenge {
        return Err(VerifyError::ChallengeMismatch);
    }

    // Verify origin (same localhost relaxation gating as assertion)
    verify_origin(
        &client_data.origin,
        expected_origin,
        origin_policy,
        "registration",
    )?;

    // 4. Verify attestation statement based on format
    let mut attestation = None;

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
                    // If the chain provided a cert AAGUID, prefer it
                    if aaguid.is_none() {
                        aaguid = result.cert_aaguid().map(str::to_owned);
                    }
                    attestation = Some(result);
                }
            }
            // No attStmt with packed format is invalid, but we're lenient
            // since the COSE key is verified through usage anyway
        }
        "fido-u2f" => {
            // FIDO U2F attestation (WebAuthn Level 2 Section 8.3). The signature
            // is over `0x00 || rpIdHash || clientDataHash || credentialId ||
            // publicKeyU2F` (not packed's `authData || clientDataHash`), with
            // `alg` fixed to ES256 — see `verify_fido_u2f_attestation`.
            //
            // Verifying `attStmt.sig` is what binds the credential to the
            // captured certificate; without it the chokepoint's `cert_aaguid`
            // is unearned (issue #1111 forgery against `fido-u2f`). The browser
            // path is safe via webauthn-rs's `verify_fidou2f_attestation`; this
            // arm mirrors it so both paths reject the same inputs. The chain
            // itself is validated by the chokepoint, which owns chain policy.
            let stmt_map = att_stmt.ok_or_else(|| {
                VerifyError::InvalidClientData(
                    "fido-u2f attestation requires an attStmt".to_string(),
                )
            })?;
            verify_fido_u2f_attestation(
                stmt_map,
                &auth_data_bytes,
                client_data_json,
                &cose_key_bytes,
                &credential_id,
            )?;

            // The authData AAGUID is not signed by a fido-u2f statement (CTAP
            // 2.0 §7.2: AAGUID "Initialized with all zeros"), so it carries no
            // model identity; the model comes from the certificate via the
            // chokepoint.
            aaguid = None;
        }
        other => {
            // No verification procedure is implemented for these formats. The
            // authData AAGUID is signed by nothing here, so it is discarded
            // (defense-in-depth); the credential is verified later via
            // assertion. This is not acceptance: the registration chokepoint
            // (`validate_registration_attestation`) runs `validate_hardware_attestation` afterwards
            // and is default-deny — these formats are rejected there. The
            // historical note about CTAP 2.0 §7.2's all-zero AAGUID lives on
            // the `fido-u2f` arm, which is the only other hardware format and
            // has its own verifier now.
            if aaguid.is_some() {
                tracing::warn!(
                    fmt = %other,
                    "Discarding AAGUID from an attestation format that is not verified"
                );
                aaguid = None;
            } else {
                tracing::debug!(fmt = %other, "Accepting unverified attestation format");
            }
        }
    }

    Ok(RegistrationVerificationResult {
        credential_id,
        public_key_cose: cose_key_bytes,
        aaguid,
        counter,
        attestation,
    })
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
) -> Result<Option<AttestationProof>, VerifyError> {
    // Extract x5c certificate chain if present
    let x5c_certs = extract_x5c_certs(stmt_map);

    // WebAuthn Level 2 Section 8.2 gives `alg` as a mandatory member of both
    // arms of the packed CDDL, and step 1 of the verification procedure is
    // "Verify that attStmt is valid CBOR conforming to the syntax defined
    // above", so a statement without it is rejected here rather than verified
    // against an algorithm nobody declared.
    let declared_alg = cbor_map_get_int_by_text(stmt_map, "alg")?;

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
            declared_alg,
        )?;

        // Validate the certificate chain against pinned Yubico roots
        let chain_result =
            super::attestation_chain::validate_attestation_chain(&certs, auth_data_aaguid)
                .map_err(|e| VerifyError::AttestationChainInvalid(e.to_string()))?;

        tracing::info!(
            attestation_verified = true,
            cert_aaguid = ?chain_result.cert_aaguid(),
            "x5c attestation chain validated"
        );

        return Ok(Some(chain_result));
    }

    // Self-attestation: extract sig from attStmt
    let sig = cbor_map_get_bytes_by_text(stmt_map, "sig")?;

    // WebAuthn Level 2 Section 8.2, verification procedure step 3: "If x5c is
    // not present, self attestation is in use." Its first sub-step is
    // "Validate that alg matches the algorithm of the credentialPublicKey in
    // authenticatorData."
    let credential_alg = cose_key_alg(cose_key_bytes)?;
    if declared_alg != credential_alg {
        return Err(VerifyError::AttestationAlgMismatch {
            declared: declared_alg,
            subject: "the credential public key",
            actual: credential_alg.to_string(),
        });
    }

    // Build signed data: authData || SHA-256(clientDataJSON)
    let client_data_hash = digest::digest(&SHA256, client_data_json);
    let mut signed_data = Vec::with_capacity(auth_data_bytes.len().saturating_add(32));
    signed_data.extend_from_slice(auth_data_bytes);
    signed_data.extend_from_slice(client_data_hash.as_ref());

    // Verify signature using the credential's own public key (self-attestation)
    verifier.verify(cose_key_bytes, &signed_data, &sig)?;
    Ok(None)
}

/// Verify a FIDO U2F attestation statement (WebAuthn Level 2 Section 8.3).
///
/// Verifies `attStmt.sig` over the concatenation of `0x00 || rpIdHash ||
/// clientDataHash || credentialId || publicKeyU2F` using the leaf attestation
/// certificate's public key, with the algorithm fixed to ES256 (ECDSA P-256
/// SHA-256) per the U2F protocol.
///
/// This is what binds the credential public key in `authData` to the
/// attestation certificate — the property the registration chokepoint relies
/// on when it stamps the certificate's AAGUID onto the authenticator row. The
/// certificate chain itself is validated by the chokepoint; this function
/// performs only the signature check the chokepoint does not.
fn verify_fido_u2f_attestation(
    stmt_map: &[(ciborium::Value, ciborium::Value)],
    auth_data_bytes: &[u8],
    client_data_json: &[u8],
    cose_key_bytes: &[u8],
    credential_id: &[u8],
) -> Result<(), VerifyError> {
    let x5c_certs = extract_x5c_certs(stmt_map).ok_or_else(|| {
        VerifyError::AttestationChainInvalid(
            "fido-u2f attestation requires an x5c certificate chain".to_string(),
        )
    })?;

    // WebAuthn Level 2 Section 8.3, verification procedure step 1: "Verify
    // that x5c has exactly one element, the attestation certificate." A
    // conforming U2F statement carries only the leaf; a chain, if present, is
    // not a U2F statement and is rejected here.
    if x5c_certs.len() != 1 {
        return Err(VerifyError::AttestationChainInvalid(format!(
            "fido-u2f x5c must have exactly one element (the leaf attestation \
             certificate), got {}",
            x5c_certs.len()
        )));
    }
    let leaf_der = x5c_certs
        .first()
        .ok_or_else(|| VerifyError::AttestationChainInvalid("fido-u2f x5c is empty".to_string()))?;

    // FIDO U2F does not declare `alg` in the statement (CDDL has only `x5c`
    // and `sig`); the algorithm is fixed by the protocol to ES256, so `sig`
    // is the only attStmt member read here.
    let sig = cbor_map_get_bytes_by_text(stmt_map, "sig")?;

    // publicKeyU2F: the credential public key in SEC1 uncompressed form
    // (0x04 || x || y), per Section 8.3. U2F authenticators register EC2/P-256
    // keys exclusively, so the credential key is required to be one.
    let public_key_u2f = cose_key_to_sec1_uncompressed(cose_key_bytes)?;

    // Build the verification data per Section 8.3:
    // 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F.
    let rp_id_hash = auth_data_bytes
        .get(0..32)
        .ok_or(VerifyError::InvalidAuthDataLength)?;
    let client_data_hash = digest::digest(&SHA256, client_data_json);
    let verification_data = build_fido_u2f_verification_data(
        rp_id_hash,
        client_data_hash.as_ref(),
        credential_id,
        &public_key_u2f,
    );

    // Verify the signature using the leaf certificate's public key. FIDO U2F
    // fixes the algorithm to ES256; `verify_attestation_sig_with_leaf_cert`
    // additionally requires the certificate's public key OID to be
    // `id-ecPublicKey`, matching the P-256 key a U2F attestation certificate
    // carries.
    verify_attestation_sig_with_leaf_cert(leaf_der, &verification_data, &sig, cose::alg::ES256)?;

    tracing::info!(
        attestation_verified = true,
        "fido-u2f attestation signature verified"
    );
    Ok(())
}

/// Build the FIDO U2F attestation signature verification data.
///
/// WebAuthn Level 2 Section 8.3: "Let verificationData be the concatenation of
/// (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)."
fn build_fido_u2f_verification_data(
    rp_id_hash: &[u8],
    client_data_hash: &[u8],
    credential_id: &[u8],
    public_key_u2f: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(
        1usize
            .saturating_add(rp_id_hash.len())
            .saturating_add(client_data_hash.len())
            .saturating_add(credential_id.len())
            .saturating_add(public_key_u2f.len()),
    );
    data.push(0x00);
    data.extend_from_slice(rp_id_hash);
    data.extend_from_slice(client_data_hash);
    data.extend_from_slice(credential_id);
    data.extend_from_slice(public_key_u2f);
    data
}

/// Convert a COSE-encoded credential public key to the SEC1 uncompressed
/// point encoding `0x04 || x || y` required by FIDO U2F attestation
/// verification (WebAuthn Level 2 Section 8.3: `publicKeyU2F`).
///
/// FIDO U2F authenticators register EC2/P-256 keys exclusively, so the
/// credential key is required to be one; any other key type or curve is
/// rejected as a non-conforming U2F registration rather than fed to a
/// verifier it does not fit.
fn cose_key_to_sec1_uncompressed(cose_key: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let parsed: ciborium::Value =
        ciborium::from_reader(cose_key).map_err(|e| VerifyError::InvalidCoseKey(e.to_string()))?;
    let ciborium::Value::Map(map) = parsed else {
        return Err(VerifyError::InvalidCoseKey("Expected COSE map".to_string()));
    };

    let kty = get_cose_int(&map, 1)?;
    if kty != cose::kty::EC2 {
        return Err(VerifyError::InvalidCoseKey(format!(
            "fido-u2f requires an EC2 credential key, got kty {kty}"
        )));
    }

    let crv = get_cose_int(&map, -1)?;
    if crv != cose::curve::P256 {
        return Err(VerifyError::InvalidCoseKey(format!(
            "fido-u2f requires a P-256 credential key, got crv {crv}"
        )));
    }

    let x = get_cose_bytes(&map, -2)?;
    let y = get_cose_bytes(&map, -3)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(VerifyError::InvalidCoseKey(
            "fido-u2f requires 32-byte P-256 coordinates".to_string(),
        ));
    }

    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Ok(point)
}

/// Read the `alg` label (3) of a CBOR-encoded COSE key.
fn cose_key_alg(cose_key: &[u8]) -> Result<i64, VerifyError> {
    let parsed: ciborium::Value =
        ciborium::from_reader(cose_key).map_err(|e| VerifyError::InvalidCoseKey(e.to_string()))?;
    let ciborium::Value::Map(map) = parsed else {
        return Err(VerifyError::InvalidCoseKey("Expected COSE map".to_string()));
    };
    get_cose_int(&map, 3)
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
///
/// WebAuthn Level 2 Section 8.2, verification procedure step 2: "Verify that
/// sig is a valid signature over the concatenation of authenticatorData and
/// clientDataHash using the attestation public key in attestnCert with the
/// algorithm specified in alg." `declared_alg` is that `alg`; a value naming a
/// different key family than attestnCert carries is rejected rather than
/// silently overridden by the certificate.
fn verify_attestation_sig_with_leaf_cert(
    leaf_der: &[u8],
    message: &[u8],
    sig: &[u8],
    declared_alg: i64,
) -> Result<(), VerifyError> {
    let cert = x509_cert::Certificate::from_der(leaf_der).map_err(|e| {
        VerifyError::AttestationChainInvalid(format!("Failed to parse leaf cert: {e}"))
    })?;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pk_bytes = spki.subject_public_key.raw_bytes();

    // Determine algorithm from the certificate's public key algorithm OID
    let pk_alg_oid = spki.algorithm.oid;

    let expected_oid = match declared_alg {
        cose::alg::ES256 => oid::public_key::EC,
        cose::alg::RS256 => oid::public_key::RSA,
        other => return Err(VerifyError::UnsupportedAlgorithm(other)),
    };
    if pk_alg_oid != expected_oid {
        return Err(VerifyError::AttestationAlgMismatch {
            declared: declared_alg,
            subject: "the attestation certificate key",
            actual: pk_alg_oid.to_string(),
        });
    }

    if pk_alg_oid == oid::public_key::EC {
        let pk = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, pk_bytes);
        pk.verify(message, sig).map_err(|e| {
            tracing::warn!("Leaf cert ECDSA verification failed: {e}");
            VerifyError::SignatureInvalid
        })
    } else if pk_alg_oid == oid::public_key::RSA {
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

/// Get an integer from a CBOR map by text key.
fn cbor_map_get_int_by_text(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<i64, VerifyError> {
    for (k, v) in map {
        if let ciborium::Value::Text(s) = k
            && s == key
            && let ciborium::Value::Integer(i) = v
        {
            let value: i128 = (*i).into();
            return i64::try_from(value).map_err(|_| {
                VerifyError::InvalidClientData(format!("Field '{key}' is out of range"))
            });
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

    // Curve (crv) - label -1. Read non-fatally: RSA has no curve (its -1 label
    // holds the modulus), and an absent or non-integer label must not preempt
    // the algorithm check below, which gives the more useful diagnosis.
    let crv = match kty {
        cose::kty::EC2 | cose::kty::OKP => get_cose_int(&map, -1).ok(),
        _ => None,
    };

    // RFC 9053 Section 2.1 requires implementations to check the key type and
    // curve, not just the algorithm. Resolving the whole triple here means a
    // key whose labels disagree is rejected at the boundary with a message
    // naming the mismatch, rather than reaching a verifier it does not fit.
    match cose::VerifiableCoseKey::from_triple(kty, alg, crv) {
        Ok(cose::VerifiableCoseKey::Es256) => verify_es256(&map, message, signature),
        Ok(cose::VerifiableCoseKey::Rs256) => verify_rs256(&map, message, signature),
        Ok(cose::VerifiableCoseKey::Ed25519) => verify_eddsa(&map, message, signature),
        Err(cose::CoseKeyError::UnsupportedAlgorithm(alg)) => {
            Err(VerifyError::UnsupportedAlgorithm(alg))
        }
        Err(e) => Err(VerifyError::InvalidCoseKey(e.to_string())),
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

    // WebAuthn Level 2 Section 6.5.5: "For COSEAlgorithmIdentifier -7 (ES256),
    // and other ECDSA-based algorithms, the sig value MUST be encoded as an
    // ASN.1 DER Ecdsa-Sig-Value, as defined in [RFC3279] section 2.2.3."
    //
    // That covers both entry points. The adjacent Note records that CTAP2
    // authenticators emit the same encoding as CTAP1/U2F "for consistency
    // reasons", and browsers pass the authenticator's signature through
    // unchanged. There is therefore no conformant client that sends a raw
    // r||s pair, and accepting one on the strength of its length would admit
    // an encoding the specification forbids.
    let public_key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &point);
    public_key.verify(message, signature).map_err(|e| {
        tracing::warn!("verify_es256: ASN1 verification failed: {e:?}");
        VerifyError::SignatureInvalid
    })
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
mod tests;
