// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Runtime validation contracts for FIDO2 data structures.
//!
//! This module provides validation functions that verify semantic correctness
//! of FIDO2 data at runtime. While the type system prevents mixing up different
//! semantic types, these contracts validate the internal structure of the data.
//!
//! # Error Handling
//!
//! All validation functions return `Result<(), ContractError>`. Using these
//! with `?` provides clear error messages for debugging interface mismatches.
//!
//! # Example
//!
//! ```rust,ignore
//! use vouch_tests::contracts::{validate_cose_key, validate_authenticator_data, validate_credential_id};
//!
//! // Validate a COSE key before using it for verification
//! fn verify_registration(public_key: &[u8], auth_data: &[u8], cred_id: &[u8]) -> anyhow::Result<()> {
//!     validate_cose_key(public_key)?;
//!     validate_authenticator_data(auth_data)?;
//!     validate_credential_id(cred_id)?;
//!     // ... proceed with verification
//!     Ok(())
//! }
//! ```

use thiserror::Error;
use vouch_common::protocol;

/// Errors from contract validation.
#[derive(Debug, Error)]
#[expect(
    clippy::enum_variant_names,
    reason = "every variant names the artifact that failed validation"
)]
pub enum ContractError {
    /// COSE key validation failed.
    #[error("Invalid COSE key: {0}")]
    InvalidCoseKey(String),

    /// Authenticator data validation failed.
    #[error("Invalid authenticator data: {0}")]
    InvalidAuthenticatorData(String),

    /// Credential ID validation failed.
    #[error("Invalid credential ID: {0}")]
    InvalidCredentialId(String),

    /// Challenge validation failed.
    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),

    /// Signature validation failed.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Client data JSON validation failed.
    #[error("Invalid client data JSON: {0}")]
    InvalidClientDataJson(String),

    /// Attestation object validation failed.
    #[error("Invalid attestation object: {0}")]
    InvalidAttestationObject(String),
}

/// Result type for contract validation.
pub type ContractResult<T> = Result<T, ContractError>;

// ============================================================================
// COSE Key Validation
// ============================================================================

/// COSE algorithm identifier for ES256 (ECDSA with P-256 and SHA-256).
pub const COSE_ALG_ES256: i64 = -7;

/// COSE algorithm identifier for EdDSA (Ed25519).
pub const COSE_ALG_EDDSA: i64 = -8;

/// COSE key type for EC2 (Elliptic Curve with x and y coordinates).
pub const COSE_KTY_EC2: i64 = 2;

/// COSE key type for OKP (Octet Key Pair, used for Ed25519).
pub const COSE_KTY_OKP: i64 = 1;

/// COSE curve identifier for P-256.
pub const COSE_CRV_P256: i64 = 1;

/// COSE curve identifier for Ed25519.
pub const COSE_CRV_ED25519: i64 = 6;

/// Validate a COSE public key structure.
///
/// This checks:
/// - Valid CBOR encoding
/// - Required key type (kty) field
/// - Required algorithm (alg) field
/// - Required curve-specific fields (x, y for EC2; x for OKP)
///
/// # Errors
///
/// Returns `ContractError::InvalidCoseKey` if validation fails.
pub fn validate_cose_key(data: &[u8]) -> ContractResult<()> {
    if data.is_empty() {
        return Err(ContractError::InvalidCoseKey("empty data".to_string()));
    }

    // Try to parse as CBOR
    let value: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| ContractError::InvalidCoseKey(format!("CBOR parse error: {e}")))?;

    // Must be a map
    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => return Err(ContractError::InvalidCoseKey("not a CBOR map".to_string())),
    };

    // Helper to get integer value from map
    let get_int = |key: i64| -> Option<i64> {
        for (k, v) in &map {
            if let ciborium::Value::Integer(i) = k {
                let key_val: i128 = (*i).into();
                if key_val == i128::from(key)
                    && let ciborium::Value::Integer(i) = v
                {
                    let val: i128 = (*i).into();
                    return i64::try_from(val).ok();
                }
            }
        }
        None
    };

    // Check for key type (kty, label 1)
    let kty = get_int(1)
        .ok_or_else(|| ContractError::InvalidCoseKey("missing kty (key type) field".to_string()))?;

    // Check for algorithm (alg, label 3)
    let alg = get_int(3).ok_or_else(|| {
        ContractError::InvalidCoseKey("missing alg (algorithm) field".to_string())
    })?;

    // Validate based on key type
    match kty {
        COSE_KTY_EC2 => {
            // EC2 keys need curve (-1), x (-2), and y (-3)
            let crv = get_int(-1);
            if crv.is_none() {
                return Err(ContractError::InvalidCoseKey(
                    "EC2 key missing crv (curve) field".to_string(),
                ));
            }

            // Check x and y are present (as byte strings)
            let has_x = map.iter().any(|(k, v)| {
                matches!(k, ciborium::Value::Integer(i) if i128::from(*i) == -2)
                    && matches!(v, ciborium::Value::Bytes(_))
            });
            let has_y = map.iter().any(|(k, v)| {
                matches!(k, ciborium::Value::Integer(i) if i128::from(*i) == -3)
                    && matches!(v, ciborium::Value::Bytes(_))
            });

            if !has_x {
                return Err(ContractError::InvalidCoseKey(
                    "EC2 key missing x coordinate".to_string(),
                ));
            }
            if !has_y {
                return Err(ContractError::InvalidCoseKey(
                    "EC2 key missing y coordinate".to_string(),
                ));
            }

            // Validate algorithm matches key type
            if alg != COSE_ALG_ES256 {
                return Err(ContractError::InvalidCoseKey(format!(
                    "EC2 key has unexpected algorithm {alg}, expected {COSE_ALG_ES256} (ES256)"
                )));
            }
        }
        COSE_KTY_OKP => {
            // OKP keys need curve (-1) and x (-2)
            let crv = get_int(-1);
            if crv.is_none() {
                return Err(ContractError::InvalidCoseKey(
                    "OKP key missing crv (curve) field".to_string(),
                ));
            }

            let has_x = map.iter().any(|(k, v)| {
                matches!(k, ciborium::Value::Integer(i) if i128::from(*i) == -2)
                    && matches!(v, ciborium::Value::Bytes(_))
            });

            if !has_x {
                return Err(ContractError::InvalidCoseKey(
                    "OKP key missing x coordinate".to_string(),
                ));
            }

            // Validate algorithm matches key type
            if alg != COSE_ALG_EDDSA {
                return Err(ContractError::InvalidCoseKey(format!(
                    "OKP key has unexpected algorithm {alg}, expected {COSE_ALG_EDDSA} (EdDSA)"
                )));
            }
        }
        _ => {
            return Err(ContractError::InvalidCoseKey(format!(
                "unsupported key type {kty}"
            )));
        }
    }

    Ok(())
}

// ============================================================================
// Authenticator Data Validation
// ============================================================================

/// Minimum length for authenticator data (RP ID hash + flags + counter).
pub const MIN_AUTH_DATA_LEN: usize = 37; // 32 + 1 + 4

/// Validate authenticator data structure.
///
/// This checks:
/// - Minimum length (37 bytes for RP ID hash + flags + counter)
/// - Flags byte is valid
/// - If AT flag is set, verifies attested credential data is present
///
/// # Errors
///
/// Returns `ContractError::InvalidAuthenticatorData` if validation fails.
pub fn validate_authenticator_data(data: &[u8]) -> ContractResult<()> {
    if data.len() < MIN_AUTH_DATA_LEN {
        return Err(ContractError::InvalidAuthenticatorData(format!(
            "too short: {} bytes, minimum is {}",
            data.len(),
            MIN_AUTH_DATA_LEN
        )));
    }

    // Flags are at byte 32
    let flags = data.get(32).ok_or_else(|| {
        ContractError::InvalidAuthenticatorData("cannot read flags byte".to_string())
    })?;

    // Bit 0 (UP) - User Present
    // Bit 2 (UV) - User Verified
    // Bit 6 (AT) - Attested credential data included
    // Bit 7 (ED) - Extension data included

    let at_flag = (flags & 0x40) != 0; // Bit 6

    if at_flag {
        // With AT flag, need at least 37 + 16 (AAGUID) + 2 (cred ID len)
        if data.len() < 55 {
            return Err(ContractError::InvalidAuthenticatorData(format!(
                "AT flag set but data too short: {} bytes",
                data.len()
            )));
        }
    }

    Ok(())
}

// ============================================================================
// Credential ID Validation
// ============================================================================

/// Minimum credential ID length (WebAuthn spec allows any length > 0).
pub const MIN_CREDENTIAL_ID_LEN: usize = 16;

/// Maximum credential ID length (spec says 1023 bytes max).
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// Validate a credential ID.
///
/// This checks:
/// - Non-empty
/// - Length within allowed bounds (16-1023 bytes)
///
/// # Errors
///
/// Returns `ContractError::InvalidCredentialId` if validation fails.
pub fn validate_credential_id(data: &[u8]) -> ContractResult<()> {
    if data.is_empty() {
        return Err(ContractError::InvalidCredentialId(
            "empty credential ID".to_string(),
        ));
    }

    if data.len() < MIN_CREDENTIAL_ID_LEN {
        return Err(ContractError::InvalidCredentialId(format!(
            "too short: {} bytes, minimum is {}",
            data.len(),
            MIN_CREDENTIAL_ID_LEN
        )));
    }

    if data.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(ContractError::InvalidCredentialId(format!(
            "too long: {} bytes, maximum is {}",
            data.len(),
            MAX_CREDENTIAL_ID_LEN
        )));
    }

    Ok(())
}

// ============================================================================
// Challenge Validation
// ============================================================================

/// Minimum challenge length (WebAuthn recommends at least 16 bytes).
pub const MIN_CHALLENGE_LEN: usize = 16;

/// Maximum challenge length (reasonable upper bound).
pub const MAX_CHALLENGE_LEN: usize = 256;

/// Validate a WebAuthn challenge.
///
/// This checks:
/// - Non-empty
/// - Length within reasonable bounds (16-256 bytes)
///
/// # Errors
///
/// Returns `ContractError::InvalidChallenge` if validation fails.
pub fn validate_challenge(data: &[u8]) -> ContractResult<()> {
    if data.is_empty() {
        return Err(ContractError::InvalidChallenge(
            "empty challenge".to_string(),
        ));
    }

    if data.len() < MIN_CHALLENGE_LEN {
        return Err(ContractError::InvalidChallenge(format!(
            "too short: {} bytes, minimum is {}",
            data.len(),
            MIN_CHALLENGE_LEN
        )));
    }

    if data.len() > MAX_CHALLENGE_LEN {
        return Err(ContractError::InvalidChallenge(format!(
            "too long: {} bytes, maximum is {}",
            data.len(),
            MAX_CHALLENGE_LEN
        )));
    }

    Ok(())
}

// ============================================================================
// Signature Validation
// ============================================================================

/// Validate a cryptographic signature.
///
/// This checks:
/// - Non-empty
/// - Reasonable length for expected algorithms
///
/// Note: This does NOT verify the signature cryptographically.
///
/// # Errors
///
/// Returns `ContractError::InvalidSignature` if validation fails.
pub fn validate_signature(data: &[u8]) -> ContractResult<()> {
    if data.is_empty() {
        return Err(ContractError::InvalidSignature(
            "empty signature".to_string(),
        ));
    }

    // Ed25519 signatures are exactly 64 bytes
    // ECDSA signatures are DER-encoded, typically 70-72 bytes
    // but can be shorter (e.g., 68 bytes) or up to 73 bytes
    if data.len() < 64 {
        return Err(ContractError::InvalidSignature(format!(
            "too short: {} bytes, minimum is 64",
            data.len()
        )));
    }

    if data.len() > 128 {
        return Err(ContractError::InvalidSignature(format!(
            "too long: {} bytes, maximum is 128",
            data.len()
        )));
    }

    Ok(())
}

// ============================================================================
// Client Data JSON Validation
// ============================================================================

/// Validate client data JSON.
///
/// This checks:
/// - Non-empty
/// - Valid UTF-8
/// - Valid JSON
/// - Contains required fields: type, challenge, origin
///
/// # Errors
///
/// Returns `ContractError::InvalidClientDataJson` if validation fails.
pub fn validate_client_data_json(data: &[u8]) -> ContractResult<()> {
    if data.is_empty() {
        return Err(ContractError::InvalidClientDataJson(
            "empty client data".to_string(),
        ));
    }

    // Parse as UTF-8
    let json_str = std::str::from_utf8(data)
        .map_err(|e| ContractError::InvalidClientDataJson(format!("invalid UTF-8: {e}")))?;

    // Parse as JSON
    let value: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| ContractError::InvalidClientDataJson(format!("invalid JSON: {e}")))?;

    // Must be an object
    let obj = value
        .as_object()
        .ok_or_else(|| ContractError::InvalidClientDataJson("not a JSON object".to_string()))?;

    // Check required fields
    if !obj.contains_key("type") {
        return Err(ContractError::InvalidClientDataJson(
            "missing 'type' field".to_string(),
        ));
    }

    if !obj.contains_key("challenge") {
        return Err(ContractError::InvalidClientDataJson(
            "missing 'challenge' field".to_string(),
        ));
    }

    if !obj.contains_key("origin") {
        return Err(ContractError::InvalidClientDataJson(
            "missing 'origin' field".to_string(),
        ));
    }

    // Validate type field value
    if let Some(type_val) = obj.get("type")
        && let Some(type_str) = type_val.as_str()
        && type_str != protocol::CLIENT_DATA_TYPE_CREATE
        && type_str != protocol::CLIENT_DATA_TYPE_GET
    {
        return Err(ContractError::InvalidClientDataJson(format!(
            "invalid type: expected 'webauthn.create' or 'webauthn.get', got '{type_str}'"
        )));
    }

    Ok(())
}

// ============================================================================
// Attestation Object Validation
// ============================================================================

/// Validate an attestation object.
///
/// This checks:
/// - Valid CBOR encoding
/// - Contains required fields: fmt, authData, attStmt
///
/// # Errors
///
/// Returns `ContractError::InvalidAttestationObject` if validation fails.
pub fn validate_attestation_object(data: &[u8]) -> ContractResult<()> {
    if data.is_empty() {
        return Err(ContractError::InvalidAttestationObject(
            "empty attestation object".to_string(),
        ));
    }

    // Try to parse as CBOR
    let value: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| ContractError::InvalidAttestationObject(format!("CBOR parse error: {e}")))?;

    // Must be a map
    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => {
            return Err(ContractError::InvalidAttestationObject(
                "not a CBOR map".to_string(),
            ));
        }
    };

    // Helper to check if key exists
    let has_key = |key: &str| -> bool {
        map.iter()
            .any(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == key))
    };

    // Check required fields
    if !has_key("fmt") {
        return Err(ContractError::InvalidAttestationObject(
            "missing 'fmt' field".to_string(),
        ));
    }

    if !has_key("authData") {
        return Err(ContractError::InvalidAttestationObject(
            "missing 'authData' field".to_string(),
        ));
    }

    if !has_key("attStmt") {
        return Err(ContractError::InvalidAttestationObject(
            "missing 'attStmt' field".to_string(),
        ));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]
mod tests {
    use super::*;

    // Helper to create a minimal valid ES256 COSE key
    fn make_es256_cose_key() -> Vec<u8> {
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty
                ciborium::Value::Integer(COSE_KTY_EC2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg
                ciborium::Value::Integer(COSE_ALG_ES256.into()),
            ),
            (
                ciborium::Value::Integer((-1).into()), // crv
                ciborium::Value::Integer(COSE_CRV_P256.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()), // x
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
            (
                ciborium::Value::Integer((-3).into()), // y
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        buf
    }

    // Helper to create a minimal valid EdDSA COSE key
    fn make_eddsa_cose_key() -> Vec<u8> {
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty
                ciborium::Value::Integer(COSE_KTY_OKP.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg
                ciborium::Value::Integer(COSE_ALG_EDDSA.into()),
            ),
            (
                ciborium::Value::Integer((-1).into()), // crv
                ciborium::Value::Integer(COSE_CRV_ED25519.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()), // x
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_validate_cose_key_es256() {
        let key = make_es256_cose_key();
        assert!(validate_cose_key(&key).is_ok());
    }

    #[test]
    fn test_validate_cose_key_eddsa() {
        let key = make_eddsa_cose_key();
        assert!(validate_cose_key(&key).is_ok());
    }

    #[test]
    fn test_validate_cose_key_empty() {
        let result = validate_cose_key(&[]);
        assert!(matches!(result, Err(ContractError::InvalidCoseKey(_))));
    }

    #[test]
    fn test_validate_cose_key_invalid_cbor() {
        let result = validate_cose_key(&[0xFF, 0xFF, 0xFF]);
        assert!(matches!(result, Err(ContractError::InvalidCoseKey(_))));
    }

    #[test]
    fn test_validate_cose_key_missing_kty() {
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![(
            ciborium::Value::Integer(3.into()), // alg only
            ciborium::Value::Integer((-7).into()),
        )]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        let result = validate_cose_key(&buf);
        assert!(matches!(result, Err(ContractError::InvalidCoseKey(msg)) if msg.contains("kty")));
    }

    #[test]
    fn test_validate_authenticator_data_valid() {
        let mut data = vec![0u8; 37];
        data[32] = 0x01; // UP flag set
        assert!(validate_authenticator_data(&data).is_ok());
    }

    #[test]
    fn test_validate_authenticator_data_too_short() {
        let data = vec![0u8; 30];
        let result = validate_authenticator_data(&data);
        assert!(matches!(
            result,
            Err(ContractError::InvalidAuthenticatorData(_))
        ));
    }

    #[test]
    fn test_validate_authenticator_data_with_at_flag() {
        // With AT flag, need more data
        let mut data = vec![0u8; 55];
        data[32] = 0x41; // UP + AT flags
        assert!(validate_authenticator_data(&data).is_ok());
    }

    #[test]
    fn test_validate_authenticator_data_at_flag_too_short() {
        let mut data = vec![0u8; 40];
        data[32] = 0x40; // AT flag set but data too short
        let result = validate_authenticator_data(&data);
        assert!(matches!(
            result,
            Err(ContractError::InvalidAuthenticatorData(_))
        ));
    }

    #[test]
    fn test_validate_credential_id_valid() {
        let cred_id = vec![0u8; 64];
        assert!(validate_credential_id(&cred_id).is_ok());
    }

    #[test]
    fn test_validate_credential_id_empty() {
        let result = validate_credential_id(&[]);
        assert!(matches!(result, Err(ContractError::InvalidCredentialId(_))));
    }

    #[test]
    fn test_validate_credential_id_too_short() {
        let cred_id = vec![0u8; 10];
        let result = validate_credential_id(&cred_id);
        assert!(matches!(result, Err(ContractError::InvalidCredentialId(_))));
    }

    #[test]
    fn test_validate_credential_id_too_long() {
        let cred_id = vec![0u8; 2000];
        let result = validate_credential_id(&cred_id);
        assert!(matches!(result, Err(ContractError::InvalidCredentialId(_))));
    }

    #[test]
    fn test_validate_challenge_valid() {
        let challenge = vec![0u8; 32];
        assert!(validate_challenge(&challenge).is_ok());
    }

    #[test]
    fn test_validate_challenge_empty() {
        let result = validate_challenge(&[]);
        assert!(matches!(result, Err(ContractError::InvalidChallenge(_))));
    }

    #[test]
    fn test_validate_challenge_too_short() {
        let challenge = vec![0u8; 8];
        let result = validate_challenge(&challenge);
        assert!(matches!(result, Err(ContractError::InvalidChallenge(_))));
    }

    #[test]
    fn test_validate_signature_valid() {
        let sig = vec![0u8; 64];
        assert!(validate_signature(&sig).is_ok());
    }

    #[test]
    fn test_validate_signature_empty() {
        let result = validate_signature(&[]);
        assert!(matches!(result, Err(ContractError::InvalidSignature(_))));
    }

    #[test]
    fn test_validate_signature_too_short() {
        let sig = vec![0u8; 32];
        let result = validate_signature(&sig);
        assert!(matches!(result, Err(ContractError::InvalidSignature(_))));
    }

    #[test]
    fn test_validate_client_data_json_valid() {
        let json = br#"{"type":"webauthn.get","challenge":"AQID","origin":"https://example.com"}"#;
        assert!(validate_client_data_json(json).is_ok());
    }

    #[test]
    fn test_validate_client_data_json_empty() {
        let result = validate_client_data_json(&[]);
        assert!(matches!(
            result,
            Err(ContractError::InvalidClientDataJson(_))
        ));
    }

    #[test]
    fn test_validate_client_data_json_invalid_utf8() {
        let result = validate_client_data_json(&[0xFF, 0xFE]);
        assert!(matches!(
            result,
            Err(ContractError::InvalidClientDataJson(msg)) if msg.contains("UTF-8")
        ));
    }

    #[test]
    fn test_validate_client_data_json_missing_type() {
        let json = br#"{"challenge":"AQID","origin":"https://example.com"}"#;
        let result = validate_client_data_json(json);
        assert!(matches!(
            result,
            Err(ContractError::InvalidClientDataJson(msg)) if msg.contains("type")
        ));
    }

    #[test]
    fn test_validate_client_data_json_invalid_type() {
        let json = br#"{"type":"invalid","challenge":"AQID","origin":"https://example.com"}"#;
        let result = validate_client_data_json(json);
        assert!(matches!(
            result,
            Err(ContractError::InvalidClientDataJson(msg)) if msg.contains("invalid type")
        ));
    }

    #[test]
    fn test_validate_attestation_object_valid() {
        let mut buf = Vec::new();
        let obj = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".to_string()),
                ciborium::Value::Text("none".to_string()),
            ),
            (
                ciborium::Value::Text("authData".to_string()),
                ciborium::Value::Bytes(vec![0u8; 37]),
            ),
            (
                ciborium::Value::Text("attStmt".to_string()),
                ciborium::Value::Map(vec![]),
            ),
        ]);
        ciborium::into_writer(&obj, &mut buf).unwrap();
        assert!(validate_attestation_object(&buf).is_ok());
    }

    #[test]
    fn test_validate_attestation_object_empty() {
        let result = validate_attestation_object(&[]);
        assert!(matches!(
            result,
            Err(ContractError::InvalidAttestationObject(_))
        ));
    }

    #[test]
    fn test_validate_attestation_object_missing_fmt() {
        let mut buf = Vec::new();
        let obj = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("authData".to_string()),
                ciborium::Value::Bytes(vec![0u8; 37]),
            ),
            (
                ciborium::Value::Text("attStmt".to_string()),
                ciborium::Value::Map(vec![]),
            ),
        ]);
        ciborium::into_writer(&obj, &mut buf).unwrap();
        let result = validate_attestation_object(&buf);
        assert!(matches!(
            result,
            Err(ContractError::InvalidAttestationObject(msg)) if msg.contains("fmt")
        ));
    }

    // =========================================================================
    // Boundary Condition Tests
    // =========================================================================

    #[test]
    fn test_validate_credential_id_minimum_boundary() {
        // Exactly MIN_CREDENTIAL_ID_LEN (16) bytes
        let cred_id = vec![0xAB; MIN_CREDENTIAL_ID_LEN];
        assert!(validate_credential_id(&cred_id).is_ok());
    }

    #[test]
    fn test_validate_credential_id_one_below_minimum() {
        // MIN_CREDENTIAL_ID_LEN - 1 bytes
        let cred_id = vec![0xAB; MIN_CREDENTIAL_ID_LEN - 1];
        let result = validate_credential_id(&cred_id);
        assert!(
            matches!(result, Err(ContractError::InvalidCredentialId(msg)) if msg.contains("too short"))
        );
    }

    #[test]
    fn test_validate_credential_id_maximum_boundary() {
        // Exactly MAX_CREDENTIAL_ID_LEN (1023) bytes
        let cred_id = vec![0xAB; MAX_CREDENTIAL_ID_LEN];
        assert!(validate_credential_id(&cred_id).is_ok());
    }

    #[test]
    fn test_validate_credential_id_one_above_maximum() {
        // MAX_CREDENTIAL_ID_LEN + 1 bytes
        let cred_id = vec![0xAB; MAX_CREDENTIAL_ID_LEN + 1];
        let result = validate_credential_id(&cred_id);
        assert!(
            matches!(result, Err(ContractError::InvalidCredentialId(msg)) if msg.contains("too long"))
        );
    }

    #[test]
    fn test_validate_challenge_minimum_boundary() {
        // Exactly MIN_CHALLENGE_LEN (16) bytes
        let challenge = vec![0xCD; MIN_CHALLENGE_LEN];
        assert!(validate_challenge(&challenge).is_ok());
    }

    #[test]
    fn test_validate_challenge_one_below_minimum() {
        // MIN_CHALLENGE_LEN - 1 bytes
        let challenge = vec![0xCD; MIN_CHALLENGE_LEN - 1];
        let result = validate_challenge(&challenge);
        assert!(
            matches!(result, Err(ContractError::InvalidChallenge(msg)) if msg.contains("too short"))
        );
    }

    #[test]
    fn test_validate_challenge_maximum_boundary() {
        // Exactly MAX_CHALLENGE_LEN (256) bytes
        let challenge = vec![0xCD; MAX_CHALLENGE_LEN];
        assert!(validate_challenge(&challenge).is_ok());
    }

    #[test]
    fn test_validate_challenge_one_above_maximum() {
        // MAX_CHALLENGE_LEN + 1 bytes
        let challenge = vec![0xCD; MAX_CHALLENGE_LEN + 1];
        let result = validate_challenge(&challenge);
        assert!(
            matches!(result, Err(ContractError::InvalidChallenge(msg)) if msg.contains("too long"))
        );
    }

    #[test]
    fn test_validate_authenticator_data_minimum_boundary() {
        // Exactly MIN_AUTH_DATA_LEN (37) bytes
        let mut data = vec![0u8; MIN_AUTH_DATA_LEN];
        data[32] = 0x01; // UP flag
        assert!(validate_authenticator_data(&data).is_ok());
    }

    #[test]
    fn test_validate_authenticator_data_one_below_minimum() {
        // MIN_AUTH_DATA_LEN - 1 bytes
        let data = vec![0u8; MIN_AUTH_DATA_LEN - 1];
        let result = validate_authenticator_data(&data);
        assert!(
            matches!(result, Err(ContractError::InvalidAuthenticatorData(msg)) if msg.contains("too short"))
        );
    }

    #[test]
    fn test_validate_authenticator_data_at_flag_boundary() {
        // With AT flag, minimum is 55 bytes
        let mut data = vec![0u8; 55];
        data[32] = 0x41; // UP + AT flags
        assert!(validate_authenticator_data(&data).is_ok());
    }

    #[test]
    fn test_validate_authenticator_data_at_flag_one_below() {
        // With AT flag, 54 bytes should fail
        let mut data = vec![0u8; 54];
        data[32] = 0x40; // AT flag
        let result = validate_authenticator_data(&data);
        assert!(
            matches!(result, Err(ContractError::InvalidAuthenticatorData(msg)) if msg.contains("too short"))
        );
    }

    #[test]
    fn test_validate_signature_minimum_boundary() {
        // Minimum is 64 bytes for Ed25519
        let sig = vec![0xEF; 64];
        assert!(validate_signature(&sig).is_ok());
    }

    #[test]
    fn test_validate_signature_one_below_minimum() {
        // 63 bytes should fail
        let sig = vec![0xEF; 63];
        let result = validate_signature(&sig);
        assert!(
            matches!(result, Err(ContractError::InvalidSignature(msg)) if msg.contains("too short"))
        );
    }

    #[test]
    fn test_validate_signature_maximum_boundary() {
        // Maximum is 128 bytes
        let sig = vec![0xEF; 128];
        assert!(validate_signature(&sig).is_ok());
    }

    #[test]
    fn test_validate_signature_one_above_maximum() {
        // 129 bytes should fail
        let sig = vec![0xEF; 129];
        let result = validate_signature(&sig);
        assert!(
            matches!(result, Err(ContractError::InvalidSignature(msg)) if msg.contains("too long"))
        );
    }

    // =========================================================================
    // Algorithm/Key Type Mismatch Tests
    // =========================================================================

    #[test]
    fn test_validate_cose_key_ec2_with_eddsa_algorithm() {
        // EC2 key type but EdDSA algorithm - should fail
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = EC2
                ciborium::Value::Integer(COSE_KTY_EC2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = EdDSA (wrong for EC2)
                ciborium::Value::Integer(COSE_ALG_EDDSA.into()),
            ),
            (
                ciborium::Value::Integer((-1).into()), // crv
                ciborium::Value::Integer(COSE_CRV_P256.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()), // x
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
            (
                ciborium::Value::Integer((-3).into()), // y
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        let result = validate_cose_key(&buf);
        assert!(
            matches!(result, Err(ContractError::InvalidCoseKey(msg)) if msg.contains("unexpected algorithm"))
        );
    }

    #[test]
    fn test_validate_cose_key_okp_with_es256_algorithm() {
        // OKP key type but ES256 algorithm - should fail
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = OKP
                ciborium::Value::Integer(COSE_KTY_OKP.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = ES256 (wrong for OKP)
                ciborium::Value::Integer(COSE_ALG_ES256.into()),
            ),
            (
                ciborium::Value::Integer((-1).into()), // crv
                ciborium::Value::Integer(COSE_CRV_ED25519.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()), // x
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        let result = validate_cose_key(&buf);
        assert!(
            matches!(result, Err(ContractError::InvalidCoseKey(msg)) if msg.contains("unexpected algorithm"))
        );
    }

    #[test]
    fn test_validate_cose_key_unsupported_key_type() {
        // Unsupported key type (RSA = 3)
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = RSA (unsupported)
                ciborium::Value::Integer(3.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = RS256
                ciborium::Value::Integer((-257).into()),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        let result = validate_cose_key(&buf);
        assert!(
            matches!(result, Err(ContractError::InvalidCoseKey(msg)) if msg.contains("unsupported key type"))
        );
    }

    #[test]
    fn test_validate_cose_key_ec2_missing_curve() {
        // EC2 key missing crv field
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = EC2
                ciborium::Value::Integer(COSE_KTY_EC2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = ES256
                ciborium::Value::Integer(COSE_ALG_ES256.into()),
            ),
            // Missing crv field
            (
                ciborium::Value::Integer((-2).into()), // x
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
            (
                ciborium::Value::Integer((-3).into()), // y
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        let result = validate_cose_key(&buf);
        assert!(matches!(result, Err(ContractError::InvalidCoseKey(msg)) if msg.contains("crv")));
    }

    #[test]
    fn test_validate_cose_key_okp_missing_curve() {
        // OKP key missing crv field
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = OKP
                ciborium::Value::Integer(COSE_KTY_OKP.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = EdDSA
                ciborium::Value::Integer(COSE_ALG_EDDSA.into()),
            ),
            // Missing crv field
            (
                ciborium::Value::Integer((-2).into()), // x
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        let result = validate_cose_key(&buf);
        assert!(matches!(result, Err(ContractError::InvalidCoseKey(msg)) if msg.contains("crv")));
    }

    #[test]
    fn test_validate_cose_key_ec2_missing_x() {
        // EC2 key missing x coordinate
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = EC2
                ciborium::Value::Integer(COSE_KTY_EC2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = ES256
                ciborium::Value::Integer(COSE_ALG_ES256.into()),
            ),
            (
                ciborium::Value::Integer((-1).into()), // crv
                ciborium::Value::Integer(COSE_CRV_P256.into()),
            ),
            // Missing x coordinate (-2)
            (
                ciborium::Value::Integer((-3).into()), // y only
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        let result = validate_cose_key(&buf);
        assert!(
            matches!(result, Err(ContractError::InvalidCoseKey(msg)) if msg.contains("x coordinate"))
        );
    }

    #[test]
    fn test_validate_cose_key_ec2_missing_y() {
        // EC2 key missing y coordinate
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = EC2
                ciborium::Value::Integer(COSE_KTY_EC2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = ES256
                ciborium::Value::Integer(COSE_ALG_ES256.into()),
            ),
            (
                ciborium::Value::Integer((-1).into()), // crv
                ciborium::Value::Integer(COSE_CRV_P256.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()), // x only
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
            // Missing y coordinate (-3)
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        let result = validate_cose_key(&buf);
        assert!(
            matches!(result, Err(ContractError::InvalidCoseKey(msg)) if msg.contains("y coordinate"))
        );
    }

    #[test]
    fn test_validate_cose_key_okp_missing_x() {
        // OKP key missing x (public key)
        let mut buf = Vec::new();
        let key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty = OKP
                ciborium::Value::Integer(COSE_KTY_OKP.into()),
            ),
            (
                ciborium::Value::Integer(3.into()), // alg = EdDSA
                ciborium::Value::Integer(COSE_ALG_EDDSA.into()),
            ),
            (
                ciborium::Value::Integer((-1).into()), // crv
                ciborium::Value::Integer(COSE_CRV_ED25519.into()),
            ),
            // Missing x coordinate (-2)
        ]);
        ciborium::into_writer(&key, &mut buf).unwrap();
        let result = validate_cose_key(&buf);
        assert!(
            matches!(result, Err(ContractError::InvalidCoseKey(msg)) if msg.contains("x coordinate"))
        );
    }

    // =========================================================================
    // Client Data JSON Additional Tests
    // =========================================================================

    #[test]
    fn test_validate_client_data_json_webauthn_create() {
        // Valid webauthn.create type
        let json =
            br#"{"type":"webauthn.create","challenge":"AQID","origin":"https://example.com"}"#;
        assert!(validate_client_data_json(json).is_ok());
    }

    #[test]
    fn test_validate_client_data_json_missing_challenge() {
        let json = br#"{"type":"webauthn.get","origin":"https://example.com"}"#;
        let result = validate_client_data_json(json);
        assert!(matches!(
            result,
            Err(ContractError::InvalidClientDataJson(msg)) if msg.contains("challenge")
        ));
    }

    #[test]
    fn test_validate_client_data_json_missing_origin() {
        let json = br#"{"type":"webauthn.get","challenge":"AQID"}"#;
        let result = validate_client_data_json(json);
        assert!(matches!(
            result,
            Err(ContractError::InvalidClientDataJson(msg)) if msg.contains("origin")
        ));
    }

    #[test]
    fn test_validate_client_data_json_not_object() {
        // JSON array instead of object
        let json = br#"["type","challenge","origin"]"#;
        let result = validate_client_data_json(json);
        assert!(matches!(
            result,
            Err(ContractError::InvalidClientDataJson(msg)) if msg.contains("object")
        ));
    }

    #[test]
    fn test_validate_client_data_json_invalid_json() {
        let json = br#"{"type": "webauthn.get" invalid"#;
        let result = validate_client_data_json(json);
        assert!(matches!(
            result,
            Err(ContractError::InvalidClientDataJson(msg)) if msg.contains("JSON")
        ));
    }

    // =========================================================================
    // Attestation Object Additional Tests
    // =========================================================================

    #[test]
    fn test_validate_attestation_object_not_map() {
        // CBOR array instead of map
        let mut buf = Vec::new();
        ciborium::into_writer(&ciborium::Value::Array(vec![]), &mut buf).unwrap();
        let result = validate_attestation_object(&buf);
        assert!(matches!(
            result,
            Err(ContractError::InvalidAttestationObject(msg)) if msg.contains("map")
        ));
    }

    #[test]
    fn test_validate_attestation_object_missing_auth_data() {
        let mut buf = Vec::new();
        let obj = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".to_string()),
                ciborium::Value::Text("none".to_string()),
            ),
            (
                ciborium::Value::Text("attStmt".to_string()),
                ciborium::Value::Map(vec![]),
            ),
            // Missing authData
        ]);
        ciborium::into_writer(&obj, &mut buf).unwrap();
        let result = validate_attestation_object(&buf);
        assert!(matches!(
            result,
            Err(ContractError::InvalidAttestationObject(msg)) if msg.contains("authData")
        ));
    }

    #[test]
    fn test_validate_attestation_object_missing_att_stmt() {
        let mut buf = Vec::new();
        let obj = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".to_string()),
                ciborium::Value::Text("none".to_string()),
            ),
            (
                ciborium::Value::Text("authData".to_string()),
                ciborium::Value::Bytes(vec![0u8; 37]),
            ),
            // Missing attStmt
        ]);
        ciborium::into_writer(&obj, &mut buf).unwrap();
        let result = validate_attestation_object(&buf);
        assert!(matches!(
            result,
            Err(ContractError::InvalidAttestationObject(msg)) if msg.contains("attStmt")
        ));
    }

    #[test]
    fn test_validate_attestation_object_packed_format() {
        // "packed" format is used by YubiKey
        let mut buf = Vec::new();
        let obj = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".to_string()),
                ciborium::Value::Text("packed".to_string()),
            ),
            (
                ciborium::Value::Text("authData".to_string()),
                ciborium::Value::Bytes(vec![0u8; 55]),
            ),
            (
                ciborium::Value::Text("attStmt".to_string()),
                ciborium::Value::Map(vec![]),
            ),
        ]);
        ciborium::into_writer(&obj, &mut buf).unwrap();
        assert!(validate_attestation_object(&buf).is_ok());
    }
}
