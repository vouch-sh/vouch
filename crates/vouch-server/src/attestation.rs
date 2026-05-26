// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Attestation format extraction and validation for WebAuthn credentials.
//!
//! This module provides utilities to extract and classify attestation formats
//! from CBOR-encoded attestation objects. The attestation format is used to
//! distinguish hardware security keys from software/synced passkeys.
//!
//! See: <https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats>

use ciborium::Value;

/// WebAuthn attestation statement formats as defined in the spec.
///
/// The attestation format reliably distinguishes hardware from software authenticators:
/// - Hardware keys (YubiKey, Titan) use `packed` or `fido-u2f`
/// - Software/synced passkeys (1Password, browser sync) use `none`
/// - Platform authenticators (Touch ID, Windows Hello) use their respective formats
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttestationFormat {
    /// Packed attestation - used by most hardware security keys (YubiKey, Titan, etc.)
    Packed,
    /// TPM attestation - used by Windows Hello and TPM-based authenticators
    Tpm,
    /// Android Key attestation - used by Android platform authenticators
    AndroidKey,
    /// Android SafetyNet attestation (deprecated but still seen)
    AndroidSafetynet,
    /// FIDO U2F attestation - used by legacy U2F hardware keys
    FidoU2f,
    /// No attestation - used by synced passkeys (1Password, browser, iCloud)
    None,
    /// Apple attestation - used by Apple platform authenticators
    Apple,
    /// Unknown format (for forward compatibility)
    Unknown(String),
}

impl AttestationFormat {
    /// Parse attestation format from string.
    #[must_use]
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "packed" => Self::Packed,
            "tpm" => Self::Tpm,
            "android-key" => Self::AndroidKey,
            "android-safetynet" => Self::AndroidSafetynet,
            "fido-u2f" => Self::FidoU2f,
            "none" => Self::None,
            "apple" => Self::Apple,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Returns the format string as it appears in the attestation object.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Packed => "packed",
            Self::Tpm => "tpm",
            Self::AndroidKey => "android-key",
            Self::AndroidSafetynet => "android-safetynet",
            Self::FidoU2f => "fido-u2f",
            Self::None => "none",
            Self::Apple => "apple",
            Self::Unknown(s) => s,
        }
    }

    /// Returns true if this format indicates a hardware-bound authenticator.
    ///
    /// Hardware authenticators use `packed` or `fido-u2f` formats and provide
    /// strong security guarantees because the private key is bound to the device.
    #[must_use]
    pub(crate) fn is_hardware(&self) -> bool {
        matches!(self, Self::Packed | Self::FidoU2f)
    }

    /// Returns true if this format indicates a software/synced passkey.
    ///
    /// Software passkeys use `none` attestation because synced credentials
    /// cannot provide attestation (they're extractable by design).
    #[must_use]
    pub(crate) fn is_software(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns true if this format indicates a platform authenticator.
    ///
    /// Platform authenticators (Touch ID, Windows Hello, Android) use their
    /// respective attestation formats but are not hardware security keys.
    #[must_use]
    pub(crate) fn is_platform(&self) -> bool {
        matches!(
            self,
            Self::Tpm | Self::AndroidKey | Self::AndroidSafetynet | Self::Apple
        )
    }
}

impl std::fmt::Display for AttestationFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Extract the attestation format from a CBOR-encoded attestation object.
///
/// The attestation object is a CBOR map containing:
/// - `fmt`: attestation statement format (string)
/// - `attStmt`: attestation statement
/// - `authData`: authenticator data
///
/// Returns the attestation format if successfully parsed, or `None` if the
/// attestation object is malformed.
#[must_use]
pub(crate) fn extract_attestation_format(attestation: &[u8]) -> Option<AttestationFormat> {
    let value: Value = ciborium::from_reader(attestation).ok()?;

    let fmt_str = value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some("fmt"))
        .and_then(|(_, v)| v.as_text())?;

    Some(AttestationFormat::parse(fmt_str))
}

/// Extract AAGUID from a CBOR-encoded attestation object.
///
/// The attestation object structure (CBOR map):
/// - `fmt`: attestation statement format
/// - `attStmt`: attestation statement
/// - `authData`: authenticator data containing AAGUID and credential public key
///
/// The authData structure:
/// - rpIdHash: 32 bytes (SHA-256 of RP ID)
/// - flags: 1 byte
/// - signCount: 4 bytes (big-endian)
/// - attestedCredentialData (if AT flag set):
///   - aaguid: 16 bytes
///   - credIdLen: 2 bytes (big-endian)
///   - credId: credIdLen bytes
///   - credentialPublicKey: COSE-encoded public key
///
/// Returns the AAGUID as a UUID string if present and valid.
#[must_use]
pub(crate) fn extract_aaguid_from_attestation(attestation: &[u8]) -> Option<String> {
    if attestation.len() < 37 {
        return None;
    }

    // Parse the CBOR attestation object
    let value: Value = ciborium::from_reader(attestation).ok()?;

    // Extract authData from the map
    let auth_data = value.as_map().and_then(|m| {
        m.iter()
            .find(|(k, _)| k.as_text() == Some("authData"))
            .and_then(|(_, v)| v.as_bytes())
    })?;

    // Extract AAGUID from authenticator data
    vouch_common::extract_aaguid_from_auth_data(auth_data)
}

/// Result of validating an attestation format for hardware-only authentication.
#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "payloads kept for diagnostics; matched but not read"
)]
pub(crate) enum AttestationValidation {
    /// The attestation format indicates a hardware security key.
    Valid(AttestationFormat),
    /// Software passkey (1Password, browser sync) - not allowed.
    SoftwarePasskey,
    /// Platform authenticator (Touch ID, Windows Hello) - not allowed.
    PlatformAuthenticator,
    /// Unknown or missing attestation format - not allowed.
    Unknown(String),
}

impl AttestationValidation {
    /// Returns the error code for rejected attestation formats.
    #[must_use]
    pub(crate) fn error_code(&self) -> Option<&'static str> {
        match self {
            Self::Valid(_) => None,
            Self::SoftwarePasskey => Some("software_passkey_not_allowed"),
            Self::PlatformAuthenticator => Some("platform_authenticator_not_allowed"),
            Self::Unknown(_) => Some("unknown_attestation_format"),
        }
    }

    /// Returns the user-facing error message for rejected attestation formats.
    #[must_use]
    pub(crate) fn error_message(&self) -> Option<String> {
        match self {
            Self::Valid(_) => None,
            Self::SoftwarePasskey => Some(
                "Software passkeys (1Password, browser sync) are not supported. \
                 Please use a hardware security key."
                    .to_string(),
            ),
            Self::PlatformAuthenticator => Some(
                "Platform authenticators (Touch ID, Windows Hello) are not supported. \
                 Please use a hardware security key."
                    .to_string(),
            ),
            Self::Unknown(_) => Some(
                "Unknown authenticator type. Please use a hardware security key like a YubiKey."
                    .to_string(),
            ),
        }
    }
}

/// Validate that an attestation object indicates a hardware security key.
///
/// This function enforces hardware-only authentication by rejecting:
/// - Software passkeys (1Password, browser sync) that use `attestation: none`
/// - Platform authenticators (Touch ID, Windows Hello) that use their own formats
/// - Unknown attestation formats
///
/// Only hardware security keys using `packed` or `fido-u2f` attestation are allowed.
#[must_use]
pub(crate) fn validate_hardware_attestation(attestation: &[u8]) -> AttestationValidation {
    let fmt = extract_attestation_format(attestation)
        .unwrap_or_else(|| AttestationFormat::Unknown("missing".to_string()));

    if fmt.is_hardware() {
        AttestationValidation::Valid(fmt)
    } else if fmt.is_software() {
        AttestationValidation::SoftwarePasskey
    } else if fmt.is_platform() {
        AttestationValidation::PlatformAuthenticator
    } else {
        AttestationValidation::Unknown(fmt.to_string())
    }
}

/// Extract x5c DER certificate arrays from a CBOR-encoded attestation object.
///
/// Parses the attestation object to find `attStmt.x5c` and returns the
/// DER-encoded certificates as byte vectors.
#[must_use]
pub(crate) fn extract_x5c_from_attestation(attestation: &[u8]) -> Option<Vec<Vec<u8>>> {
    let value: Value = ciborium::from_reader(attestation).ok()?;
    let map = value.as_map()?;

    let att_stmt = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("attStmt"))
        .and_then(|(_, v)| v.as_map())?;

    let x5c_array = att_stmt
        .iter()
        .find(|(k, _)| k.as_text() == Some("x5c"))
        .and_then(|(_, v)| v.as_array())?;

    let certs: Vec<Vec<u8>> = x5c_array
        .iter()
        .filter_map(|item| {
            if let Value::Bytes(bytes) = item {
                Some(bytes.clone())
            } else {
                None
            }
        })
        .collect();

    if certs.is_empty() { None } else { Some(certs) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_classification() {
        assert!(AttestationFormat::Packed.is_hardware());
        assert!(AttestationFormat::FidoU2f.is_hardware());

        assert!(AttestationFormat::None.is_software());

        assert!(AttestationFormat::Tpm.is_platform());
        assert!(AttestationFormat::Apple.is_platform());
        assert!(AttestationFormat::AndroidKey.is_platform());
        assert!(AttestationFormat::AndroidSafetynet.is_platform());

        assert!(!AttestationFormat::Packed.is_software());
        assert!(!AttestationFormat::Packed.is_platform());
        assert!(!AttestationFormat::None.is_hardware());
        assert!(!AttestationFormat::None.is_platform());
    }

    #[test]
    fn test_parse() {
        assert_eq!(
            AttestationFormat::parse("packed"),
            AttestationFormat::Packed
        );
        assert_eq!(AttestationFormat::parse("none"), AttestationFormat::None);
        assert_eq!(AttestationFormat::parse("tpm"), AttestationFormat::Tpm);
        assert_eq!(AttestationFormat::parse("apple"), AttestationFormat::Apple);
        assert_eq!(
            AttestationFormat::parse("fido-u2f"),
            AttestationFormat::FidoU2f
        );
        assert_eq!(
            AttestationFormat::parse("android-key"),
            AttestationFormat::AndroidKey
        );
        assert_eq!(
            AttestationFormat::parse("android-safetynet"),
            AttestationFormat::AndroidSafetynet
        );
        assert!(matches!(
            AttestationFormat::parse("unknown-format"),
            AttestationFormat::Unknown(_)
        ));
    }

    #[test]
    fn test_as_str() {
        assert_eq!(AttestationFormat::Packed.as_str(), "packed");
        assert_eq!(AttestationFormat::None.as_str(), "none");
        assert_eq!(AttestationFormat::Tpm.as_str(), "tpm");
        assert_eq!(AttestationFormat::Apple.as_str(), "apple");
        assert_eq!(AttestationFormat::FidoU2f.as_str(), "fido-u2f");
        assert_eq!(AttestationFormat::AndroidKey.as_str(), "android-key");
        assert_eq!(
            AttestationFormat::AndroidSafetynet.as_str(),
            "android-safetynet"
        );
        assert_eq!(
            AttestationFormat::Unknown("custom".to_string()).as_str(),
            "custom"
        );
    }

    #[test]
    fn test_extract_packed_format() {
        // CBOR map: {"fmt": "packed", "authData": ..., "attStmt": ...}
        // Minimal valid CBOR for testing
        let mut cbor_data = Vec::new();
        ciborium::into_writer(
            &ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("fmt".to_string()),
                    ciborium::Value::Text("packed".to_string()),
                ),
                (
                    ciborium::Value::Text("authData".to_string()),
                    ciborium::Value::Bytes(vec![0u8; 37]),
                ),
                (
                    ciborium::Value::Text("attStmt".to_string()),
                    ciborium::Value::Map(vec![]),
                ),
            ]),
            &mut cbor_data,
        )
        .ok();

        let result = extract_attestation_format(&cbor_data);
        assert_eq!(result, Some(AttestationFormat::Packed));
    }

    #[test]
    fn test_extract_none_format() {
        let mut cbor_data = Vec::new();
        ciborium::into_writer(
            &ciborium::Value::Map(vec![
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
            ]),
            &mut cbor_data,
        )
        .ok();

        let result = extract_attestation_format(&cbor_data);
        assert_eq!(result, Some(AttestationFormat::None));
    }

    #[test]
    fn test_extract_invalid_cbor() {
        let invalid_data = vec![0xFF, 0xFF, 0xFF];
        let result = extract_attestation_format(&invalid_data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_missing_fmt() {
        let mut cbor_data = Vec::new();
        ciborium::into_writer(
            &ciborium::Value::Map(vec![(
                ciborium::Value::Text("authData".to_string()),
                ciborium::Value::Bytes(vec![0u8; 37]),
            )]),
            &mut cbor_data,
        )
        .ok();

        let result = extract_attestation_format(&cbor_data);
        assert_eq!(result, None);
    }
}
