// SPDX-License-Identifier: Apache-2.0 OR MIT
//! WebAuthn registration attestation validation.

use crate::attestation::{extract_aaguid_from_attestation, validate_hardware_attestation};
use crate::error::ServiceError;
use axum::http::StatusCode;

/// Result of validating a registration attestation.
pub(crate) struct ValidatedAttestation {
    /// The AAGUID extracted from the attestation (if available).
    pub aaguid: Option<String>,
    /// The device name determined from the AAGUID.
    pub device_name: String,
    /// Whether the attestation was cryptographically verified via x5c chain.
    pub attestation_verified: bool,
}

/// Validate a WebAuthn registration attestation.
///
/// This performs common validation for both CLI and browser registration:
/// 1. Validates the attestation is from a hardware authenticator (not software/platform)
/// 2. Checks the AAGUID against the configured `AaguidPolicy`
/// 3. Extracts the AAGUID from the attestation
/// 4. Determines the device name from the AAGUID
///
/// Duplicate credential prevention is handled by WebAuthn's `excludeCredentials`
/// mechanism, which checks on the authenticator itself during `navigator.credentials.create()`.
///
/// # Errors
///
/// Returns an error if the attestation is from a software passkey or platform
/// authenticator, or if the AAGUID is not permitted by the policy.
pub(crate) fn validate_registration_attestation(
    attestation_object: &[u8],
    policy: &vouch_common::AaguidPolicy,
    require_attestation_cert: bool,
) -> Result<ValidatedAttestation, ServiceError> {
    // Validate attestation format - reject software passkeys and platform authenticators
    let validation = validate_hardware_attestation(attestation_object);
    if let (Some(code), Some(message)) = (validation.error_code(), validation.error_message()) {
        tracing::warn!("Rejected registration: {}", code);
        return Err(ServiceError::api(StatusCode::BAD_REQUEST, code, message));
    }

    // When require_attestation_cert is enabled, check that the attestation
    // statement contains an x5c certificate chain. Self-attestation (no chain)
    // is rejected since the AAGUID cannot be cryptographically verified.
    if require_attestation_cert {
        let has_x5c = has_x5c_in_attestation(attestation_object);
        if !has_x5c {
            tracing::warn!(
                "Rejected registration: attestation certificate \
                 required but not present (self-attestation)"
            );
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "attestation_cert_required",
                "This server requires authenticators that provide \
                 an attestation certificate chain. \
                 Self-attestation is not accepted.",
            ));
        }
    }

    // Extract AAGUID from the attestation object
    let aaguid = extract_aaguid_from_attestation(attestation_object);

    // SECURITY: AAGUID is extracted from the attestation object's authData.
    // When x5c chain validation is performed (in webauthn_verify or via
    // validate_attestation_chain), the AAGUID is cryptographically verified
    // against the leaf certificate. Without x5c validation, a sophisticated
    // attacker could forge an AAGUID.

    // Check AAGUID against configured policy.
    // When the policy is not `Any`, a missing AAGUID must be rejected —
    // otherwise an authenticator with malformed/missing attestation data
    // would silently bypass the allowlist.
    if !matches!(policy, vouch_common::AaguidPolicy::Any) {
        match aaguid {
            Some(ref aaguid_str) if !policy.is_allowed(aaguid_str) => {
                tracing::warn!(
                    aaguid = %aaguid_str,
                    "Rejected registration: AAGUID not allowed by policy"
                );
                return Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "aaguid_not_allowed",
                    format!(
                        "Authenticator '{aaguid_str}' is not permitted \
                         by the server's AAGUID policy. \
                         Please use an approved hardware security key."
                    ),
                ));
            }
            None => {
                tracing::warn!(
                    "Rejected registration: missing AAGUID \
                     with non-Any policy"
                );
                return Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "aaguid_missing",
                    "Could not extract authenticator identity \
                     (AAGUID). Registration requires an \
                     identifiable hardware security key when an \
                     AAGUID policy is configured.",
                ));
            }
            _ => {} // AAGUID present and allowed
        }
    }

    // Determine device name from AAGUID if known
    let device_name = aaguid
        .as_deref()
        .and_then(vouch_common::lookup_device_model)
        .unwrap_or("Security Key")
        .to_string();

    Ok(ValidatedAttestation {
        aaguid,
        device_name,
        attestation_verified: false,
    })
}

/// Check if the attestation object contains an x5c certificate chain.
fn has_x5c_in_attestation(attestation: &[u8]) -> bool {
    let Ok(value) = ciborium::from_reader::<ciborium::Value, _>(attestation) else {
        return false;
    };
    let Some(map) = value.as_map() else {
        return false;
    };
    let Some((_, att_stmt)) = map.iter().find(|(k, _)| k.as_text() == Some("attStmt")) else {
        return false;
    };
    let Some(stmt_map) = att_stmt.as_map() else {
        return false;
    };
    stmt_map
        .iter()
        .any(|(k, v)| k.as_text() == Some("x5c") && v.as_array().is_some_and(|a| !a.is_empty()))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use ciborium::Value;
    use std::collections::HashSet;

    /// YubiKey 5 NFC AAGUID bytes.
    const YUBIKEY_5_NFC_AAGUID: [u8; 16] = [
        0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39, 0x93, 0xec, 0x0a, 0x27, 0x29, 0xa1, 0x54,
        0xa8,
    ];

    /// Build a minimal CBOR attestation object for testing.
    fn build_attestation(
        fmt: &str,
        aaguid: Option<[u8; 16]>,
        x5c: Option<Vec<Vec<u8>>>,
    ) -> Vec<u8> {
        // Build authData: rpIdHash(32) + flags(1) + signCount(4)
        let mut auth_data = vec![0u8; 37];
        if let Some(aaguid_bytes) = aaguid {
            // Set AT flag (bit 6) and UP flag (bit 0)
            auth_data[32] = 0x41;
            auth_data.extend_from_slice(&aaguid_bytes);
            // credIdLen = 0, no credential ID
            auth_data.extend_from_slice(&[0x00, 0x00]);
        } else {
            auth_data[32] = 0x01; // UP flag only
        }

        let mut stmt_entries = Vec::new();
        if let Some(certs) = x5c {
            let x5c_array: Vec<Value> = certs.into_iter().map(Value::Bytes).collect();
            stmt_entries.push((Value::Text("x5c".to_string()), Value::Array(x5c_array)));
        }

        let mut cbor = Vec::new();
        ciborium::into_writer(
            &Value::Map(vec![
                (Value::Text("fmt".to_string()), Value::Text(fmt.to_string())),
                (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
                (Value::Text("attStmt".to_string()), Value::Map(stmt_entries)),
            ]),
            &mut cbor,
        )
        .expect("CBOR serialization");
        cbor
    }

    // ====================================================================
    // has_x5c_in_attestation tests
    // ====================================================================

    #[test]
    fn test_has_x5c_with_certs() {
        let att = build_attestation(
            "packed",
            Some(YUBIKEY_5_NFC_AAGUID),
            Some(vec![vec![0xDE, 0xAD]]),
        );
        assert!(has_x5c_in_attestation(&att));
    }

    #[test]
    fn test_has_x5c_without_certs() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        assert!(!has_x5c_in_attestation(&att));
    }

    #[test]
    fn test_has_x5c_empty_array() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), Some(vec![]));
        assert!(!has_x5c_in_attestation(&att));
    }

    #[test]
    fn test_has_x5c_invalid_cbor() {
        assert!(!has_x5c_in_attestation(&[0xFF, 0xFF]));
    }

    // ====================================================================
    // validate_registration_attestation tests
    // ====================================================================

    #[test]
    fn test_validate_packed_any_policy() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false);
        let validated = result.expect("should succeed");
        assert!(validated.aaguid.is_some());
        assert!(!validated.attestation_verified);
    }

    #[test]
    fn test_validate_rejects_software_passkey() {
        let att = build_attestation("none", None, None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_platform_authenticator() {
        let att = build_attestation("apple", None, None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_allowlist_permits_listed_aaguid() {
        let aaguid_str = "cb69481e-8ff7-4039-93ec-0a2729a154a8";
        let mut set = HashSet::new();
        set.insert(aaguid_str.to_string());
        let policy = vouch_common::AaguidPolicy::AllowList(set);

        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let result = validate_registration_attestation(&att, &policy, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_allowlist_rejects_unlisted_aaguid() {
        let mut set = HashSet::new();
        set.insert("00000000-0000-0000-0000-000000000000".to_string());
        let policy = vouch_common::AaguidPolicy::AllowList(set);

        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let result = validate_registration_attestation(&att, &policy, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_missing_aaguid_with_non_any_policy() {
        let policy = vouch_common::AaguidPolicy::FipsOnly;

        // No AAGUID in authData (UP flag only, no AT flag)
        let att = build_attestation("packed", None, None);
        let result = validate_registration_attestation(&att, &policy, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_require_cert_rejects_self_attestation() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_require_cert_accepts_x5c() {
        let att = build_attestation(
            "packed",
            Some(YUBIKEY_5_NFC_AAGUID),
            Some(vec![vec![0xDE, 0xAD]]),
        );
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_no_require_cert_allows_self_attestation() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_known_aaguid_sets_device_name() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false);
        let validated = result.expect("should succeed");
        assert_ne!(validated.device_name, "Security Key");
    }

    #[test]
    fn test_validate_unknown_aaguid_uses_default_name() {
        let unknown_aaguid = [0x00; 16];
        let att = build_attestation("packed", Some(unknown_aaguid), None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false);
        let validated = result.expect("should succeed");
        assert_eq!(validated.device_name, "Security Key");
    }
}
