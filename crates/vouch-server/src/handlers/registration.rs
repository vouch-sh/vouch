// SPDX-License-Identifier: BUSL-1.1
//! WebAuthn registration attestation validation.

use crate::attestation::{extract_aaguid_from_attestation, validate_hardware_attestation};
use crate::services::error::ServiceError;
use axum::http::StatusCode;

/// Result of validating a registration attestation.
pub struct ValidatedAttestation {
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
pub fn validate_registration_attestation(
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
