// SPDX-License-Identifier: BUSL-1.1
//! WebAuthn registration attestation validation.

use axum::Json;
use axum::http::StatusCode;
use vouch_common::{ApiError, extract_aaguid_from_attestation, validate_hardware_attestation};

use super::errors::json_error;

/// Result of validating a registration attestation.
pub struct ValidatedAttestation {
    /// The AAGUID extracted from the attestation (if available).
    pub aaguid: Option<String>,
    /// The device name determined from the AAGUID.
    pub device_name: String,
}

/// Validate a WebAuthn registration attestation.
///
/// This performs common validation for both CLI and browser registration:
/// 1. Validates the attestation is from a hardware authenticator (not software/platform)
/// 2. Extracts the AAGUID from the attestation
/// 3. Determines the device name from the AAGUID
///
/// Duplicate credential prevention is handled by WebAuthn's `excludeCredentials`
/// mechanism, which checks on the authenticator itself during `navigator.credentials.create()`.
///
/// # Errors
///
/// Returns an error if the attestation is from a software passkey or platform authenticator.
pub fn validate_registration_attestation(
    attestation_object: &[u8],
) -> Result<ValidatedAttestation, (StatusCode, Json<ApiError>)> {
    // Validate attestation format - reject software passkeys and platform authenticators
    let validation = validate_hardware_attestation(attestation_object);
    if let (Some(code), Some(message)) = (validation.error_code(), validation.error_message()) {
        tracing::warn!("Rejected registration: {}", code);
        return Err(json_error(StatusCode::BAD_REQUEST, code, message));
    }

    // Extract AAGUID from the attestation object
    let aaguid = extract_aaguid_from_attestation(attestation_object);

    // Determine device name from AAGUID if known
    let device_name = aaguid
        .as_deref()
        .and_then(vouch_common::lookup_device_model)
        .unwrap_or("Security Key")
        .to_string();

    Ok(ValidatedAttestation {
        aaguid,
        device_name,
    })
}
