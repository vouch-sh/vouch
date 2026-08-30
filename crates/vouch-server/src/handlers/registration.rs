// SPDX-License-Identifier: Apache-2.0 OR MIT
//! WebAuthn registration attestation validation.

use crate::attestation::{extract_aaguid_from_attestation, validate_hardware_attestation};
use crate::crypto::attestation_chain::AttestationProof;
use crate::error::ServiceError;
use axum::http::StatusCode;

/// Result of validating a registration attestation.
#[derive(Debug)]
pub(crate) struct ValidatedAttestation {
    /// The AAGUID extracted from the attestation (if available).
    pub aaguid: Option<String>,
    /// The device name determined from the AAGUID.
    pub device_name: String,
    /// Whether the attestation was cryptographically verified via x5c chain.
    pub attestation: Option<AttestationProof>,
}

/// Validate a WebAuthn registration attestation.
///
/// This performs common validation for both CLI and browser registration:
/// 1. Validates the attestation is from a hardware authenticator (not software/platform)
/// 2. Enforces `require_attestation_cert` against the caller's chain proof
/// 3. Checks the AAGUID against the configured `AaguidPolicy`
/// 4. Extracts the AAGUID from the attestation
/// 5. Determines the device name from the AAGUID
///
/// `attestation` is the result of running
/// [`validate_attestation_chain`](crate::crypto::attestation_chain::validate_attestation_chain)
/// over the attestation statement's x5c chain. Callers must run it *before*
/// calling this function: an
/// [`AttestationProof`](crate::crypto::attestation_chain::AttestationProof)
/// cannot be constructed any other way, so requiring it here is what stops an
/// AAGUID policy from being satisfied by an unverified, forgeable value.
///
/// Duplicate credential prevention is handled by WebAuthn's `excludeCredentials`
/// mechanism, which checks on the authenticator itself during `navigator.credentials.create()`.
///
/// # Errors
///
/// Returns an error if the attestation is from a software passkey or platform
/// authenticator, if a certificate chain is required but was not verified, or
/// if the AAGUID is missing, not permitted by the policy, or not vouched for
/// by the certificate chain.
pub(crate) fn validate_registration_attestation(
    attestation_object: &[u8],
    policy: &vouch_common::AaguidPolicy,
    require_attestation_cert: bool,
    attestation: Option<AttestationProof>,
) -> Result<ValidatedAttestation, ServiceError> {
    // Validate attestation format - reject software passkeys and platform authenticators
    let validation = validate_hardware_attestation(attestation_object);
    if let (Some(code), Some(message)) = (validation.error_code(), validation.error_message()) {
        tracing::warn!("Rejected registration: {}", code);
        return Err(ServiceError::api(StatusCode::BAD_REQUEST, code, message));
    }

    // When require_attestation_cert is enabled, the chain must have *validated*
    // against a pinned root, not merely been present. An x5c array carrying an
    // attacker's self-signed certificate proves nothing.
    if require_attestation_cert && attestation.is_none() {
        tracing::warn!(
            "Rejected registration: attestation certificate chain \
             required but not verified"
        );
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "attestation_cert_required",
            "This server requires authenticators that provide an \
             attestation certificate chain validating against a \
             trusted root. Self-attestation is not accepted.",
        ));
    }

    // Extract AAGUID from the attestation object's authData. This value is
    // self-reported and forgeable on its own; the policy branch below only
    // trusts it when the certificate chain vouches for it.
    let aaguid = extract_aaguid_from_attestation(attestation_object);

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
            // AAGUID is present and permitted. WebAuthn Level 2 section 7.1
            // step 25: registering a credential whose attestation is not
            // trustworthy means "the Relying Party is asserting there is no
            // cryptographic proof that the public key credential has been
            // generated by a particular authenticator model". A configured
            // policy is the operator asserting the opposite, so the model
            // identity has to come from the certificate rather than from
            // authData alone.
            Some(_) => {
                if attestation
                    .as_ref()
                    .and_then(AttestationProof::cert_aaguid)
                    .is_none()
                {
                    tracing::warn!(
                        aaguid = ?aaguid,
                        chain_validated = attestation.is_some(),
                        "Rejected registration: AAGUID policy configured but \
                         the AAGUID is not vouched for by an attestation \
                         certificate"
                    );
                    return Err(ServiceError::api(
                        StatusCode::BAD_REQUEST,
                        "attestation_not_verified",
                        "The authenticator's identity could not be \
                         cryptographically verified. This server restricts \
                         which authenticator models may enroll, which \
                         requires an attestation certificate chain that \
                         identifies the model.",
                    ));
                }
            }
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
        attestation,
    })
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

    /// A proof standing in for a validated chain whose leaf certificate
    /// carried the `id-fido-gen-ce-aaguid` extension.
    fn proof_with_cert_aaguid(aaguid: &str) -> Option<AttestationProof> {
        Some(AttestationProof::for_test(Some(aaguid.to_string())))
    }

    /// A proof standing in for a chain that validated but whose leaf carried
    /// no AAGUID extension, so nothing vouches for the authData AAGUID.
    fn proof_without_cert_aaguid() -> Option<AttestationProof> {
        Some(AttestationProof::for_test(None))
    }

    fn allowlist_of(aaguid: &str) -> vouch_common::AaguidPolicy {
        let mut set = HashSet::new();
        set.insert(aaguid.to_string());
        vouch_common::AaguidPolicy::AllowList(set)
    }

    fn error_code(err: &ServiceError) -> String {
        format!("{err:?}")
    }

    // ====================================================================
    // Format gate
    // ====================================================================

    #[test]
    fn test_validate_packed_any_policy() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false, None);
        let validated = result.expect("should succeed");
        assert!(validated.aaguid.is_some());
        assert!(validated.attestation.is_none());
    }

    #[test]
    fn test_validate_rejects_software_passkey() {
        let att = build_attestation("none", None, None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_platform_authenticator() {
        let att = build_attestation("apple", None, None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false, None);
        assert!(result.is_err());
    }

    /// The hardware-only gate is default-deny and runs before everything else,
    /// so an unrecognized format is rejected even when it carries an
    /// allowlisted AAGUID and a verified chain. Only `packed` and `fido-u2f`
    /// are admitted; nothing about the attestation proof can buy an exemption.
    #[test]
    fn test_validate_rejects_unknown_format_despite_verified_chain() {
        let aaguid_str = "cb69481e-8ff7-4039-93ec-0a2729a154a8";
        let att = build_attestation("acme-custom", Some(YUBIKEY_5_NFC_AAGUID), None);
        let err = validate_registration_attestation(
            &att,
            &allowlist_of(aaguid_str),
            false,
            proof_with_cert_aaguid(aaguid_str),
        )
        .expect_err("an unrecognized attestation format must be rejected");
        assert!(
            error_code(&err).contains("unknown_attestation_format"),
            "expected unknown_attestation_format, got {err:?}"
        );
    }

    /// `fido-u2f` is hardware and stays registrable, so the gate above is a
    /// format allowlist rather than a ban on everything but `packed`.
    #[test]
    fn test_validate_accepts_fido_u2f_as_hardware() {
        let att = build_attestation("fido-u2f", Some(YUBIKEY_5_NFC_AAGUID), None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false, None);
        assert!(result.is_ok(), "fido-u2f is a hardware format");
    }

    // ====================================================================
    // AAGUID policy requires a verified chain
    //
    // WebAuthn L2 section 7.1 step 25: registering a credential whose
    // attestation is not trustworthy means "the Relying Party is asserting
    // there is no cryptographic proof that the public key credential has been
    // generated by a particular authenticator model". A configured AAGUID
    // policy asserts the opposite, so the two cannot both hold.
    // ====================================================================

    #[test]
    fn test_allowlist_permits_listed_aaguid_with_verified_chain() {
        let aaguid_str = "cb69481e-8ff7-4039-93ec-0a2729a154a8";
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let result = validate_registration_attestation(
            &att,
            &allowlist_of(aaguid_str),
            false,
            proof_with_cert_aaguid(aaguid_str),
        );
        let validated = result.expect("a chain-verified AAGUID on the allowlist is accepted");
        assert!(validated.attestation.is_some());
    }

    #[test]
    fn test_allowlist_rejects_self_attested_aaguid() {
        // The issue #1111 bypass: a self-attested registration naming an
        // allowlisted AAGUID. No chain, so no proof, so no model identity.
        let aaguid_str = "cb69481e-8ff7-4039-93ec-0a2729a154a8";
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let err = validate_registration_attestation(&att, &allowlist_of(aaguid_str), false, None)
            .expect_err("a self-attested AAGUID must not satisfy an allowlist");
        assert!(
            error_code(&err).contains("attestation_not_verified"),
            "expected attestation_not_verified, got {err:?}"
        );
    }

    #[test]
    fn test_fips_only_rejects_forged_fips_aaguid() {
        // The exploit scenario from issue #1111: forge a FIPS AAGUID into
        // authData under a self-attested packed statement to satisfy
        // VOUCH_ALLOWED_AAGUIDS=fips-only.
        const YUBIKEY_5C_NANO_FIPS_AAGUID: [u8; 16] = [
            0x28, 0x96, 0x9c, 0x24, 0x04, 0x87, 0x4a, 0x46, 0xbe, 0x39, 0x37, 0xbc, 0x63, 0x37,
            0xa2, 0x4f,
        ];
        assert!(
            vouch_common::is_fips("28969c24-0487-4a46-be39-37bc6337a24f"),
            "fixture AAGUID must be one fips-only accepts, or the test proves nothing"
        );

        let att = build_attestation("packed", Some(YUBIKEY_5C_NANO_FIPS_AAGUID), None);
        let err = validate_registration_attestation(
            &att,
            &vouch_common::AaguidPolicy::FipsOnly,
            false,
            None,
        )
        .expect_err("a forged FIPS AAGUID must not satisfy fips-only");
        assert!(
            error_code(&err).contains("attestation_not_verified"),
            "expected attestation_not_verified, got {err:?}"
        );
    }

    #[test]
    fn test_allowlist_rejects_chain_without_aaguid_extension() {
        // WebAuthn L2 section 8.2.1 makes id-fido-gen-ce-aaguid mandatory only
        // when the root serves multiple models. A chain that validated without
        // it proves the key is genuine but says nothing about which model, so
        // the cross-check in validate_attestation_chain never ran.
        let aaguid_str = "cb69481e-8ff7-4039-93ec-0a2729a154a8";
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let err = validate_registration_attestation(
            &att,
            &allowlist_of(aaguid_str),
            false,
            proof_without_cert_aaguid(),
        )
        .expect_err("a chain that does not name the model must not satisfy a policy");
        assert!(
            error_code(&err).contains("attestation_not_verified"),
            "expected attestation_not_verified, got {err:?}"
        );
    }

    #[test]
    fn test_validate_allowlist_rejects_unlisted_aaguid() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let err = validate_registration_attestation(
            &att,
            &allowlist_of("00000000-0000-0000-0000-000000000000"),
            false,
            proof_with_cert_aaguid("cb69481e-8ff7-4039-93ec-0a2729a154a8"),
        )
        .expect_err("an unlisted AAGUID is rejected even with a verified chain");
        assert!(
            error_code(&err).contains("aaguid_not_allowed"),
            "expected aaguid_not_allowed, got {err:?}"
        );
    }

    #[test]
    fn test_validate_missing_aaguid_with_non_any_policy() {
        // No AAGUID in authData (UP flag only, no AT flag)
        let att = build_attestation("packed", None, None);
        let err = validate_registration_attestation(
            &att,
            &vouch_common::AaguidPolicy::FipsOnly,
            false,
            None,
        )
        .expect_err("a missing AAGUID must not bypass the policy");
        assert!(
            error_code(&err).contains("aaguid_missing"),
            "expected aaguid_missing, got {err:?}"
        );
    }

    #[test]
    fn test_any_policy_still_accepts_self_attestation() {
        // The default configuration is unchanged: without a model restriction
        // a self-attested hardware key still enrolls.
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let result =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false, None);
        assert!(result.is_ok());
    }

    // ====================================================================
    // require_attestation_cert demands a validated chain, not a present x5c
    // ====================================================================

    #[test]
    fn test_require_cert_rejects_missing_proof() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let err =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, true, None)
                .expect_err("self-attestation must be rejected when a cert is required");
        assert!(
            error_code(&err).contains("attestation_cert_required"),
            "expected attestation_cert_required, got {err:?}"
        );
    }

    #[test]
    fn test_require_cert_rejects_unvalidated_x5c() {
        // Presence is not validation: an attacker can put any bytes in x5c.
        // Before this change the flag was satisfied by the array alone.
        let att = build_attestation(
            "packed",
            Some(YUBIKEY_5_NFC_AAGUID),
            Some(vec![vec![0xDE, 0xAD]]),
        );
        let err =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, true, None)
                .expect_err("an x5c array that did not validate must not satisfy the flag");
        assert!(
            error_code(&err).contains("attestation_cert_required"),
            "expected attestation_cert_required, got {err:?}"
        );
    }

    #[test]
    fn test_require_cert_accepts_validated_chain() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let result = validate_registration_attestation(
            &att,
            &vouch_common::AaguidPolicy::Any,
            true,
            proof_with_cert_aaguid("cb69481e-8ff7-4039-93ec-0a2729a154a8"),
        );
        assert!(result.is_ok());
    }

    // ====================================================================
    // Device naming
    // ====================================================================

    #[test]
    fn test_validate_known_aaguid_sets_device_name() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let validated =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false, None)
                .expect("should succeed");
        assert_ne!(validated.device_name, "Security Key");
    }

    #[test]
    fn test_validate_unknown_aaguid_uses_default_name() {
        let att = build_attestation("packed", Some([0x00; 16]), None);
        let validated =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false, None)
                .expect("should succeed");
        assert_eq!(validated.device_name, "Security Key");
    }
}
