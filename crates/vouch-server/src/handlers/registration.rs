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

/// The all-zero AAGUID, which means "this authenticator does not identify a
/// model" rather than "the model is zero".
///
/// CTAP 2.0 section 7.2 specifies the authenticator data a platform
/// synthesizes from a CTAP1/U2F response as carrying an AAGUID "Initialized
/// with all zeros", and WebAuthn Level 2 section 5.1.3 has the client
/// substitute the same value when attestation conveyance is `none`.
const ZERO_AAGUID: &str = "00000000-0000-0000-0000-000000000000";

/// Validate a WebAuthn registration attestation.
///
/// This is the single chokepoint for registration policy. Both the CLI
/// (`/v1/keys/register/complete`) and browser (`/enroll/webauthn/complete`)
/// paths call it with the raw attestation object and the server's
/// configuration, and it performs every step itself:
///
/// 1. Rejects software passkeys and platform authenticators by format
/// 2. Validates the x5c certificate chain against the pinned roots
/// 3. Enforces `require_attestation_cert`
/// 4. Checks the AAGUID against the configured `AaguidPolicy`
/// 5. Determines the device name from the AAGUID
///
/// The two paths use different WebAuthn *verification* libraries — the CLI
/// uses [`crate::crypto::webauthn_verify`], the browser uses `webauthn-rs` —
/// so registration policy deliberately does not live in either of them.
/// Deciding it here, from the attestation bytes and the server config alone,
/// is what guarantees the two paths accept and reject exactly the same
/// registrations for exactly the same reasons.
///
/// Duplicate credential prevention is handled by WebAuthn's `excludeCredentials`
/// mechanism, which checks on the authenticator itself during `navigator.credentials.create()`.
///
/// # Errors
///
/// Returns an error if the attestation is from a software passkey or platform
/// authenticator, if a presented certificate chain does not validate, if a
/// chain is required but absent, or if the AAGUID is missing, not permitted by
/// the policy, or not vouched for by the certificate chain.
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

    // The AAGUID in authData is self-reported and forgeable on its own. The
    // all-zero value is not an identity, so it is read as absent.
    let aaguid = extract_aaguid_from_attestation(attestation_object).filter(|a| a != ZERO_AAGUID);

    // Validate the certificate chain whenever one is presented. An x5c array
    // that does not chain to a pinned root is a stronger signal than no chain
    // at all, so it is rejected regardless of configuration rather than
    // degraded to "unattested".
    let attestation = match crate::attestation::extract_x5c_from_attestation(attestation_object) {
        Some(certs) => {
            match crate::crypto::attestation_chain::validate_attestation_chain(
                &certs,
                aaguid.as_deref(),
            ) {
                Ok(proof) => {
                    tracing::info!(
                        cert_aaguid = ?proof.cert_aaguid(),
                        "x5c attestation chain validated"
                    );
                    Some(proof)
                }
                Err(e) => {
                    tracing::warn!("Rejected registration: x5c chain validation failed: {e}");
                    return Err(ServiceError::api(
                        StatusCode::BAD_REQUEST,
                        "attestation_chain_invalid",
                        "Attestation certificate chain could not be \
                         verified against trusted roots. Only genuine \
                         hardware authenticators with valid attestation \
                         chains are accepted.",
                    ));
                }
            }
        }
        None => None,
    };

    // When require_attestation_cert is enabled, a chain must have been
    // presented and validated. Self-attestation carries no provenance:
    // WebAuthn Level 2 section 6.5.3 — "If an authenticator employs self
    // attestation or no attestation, then no provenance information is
    // provided for the Relying Party to base a trust decision on."
    if require_attestation_cert && attestation.is_none() {
        tracing::warn!(
            "Rejected registration: attestation certificate chain \
             required but not presented"
        );
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "attestation_cert_required",
            "This server requires authenticators that provide an \
             attestation certificate chain validating against a \
             trusted root. Self-attestation is not accepted.",
        ));
    }

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

    /// A real `packed` attestation captured from a YubiKey 5C Nano FIPS
    /// (Enterprise), whose chain validates against a pinned Yubico root and
    /// whose leaf names the model. Synthetic certificates cannot chain to
    /// `PINNED_ROOTS`, so this is the only way to exercise the accept path.
    /// See `crypto/attestation_chain/fixtures/README.md`.
    fn real_attestation() -> Vec<u8> {
        use base64::Engine as _;
        let b64 = include_str!(
            "../crypto/attestation_chain/fixtures/yubikey-5c-nano-fips-enterprise.attestation.b64"
        );
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64.trim())
            .expect("fixture is valid base64url")
    }

    /// AAGUID of the authenticator the fixture came from.
    const FIXTURE_AAGUID: &str = "28969c24-0487-4a46-be39-37bc6337a24f";

    fn allowlist_of(aaguid: &str) -> vouch_common::AaguidPolicy {
        let mut set = HashSet::new();
        set.insert(aaguid.to_string());
        vouch_common::AaguidPolicy::AllowList(set)
    }

    fn error_code(err: &ServiceError) -> String {
        format!("{err:?}")
    }

    // ====================================================================
    // Format gate — default-deny, runs before everything else
    // ====================================================================

    #[test]
    fn test_validate_packed_any_policy() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let validated =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false)
                .expect("should succeed");
        assert!(validated.aaguid.is_some());
        assert!(validated.attestation.is_none());
    }

    #[test]
    fn test_validate_rejects_software_passkey() {
        let att = build_attestation("none", None, None);
        assert!(
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false)
                .is_err()
        );
    }

    #[test]
    fn test_validate_rejects_platform_authenticator() {
        let att = build_attestation("apple", None, None);
        assert!(
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false)
                .is_err()
        );
    }

    #[test]
    fn test_validate_rejects_unknown_format() {
        let att = build_attestation("acme-custom", Some(YUBIKEY_5_NFC_AAGUID), None);
        let err = validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false)
            .expect_err("an unrecognized attestation format must be rejected");
        assert!(
            error_code(&err).contains("unknown_attestation_format"),
            "expected unknown_attestation_format, got {err:?}"
        );
    }

    #[test]
    fn test_validate_accepts_fido_u2f_as_hardware() {
        let att = build_attestation("fido-u2f", Some(YUBIKEY_5_NFC_AAGUID), None);
        assert!(
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false)
                .is_ok(),
            "fido-u2f is a hardware format"
        );
    }

    // ====================================================================
    // A presented chain must validate, whatever the configuration
    // ====================================================================

    #[test]
    fn test_presented_chain_must_validate_even_under_default_config() {
        // Bytes that are not a certificate. Offering a chain that does not
        // verify is a stronger signal than offering none, so it is rejected
        // without needing require_attestation_cert or a policy.
        let att = build_attestation(
            "packed",
            Some(YUBIKEY_5_NFC_AAGUID),
            Some(vec![vec![0xDE, 0xAD, 0xBE, 0xEF]]),
        );
        let err = validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false)
            .expect_err("an x5c chain that does not validate must be rejected");
        assert!(
            error_code(&err).contains("attestation_chain_invalid"),
            "expected attestation_chain_invalid, got {err:?}"
        );
    }

    #[test]
    fn test_real_chain_validates_and_names_the_model() {
        let validated = validate_registration_attestation(
            &real_attestation(),
            &vouch_common::AaguidPolicy::Any,
            true,
        )
        .expect("a genuine YubiKey attestation must be accepted");
        assert_eq!(validated.aaguid.as_deref(), Some(FIXTURE_AAGUID));
        assert_eq!(
            validated
                .attestation
                .as_ref()
                .and_then(AttestationProof::cert_aaguid),
            Some(FIXTURE_AAGUID)
        );
    }

    // ====================================================================
    // require_attestation_cert demands a validated chain
    // ====================================================================

    #[test]
    fn test_require_cert_rejects_self_attestation() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let err = validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, true)
            .expect_err("self-attestation must be rejected when a chain is required");
        assert!(
            error_code(&err).contains("attestation_cert_required"),
            "expected attestation_cert_required, got {err:?}"
        );
    }

    #[test]
    fn test_require_cert_accepts_real_chain() {
        assert!(
            validate_registration_attestation(
                &real_attestation(),
                &vouch_common::AaguidPolicy::Any,
                true
            )
            .is_ok()
        );
    }

    // ====================================================================
    // AAGUID policy requires a chain that names the model
    //
    // WebAuthn L2 section 7.1 step 25: registering a credential whose
    // attestation is not trustworthy means "the Relying Party is asserting
    // there is no cryptographic proof that the public key credential has been
    // generated by a particular authenticator model". A configured policy
    // asserts the opposite, so the two cannot both hold.
    // ====================================================================

    #[test]
    fn test_allowlist_permits_listed_aaguid_with_verified_chain() {
        let validated = validate_registration_attestation(
            &real_attestation(),
            &allowlist_of(FIXTURE_AAGUID),
            false,
        )
        .expect("a chain-verified AAGUID on the allowlist is accepted");
        assert!(validated.attestation.is_some());
    }

    #[test]
    fn test_allowlist_rejects_self_attested_aaguid() {
        // The issue #1111 bypass: a self-attested registration naming an
        // allowlisted AAGUID. No chain, so no model identity.
        let aaguid_str = "cb69481e-8ff7-4039-93ec-0a2729a154a8";
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let err = validate_registration_attestation(&att, &allowlist_of(aaguid_str), false)
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
            vouch_common::is_fips(FIXTURE_AAGUID),
            "fixture AAGUID must be one fips-only accepts, or the test proves nothing"
        );

        let att = build_attestation("packed", Some(YUBIKEY_5C_NANO_FIPS_AAGUID), None);
        let err =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::FipsOnly, false)
                .expect_err("a forged FIPS AAGUID must not satisfy fips-only");
        assert!(
            error_code(&err).contains("attestation_not_verified"),
            "expected attestation_not_verified, got {err:?}"
        );
    }

    #[test]
    fn test_validate_allowlist_rejects_unlisted_aaguid() {
        let err = validate_registration_attestation(
            &real_attestation(),
            &allowlist_of("00000000-0000-0000-0000-000000000001"),
            false,
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
        let err =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::FipsOnly, false)
                .expect_err("a missing AAGUID must not bypass the policy");
        assert!(
            error_code(&err).contains("aaguid_missing"),
            "expected aaguid_missing, got {err:?}"
        );
    }

    #[test]
    fn test_zero_aaguid_is_read_as_absent() {
        // CTAP 2.0 section 7.2 and WebAuthn L2 section 5.1.3 both use the
        // all-zero AAGUID to mean "no model conveyed", so it must not be
        // treated as an identity a policy could match.
        let att = build_attestation("packed", Some([0x00; 16]), None);
        let validated =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false)
                .expect("should succeed under the default policy");
        assert_eq!(validated.aaguid, None);
        assert_eq!(validated.device_name, "Security Key");

        let err =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::FipsOnly, false)
                .expect_err("an absent AAGUID cannot satisfy a policy");
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
        assert!(
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false)
                .is_ok()
        );
    }

    // ====================================================================
    // Device naming
    // ====================================================================

    #[test]
    fn test_validate_known_aaguid_sets_device_name() {
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let validated =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false)
                .expect("should succeed");
        assert_ne!(validated.device_name, "Security Key");
    }

    #[test]
    fn test_validate_unknown_aaguid_uses_default_name() {
        let att = build_attestation("packed", Some([0x11; 16]), None);
        let validated =
            validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any, false)
                .expect("should succeed");
        assert_eq!(validated.device_name, "Security Key");
    }
}
