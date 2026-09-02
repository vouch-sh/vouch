// SPDX-License-Identifier: Apache-2.0 OR MIT
//! WebAuthn registration attestation validation.

use crate::attestation::{extract_aaguid_from_attestation, validate_hardware_attestation};
use crate::error::ServiceError;
use axum::http::StatusCode;

/// Result of validating a registration attestation.
#[derive(Debug)]
pub(crate) struct ValidatedAttestation {
    /// The AAGUID extracted from the attestation (if available).
    pub aaguid: Option<String>,
    /// The device name determined from the AAGUID.
    pub device_name: String,
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
/// paths call it with the raw attestation object and the server's AAGUID
/// policy, and it performs every step itself:
///
/// 1. Rejects software passkeys and platform authenticators by format
/// 2. Requires an x5c chain that validates against the pinned Yubico roots
/// 3. Takes the AAGUID from the leaf certificate, not from authData
/// 4. Checks that AAGUID against the configured `AaguidPolicy`
/// 5. Determines the device name from the AAGUID
///
/// Attestation is not optional and there is no setting to relax it. Vouch
/// issues credentials on the strength of a hardware key, and a self-attested
/// registration offers no evidence that a hardware key exists — WebAuthn
/// Level 2 section 6.5.3: "If an authenticator employs self attestation or no
/// attestation, then no provenance information is provided for the Relying
/// Party to base a trust decision on." Accepting one would make the
/// `hardware_verified` claim a statement Vouch cannot support.
///
/// The AAGUID is read from the attestation certificate rather than authData
/// for the same reason. authData is supplied by the client and a forged value
/// there would flow into the `hardware_aaguid` claim, which relying parties
/// use to gate access by authenticator model. Sourcing it from the verified
/// certificate makes that forgery structurally impossible instead of merely
/// checked for.
///
/// The two registration paths use different WebAuthn *verification* libraries
/// — the CLI uses [`crate::crypto::webauthn_verify`], the browser uses
/// `webauthn-rs` — so registration policy deliberately lives in neither.
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
/// authenticator, if no certificate chain was presented, if the chain does not
/// validate against a pinned root, or if the resulting AAGUID is missing or
/// not permitted by the policy.
pub(crate) fn validate_registration_attestation(
    attestation_object: &[u8],
    policy: &vouch_common::AaguidPolicy,
) -> Result<ValidatedAttestation, ServiceError> {
    // Validate attestation format - reject software passkeys and platform authenticators
    let validation = validate_hardware_attestation(attestation_object);
    if let (Some(code), Some(message)) = (validation.error_code(), validation.error_message()) {
        tracing::warn!("Rejected registration: {}", code);
        return Err(ServiceError::api(StatusCode::BAD_REQUEST, code, message));
    }

    // An attestation certificate chain is mandatory, and a malformed one is
    // rejected outright rather than repaired by dropping the offending
    // elements — filtering would let this layer accept a statement the
    // verification library on either path rejects.
    let certs = match crate::attestation::extract_x5c_from_attestation(attestation_object) {
        Ok(Some(certs)) => certs,
        Ok(None) => {
            tracing::warn!(
                "Rejected registration: no attestation certificate chain \
                 (self-attestation)"
            );
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "attestation_cert_required",
                "This server requires authenticators that provide an \
                 attestation certificate chain validating against a \
                 trusted root. Self-attestation is not accepted.",
            ));
        }
        Err(reason) => {
            tracing::warn!("Rejected registration: malformed x5c: {reason}");
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "attestation_chain_invalid",
                "Attestation certificate chain is malformed. Only genuine \
                 hardware authenticators with valid attestation chains are \
                 accepted.",
            ));
        }
    };

    // The AAGUID in authData is client-supplied. It is passed here only so the
    // chain validator can cross-check it against the certificate and reject a
    // statement whose two halves disagree; the value Vouch keeps comes from
    // the certificate below. The all-zero value is not an identity, so it is
    // read as absent.
    let claimed_aaguid =
        extract_aaguid_from_attestation(attestation_object).filter(|a| a != ZERO_AAGUID);

    let attestation = crate::crypto::attestation_chain::validate_attestation_chain(
        &certs,
        claimed_aaguid.as_deref(),
    )
    .map_err(|e| {
        tracing::warn!("Rejected registration: x5c chain validation failed: {e}");
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "attestation_chain_invalid",
            "Attestation certificate chain could not be verified \
             against trusted roots. Only genuine hardware \
             authenticators with valid attestation chains are accepted.",
        )
    })?;

    // The model identity comes from the verified certificate. A chain that
    // validates without the `id-fido-gen-ce-aaguid` extension proves the key
    // is genuine but not which model it is, so it yields no AAGUID rather than
    // falling back to the client's claim.
    let aaguid = attestation.cert_aaguid().map(str::to_owned);

    tracing::info!(
        aaguid = ?aaguid,
        "x5c attestation chain validated"
    );

    // Check AAGUID against configured policy.
    // When the policy is not `Any`, a missing AAGUID must be rejected —
    // otherwise an authenticator whose certificate does not name its model
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
                    "Rejected registration: attestation certificate does \
                     not identify the authenticator model, with non-Any policy"
                );
                return Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "aaguid_missing",
                    "The attestation certificate does not identify the \
                     authenticator model. Registration requires an \
                     identifiable hardware security key when an \
                     AAGUID policy is configured.",
                ));
            }
            Some(_) => {}
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

    /// The fixture with authData's AAGUID zeroed, leaving the certificate as
    /// the only place a model identity can come from.
    fn attestation_with_zeroed_authdata_aaguid() -> Vec<u8> {
        let raw = real_attestation();
        let mut value: Value = ciborium::from_reader(raw.as_slice()).expect("fixture is CBOR");
        if let Value::Map(ref mut entries) = value {
            for (k, v) in entries.iter_mut() {
                if k.as_text() == Some("authData")
                    && let Value::Bytes(ref mut bytes) = *v
                {
                    for byte in bytes.iter_mut().skip(37).take(16) {
                        *byte = 0;
                    }
                }
            }
        }
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).expect("CBOR serialization");
        out
    }

    // ====================================================================
    // Format gate — default-deny, runs first
    // ====================================================================

    #[test]
    fn test_validate_rejects_software_passkey() {
        let att = build_attestation("none", None, None);
        assert!(validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any).is_err());
    }

    #[test]
    fn test_validate_rejects_platform_authenticator() {
        let att = build_attestation("apple", None, None);
        assert!(validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any).is_err());
    }

    #[test]
    fn test_validate_rejects_unknown_format() {
        let att = build_attestation("acme-custom", Some(YUBIKEY_5_NFC_AAGUID), None);
        let err = validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any)
            .expect_err("an unrecognized attestation format must be rejected");
        assert!(
            error_code(&err).contains("unknown_attestation_format"),
            "expected unknown_attestation_format, got {err:?}"
        );
    }

    // ====================================================================
    // Attestation is mandatory, under every configuration
    //
    // WebAuthn L2 section 6.5.3: "If an authenticator employs self attestation
    // or no attestation, then no provenance information is provided for the
    // Relying Party to base a trust decision on." Vouch issues credentials on
    // the strength of a hardware key, so it cannot accept a registration that
    // offers no evidence one exists.
    // ====================================================================

    #[test]
    fn test_self_attestation_is_rejected_under_the_default_policy() {
        // Issue #1111: this registration used to be accepted, and its
        // client-chosen AAGUID went on to become the hardware_aaguid claim.
        let att = build_attestation("packed", Some(YUBIKEY_5_NFC_AAGUID), None);
        let err = validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any)
            .expect_err("self-attestation must be rejected even with no AAGUID policy");
        assert!(
            error_code(&err).contains("attestation_cert_required"),
            "expected attestation_cert_required, got {err:?}"
        );
    }

    #[test]
    fn test_forged_fips_aaguid_cannot_be_registered() {
        // The exploit from issue #1111: forge a FIPS AAGUID into authData
        // under a self-attested packed statement. There is no configuration
        // under which this succeeds any more.
        const YUBIKEY_5C_NANO_FIPS_AAGUID: [u8; 16] = [
            0x28, 0x96, 0x9c, 0x24, 0x04, 0x87, 0x4a, 0x46, 0xbe, 0x39, 0x37, 0xbc, 0x63, 0x37,
            0xa2, 0x4f,
        ];
        assert!(
            vouch_common::is_fips(FIXTURE_AAGUID),
            "fixture AAGUID must be one fips-only accepts, or the test proves nothing"
        );
        let att = build_attestation("packed", Some(YUBIKEY_5C_NANO_FIPS_AAGUID), None);

        for policy in [
            vouch_common::AaguidPolicy::Any,
            vouch_common::AaguidPolicy::FipsOnly,
            allowlist_of(FIXTURE_AAGUID),
        ] {
            let err = validate_registration_attestation(&att, &policy)
                .expect_err("a forged AAGUID must never be registrable");
            assert!(
                error_code(&err).contains("attestation_cert_required"),
                "expected attestation_cert_required, got {err:?}"
            );
        }
    }

    #[test]
    fn test_chain_that_does_not_validate_is_rejected() {
        let att = build_attestation(
            "packed",
            Some(YUBIKEY_5_NFC_AAGUID),
            Some(vec![vec![0xDE, 0xAD, 0xBE, 0xEF]]),
        );
        let err = validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any)
            .expect_err("an x5c chain that does not validate must be rejected");
        assert!(
            error_code(&err).contains("attestation_chain_invalid"),
            "expected attestation_chain_invalid, got {err:?}"
        );
    }

    /// WebAuthn L2 §8.2 CDDL types every x5c element as `bytes`
    /// (`x5c: [ attestnCert: bytes, * (caCert: bytes) ]`). A statement whose
    /// x5c carries the genuine chain plus a junk text element is malformed and
    /// must be rejected at the chokepoint — not repaired by dropping the junk
    /// and validating the survivors, which both verification libraries would
    /// refuse to do (issue #1167).
    #[test]
    fn test_x5c_with_non_byte_string_element_is_rejected() {
        let raw = real_attestation();
        let mut value: Value = ciborium::from_reader(raw.as_slice()).expect("fixture is CBOR");
        if let Value::Map(ref mut entries) = value {
            for (k, v) in entries.iter_mut() {
                if k.as_text() == Some("attStmt")
                    && let Value::Map(ref mut stmt) = *v
                {
                    for (sk, sv) in stmt.iter_mut() {
                        if sk.as_text() == Some("x5c")
                            && let Value::Array(ref mut arr) = *sv
                        {
                            arr.push(Value::Text("junk".to_string()));
                        }
                    }
                }
            }
        }
        let mut att = Vec::new();
        ciborium::into_writer(&value, &mut att).expect("CBOR serialization");

        let err = validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any)
            .expect_err("an x5c with a non-byte-string element must be rejected");
        assert!(
            error_code(&err).contains("attestation_chain_invalid"),
            "expected attestation_chain_invalid, got {err:?}"
        );
    }

    // ====================================================================
    // A genuine YubiKey, and where its identity comes from
    // ====================================================================

    #[test]
    fn test_real_chain_is_accepted_and_names_the_model() {
        let validated = validate_registration_attestation(
            &real_attestation(),
            &vouch_common::AaguidPolicy::Any,
        )
        .expect("a genuine YubiKey attestation must be accepted");
        assert_eq!(validated.aaguid.as_deref(), Some(FIXTURE_AAGUID));
        assert_eq!(validated.device_name, "YubiKey 5C Nano FIPS (Enterprise)");
    }

    #[test]
    fn test_aaguid_comes_from_the_certificate_not_authdata() {
        // authData is client-supplied. Zeroing it leaves the certificate as
        // the only source, and the model identity survives — proving the
        // stored AAGUID is the verified one rather than the claimed one.
        let att = attestation_with_zeroed_authdata_aaguid();
        assert_eq!(
            extract_aaguid_from_attestation(&att).as_deref(),
            Some(ZERO_AAGUID),
            "the fixture's authData AAGUID should now be all zeros"
        );

        let validated = validate_registration_attestation(&att, &vouch_common::AaguidPolicy::Any)
            .expect("a valid chain with no authData AAGUID is still acceptable");
        assert_eq!(validated.aaguid.as_deref(), Some(FIXTURE_AAGUID));
    }

    // ====================================================================
    // AAGUID policy, checked against the certificate's value
    // ====================================================================

    #[test]
    fn test_allowlist_permits_listed_aaguid() {
        let validated =
            validate_registration_attestation(&real_attestation(), &allowlist_of(FIXTURE_AAGUID))
                .expect("a chain-verified AAGUID on the allowlist is accepted");
        assert_eq!(validated.aaguid.as_deref(), Some(FIXTURE_AAGUID));
    }

    #[test]
    fn test_fips_only_permits_a_real_fips_key() {
        assert!(
            validate_registration_attestation(
                &real_attestation(),
                &vouch_common::AaguidPolicy::FipsOnly
            )
            .is_ok()
        );
    }

    #[test]
    fn test_allowlist_rejects_unlisted_aaguid() {
        let err = validate_registration_attestation(
            &real_attestation(),
            &allowlist_of("00000000-0000-0000-0000-000000000001"),
        )
        .expect_err("an unlisted AAGUID is rejected even with a verified chain");
        assert!(
            error_code(&err).contains("aaguid_not_allowed"),
            "expected aaguid_not_allowed, got {err:?}"
        );
    }
}
