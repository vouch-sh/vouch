// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authentication assurance vocabulary shared across layers.
//!
//! Implements:
//! - RFC 8176 — Authentication Method Reference Values
//! - RFC 9068 Section 2.2 — JWT Access Token claims (`amr`, `acr`, `auth_time`)
//!
//! Lives at the crate root because the vocabulary is consumed on both sides
//! of the layer boundary: the db layer records a [`HardwareVerification`] on
//! device authorization approvals, and the services layer expands it into
//! token claims.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Authentication method reference value (RFC 8176).
///
/// Represents a single authentication method used during user authentication.
/// Vouch always uses FIDO2 hardware keys with PIN and user presence, so all
/// three methods are present in every authentication event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// RFC 8176: Proof-of-possession of a hardware-secured key.
    HardwareKey,
    /// RFC 8176: Personal Identification Number or pattern verified on device.
    Pin,
    /// RFC 8176: User presence test (physical interaction with authenticator).
    UserPresence,
}

impl AuthMethod {
    /// Return the wire-format string per RFC 8176.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HardwareKey => "hwk",
            Self::Pin => "pin",
            Self::UserPresence => "user",
        }
    }

    /// All authentication methods used in a FIDO2 hardware key flow.
    ///
    /// Vouch always requires hardware key + PIN + user presence, so this
    /// returns all three methods.
    #[must_use]
    pub const fn all_fido2() -> &'static [Self] {
        &[Self::HardwareKey, Self::Pin, Self::UserPresence]
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for AuthMethod {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AuthMethod {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "hwk" => Ok(Self::HardwareKey),
            "pin" => Ok(Self::Pin),
            "user" => Ok(Self::UserPresence),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["hwk", "pin", "user"],
            )),
        }
    }
}

/// NIST SP 800-63B AAL3: Hardware-based multi-factor authentication.
///
/// FIDO2 hardware key + PIN + user presence meets AAL3 per NIST SP 800-63B.
pub(crate) const ACR_AAL3: &str = "urn:nist:authentication:assurance-level:aal3";

/// Authentication assurance level for an issued token.
///
/// Bundles `hardware_verified`, `auth_time`, `amr`, and `acr` into a single
/// type to prevent inconsistent combinations (e.g., `hardware_verified: true`
/// with `amr: None`).
///
/// `auth_time` lives inside [`Self::Verified`] rather than beside this enum
/// because it records *when the FIDO2 assertion happened*. A token that ran no
/// assertion has no such instant, and [`Self::NotVerified`] has nowhere to put
/// one — so an enrollment bootstrap or M2M token cannot carry an `auth_time`
/// that a freshness gate would read as proof of recent FIDO2 (issue #1114).
#[derive(Debug, Clone)]
pub enum HardwareVerification {
    /// FIDO2 hardware key verified by Vouch (UP + UV).
    /// Sets `hardware_verified: true`, `amr: [hwk, pin, user]`,
    /// `acr: urn:nist:...:aal3`.
    Verified {
        /// When the assertion happened (Unix seconds), for the `auth_time`
        /// claim. `None` when verification is inherited rather than observed
        /// — RFC 8693 token exchange runs no ceremony of its own, and device
        /// approvals written before the ceremony instant was recorded lost
        /// it. Freshness gates read `None` as epoch and challenge.
        auth_time: Option<i64>,
    },
    /// No hardware verification performed (M2M, JWT bearer, etc.).
    /// Sets `hardware_verified: false`, `auth_time: None`, `amr: None`,
    /// `acr: None`.
    NotVerified,
}

impl HardwareVerification {
    /// Whether FIDO2 hardware verification was performed.
    #[must_use]
    pub(crate) fn hardware_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// RFC 9068 Section 2.2.1 / OIDC Core Section 2: when the End-User
    /// authentication occurred. Absent unless FIDO2 ran.
    #[must_use]
    pub(crate) fn auth_time(&self) -> Option<i64> {
        match self {
            Self::Verified { auth_time } => *auth_time,
            Self::NotVerified => None,
        }
    }

    /// RFC 8176 authentication methods reference.
    #[must_use]
    pub(crate) fn amr(&self) -> Option<Vec<AuthMethod>> {
        match self {
            Self::Verified { .. } => Some(AuthMethod::all_fido2().to_vec()),
            Self::NotVerified => None,
        }
    }

    /// RFC 9068 authentication context class reference.
    #[must_use]
    pub(crate) fn acr(&self) -> Option<String> {
        match self {
            Self::Verified { .. } => Some(ACR_AAL3.to_string()),
            Self::NotVerified => None,
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    // AMR tests (RFC 8176)

    #[test]
    fn test_auth_method_wire_format() {
        assert_eq!(AuthMethod::HardwareKey.as_str(), "hwk");
        assert_eq!(AuthMethod::Pin.as_str(), "pin");
        assert_eq!(AuthMethod::UserPresence.as_str(), "user");
    }

    #[test]
    fn test_all_fido2() {
        let methods = AuthMethod::all_fido2();
        assert_eq!(methods.len(), 3);
        assert_eq!(methods[0], AuthMethod::HardwareKey);
        assert_eq!(methods[1], AuthMethod::Pin);
        assert_eq!(methods[2], AuthMethod::UserPresence);
    }

    #[test]
    fn test_auth_method_serde_roundtrip() {
        let methods: Vec<AuthMethod> = AuthMethod::all_fido2().to_vec();
        let json = serde_json::to_string(&methods).unwrap();
        assert_eq!(json, r#"["hwk","pin","user"]"#);

        let deserialized: Vec<AuthMethod> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, methods);
    }

    #[test]
    fn test_auth_method_deserialize_rejects_unknown() {
        let result: Result<AuthMethod, _> = serde_json::from_str(r#""mfa""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_method_display() {
        assert_eq!(format!("{}", AuthMethod::HardwareKey), "hwk");
        assert_eq!(format!("{}", AuthMethod::Pin), "pin");
        assert_eq!(format!("{}", AuthMethod::UserPresence), "user");
    }

    /// The claim mapping the browser-enrollment regression test from #1124
    /// used to assert end to end. Registration now requires an attestation
    /// chain no test can mint, so the mapping is pinned here instead.
    #[test]
    fn test_verified_hardware_sets_amr_acr_and_flag() {
        let verified = HardwareVerification::Verified {
            auth_time: Some(42),
        };
        assert!(verified.hardware_verified());
        assert_eq!(verified.acr().as_deref(), Some(ACR_AAL3));
        let amr = verified.amr().expect("Verified must set amr");
        for expected in AuthMethod::all_fido2() {
            assert!(
                amr.contains(expected),
                "amr must include {expected:?}, got {amr:?}"
            );
        }

        // The negative half: without a FIDO2 ceremony none of the three are
        // asserted, so a machine token cannot look like a hardware login.
        let not_verified = HardwareVerification::NotVerified;
        assert!(!not_verified.hardware_verified());
        assert!(not_verified.amr().is_none());
        assert!(not_verified.acr().is_none());
    }

    #[test]
    fn test_acr_aal3_constant() {
        assert!(ACR_AAL3.starts_with("urn:nist:"));
        assert!(ACR_AAL3.contains("aal3"));
    }
}
