// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authentication method reference (AMR) and assurance level (ACR) types.
//!
//! Provides type-safe representations of authentication methods and assurance
//! levels used in access tokens and ID tokens per RFC 9068 Section 2.2.
//!
//! ## Standards
//!
//! - RFC 8176 — Authentication Method Reference Values
//! - RFC 9068 Section 2.2 — RECOMMENDED `amr` and `acr` claims
//! - NIST SP 800-63B — Authentication Assurance Levels (AAL)

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
pub const ACR_AAL3: &str = "urn:nist:authentication:assurance-level:aal3";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

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
    fn test_serde_roundtrip() {
        let methods: Vec<AuthMethod> = AuthMethod::all_fido2().to_vec();
        let json = serde_json::to_string(&methods).unwrap();
        assert_eq!(json, r#"["hwk","pin","user"]"#);

        let deserialized: Vec<AuthMethod> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, methods);
    }

    #[test]
    fn test_deserialize_rejects_unknown() {
        let result: Result<AuthMethod, _> = serde_json::from_str(r#""mfa""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", AuthMethod::HardwareKey), "hwk");
        assert_eq!(format!("{}", AuthMethod::Pin), "pin");
        assert_eq!(format!("{}", AuthMethod::UserPresence), "user");
    }

    #[test]
    fn test_acr_aal3_constant() {
        assert!(ACR_AAL3.starts_with("urn:nist:"));
        assert!(ACR_AAL3.contains("aal3"));
    }
}
