// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWS signing algorithms.
//!
//! The `alg` values Vouch signs and verifies with, and the policy sets that
//! decide which are acceptable where. This lives in `crypto` because the JOSE
//! header ([`crate::crypto::jwt::JoseHeader`]) is typed on it and `crypto`
//! imports no other layer; `db` and `services` consume it from here.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An `alg` value that is not one Vouch signs or verifies with.
///
/// Carries the rejected name so a caller can report which algorithm it
/// refused rather than reporting a parse failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("Unknown JWS algorithm: {0}")]
pub struct UnknownJwsAlgorithm(pub String);

/// JWS signing algorithm for OAuth 2.0 / OIDC.
///
/// Only asymmetric algorithms are supported. Symmetric (HS*)
/// and `none` are rejected at registration time via serde deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum JwsAlgorithm {
    /// ECDSA using P-256 and SHA-256.
    ///
    /// A `serde(rename)` takes a literal, so this is the one spelling of
    /// `ES256` that cannot reference [`vouch_common::protocol::JWS_ALG_ES256`]
    /// directly; `jws_algorithm_serde_matches_protocol_constant` pins the two
    /// together instead.
    #[default]
    #[serde(rename = "ES256")]
    Es256,
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    #[serde(rename = "RS256")]
    Rs256,
    /// RSASSA-PSS using SHA-256.
    #[serde(rename = "PS256")]
    Ps256,
    /// Edwards-curve Digital Signature Algorithm.
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl JwsAlgorithm {
    /// Returns the canonical string representation used in the wire format.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Es256 => vouch_common::protocol::JWS_ALG_ES256,
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
            Self::EdDsa => "EdDSA",
        }
    }

    /// Algorithms permitted for FAPI 2.0-scoped signing (DPoP proofs, token endpoint
    /// client authentication, and other FAPI-profiled JWTs).
    ///
    /// FAPI 2.0 Security Profile, Section 5.4.1 "General requirements"
    /// (<https://openid.net/specs/fapi-security-profile-2_0-final.html>) reads:
    ///
    /// > Authorization servers, clients, and resource servers when creating or processing
    /// > JWTs shall adhere to \[RFC8725\]; use `PS256`, `ES256`, or `EdDSA` (using the
    /// > `Ed25519` variant) algorithms; and not use or accept the `none` algorithm.
    ///
    /// This is a `shall` (MUST-strength) requirement, and the three-algorithm list is
    /// restrictive: `RS256` is deliberately not among them.
    pub const FAPI_ALLOWED: [Self; 3] = [Self::Es256, Self::Ps256, Self::EdDsa];

    /// Algorithms permitted for `private_key_jwt` (RFC 7523 §2.2) client-assertion
    /// signing by clients not opted into FAPI 2.0 (`FapiProfile::None`):
    /// [`Self::FAPI_ALLOWED`] plus `RS256`.
    ///
    /// `FapiProfile::client_assertion_algorithms` selects this per client, and
    /// `FapiProfile::client_assertion_algorithms_union` — what discovery's
    /// `token_endpoint_auth_signing_alg_values_supported` (`services/oidc/discovery.rs`)
    /// actually advertises — is derived from it, not an independently maintained copy.
    pub const CLIENT_ASSERTION_ALLOWED: [Self; 4] =
        [Self::Es256, Self::Rs256, Self::Ps256, Self::EdDsa];
}

impl std::str::FromStr for JwsAlgorithm {
    type Err = UnknownJwsAlgorithm;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            vouch_common::protocol::JWS_ALG_ES256 => Ok(Self::Es256),
            "RS256" => Ok(Self::Rs256),
            "PS256" => Ok(Self::Ps256),
            "EdDSA" => Ok(Self::EdDsa),
            _ => Err(UnknownJwsAlgorithm(s.to_string())),
        }
    }
}

impl std::fmt::Display for JwsAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test assertions")]
mod tests {
    use std::str::FromStr;

    use super::{JwsAlgorithm, UnknownJwsAlgorithm};

    /// `Es256`'s `serde(rename)` is a literal and its `as_str`/`FromStr` arms
    /// are the shared constant. Serialize, deserialize, and parse all have to
    /// agree with `JWS_ALG_ES256`, or a stored client's signing algorithm
    /// stops round-tripping.
    #[test]
    fn jws_algorithm_serde_matches_protocol_constant() {
        let alg = vouch_common::protocol::JWS_ALG_ES256;
        assert_eq!(
            serde_json::to_string(&JwsAlgorithm::Es256).unwrap(),
            format!("\"{alg}\"")
        );
        assert_eq!(
            serde_json::from_str::<JwsAlgorithm>(&format!("\"{alg}\"")).unwrap(),
            JwsAlgorithm::Es256
        );
        assert_eq!(JwsAlgorithm::Es256.as_str(), alg);
        assert_eq!(JwsAlgorithm::from_str(alg).unwrap(), JwsAlgorithm::Es256);
    }

    #[test]
    fn test_jws_algorithm_round_trip() {
        for (s, variant) in [
            ("ES256", JwsAlgorithm::Es256),
            ("RS256", JwsAlgorithm::Rs256),
            ("PS256", JwsAlgorithm::Ps256),
            ("EdDSA", JwsAlgorithm::EdDsa),
        ] {
            assert_eq!(JwsAlgorithm::from_str(s).unwrap(), variant, "from_str({s})");
            assert_eq!(variant.as_str(), s, "as_str({s})");
            assert_eq!(variant.to_string(), s, "Display({s})");
        }
    }

    #[test]
    fn test_jws_algorithm_default_is_es256() {
        assert_eq!(JwsAlgorithm::default(), JwsAlgorithm::Es256);
    }

    /// FAPI 2.0 Security Profile Section 5.4.1 forbids `none`, and the
    /// symmetric families are not asymmetric signing algorithms.
    #[test]
    fn test_jws_algorithm_from_str_unknown() {
        for rejected in [
            "HS256", "HS384", "HS512", "none", "FOOBAR", "", "es256", "ES384",
        ] {
            assert_eq!(
                JwsAlgorithm::from_str(rejected),
                Err(UnknownJwsAlgorithm(rejected.to_string()))
            );
        }
    }
}
