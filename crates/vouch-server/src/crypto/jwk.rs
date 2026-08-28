// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JSON Web Keys (RFC 7517), in both directions.
//!
//! One [`Jwk`] serves the JWKS response Vouch publishes and the `jwk` Header
//! Parameter it parses off an untrusted JWS. The two directions want opposite
//! things from the same members, so the difference is carried by construction
//! rather than by two types:
//!
//! * A published key must name its `kid`, `alg`, and `use` — a client selects
//!   by them. Fields are private and [`EcJwk::for_jwks`] / [`RsaJwk::for_jwks`]
//!   are the only way to build one, so a JWKS entry cannot be assembled
//!   without them.
//! * A parsed key may carry none of those. RFC 7517 Section 4 requires the
//!   optional members be tolerated: "Additional members can be present in the
//!   JWK; if not understood by implementations encountering them, they MUST be
//!   ignored." So they deserialize as `None` and are omitted when absent.
//!
//! What a parsed key may *not* carry is private key material; see
//! [`PrivateKeyMaterial`].
//!
//! Serializing a `Jwk` does not produce an RFC 7638 thumbprint input — that
//! form is the required members alone, in lexicographic order, and
//! [`vouch_common::jwk::JwkThumbprintKey`] is what builds it.

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};

use crate::crypto::alg::JwsAlgorithm;

/// A JSON Web Key, tagged by `kty` (RFC 7517 Section 4.1).
///
/// Only the key types Vouch signs or verifies with are representable, so an
/// unusable key is refused by the parse rather than by a check further in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Jwk {
    /// RFC 7518 Section 6.2 — an EC public key.
    #[serde(rename = "EC")]
    Ec(EcJwk),
    /// RFC 7518 Section 6.3 — an RSA public key.
    #[serde(rename = "RSA")]
    Rsa(RsaJwk),
    /// RFC 8037 Section 2 — an octet key pair.
    ///
    /// Parsed but never published: Vouch verifies Ed25519 DPoP proofs and
    /// signs with neither, so there is no `for_jwks` constructor for it.
    #[serde(rename = "OKP")]
    Okp(OkpJwk),
}

/// An EC public key on the one curve Vouch uses (RFC 7518 Section 6.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcJwk {
    /// RFC 7518 Section 6.2.1.1.
    crv: EcCurve,
    /// RFC 7518 Section 6.2.1.2 — the base64url X coordinate.
    x: String,
    /// RFC 7518 Section 6.2.1.3 — the base64url Y coordinate.
    y: String,
    /// RFC 7517 Section 4.5 — the Key ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    /// RFC 7517 Section 4.4 — the Algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alg: Option<JwsAlgorithm>,
    /// RFC 7517 Section 4.2 — the Public Key Use.
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    key_use: Option<KeyUse>,
    /// The EC private key. Refused on the way in and never on the way out;
    /// see [`PrivateKeyMaterial`] for the requirement that forbids it.
    #[serde(default, skip_serializing)]
    d: PrivateKeyMaterial,
}

/// An RSA public key (RFC 7518 Section 6.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaJwk {
    /// RFC 7518 Section 6.3.1.1 — the base64url modulus.
    n: String,
    /// RFC 7518 Section 6.3.1.2 — the base64url public exponent.
    e: String,
    /// RFC 7517 Section 4.5 — the Key ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    /// RFC 7517 Section 4.4 — the Algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alg: Option<JwsAlgorithm>,
    /// RFC 7517 Section 4.2 — the Public Key Use.
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    key_use: Option<KeyUse>,
    /// The RSA private key members. All refused; see [`PrivateKeyMaterial`].
    #[serde(default, skip_serializing)]
    d: PrivateKeyMaterial,
    #[serde(default, skip_serializing)]
    p: PrivateKeyMaterial,
    #[serde(default, skip_serializing)]
    q: PrivateKeyMaterial,
    #[serde(default, skip_serializing)]
    dp: PrivateKeyMaterial,
    #[serde(default, skip_serializing)]
    dq: PrivateKeyMaterial,
    #[serde(default, skip_serializing)]
    qi: PrivateKeyMaterial,
}

/// An octet key pair on the one curve Vouch verifies with (RFC 8037 Section 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkpJwk {
    /// RFC 8037 Section 2 — the subtype of the key pair.
    crv: OkpCurve,
    /// RFC 8037 Section 2 — the base64url public key.
    x: String,
    /// The Ed25519 private key. Refused; see [`PrivateKeyMaterial`].
    #[serde(default, skip_serializing)]
    d: PrivateKeyMaterial,
}

impl EcJwk {
    /// Build the JWKS entry for a P-256 signing key.
    ///
    /// The only way to construct one in code: the fields are private, so a
    /// published entry cannot omit the `kid` a client selects by. `alg` and
    /// `use` follow from the key type — [`EcCurve`] has one variant, and
    /// ES256 is the algorithm for it.
    #[must_use]
    pub fn for_jwks(kid: String, x: String, y: String) -> Self {
        Self {
            crv: EcCurve::P256,
            x,
            y,
            kid: Some(kid),
            alg: Some(JwsAlgorithm::Es256),
            key_use: Some(KeyUse::Signature),
            d: PrivateKeyMaterial::Absent,
        }
    }

    /// The base64url X coordinate.
    #[must_use]
    pub fn x(&self) -> &str {
        &self.x
    }

    /// The base64url Y coordinate.
    #[must_use]
    pub fn y(&self) -> &str {
        &self.y
    }

    /// RFC 7517 Section 4.5 — the Key ID.
    ///
    /// `Some` for anything [`Self::for_jwks`] built; `None` when a parsed
    /// key omitted it, which RFC 7517 Section 4.5 permits.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

impl RsaJwk {
    /// Build the JWKS entry for an RSA signing key.
    ///
    /// See [`EcJwk::for_jwks`]; RS256 is the algorithm Vouch signs ID tokens
    /// with (OIDC Core Section 3.1.3.7).
    #[must_use]
    pub fn for_jwks(kid: String, n: String, e: String) -> Self {
        Self {
            n,
            e,
            kid: Some(kid),
            alg: Some(JwsAlgorithm::Rs256),
            key_use: Some(KeyUse::Signature),
            d: PrivateKeyMaterial::Absent,
            p: PrivateKeyMaterial::Absent,
            q: PrivateKeyMaterial::Absent,
            dp: PrivateKeyMaterial::Absent,
            dq: PrivateKeyMaterial::Absent,
            qi: PrivateKeyMaterial::Absent,
        }
    }

    /// The base64url modulus.
    #[must_use]
    pub fn n(&self) -> &str {
        &self.n
    }

    /// The base64url public exponent.
    #[must_use]
    pub fn e(&self) -> &str {
        &self.e
    }

    /// RFC 7517 Section 4.5 — the Key ID.
    ///
    /// `Some` for anything [`Self::for_jwks`] built; `None` when a parsed
    /// key omitted it, which RFC 7517 Section 4.5 permits.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

impl OkpJwk {
    /// The base64url public key.
    #[must_use]
    pub fn x(&self) -> &str {
        &self.x
    }
}

impl Jwk {
    /// Whether any member holding private key material was present.
    ///
    /// Only a parsed key can answer yes: `for_jwks` never sets one.
    pub(crate) fn carries_private_key(&self) -> bool {
        let members: &[&PrivateKeyMaterial] = match self {
            Self::Ec(ec) => &[&ec.d],
            Self::Rsa(rsa) => &[&rsa.d, &rsa.p, &rsa.q, &rsa.dp, &rsa.dq, &rsa.qi],
            Self::Okp(okp) => &[&okp.d],
        };
        members.contains(&&PrivateKeyMaterial::Present)
    }

    /// The RFC 7638 thumbprint of this key, as used for the DPoP `jkt`
    /// confirmation claim (RFC 9449 Section 6.1).
    ///
    /// Delegates to [`vouch_common::jwk::JwkThumbprintKey`] rather than
    /// serializing `self`: the thumbprint is computed over the required
    /// members alone, in lexicographic order, so the optional members this
    /// type can carry must not reach the hash.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        match self {
            Self::Ec(ec) => vouch_common::jwk::JwkThumbprintKey::Ec {
                crv: ec.crv.as_str(),
                x: &ec.x,
                y: &ec.y,
            },
            Self::Rsa(rsa) => vouch_common::jwk::JwkThumbprintKey::Rsa {
                e: &rsa.e,
                n: &rsa.n,
            },
            Self::Okp(okp) => vouch_common::jwk::JwkThumbprintKey::Okp {
                crv: okp.crv.as_str(),
                x: &okp.x,
            },
        }
        .thumbprint()
    }
}

/// The EC curve of an [`EcJwk`].
///
/// P-256 is the only one, because ES256 is the only EC algorithm in
/// [`JwsAlgorithm`]. A curve no signature could be verified on is therefore
/// not representable, rather than checked for after the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcCurve {
    /// RFC 7518 Section 6.2.1.1.
    #[serde(rename = "P-256")]
    P256,
}

impl EcCurve {
    /// The `crv` value as RFC 7638 Section 3.2 hashes it.
    fn as_str(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
        }
    }
}

/// The curve of an [`OkpJwk`]. Ed25519 for the same reason [`EcCurve`] has one
/// variant: FAPI 2.0 Section 5.4.1 admits `EdDSA` only in its Ed25519 variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OkpCurve {
    /// RFC 8037 Section 3.1.
    #[serde(rename = "Ed25519")]
    Ed25519,
}

impl OkpCurve {
    /// The `crv` value as RFC 7638 Section 3.2 hashes it.
    fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
        }
    }
}

/// RFC 7517 Section 4.2, the `use` member. Vouch publishes signing keys only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUse {
    /// A key used to verify signatures.
    #[serde(rename = "sig")]
    Signature,
}

/// Whether a JWK carried a member holding private key material.
///
/// RFC 9449 Section 4.3 lists what "the receiving server MUST ensure" of a
/// DPoP proof, item 7 being "The jwk JOSE Header Parameter does not contain a
/// private key." Recording presence rather than the value makes that a
/// property of the type: `Jws::parse` refuses any header whose JWK reports
/// [`Present`](Self::Present), so no caller can hold a [`Jwk`] that carried
/// one and no caller has to remember to look.
///
/// The alternative — a key type that simply omits `d` and friends — silently
/// discards them instead, which reduces the check to one that always passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PrivateKeyMaterial {
    /// The member was not in the JWK.
    #[default]
    Absent,
    /// The member was present, whatever it held.
    Present,
}

impl<'de> Deserialize<'de> for PrivateKeyMaterial {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        IgnoredAny::deserialize(deserializer)?;
        Ok(Self::Present)
    }
}
