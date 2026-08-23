// SPDX-License-Identifier: Apache-2.0 OR MIT
//! COSE key serialization utilities.
//!
//! Converts webauthn-rs `COSEKey` types into raw CBOR bytes suitable for
//! storage and later verification by our WebAuthn verification code.

use webauthn_rs::prelude::{COSEKey, COSEKeyType, ECDSACurve, EDDSACurve};

/// Errors that can occur during COSE key serialization.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CoseError {
    /// CBOR serialization failed.
    #[error("CBOR serialization failed: {0}")]
    Cbor(String),
}

/// COSE key type (`kty`, label 1) — IANA "COSE Key Types" registry.
pub(crate) mod kty {
    pub(crate) const OKP: i64 = 1;
    pub(crate) const EC2: i64 = 2;
    pub(crate) const RSA: i64 = 3;
}

/// COSE algorithm (`alg`, label 3) — IANA "COSE Algorithms" registry.
pub(crate) mod alg {
    pub(crate) const ES256: i64 = -7;
    pub(crate) const EDDSA: i64 = -8;
    pub(crate) const RS256: i64 = -257;
}

/// COSE elliptic curve (`crv`, label -1) — IANA "COSE Elliptic Curves" registry.
pub(crate) mod curve {
    pub(crate) const P256: i64 = 1;
    pub(crate) const P384: i64 = 2;
    pub(crate) const P521: i64 = 3;
    pub(crate) const ED25519: i64 = 6;
    pub(crate) const ED448: i64 = 7;
}

/// A `(kty, alg, crv)` combination this server is able to verify.
///
/// RFC 9053 Section 2.1: "Implementations need to check that the key type and
/// curve are correct when creating and verifying a signature." Reading `alg`
/// alone leaves `crv` unchecked, which lets an EC2 key that declares ES256 but
/// carries P-384 coordinates reach a P-256 verifier and fail deep inside the
/// crypto library instead of at the boundary.
///
/// The specific ES256-with-P-256 pairing is *suggested* rather than required
/// by RFC 9053 ("it is suggested that SHA-256 be used only with curve P-256"),
/// so pinning it is our decision: it is the only curve `verify_es256`
/// implements, and the only one WebAuthn registration requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifiableCoseKey {
    /// EC2 key, ES256, P-256.
    Es256,
    /// RSA key, RS256. RSA keys carry no curve.
    Rs256,
    /// OKP key, EdDSA, Ed25519.
    Ed25519,
}

/// Why a COSE key cannot be used for signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoseKeyError {
    /// The `alg` value names an algorithm this server does not verify.
    UnsupportedAlgorithm(i64),
    /// The `alg` is supported but the `kty` is not the one it requires.
    KeyTypeMismatch { alg: i64, expected: i64, got: i64 },
    /// The `alg` is supported but the `crv` is not the one it requires.
    CurveMismatch { alg: i64, expected: i64, got: i64 },
    /// A curve-bearing key type carried no `crv` label.
    MissingCurve(i64),
}

impl std::fmt::Display for CoseKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(alg) => write!(f, "unsupported COSE alg {alg}"),
            Self::KeyTypeMismatch { alg, expected, got } => write!(
                f,
                "COSE alg {alg} requires kty {expected}, but the key declares kty {got}"
            ),
            Self::CurveMismatch { alg, expected, got } => write!(
                f,
                "COSE alg {alg} requires crv {expected}, but the key declares crv {got}"
            ),
            Self::MissingCurve(alg) => write!(f, "COSE alg {alg} requires a crv label"),
        }
    }
}

impl VerifiableCoseKey {
    /// Resolve a COSE `(kty, alg, crv)` triple, rejecting any inconsistency.
    ///
    /// `crv` is `None` when the key carried no `-1` label, which is correct
    /// only for RSA.
    ///
    /// # Errors
    ///
    /// Returns [`CoseKeyError`] naming the offending label and both the
    /// expected and actual value.
    pub(crate) fn from_triple(kty: i64, alg: i64, crv: Option<i64>) -> Result<Self, CoseKeyError> {
        let (expected_kty, expected_crv, resolved) = match alg {
            alg::ES256 => (kty::EC2, Some(curve::P256), Self::Es256),
            alg::RS256 => (kty::RSA, None, Self::Rs256),
            alg::EDDSA => (kty::OKP, Some(curve::ED25519), Self::Ed25519),
            other => return Err(CoseKeyError::UnsupportedAlgorithm(other)),
        };

        if kty != expected_kty {
            return Err(CoseKeyError::KeyTypeMismatch {
                alg,
                expected: expected_kty,
                got: kty,
            });
        }

        if let Some(expected) = expected_crv {
            match crv {
                Some(got) if got == expected => {}
                Some(got) => {
                    return Err(CoseKeyError::CurveMismatch { alg, expected, got });
                }
                None => return Err(CoseKeyError::MissingCurve(alg)),
            }
        }

        Ok(resolved)
    }
}

/// Convert a webauthn-rs `COSEKey` to raw CBOR bytes for storage.
///
/// This produces the same format expected by our WebAuthn verification code:
/// a CBOR map with keys: 1 (kty), 3 (alg), -1 (curve/n), -2 (x/e), -3 (y).
///
/// # Errors
///
/// Returns [`CoseError::Cbor`] if CBOR serialization fails.
pub(crate) fn cose_key_to_cbor(key: &COSEKey) -> Result<Vec<u8>, CoseError> {
    use ciborium::Value;

    let map: Vec<(Value, Value)> = match &key.key {
        COSEKeyType::EC_EC2(ec2) => {
            // COSE EC2 key: {1: 2 (kty), 3: alg, -1: curve, -2: x, -3: y}
            let alg = key.type_ as i64;
            let curve = match ec2.curve {
                ECDSACurve::SECP256R1 => curve::P256,
                ECDSACurve::SECP384R1 => curve::P384,
                ECDSACurve::SECP521R1 => curve::P521,
            };
            vec![
                (Value::Integer(1.into()), Value::Integer(kty::EC2.into())), // kty = EC2
                (Value::Integer(3.into()), Value::Integer(alg.into())),      // alg
                (
                    Value::Integer((-1_i64).into()),
                    Value::Integer(curve.into()),
                ), // curve
                (
                    Value::Integer((-2_i64).into()),
                    Value::Bytes(ec2.x.to_vec()),
                ), // x
                (
                    Value::Integer((-3_i64).into()),
                    Value::Bytes(ec2.y.to_vec()),
                ), // y
            ]
        }
        COSEKeyType::RSA(rsa) => {
            // COSE RSA key: {1: 3 (kty), 3: alg, -1: n, -2: e}
            let alg = key.type_ as i64;
            vec![
                (Value::Integer(1.into()), Value::Integer(kty::RSA.into())), // kty = RSA
                (Value::Integer(3.into()), Value::Integer(alg.into())),      // alg
                (
                    Value::Integer((-1_i64).into()),
                    Value::Bytes(rsa.n.to_vec()),
                ), // n
                (
                    Value::Integer((-2_i64).into()),
                    Value::Bytes(rsa.e.to_vec()),
                ), // e
            ]
        }
        COSEKeyType::EC_OKP(okp) => {
            // COSE OKP key: {1: 1 (kty), 3: alg, -1: curve, -2: x}
            let alg = key.type_ as i64;
            let curve = match okp.curve {
                EDDSACurve::ED25519 => curve::ED25519,
                EDDSACurve::ED448 => curve::ED448,
            };
            vec![
                (Value::Integer(1.into()), Value::Integer(kty::OKP.into())), // kty = OKP
                (Value::Integer(3.into()), Value::Integer(alg.into())),      // alg
                (
                    Value::Integer((-1_i64).into()),
                    Value::Integer(curve.into()),
                ), // curve
                (
                    Value::Integer((-2_i64).into()),
                    Value::Bytes(okp.x.to_vec()),
                ), // x
            ]
        }
    };

    let mut buf = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut buf)
        .map_err(|e| CoseError::Cbor(e.to_string()))?;

    Ok(buf)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use webauthn_rs::prelude::{COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};

    #[test]
    fn test_ec2_p256_key_roundtrip() {
        let key = COSEKey {
            type_: COSEAlgorithm::ES256,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: vec![1u8; 32].into(),
                y: vec![2u8; 32].into(),
            }),
        };

        let cbor = cose_key_to_cbor(&key).unwrap();
        assert!(!cbor.is_empty());

        // Decode and verify structure
        let value: ciborium::Value = ciborium::from_reader(cbor.as_slice()).expect("valid CBOR");
        assert!(
            matches!(value, ciborium::Value::Map(_)),
            "Expected CBOR map"
        );
        let ciborium::Value::Map(map) = value else {
            return;
        };

        // kty = 2 (EC2)
        assert!(map.iter().any(|(k, v)| {
            matches!(k, ciborium::Value::Integer(i) if *i == 1.into())
                && matches!(v, ciborium::Value::Integer(i) if *i == 2.into())
        }));
    }

    #[test]
    fn test_ec2_p384_key() {
        let key = COSEKey {
            type_: COSEAlgorithm::ES384,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP384R1,
                x: vec![3u8; 48].into(),
                y: vec![4u8; 48].into(),
            }),
        };

        let cbor = cose_key_to_cbor(&key).unwrap();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_deterministic_output() {
        let key = COSEKey {
            type_: COSEAlgorithm::ES256,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: vec![5u8; 32].into(),
                y: vec![6u8; 32].into(),
            }),
        };

        let cbor1 = cose_key_to_cbor(&key).unwrap();
        let cbor2 = cose_key_to_cbor(&key).unwrap();
        assert_eq!(cbor1, cbor2, "COSE serialization must be deterministic");
    }
}
