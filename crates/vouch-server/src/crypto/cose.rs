// SPDX-License-Identifier: BUSL-1.1
//! COSE key serialization utilities.
//!
//! Converts webauthn-rs `COSEKey` types into raw CBOR bytes suitable for
//! storage and later verification by our WebAuthn verification code.

use webauthn_rs::prelude::{COSEKey, COSEKeyType, ECDSACurve, EDDSACurve};

/// Errors that can occur during COSE key serialization.
#[derive(Debug, thiserror::Error)]
pub enum CoseError {
    /// CBOR serialization failed.
    #[error("CBOR serialization failed: {0}")]
    Cbor(String),
}

/// Convert a webauthn-rs `COSEKey` to raw CBOR bytes for storage.
///
/// This produces the same format expected by our WebAuthn verification code:
/// a CBOR map with keys: 1 (kty), 3 (alg), -1 (curve/n), -2 (x/e), -3 (y).
///
/// # Errors
///
/// Returns [`CoseError::Cbor`] if CBOR serialization fails.
pub fn cose_key_to_cbor(key: &COSEKey) -> Result<Vec<u8>, CoseError> {
    use ciborium::Value;

    let map: Vec<(Value, Value)> = match &key.key {
        COSEKeyType::EC_EC2(ec2) => {
            // COSE EC2 key: {1: 2 (kty), 3: alg, -1: curve, -2: x, -3: y}
            let alg = key.type_ as i64;
            let curve = match ec2.curve {
                ECDSACurve::SECP256R1 => 1,
                ECDSACurve::SECP384R1 => 2,
                ECDSACurve::SECP521R1 => 3,
            };
            vec![
                (Value::Integer(1.into()), Value::Integer(2.into())), // kty = EC2
                (Value::Integer(3.into()), Value::Integer(alg.into())), // alg
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
                (Value::Integer(1.into()), Value::Integer(3.into())), // kty = RSA
                (Value::Integer(3.into()), Value::Integer(alg.into())), // alg
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
                EDDSACurve::ED25519 => 6,
                EDDSACurve::ED448 => 7,
            };
            vec![
                (Value::Integer(1.into()), Value::Integer(1.into())), // kty = OKP
                (Value::Integer(3.into()), Value::Integer(alg.into())), // alg
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
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
        let map = match value {
            ciborium::Value::Map(m) => m,
            other => panic!("Expected CBOR map, got: {other:?}"),
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
