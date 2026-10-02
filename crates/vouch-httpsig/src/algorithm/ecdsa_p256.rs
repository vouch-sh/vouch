// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ecdsa-p256-sha256` algorithm (RFC 9421 Section 3.3.4).
//!
//! The signature is the 64-octet concatenation of `r` and `s`, each a
//! big-endian unsigned integer zero-padded to 32 octets (the same form JWS
//! ES256 uses), not a DER `ECDSA-Sig-Value`.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};

use crate::error::HttpSigError;

use super::{SigningAlgorithm, VerifyingAlgorithm};

/// ECDSA P-256 signing key.
pub struct EcdsaP256Signer {
    key_pair: EcdsaKeyPair,
    key_id: String,
}

impl EcdsaP256Signer {
    /// Create a signer from PKCS#8 DER-encoded private key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::SigningFailed`] if the key cannot be parsed.
    pub fn from_pkcs8(der: &[u8], key_id: &str) -> Result<Self, HttpSigError> {
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)
            .map_err(|e| HttpSigError::SigningFailed(format!("PKCS#8 parse: {e}")))?;
        Ok(Self {
            key_pair,
            key_id: key_id.to_string(),
        })
    }

    /// Generate a new random P-256 signing key.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::SigningFailed`] on key generation failure.
    pub fn generate(key_id: &str) -> Result<Self, HttpSigError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| HttpSigError::SigningFailed(format!("key generation: {e}")))?;
        Self::from_pkcs8(pkcs8.as_ref(), key_id)
    }

    /// Get the raw public key bytes (65-byte uncompressed SEC1 point).
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Create a verifier from this signer's public key.
    #[must_use]
    pub fn verifier(&self) -> EcdsaP256Verifier {
        EcdsaP256Verifier {
            public_key: self.key_pair.public_key().as_ref().to_vec(),
        }
    }
}

impl std::fmt::Debug for EcdsaP256Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaP256Signer")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl SigningAlgorithm for EcdsaP256Signer {
    fn algorithm(&self) -> super::SignatureAlgorithm {
        super::SignatureAlgorithm::EcdsaP256Sha256
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, base: &[u8]) -> Result<Vec<u8>, HttpSigError> {
        let rng = SystemRandom::new();
        let sig = self
            .key_pair
            .sign(&rng, base)
            .map_err(|e| HttpSigError::SigningFailed(format!("ECDSA sign: {e}")))?;
        Ok(sig.as_ref().to_vec())
    }
}

/// ECDSA P-256 verification key.
#[derive(Debug, Clone)]
pub struct EcdsaP256Verifier {
    public_key: Vec<u8>,
}

impl EcdsaP256Verifier {
    /// Create a verifier from raw uncompressed SEC1 public key bytes (65 bytes).
    #[must_use]
    pub fn new(public_key: &[u8]) -> Self {
        Self {
            public_key: public_key.to_vec(),
        }
    }
}

impl VerifyingAlgorithm for EcdsaP256Verifier {
    fn algorithm(&self) -> super::SignatureAlgorithm {
        super::SignatureAlgorithm::EcdsaP256Sha256
    }

    fn verify(&self, base: &[u8], signature: &[u8]) -> Result<(), HttpSigError> {
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.public_key);
        public_key
            .verify(base, signature)
            .map_err(|e| HttpSigError::VerificationFailed(format!("ECDSA verify: {e}")))
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    // RFC 9421 §3.3.4: ecdsa-p256-sha256 round trip.
    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = EcdsaP256Signer::generate("test-key").unwrap();
        let verifier = signer.verifier();

        let message = b"test signature base";
        let signature = signer.sign(message).unwrap();

        verifier.verify(message, &signature).unwrap();
    }

    // RFC 9421 §3.3.4: an altered signature base fails verification.
    #[test]
    fn test_verify_rejects_tampered() {
        let signer = EcdsaP256Signer::generate("test-key").unwrap();
        let verifier = signer.verifier();

        let signature = signer.sign(b"original message").unwrap();
        let result = verifier.verify(b"tampered message", &signature);
        assert!(result.is_err());
    }

    // RFC 9421 §3.3.4: the registered algorithm name is ecdsa-p256-sha256.
    #[test]
    fn test_algorithm_identifier() {
        let signer = EcdsaP256Signer::generate("k1").unwrap();
        assert_eq!(signer.algorithm().as_str(), "ecdsa-p256-sha256");
        assert_eq!(signer.verifier().algorithm().as_str(), "ecdsa-p256-sha256");
    }

    // RFC 9421 §2.3: keyid identifies the verification key.
    #[test]
    fn test_key_id() {
        let signer = EcdsaP256Signer::generate("my-key-id").unwrap();
        assert_eq!(signer.key_id(), "my-key-id");
    }

    // RFC 9421 §3.3.4: "These encoded values are concatenated into a single
    // 64-octet array consisting of the encoded value of r followed by the
    // encoded value of s."
    #[test]
    fn test_signature_is_64_octet_r_s() {
        let signer = EcdsaP256Signer::generate("k").unwrap();
        for _ in 0..32 {
            let sig = signer.sign(b"data").unwrap();
            assert_eq!(sig.len(), 64, "r || s is always 64 octets");
        }
    }

    // RFC 9421 §3.3.4: the verifier input "is a 64-octet array consisting of
    // the encoded values of r and s concatenated in order", so a DER
    // ECDSA-Sig-Value over the same base does not verify.
    #[test]
    fn test_verify_rejects_der_signature() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let signer = EcdsaP256Signer::from_pkcs8(pkcs8.as_ref(), "k").unwrap();
        let der_key = EcdsaKeyPair::from_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
        )
        .unwrap();

        let message = b"signature base";
        let der_sig = der_key.sign(&rng, message).unwrap();
        assert_eq!(der_sig.as_ref().first(), Some(&0x30), "DER SEQUENCE tag");

        assert!(signer.verifier().verify(message, der_sig.as_ref()).is_err());
    }

    // RFC 9421 §3.3.4: a different key does not verify.
    #[test]
    fn test_wrong_key_rejects() {
        let signer1 = EcdsaP256Signer::generate("k1").unwrap();
        let signer2 = EcdsaP256Signer::generate("k2").unwrap();
        let verifier2 = signer2.verifier();

        let sig = signer1.sign(b"message").unwrap();
        assert!(verifier2.verify(b"message", &sig).is_err());
    }
}
