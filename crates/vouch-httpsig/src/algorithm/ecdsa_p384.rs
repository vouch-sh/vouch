// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ecdsa-p384-sha384` algorithm (RFC 9421 Section 3.3.4).
//!
//! Uses DER-encoded ECDSA signatures (NOT the R||S format used by JWS/JWT).

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};

use crate::error::HttpSigError;

use super::{SigningAlgorithm, VerifyingAlgorithm};

/// ECDSA P-384 signing key.
pub struct EcdsaP384Signer {
    key_pair: EcdsaKeyPair,
    key_id: String,
}

impl EcdsaP384Signer {
    /// Create a signer from PKCS#8 DER-encoded private key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::SigningFailed`] if the key cannot be parsed.
    pub fn from_pkcs8(der: &[u8], key_id: &str) -> Result<Self, HttpSigError> {
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, der)
            .map_err(|e| HttpSigError::SigningFailed(format!("PKCS#8 parse: {e}")))?;
        Ok(Self {
            key_pair,
            key_id: key_id.to_string(),
        })
    }

    /// Generate a new random P-384 signing key.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::SigningFailed`] on key generation failure.
    pub fn generate(key_id: &str) -> Result<Self, HttpSigError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
            .map_err(|e| HttpSigError::SigningFailed(format!("key generation: {e}")))?;
        Self::from_pkcs8(pkcs8.as_ref(), key_id)
    }

    /// Get the raw public key bytes (97-byte uncompressed SEC1 point).
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Create a verifier from this signer's public key.
    #[must_use]
    pub fn verifier(&self) -> EcdsaP384Verifier {
        EcdsaP384Verifier {
            public_key: self.key_pair.public_key().as_ref().to_vec(),
            key_id: self.key_id.clone(),
        }
    }
}

impl std::fmt::Debug for EcdsaP384Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaP384Signer")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl SigningAlgorithm for EcdsaP384Signer {
    fn algorithm_id(&self) -> &str {
        "ecdsa-p384-sha384"
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

/// ECDSA P-384 verification key.
#[derive(Debug, Clone)]
pub struct EcdsaP384Verifier {
    public_key: Vec<u8>,
    key_id: String,
}

impl EcdsaP384Verifier {
    /// Create a verifier from raw uncompressed SEC1 public key bytes (97 bytes).
    #[must_use]
    pub fn new(public_key: &[u8], key_id: &str) -> Self {
        Self {
            public_key: public_key.to_vec(),
            key_id: key_id.to_string(),
        }
    }

    /// Get the key ID.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl VerifyingAlgorithm for EcdsaP384Verifier {
    fn algorithm_id(&self) -> &str {
        "ecdsa-p384-sha384"
    }

    fn verify(&self, base: &[u8], signature: &[u8]) -> Result<(), HttpSigError> {
        let public_key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, &self.public_key);
        public_key
            .verify(base, signature)
            .map_err(|e| HttpSigError::VerificationFailed(format!("ECDSA verify: {e}")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = EcdsaP384Signer::generate("test-key").unwrap();
        let verifier = signer.verifier();

        let message = b"test signature base";
        let signature = signer.sign(message).unwrap();

        verifier.verify(message, &signature).unwrap();
    }

    #[test]
    fn test_verify_rejects_tampered() {
        let signer = EcdsaP384Signer::generate("test-key").unwrap();
        let verifier = signer.verifier();

        let signature = signer.sign(b"original message").unwrap();
        let result = verifier.verify(b"tampered message", &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_algorithm_id() {
        let signer = EcdsaP384Signer::generate("k1").unwrap();
        assert_eq!(signer.algorithm_id(), "ecdsa-p384-sha384");
        assert_eq!(signer.verifier().algorithm_id(), "ecdsa-p384-sha384");
    }

    #[test]
    fn test_key_id() {
        let signer = EcdsaP384Signer::generate("my-key-id").unwrap();
        assert_eq!(signer.key_id(), "my-key-id");
    }

    #[test]
    fn test_der_signature_format() {
        let signer = EcdsaP384Signer::generate("k").unwrap();
        let sig = signer.sign(b"data").unwrap();
        // DER-encoded ECDSA signature starts with 0x30 (SEQUENCE tag)
        assert_eq!(sig.first(), Some(&0x30), "should be DER-encoded");
        // DER ECDSA sigs for P-384 are typically 100-104 bytes (not fixed)
        assert!(
            sig.len() >= 96 && sig.len() <= 106,
            "DER sig length: {}",
            sig.len()
        );
    }

    #[test]
    fn test_wrong_key_rejects() {
        let signer1 = EcdsaP384Signer::generate("k1").unwrap();
        let signer2 = EcdsaP384Signer::generate("k2").unwrap();
        let verifier2 = signer2.verifier();

        let sig = signer1.sign(b"message").unwrap();
        assert!(verifier2.verify(b"message", &sig).is_err());
    }

    #[test]
    fn test_debug_redacts_key() {
        let signer = EcdsaP384Signer::generate("k").unwrap();
        let debug = format!("{signer:?}");
        assert!(debug.contains("key_id"));
        assert!(!debug.contains("key_pair"));
    }
}
