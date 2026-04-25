// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `rsa-pss-sha512` algorithm (RFC 9421 Section 3.3.1).
//!
//! Uses RSASSA-PSS with SHA-512 digest and MGF1-SHA-512 mask generation.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    KeyPair, RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA512, RsaKeyPair, UnparsedPublicKey,
};

use crate::error::HttpSigError;

use super::{SigningAlgorithm, VerifyingAlgorithm};

/// RSA-PSS-SHA-512 signing key.
pub struct RsaPssSha512Signer {
    key_pair: RsaKeyPair,
    key_id: String,
}

impl RsaPssSha512Signer {
    /// Create a signer from PKCS#8 DER-encoded RSA private key bytes.
    ///
    /// The key must be at least 2048 bits.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::SigningFailed`] if the key cannot be parsed.
    pub fn from_pkcs8(der: &[u8], key_id: &str) -> Result<Self, HttpSigError> {
        let key_pair = RsaKeyPair::from_pkcs8(der)
            .map_err(|e| HttpSigError::SigningFailed(format!("RSA PKCS#8 parse: {e}")))?;
        Ok(Self {
            key_pair,
            key_id: key_id.to_string(),
        })
    }

    /// Get the DER-encoded public key bytes (RSAPublicKey format).
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Create a verifier from this signer's public key.
    #[must_use]
    pub fn verifier(&self) -> RsaPssSha512Verifier {
        RsaPssSha512Verifier {
            public_key: self.key_pair.public_key().as_ref().to_vec(),
            key_id: self.key_id.clone(),
        }
    }
}

impl std::fmt::Debug for RsaPssSha512Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaPssSha512Signer")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl SigningAlgorithm for RsaPssSha512Signer {
    fn algorithm_id(&self) -> &str {
        "rsa-pss-sha512"
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, base: &[u8]) -> Result<Vec<u8>, HttpSigError> {
        let rng = SystemRandom::new();
        let modulus_len = self.key_pair.public_modulus_len();
        let mut signature = vec![0u8; modulus_len];
        self.key_pair
            .sign(&RSA_PSS_SHA512, &rng, base, &mut signature)
            .map_err(|e| HttpSigError::SigningFailed(format!("RSA-PSS sign: {e}")))?;
        Ok(signature)
    }
}

/// RSA-PSS-SHA-512 verification key.
#[derive(Debug, Clone)]
pub struct RsaPssSha512Verifier {
    public_key: Vec<u8>,
    key_id: String,
}

impl RsaPssSha512Verifier {
    /// Create a verifier from DER-encoded RSA public key bytes (RSAPublicKey format).
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

impl VerifyingAlgorithm for RsaPssSha512Verifier {
    fn algorithm_id(&self) -> &str {
        "rsa-pss-sha512"
    }

    fn verify(&self, base: &[u8], signature: &[u8]) -> Result<(), HttpSigError> {
        let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, &self.public_key);
        public_key
            .verify(base, signature)
            .map_err(|e| HttpSigError::VerificationFailed(format!("RSA-PSS verify: {e}")))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code: panic on assertion failure is acceptable")]
mod tests {
    use super::*;

    /// Generate a 2048-bit RSA PKCS#8 key for testing using aws-lc-rs.
    fn test_rsa_pkcs8_key() -> Vec<u8> {
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::rsa::KeySize;
        use aws_lc_rs::rsa::PrivateDecryptingKey;

        let key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        key.as_der().unwrap().as_ref().to_vec()
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let der = test_rsa_pkcs8_key();
        let signer = RsaPssSha512Signer::from_pkcs8(&der, "test-key").unwrap();
        let verifier = signer.verifier();

        let message = b"test signature base";
        let signature = signer.sign(message).unwrap();

        verifier.verify(message, &signature).unwrap();
    }

    #[test]
    fn test_verify_rejects_tampered() {
        let der = test_rsa_pkcs8_key();
        let signer = RsaPssSha512Signer::from_pkcs8(&der, "test-key").unwrap();
        let verifier = signer.verifier();

        let signature = signer.sign(b"original message").unwrap();
        let result = verifier.verify(b"tampered message", &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_algorithm_id() {
        let der = test_rsa_pkcs8_key();
        let signer = RsaPssSha512Signer::from_pkcs8(&der, "k1").unwrap();
        assert_eq!(signer.algorithm_id(), "rsa-pss-sha512");
        assert_eq!(signer.verifier().algorithm_id(), "rsa-pss-sha512");
    }

    #[test]
    fn test_key_id() {
        let der = test_rsa_pkcs8_key();
        let signer = RsaPssSha512Signer::from_pkcs8(&der, "my-rsa-key").unwrap();
        assert_eq!(signer.key_id(), "my-rsa-key");
    }

    #[test]
    fn test_signature_length() {
        let der = test_rsa_pkcs8_key();
        let signer = RsaPssSha512Signer::from_pkcs8(&der, "k").unwrap();
        let sig = signer.sign(b"data").unwrap();
        // 2048-bit key → 256-byte signature
        assert_eq!(sig.len(), 256, "RSA-2048 signature must be 256 bytes");
    }

    #[test]
    fn test_wrong_key_rejects() {
        let der1 = test_rsa_pkcs8_key();
        let der2 = test_rsa_pkcs8_key();
        let signer1 = RsaPssSha512Signer::from_pkcs8(&der1, "k1").unwrap();
        let signer2 = RsaPssSha512Signer::from_pkcs8(&der2, "k2").unwrap();
        let verifier2 = signer2.verifier();

        let sig = signer1.sign(b"message").unwrap();
        assert!(verifier2.verify(b"message", &sig).is_err());
    }

    #[test]
    fn test_debug_redacts_key() {
        let der = test_rsa_pkcs8_key();
        let signer = RsaPssSha512Signer::from_pkcs8(&der, "k").unwrap();
        let debug = format!("{signer:?}");
        assert!(debug.contains("key_id"));
        assert!(!debug.contains("key_pair"));
    }
}
