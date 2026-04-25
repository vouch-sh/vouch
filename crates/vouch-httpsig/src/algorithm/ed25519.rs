// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ed25519` algorithm (RFC 9421 Section 3.3.6).
//!
//! Uses raw 64-byte Ed25519 signatures.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use crate::error::HttpSigError;

use super::{SigningAlgorithm, VerifyingAlgorithm};

/// Ed25519 signing key.
pub struct Ed25519Signer {
    key_pair: Ed25519KeyPair,
    key_id: String,
}

impl Ed25519Signer {
    /// Create a signer from PKCS#8 v2 DER-encoded private key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::SigningFailed`] if the key cannot be parsed.
    pub fn from_pkcs8(der: &[u8], key_id: &str) -> Result<Self, HttpSigError> {
        let key_pair = Ed25519KeyPair::from_pkcs8(der)
            .map_err(|e| HttpSigError::SigningFailed(format!("Ed25519 PKCS#8 parse: {e}")))?;
        Ok(Self {
            key_pair,
            key_id: key_id.to_string(),
        })
    }

    /// Generate a new random Ed25519 signing key.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::SigningFailed`] on key generation failure.
    pub fn generate(key_id: &str) -> Result<Self, HttpSigError> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| HttpSigError::SigningFailed(format!("Ed25519 keygen: {e}")))?;
        Self::from_pkcs8(pkcs8.as_ref(), key_id)
    }

    /// Get the raw 32-byte public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Create a verifier from this signer's public key.
    #[must_use]
    pub fn verifier(&self) -> Ed25519Verifier {
        Ed25519Verifier {
            public_key: self.key_pair.public_key().as_ref().to_vec(),
            key_id: self.key_id.clone(),
        }
    }
}

impl std::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl SigningAlgorithm for Ed25519Signer {
    fn algorithm_id(&self) -> &str {
        "ed25519"
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, base: &[u8]) -> Result<Vec<u8>, HttpSigError> {
        let sig = self.key_pair.sign(base);
        Ok(sig.as_ref().to_vec())
    }
}

/// Ed25519 verification key.
#[derive(Debug, Clone)]
pub struct Ed25519Verifier {
    public_key: Vec<u8>,
    key_id: String,
}

impl Ed25519Verifier {
    /// Create a verifier from a raw 32-byte Ed25519 public key.
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

impl VerifyingAlgorithm for Ed25519Verifier {
    fn algorithm_id(&self) -> &str {
        "ed25519"
    }

    fn verify(&self, base: &[u8], sig: &[u8]) -> Result<(), HttpSigError> {
        let public_key = UnparsedPublicKey::new(&signature::ED25519, &self.public_key);
        public_key
            .verify(base, sig)
            .map_err(|e| HttpSigError::VerificationFailed(format!("Ed25519 verify: {e}")))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code: panic on assertion failure is acceptable")]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate("test-ed25519").unwrap();
        let verifier = signer.verifier();

        let message = b"test ed25519 signature base";
        let sig = signer.sign(message).unwrap();

        assert_eq!(sig.len(), 64, "Ed25519 signature must be 64 bytes");
        verifier.verify(message, &sig).unwrap();
    }

    #[test]
    fn test_verify_rejects_tampered() {
        let signer = Ed25519Signer::generate("k").unwrap();
        let verifier = signer.verifier();

        let sig = signer.sign(b"original").unwrap();
        assert!(verifier.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_deterministic_signatures() {
        let signer = Ed25519Signer::generate("k").unwrap();
        let msg = b"deterministic test";
        let sig1 = signer.sign(msg).unwrap();
        let sig2 = signer.sign(msg).unwrap();
        assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");
    }

    #[test]
    fn test_algorithm_id() {
        let signer = Ed25519Signer::generate("k").unwrap();
        assert_eq!(signer.algorithm_id(), "ed25519");
        assert_eq!(signer.verifier().algorithm_id(), "ed25519");
    }

    #[test]
    fn test_wrong_key_rejects() {
        let signer1 = Ed25519Signer::generate("k1").unwrap();
        let signer2 = Ed25519Signer::generate("k2").unwrap();
        let verifier2 = signer2.verifier();

        let sig = signer1.sign(b"message").unwrap();
        assert!(verifier2.verify(b"message", &sig).is_err());
    }
}
