// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `hmac-sha256` algorithm (RFC 9421 Section 3.3.5).
//!
//! Symmetric HMAC signing/verification using a shared secret.

use aws_lc_rs::hmac;

use crate::error::HttpSigError;

use super::{SigningAlgorithm, VerifyingAlgorithm};

/// HMAC-SHA256 signing/verification key.
pub struct HmacSha256Key {
    key: hmac::Key,
    key_id: String,
}

impl HmacSha256Key {
    /// Create a key from raw secret bytes.
    #[must_use]
    pub fn new(secret: &[u8], key_id: &str) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            key_id: key_id.to_string(),
        }
    }
}

impl std::fmt::Debug for HmacSha256Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacSha256Key")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl SigningAlgorithm for HmacSha256Key {
    fn algorithm(&self) -> super::SignatureAlgorithm {
        super::SignatureAlgorithm::HmacSha256
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, base: &[u8]) -> Result<Vec<u8>, HttpSigError> {
        let tag = hmac::sign(&self.key, base);
        Ok(tag.as_ref().to_vec())
    }
}

impl VerifyingAlgorithm for HmacSha256Key {
    fn algorithm(&self) -> super::SignatureAlgorithm {
        super::SignatureAlgorithm::HmacSha256
    }

    fn verify(&self, base: &[u8], signature: &[u8]) -> Result<(), HttpSigError> {
        hmac::verify(&self.key, base, signature)
            .map_err(|e| HttpSigError::VerificationFailed(format!("HMAC verify: {e}")))
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let key = HmacSha256Key::new(b"test-shared-secret", "test-hmac");
        let message = b"test hmac signature base";

        let sig = key.sign(message).unwrap();
        assert_eq!(sig.len(), 32, "HMAC-SHA256 output is 32 bytes");

        key.verify(message, &sig).unwrap();
    }

    #[test]
    fn test_verify_rejects_tampered() {
        let key = HmacSha256Key::new(b"secret", "k");
        let sig = key.sign(b"original").unwrap();
        assert!(key.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_deterministic() {
        let key = HmacSha256Key::new(b"secret", "k");
        let msg = b"deterministic";
        let sig1 = key.sign(msg).unwrap();
        let sig2 = key.sign(msg).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_different_keys_different_signatures() {
        let key1 = HmacSha256Key::new(b"secret1", "k1");
        let key2 = HmacSha256Key::new(b"secret2", "k2");

        let msg = b"message";
        let sig1 = key1.sign(msg).unwrap();
        let sig2 = key2.sign(msg).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_wrong_key_rejects() {
        let key1 = HmacSha256Key::new(b"secret1", "k1");
        let key2 = HmacSha256Key::new(b"secret2", "k2");

        let sig = key1.sign(b"message").unwrap();
        assert!(key2.verify(b"message", &sig).is_err());
    }

    #[test]
    fn test_algorithm_identifier() {
        let key = HmacSha256Key::new(b"s", "k");
        assert_eq!(SigningAlgorithm::algorithm(&key).as_str(), "hmac-sha256");
        assert_eq!(VerifyingAlgorithm::algorithm(&key).as_str(), "hmac-sha256");
    }
}
