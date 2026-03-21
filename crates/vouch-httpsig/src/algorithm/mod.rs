// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Signing and verification algorithm implementations for RFC 9421.

pub mod ecdsa_p256;
pub mod ecdsa_p384;
pub mod ed25519;
pub mod hmac_sha256;
pub mod rsa_pss_sha512;
pub mod rsa_v15_sha256;

use crate::error::HttpSigError;

/// Trait for algorithms that can sign a signature base.
pub trait SigningAlgorithm: Send + Sync {
    /// The RFC 9421 algorithm identifier (e.g., `"ecdsa-p256-sha256"`).
    fn algorithm_id(&self) -> &str;

    /// The key identifier for the `keyid` signature parameter.
    fn key_id(&self) -> &str;

    /// Sign the given signature base bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::SigningFailed`] on failure.
    fn sign(&self, base: &[u8]) -> Result<Vec<u8>, HttpSigError>;
}

/// Trait for algorithms that can verify a signature against a base.
pub trait VerifyingAlgorithm: Send + Sync {
    /// The RFC 9421 algorithm identifier (e.g., `"ecdsa-p256-sha256"`).
    fn algorithm_id(&self) -> &str;

    /// Verify that `signature` is valid for the given `base` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::VerificationFailed`] if the signature is invalid.
    fn verify(&self, base: &[u8], signature: &[u8]) -> Result<(), HttpSigError>;
}
