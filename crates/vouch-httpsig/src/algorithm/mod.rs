// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Signing and verification algorithm implementations for RFC 9421.

pub mod ecdsa_p256;
pub mod ed25519;
pub mod hmac_sha256;

use crate::error::HttpSigError;

/// Trait for algorithms that can sign a signature base.
/// RFC 9421 signature algorithm identifiers.
///
/// The wire value is a bare string compared by equality, so a typo in a new
/// implementation would compile and simply never match. Naming the set means
/// both the signer and the verifier return a value from it, and the
/// `Accept-Signature` advertisement spells the same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// `ecdsa-p256-sha256` — RFC 9421 Section 3.3.4. DER-encoded signatures.
    EcdsaP256Sha256,
    /// `ed25519` — RFC 9421 Section 3.3.6. Raw 64-byte signatures.
    Ed25519,
    /// `hmac-sha256` — RFC 9421 Section 3.3.3.
    HmacSha256,
}

impl SignatureAlgorithm {
    /// The identifier as it appears in a `Signature-Input` `alg` parameter.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            Self::Ed25519 => "ed25519",
            Self::HmacSha256 => "hmac-sha256",
        }
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub trait SigningAlgorithm: Send + Sync {
    /// The RFC 9421 algorithm identifier.
    fn algorithm(&self) -> SignatureAlgorithm;

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
    /// The RFC 9421 algorithm identifier.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Verify that `signature` is valid for the given `base` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::VerificationFailed`] if the signature is invalid.
    fn verify(&self, base: &[u8], signature: &[u8]) -> Result<(), HttpSigError>;
}
