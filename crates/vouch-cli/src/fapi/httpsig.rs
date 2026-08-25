// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Adapter bridging the FAPI `ClientKey` to RFC 9421 HTTP message signatures.
//!
//! The `ClientKey` already holds an `EcdsaKeyPair` (P-256) for `private_key_jwt`
//! and DPoP. This adapter wraps it to implement `vouch_httpsig::algorithm::SigningAlgorithm`,
//! allowing the same key to sign `/v1/*` API requests with RFC 9421 HTTP signatures.
//!
//! Note: RFC 9421 uses DER-encoded ECDSA signatures (ASN.1), while JWS/DPoP uses
//! fixed-size R||S. The `ClientKey` currently uses `ECDSA_P256_SHA256_FIXED_SIGNING`
//! (R||S). This adapter generates a *separate* `EcdsaKeyPair` using the ASN.1 signing
//! algorithm from the same PKCS#8 key bytes.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};

use vouch_httpsig::HttpSigError;
use vouch_httpsig::algorithm::SigningAlgorithm;

use super::error::FapiError;
use super::key::ClientKey;

/// Adapter that wraps a `ClientKey` as an RFC 9421 signer.
///
/// Produces DER-encoded ECDSA P-256 signatures as required by
/// RFC 9421 Section 3.3.3 (`ecdsa-p256-sha256`).
pub struct ClientKeySigner {
    key_pair: EcdsaKeyPair,
    key_id: String,
}

impl std::fmt::Debug for ClientKeySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKeySigner")
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl ClientKeySigner {
    /// Create a signer adapter from a `ClientKey`.
    ///
    /// Reconstructs the key pair using the ASN.1 signing algorithm
    /// to produce DER-encoded signatures per RFC 9421.
    ///
    /// # Errors
    ///
    /// Returns [`FapiError::InvalidKeyFormat`] if the PKCS#8 bytes cannot be
    /// parsed with the ASN.1 signing algorithm.
    pub fn from_client_key(client_key: &ClientKey) -> Result<Self, FapiError> {
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, client_key.pkcs8_der())
                .map_err(|e| {
                    FapiError::InvalidKeyFormat(format!("ASN.1 key pair from PKCS#8: {e}"))
                })?;

        Ok(Self {
            key_pair,
            key_id: client_key.kid().to_string(),
        })
    }
}

impl SigningAlgorithm for ClientKeySigner {
    fn algorithm(&self) -> vouch_httpsig::algorithm::SignatureAlgorithm {
        vouch_httpsig::algorithm::SignatureAlgorithm::EcdsaP256Sha256
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, base: &[u8]) -> Result<Vec<u8>, HttpSigError> {
        let rng = SystemRandom::new();
        let sig = self
            .key_pair
            .sign(&rng, base)
            .map_err(|e| HttpSigError::SigningFailed(format!("ECDSA ASN.1 sign: {e}")))?;
        Ok(sig.as_ref().to_vec())
    }
}
