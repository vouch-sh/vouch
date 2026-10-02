// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Adapter bridging the FAPI `ClientKey` to RFC 9421 HTTP message signatures.
//!
//! The `ClientKey` holds the P-256 key pair used for `private_key_jwt` and
//! DPoP. This adapter lets the same key sign `/v1/*` API requests. RFC 9421
//! `ecdsa-p256-sha256` (Section 3.3.4) and JWS ES256 share one signature
//! encoding, the 64-octet `r || s` array, so the adapter signs through
//! [`ClientKey::sign_raw`].

use vouch_httpsig::HttpSigError;
use vouch_httpsig::algorithm::SigningAlgorithm;

use super::key::ClientKey;
use vouch_httpsig::algorithm::SignatureAlgorithm;

/// Adapter that wraps a `ClientKey` as an RFC 9421 `ecdsa-p256-sha256` signer.
pub struct ClientKeySigner<'a> {
    key: &'a ClientKey,
}

impl std::fmt::Debug for ClientKeySigner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKeySigner")
            .field("key_id", &self.key.kid())
            .finish()
    }
}

impl<'a> ClientKeySigner<'a> {
    /// Create a signer adapter from a `ClientKey`.
    #[must_use]
    pub fn new(key: &'a ClientKey) -> Self {
        Self { key }
    }
}

impl SigningAlgorithm for ClientKeySigner<'_> {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaP256Sha256
    }

    fn key_id(&self) -> &str {
        self.key.kid()
    }

    fn sign(&self, base: &[u8]) -> Result<Vec<u8>, HttpSigError> {
        self.key
            .sign_raw(base)
            .map_err(|e| HttpSigError::SigningFailed(format!("ECDSA sign: {e}")))
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use vouch_httpsig::algorithm::VerifyingAlgorithm;
    use vouch_httpsig::algorithm::ecdsa_p256::EcdsaP256Verifier;

    use super::*;

    // RFC 9421 §3.3.4: the signer emits "a single 64-octet array consisting of
    // the encoded value of r followed by the encoded value of s", which is
    // what the server-side verifier accepts.
    #[test]
    fn test_signature_is_r_s_and_verifies() {
        let key = ClientKey::generate().unwrap();
        let signer = ClientKeySigner::new(&key);

        let base = b"signature base";
        let sig = signer.sign(base).unwrap();
        assert_eq!(sig.len(), 64);

        let jwk = key.public_jwk().unwrap();
        let mut point = vec![0x04];
        point.extend(URL_SAFE_NO_PAD.decode(&jwk.x).unwrap());
        point.extend(URL_SAFE_NO_PAD.decode(&jwk.y).unwrap());
        EcdsaP256Verifier::new(&point).verify(base, &sig).unwrap();
    }

    // RFC 9421 §2.3: keyid is the client key's JWK thumbprint.
    #[test]
    fn test_key_id_is_client_kid() {
        let key = ClientKey::generate().unwrap();
        assert_eq!(ClientKeySigner::new(&key).key_id(), key.kid());
    }
}
