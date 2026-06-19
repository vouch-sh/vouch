// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ES256 (P-256 ECDSA) key management for FAPI 2.0 client authentication.
//!
//! This key is a **per-device** artifact used for OAuth 2.0 confidential client
//! authentication (`private_key_jwt`) and DPoP proof generation. It is **not**
//! bound to the YubiKey — the YubiKey provides *user* identity via FIDO2, while
//! this key provides *device/client* identity.
//!
//! When a user inserts their registered YubiKey into a new machine, `vouch login`
//! automatically generates a new client key and registers a new `client_id` via
//! RFC 7591 Dynamic Client Registration. This is the correct behavior:
//!
//! - **Client key = device identity** (OAuth confidential client authentication)
//! - **FIDO2 credential = user identity** (portable on YubiKey)
//! - **DPoP binding** prevents token theft even if the client key is compromised
//! - The `private_key_jwt` + DPoP combination prevents stolen authorization code attacks
//!
//! Keys are stored in the OS keychain when available (see [`super::key_store`]),
//! falling back to JSON files on disk with 0600 permissions. Enterprise
//! deployments can further tighten security by:
//! 1. Disabling open registration (require MDM-issued software statements)
//! 2. Binding `client_id` to FIDO2 `credential_id` at first registration
//! 3. Using Secure Enclave / TPM for client key generation

use std::collections::BTreeMap;
use std::path::Path;

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::error::FapiError;

/// ES256 client keypair with associated metadata.
///
/// The private key material is stored in a `Zeroizing` wrapper
/// to ensure it is cleared from memory when dropped.
pub struct ClientKey {
    /// The ECDSA key pair used for signing.
    key_pair: EcdsaKeyPair,
    /// PKCS#8 DER-encoded private key, zeroized on drop.
    der_bytes: Zeroizing<Vec<u8>>,
    /// Key ID (JWK thumbprint per RFC 7638).
    kid: String,
}

impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKey")
            .field("kid", &self.kid)
            .field("der_bytes", &"[REDACTED]")
            .finish()
    }
}

/// Public EC JWK (JSON Web Key) for P-256 keys (RFC 7517, RFC 7518 Section 6.2).
///
/// Contains only the public key components — no private key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicEcJwk {
    /// Key type — always "EC".
    pub kty: String,
    /// Curve — always "P-256".
    pub crv: String,
    /// Base64url-encoded X coordinate of the public key point.
    pub x: String,
    /// Base64url-encoded Y coordinate of the public key point.
    pub y: String,
    /// Key ID (JWK thumbprint per RFC 7638).
    pub kid: String,
}

/// On-disk serialization format for a `ClientKey`.
///
/// The `pkcs8` field contains the PKCS#8 DER bytes as base64url.
/// The `Debug` implementation redacts `pkcs8` to prevent accidental
/// logging of private key material.
#[derive(Serialize, Deserialize)]
pub struct ClientKeyFile {
    /// Key type — always "EC".
    pub kty: String,
    /// Curve — always "P-256".
    pub crv: String,
    /// Base64url-encoded X coordinate.
    pub x: String,
    /// Base64url-encoded Y coordinate.
    pub y: String,
    /// Key ID (JWK thumbprint per RFC 7638).
    pub kid: String,
    /// Base64url-encoded PKCS#8 DER private key bytes.
    pub pkcs8: String,
}

impl std::fmt::Debug for ClientKeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKeyFile")
            .field("kty", &self.kty)
            .field("crv", &self.crv)
            .field("x", &self.x)
            .field("y", &self.y)
            .field("kid", &self.kid)
            .field("pkcs8", &"[REDACTED]")
            .finish()
    }
}

impl ClientKey {
    /// Generate a new P-256 ECDSA keypair.
    ///
    /// The key ID is computed as the RFC 7638 JWK thumbprint of the public key.
    ///
    /// # Errors
    ///
    /// Returns [`FapiError::KeyGeneration`] if the key pair cannot be generated.
    /// Returns [`FapiError::ThumbprintComputation`] if the thumbprint cannot be computed.
    pub fn generate() -> Result<Self, FapiError> {
        let rng = SystemRandom::new();

        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| FapiError::KeyGeneration(e.to_string()))?;

        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref())
                .map_err(|e| FapiError::KeyGeneration(e.to_string()))?;

        let der_bytes = Zeroizing::new(pkcs8_bytes.as_ref().to_vec());

        let (x, y) = extract_ec_coordinates(&key_pair)?;
        let kid = compute_thumbprint(&x, &y)?;

        Ok(Self {
            key_pair,
            der_bytes,
            kid,
        })
    }

    /// Reconstruct a `ClientKey` from a [`ClientKeyFile`].
    ///
    /// Verifies that the stored thumbprint matches the computed thumbprint
    /// of the loaded public key.
    ///
    /// # Errors
    ///
    /// Returns [`FapiError::InvalidKeyFormat`] if the format is incorrect.
    /// Returns [`FapiError::ThumbprintComputation`] if the thumbprint mismatches.
    pub fn from_key_file(key_file: &ClientKeyFile) -> Result<Self, FapiError> {
        let pkcs8_der = URL_SAFE_NO_PAD
            .decode(&key_file.pkcs8)
            .map_err(|e| FapiError::InvalidKeyFormat(format!("base64url decode error: {e}")))?;

        let der_bytes = Zeroizing::new(pkcs8_der);

        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der_bytes)
            .map_err(|e| FapiError::InvalidKeyFormat(format!("PKCS#8 parse error: {e}")))?;

        let (x, y) = extract_ec_coordinates(&key_pair)?;
        let computed_kid = compute_thumbprint(&x, &y)?;

        if computed_kid != key_file.kid {
            return Err(FapiError::InvalidKeyFormat(format!(
                "key ID mismatch: stored={}, computed={}",
                key_file.kid, computed_kid
            )));
        }

        Ok(Self {
            key_pair,
            der_bytes,
            kid: computed_kid,
        })
    }

    /// Load a `ClientKey` from a JSON key file on disk.
    ///
    /// Verifies that the stored thumbprint matches the computed thumbprint
    /// of the loaded public key.
    ///
    /// # Errors
    ///
    /// Returns [`FapiError::KeyLoad`] if the file cannot be read or parsed.
    /// Returns [`FapiError::InvalidKeyFormat`] if the format is incorrect.
    /// Returns [`FapiError::ThumbprintComputation`] if the thumbprint mismatches.
    pub fn load(path: &Path) -> Result<Self, FapiError> {
        let content = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| FapiError::KeyLoad(format!("{}: {e}", path.display())))?,
        );

        let key_file: ClientKeyFile = serde_json::from_str(&content)
            .map_err(|e| FapiError::InvalidKeyFormat(format!("JSON parse error: {e}")))?;

        Self::from_key_file(&key_file)
    }

    /// Save this key to a JSON file with 0600 permissions.
    ///
    /// # Errors
    ///
    /// Returns [`FapiError::KeySave`] if the file cannot be written.
    /// Returns [`FapiError::ThumbprintComputation`] if coordinates cannot be extracted.
    pub fn save(&self, path: &Path) -> Result<(), FapiError> {
        let key_file = self.to_key_file()?;

        let json = serde_json::to_vec_pretty(&key_file)
            .map_err(|e| FapiError::KeySave(format!("JSON serialization error: {e}")))?;

        vouch_common::fs::atomic_write_secure(path, &json)
            .map_err(|e| FapiError::KeySave(format!("{}: {e}", path.display())))?;

        Ok(())
    }

    /// Serialize this key as a [`ClientKeyFile`] for storage.
    ///
    /// # Errors
    ///
    /// Returns [`FapiError::ThumbprintComputation`] if coordinates cannot be extracted.
    pub fn to_key_file(&self) -> Result<ClientKeyFile, FapiError> {
        let (x, y) = extract_ec_coordinates(&self.key_pair)?;
        let pkcs8_b64 = URL_SAFE_NO_PAD.encode(&*self.der_bytes);

        Ok(ClientKeyFile {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x,
            y,
            kid: self.kid.clone(),
            pkcs8: pkcs8_b64,
        })
    }

    /// Get the key ID (JWK thumbprint).
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Get a reference to the PKCS#8 DER-encoded private key bytes.
    #[must_use]
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.der_bytes
    }

    /// Get the public key as a [`PublicEcJwk`].
    ///
    /// # Errors
    ///
    /// Returns [`FapiError::ThumbprintComputation`] if coordinates cannot be extracted.
    pub fn public_jwk(&self) -> Result<PublicEcJwk, FapiError> {
        let (x, y) = extract_ec_coordinates(&self.key_pair)?;
        Ok(PublicEcJwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x,
            y,
            kid: self.kid.clone(),
        })
    }

    /// Get the `jsonwebtoken` encoding key for signing JWTs.
    #[must_use]
    pub fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_ec_der(&self.der_bytes)
    }

    /// Sign raw bytes using the ECDSA private key.
    ///
    /// The signature is in IEEE P1363 format (r || s, 64 bytes), which is
    /// the correct encoding for JWS ES256 signatures.
    ///
    /// # Errors
    ///
    /// Returns [`FapiError::JwtSigning`] if signing fails.
    pub fn sign_raw(&self, data: &[u8]) -> Result<Vec<u8>, FapiError> {
        let rng = SystemRandom::new();
        let sig = self
            .key_pair
            .sign(&rng, data)
            .map_err(|e| FapiError::JwtSigning(e.to_string()))?;
        Ok(sig.as_ref().to_vec())
    }
}

/// Extract the base64url-encoded x and y coordinates from a P-256 public key.
///
/// P-256 uncompressed public keys are 65 bytes: `0x04 || x (32 bytes) || y (32 bytes)`.
fn extract_ec_coordinates(key_pair: &EcdsaKeyPair) -> Result<(String, String), FapiError> {
    let pub_key_bytes = key_pair.public_key().as_ref();

    if pub_key_bytes.len() != 65 {
        return Err(FapiError::ThumbprintComputation(format!(
            "invalid P-256 public key length: expected 65, got {}",
            pub_key_bytes.len()
        )));
    }

    if pub_key_bytes.first() != Some(&0x04) {
        return Err(FapiError::ThumbprintComputation(
            "invalid P-256 public key format: expected uncompressed point (0x04)".to_string(),
        ));
    }

    let x = pub_key_bytes
        .get(1..33)
        .map(|b| URL_SAFE_NO_PAD.encode(b))
        .ok_or_else(|| {
            FapiError::ThumbprintComputation("failed to extract x coordinate".to_string())
        })?;

    let y = pub_key_bytes
        .get(33..65)
        .map(|b| URL_SAFE_NO_PAD.encode(b))
        .ok_or_else(|| {
            FapiError::ThumbprintComputation("failed to extract y coordinate".to_string())
        })?;

    Ok((x, y))
}

/// Compute the RFC 7638 JWK thumbprint for a P-256 public key.
///
/// The canonical JSON is: `{"crv":"P-256","kty":"EC","x":"...","y":"..."}`
/// (lexicographically ordered keys). The thumbprint is `base64url(SHA-256(canonical_json))`.
fn compute_thumbprint(x: &str, y: &str) -> Result<String, FapiError> {
    // RFC 7638 requires lexicographic key ordering — use BTreeMap to guarantee this.
    let mut map = BTreeMap::new();
    map.insert("crv", "P-256");
    map.insert("kty", "EC");
    map.insert("x", x);
    map.insert("y", y);

    let canonical_json = serde_json::to_vec(&map)
        .map_err(|e| FapiError::ThumbprintComputation(format!("JSON serialization: {e}")))?;

    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &canonical_json);
    Ok(URL_SAFE_NO_PAD.encode(digest.as_ref()))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_key_has_kid() {
        let key = ClientKey::generate().expect("should generate key");
        assert!(!key.kid().is_empty(), "kid should not be empty");
    }

    #[test]
    fn test_generate_key_public_jwk() {
        let key = ClientKey::generate().expect("should generate key");
        let jwk = key.public_jwk().expect("should get public JWK");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert!(!jwk.x.is_empty());
        assert!(!jwk.y.is_empty());
        assert_eq!(jwk.kid, key.kid());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("client_key.json");

        let key1 = ClientKey::generate().expect("should generate key");
        key1.save(&path).expect("should save key");

        let key2 = ClientKey::load(&path).expect("should load key");
        assert_eq!(key1.kid(), key2.kid());

        let jwk1 = key1.public_jwk().unwrap();
        let jwk2 = key2.public_jwk().unwrap();
        assert_eq!(jwk1.x, jwk2.x);
        assert_eq!(jwk1.y, jwk2.y);
    }

    #[test]
    fn test_load_rejects_tampered_kid() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("tampered_key.json");

        let key = ClientKey::generate().unwrap();
        key.save(&path).unwrap();

        // Tamper with the kid in the file
        let content = std::fs::read_to_string(&path).unwrap();
        let mut key_file: ClientKeyFile = serde_json::from_str(&content).unwrap();
        key_file.kid = "tampered_kid".to_string();
        let tampered = serde_json::to_string_pretty(&key_file).unwrap();
        std::fs::write(&path, tampered).unwrap();

        let result = ClientKey::load(&path);
        assert!(result.is_err(), "should reject tampered kid");
        let err = result.unwrap_err();
        assert!(
            matches!(err, FapiError::InvalidKeyFormat(_)),
            "should be InvalidKeyFormat"
        );
    }

    #[test]
    fn test_sign_raw_produces_64_bytes() {
        let key = ClientKey::generate().unwrap();
        let sig = key.sign_raw(b"hello world").unwrap();
        // ES256 signature: r || s, each 32 bytes
        assert_eq!(sig.len(), 64, "ES256 signature should be 64 bytes");
    }

    #[test]
    fn test_client_key_file_debug_redacts_pkcs8() {
        let key_file = ClientKeyFile {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: "xcoord".to_string(),
            y: "ycoord".to_string(),
            kid: "kidvalue".to_string(),
            pkcs8: "super_secret_key_material".to_string(),
        };
        let debug_str = format!("{key_file:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("super_secret_key_material"));
    }

    #[test]
    fn test_client_key_debug_redacts_der_bytes() {
        let key = ClientKey::generate().unwrap();
        let debug_str = format!("{key:?}");
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_thumbprint_is_deterministic() {
        let key = ClientKey::generate().unwrap();
        let jwk = key.public_jwk().unwrap();
        let t1 = compute_thumbprint(&jwk.x, &jwk.y).unwrap();
        let t2 = compute_thumbprint(&jwk.x, &jwk.y).unwrap();
        assert_eq!(t1, t2);
    }
}
