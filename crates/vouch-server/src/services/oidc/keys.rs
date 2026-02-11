// SPDX-License-Identifier: BUSL-1.1
//! OIDC signing key management for ES256 (P-256 ECDSA) JWT signing.
//!
//! This module provides functionality to:
//! - Generate P-256 EC keypairs for OIDC ID token signing
//! - Load keys from PEM content or generate new ones
//! - Export public keys in JWK format for the JWKS endpoint
//! - Sign JWTs with ES256 algorithm

use anyhow::{Context, Result, bail};
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

/// OIDC signing key using P-256 ECDSA (ES256).
pub struct OidcSigningKey {
    /// The ECDSA key pair for signing.
    key_pair: EcdsaKeyPair,
    /// Key ID for the JWK.
    key_id: String,
    /// DER-encoded private key (PKCS#8 format for jsonwebtoken).
    der_bytes: Vec<u8>,
}

impl OidcSigningKey {
    /// Generate a new P-256 ECDSA key pair.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();

        // Generate a new key pair using PKCS#8 format
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| anyhow::anyhow!("Failed to generate ECDSA key: {e}"))?;

        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref())
                .map_err(|e| anyhow::anyhow!("Failed to parse generated ECDSA key: {e}"))?;

        // Generate key ID from first 8 bytes of public key hash
        let pub_key_bytes = key_pair.public_key().as_ref();
        let key_id = format!(
            "vouch-oidc-{}",
            hex::encode(pub_key_bytes.get(..8).unwrap_or(pub_key_bytes))
        );

        // Store DER bytes for jsonwebtoken
        let der_bytes = pkcs8_bytes.as_ref().to_vec();

        tracing::info!("Generated new OIDC signing key: {}", key_id);

        Ok(Self {
            key_pair,
            key_id,
            der_bytes,
        })
    }

    /// Load from PEM-encoded private key content.
    pub fn from_pem(pem_content: &str) -> Result<Self> {
        // Parse PEM to get DER bytes
        let pem_content = pem_content.trim();

        // Extract the base64 content between headers
        let der_bytes = if pem_content.starts_with("-----BEGIN") {
            Self::pem_to_der(pem_content)?
        } else {
            // Assume it's already base64-encoded DER
            URL_SAFE_NO_PAD
                .decode(pem_content)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(pem_content))
                .context("Invalid base64 encoding for key")?
        };

        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse ECDSA key from PEM: {e}"))?;

        // Generate key ID from public key
        let pub_key_bytes = key_pair.public_key().as_ref();
        let key_id = format!(
            "vouch-oidc-{}",
            hex::encode(pub_key_bytes.get(..8).unwrap_or(pub_key_bytes))
        );

        tracing::info!("Loaded OIDC signing key from PEM: {}", key_id);

        Ok(Self {
            key_pair,
            key_id,
            der_bytes,
        })
    }

    /// Load from environment variable content or generate a new key.
    pub fn load_or_generate(pem_content: Option<&str>) -> Result<Self> {
        if let Some(pem) = pem_content {
            if pem.trim().is_empty() {
                tracing::info!("Empty OIDC signing key provided, generating new key");
                Self::generate()
            } else {
                Self::from_pem(pem)
            }
        } else {
            tracing::info!("No OIDC signing key provided, generating ephemeral key");
            Self::generate()
        }
    }

    /// Get the key ID.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the `jsonwebtoken` encoding key for signing JWTs.
    #[must_use]
    pub fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_ec_der(&self.der_bytes)
    }

    /// Get the public key as a JWK for the JWKS endpoint.
    pub fn public_key_jwk(&self) -> Result<EcJwk> {
        let pub_key_bytes = self.key_pair.public_key().as_ref();

        // P-256 public key is 65 bytes: 0x04 || x (32 bytes) || y (32 bytes)
        if pub_key_bytes.len() != 65 {
            bail!(
                "Invalid P-256 public key length: expected 65, got {}",
                pub_key_bytes.len()
            );
        }
        if pub_key_bytes.first() != Some(&0x04) {
            bail!("Invalid P-256 public key format: expected uncompressed point (0x04)");
        }

        let x = pub_key_bytes
            .get(1..33)
            .map(|b| URL_SAFE_NO_PAD.encode(b))
            .ok_or_else(|| anyhow::anyhow!("Failed to extract x coordinate"))?;
        let y = pub_key_bytes
            .get(33..65)
            .map(|b| URL_SAFE_NO_PAD.encode(b))
            .ok_or_else(|| anyhow::anyhow!("Failed to extract y coordinate"))?;

        Ok(EcJwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            alg: "ES256".to_string(),
            kid: self.key_id.clone(),
            key_use: "sig".to_string(),
            x,
            y,
        })
    }

    /// Sign a JWT with the given claims.
    pub fn sign_jwt<T: Serialize>(&self, claims: &T) -> Result<String> {
        let encoding_key = self.encoding_key();

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        jsonwebtoken::encode(&header, claims, &encoding_key)
            .map_err(|e| anyhow::anyhow!("Failed to sign JWT: {e}"))
    }

    /// Convert PEM to DER bytes.
    fn pem_to_der(pem_content: &str) -> Result<Vec<u8>> {
        // Find the content between headers
        let lines: Vec<&str> = pem_content.lines().collect();
        let mut base64_content = String::new();
        let mut in_content = false;

        for line in lines {
            let line = line.trim();
            if line.starts_with("-----BEGIN") {
                in_content = true;
                continue;
            }
            if line.starts_with("-----END") {
                break;
            }
            if in_content {
                base64_content.push_str(line);
            }
        }

        base64::engine::general_purpose::STANDARD
            .decode(&base64_content)
            .context("Failed to decode PEM base64 content")
    }
}

/// EC JWK (JSON Web Key) for P-256 keys (RFC 7517 Section 4, RFC 7518 Section 6.2).
#[derive(Debug, Clone, Serialize)]
pub struct EcJwk {
    /// RFC 7517 Section 4.1: Key Type — "EC" for Elliptic Curve.
    pub kty: String,
    /// RFC 7518 Section 6.2.1.1: Curve — "P-256" for NIST P-256.
    pub crv: String,
    /// RFC 7517 Section 4.4: Algorithm — "ES256" (ECDSA using P-256 and SHA-256).
    pub alg: String,
    /// RFC 7517 Section 4.5: Key ID.
    pub kid: String,
    /// RFC 7517 Section 4.2: Public Key Use — "sig" for signature.
    #[serde(rename = "use")]
    pub key_use: String,
    /// RFC 7518 Section 6.2.1.2: X Coordinate (base64url encoded).
    pub x: String,
    /// RFC 7518 Section 6.2.1.3: Y Coordinate (base64url encoded).
    pub y: String,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        exp: i64,
        iat: i64,
    }

    #[test]
    fn test_generate_key() {
        let key = OidcSigningKey::generate().expect("Should generate key");
        assert!(key.key_id().starts_with("vouch-oidc-"));
    }

    #[test]
    fn test_public_key_jwk() {
        let key = OidcSigningKey::generate().expect("Should generate key");
        let jwk = key.public_key_jwk().expect("Should create JWK");

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.alg, "ES256");
        assert_eq!(jwk.key_use, "sig");
        assert!(!jwk.x.is_empty());
        assert!(!jwk.y.is_empty());
        assert_eq!(jwk.kid, key.key_id());
    }

    #[test]
    fn test_sign_and_verify_jwt() {
        let key = OidcSigningKey::generate().expect("Should generate key");

        let claims = TestClaims {
            sub: "test@example.com".to_string(),
            iss: "https://example.com".to_string(),
            exp: 9999999999,
            iat: 1000000000,
        };

        let token = key.sign_jwt(&claims).expect("Should sign JWT");

        // Verify the token has the correct structure
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        // Decode and verify header
        let header_json = URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("Header should be base64");
        let header: serde_json::Value =
            serde_json::from_slice(&header_json).expect("Header should be JSON");

        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert!(header.get("kid").is_some(), "Header should have kid");
    }

    #[test]
    fn test_load_or_generate_none() {
        let key = OidcSigningKey::load_or_generate(None).expect("Should generate key");
        assert!(key.key_id().starts_with("vouch-oidc-"));
    }

    #[test]
    fn test_load_or_generate_empty() {
        let key = OidcSigningKey::load_or_generate(Some("")).expect("Should generate key");
        assert!(key.key_id().starts_with("vouch-oidc-"));
    }

    #[test]
    fn test_roundtrip_pem() {
        // Generate a key
        let key1 = OidcSigningKey::generate().expect("Should generate key");
        let jwk1 = key1.public_key_jwk().expect("Should create JWK");

        // Export to PEM and reload
        let pem_str = pkcs8_to_pem(&key1.der_bytes);
        let key2 = OidcSigningKey::from_pem(&pem_str).expect("Should load from PEM");
        let jwk2 = key2.public_key_jwk().expect("Should create JWK");

        // Public keys should match
        assert_eq!(jwk1.x, jwk2.x);
        assert_eq!(jwk1.y, jwk2.y);
    }

    /// Convert PKCS#8 DER to PEM format for testing.
    fn pkcs8_to_pem(der_bytes: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der_bytes);
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");

        // Add base64 in 64-character lines
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            pem.push('\n');
        }

        pem.push_str("-----END PRIVATE KEY-----\n");
        pem
    }
}
