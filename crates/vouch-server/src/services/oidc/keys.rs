// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC signing key management for ES256 (P-256 ECDSA) JWT signing.
//!
//! This module provides functionality to:
//! - Generate P-256 EC keypairs for OIDC ID token signing (Local variant)
//! - Sign using AWS KMS P-256 keys via `kms:Sign` (Kms variant)
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
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::crypto::kms_signer::KmsSignerP256;

/// OIDC signing key using P-256 ECDSA (ES256).
///
/// Supports two modes:
/// - `Local`: Uses a local ECDSA key pair (generated or from PEM)
/// - `Kms`: Uses an AWS KMS P-256 key via `kms:Sign`
pub enum OidcSigningKey {
    /// Local P-256 ECDSA key pair for signing.
    Local {
        /// The ECDSA key pair for signing.
        key_pair: EcdsaKeyPair,
        /// Key ID for the JWK.
        key_id: String,
        /// DER-encoded private key (PKCS#8 format for jsonwebtoken).
        /// Wrapped in `Zeroizing` to clear from memory on drop.
        der_bytes: Zeroizing<Vec<u8>>,
        /// Cached decoding key for ES256 JWT verification.
        decoding_key: DecodingKey,
    },
    /// AWS KMS P-256 ECDSA key for signing.
    Kms {
        /// KMS signer that calls `kms:Sign` for each operation.
        signer: KmsSignerP256,
        /// Key ID for the JWK.
        key_id: String,
        /// Cached decoding key for ES256 JWT verification.
        decoding_key: DecodingKey,
    },
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

        // Store DER bytes for jsonwebtoken (zeroized on drop)
        let der_bytes = Zeroizing::new(pkcs8_bytes.as_ref().to_vec());

        // Cache the decoding key at construction time
        let decoding_key = build_decoding_key_from_pair(&key_pair)?;

        tracing::info!("Generated new OIDC signing key: {}", key_id);

        Ok(Self::Local {
            key_pair,
            key_id,
            der_bytes,
            decoding_key,
        })
    }

    /// Load from PEM-encoded private key content.
    pub fn from_pem(pem_content: &str) -> Result<Self> {
        // Parse PEM to get DER bytes
        let pem_content = pem_content.trim();

        // Extract the base64 content between headers (zeroized on drop)
        let der_bytes = Zeroizing::new(if pem_content.starts_with("-----BEGIN") {
            Self::pem_to_der(pem_content)?
        } else {
            // Assume it's already base64-encoded DER
            URL_SAFE_NO_PAD
                .decode(pem_content)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(pem_content))
                .context("Invalid base64 encoding for key")?
        });

        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse ECDSA key from PEM: {e}"))?;

        // Generate key ID from public key
        let pub_key_bytes = key_pair.public_key().as_ref();
        let key_id = format!(
            "vouch-oidc-{}",
            hex::encode(pub_key_bytes.get(..8).unwrap_or(pub_key_bytes))
        );

        // Cache the decoding key at construction time
        let decoding_key = build_decoding_key_from_pair(&key_pair)?;

        tracing::info!("Loaded OIDC signing key from PEM: {}", key_id);

        Ok(Self::Local {
            key_pair,
            key_id,
            der_bytes,
            decoding_key,
        })
    }

    /// Create a KMS-backed OIDC signing key.
    ///
    /// Calls `kms:GetPublicKey` to fetch and cache the P-256 public key.
    pub async fn from_kms(kms_client: aws_sdk_kms::Client, key_id: String) -> Result<Self> {
        let signer = KmsSignerP256::new(kms_client, key_id).await?;

        // Build decoding key from x/y coordinates
        let decoding_key = DecodingKey::from_ec_components(&signer.x_b64(), &signer.y_b64())
            .map_err(|e| {
                anyhow::anyhow!("Failed to build decoding key from KMS public key: {e}")
            })?;

        // Generate key ID from first 8 bytes of public key
        let pub_bytes = signer.public_key_bytes();
        let kid = format!(
            "vouch-oidc-kms-{}",
            hex::encode(pub_bytes.get(..8).unwrap_or(pub_bytes))
        );

        tracing::debug!("KMS OIDC signing key initialized: {}", kid);

        Ok(Self::Kms {
            signer,
            key_id: kid,
            decoding_key,
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
        match self {
            Self::Local { key_id, .. } | Self::Kms { key_id, .. } => key_id,
        }
    }

    /// Get the cached `jsonwebtoken` decoding key for verifying ES256 JWTs.
    ///
    /// Used to verify both ID tokens (OIDC Core Section 2) and
    /// access tokens (RFC 9068) signed by this key.
    #[must_use]
    pub fn decoding_key(&self) -> &DecodingKey {
        match self {
            Self::Local { decoding_key, .. } | Self::Kms { decoding_key, .. } => decoding_key,
        }
    }

    /// Get the public key as a JWK for the JWKS endpoint.
    pub fn public_key_jwk(&self) -> Result<EcJwk> {
        match self {
            Self::Local {
                key_pair, key_id, ..
            } => {
                let (x, y) = extract_ec_coordinates(key_pair)?;
                Ok(EcJwk {
                    kty: "EC".to_string(),
                    crv: "P-256".to_string(),
                    alg: "ES256".to_string(),
                    kid: key_id.clone(),
                    key_use: "sig".to_string(),
                    x,
                    y,
                })
            }
            Self::Kms { signer, key_id, .. } => Ok(EcJwk {
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                alg: "ES256".to_string(),
                kid: key_id.clone(),
                key_use: "sig".to_string(),
                x: signer.x_b64(),
                y: signer.y_b64(),
            }),
        }
    }

    /// Sign a JWT with the given claims (ID token style, `typ: "JWT"`).
    pub async fn sign_jwt<T: Serialize>(&self, claims: &T) -> Result<String> {
        self.sign_jwt_with_typ(claims, None).await
    }

    /// Sign a JWT access token per RFC 9068 Section 2.1.
    ///
    /// RFC 9068 Section 2.1: The "typ" header parameter MUST be set to
    /// "at+jwt" to distinguish access tokens from other JWT types (e.g.,
    /// ID tokens). This prevents token substitution attacks where an ID
    /// token could be used in place of an access token.
    pub async fn sign_access_token_jwt<T: Serialize>(&self, claims: &T) -> Result<String> {
        self.sign_jwt_with_typ(claims, Some("at+jwt")).await
    }

    /// Sign a JWT with the given claims and optional `typ` header override.
    ///
    /// When `typ` is `None`, the default `"JWT"` type is used (for ID tokens).
    /// When `typ` is `Some("at+jwt")`, produces an RFC 9068 access token.
    async fn sign_jwt_with_typ<T: Serialize>(
        &self,
        claims: &T,
        typ: Option<&str>,
    ) -> Result<String> {
        match self {
            Self::Local {
                der_bytes, key_id, ..
            } => {
                // Serialize claims and clone key material before crossing
                // the spawn_blocking boundary (avoids T: Send + 'static).
                let claims_value = serde_json::to_value(claims)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize JWT claims: {e}"))?;
                let der = der_bytes.clone();
                let kid = key_id.clone();
                let typ_owned = typ.map(String::from);

                // Offload ES256 signing to a blocking thread to avoid
                // starving the tokio runtime on 1-vCPU instances.
                tokio::task::spawn_blocking(move || {
                    let encoding_key = EncodingKey::from_ec_der(&der);
                    let mut header = Header::new(Algorithm::ES256);
                    if let Some(t) = typ_owned {
                        header.typ = Some(t);
                    }
                    header.kid = Some(kid);

                    jsonwebtoken::encode(&header, &claims_value, &encoding_key)
                        .map_err(|e| anyhow::anyhow!("Failed to sign JWT: {e}"))
                })
                .await
                .map_err(|e| anyhow::anyhow!("JWT signing task failed: {e}"))?
            }
            Self::Kms { signer, key_id, .. } => {
                sign_jwt_with_kms(signer, key_id, claims, typ).await
            }
        }
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

/// JWT header for KMS-signed tokens.
///
/// Uses a typed struct to guarantee field presence and deterministic
/// serialization order (matching what `jsonwebtoken::encode` produces).
/// Any future header fields must be added here and in the Local
/// variant's `jsonwebtoken::Header` to keep both paths in sync.
#[derive(serde::Serialize)]
struct KmsJwtHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

/// Manually construct and sign a JWT using KMS.
///
/// Steps:
/// 1. Build header JSON with `alg: "ES256"`, `typ`, and `kid`
/// 2. Serialize claims to JSON
/// 3. Base64url-encode header and payload, join with "."
/// 4. Call `signer.sign_raw(signing_input)` → DER signature
/// 5. Convert DER ECDSA to R||S format for JWT
/// 6. Base64url-encode signature, return `header.payload.signature`
async fn sign_jwt_with_kms<T: Serialize>(
    signer: &KmsSignerP256,
    key_id: &str,
    claims: &T,
    typ: Option<&str>,
) -> Result<String> {
    use crate::crypto::kms_signer::der_ecdsa_to_jwt;

    let header = KmsJwtHeader {
        alg: "ES256",
        typ: typ.unwrap_or("JWT"),
        kid: key_id,
    };

    let header_json = serde_json::to_vec(&header).context("Failed to serialize JWT header")?;
    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);

    // Serialize claims
    let claims_json = serde_json::to_vec(claims).context("Failed to serialize JWT claims")?;
    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

    // Build signing input: header.payload
    let signing_input = format!("{header_b64}.{claims_b64}");

    // Sign with KMS (ECDSA_SHA_256, MessageType: Raw)
    let der_sig = signer
        .sign_raw(signing_input.as_bytes())
        .await
        .context("KMS JWT signing failed")?;

    // Convert DER ECDSA to JWT R||S format
    let jwt_sig =
        der_ecdsa_to_jwt(&der_sig).context("Failed to convert ECDSA DER to JWT format")?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(jwt_sig);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Extract the base64url-encoded x and y coordinates from a P-256 public key.
///
/// P-256 uncompressed public keys are 65 bytes: `0x04 || x (32) || y (32)`.
fn extract_ec_coordinates(key_pair: &EcdsaKeyPair) -> Result<(String, String)> {
    let pub_key_bytes = key_pair.public_key().as_ref();

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

    Ok((x, y))
}

/// Build a `DecodingKey` from an ECDSA key pair's public key.
fn build_decoding_key_from_pair(key_pair: &EcdsaKeyPair) -> Result<DecodingKey> {
    let (x, y) = extract_ec_coordinates(key_pair)?;
    DecodingKey::from_ec_components(&x, &y)
        .map_err(|e| anyhow::anyhow!("Failed to build decoding key: {e}"))
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

    #[tokio::test]
    async fn test_sign_and_verify_jwt() {
        let key = OidcSigningKey::generate().expect("Should generate key");

        let claims = TestClaims {
            sub: "test@example.com".to_string(),
            iss: "https://example.com".to_string(),
            exp: 9999999999,
            iat: 1000000000,
        };

        let token = key.sign_jwt(&claims).await.expect("Should sign JWT");

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

    #[tokio::test]
    async fn test_sign_access_token_jwt_typ_header() {
        // RFC 9068 Section 2.1: typ MUST be "at+jwt"
        let key = OidcSigningKey::generate().expect("Should generate key");

        let claims = TestClaims {
            sub: "test@example.com".to_string(),
            iss: "https://example.com".to_string(),
            exp: 9999999999,
            iat: 1000000000,
        };

        let token = key
            .sign_access_token_jwt(&claims)
            .await
            .expect("Should sign access token JWT");

        // Decode and verify header has typ: "at+jwt"
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        let header_json = URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("Header should be base64");
        let header: serde_json::Value =
            serde_json::from_slice(&header_json).expect("Header should be JSON");

        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "at+jwt");
        assert!(header.get("kid").is_some(), "Header should have kid");
    }

    #[tokio::test]
    async fn test_decoding_key_roundtrip() {
        // Verify that sign + decode round-trips correctly
        let key = OidcSigningKey::generate().expect("Should generate key");
        let decoding_key = key.decoding_key();

        let claims = TestClaims {
            sub: "test@example.com".to_string(),
            iss: "https://example.com".to_string(),
            exp: 9999999999,
            iat: 1000000000,
        };

        // Sign with access token method
        let token = key
            .sign_access_token_jwt(&claims)
            .await
            .expect("Should sign access token JWT");

        // Verify with decoding key
        let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
        validation.validate_aud = false;
        let decoded = jsonwebtoken::decode::<TestClaims>(&token, decoding_key, &validation)
            .expect("Should decode token");

        assert_eq!(decoded.claims.sub, "test@example.com");
        assert_eq!(decoded.claims.iss, "https://example.com");
        assert_eq!(decoded.header.typ, Some("at+jwt".to_string()));

        // Also verify with sign_jwt (ID token style)
        let id_token = key.sign_jwt(&claims).await.expect("Should sign JWT");
        let decoded_id = jsonwebtoken::decode::<TestClaims>(&id_token, decoding_key, &validation)
            .expect("Should decode ID token");
        assert_eq!(decoded_id.claims.sub, "test@example.com");
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

        // Export to PEM and reload — generate() always returns Local
        let OidcSigningKey::Local { der_bytes, .. } = &key1 else {
            // generate() always returns Local variant
            return;
        };
        let pem_str = pkcs8_to_pem(der_bytes);
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
