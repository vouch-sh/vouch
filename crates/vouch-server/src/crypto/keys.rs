// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC signing key management for ES256 (P-256 ECDSA) and RS256 (RSA-3072) JWT signing.
//!
//! This module provides functionality to:
//! - Generate P-256 EC keypairs for OIDC access token signing — [`OidcSigningKey`]
//! - Generate RSA-3072 keypairs for OIDC ID token signing — [`OidcRsaSigningKey`]
//! - Sign using AWS KMS P-256 or RSA-3072 keys via `kms:Sign`
//! - Load keys from PEM content or generate new ones
//! - Export public keys in JWK format for the JWKS endpoint
//! - Sign JWTs with ES256 or RS256 algorithm

use anyhow::{Context, Result, bail};
use aws_lc_rs::{
    digest,
    encoding::AsDer,
    rand::SystemRandom,
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use serde::Serialize;
use vouch_common::protocol;
use zeroize::Zeroizing;

use crate::crypto::jwk::{EcJwk, RsaJwk};
use crate::crypto::kms_signer::{KmsSignerP256, KmsSignerRsa3072, parse_spki_rsa};

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
    ///
    /// Accepts raw PEM, base64-encoded PEM, or base64-encoded DER.
    pub fn from_pem(pem_content: &str) -> Result<Self> {
        let trimmed = pem_content.trim();

        let der_bytes = Zeroizing::new(if trimmed.starts_with("-----BEGIN") {
            pem_to_der(trimmed)?
        } else {
            match crate::crypto::pem::decode_base64_pem(trimmed) {
                Ok(pem_text) => pem_to_der(&pem_text)?,
                Err(_) => {
                    // Fall back to base64-encoded DER
                    URL_SAFE_NO_PAD
                        .decode(trimmed)
                        .or_else(|_| {
                            base64::engine::general_purpose::STANDARD.decode(trimmed)
                        })
                        .context("Failed to decode OIDC signing key: expected PEM, base64(PEM), or base64(DER)")?
                }
            }
        });

        Self::from_pkcs8_der(&der_bytes)
    }

    /// Generate a fresh P-256 key pair and return its PKCS#8 DER.
    ///
    /// Used to mint per-org issuer signing keys for storage; pair with
    /// [`from_pkcs8_der`](Self::from_pkcs8_der) to rebuild the signer.
    pub fn generate_pkcs8_der() -> Result<Zeroizing<Vec<u8>>> {
        let rng = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| anyhow::anyhow!("Failed to generate ECDSA key: {e}"))?;
        Ok(Zeroizing::new(pkcs8_bytes.as_ref().to_vec()))
    }

    /// Build a local signer from a PKCS#8 DER private key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let der_bytes = Zeroizing::new(der.to_vec());
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse ECDSA key from PKCS#8 DER: {e}"))?;

        // Generate key ID from public key (unique per key pair).
        let pub_key_bytes = key_pair.public_key().as_ref();
        let key_id = format!(
            "vouch-oidc-{}",
            hex::encode(pub_key_bytes.get(..8).unwrap_or(pub_key_bytes))
        );

        let decoding_key = build_decoding_key_from_pair(&key_pair)?;

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
                Ok(EcJwk::for_jwks(key_id.clone(), x, y))
            }
            Self::Kms { signer, key_id, .. } => Ok(EcJwk::for_jwks(
                key_id.clone(),
                signer.x_b64(),
                signer.y_b64(),
            )),
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
    /// When `typ` is `Some("token-introspection+jwt")`, produces an RFC 9701 response.
    pub(crate) async fn sign_jwt_with_typ<T: Serialize>(
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
}

/// Parse PEM-encoded content and return the DER bytes.
fn pem_to_der(pem_content: &str) -> Result<Vec<u8>> {
    let mut base64_content = String::new();
    let mut in_content = false;

    for line in pem_content.lines() {
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
/// 1. Build header JSON with [`protocol::JWS_ALG_ES256`], `typ`, and `kid`
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
        alg: protocol::JWS_ALG_ES256,
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
fn extract_ec_coordinates(key_pair: &EcdsaKeyPair) -> Result<(String, String)> {
    let point = p256::EncodedPoint::from_bytes(key_pair.public_key().as_ref())
        .map_err(|e| anyhow::anyhow!("Invalid P-256 public key encoding: {e}"))?;
    let x = point
        .x()
        .ok_or_else(|| anyhow::anyhow!("P-256 public key has no x coordinate"))?;
    let y = point
        .y()
        .ok_or_else(|| anyhow::anyhow!("P-256 public key is not an uncompressed point"))?;
    Ok((URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y)))
}

/// Build a `DecodingKey` from an ECDSA key pair's public key.
fn build_decoding_key_from_pair(key_pair: &EcdsaKeyPair) -> Result<DecodingKey> {
    let (x, y) = extract_ec_coordinates(key_pair)?;
    DecodingKey::from_ec_components(&x, &y)
        .map_err(|e| anyhow::anyhow!("Failed to build decoding key: {e}"))
}

/// OIDC signing key using RSA-3072 (RS256).
///
/// Used to sign OIDC ID tokens. Per OIDC Core Section 3.1.3.7, RS256 is the
/// default `id_token_signed_response_alg` and MUST be supported.
///
/// Supports two modes:
/// - `Local`: Uses a local RSA-3072 key pair (generated or from PEM)
/// - `Kms`: Uses an AWS KMS RSA-3072 key via `kms:Sign`
pub enum OidcRsaSigningKey {
    /// Local RSA-3072 key pair for signing.
    Local {
        /// RSA-3072 key pair (signing only; aws-lc-rs does not expose private key inspection).
        key_pair: RsaKeyPair,
        /// Key ID for the JWK (`kid` header).
        key_id: String,
        /// PKCS#8 DER private key bytes, zeroized on drop.
        der_bytes: Zeroizing<Vec<u8>>,
        /// Cached decoding key for RS256 JWT verification.
        decoding_key: DecodingKey,
        /// SPKI DER for JWK extraction (cached at construction).
        spki_der: Vec<u8>,
    },
    /// AWS KMS RSA-3072 key for signing.
    Kms {
        /// KMS signer that calls `kms:Sign` for each operation.
        signer: KmsSignerRsa3072,
        /// Key ID for the JWK.
        key_id: String,
        /// Cached decoding key for RS256 JWT verification.
        decoding_key: DecodingKey,
    },
}

impl OidcRsaSigningKey {
    /// Generate a new RSA-3072 key pair.
    ///
    /// RSA-3072 generation takes ~200ms. Use `spawn_blocking` if calling from an async context.
    pub fn generate() -> Result<Self> {
        let key_pair = RsaKeyPair::generate(KeySize::Rsa3072)
            .map_err(|e| anyhow::anyhow!("Failed to generate RSA-3072 key: {e}"))?;

        // Serialize to PKCS#8 DER (private key, zeroized on drop)
        let pkcs8_der = key_pair
            .as_der()
            .map_err(|e| anyhow::anyhow!("Failed to serialize RSA key to PKCS#8 DER: {e}"))?;
        let der_bytes = Zeroizing::new(pkcs8_der.as_ref().to_vec());

        // Get SPKI DER for the public key (X.509 SubjectPublicKeyInfo)
        let spki_der_obj = key_pair
            .public_key()
            .as_der()
            .map_err(|e| anyhow::anyhow!("Failed to serialize RSA public key to SPKI DER: {e}"))?;
        let spki_der = spki_der_obj.as_ref().to_vec();

        let (n_bytes, e_bytes) =
            parse_spki_rsa(&spki_der).context("Failed to extract RSA components from SPKI")?;

        // Derive key ID from first 8 bytes of the modulus (unique per key).
        // Unlike the SPKI DER prefix (which is identical for all RSA-3072 keys),
        // the modulus is unique per generated key pair.
        let key_id = format!(
            "vouch-oidc-rsa-{}",
            hex::encode(n_bytes.get(..8).unwrap_or(&n_bytes))
        );
        let decoding_key = DecodingKey::from_rsa_components(
            &URL_SAFE_NO_PAD.encode(&n_bytes),
            &URL_SAFE_NO_PAD.encode(&e_bytes),
        )
        .map_err(|e| anyhow::anyhow!("Failed to build RSA decoding key: {e}"))?;

        tracing::info!("Generated new OIDC RSA signing key: {}", key_id);

        Ok(Self::Local {
            key_pair,
            key_id,
            der_bytes,
            decoding_key,
            spki_der,
        })
    }

    /// Load from PEM-encoded RSA private key content (PKCS#8).
    ///
    /// Accepts raw PEM, base64-encoded PEM, or base64-encoded DER.
    pub fn from_pem(pem_content: &str) -> Result<Self> {
        let trimmed = pem_content.trim();

        let der_bytes = Zeroizing::new(if trimmed.starts_with("-----BEGIN") {
            pem_to_der(trimmed)?
        } else {
            match crate::crypto::pem::decode_base64_pem(trimmed) {
                Ok(pem_text) => pem_to_der(&pem_text)?,
                Err(_) => {
                    // Fall back to base64-encoded DER
                    URL_SAFE_NO_PAD
                        .decode(trimmed)
                        .or_else(|_| {
                            base64::engine::general_purpose::STANDARD.decode(trimmed)
                        })
                        .context("Failed to decode RSA signing key: expected PEM, base64(PEM), or base64(DER)")?
                }
            }
        });

        Self::from_pkcs8_der(&der_bytes)
    }

    /// Generate a fresh RSA-3072 key pair and return its PKCS#8 DER.
    ///
    /// RSA-3072 generation takes ~200ms; call from `spawn_blocking` in async
    /// contexts. Pair with [`from_pkcs8_der`](Self::from_pkcs8_der) to rebuild.
    pub fn generate_pkcs8_der() -> Result<Zeroizing<Vec<u8>>> {
        let key_pair = RsaKeyPair::generate(KeySize::Rsa3072)
            .map_err(|e| anyhow::anyhow!("Failed to generate RSA-3072 key: {e}"))?;
        let pkcs8_der = key_pair
            .as_der()
            .map_err(|e| anyhow::anyhow!("Failed to serialize RSA key to PKCS#8 DER: {e}"))?;
        Ok(Zeroizing::new(pkcs8_der.as_ref().to_vec()))
    }

    /// Build a local signer from a PKCS#8 DER private key (RSA ≥ 3072 bits).
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let der_bytes = Zeroizing::new(der.to_vec());
        let key_pair = RsaKeyPair::from_pkcs8(&der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse RSA key from PKCS#8 DER: {e}"))?;

        let spki_der_obj = key_pair
            .public_key()
            .as_der()
            .map_err(|e| anyhow::anyhow!("Failed to serialize RSA public key to SPKI DER: {e}"))?;
        let spki_der = spki_der_obj.as_ref().to_vec();

        let (n_bytes, e_bytes) =
            parse_spki_rsa(&spki_der).context("Failed to extract RSA components from SPKI")?;

        // Enforce minimum RSA-3072 key size. generate_pkcs8_der() uses
        // KeySize::Rsa3072 and KMS validates KeySpec::Rsa3072, but this
        // accepts any PKCS#8 RSA key — reject undersized ones. Bit-counting
        // (not byte length) handles DER sign-padding edge cases.
        let key_bits = n_bytes
            .len()
            .saturating_mul(8)
            .saturating_sub(n_bytes.first().map_or(0, |b| b.leading_zeros() as usize));
        if key_bits < 3072 {
            bail!("RSA key must be at least 3072 bits, got {key_bits} bits");
        }

        let key_id = format!(
            "vouch-oidc-rsa-{}",
            hex::encode(n_bytes.get(..8).unwrap_or(&n_bytes))
        );
        let decoding_key = DecodingKey::from_rsa_components(
            &URL_SAFE_NO_PAD.encode(&n_bytes),
            &URL_SAFE_NO_PAD.encode(&e_bytes),
        )
        .map_err(|e| anyhow::anyhow!("Failed to build RSA decoding key: {e}"))?;

        Ok(Self::Local {
            key_pair,
            key_id,
            der_bytes,
            decoding_key,
            spki_der,
        })
    }

    /// Create a KMS-backed OIDC RSA signing key.
    ///
    /// Calls `kms:GetPublicKey` to fetch and cache the RSA-3072 public key.
    pub async fn from_kms(kms_client: aws_sdk_kms::Client, key_id: String) -> Result<Self> {
        let signer = KmsSignerRsa3072::new(kms_client, key_id).await?;

        let decoding_key = DecodingKey::from_rsa_components(signer.n_b64(), signer.e_b64())
            .map_err(|e| {
                anyhow::anyhow!("Failed to build RSA decoding key from KMS components: {e}")
            })?;

        // Derive key ID from the modulus prefix (unique per key), not the SPKI
        // header bytes (identical for all RSA-3072 keys).
        let n_prefix = URL_SAFE_NO_PAD
            .decode(signer.n_b64())
            .map_err(|e| anyhow::anyhow!("Failed to decode KMS RSA modulus: {e}"))?;
        let kid = format!(
            "vouch-oidc-rsa-kms-{}",
            hex::encode(n_prefix.get(..8).unwrap_or(&n_prefix))
        );

        tracing::debug!("KMS OIDC RSA signing key initialized: {}", kid);

        Ok(Self::Kms {
            signer,
            key_id: kid,
            decoding_key,
        })
    }

    /// Load from PEM content or generate a new ephemeral RSA-3072 key.
    ///
    /// RSA key generation takes ~200ms. The caller should use `spawn_blocking`
    /// when generating during server startup.
    pub fn load_or_generate(pem_content: Option<&str>) -> Result<Self> {
        if let Some(pem) = pem_content {
            if pem.trim().is_empty() {
                tracing::info!("Empty OIDC RSA signing key provided, generating new key");
                Self::generate()
            } else {
                Self::from_pem(pem)
            }
        } else {
            tracing::warn!(
                "No OIDC RSA signing key configured; generating ephemeral RSA-3072 key (~200ms). \
                 Set VOUCH_OIDC_RSA_SIGNING_KEY or VOUCH_OIDC_RSA_SIGNING_KMS_KEY_ID for production."
            );
            Self::generate()
        }
    }

    /// Get the key ID (`kid`).
    #[must_use]
    pub fn key_id(&self) -> &str {
        match self {
            Self::Local { key_id, .. } | Self::Kms { key_id, .. } => key_id,
        }
    }

    /// Get the cached `jsonwebtoken` decoding key for verifying RS256 JWTs.
    #[must_use]
    pub fn decoding_key(&self) -> &DecodingKey {
        match self {
            Self::Local { decoding_key, .. } | Self::Kms { decoding_key, .. } => decoding_key,
        }
    }

    /// Get the public key as an RSA JWK for the JWKS endpoint.
    pub fn public_key_jwk(&self) -> Result<RsaJwk> {
        match self {
            Self::Local {
                key_id, spki_der, ..
            } => {
                let (n_bytes, e_bytes) = parse_spki_rsa(spki_der)
                    .context("Failed to extract RSA public key components from SPKI")?;
                Ok(RsaJwk::for_jwks(
                    key_id.clone(),
                    URL_SAFE_NO_PAD.encode(&n_bytes),
                    URL_SAFE_NO_PAD.encode(&e_bytes),
                ))
            }
            Self::Kms { signer, key_id, .. } => Ok(RsaJwk::for_jwks(
                key_id.clone(),
                signer.n_b64().to_string(),
                signer.e_b64().to_string(),
            )),
        }
    }

    /// Sign a JWT with RS256 (`typ: "JWT"`).
    ///
    /// Used for OIDC ID tokens. Access tokens remain ES256 via `OidcSigningKey`.
    pub async fn sign_jwt<T: Serialize>(&self, claims: &T) -> Result<String> {
        self.sign_jwt_with_typ(claims, None).await
    }

    /// Sign a JWT with RS256 and an optional `typ` header override.
    pub async fn sign_jwt_with_typ<T: Serialize>(
        &self,
        claims: &T,
        typ: Option<&str>,
    ) -> Result<String> {
        match self {
            Self::Local {
                der_bytes, key_id, ..
            } => {
                let claims_json = serde_json::to_vec(claims)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize JWT claims: {e}"))?;
                let der = der_bytes.clone();
                let kid = key_id.clone();
                let typ_owned = typ.map(String::from);

                // RSA-3072 signing is CPU-intensive (~10ms); offload to avoid starving
                // the tokio runtime on low-vCPU instances.
                tokio::task::spawn_blocking(move || {
                    sign_jwt_rsa_local(&der, &kid, &claims_json, typ_owned.as_deref())
                })
                .await
                .map_err(|e| anyhow::anyhow!("JWT signing task failed: {e}"))?
            }
            Self::Kms { signer, key_id, .. } => {
                sign_jwt_rsa_with_kms(signer, key_id, claims, typ).await
            }
        }
    }
}

/// Sign a JWT with RS256 locally using aws-lc-rs.
///
/// Called from `spawn_blocking` to avoid blocking the tokio runtime.
/// Manually constructs the JWT instead of using `jsonwebtoken::encode` because
/// `jsonwebtoken` expects PKCS#1 DER for the private key, but aws-lc-rs generates
/// PKCS#8. We build the signing input and call `KeyPair::sign()` directly.
fn sign_jwt_rsa_local(
    pkcs8_der: &[u8],
    kid: &str,
    claims_json: &[u8],
    typ: Option<&str>,
) -> Result<String> {
    use aws_lc_rs::signature::RSA_PKCS1_SHA256;

    // aws-lc-rs RsaKeyPair is !Send — it cannot be stored in AppState or moved
    // across the spawn_blocking boundary. Re-parsing from PKCS#8 DER on each call
    // costs ~1ms, which is acceptable relative to the ~10ms RSA signing operation.
    let key_pair = RsaKeyPair::from_pkcs8(pkcs8_der)
        .map_err(|e| anyhow::anyhow!("Failed to load RSA key from PKCS#8: {e}"))?;

    let header = KmsJwtHeader {
        alg: "RS256",
        typ: typ.unwrap_or("JWT"),
        kid,
    };

    let header_json = serde_json::to_vec(&header).context("Failed to serialize JWT header")?;
    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json);

    let signing_input = format!("{header_b64}.{claims_b64}");

    // sign() takes the full message and hashes internally with SHA-256.
    let mut sig_bytes = vec![0u8; key_pair.public_modulus_len()];
    let rng = SystemRandom::new();
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &rng,
            signing_input.as_bytes(),
            &mut sig_bytes,
        )
        .map_err(|e| anyhow::anyhow!("RSA-3072 signing failed: {e}"))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Manually construct and sign a JWT using KMS RSA.
///
/// Steps:
/// 1. Build header JSON with `alg: "RS256"`, `typ`, and `kid`
/// 2. Serialize claims to JSON
/// 3. Base64url-encode header and payload, join with "."
/// 4. SHA-256 hash the signing input (`header.payload`)
/// 5. Call `signer.sign_digest(&sha256_hash)` → raw PKCS#1 v1.5 signature bytes
/// 6. Base64url-encode signature, return `header.payload.signature`
async fn sign_jwt_rsa_with_kms<T: Serialize>(
    signer: &KmsSignerRsa3072,
    key_id: &str,
    claims: &T,
    typ: Option<&str>,
) -> Result<String> {
    let header = KmsJwtHeader {
        alg: "RS256",
        typ: typ.unwrap_or("JWT"),
        kid: key_id,
    };

    let header_json = serde_json::to_vec(&header).context("Failed to serialize JWT header")?;
    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);

    let claims_json = serde_json::to_vec(claims).context("Failed to serialize JWT claims")?;
    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

    let signing_input = format!("{header_b64}.{claims_b64}");

    // SHA-256 hash the signing input. KMS RSA requires MessageType::Digest.
    let sha256_digest = digest::digest(&digest::SHA256, signing_input.as_bytes());

    let sig_bytes = signer
        .sign_digest(sha256_digest.as_ref())
        .await
        .context("KMS RSA JWT signing failed")?;

    // RSA PKCS#1 v1.5 signatures are raw bytes — no DER conversion needed.
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);

    Ok(format!("{signing_input}.{sig_b64}"))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::crypto::jwk::Jwk;
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

    /// RFC 7517 Section 4 and RFC 7518 Section 6.2: the exact entry the JWKS
    /// endpoint publishes for an ES256 key. Asserted on the serialized form
    /// rather than the fields, because the wire shape is the contract a
    /// relying party reads — and the member count catches an accidental
    /// addition as well as a removal.
    #[test]
    fn test_public_key_jwk() {
        let key = OidcSigningKey::generate().expect("Should generate key");
        let jwk = key.public_key_jwk().expect("Should create JWK");
        let x = jwk.x().to_string();
        let y = jwk.y().to_string();
        let value = serde_json::to_value(Jwk::Ec(jwk)).expect("JWK serializes");

        assert_eq!(value["kty"], "EC");
        assert_eq!(value["crv"], "P-256");
        assert_eq!(value["alg"], "ES256");
        assert_eq!(value["use"], "sig");
        assert_eq!(value["kid"], key.key_id());
        assert_eq!(value["x"], x);
        assert_eq!(value["y"], y);
        assert!(!x.is_empty() && !y.is_empty());
        // A published key is a public key: no `d`.
        assert!(value.get("d").is_none(), "published JWK must not carry `d`");
        assert_eq!(
            value.as_object().expect("JWK is an object").len(),
            7,
            "published EC entry is exactly kty, crv, x, y, kid, alg, use: {value}"
        );
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
        assert_eq!(jwk1.x(), jwk2.x());
        assert_eq!(jwk1.y(), jwk2.y());
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

    // -----------------------------------------------------------------------
    // RSA (OidcRsaSigningKey) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_rsa_key() {
        let key = OidcRsaSigningKey::generate().expect("RSA key generation failed");
        assert!(
            key.key_id().starts_with("vouch-oidc-rsa-"),
            "key_id should have 'vouch-oidc-rsa-' prefix, got: {}",
            key.key_id()
        );
    }

    /// RFC 7517 Section 4 and RFC 7518 Section 6.3: the published RS256 entry.
    /// See `test_public_key_jwk` for why this asserts the serialized form.
    #[test]
    fn test_rsa_public_key_jwk() {
        let key = OidcRsaSigningKey::generate().expect("RSA key generation failed");
        let jwk = key.public_key_jwk().expect("public_key_jwk failed");
        let n = jwk.n().to_string();
        let e = jwk.e().to_string();
        let value = serde_json::to_value(Jwk::Rsa(jwk)).expect("JWK serializes");

        assert_eq!(value["kty"], "RSA");
        assert_eq!(value["alg"], "RS256");
        assert_eq!(value["use"], "sig");
        assert_eq!(value["kid"], key.key_id());
        assert_eq!(value["n"], n);
        assert_eq!(value["e"], e);
        assert!(!n.is_empty(), "modulus must not be empty");
        assert!(!e.is_empty(), "exponent must not be empty");
        // A published key is a public key: no private members.
        for private in ["d", "p", "q", "dp", "dq", "qi"] {
            assert!(
                value.get(private).is_none(),
                "published JWK must not carry `{private}`"
            );
        }
        assert_eq!(
            value.as_object().expect("JWK is an object").len(),
            6,
            "published RSA entry is exactly kty, n, e, kid, alg, use: {value}"
        );
    }

    #[tokio::test]
    async fn test_rsa_sign_and_verify_jwt() {
        let key = OidcRsaSigningKey::generate().expect("RSA key generation failed");

        let claims = TestClaims {
            sub: "test@example.com".to_string(),
            iss: "https://example.com".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
        };

        let token = key.sign_jwt(&claims).await.expect("sign_jwt failed");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");

        let header_json = URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("header base64 failed");
        let header: serde_json::Value =
            serde_json::from_slice(&header_json).expect("header JSON failed");

        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");
        assert!(header.get("kid").is_some(), "header must have kid");
    }

    #[tokio::test]
    async fn test_rsa_decoding_key_roundtrip() {
        let key = OidcRsaSigningKey::generate().expect("RSA key generation failed");
        let decoding_key = key.decoding_key();

        let claims = TestClaims {
            sub: "rsa-roundtrip@example.com".to_string(),
            iss: "https://example.com".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
        };

        let token = key.sign_jwt(&claims).await.expect("sign_jwt failed");

        let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        let decoded = jsonwebtoken::decode::<TestClaims>(&token, decoding_key, &validation)
            .expect("decode failed");

        assert_eq!(decoded.claims.sub, "rsa-roundtrip@example.com");
        assert_eq!(decoded.header.typ, Some("JWT".to_string()));
    }

    #[test]
    fn test_rsa_load_or_generate_none() {
        let key = OidcRsaSigningKey::load_or_generate(None).expect("load_or_generate failed");
        assert!(key.key_id().starts_with("vouch-oidc-rsa-"));
    }

    #[test]
    fn test_rsa_load_or_generate_empty() {
        let key =
            OidcRsaSigningKey::load_or_generate(Some("")).expect("load_or_generate empty failed");
        assert!(key.key_id().starts_with("vouch-oidc-rsa-"));
    }

    #[test]
    fn test_rsa_roundtrip_pem() {
        let key1 = OidcRsaSigningKey::generate().expect("RSA key generation failed");
        let jwk1 = key1.public_key_jwk().expect("jwk1 failed");

        let OidcRsaSigningKey::Local { der_bytes, .. } = &key1 else {
            // generate() always returns Local variant
            return;
        };

        let pem_str = pkcs8_to_pem(der_bytes);
        let key2 = OidcRsaSigningKey::from_pem(&pem_str).expect("from_pem failed");
        let jwk2 = key2.public_key_jwk().expect("jwk2 failed");

        // Same key → same modulus and exponent
        assert_eq!(
            jwk1.n(),
            jwk2.n(),
            "modulus must match after PEM round-trip"
        );
        assert_eq!(
            jwk1.e(),
            jwk2.e(),
            "exponent must match after PEM round-trip"
        );
    }

    #[test]
    fn test_jwk_enum_serialization() {
        let ec_key = OidcSigningKey::generate().expect("EC key generation failed");
        let ec_jwk = ec_key.public_key_jwk().expect("EC JWK failed");

        let rsa_key = OidcRsaSigningKey::generate().expect("RSA key generation failed");
        let rsa_jwk = rsa_key.public_key_jwk().expect("RSA JWK failed");

        let ec = Jwk::Ec(ec_jwk);
        let rsa = Jwk::Rsa(rsa_jwk);

        let ec_json = serde_json::to_value(&ec).expect("EC JWK serialization failed");
        let rsa_json = serde_json::to_value(&rsa).expect("RSA JWK serialization failed");

        assert_eq!(ec_json["kty"], "EC");
        assert_eq!(ec_json["alg"], "ES256");

        assert_eq!(rsa_json["kty"], "RSA");
        assert_eq!(rsa_json["alg"], "RS256");
        assert!(rsa_json.get("n").is_some(), "RSA JWK must have n");
        assert!(rsa_json.get("e").is_some(), "RSA JWK must have e");
        // EC JWK must not leak RSA fields (untagged serialization)
        assert!(ec_json.get("n").is_none(), "EC JWK must not have n");
        assert!(ec_json.get("crv").is_some(), "EC JWK must have crv");
    }

    #[test]
    fn test_rsa_from_pem_rejects_small_key() {
        // Generate an RSA-2048 key (below the 3072-bit minimum)
        use aws_lc_rs::encoding::AsDer;
        let small_key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("RSA-2048 keygen");
        let pkcs8_der = small_key.as_der().expect("PKCS#8 DER");

        // Convert to PEM
        let der_slice: &[u8] = pkcs8_der.as_ref();
        let b64 = base64::engine::general_purpose::STANDARD.encode(der_slice);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");

        let result = OidcRsaSigningKey::from_pem(&pem);
        let err = result.err().expect("RSA-2048 should be rejected");
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("3072 bits"),
            "Error should mention 3072-bit requirement, got: {err_msg}"
        );
    }

    #[test]
    fn test_rsa_key_id_is_unique() {
        // Two independently generated keys must have different key IDs
        let key1 = OidcRsaSigningKey::generate().expect("RSA key 1");
        let key2 = OidcRsaSigningKey::generate().expect("RSA key 2");
        assert_ne!(
            key1.key_id(),
            key2.key_id(),
            "Different RSA keys must have different key IDs"
        );
    }

    #[test]
    fn test_rsa_from_pem_rejects_ec_key() {
        // Generate an EC P-256 key and try to load it as RSA
        let ec_key = OidcSigningKey::generate().expect("EC key");
        let OidcSigningKey::Local { der_bytes, .. } = &ec_key else {
            return;
        };
        let der_slice: &[u8] = der_bytes;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der_slice);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");

        assert!(
            OidcRsaSigningKey::from_pem(&pem).is_err(),
            "EC key should be rejected by RSA loader"
        );
    }
}
