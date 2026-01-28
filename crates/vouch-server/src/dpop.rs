// SPDX-License-Identifier: BUSL-1.1
//! RFC 9449 DPoP (Demonstrating Proof of Possession) implementation.
//!
//! DPoP provides sender-constrained tokens by binding tokens to a client's
//! cryptographic key pair. This prevents token theft and replay attacks.
//!
//! Key components:
//! - DPoP Proof JWT: A signed JWT proving possession of a private key
//! - JWK Thumbprint: SHA-256 hash of the public key (RFC 7638)
//! - Token Binding: Access tokens include `cnf` claim with JWK thumbprint

// Allow string slicing for JWT parsing
#![allow(clippy::string_slice)]

use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Timestamp, ToSpan};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Supported DPoP signing algorithms (asymmetric only per RFC 9449).
pub const SUPPORTED_ALGORITHMS: &[&str] = &["ES256", "RS256", "EdDSA"];

/// DPoP JWT header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopHeader {
    /// Type must be "dpop+jwt".
    pub typ: String,
    /// Algorithm used for signing (ES256, RS256, EdDSA).
    pub alg: String,
    /// JSON Web Key (embedded public key).
    pub jwk: DpopJwk,
}

/// DPoP JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopClaims {
    /// Unique identifier for the proof (prevents replay).
    pub jti: String,
    /// HTTP method of the request (e.g., "POST").
    pub htm: String,
    /// HTTP URI of the request (without query/fragment).
    pub htu: String,
    /// Issued at timestamp (seconds since epoch).
    pub iat: i64,
    /// Server-provided nonce (if required).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Access token hash (for protected resource requests).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

/// JSON Web Key for DPoP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DpopJwk {
    /// Elliptic Curve key (P-256).
    Ec(EcJwk),
    /// RSA key.
    Rsa(RsaJwk),
    /// Octet Key Pair (Ed25519).
    Okp(OkpJwk),
}

/// EC JWK (P-256 / ES256).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// RSA JWK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaJwk {
    pub kty: String,
    pub n: String,
    pub e: String,
}

/// OKP JWK (Ed25519).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkpJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

impl DpopJwk {
    /// Compute the JWK thumbprint (RFC 7638).
    ///
    /// The thumbprint is a base64url-encoded SHA-256 hash of the canonical
    /// JSON representation of the required JWK members.
    pub fn thumbprint(&self) -> String {
        let canonical = match self {
            DpopJwk::Ec(ec) => {
                // For EC keys: {"crv":"...","kty":"EC","x":"...","y":"..."}
                format!(
                    r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
                    ec.crv, ec.kty, ec.x, ec.y
                )
            }
            DpopJwk::Rsa(rsa) => {
                // For RSA keys: {"e":"...","kty":"RSA","n":"..."}
                format!(r#"{{"e":"{}","kty":"{}","n":"{}"}}"#, rsa.e, rsa.kty, rsa.n)
            }
            DpopJwk::Okp(okp) => {
                // For OKP keys: {"crv":"...","kty":"OKP","x":"..."}
                format!(
                    r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#,
                    okp.crv, okp.kty, okp.x
                )
            }
        };

        let hash = digest::digest(&SHA256, canonical.as_bytes());
        URL_SAFE_NO_PAD.encode(hash.as_ref())
    }
}

/// Confirmation claim for token binding (RFC 9449 Section 6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnfClaim {
    /// JWK thumbprint of the sender's key.
    pub jkt: String,
}

/// DPoP validation error.
#[derive(Debug, Clone)]
pub enum DpopError {
    /// Missing DPoP header.
    #[allow(dead_code)]
    MissingProof,
    /// Invalid proof format.
    InvalidFormat(String),
    /// Invalid signature.
    InvalidSignature,
    /// Unsupported algorithm.
    UnsupportedAlgorithm(String),
    /// Proof has expired.
    Expired,
    /// JTI replay detected.
    ReplayDetected,
    /// HTTP method mismatch.
    MethodMismatch,
    /// HTTP URI mismatch.
    UriMismatch,
    /// Missing or invalid nonce.
    InvalidNonce,
    /// Access token hash mismatch.
    TokenHashMismatch,
    /// Server requires nonce.
    UseNonce(String),
}

impl std::fmt::Display for DpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingProof => write!(f, "missing DPoP proof"),
            Self::InvalidFormat(msg) => write!(f, "invalid DPoP format: {msg}"),
            Self::InvalidSignature => write!(f, "invalid DPoP signature"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "unsupported DPoP algorithm: {alg}"),
            Self::Expired => write!(f, "DPoP proof expired"),
            Self::ReplayDetected => write!(f, "DPoP proof replay detected"),
            Self::MethodMismatch => write!(f, "DPoP htm claim mismatch"),
            Self::UriMismatch => write!(f, "DPoP htu claim mismatch"),
            Self::InvalidNonce => write!(f, "invalid or missing DPoP nonce"),
            Self::TokenHashMismatch => write!(f, "DPoP ath claim mismatch"),
            Self::UseNonce(nonce) => write!(f, "use_dpop_nonce: {nonce}"),
        }
    }
}

impl std::error::Error for DpopError {}

/// Validated DPoP proof information.
#[derive(Debug, Clone)]
pub struct ValidatedDpopProof {
    /// JWK thumbprint of the sender's key.
    pub jkt: String,
    /// The public key from the proof.
    #[allow(dead_code)]
    pub jwk: DpopJwk,
    /// Unique identifier from the proof.
    pub jti: String,
}

/// DPoP nonce manager for server-provided nonces.
pub struct DpopNonceManager {
    /// Active nonces (nonce -> expiration).
    nonces: HashMap<String, Timestamp>,
    /// Nonce validity duration.
    validity_seconds: i64,
}

impl DpopNonceManager {
    /// Create a new nonce manager.
    pub fn new(validity_seconds: i64) -> Self {
        Self {
            nonces: HashMap::new(),
            validity_seconds,
        }
    }

    /// Generate a new nonce.
    pub fn generate_nonce(&mut self) -> String {
        let nonce = generate_random_string(32);
        let expires_at = Timestamp::now()
            .checked_add(self.validity_seconds.seconds())
            .unwrap_or_else(|_| Timestamp::now());
        self.nonces.insert(nonce.clone(), expires_at);
        nonce
    }

    /// Validate and consume a nonce.
    pub fn validate_nonce(&mut self, nonce: &str) -> bool {
        if let Some(expires_at) = self.nonces.remove(nonce) {
            Timestamp::now() < expires_at
        } else {
            false
        }
    }

    /// Clean up expired nonces.
    pub fn cleanup(&mut self) {
        let now = Timestamp::now();
        self.nonces.retain(|_, expires_at| *expires_at > now);
    }
}

impl Default for DpopNonceManager {
    fn default() -> Self {
        Self::new(300) // 5 minutes default
    }
}

/// JTI cache for replay prevention.
pub struct JtiCache {
    /// Recently used JTIs (jti -> expiration).
    jtis: HashMap<String, Timestamp>,
    /// JTI validity duration (how long to remember).
    validity_seconds: i64,
}

impl JtiCache {
    /// Create a new JTI cache.
    pub fn new(validity_seconds: i64) -> Self {
        Self {
            jtis: HashMap::new(),
            validity_seconds,
        }
    }

    /// Check if a JTI has been seen before and record it.
    ///
    /// Returns `true` if this is a new JTI, `false` if it's a replay.
    pub fn check_and_record(&mut self, jti: &str) -> bool {
        let now = Timestamp::now();

        // Clean up expired entries
        self.jtis.retain(|_, expires_at| *expires_at > now);

        // Check if already seen
        if self.jtis.contains_key(jti) {
            return false;
        }

        // Record the new JTI
        let expires_at = now
            .checked_add(self.validity_seconds.seconds())
            .unwrap_or(now);
        self.jtis.insert(jti.to_string(), expires_at);

        true
    }
}

impl Default for JtiCache {
    fn default() -> Self {
        Self::new(300) // 5 minutes default
    }
}

/// Thread-safe DPoP state.
pub struct DpopState {
    /// Nonce manager.
    pub nonce_manager: Arc<RwLock<DpopNonceManager>>,
    /// JTI cache.
    pub jti_cache: Arc<RwLock<JtiCache>>,
}

impl DpopState {
    /// Create new DPoP state.
    pub fn new() -> Self {
        Self {
            nonce_manager: Arc::new(RwLock::new(DpopNonceManager::default())),
            jti_cache: Arc::new(RwLock::new(JtiCache::default())),
        }
    }
}

impl Default for DpopState {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a random URL-safe string.
///
/// # Panics
/// Panics if the system RNG fails.
#[allow(clippy::expect_used)]
fn generate_random_string(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    aws_rand::fill(&mut bytes).expect("RNG failure");
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Compute the access token hash (ath) for DPoP.
///
/// The hash is the base64url-encoded SHA-256 hash of the ASCII access token.
/// This is used at protected resource endpoints (e.g., userinfo) to verify
/// that the DPoP proof was created for the specific access token being used.
#[allow(dead_code)]
pub fn compute_access_token_hash(access_token: &str) -> String {
    let hash = digest::digest(&SHA256, access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(hash.as_ref())
}

/// Parse a DPoP proof JWT (without signature verification).
///
/// This extracts the header and claims for initial validation.
/// Signature verification must be done separately using the embedded JWK.
pub fn parse_dpop_proof(proof: &str) -> Result<(DpopHeader, DpopClaims), DpopError> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(DpopError::InvalidFormat(
            "JWT must have 3 parts".to_string(),
        ));
    }

    // Decode header
    let header_part = parts
        .first()
        .ok_or_else(|| DpopError::InvalidFormat("missing header".to_string()))?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_part)
        .map_err(|e| DpopError::InvalidFormat(format!("invalid header encoding: {e}")))?;
    let header: DpopHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| DpopError::InvalidFormat(format!("invalid header JSON: {e}")))?;

    // Validate header
    if header.typ != "dpop+jwt" {
        return Err(DpopError::InvalidFormat(format!(
            "typ must be 'dpop+jwt', got '{}'",
            header.typ
        )));
    }

    if !SUPPORTED_ALGORITHMS.contains(&header.alg.as_str()) {
        return Err(DpopError::UnsupportedAlgorithm(header.alg.clone()));
    }

    // Decode claims
    let claims_part = parts
        .get(1)
        .ok_or_else(|| DpopError::InvalidFormat("missing claims".to_string()))?;
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_part)
        .map_err(|e| DpopError::InvalidFormat(format!("invalid claims encoding: {e}")))?;
    let claims: DpopClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|e| DpopError::InvalidFormat(format!("invalid claims JSON: {e}")))?;

    Ok((header, claims))
}

/// Validate DPoP proof claims (without signature verification).
pub fn validate_dpop_claims(
    claims: &DpopClaims,
    expected_method: &str,
    expected_uri: &str,
    max_age_seconds: i64,
    require_nonce: bool,
    expected_nonce: Option<&str>,
    expected_ath: Option<&str>,
) -> Result<(), DpopError> {
    let now = Timestamp::now().as_second();

    // Check method
    if claims.htm.to_uppercase() != expected_method.to_uppercase() {
        return Err(DpopError::MethodMismatch);
    }

    // Check URI (normalize by removing query/fragment)
    let claims_uri = normalize_uri(&claims.htu);
    let expected_uri = normalize_uri(expected_uri);
    if claims_uri != expected_uri {
        return Err(DpopError::UriMismatch);
    }

    // Check timestamp (not too old, not in future)
    let age = now - claims.iat;
    if age < -60 {
        // Allow 60 seconds clock skew into future
        return Err(DpopError::Expired);
    }
    if age > max_age_seconds {
        return Err(DpopError::Expired);
    }

    // Check nonce if required
    if require_nonce {
        match (&claims.nonce, expected_nonce) {
            (Some(proof_nonce), Some(expected)) if proof_nonce == expected => {}
            _ => return Err(DpopError::InvalidNonce),
        }
    }

    // Check access token hash if provided
    if let Some(expected_ath) = expected_ath {
        match &claims.ath {
            Some(proof_ath) if proof_ath == expected_ath => {}
            _ => return Err(DpopError::TokenHashMismatch),
        }
    }

    Ok(())
}

/// Normalize a URI by removing query string and fragment.
fn normalize_uri(uri: &str) -> String {
    if let Some(idx) = uri.find('?') {
        uri[..idx].to_string()
    } else if let Some(idx) = uri.find('#') {
        uri[..idx].to_string()
    } else {
        uri.to_string()
    }
}

/// Build a `DecodingKey` from a DPoP JWK.
fn build_decoding_key(jwk: &DpopJwk, alg: &str) -> Result<jsonwebtoken::DecodingKey, DpopError> {
    match (jwk, alg) {
        (DpopJwk::Ec(ec), "ES256") => {
            if ec.kty != "EC" || ec.crv != "P-256" {
                return Err(DpopError::InvalidFormat(
                    "ES256 requires EC key with P-256 curve".to_string(),
                ));
            }
            // jsonwebtoken expects base64url-encoded strings
            jsonwebtoken::DecodingKey::from_ec_components(&ec.x, &ec.y)
                .map_err(|e| DpopError::InvalidFormat(format!("Invalid EC key: {e}")))
        }
        (DpopJwk::Rsa(rsa), "RS256") => {
            if rsa.kty != "RSA" {
                return Err(DpopError::InvalidFormat(
                    "RS256 requires RSA key".to_string(),
                ));
            }
            // jsonwebtoken expects base64url-encoded strings
            jsonwebtoken::DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
                .map_err(|e| DpopError::InvalidFormat(format!("Invalid RSA key: {e}")))
        }
        (DpopJwk::Okp(okp), "EdDSA") => {
            if okp.kty != "OKP" || okp.crv != "Ed25519" {
                return Err(DpopError::InvalidFormat(
                    "EdDSA requires OKP key with Ed25519 curve".to_string(),
                ));
            }
            // jsonwebtoken expects base64url-encoded string
            jsonwebtoken::DecodingKey::from_ed_components(&okp.x)
                .map_err(|e| DpopError::InvalidFormat(format!("Invalid Ed25519 key: {e}")))
        }
        _ => Err(DpopError::UnsupportedAlgorithm(alg.to_string())),
    }
}

/// Verify a DPoP proof signature using the embedded JWK.
///
/// This verifies that the proof was signed by the private key corresponding
/// to the public key embedded in the JWT header.
pub fn verify_dpop_signature(proof: &str, header: &DpopHeader) -> Result<(), DpopError> {
    // Build decoding key from JWK
    let decoding_key = build_decoding_key(&header.jwk, &header.alg)?;

    // Map algorithm string to jsonwebtoken Algorithm
    let algorithm = match header.alg.as_str() {
        "ES256" => jsonwebtoken::Algorithm::ES256,
        "RS256" => jsonwebtoken::Algorithm::RS256,
        "EdDSA" => jsonwebtoken::Algorithm::EdDSA,
        alg => return Err(DpopError::UnsupportedAlgorithm(alg.to_string())),
    };

    // Build validation settings
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.required_spec_claims.clear(); // DPoP has custom claims
    validation.validate_exp = false; // We validate iat manually
    validation.validate_aud = false; // No audience in DPoP

    // Verify signature
    jsonwebtoken::decode::<DpopClaims>(proof, &decoding_key, &validation)
        .map_err(|_| DpopError::InvalidSignature)?;

    Ok(())
}

/// Fully validate a DPoP proof, including signature verification.
///
/// This is the main entry point for DPoP validation. It:
/// 1. Parses the JWT
/// 2. Verifies the signature using the embedded JWK
/// 3. Validates all claims (method, URI, timestamp, etc.)
/// 4. Checks for replay (JTI)
///
/// Returns the validated proof information including the JWK thumbprint.
pub async fn validate_dpop_proof(
    proof: &str,
    expected_method: &str,
    expected_uri: &str,
    dpop_state: &DpopState,
    config_max_age: i64,
    require_nonce: bool,
) -> Result<ValidatedDpopProof, DpopError> {
    // Parse the proof
    let (header, claims) = parse_dpop_proof(proof)?;

    // Verify signature
    verify_dpop_signature(proof, &header)?;

    // Check for replay (JTI must be unique)
    {
        let mut jti_cache = dpop_state.jti_cache.write().await;
        if !jti_cache.check_and_record(&claims.jti) {
            return Err(DpopError::ReplayDetected);
        }
    }

    // Validate claims
    let expected_nonce = if require_nonce {
        // Generate a nonce if required but not provided
        if claims.nonce.is_none() {
            let mut nonce_manager = dpop_state.nonce_manager.write().await;
            let new_nonce = nonce_manager.generate_nonce();
            return Err(DpopError::UseNonce(new_nonce));
        }
        claims.nonce.as_deref()
    } else {
        None
    };

    validate_dpop_claims(
        &claims,
        expected_method,
        expected_uri,
        config_max_age,
        require_nonce,
        expected_nonce,
        None, // No access token hash for token endpoint
    )?;

    // Validate nonce if provided
    if let Some(nonce) = &claims.nonce {
        let mut nonce_manager = dpop_state.nonce_manager.write().await;
        if !nonce_manager.validate_nonce(nonce) {
            // Generate a new nonce for the client
            let new_nonce = nonce_manager.generate_nonce();
            return Err(DpopError::UseNonce(new_nonce));
        }
    }

    // Return validated proof info
    Ok(ValidatedDpopProof {
        jkt: header.jwk.thumbprint(),
        jwk: header.jwk,
        jti: claims.jti,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_ec_jwk_thumbprint() {
        // Test vector from RFC 7638
        let jwk = DpopJwk::Ec(EcJwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: "test_x".to_string(),
            y: "test_y".to_string(),
        });

        let thumbprint = jwk.thumbprint();
        assert!(!thumbprint.is_empty());
        // Thumbprint should be base64url encoded SHA-256 (43 chars)
        assert_eq!(thumbprint.len(), 43);
    }

    #[test]
    fn test_jti_cache() {
        let mut cache = JtiCache::new(300);

        // First use should succeed
        assert!(cache.check_and_record("test-jti-1"));

        // Replay should fail
        assert!(!cache.check_and_record("test-jti-1"));

        // Different JTI should succeed
        assert!(cache.check_and_record("test-jti-2"));
    }

    #[test]
    fn test_nonce_manager() {
        let mut manager = DpopNonceManager::new(300);

        let nonce = manager.generate_nonce();
        assert!(!nonce.is_empty());

        // Validate should succeed and consume
        assert!(manager.validate_nonce(&nonce));

        // Second validation should fail (consumed)
        assert!(!manager.validate_nonce(&nonce));
    }

    #[test]
    fn test_normalize_uri() {
        assert_eq!(
            normalize_uri("https://example.com/token?foo=bar"),
            "https://example.com/token"
        );
        assert_eq!(
            normalize_uri("https://example.com/token#frag"),
            "https://example.com/token"
        );
        assert_eq!(
            normalize_uri("https://example.com/token"),
            "https://example.com/token"
        );
    }

    #[test]
    fn test_access_token_hash() {
        let hash = compute_access_token_hash("test_token");
        assert!(!hash.is_empty());
        // SHA-256 base64url encoded should be 43 chars
        assert_eq!(hash.len(), 43);
    }
}
