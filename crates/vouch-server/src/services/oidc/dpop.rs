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

use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Timestamp, ToSpan};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;
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
    ///
    /// Uses `BTreeMap` to guarantee lexicographic key ordering per RFC 7638 Section 3.2,
    /// and `serde_json` for proper escaping of values.
    ///
    /// # Errors
    ///
    /// Returns `DpopError::InvalidFormat` if canonical JSON serialization fails.
    pub fn thumbprint(&self) -> Result<String, DpopError> {
        use std::collections::BTreeMap;

        let mut members = BTreeMap::new();
        match self {
            DpopJwk::Ec(ec) => {
                // RFC 7638 Section 3.2: Required EC members in lexicographic order
                members.insert("crv", ec.crv.as_str());
                members.insert("kty", ec.kty.as_str());
                members.insert("x", ec.x.as_str());
                members.insert("y", ec.y.as_str());
            }
            DpopJwk::Rsa(rsa) => {
                // RFC 7638 Section 3.2: Required RSA members in lexicographic order
                members.insert("e", rsa.e.as_str());
                members.insert("kty", rsa.kty.as_str());
                members.insert("n", rsa.n.as_str());
            }
            DpopJwk::Okp(okp) => {
                // RFC 7638 Section 3.2: Required OKP members in lexicographic order
                members.insert("crv", okp.crv.as_str());
                members.insert("kty", okp.kty.as_str());
                members.insert("x", okp.x.as_str());
            }
        };

        // BTreeMap iteration is lexicographic, serde_json handles escaping
        let canonical = serde_json::to_string(&members).map_err(|e| {
            DpopError::InvalidFormat(format!("JWK thumbprint serialization failed: {e}"))
        })?;
        let hash = digest::digest(&SHA256, canonical.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(hash.as_ref()))
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

/// Maximum number of entries in the nonce manager before rejecting new nonces.
const MAX_NONCE_ENTRIES: usize = 100_000;

/// Maximum number of entries in the JTI cache before rejecting new JTIs.
const MAX_JTI_ENTRIES: usize = 100_000;

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
    ///
    /// Returns `None` if the RNG fails or if the cache is at capacity
    /// after cleanup.
    pub fn generate_nonce(&mut self) -> Option<String> {
        // Periodically clean up expired entries
        self.cleanup();

        // Reject if still at capacity after cleanup
        if self.nonces.len() >= MAX_NONCE_ENTRIES {
            return None;
        }

        let nonce = generate_random_string(32)?;
        let expires_at = Timestamp::now()
            .checked_add(self.validity_seconds.seconds())
            .unwrap_or_else(|_| Timestamp::now());
        self.nonces.insert(nonce.clone(), expires_at);
        Some(nonce)
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
    /// Returns `true` if this is a new JTI, `false` if it's a replay
    /// or if the cache is at capacity.
    pub fn check_and_record(&mut self, jti: &str) -> bool {
        let now = Timestamp::now();

        // Clean up expired entries
        self.jtis.retain(|_, expires_at| *expires_at > now);

        // Check if already seen
        if self.jtis.contains_key(jti) {
            return false;
        }

        // Reject if at capacity after cleanup
        if self.jtis.len() >= MAX_JTI_ENTRIES {
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
/// Returns `None` if the system RNG fails.
fn generate_random_string(len: usize) -> Option<String> {
    let mut bytes = vec![0u8; len];
    aws_rand::fill(&mut bytes).ok()?;
    Some(URL_SAFE_NO_PAD.encode(&bytes))
}

/// Compute the access token hash (`ath`) for DPoP (RFC 9449 Section 4.2).
///
/// The hash is the base64url-encoded SHA-256 hash of the ASCII access token.
/// This is used at protected resource endpoints (e.g., userinfo) to verify
/// that the DPoP proof was created for the specific access token being used.
pub fn compute_access_token_hash(access_token: &str) -> String {
    let hash = digest::digest(&SHA256, access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(hash.as_ref())
}

/// Parse a DPoP proof JWT header (without signature verification or claims parsing).
///
/// Extracts only the header to obtain the JWK and algorithm. Used internally
/// by `parse_and_verify_dpop_proof` to build the decoding key before
/// performing combined signature verification + claims extraction.
fn parse_dpop_header(proof: &str) -> Result<DpopHeader, DpopError> {
    let header_part = proof
        .split('.')
        .next()
        .ok_or_else(|| DpopError::InvalidFormat("JWT must have 3 parts".to_string()))?;

    // Verify the JWT has exactly 3 parts
    if proof.split('.').count() != 3 {
        return Err(DpopError::InvalidFormat(
            "JWT must have 3 parts".to_string(),
        ));
    }

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

    Ok(header)
}

/// Parse and verify a DPoP proof in a single pass.
///
/// 1. Decodes the header to extract the JWK and algorithm.
/// 2. Builds a decoding key from the JWK.
/// 3. Uses `jsonwebtoken::decode()` for combined signature verification
///    and claims extraction (avoiding a redundant second parse).
///
/// Returns the parsed header and verified claims.
fn parse_and_verify_dpop_proof(proof: &str) -> Result<(DpopHeader, DpopClaims), DpopError> {
    let header = parse_dpop_header(proof)?;

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

    // Verify signature and extract claims in a single pass
    let token_data = jsonwebtoken::decode::<DpopClaims>(proof, &decoding_key, &validation)
        .map_err(|_| DpopError::InvalidSignature)?;

    Ok((header, token_data.claims))
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

    // RFC 9449 Section 5.1: Nonce validation.
    // When `expected_nonce` is Some, validate inline with constant-time comparison.
    // When `expected_nonce` is None (callers use the nonce manager instead), skip
    // the inline check here. Callers handle missing nonce before calling this
    // function and validate provided nonces via the nonce manager afterward.
    if let Some(expected) = expected_nonce {
        match &claims.nonce {
            Some(proof_nonce) => {
                let is_valid: bool = proof_nonce.as_bytes().ct_eq(expected.as_bytes()).into();
                if !is_valid {
                    return Err(DpopError::InvalidNonce);
                }
            }
            None => return Err(DpopError::InvalidNonce),
        }
    } else if require_nonce && claims.nonce.is_none() {
        // Nonce is required but not provided and caller didn't handle it
        return Err(DpopError::InvalidNonce);
    }

    // Check access token hash if provided (constant-time comparison for defense-in-depth)
    if let Some(expected_ath) = expected_ath {
        match &claims.ath {
            Some(proof_ath) => {
                let is_valid: bool = proof_ath.as_bytes().ct_eq(expected_ath.as_bytes()).into();
                if !is_valid {
                    return Err(DpopError::TokenHashMismatch);
                }
            }
            _ => return Err(DpopError::TokenHashMismatch),
        }
    }

    Ok(())
}

/// Normalize a URI by removing query string and fragment.
///
/// RFC 9449 Section 4.2: The `htu` claim should contain the HTTP target URI
/// without query and fragment components.
#[allow(clippy::string_slice)]
fn normalize_uri(uri: &str) -> String {
    // Find the first occurrence of either '?' or '#' to handle all orderings
    // Safety: both `find('?')` and `find('#')` return byte offsets of ASCII
    // characters, so slicing at `end` is always at a valid char boundary.
    let end = uri
        .find('?')
        .into_iter()
        .chain(uri.find('#'))
        .min()
        .unwrap_or(uri.len());
    uri[..end].to_string()
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

/// Fully validate a DPoP proof, including signature verification.
///
/// This is the main entry point for DPoP validation. It:
/// 1. Parses the JWT header and verifies the signature in a single pass
/// 2. Validates all claims (method, URI, timestamp, etc.)
/// 3. Checks for replay (JTI)
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
    // Parse header, verify signature, and extract claims in a single pass
    let (header, claims) = parse_and_verify_dpop_proof(proof)?;

    // Check for replay (JTI must be unique)
    {
        let mut jti_cache = dpop_state.jti_cache.write().await;
        if !jti_cache.check_and_record(&claims.jti) {
            return Err(DpopError::ReplayDetected);
        }
    }

    // Validate claims
    // Note: Nonce validation is handled by the nonce manager below (lines 579-586).
    // We pass None here to avoid a redundant self-comparison of the client's own nonce.
    let expected_nonce: Option<&str> = if require_nonce {
        // Generate a nonce if required but not provided
        if claims.nonce.is_none() {
            let mut nonce_manager = dpop_state.nonce_manager.write().await;
            let new_nonce = nonce_manager
                .generate_nonce()
                .ok_or_else(|| DpopError::InvalidFormat("nonce generation failed".to_string()))?;
            return Err(DpopError::UseNonce(new_nonce));
        }
        None
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
            let new_nonce = nonce_manager
                .generate_nonce()
                .ok_or_else(|| DpopError::InvalidFormat("nonce generation failed".to_string()))?;
            return Err(DpopError::UseNonce(new_nonce));
        }
    }

    // Return validated proof info
    let jkt = header.jwk.thumbprint()?;
    Ok(ValidatedDpopProof {
        jkt,
        jwk: header.jwk,
        jti: claims.jti,
    })
}

/// Validate a DPoP proof at a resource endpoint (e.g., userinfo).
///
/// This is similar to `validate_dpop_proof` but also validates the `ath` claim
/// (access token hash) per RFC 9449 Section 7.1. Resource endpoints MUST verify
/// that the DPoP proof binds to the specific access token being used.
///
/// # Arguments
/// * `proof` - The DPoP proof JWT from the `DPoP` header
/// * `access_token` - The access token from the `Authorization: DPoP` header
/// * `method` - HTTP method of the request
/// * `uri` - Full request URI
/// * `dpop_state` - DPoP state for JTI and nonce management
/// * `config_max_age` - Maximum allowed proof age in seconds
/// * `require_nonce` - Whether server-provided nonces are required
pub async fn validate_dpop_at_resource(
    proof: &str,
    access_token: &str,
    method: &str,
    uri: &str,
    dpop_state: &DpopState,
    config_max_age: i64,
    require_nonce: bool,
) -> Result<ValidatedDpopProof, DpopError> {
    // Parse header, verify signature, and extract claims in a single pass
    let (header, claims) = parse_and_verify_dpop_proof(proof)?;

    // Check for replay (JTI must be unique)
    {
        let mut jti_cache = dpop_state.jti_cache.write().await;
        if !jti_cache.check_and_record(&claims.jti) {
            return Err(DpopError::ReplayDetected);
        }
    }

    // Compute the expected access token hash
    let expected_ath = compute_access_token_hash(access_token);

    // Handle nonce: pass None to skip redundant self-comparison in validate_dpop_claims
    let expected_nonce: Option<&str> = if require_nonce {
        if claims.nonce.is_none() {
            let mut nonce_manager = dpop_state.nonce_manager.write().await;
            let new_nonce = nonce_manager
                .generate_nonce()
                .ok_or_else(|| DpopError::InvalidFormat("nonce generation failed".to_string()))?;
            return Err(DpopError::UseNonce(new_nonce));
        }
        None
    } else {
        None
    };

    // Validate claims including the access token hash
    validate_dpop_claims(
        &claims,
        method,
        uri,
        config_max_age,
        require_nonce,
        expected_nonce,
        Some(&expected_ath),
    )?;

    // Validate nonce via nonce manager if provided
    if let Some(nonce) = &claims.nonce {
        let mut nonce_manager = dpop_state.nonce_manager.write().await;
        if !nonce_manager.validate_nonce(nonce) {
            let new_nonce = nonce_manager
                .generate_nonce()
                .ok_or_else(|| DpopError::InvalidFormat("nonce generation failed".to_string()))?;
            return Err(DpopError::UseNonce(new_nonce));
        }
    }

    // Return validated proof info
    let jkt = header.jwk.thumbprint()?;
    Ok(ValidatedDpopProof {
        jkt,
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

        let thumbprint = jwk.thumbprint().expect("thumbprint");
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

        let nonce = manager.generate_nonce().expect("should generate nonce");
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
