// SPDX-License-Identifier: Apache-2.0 OR MIT
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
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::db::{self, store::DocumentStore};

/// Nonce validity in seconds (5 minutes).
const NONCE_VALIDITY_SECONDS: i64 = 300;

/// Supported DPoP signing algorithms (asymmetric only per RFC 9449).
///
/// RS256 is excluded per FAPI 2.0 Section 5.2.2.
pub const SUPPORTED_ALGORITHMS: &[&str] = &["ES256", "PS256", "EdDSA"];

/// DPoP JWT header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopHeader {
    /// Type must be "dpop+jwt".
    pub typ: String,
    /// Algorithm used for signing (ES256, PS256, EdDSA).
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

    // RFC 9449 Section 4.3: The JWK MUST NOT contain a private key.
    // Check for private key fields (`d`, `p`, `q`, `dp`, `dq`, `qi`) in the
    // raw JSON before deserializing (our structs intentionally omit these fields
    // so serde would silently ignore them).
    let header_json: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| DpopError::InvalidFormat(format!("invalid header JSON: {e}")))?;
    if let Some(jwk_value) = header_json.get("jwk") {
        for private_field in ["d", "p", "q", "dp", "dq", "qi"] {
            if jwk_value.get(private_field).is_some() {
                return Err(DpopError::InvalidFormat(
                    "JWK in DPoP proof header must not contain private key material".to_string(),
                ));
            }
        }
    }

    let header: DpopHeader = serde_json::from_value(header_json)
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
        "PS256" => jsonwebtoken::Algorithm::PS256,
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
    // When `expected_nonce` is None (callers use the database instead), skip
    // the inline check here. Callers handle missing nonce before calling this
    // function and validate provided nonces via the database afterward.
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
        (DpopJwk::Rsa(rsa), "PS256") => {
            if rsa.kty != "RSA" {
                return Err(DpopError::InvalidFormat(
                    "PS256 requires RSA key".to_string(),
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

/// Shared DPoP validation logic for both token and resource endpoints.
///
/// Handles: signature verification, JTI replay check, nonce requirement,
/// claims validation, nonce validation, and thumbprint extraction.
///
/// All state (nonces and JTIs) is persisted in the database for
/// multi-instance consistency.
async fn validate_dpop_common(
    proof: &str,
    expected_method: &str,
    expected_uri: &str,
    store: &DocumentStore,
    config_max_age: i64,
    expected_ath: Option<&str>,
    require_nonce: bool,
) -> Result<ValidatedDpopProof, DpopError> {
    // Parse header, verify signature, and extract claims in a single pass
    let (header, claims) = parse_and_verify_dpop_proof(proof)?;

    // Check for replay (JTI must be unique) — atomic INSERT on PRIMARY KEY
    let is_new = db::check_and_store_dpop_jti(store, &claims.jti, config_max_age)
        .await
        .map_err(|e| DpopError::InvalidFormat(format!("JTI check failed: {e}")))?;
    if !is_new {
        return Err(DpopError::ReplayDetected);
    }

    // Nonce requirement: enforced at token endpoint (RFC 9449 Section 8)
    // where precomputation attacks are a concern. Resource endpoints use
    // `ath` (access token hash) for binding, so nonces are optional there.
    if require_nonce && claims.nonce.is_none() {
        let new_nonce = db::generate_dpop_nonce(store, NONCE_VALIDITY_SECONDS)
            .await
            .map_err(|e| DpopError::InvalidFormat(format!("nonce generation failed: {e}")))?;
        return Err(DpopError::UseNonce(new_nonce));
    }

    // Validate claims (method, URI, timestamp, nonce inline, ath)
    // Pass None for expected_nonce to skip redundant self-comparison;
    // database nonce validation happens below.
    validate_dpop_claims(
        &claims,
        expected_method,
        expected_uri,
        config_max_age,
        None,
        expected_ath,
    )?;

    // Validate nonce via database if provided — atomic DELETE WHERE nonce=? AND expires_at > now
    if let Some(nonce) = claims.nonce.as_deref() {
        let valid = db::validate_and_consume_dpop_nonce(store, nonce)
            .await
            .map_err(|e| DpopError::InvalidFormat(format!("nonce validation failed: {e}")))?;
        if !valid {
            let new_nonce = db::generate_dpop_nonce(store, NONCE_VALIDITY_SECONDS)
                .await
                .map_err(|e| DpopError::InvalidFormat(format!("nonce generation failed: {e}")))?;
            return Err(DpopError::UseNonce(new_nonce));
        }
    }

    let jkt = header.jwk.thumbprint()?;
    Ok(ValidatedDpopProof {
        jkt,
        jwk: header.jwk,
        jti: claims.jti,
    })
}

/// Fully validate a DPoP proof, including signature verification.
///
/// This is the main entry point for DPoP validation at the token endpoint.
/// It parses, verifies the signature, validates claims, and checks for replay.
///
/// Returns the validated proof information including the JWK thumbprint.
pub async fn validate_dpop_proof(
    proof: &str,
    expected_method: &str,
    expected_uri: &str,
    store: &DocumentStore,
    config_max_age: i64,
) -> Result<ValidatedDpopProof, DpopError> {
    validate_dpop_common(
        proof,
        expected_method,
        expected_uri,
        store,
        config_max_age,
        None, // No access token hash for token endpoint
        true, // Require nonce at token endpoint
    )
    .await
}

/// Validate a DPoP proof at a resource endpoint (e.g., userinfo).
///
/// This also validates the `ath` claim (access token hash) per RFC 9449
/// Section 7.1. Resource endpoints MUST verify that the DPoP proof binds
/// to the specific access token being used.
///
/// # Arguments
/// * `proof` - The DPoP proof JWT from the `DPoP` header
/// * `access_token` - The access token from the `Authorization: DPoP` header
/// * `method` - HTTP method of the request
/// * `uri` - Full request URI
/// * `pool` - Database pool for nonce and JTI persistence
/// * `config_max_age` - Maximum allowed proof age in seconds
pub async fn validate_dpop_at_resource(
    access_token: &str,
    proof: &str,
    method: &str,
    uri: &str,
    store: &DocumentStore,
    config_max_age: i64,
) -> Result<ValidatedDpopProof, DpopError> {
    let expected_ath = compute_access_token_hash(access_token);
    validate_dpop_common(
        proof,
        method,
        uri,
        store,
        config_max_age,
        Some(&expected_ath),
        false, // Nonces optional at resource endpoints (ath provides binding)
    )
    .await
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

    fn make_claims(htm: &str, htu: &str, iat: i64) -> DpopClaims {
        DpopClaims {
            jti: "test-jti".to_string(),
            htm: htm.to_string(),
            htu: htu.to_string(),
            iat,
            nonce: None,
            ath: None,
        }
    }

    fn now() -> i64 {
        jiff::Timestamp::now().as_second()
    }

    #[test]
    fn test_validate_dpop_claims_method_mismatch() {
        let claims = make_claims("GET", "https://example.com/token", now());
        let result =
            validate_dpop_claims(&claims, "POST", "https://example.com/token", 60, None, None);
        assert!(matches!(result, Err(DpopError::MethodMismatch)));
    }

    #[test]
    fn test_validate_dpop_claims_uri_mismatch() {
        let claims = make_claims("POST", "https://other.com/token", now());
        let result =
            validate_dpop_claims(&claims, "POST", "https://example.com/token", 60, None, None);
        assert!(matches!(result, Err(DpopError::UriMismatch)));
    }

    #[test]
    fn test_validate_dpop_claims_expired() {
        // iat older than max_age_seconds
        let claims = make_claims("POST", "https://example.com/token", now() - 120);
        let result =
            validate_dpop_claims(&claims, "POST", "https://example.com/token", 60, None, None);
        assert!(matches!(result, Err(DpopError::Expired)));
    }

    #[test]
    fn test_validate_dpop_claims_future_iat() {
        // iat more than 60 seconds in the future (age < -60)
        let claims = make_claims("POST", "https://example.com/token", now() + 120);
        let result = validate_dpop_claims(
            &claims,
            "POST",
            "https://example.com/token",
            300,
            None,
            None,
        );
        assert!(matches!(result, Err(DpopError::Expired)));
    }

    #[test]
    fn test_validate_dpop_claims_wrong_ath() {
        let mut claims = make_claims("POST", "https://example.com/token", now());
        claims.ath = Some("wrong_hash_value_here_xxxxxxxxxxxxxxxxxxxxxxx".to_string());
        let correct_ath = compute_access_token_hash("my-access-token");
        let result = validate_dpop_claims(
            &claims,
            "POST",
            "https://example.com/token",
            60,
            None,
            Some(&correct_ath),
        );
        assert!(matches!(result, Err(DpopError::TokenHashMismatch)));
    }

    #[test]
    fn test_validate_dpop_claims_valid_with_ath() {
        let access_token = "my-access-token";
        let ath = compute_access_token_hash(access_token);
        let mut claims = make_claims("POST", "https://example.com/token", now());
        claims.ath = Some(ath.clone());
        let result = validate_dpop_claims(
            &claims,
            "POST",
            "https://example.com/token",
            60,
            None,
            Some(&ath),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_dpop_claims_valid_no_ath() {
        let claims = make_claims("POST", "https://example.com/token", now());
        let result =
            validate_dpop_claims(&claims, "POST", "https://example.com/token", 60, None, None);
        assert!(result.is_ok());
    }

    // ========================================================================
    // parse_dpop_header — RFC 9449 Section 4.3 private key rejection
    //
    // The JWK embedded in a DPoP proof header MUST NOT contain private key
    // material. Our structs intentionally omit these fields, so we check the
    // raw JSON before deserializing.
    // ========================================================================

    /// Build a minimal JWT string whose header is the given JSON value.
    ///
    /// The payload and signature segments are dummy values — only the header
    /// is inspected by `parse_dpop_header`.
    fn make_dpop_jwt_with_header(header_json: &serde_json::Value) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header_json).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"{}");
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"sig");
        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    #[test]
    fn test_parse_dpop_header_rejects_jwk_with_private_key_d() {
        // A DPoP proof whose JWK contains the EC private key field "d" must
        // be rejected per RFC 9449 Section 4.3.
        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
            }
        });
        let jwt = make_dpop_jwt_with_header(&header_json);

        let result = parse_dpop_header(&jwt);

        assert!(
            matches!(result, Err(DpopError::InvalidFormat(_))),
            "JWK with private 'd' field must be rejected with InvalidFormat, got: {result:?}"
        );
        if let Err(DpopError::InvalidFormat(msg)) = result {
            assert!(
                msg.contains("private key"),
                "Error message should mention private key material, got: {msg}"
            );
        }
    }

    #[test]
    fn test_parse_dpop_header_rejects_rsa_jwk_with_private_fields() {
        // RSA private key components (p, q, dp, dq, qi) must also be rejected.
        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "PS256",
            "jwk": {
                "kty": "RSA",
                "n": "somersakeymodulus",
                "e": "AQAB",
                "p": "private_p_value"
            }
        });
        let jwt = make_dpop_jwt_with_header(&header_json);

        let result = parse_dpop_header(&jwt);

        assert!(
            matches!(result, Err(DpopError::InvalidFormat(_))),
            "JWK with RSA private 'p' field must be rejected with InvalidFormat, got: {result:?}"
        );
    }

    #[test]
    fn test_parse_dpop_header_accepts_public_ec_jwk() {
        // A public EC JWK (no 'd' field) in the header must be accepted.
        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            }
        });
        let jwt = make_dpop_jwt_with_header(&header_json);

        let result = parse_dpop_header(&jwt);

        // The header parses successfully — signature verification is not
        // attempted here since we call parse_dpop_header directly.
        assert!(
            result.is_ok(),
            "Public EC JWK without private key fields must be accepted, got: {result:?}"
        );
    }
}
