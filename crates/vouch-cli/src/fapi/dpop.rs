// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9449 DPoP proof JWT generation.
//!
//! DPoP (Demonstrating Proof of Possession) binds access tokens to a specific
//! client keypair, preventing token theft. The proof is a compact JWT containing
//! the HTTP method, URL, timestamp, and an embedded public JWK.
//!
//! This implementation uses manual JWT construction (header.payload.signature)
//! rather than the `jsonwebtoken` crate because DPoP requires embedding the
//! full public JWK in the JWT header, which `jsonwebtoken` does not support.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use vouch_common::protocol;

use super::error::FapiError;
use super::key::{ClientKey, PublicEcJwk};

/// JWT header for a DPoP proof (RFC 9449 Section 4.2).
#[derive(Debug, Serialize)]
struct DpopHeader<'a> {
    /// Token type — must be "dpop+jwt" per RFC 9449.
    typ: &'a str,
    /// Algorithm — [`protocol::JWS_ALG_ES256`] for P-256 ECDSA with SHA-256.
    alg: &'a str,
    /// Public key confirming possession of the corresponding private key.
    jwk: PublicEcJwk,
}

/// JWT payload (claims) for a DPoP proof (RFC 9449 Section 4.2).
#[derive(Debug, Serialize)]
struct DpopClaims {
    /// Unique token ID — prevents replay attacks.
    jti: String,
    /// HTTP method the proof is bound to (uppercase).
    htm: String,
    /// HTTP URI the proof is bound to (no query or fragment).
    htu: String,
    /// Issued-at timestamp (Unix seconds).
    iat: i64,
    /// Server-issued nonce for replay prevention (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    /// Base64url-encoded SHA-256 hash of the access token (optional, RFC 9449 Section 4.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
    /// Credential source identifier (custom claim, RFC 9449 §4.2 allows additional claims).
    /// When present, the server adds AI-specific session tags to issued tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
}

/// Builder for DPoP proof JWTs per RFC 9449.
///
/// # Examples
///
/// ```rust,ignore
/// let proof = DpopProofBuilder::new("POST", "https://server.example.com/token")
///     .nonce("server-issued-nonce")
///     .build(&client_key)?;
/// ```
pub struct DpopProofBuilder {
    /// HTTP method (uppercase).
    htm: String,
    /// HTTP URI without query/fragment.
    htu: String,
    /// Optional server-issued nonce.
    nonce: Option<String>,
    /// Optional access token hash (base64url SHA-256).
    ath: Option<String>,
    /// Optional credential source identifier (custom claim).
    source: Option<String>,
}

impl DpopProofBuilder {
    /// Create a new DPoP proof builder.
    ///
    /// The `url` is stripped of query parameters and fragment before being
    /// stored as `htu`, per RFC 9449 Section 4.2.
    #[must_use]
    pub fn new(method: &str, url: &str) -> Self {
        // Strip query and fragment from the URL for htu
        let htu = strip_query_and_fragment(url);

        Self {
            htm: method.to_uppercase(),
            htu,
            nonce: None,
            ath: None,
            source: None,
        }
    }

    /// Set the server-issued nonce for replay prevention.
    #[must_use]
    pub fn nonce(mut self, nonce: &str) -> Self {
        self.nonce = Some(nonce.to_string());
        self
    }

    /// Bind this proof to a specific access token (RFC 9449 Section 4.2).
    ///
    /// Computes `ath = base64url(SHA-256(access_token))`.
    #[must_use]
    pub fn access_token(mut self, token: &str) -> Self {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes());
        self.ath = Some(URL_SAFE_NO_PAD.encode(digest.as_ref()));
        self
    }

    /// Set the credential source identifier (custom claim).
    ///
    /// When present, the server adds AI-specific session tags
    /// (`vouch:AccessType=AI`, `vouch:Agent=<value>`) to issued tokens.
    /// The value is the detected agent name (e.g., "claude-code", "cursor").
    #[must_use]
    pub fn source(mut self, source: &str) -> Self {
        self.source = Some(source.to_string());
        self
    }

    /// Build and sign the DPoP proof JWT.
    ///
    /// Constructs the JWT manually (not via `jsonwebtoken`) to support
    /// embedding the public JWK in the header, which RFC 9449 requires.
    ///
    /// # Errors
    ///
    /// Returns [`FapiError::JwtSigning`] if serialization or signing fails.
    pub fn build(self, key: &ClientKey) -> Result<String, FapiError> {
        let jwk = key.public_jwk()?;

        let header = DpopHeader {
            typ: "dpop+jwt",
            alg: protocol::JWS_ALG_ES256,
            jwk,
        };

        let claims = DpopClaims {
            jti: uuid::Uuid::now_v7().to_string(),
            htm: self.htm,
            htu: self.htu,
            iat: jiff::Timestamp::now().as_second(),
            nonce: self.nonce,
            ath: self.ath,
            source: self.source,
        };

        // Manually encode header and claims as base64url(JSON)
        let header_json = serde_json::to_vec(&header)
            .map_err(|e| FapiError::JwtSigning(format!("header serialization: {e}")))?;
        let claims_json = serde_json::to_vec(&claims)
            .map_err(|e| FapiError::JwtSigning(format!("claims serialization: {e}")))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        let signing_input = format!("{header_b64}.{claims_b64}");

        // Sign the input with the private key (IEEE P1363 format = r||s = correct for JWS ES256)
        let signature = key.sign_raw(signing_input.as_bytes())?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

/// Strip query parameters and fragment from a URL, returning just scheme + host + path.
///
/// Uses the `url` crate for proper parsing per RFC 3986, which is important
/// for correct DPoP proof binding (RFC 9449 Section 4.2).
fn strip_query_and_fragment(raw_url: &str) -> String {
    match url::Url::parse(raw_url) {
        Ok(mut parsed) => {
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.to_string()
        }
        // Fall back to the raw URL if parsing fails
        Err(_) => raw_url.to_string(),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::fapi::key::ClientKey;

    fn decode_b64_json(b64: &str) -> serde_json::Value {
        let bytes = URL_SAFE_NO_PAD.decode(b64).expect("valid base64url");
        serde_json::from_slice(&bytes).expect("valid JSON")
    }

    #[test]
    fn test_dpop_proof_structure() {
        let key = ClientKey::generate().unwrap();
        let proof = DpopProofBuilder::new("POST", "https://example.com/token")
            .build(&key)
            .unwrap();

        // JWT has 3 parts
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3, "DPoP JWT must have 3 parts");

        // Header checks
        let header = decode_b64_json(parts.first().unwrap());
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert!(header.get("jwk").is_some(), "header must contain jwk");

        let jwk = &header["jwk"];
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk.get("x").is_some());
        assert!(jwk.get("y").is_some());

        // Claims checks
        let claims = decode_b64_json(parts[1]);
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://example.com/token");
        assert!(claims.get("jti").is_some(), "must have jti");
        assert!(claims.get("iat").is_some(), "must have iat");
        assert!(claims.get("nonce").is_none(), "nonce should be absent");
        assert!(claims.get("ath").is_none(), "ath should be absent");
    }

    #[test]
    fn test_dpop_strips_query_from_url() {
        let key = ClientKey::generate().unwrap();
        let proof = DpopProofBuilder::new("GET", "https://example.com/resource?foo=bar&baz=1")
            .build(&key)
            .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let claims = decode_b64_json(parts[1]);
        assert_eq!(claims["htu"], "https://example.com/resource");
    }

    #[test]
    fn test_dpop_strips_fragment_from_url() {
        let key = ClientKey::generate().unwrap();
        let proof = DpopProofBuilder::new("GET", "https://example.com/page#section")
            .build(&key)
            .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let claims = decode_b64_json(parts[1]);
        assert_eq!(claims["htu"], "https://example.com/page");
    }

    #[test]
    fn test_dpop_with_nonce() {
        let key = ClientKey::generate().unwrap();
        let proof = DpopProofBuilder::new("POST", "https://example.com/token")
            .nonce("server-nonce-abc123")
            .build(&key)
            .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let claims = decode_b64_json(parts[1]);
        assert_eq!(claims["nonce"], "server-nonce-abc123");
    }

    #[test]
    fn test_dpop_with_access_token_computes_ath() {
        let key = ClientKey::generate().unwrap();
        let proof = DpopProofBuilder::new("GET", "https://example.com/resource")
            .access_token("some-access-token")
            .build(&key)
            .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let claims = decode_b64_json(parts[1]);

        let ath = claims["ath"].as_str().unwrap();
        assert!(!ath.is_empty(), "ath should not be empty");

        // Verify the ath value: base64url(SHA-256("some-access-token"))
        let expected_digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"some-access-token");
        let expected_ath = URL_SAFE_NO_PAD.encode(expected_digest.as_ref());
        assert_eq!(ath, expected_ath);
    }

    #[test]
    fn test_dpop_method_uppercased() {
        let key = ClientKey::generate().unwrap();
        let proof = DpopProofBuilder::new("post", "https://example.com/token")
            .build(&key)
            .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let claims = decode_b64_json(parts[1]);
        assert_eq!(claims["htm"], "POST");
    }

    #[test]
    fn test_dpop_proof_signature_verifies() {
        let key = ClientKey::generate().unwrap();
        let proof = DpopProofBuilder::new("POST", "https://example.com/token")
            .build(&key)
            .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();

        // Reconstruct the public key from the JWK
        let jwk = key.public_jwk().unwrap();
        let x = URL_SAFE_NO_PAD.decode(&jwk.x).unwrap();
        let y = URL_SAFE_NO_PAD.decode(&jwk.y).unwrap();
        let mut pub_key_bytes = vec![0x04];
        pub_key_bytes.extend_from_slice(&x);
        pub_key_bytes.extend_from_slice(&y);

        // Verify the signature using aws_lc_rs
        let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
            &pub_key_bytes,
        );
        public_key
            .verify(signing_input.as_bytes(), &sig_bytes)
            .expect("DPoP signature must verify");
    }

    #[test]
    fn test_strip_query_and_fragment_no_query() {
        assert_eq!(
            strip_query_and_fragment("https://example.com/path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_strip_query_and_fragment_with_query() {
        assert_eq!(
            strip_query_and_fragment("https://example.com/path?a=1"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_strip_query_and_fragment_with_fragment() {
        assert_eq!(
            strip_query_and_fragment("https://example.com/path#anchor"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_strip_query_and_fragment_with_both() {
        assert_eq!(
            strip_query_and_fragment("https://example.com/path?q=1#anchor"),
            "https://example.com/path"
        );
    }
}
