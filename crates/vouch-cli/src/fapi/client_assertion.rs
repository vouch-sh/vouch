// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7523 `private_key_jwt` client assertion generation.
//!
//! Client assertions allow a confidential client to authenticate to an OAuth 2.0
//! authorization server using a signed JWT instead of a shared secret.
//! This is required by FAPI 2.0 (RFC 9700).

use jsonwebtoken::{Algorithm, Header};
use serde::Serialize;

use super::error::FapiError;
use super::key::ClientKey;

/// JWT claims for a `private_key_jwt` client assertion (RFC 7523 Section 3).
#[derive(Debug, Serialize)]
struct ClientAssertionClaims {
    /// Issuer — must equal the `client_id`.
    iss: String,
    /// Subject — must equal the `client_id`.
    sub: String,
    /// Audience — must be the token endpoint URL.
    aud: String,
    /// JWT ID — prevents replay attacks.
    jti: String,
    /// Issued-at time (Unix seconds).
    iat: i64,
    /// Expiration time (Unix seconds). Short-lived: 60 seconds.
    exp: i64,
}

/// A signed client assertion ready to be included in a token request.
#[derive(Debug)]
pub struct ClientAssertion {
    /// The signed JWT assertion string.
    pub assertion: String,
    /// The assertion type URI per RFC 7523.
    pub assertion_type: &'static str,
}

impl ClientAssertion {
    /// The `client_assertion_type` value for `private_key_jwt` per RFC 7523.
    pub const TYPE: &'static str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
}

/// Builder for `private_key_jwt` client assertions.
///
/// # Examples
///
/// ```rust,ignore
/// let assertion = ClientAssertionBuilder::new("my-client-id", "https://server.example.com/token")
///     .build(&client_key)?;
/// // Use assertion.assertion and assertion.assertion_type in the token request
/// ```
pub struct ClientAssertionBuilder {
    /// OAuth 2.0 client ID.
    client_id: String,
    /// Token endpoint URL (used as the audience).
    token_endpoint_url: String,
}

impl ClientAssertionBuilder {
    /// Create a new client assertion builder.
    #[must_use]
    pub fn new(client_id: &str, token_endpoint_url: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            token_endpoint_url: token_endpoint_url.to_string(),
        }
    }

    /// Build and sign the client assertion JWT.
    ///
    /// Uses ES256 (P-256 ECDSA with SHA-256) with a standard JWT header
    /// that includes the key ID (`kid`). The assertion is valid for 60 seconds.
    ///
    /// # Errors
    ///
    /// Returns [`FapiError::JwtSigning`] if signing fails.
    pub fn build(self, key: &ClientKey) -> Result<ClientAssertion, FapiError> {
        let now = jiff::Timestamp::now().as_second();

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key.kid().to_string());

        let claims = ClientAssertionClaims {
            iss: self.client_id.clone(),
            sub: self.client_id,
            aud: self.token_endpoint_url,
            jti: uuid::Uuid::now_v7().to_string(),
            iat: now,
            exp: now + 60,
        };

        let token = jsonwebtoken::encode(&header, &claims, &key.encoding_key())
            .map_err(|e| FapiError::JwtSigning(e.to_string()))?;

        Ok(ClientAssertion {
            assertion: token,
            assertion_type: ClientAssertion::TYPE,
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::get_unwrap
)]
mod tests {
    use super::*;
    use crate::fapi::key::ClientKey;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn decode_jwt_payload(token: &str) -> serde_json::Value {
        let parts: Vec<&str> = token.split('.').collect();
        let payload_b64 = parts[1];
        let bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("valid base64url");
        serde_json::from_slice(&bytes).expect("valid JSON")
    }

    fn decode_jwt_header(token: &str) -> serde_json::Value {
        let parts: Vec<&str> = token.split('.').collect();
        let header_b64 = parts[0];
        let bytes = URL_SAFE_NO_PAD.decode(header_b64).expect("valid base64url");
        serde_json::from_slice(&bytes).expect("valid JSON")
    }

    #[test]
    fn test_client_assertion_structure() {
        let key = ClientKey::generate().unwrap();
        let assertion =
            ClientAssertionBuilder::new("my-client-id", "https://server.example.com/oauth/token")
                .build(&key)
                .unwrap();

        assert_eq!(assertion.assertion_type, ClientAssertion::TYPE);
        assert!(!assertion.assertion.is_empty());

        // JWT must have 3 parts
        let parts: Vec<&str> = assertion.assertion.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_client_assertion_header() {
        let key = ClientKey::generate().unwrap();
        let assertion =
            ClientAssertionBuilder::new("my-client-id", "https://server.example.com/oauth/token")
                .build(&key)
                .unwrap();

        let header = decode_jwt_header(&assertion.assertion);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], key.kid());
    }

    #[test]
    fn test_client_assertion_claims() {
        let key = ClientKey::generate().unwrap();
        let assertion =
            ClientAssertionBuilder::new("my-client-id", "https://server.example.com/oauth/token")
                .build(&key)
                .unwrap();

        let claims = decode_jwt_payload(&assertion.assertion);
        assert_eq!(claims["iss"], "my-client-id");
        assert_eq!(claims["sub"], "my-client-id");
        assert_eq!(claims["aud"], "https://server.example.com/oauth/token");
        assert!(claims.get("jti").is_some(), "must have jti");
        assert!(claims.get("iat").is_some(), "must have iat");
        assert!(claims.get("exp").is_some(), "must have exp");

        // exp must be roughly iat + 60
        let iat = claims["iat"].as_i64().unwrap();
        let exp = claims["exp"].as_i64().unwrap();
        assert_eq!(exp - iat, 60, "assertion must expire in 60 seconds");
    }

    #[test]
    fn test_client_assertion_type_constant() {
        assert_eq!(
            ClientAssertion::TYPE,
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        );
    }

    #[test]
    fn test_client_assertion_jti_is_unique() {
        let key = ClientKey::generate().unwrap();

        let a1 = ClientAssertionBuilder::new("client", "https://example.com/token")
            .build(&key)
            .unwrap();
        let a2 = ClientAssertionBuilder::new("client", "https://example.com/token")
            .build(&key)
            .unwrap();

        let claims1 = decode_jwt_payload(&a1.assertion);
        let claims2 = decode_jwt_payload(&a2.assertion);

        assert_ne!(
            claims1["jti"], claims2["jti"],
            "each assertion must have a unique jti"
        );
    }
}
