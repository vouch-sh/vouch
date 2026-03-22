// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWT token type management (RFC 8725 compliance).
//!
//! Implements:
//! - RFC 8725 Section 3.11 — Explicit Typing (RECOMMENDED)
//! - RFC 8725 Section 3.12 — Mutually Exclusive Validation Rules (MUST)
//! - RFC 8725 Section 3.8 — Issuer Validation (MUST)
//! - RFC 8725 Section 3.9 — Audience Validation (MUST)
//!
//! This module defines [`JwtType`] for explicit JWT type differentiation via
//! the `typ` header (RFC 7515 Section 4.1.9), preventing cross-type token
//! substitution attacks.

use crate::services::auth::{AccessTokenClaims, DecodedToken};
use crate::services::oidc::keys::OidcSigningKey;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt;
use zeroize::Zeroizing;

/// JWT token types used in the vouch system.
///
/// Each type maps to a distinct `typ` header value (RFC 7515 Section 4.1.9),
/// preventing cross-type token substitution (RFC 8725 Section 3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtType {
    /// RFC 9068 Section 2.1: OAuth 2.0 access token.
    AccessToken,
    /// Internal short-lived authorization code.
    AuthorizationCode,
    /// WebAuthn registration state (CLI flow).
    RegistrationState,
    /// Browser WebAuthn registration state.
    BrowserRegistrationState,
    /// Browser WebAuthn authentication state.
    BrowserAuthenticationState,
    /// GitHub OAuth state token.
    GitHubState,
    /// FIDO2 challenge state for the FIDO2 assertion grant.
    Fido2ChallengeState,
}

impl JwtType {
    /// RFC 7515 Section 4.1.9: `typ` header value.
    #[must_use]
    pub const fn as_header_str(&self) -> &'static str {
        match self {
            Self::AccessToken => "at+jwt",
            Self::AuthorizationCode => "vouch-authz+jwt",
            Self::RegistrationState => "vouch-reg-state+jwt",
            Self::BrowserRegistrationState => "vouch-browser-reg+jwt",
            Self::BrowserAuthenticationState => "vouch-browser-auth+jwt",
            Self::GitHubState => "vouch-github-state+jwt",
            Self::Fido2ChallengeState => "vouch-fido2-challenge+jwt",
        }
    }

    /// Parse a `typ` header value to a `JwtType`.
    #[cfg(test)]
    #[must_use]
    pub fn from_header_str(s: &str) -> Option<Self> {
        match s {
            "at+jwt" => Some(Self::AccessToken),
            "vouch-authz+jwt" => Some(Self::AuthorizationCode),
            "vouch-reg-state+jwt" => Some(Self::RegistrationState),
            "vouch-browser-reg+jwt" => Some(Self::BrowserRegistrationState),
            "vouch-browser-auth+jwt" => Some(Self::BrowserAuthenticationState),
            "vouch-github-state+jwt" => Some(Self::GitHubState),
            "vouch-fido2-challenge+jwt" => Some(Self::Fido2ChallengeState),
            _ => None,
        }
    }
}

impl From<JwtType> for Header {
    fn from(jwt_type: JwtType) -> Self {
        Self {
            typ: Some(jwt_type.as_header_str().to_string()),
            ..Default::default()
        }
    }
}

// ============================================================================
// State Token Signer (Local HS256 or KMS HMAC-SHA256)
// ============================================================================

/// Errors from state token encoding/decoding.
#[derive(Debug)]
pub enum StateTokenError {
    /// JWT encoding/decoding error (Local variant).
    Jwt(jsonwebtoken::errors::Error),
    /// KMS or JWT construction error (KMS variant).
    Internal(String),
    /// Token validation failed (expired, wrong type, etc.).
    Validation(String),
}

impl fmt::Display for StateTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jwt(e) => write!(f, "{e}"),
            Self::Internal(msg) => write!(f, "{msg}"),
            Self::Validation(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for StateTokenError {}

impl From<jsonwebtoken::errors::Error> for StateTokenError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Self::Jwt(e)
    }
}

/// Signs and verifies short-lived state tokens (HS256 locally or HMAC-SHA256
/// via KMS).
///
/// This enum dispatches at runtime, following the same `Local`/`Kms` pattern
/// used by [`OidcSigningKey`] and [`SshCa`].
pub enum StateTokenSigner {
    /// Local HS256 signing using a symmetric secret.
    Local {
        /// HS256 signing secret bytes (zeroized on drop).
        secret: Zeroizing<Vec<u8>>,
    },
    /// AWS KMS HMAC-SHA256 signing via `GenerateMac`/`VerifyMac`.
    Kms {
        /// KMS client for API calls.
        kms_client: aws_sdk_kms::Client,
        /// KMS key ID (must be an HMAC_256 key).
        key_id: String,
    },
}

impl StateTokenSigner {
    /// Create a local signer from a symmetric secret.
    #[must_use]
    pub fn local(secret: Vec<u8>) -> Self {
        Self::Local {
            secret: Zeroizing::new(secret),
        }
    }

    /// Create a KMS-backed signer.
    ///
    /// The key spec is validated implicitly on first `GenerateMac` call —
    /// KMS returns a clear error if the key is not an HMAC key.
    #[must_use]
    pub fn from_kms(kms_client: aws_sdk_kms::Client, key_id: String) -> Self {
        Self::Kms { kms_client, key_id }
    }

    /// Encode claims as a signed state token JWT.
    pub async fn encode_state_token<T: Serialize>(
        &self,
        claims: &T,
        jwt_type: JwtType,
    ) -> Result<String, StateTokenError> {
        match self {
            Self::Local { secret } => {
                encode_state_token(claims, jwt_type, secret).map_err(StateTokenError::Jwt)
            }
            Self::Kms { kms_client, key_id } => {
                kms_encode(kms_client, key_id, claims, jwt_type).await
            }
        }
    }

    /// Decode and verify a state token JWT.
    pub async fn decode_state_token<T: DeserializeOwned>(
        &self,
        token: &str,
        jwt_type: JwtType,
    ) -> Result<T, StateTokenError> {
        match self {
            Self::Local { secret } => {
                decode_state_token(token, jwt_type, secret).map_err(StateTokenError::Jwt)
            }
            Self::Kms { kms_client, key_id } => {
                kms_decode(kms_client, key_id, token, jwt_type).await
            }
        }
    }
}

/// KMS: build a JWT manually and sign with `GenerateMac`.
async fn kms_encode<T: Serialize>(
    kms_client: &aws_sdk_kms::Client,
    key_id: &str,
    claims: &T,
    jwt_type: JwtType,
) -> Result<String, StateTokenError> {
    let header_json = serde_json::json!({
        "alg": "HS256",
        "typ": jwt_type.as_header_str()
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());

    let payload_bytes = serde_json::to_vec(claims)
        .map_err(|e| StateTokenError::Internal(format!("Failed to serialize claims: {e}")))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);

    let message = format!("{header_b64}.{payload_b64}");

    tracing::debug!(
        key_id,
        typ = jwt_type.as_header_str(),
        "KMS GenerateMac: signing state token"
    );

    let response = kms_client
        .generate_mac()
        .key_id(key_id)
        .mac_algorithm(aws_sdk_kms::types::MacAlgorithmSpec::HmacSha256)
        .message(aws_smithy_types::Blob::new(message.as_bytes()))
        .send()
        .await
        .map_err(|e| {
            tracing::debug!(key_id, error = %e, "KMS GenerateMac failed");
            StateTokenError::Internal(format!("KMS GenerateMac failed: {e}"))
        })?;

    let mac = response
        .mac()
        .ok_or_else(|| StateTokenError::Internal("KMS GenerateMac returned no MAC".to_string()))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(mac.as_ref());

    tracing::debug!(
        key_id,
        typ = jwt_type.as_header_str(),
        "KMS GenerateMac: success"
    );

    Ok(format!("{message}.{sig_b64}"))
}

/// KMS: verify a JWT using `VerifyMac`, then validate typ + exp.
async fn kms_decode<T: DeserializeOwned>(
    kms_client: &aws_sdk_kms::Client,
    key_id: &str,
    token: &str,
    jwt_type: JwtType,
) -> Result<T, StateTokenError> {
    // Split into header.payload.signature
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    let [header_b64, payload_b64, sig_b64] = parts.as_slice() else {
        return Err(StateTokenError::Validation("Malformed JWT".to_string()));
    };

    // Verify MAC via KMS
    let message = format!("{header_b64}.{payload_b64}");
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| StateTokenError::Validation(format!("Invalid signature encoding: {e}")))?;

    tracing::debug!(
        key_id,
        typ = jwt_type.as_header_str(),
        "KMS VerifyMac: verifying state token"
    );

    let verify_result = kms_client
        .verify_mac()
        .key_id(key_id)
        .mac_algorithm(aws_sdk_kms::types::MacAlgorithmSpec::HmacSha256)
        .message(aws_smithy_types::Blob::new(message.as_bytes()))
        .mac(aws_smithy_types::Blob::new(sig_bytes))
        .send()
        .await
        .map_err(|e| {
            tracing::debug!(key_id, error = %e, "KMS VerifyMac failed");
            StateTokenError::Internal(format!("KMS VerifyMac failed: {e}"))
        })?;

    if !verify_result.mac_valid() {
        tracing::debug!(
            key_id,
            typ = jwt_type.as_header_str(),
            "KMS VerifyMac: MAC verification failed"
        );
        return Err(StateTokenError::Validation(
            "MAC verification failed".to_string(),
        ));
    }

    tracing::debug!(
        key_id,
        typ = jwt_type.as_header_str(),
        "KMS VerifyMac: success"
    );

    // Validate typ header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| StateTokenError::Validation(format!("Invalid header encoding: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| StateTokenError::Validation(format!("Invalid header JSON: {e}")))?;

    if header.get("typ").and_then(|v| v.as_str()) != Some(jwt_type.as_header_str()) {
        return Err(StateTokenError::Validation(format!(
            "Wrong typ header: expected {}",
            jwt_type.as_header_str()
        )));
    }

    // Decode payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| StateTokenError::Validation(format!("Invalid payload encoding: {e}")))?;

    // Require and validate exp claim (parity with Local path's jsonwebtoken)
    let raw: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| StateTokenError::Validation(format!("Invalid payload JSON: {e}")))?;
    let exp = raw
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| StateTokenError::Validation("Missing exp claim".to_string()))?;
    let now = jiff::Timestamp::now().as_second();
    if now > exp {
        return Err(StateTokenError::Validation("Token has expired".to_string()));
    }

    serde_json::from_slice(&payload_bytes)
        .map_err(|e| StateTokenError::Validation(format!("Failed to deserialize claims: {e}")))
}

// ============================================================================
// ES256 Access Token Validation
// ============================================================================

/// Context for token validation, bundling the OIDC signing key and issuer info.
///
/// Avoids parameter proliferation on [`decode_token`].
pub struct TokenValidationContext<'a> {
    /// ES256 OIDC signing key.
    pub(crate) oidc_key: &'a OidcSigningKey,
    /// Expected issuer (base_url).
    pub(crate) expected_issuer: &'a str,
    /// Optional expected audience for access tokens.
    ///
    /// When `Some`, the `aud` claim of ES256 access tokens is validated
    /// against this value (RFC 8725 Section 3.9). When `None`, audience
    /// validation is skipped (for introspection/revocation endpoints that
    /// accept tokens for any audience).
    pub(crate) expected_audience: Option<&'a str>,
}

impl<'a> TokenValidationContext<'a> {
    /// Create from an OIDC signing key and issuer.
    ///
    /// Note: `config` must be passed separately because `AppState::config()`
    /// returns a guard that must be held for the lifetime of the reference.
    #[must_use]
    pub fn new(oidc_key: &'a OidcSigningKey, expected_issuer: &'a str) -> Self {
        Self {
            oidc_key,
            expected_issuer,
            expected_audience: None,
        }
    }
}

/// Decode a JWT as an RFC 9068 ES256 access token.
///
/// Prevents algorithm confusion attacks by pinning the decode path
/// to ES256 via explicit `Validation`. Validates `typ` header
/// (RFC 8725 Section 3.11) and `iss` claim (RFC 8725 Section 3.8).
///
/// For access tokens, audience validation is contextual — callers MUST
/// validate `aud` against their expected audience (RFC 8725 Section 3.9).
///
/// Returns `None` for invalid, expired, or unsupported tokens.
pub fn decode_token(token: &str, ctx: &TokenValidationContext<'_>) -> Option<DecodedToken> {
    // Peek at the header to determine the algorithm
    let header = jsonwebtoken::decode_header(token).ok()?;

    match header.alg {
        Algorithm::ES256 => {
            // Attempt to decode as an RFC 9068 access token
            let decoding_key = ctx.oidc_key.decoding_key();
            let mut validation = Validation::new(Algorithm::ES256);
            // Validate audience when caller specifies one (RFC 8725 §3.9)
            if let Some(aud) = ctx.expected_audience {
                validation.set_audience(&[aud]);
                validation.validate_aud = true;
            } else {
                validation.validate_aud = false;
            }
            // RFC 8725 §3.8: Validate issuer
            validation.set_issuer(&[ctx.expected_issuer]);

            let token_data =
                jsonwebtoken::decode::<AccessTokenClaims>(token, decoding_key, &validation).ok()?;

            // RFC 9068 Section 2.1: Verify typ is "at+jwt" to prevent
            // ID tokens from being accepted as access tokens (same signing key).
            if token_data.header.typ.as_deref() != Some(JwtType::AccessToken.as_header_str()) {
                return None;
            }

            Some(DecodedToken::AccessToken(token_data.claims))
        }
        // Reject all other algorithms (including "none" and HS256) to prevent attacks
        _ => None,
    }
}

/// Encode a short-lived state token as a JWT with an explicit `typ` header.
///
/// This is a generic helper for the state token types (registration, authentication,
/// browser registration, browser authentication, GitHub state, FIDO2 challenge) that
/// share the same encode pattern: set `typ` header from [`JwtType`], sign with HS256.
pub fn encode_state_token<T: Serialize>(
    claims: &T,
    jwt_type: JwtType,
    secret: &[u8],
) -> Result<String, jsonwebtoken::errors::Error> {
    jsonwebtoken::encode(
        &Header::from(jwt_type),
        claims,
        &EncodingKey::from_secret(secret),
    )
}

/// Decode a short-lived state token, validating the `typ` header.
///
/// This is a generic helper for the state token types. It decodes with
/// default validation (only `exp` check), then validates that the `typ`
/// header matches the expected [`JwtType`].
pub fn decode_state_token<T: DeserializeOwned>(
    token: &str,
    jwt_type: JwtType,
    secret: &[u8],
) -> Result<T, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.required_spec_claims.clear();
    // Skip aud validation — callers that need it (e.g. AuthorizationCode)
    // validate iss/aud manually after decode.
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<T>(token, &DecodingKey::from_secret(secret), &validation)?;
    // RFC 8725 §3.11: Validate typ header
    if data.header.typ.as_deref() != Some(jwt_type.as_header_str()) {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }
    Ok(data.claims)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::services::auth::AccessTokenClaims;
    use crate::services::oidc::keys::OidcSigningKey;
    use crate::test_utils::{
        TEST_ISSUER, TEST_JWT_SECRET, make_test_access_token, make_test_oidc_key,
    };

    fn make_ctx(key: &OidcSigningKey) -> TokenValidationContext<'_> {
        TokenValidationContext::new(key, TEST_ISSUER)
    }

    #[tokio::test]
    async fn test_decode_token_routes_es256_to_access_token() {
        let key = make_test_oidc_key();
        let ctx = make_ctx(&key);
        let token = make_test_access_token(&key).await;

        let decoded = decode_token(&token, &ctx);
        assert!(decoded.is_some());
        match decoded.unwrap() {
            DecodedToken::AccessToken(c) => {
                assert_eq!(c.sub, "user-123");
                assert_eq!(c.client_id, "client-abc");
                assert_eq!(c.email.as_deref(), Some("test@example.com"));
            }
        }
    }

    #[tokio::test]
    async fn test_decode_token_rejects_id_token_without_at_jwt_typ() {
        let key = make_test_oidc_key();
        let ctx = make_ctx(&key);

        let claims = AccessTokenClaims {
            iss: TEST_ISSUER.to_string(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
            nbf: None,
            jti: "jti-1".to_string(),
            client_id: "client-abc".to_string(),
            scope: None,
            email: None,
            email_verified: None,
            hardware_verified: false,
            cnf: None,
            auth_time: None,
            act: None,
            amr: None,
            acr: None,
        };

        // Sign as ID token (typ: "JWT", no "at+jwt")
        let token = key.sign_jwt(&claims).await.expect("sign");
        let decoded = decode_token(&token, &ctx);
        assert!(decoded.is_none(), "ID token should be rejected");
    }

    #[test]
    fn test_decode_token_rejects_garbage() {
        let key = make_test_oidc_key();
        let ctx = make_ctx(&key);
        assert!(decode_token("not.a.jwt", &ctx).is_none());
        assert!(decode_token("", &ctx).is_none());
        assert!(decode_token("abc123", &ctx).is_none());
    }

    #[tokio::test]
    async fn test_decode_token_rejects_expired_access_token() {
        let key = make_test_oidc_key();
        let ctx = make_ctx(&key);

        let claims = AccessTokenClaims {
            iss: TEST_ISSUER.to_string(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp: 1, // Expired in 1970
            iat: 0,
            nbf: None,
            jti: "jti-1".to_string(),
            client_id: "client-abc".to_string(),
            scope: None,
            email: None,
            email_verified: None,
            hardware_verified: false,
            cnf: None,
            auth_time: None,
            act: None,
            amr: None,
            acr: None,
        };

        let token = key.sign_access_token_jwt(&claims).await.expect("sign");
        let decoded = decode_token(&token, &ctx);
        assert!(decoded.is_none(), "Expired token should be rejected");
    }

    #[tokio::test]
    async fn test_decode_token_rejects_wrong_issuer() {
        let key = make_test_oidc_key();
        let token = make_test_access_token(&key).await;

        // Use a different expected issuer
        let ctx = TokenValidationContext::new(&key, "https://wrong-issuer.com");
        let decoded = decode_token(&token, &ctx);
        assert!(
            decoded.is_none(),
            "Token with wrong issuer should be rejected"
        );
    }

    #[test]
    fn test_jwt_type_roundtrip() {
        let types = [
            JwtType::AccessToken,
            JwtType::AuthorizationCode,
            JwtType::RegistrationState,
            JwtType::BrowserRegistrationState,
            JwtType::BrowserAuthenticationState,
            JwtType::GitHubState,
            JwtType::Fido2ChallengeState,
        ];

        for typ in types {
            let s = typ.as_header_str();
            let parsed = JwtType::from_header_str(s);
            assert_eq!(parsed, Some(typ), "Roundtrip failed for {:?}", typ);
        }
    }

    #[test]
    fn test_jwt_type_unknown_returns_none() {
        assert_eq!(JwtType::from_header_str("unknown"), None);
        assert_eq!(JwtType::from_header_str(""), None);
        // Legacy session type is no longer supported
        assert_eq!(JwtType::from_header_str("vouch-session+jwt"), None);
    }

    #[tokio::test]
    async fn test_access_token_rejects_wrong_issuer() {
        let key = make_test_oidc_key();

        let claims = AccessTokenClaims {
            iss: "https://wrong-issuer.com".to_string(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
            nbf: None,
            jti: "jti-1".to_string(),
            client_id: "client-abc".to_string(),
            scope: None,
            email: None,
            email_verified: None,
            hardware_verified: false,
            cnf: None,
            auth_time: None,
            act: None,
            amr: None,
            acr: None,
        };

        let token = key.sign_access_token_jwt(&claims).await.expect("sign");
        let ctx = make_ctx(&key);
        let decoded = decode_token(&token, &ctx);
        assert!(
            decoded.is_none(),
            "Access token with wrong issuer should be rejected"
        );
    }

    // ====================================================================
    // State token encode/decode helpers
    // ====================================================================

    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
    struct TestState {
        data: String,
        iat: i64,
        exp: i64,
    }

    #[test]
    fn test_state_token_roundtrip() {
        let state = TestState {
            data: "hello".to_string(),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
        };
        let token = encode_state_token(&state, JwtType::RegistrationState, TEST_JWT_SECRET)
            .expect("encode");
        let decoded: TestState =
            decode_state_token(&token, JwtType::RegistrationState, TEST_JWT_SECRET)
                .expect("decode");
        assert_eq!(decoded, state);
    }

    #[test]
    fn test_state_token_wrong_type_rejected() {
        let state = TestState {
            data: "hello".to_string(),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
        };
        // Encode as RegistrationState, decode as BrowserRegistrationState (different typ)
        let token = encode_state_token(&state, JwtType::RegistrationState, TEST_JWT_SECRET)
            .expect("encode");
        let result: Result<TestState, _> =
            decode_state_token(&token, JwtType::BrowserRegistrationState, TEST_JWT_SECRET);
        assert!(result.is_err(), "Wrong type should be rejected");
    }

    #[test]
    fn test_state_token_wrong_secret_rejected() {
        let state = TestState {
            data: "hello".to_string(),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
        };
        let token =
            encode_state_token(&state, JwtType::GitHubState, TEST_JWT_SECRET).expect("encode");
        let result: Result<TestState, _> =
            decode_state_token(&token, JwtType::GitHubState, b"wrong-secret");
        assert!(result.is_err(), "Wrong secret should be rejected");
    }

    // ================================================================
    // StateTokenSigner::Local roundtrip tests
    // ================================================================

    #[tokio::test]
    async fn test_state_token_signer_local_roundtrip() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let state = TestState {
            data: "signer-test".to_string(),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
        };

        let token = signer
            .encode_state_token(&state, JwtType::Fido2ChallengeState)
            .await
            .expect("encode");
        let decoded: TestState = signer
            .decode_state_token(&token, JwtType::Fido2ChallengeState)
            .await
            .expect("decode");
        assert_eq!(decoded, state);
    }

    #[tokio::test]
    async fn test_state_token_signer_local_wrong_type_rejected() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let state = TestState {
            data: "wrong-type".to_string(),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
        };

        let token = signer
            .encode_state_token(&state, JwtType::GitHubState)
            .await
            .expect("encode");
        let result: Result<TestState, _> = signer
            .decode_state_token(&token, JwtType::RegistrationState)
            .await;
        assert!(result.is_err(), "Wrong type should be rejected");
    }

    #[tokio::test]
    async fn test_state_token_signer_local_wrong_secret_rejected() {
        let signer_a = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let signer_b =
            StateTokenSigner::local(b"different_secret_at_least_32chars_long!!".to_vec());
        let state = TestState {
            data: "wrong-secret".to_string(),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
        };

        let token = signer_a
            .encode_state_token(&state, JwtType::AuthorizationCode)
            .await
            .expect("encode");
        let result: Result<TestState, _> = signer_b
            .decode_state_token(&token, JwtType::AuthorizationCode)
            .await;
        assert!(result.is_err(), "Wrong secret should be rejected");
    }

    #[tokio::test]
    async fn test_state_token_signer_all_jwt_types() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let types = [
            JwtType::AuthorizationCode,
            JwtType::RegistrationState,
            JwtType::BrowserRegistrationState,
            JwtType::BrowserAuthenticationState,
            JwtType::GitHubState,
            JwtType::Fido2ChallengeState,
        ];

        for jwt_type in types {
            let state = TestState {
                data: format!("type-{}", jwt_type.as_header_str()),
                iat: 1_000_000_000,
                exp: 9_999_999_999,
            };

            let token = signer
                .encode_state_token(&state, jwt_type)
                .await
                .expect("encode");
            let decoded: TestState = signer
                .decode_state_token(&token, jwt_type)
                .await
                .expect("decode");
            assert_eq!(decoded, state, "Roundtrip failed for {:?}", jwt_type);
        }
    }

    #[tokio::test]
    async fn test_state_token_signer_local_expired_rejected() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let state = TestState {
            data: "expired".to_string(),
            iat: 0,
            exp: 1, // Expired in 1970
        };

        let token = signer
            .encode_state_token(&state, JwtType::RegistrationState)
            .await
            .expect("encode");
        let result: Result<TestState, _> = signer
            .decode_state_token(&token, JwtType::RegistrationState)
            .await;
        assert!(result.is_err(), "Expired token should be rejected");
    }

    #[test]
    fn test_state_token_error_display() {
        let jwt_err = StateTokenError::Jwt(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
        assert!(!format!("{jwt_err}").is_empty());

        let internal = StateTokenError::Internal("boom".to_string());
        assert_eq!(format!("{internal}"), "boom");

        let validation = StateTokenError::Validation("bad".to_string());
        assert_eq!(format!("{validation}"), "bad");
    }

    #[test]
    fn test_hs256_tokens_rejected_by_decode_token() {
        // HS256 tokens (legacy session tokens) must be rejected by decode_token
        use jsonwebtoken::{EncodingKey, encode};

        let key = make_test_oidc_key();
        let ctx = make_ctx(&key);

        // Create an HS256 signed JWT
        #[derive(serde::Serialize)]
        struct LegacyClaims {
            iss: String,
            sub: String,
            exp: i64,
        }
        let claims = LegacyClaims {
            iss: TEST_ISSUER.to_string(),
            sub: "user-456".to_string(),
            exp: 9_999_999_999,
        };
        let token = encode(
            &Header::default(), // HS256 by default
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET),
        )
        .expect("encode");

        let decoded = decode_token(&token, &ctx);
        assert!(decoded.is_none(), "HS256 tokens must be rejected");
    }
}
