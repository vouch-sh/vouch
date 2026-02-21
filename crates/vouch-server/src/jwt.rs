// SPDX-License-Identifier: BUSL-1.1
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

use crate::services::auth::{AccessTokenClaims, DecodedToken, SessionClaims};
use crate::services::oidc::keys::OidcSigningKey;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// JWT token types used in the vouch system.
///
/// Each type maps to a distinct `typ` header value (RFC 7515 Section 4.1.9),
/// preventing cross-type token substitution (RFC 8725 Section 3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtType {
    /// RFC 9068 Section 2.1: OAuth 2.0 access token.
    AccessToken,
    /// Internal FIDO2 session token.
    Session,
    /// Internal short-lived authorization code.
    AuthorizationCode,
    /// WebAuthn registration state (CLI flow).
    RegistrationState,
    /// WebAuthn authentication state (CLI flow).
    AuthenticationState,
    /// Browser WebAuthn registration state.
    BrowserRegistrationState,
    /// Browser WebAuthn authentication state.
    BrowserAuthenticationState,
    /// GitHub OAuth state token.
    GitHubState,
}

impl JwtType {
    /// RFC 7515 Section 4.1.9: `typ` header value.
    #[must_use]
    pub const fn as_header_str(&self) -> &'static str {
        match self {
            Self::AccessToken => "at+jwt",
            Self::Session => "vouch-session+jwt",
            Self::AuthorizationCode => "vouch-authz+jwt",
            Self::RegistrationState => "vouch-reg-state+jwt",
            Self::AuthenticationState => "vouch-auth-state+jwt",
            Self::BrowserRegistrationState => "vouch-browser-reg+jwt",
            Self::BrowserAuthenticationState => "vouch-browser-auth+jwt",
            Self::GitHubState => "vouch-github-state+jwt",
        }
    }

    /// Parse a `typ` header value to a `JwtType`.
    #[must_use]
    pub fn from_header_str(s: &str) -> Option<Self> {
        match s {
            "at+jwt" => Some(Self::AccessToken),
            "vouch-session+jwt" => Some(Self::Session),
            "vouch-authz+jwt" => Some(Self::AuthorizationCode),
            "vouch-reg-state+jwt" => Some(Self::RegistrationState),
            "vouch-auth-state+jwt" => Some(Self::AuthenticationState),
            "vouch-browser-reg+jwt" => Some(Self::BrowserRegistrationState),
            "vouch-browser-auth+jwt" => Some(Self::BrowserAuthenticationState),
            "vouch-github-state+jwt" => Some(Self::GitHubState),
            _ => None,
        }
    }

    /// Create a JWT header with the `typ` field set.
    #[must_use]
    pub fn to_header(self) -> Header {
        Header {
            typ: Some(self.as_header_str().to_string()),
            ..Default::default()
        }
    }
}

/// Context for token validation, bundling secrets and issuer info.
///
/// Avoids parameter proliferation on [`decode_token`].
pub struct TokenValidationContext<'a> {
    /// HS256 symmetric secret.
    pub jwt_secret: &'a [u8],
    /// ES256 OIDC signing key.
    pub oidc_key: &'a OidcSigningKey,
    /// Expected issuer (base_url).
    pub expected_issuer: &'a str,
}

impl<'a> TokenValidationContext<'a> {
    /// Create from `AppState`.
    ///
    /// Note: `config` must be passed separately because `AppState::config()`
    /// returns a guard that must be held for the lifetime of the reference.
    #[must_use]
    pub fn new(
        jwt_secret: &'a [u8],
        oidc_key: &'a OidcSigningKey,
        expected_issuer: &'a str,
    ) -> Self {
        Self {
            jwt_secret,
            oidc_key,
            expected_issuer,
        }
    }
}

/// Decode a JWT, routing to the correct claims type based on algorithm.
///
/// Prevents algorithm confusion attacks by pinning each decode path
/// to a single algorithm via explicit `Validation`. Validates `typ` header
/// for both ES256 and HS256 tokens (RFC 8725 Section 3.11). Validates
/// `iss` claim (RFC 8725 Section 3.8).
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
            validation.validate_aud = false;
            // RFC 8725 §3.8: Validate issuer
            validation.set_issuer(&[ctx.expected_issuer]);

            let token_data =
                jsonwebtoken::decode::<AccessTokenClaims>(token, decoding_key, &validation).ok()?;

            // RFC 9068 Section 2.1: Verify typ is "at+jwt" to prevent
            // ID tokens from being accepted as access tokens (same signing key).
            if token_data.header.typ.as_deref() != Some("at+jwt") {
                return None;
            }

            Some(DecodedToken::AccessToken(token_data.claims))
        }
        Algorithm::HS256 => {
            // Attempt to decode as a FIDO2 session token
            let decoding_key = DecodingKey::from_secret(ctx.jwt_secret);
            let validation = session_validation(ctx.expected_issuer);

            let token_data =
                jsonwebtoken::decode::<SessionClaims>(token, &decoding_key, &validation).ok()?;

            // RFC 8725 §3.11: Validate typ header
            if token_data.header.typ.as_deref() != Some(JwtType::Session.as_header_str()) {
                return None;
            }

            Some(DecodedToken::Session(token_data.claims))
        }
        // Reject all other algorithms (including "none") to prevent attacks
        _ => None,
    }
}

/// Build HS256 session validation with issuer and audience set to the expected issuer.
///
/// This consolidates the identical validation setup used in [`decode_session_jwt`]
/// (`handlers/common.rs`) and the HS256 branch of [`decode_token`].
#[must_use]
pub(crate) fn session_validation(expected_issuer: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_issuer]);
    validation
}

/// Encode a short-lived state token as a JWT with an explicit `typ` header.
///
/// This is a generic helper for the 5 state token types (registration, authentication,
/// browser registration, browser authentication, GitHub state) that share the same
/// encode pattern: set `typ` header from [`JwtType`], sign with HS256.
pub fn encode_state_token<T: Serialize>(
    claims: &T,
    jwt_type: JwtType,
    secret: &[u8],
) -> Result<String, jsonwebtoken::errors::Error> {
    jsonwebtoken::encode(
        &jwt_type.to_header(),
        claims,
        &EncodingKey::from_secret(secret),
    )
}

/// Decode a short-lived state token, validating the `typ` header.
///
/// This is a generic helper for the 5 state token types. It decodes with
/// default validation (only `exp` check), then validates that the `typ`
/// header matches the expected [`JwtType`].
pub fn decode_state_token<T: DeserializeOwned>(
    token: &str,
    jwt_type: JwtType,
    secret: &[u8],
) -> Result<T, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.required_spec_claims.clear();
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::services::auth::{AccessTokenClaims, SessionClaims};
    use crate::services::oidc::keys::OidcSigningKey;
    use crate::services::oidc::scope::ScopeSet;
    use jsonwebtoken::{EncodingKey, encode};

    const TEST_JWT_SECRET: &[u8] = b"test-jwt-secret-for-unit-tests-only";
    const TEST_ISSUER: &str = "https://example.com";

    fn make_oidc_key() -> OidcSigningKey {
        OidcSigningKey::generate().expect("generate key")
    }

    fn make_ctx(key: &OidcSigningKey) -> TokenValidationContext<'_> {
        TokenValidationContext::new(TEST_JWT_SECRET, key, TEST_ISSUER)
    }

    fn make_access_token(key: &OidcSigningKey) -> String {
        let claims = AccessTokenClaims {
            iss: TEST_ISSUER.to_string(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
            jti: "jti-1".to_string(),
            client_id: "client-abc".to_string(),
            scope: Some(ScopeSet::parse("openid email")),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            hardware_verified: true,
            cnf: None,
            auth_time: None,
            act: None,
            amr: None,
            acr: None,
        };
        key.sign_access_token_jwt(&claims).expect("sign")
    }

    fn make_session_token() -> String {
        let claims = SessionClaims {
            iss: TEST_ISSUER.to_string(),
            aud: TEST_ISSUER.to_string(),
            sub: "user-456".to_string(),
            email: "session@example.com".to_string(),
            authenticator_id: Some("auth-1".to_string()),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
            purpose: crate::db::SessionPurpose::Fido2Session,
            scope: None,
        };
        encode(
            &JwtType::Session.to_header(),
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET),
        )
        .expect("encode")
    }

    #[test]
    fn test_decode_token_routes_es256_to_access_token() {
        let key = make_oidc_key();
        let ctx = make_ctx(&key);
        let token = make_access_token(&key);

        let decoded = decode_token(&token, &ctx);
        assert!(decoded.is_some());
        match decoded.unwrap() {
            DecodedToken::AccessToken(c) => {
                assert_eq!(c.sub, "user-123");
                assert_eq!(c.client_id, "client-abc");
                assert_eq!(c.email.as_deref(), Some("test@example.com"));
            }
            DecodedToken::Session(_) => panic!("Expected AccessToken, got Session"),
        }
    }

    #[test]
    fn test_decode_token_routes_hs256_to_session() {
        let key = make_oidc_key();
        let ctx = make_ctx(&key);
        let token = make_session_token();

        let decoded = decode_token(&token, &ctx);
        assert!(decoded.is_some());
        match decoded.unwrap() {
            DecodedToken::Session(c) => {
                assert_eq!(c.sub, "user-456");
                assert_eq!(c.email, "session@example.com");
            }
            DecodedToken::AccessToken(_) => panic!("Expected Session, got AccessToken"),
        }
    }

    #[test]
    fn test_decode_token_rejects_id_token_without_at_jwt_typ() {
        let key = make_oidc_key();
        let ctx = make_ctx(&key);

        let claims = AccessTokenClaims {
            iss: TEST_ISSUER.to_string(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
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
        let token = key.sign_jwt(&claims).expect("sign");
        let decoded = decode_token(&token, &ctx);
        assert!(decoded.is_none(), "ID token should be rejected");
    }

    #[test]
    fn test_decode_token_rejects_garbage() {
        let key = make_oidc_key();
        let ctx = make_ctx(&key);
        assert!(decode_token("not.a.jwt", &ctx).is_none());
        assert!(decode_token("", &ctx).is_none());
        assert!(decode_token("abc123", &ctx).is_none());
    }

    #[test]
    fn test_decode_token_rejects_wrong_hs256_secret() {
        let key = make_oidc_key();
        let token = make_session_token();

        let ctx = TokenValidationContext::new(b"wrong-secret", &key, TEST_ISSUER);
        let decoded = decode_token(&token, &ctx);
        assert!(decoded.is_none());
    }

    #[test]
    fn test_decode_token_rejects_expired_access_token() {
        let key = make_oidc_key();
        let ctx = make_ctx(&key);

        let claims = AccessTokenClaims {
            iss: TEST_ISSUER.to_string(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp: 1, // Expired in 1970
            iat: 0,
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

        let token = key.sign_access_token_jwt(&claims).expect("sign");
        let decoded = decode_token(&token, &ctx);
        assert!(decoded.is_none(), "Expired token should be rejected");
    }

    #[test]
    fn test_decode_token_rejects_wrong_issuer() {
        let key = make_oidc_key();
        let token = make_session_token();

        // Use a different expected issuer
        let ctx = TokenValidationContext::new(TEST_JWT_SECRET, &key, "https://wrong-issuer.com");
        let decoded = decode_token(&token, &ctx);
        assert!(
            decoded.is_none(),
            "Token with wrong issuer should be rejected"
        );
    }

    #[test]
    fn test_decode_token_rejects_wrong_audience() {
        let key = make_oidc_key();

        // Create a session token with different audience
        let claims = SessionClaims {
            iss: TEST_ISSUER.to_string(),
            aud: "https://wrong-audience.com".to_string(),
            sub: "user-456".to_string(),
            email: "session@example.com".to_string(),
            authenticator_id: Some("auth-1".to_string()),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
            purpose: crate::db::SessionPurpose::Fido2Session,
            scope: None,
        };
        let token = encode(
            &JwtType::Session.to_header(),
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET),
        )
        .expect("encode");

        let ctx = make_ctx(&key);
        let decoded = decode_token(&token, &ctx);
        assert!(
            decoded.is_none(),
            "Token with wrong audience should be rejected"
        );
    }

    #[test]
    fn test_decode_token_rejects_session_without_typ() {
        let key = make_oidc_key();
        let ctx = make_ctx(&key);

        // Create a session token without typ header
        let claims = SessionClaims {
            iss: TEST_ISSUER.to_string(),
            aud: TEST_ISSUER.to_string(),
            sub: "user-456".to_string(),
            email: "session@example.com".to_string(),
            authenticator_id: Some("auth-1".to_string()),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
            purpose: crate::db::SessionPurpose::Fido2Session,
            scope: None,
        };
        let token = encode(
            &Header::default(), // No typ
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET),
        )
        .expect("encode");

        let decoded = decode_token(&token, &ctx);
        assert!(
            decoded.is_none(),
            "Session token without typ should be rejected"
        );
    }

    #[test]
    fn test_decode_token_rejects_cross_type_substitution() {
        let key = make_oidc_key();
        let ctx = make_ctx(&key);

        // Create a session token with auth code typ
        let claims = SessionClaims {
            iss: TEST_ISSUER.to_string(),
            aud: TEST_ISSUER.to_string(),
            sub: "user-456".to_string(),
            email: "session@example.com".to_string(),
            authenticator_id: Some("auth-1".to_string()),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
            purpose: crate::db::SessionPurpose::Fido2Session,
            scope: None,
        };
        let token = encode(
            &JwtType::AuthorizationCode.to_header(), // Wrong typ for a session
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET),
        )
        .expect("encode");

        let decoded = decode_token(&token, &ctx);
        assert!(decoded.is_none(), "Token with wrong typ should be rejected");
    }

    #[test]
    fn test_jwt_type_roundtrip() {
        let types = [
            JwtType::AccessToken,
            JwtType::Session,
            JwtType::AuthorizationCode,
            JwtType::RegistrationState,
            JwtType::AuthenticationState,
            JwtType::BrowserRegistrationState,
            JwtType::BrowserAuthenticationState,
            JwtType::GitHubState,
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
    }

    #[test]
    fn test_jwt_type_to_header() {
        let header = JwtType::Session.to_header();
        assert_eq!(header.typ, Some("vouch-session+jwt".to_string()));
        assert_eq!(header.alg, Algorithm::HS256); // Default algorithm
    }

    #[test]
    fn test_access_token_rejects_wrong_issuer() {
        let key = make_oidc_key();

        let claims = AccessTokenClaims {
            iss: "https://wrong-issuer.com".to_string(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
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

        let token = key.sign_access_token_jwt(&claims).expect("sign");
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
        // Encode as RegistrationState, decode as AuthenticationState
        let token = encode_state_token(&state, JwtType::RegistrationState, TEST_JWT_SECRET)
            .expect("encode");
        let result: Result<TestState, _> =
            decode_state_token(&token, JwtType::AuthenticationState, TEST_JWT_SECRET);
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

    // ====================================================================
    // Session validation helper
    // ====================================================================

    #[test]
    fn test_session_validation_config() {
        let validation = session_validation("https://example.com");
        assert_eq!(validation.algorithms, vec![Algorithm::HS256]);
        // Issuer and audience are set (internal fields tested via decode behavior)
    }
}
