// SPDX-License-Identifier: BUSL-1.1
//! Authentication service for FIDO2/WebAuthn login.
//!
//! Implements:
//! - WebAuthn Level 2 Section 7.2 — Verifying an Authentication Assertion
//! - RFC 7519 — JSON Web Token (JWT) for session tokens
//!
//! This module provides business logic for authenticating users via WebAuthn
//! discoverable credentials. It handles:
//! - Authenticator lookup and ownership verification
//! - WebAuthn assertion verification
//! - Session token creation and storage
//!
//! The handlers remain thin, focusing on HTTP concerns.

use crate::AppState;
use crate::db::{self, Authenticator, SessionPurpose, User};
use crate::handlers::common::hash_token;
use crate::services::oidc::dpop::CnfClaim;
use crate::services::oidc::keys::OidcSigningKey;
use crate::services::oidc::scope::ScopeSet;
use crate::webauthn_verify;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{OAuthErrorCode, ServiceError, ServiceResult};

/// Parameters for verifying authenticator ownership.
pub struct AuthenticatorLookupParams<'a> {
    /// The credential ID from the WebAuthn assertion.
    pub credential_id: &'a [u8],
    /// The user ID from the user handle.
    pub user_id: Uuid,
}

/// Result of authenticator lookup and ownership verification.
pub struct AuthenticatorLookupResult {
    /// The verified authenticator.
    pub authenticator: Authenticator,
    /// The user who owns the authenticator.
    pub user: User,
}

/// Look up an authenticator and verify it belongs to the specified user.
///
/// Uses a single JOIN query to fetch both the authenticator and user,
/// eliminating a sequential DB round-trip.
///
/// # Errors
///
/// Returns `ServiceError::NotFound` if the credential or user is not found.
/// Returns `ServiceError::Forbidden` if the credential doesn't belong to the user.
pub async fn lookup_and_verify_authenticator(
    state: &AppState,
    params: AuthenticatorLookupParams<'_>,
) -> ServiceResult<AuthenticatorLookupResult> {
    // Get the authenticator and user in a single JOIN query
    let row = db::get_authenticator_with_user_by_credential_id(&state.db, params.credential_id)
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
        .ok_or(ServiceError::NotFound("credential"))?;

    let (authenticator, user) = row.into_parts();

    // Verify authenticator belongs to this user (from user_handle)
    if authenticator.user_id != params.user_id.to_string() {
        return Err(ServiceError::Forbidden("user_mismatch"));
    }

    Ok(AuthenticatorLookupResult {
        authenticator,
        user,
    })
}

/// Parameters for verifying a WebAuthn login assertion.
pub struct LoginAssertionParams<'a> {
    /// Authenticator data from the assertion.
    pub authenticator_data: &'a [u8],
    /// Client data JSON from the assertion.
    pub client_data_json: &'a [u8],
    /// Signature from the assertion.
    pub signature: &'a [u8],
    /// Public key of the authenticator.
    pub public_key: &'a [u8],
    /// Relying party ID.
    pub rp_id: &'a str,
    /// Expected challenge (raw bytes).
    pub challenge: &'a [u8],
    /// Current counter value from the database.
    pub stored_counter: u32,
}

/// Result of WebAuthn assertion verification.
pub struct LoginAssertionResult {
    /// New counter value to store.
    pub new_counter: u32,
    /// Whether user verification was performed.
    pub user_verified: bool,
}

/// Verify a WebAuthn login assertion (WebAuthn Level 2 Section 7.2).
///
/// Performs signature verification, user verification check, and counter
/// validation as specified in the WebAuthn authentication ceremony.
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with `InvalidGrant` if verification fails.
pub fn verify_login_assertion(
    params: LoginAssertionParams<'_>,
) -> ServiceResult<LoginAssertionResult> {
    let expected_origin = format!("https://{}", params.rp_id);
    let expected_challenge = URL_SAFE_NO_PAD.encode(params.challenge);

    // Debug logging for signature verification (debug builds only)
    #[cfg(debug_assertions)]
    {
        tracing::debug!(
            "verify_login_assertion: sig_len={}, auth_data_len={}",
            params.signature.len(),
            params.authenticator_data.len()
        );
    }

    let result = webauthn_verify::verify_assertion(
        params.authenticator_data,
        params.client_data_json,
        params.signature,
        params.public_key,
        params.rp_id,
        &expected_challenge,
        &expected_origin,
        params.stored_counter,
        true, // require_user_verification
    )
    .map_err(|e| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            format!("WebAuthn verification failed: {e}"),
        )
    })?;

    Ok(LoginAssertionResult {
        new_counter: result.counter,
        user_verified: result.user_verified,
    })
}

/// Actor claim for delegation chains (RFC 8693 Section 4.1).
///
/// Used in both token exchange responses and access token JWTs to
/// represent the acting party in a delegation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorClaim {
    /// RFC 8693 Section 4.1: Subject identifier of the actor.
    pub sub: String,
    /// RFC 8693 Section 4.1: Nested actor (for multi-hop delegation).
    #[serde(rename = "act", skip_serializing_if = "Option::is_none")]
    pub actor: Option<Box<ActorClaim>>,
}

impl ActorClaim {
    /// Count the delegation depth of this actor chain.
    ///
    /// Returns 1 for a single actor, 2 for a nested actor, etc.
    /// Uses iterative traversal to prevent stack overflow from
    /// deeply nested (potentially malicious) actor chains.
    #[must_use]
    pub fn depth(&self) -> usize {
        let mut depth = 1;
        let mut current = &self.actor;
        while let Some(inner) = current {
            depth += 1;
            current = &inner.actor;
        }
        depth
    }
}

/// Maximum allowed delegation depth for actor chains.
///
/// Prevents unbounded nesting in token exchange delegation chains.
pub const MAX_DELEGATION_DEPTH: usize = 5;

/// JWT Access Token claims per RFC 9068 Section 2.2.
///
/// These claims are included in OAuth 2.0 access tokens signed with ES256.
/// The JWT header MUST have `typ: "at+jwt"` (RFC 9068 Section 2.1).
///
/// Note: `authenticator_id` is intentionally excluded from the JWT to
/// prevent information leakage. It is stored server-side in the sessions
/// table and looked up via the token hash.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// RFC 9068 Section 2.2: REQUIRED. Issuer identifier (base_url).
    pub iss: String,
    /// RFC 9068 Section 2.2: REQUIRED. Subject identifier (user ID).
    pub sub: String,
    /// RFC 9068 Section 2.2: REQUIRED. Audience (client_id or target resource).
    pub aud: String,
    /// RFC 9068 Section 2.2: REQUIRED. Expiration time (Unix timestamp).
    pub exp: i64,
    /// RFC 9068 Section 2.2: REQUIRED. Issued at time (Unix timestamp).
    pub iat: i64,
    /// RFC 9068 Section 2.2: REQUIRED. Unique token identifier.
    pub jti: String,
    /// RFC 9068 Section 2.2: REQUIRED. OAuth client that requested this token.
    pub client_id: String,
    /// RFC 6749 Section 3.3: Granted scope (space-separated in JWT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeSet>,
    /// OIDC Core Section 5.1: User email (included when email scope is granted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// OIDC Core Section 5.1: Whether email has been verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Custom claim: FIDO2 hardware verification proof.
    #[serde(default)]
    pub hardware_verified: bool,
    /// RFC 9449 Section 6: DPoP confirmation (sender-constrained token binding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
    /// RFC 9068 Section 2.2: Time when the End-User authentication occurred.
    /// RECOMMENDED per OIDC Core Section 2. Reflects FIDO2 session creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// RFC 8693 Section 4.1: Actor claim for delegation chains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
}

/// Parameters for creating an OAuth access token (RFC 9068).
pub struct CreateOAuthTokenParams<'a> {
    /// User ID (stored as `sub` claim).
    pub user_id: &'a str,
    /// User email (included when email scope is granted).
    pub email: &'a str,
    /// Authenticator ID (stored server-side in session, NOT in the JWT).
    pub authenticator_id: Option<&'a str>,
    /// OAuth client_id that requested this token.
    pub client_id: &'a str,
    /// Granted OAuth scope.
    pub scope: Option<ScopeSet>,
    /// DPoP JWK thumbprint for sender-constrained binding.
    pub dpop_jkt: Option<&'a str>,
    /// Actor claim for delegation chains (token exchange).
    pub act: Option<ActorClaim>,
    /// Optional audience override (for token exchange with explicit audience).
    /// When `None`, defaults to `client_id`.
    pub audience: Option<&'a str>,
    /// Time when the End-User authentication occurred (Unix timestamp).
    /// Populated from FIDO2 session creation time for authorization code grants.
    pub auth_time: Option<i64>,
}

/// Session claims for JWT tokens (RFC 7519 Section 4.1).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SessionClaims {
    /// RFC 7519 Section 4.1.2: Subject — the user ID.
    pub sub: String,
    /// User email (custom claim).
    pub email: String,
    /// Authenticator ID used for this session (custom claim).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_id: Option<String>,
    /// RFC 7519 Section 4.1.6: Issued At — Unix timestamp.
    pub iat: i64,
    /// RFC 7519 Section 4.1.4: Expiration Time — Unix timestamp.
    pub exp: i64,
    /// Session purpose — distinguishes FIDO2 sessions from OAuth access tokens.
    /// Defaults to `Fido2Session` for backward compatibility with existing JWTs.
    #[serde(default)]
    pub purpose: SessionPurpose,
    /// OAuth 2.0 granted scope. `None` for FIDO2 sessions and legacy tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeSet>,
}

/// Parameters for creating a login session.
pub struct CreateSessionParams<'a> {
    /// User ID.
    pub user_id: &'a str,
    /// User email.
    pub email: &'a str,
    /// Authenticator ID (optional for OIDC-only users).
    pub authenticator_id: Option<&'a str>,
    /// Session purpose (FIDO2 login vs OAuth access token).
    pub purpose: SessionPurpose,
    /// OAuth 2.0 granted scope. `None` for FIDO2 sessions.
    pub scope: Option<ScopeSet>,
}

/// Result of creating a login session.
pub struct CreateSessionResult {
    /// The JWT token.
    pub token: String,
    /// When the session expires (ISO 8601 string).
    pub expires_at: String,
}

/// Create a new login session and store it in the database.
///
/// # Errors
///
/// Returns `ServiceError::Internal` if token encoding or database operations fail.
pub async fn create_login_session(
    state: &AppState,
    params: CreateSessionParams<'_>,
) -> ServiceResult<CreateSessionResult> {
    let now = Timestamp::now();
    let session_hours = i64::try_from(state.config().session_hours)
        .map_err(|_| ServiceError::Internal("Invalid session hours".to_string()))?;
    let duration = Span::new().hours(session_hours);
    let expires = now
        .checked_add(duration)
        .map_err(|_| ServiceError::Internal("Time overflow".to_string()))?;

    let claims = SessionClaims {
        sub: params.user_id.to_string(),
        email: params.email.to_string(),
        authenticator_id: params.authenticator_id.map(String::from),
        iat: now.as_second(),
        exp: expires.as_second(),
        purpose: params.purpose,
        scope: params.scope,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config().jwt_secret_bytes()),
    )
    .map_err(|e| ServiceError::Internal(format!("Token encoding failed: {e}")))?;

    // Store session in database
    let token_hash = hash_token(&token);
    db::create_session(
        &state.db,
        params.user_id,
        &token_hash,
        params.authenticator_id,
        &expires.to_string(),
        params.purpose.as_str(),
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to store session: {e}")))?;

    Ok(CreateSessionResult {
        token,
        expires_at: expires.to_string(),
    })
}

/// Create an OAuth 2.0 access token per RFC 9068.
///
/// Signs the token with ES256 using the OIDC signing key, making it
/// verifiable via the JWKS endpoint by third-party resource servers.
/// The `authenticator_id` is stored server-side in the session record
/// and NOT included in the JWT to prevent information leakage.
///
/// # Errors
///
/// Returns `ServiceError::Internal` if token signing or database operations fail.
pub async fn create_oauth_access_token(
    state: &AppState,
    params: CreateOAuthTokenParams<'_>,
) -> ServiceResult<CreateSessionResult> {
    let now = Timestamp::now();
    let session_hours = i64::try_from(state.config().session_hours)
        .map_err(|_| ServiceError::Internal("Invalid session hours".to_string()))?;
    let duration = Span::new().hours(session_hours);
    let expires = now
        .checked_add(duration)
        .map_err(|_| ServiceError::Internal("Time overflow".to_string()))?;

    // RFC 9068 Section 2.2: jti MUST be a unique identifier
    let jti = Uuid::now_v7().to_string();

    // Determine audience: explicit audience (token exchange) or client_id
    let aud = params.audience.unwrap_or(params.client_id).to_string();

    // Include email claims when email scope is granted
    let has_email_scope = params
        .scope
        .as_ref()
        .is_some_and(|s| s.contains(crate::services::oidc::scope::OAuthScope::Email));

    // RFC 9449 Section 6: Include cnf claim if DPoP was used
    let cnf = params.dpop_jkt.map(|jkt| CnfClaim {
        jkt: jkt.to_string(),
    });

    let claims = AccessTokenClaims {
        iss: state.config().base_url.clone(),
        sub: params.user_id.to_string(),
        aud,
        exp: expires.as_second(),
        iat: now.as_second(),
        jti,
        client_id: params.client_id.to_string(),
        scope: params.scope.clone(),
        email: if has_email_scope {
            Some(params.email.to_string())
        } else {
            None
        },
        email_verified: if has_email_scope { Some(true) } else { None },
        hardware_verified: true,
        cnf,
        auth_time: params.auth_time,
        act: params.act,
    };

    let token = state
        .oidc_key
        .sign_access_token_jwt(&claims)
        .map_err(|e| ServiceError::Internal(format!("Access token signing failed: {e}")))?;

    // Store session in database (authenticator_id is server-side only)
    let token_hash = hash_token(&token);
    db::create_session(
        &state.db,
        params.user_id,
        &token_hash,
        params.authenticator_id,
        &expires.to_string(),
        SessionPurpose::OAuthAccessToken.as_str(),
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to store session: {e}")))?;

    Ok(CreateSessionResult {
        token,
        expires_at: expires.to_string(),
    })
}

/// Decoded JWT token — either a FIDO2 session (HS256) or an
/// RFC 9068 OAuth access token (ES256).
pub enum DecodedToken {
    /// Internal FIDO2 session token (HS256, RFC 7519).
    Session(SessionClaims),
    /// OAuth 2.0 access token (ES256, RFC 9068).
    AccessToken(AccessTokenClaims),
}

impl DecodedToken {
    /// RFC 7519 Section 4.1.2: Subject claim.
    #[must_use]
    pub fn sub(&self) -> &str {
        match self {
            Self::Session(c) => &c.sub,
            Self::AccessToken(c) => &c.sub,
        }
    }

    /// User email. Returns `None` for access tokens without email scope.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        match self {
            Self::Session(c) => Some(&c.email),
            Self::AccessToken(c) => c.email.as_deref(),
        }
    }

    /// RFC 6749 Section 3.3: Granted scope.
    #[must_use]
    pub fn scope(&self) -> Option<&ScopeSet> {
        match self {
            Self::Session(c) => c.scope.as_ref(),
            Self::AccessToken(c) => c.scope.as_ref(),
        }
    }

    /// DPoP confirmation claim (None for FIDO2 sessions or non-DPoP tokens).
    #[must_use]
    pub fn cnf(&self) -> Option<&CnfClaim> {
        match self {
            Self::Session(_) => None,
            Self::AccessToken(c) => c.cnf.as_ref(),
        }
    }

    /// RFC 7519 Section 4.1.4: Expiration time (Unix timestamp).
    #[must_use]
    pub fn exp(&self) -> Option<i64> {
        match self {
            Self::Session(c) => Some(c.exp),
            Self::AccessToken(c) => Some(c.exp),
        }
    }

    /// RFC 8693 Section 4.1: Actor claim for delegation chains.
    /// Only present in access tokens that resulted from token exchange.
    #[must_use]
    pub fn act(&self) -> Option<&ActorClaim> {
        match self {
            Self::Session(_) => None,
            Self::AccessToken(c) => c.act.as_ref(),
        }
    }
}

/// Decode a JWT, routing to the correct claims type based on algorithm.
///
/// Prevents algorithm confusion attacks by pinning each decode path
/// to a single algorithm via explicit `Validation`. Prevents token
/// substitution by checking `typ: "at+jwt"` (RFC 9068 Section 2.1)
/// for ES256 tokens.
///
/// Returns `None` for invalid, expired, or unsupported tokens.
pub fn decode_token(
    token: &str,
    jwt_secret: &[u8],
    oidc_key: &OidcSigningKey,
) -> Option<DecodedToken> {
    // Peek at the header to determine the algorithm
    let header = jsonwebtoken::decode_header(token).ok()?;

    match header.alg {
        Algorithm::ES256 => {
            // Attempt to decode as an RFC 9068 access token
            let decoding_key = oidc_key.decoding_key();
            let mut validation = Validation::new(Algorithm::ES256);
            validation.validate_aud = false;

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
            let decoding_key = DecodingKey::from_secret(jwt_secret);
            let validation = Validation::new(Algorithm::HS256);

            let token_data =
                jsonwebtoken::decode::<SessionClaims>(token, &decoding_key, &validation).ok()?;

            Some(DecodedToken::Session(token_data.claims))
        }
        // Reject all other algorithms (including "none") to prevent attacks
        _ => None,
    }
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
    use crate::services::oidc::keys::OidcSigningKey;

    const TEST_JWT_SECRET: &[u8] = b"test-jwt-secret-for-unit-tests-only";

    fn make_oidc_key() -> OidcSigningKey {
        OidcSigningKey::generate().expect("generate key")
    }

    fn make_access_token(key: &OidcSigningKey) -> String {
        let claims = AccessTokenClaims {
            iss: "https://example.com".to_string(),
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
        };
        key.sign_access_token_jwt(&claims).expect("sign")
    }

    fn make_session_token() -> String {
        let claims = SessionClaims {
            sub: "user-456".to_string(),
            email: "session@example.com".to_string(),
            authenticator_id: Some("auth-1".to_string()),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
            purpose: crate::db::SessionPurpose::Fido2Session,
            scope: None,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET),
        )
        .expect("encode")
    }

    #[test]
    fn test_decode_token_routes_es256_to_access_token() {
        let key = make_oidc_key();
        let token = make_access_token(&key);

        let decoded = decode_token(&token, TEST_JWT_SECRET, &key);
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
        let token = make_session_token();

        let decoded = decode_token(&token, TEST_JWT_SECRET, &key);
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
        // An ES256 JWT signed with the OIDC key but with typ: "JWT" (ID token)
        // should NOT be decoded as an access token.
        let key = make_oidc_key();

        let claims = AccessTokenClaims {
            iss: "https://example.com".to_string(),
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
        };

        // Sign as ID token (typ: "JWT", no "at+jwt")
        let token = key.sign_jwt(&claims).expect("sign");

        let decoded = decode_token(&token, TEST_JWT_SECRET, &key);
        assert!(decoded.is_none(), "ID token should be rejected");
    }

    #[test]
    fn test_decode_token_rejects_garbage() {
        let key = make_oidc_key();
        assert!(decode_token("not.a.jwt", TEST_JWT_SECRET, &key).is_none());
        assert!(decode_token("", TEST_JWT_SECRET, &key).is_none());
        assert!(decode_token("abc123", TEST_JWT_SECRET, &key).is_none());
    }

    #[test]
    fn test_decode_token_rejects_wrong_hs256_secret() {
        let key = make_oidc_key();
        let token = make_session_token();

        // Decode with wrong secret should fail
        let decoded = decode_token(&token, b"wrong-secret", &key);
        assert!(decoded.is_none());
    }

    #[test]
    fn test_decode_token_rejects_expired_access_token() {
        let key = make_oidc_key();

        let claims = AccessTokenClaims {
            iss: "https://example.com".to_string(),
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
        };

        let token = key.sign_access_token_jwt(&claims).expect("sign");
        let decoded = decode_token(&token, TEST_JWT_SECRET, &key);
        assert!(decoded.is_none(), "Expired token should be rejected");
    }

    #[test]
    fn test_decoded_token_accessors() {
        let key = make_oidc_key();
        let token = make_access_token(&key);
        let decoded = decode_token(&token, TEST_JWT_SECRET, &key).unwrap();

        assert_eq!(decoded.sub(), "user-123");
        assert_eq!(decoded.email(), Some("test@example.com"));
        assert!(decoded.scope().is_some());
        assert!(decoded.cnf().is_none());
        assert!(decoded.act().is_none());
    }

    #[test]
    fn test_decoded_token_session_accessors() {
        let key = make_oidc_key();
        let token = make_session_token();
        let decoded = decode_token(&token, TEST_JWT_SECRET, &key).unwrap();

        assert_eq!(decoded.sub(), "user-456");
        assert_eq!(decoded.email(), Some("session@example.com"));
        assert!(decoded.scope().is_none());
        assert!(decoded.cnf().is_none());
        assert!(decoded.act().is_none());
    }

    #[test]
    fn test_actor_claim_depth() {
        let single = ActorClaim {
            sub: "a@example.com".to_string(),
            actor: None,
        };
        assert_eq!(single.depth(), 1);

        let nested = ActorClaim {
            sub: "b@example.com".to_string(),
            actor: Some(Box::new(ActorClaim {
                sub: "a@example.com".to_string(),
                actor: None,
            })),
        };
        assert_eq!(nested.depth(), 2);

        let deep = ActorClaim {
            sub: "c@example.com".to_string(),
            actor: Some(Box::new(ActorClaim {
                sub: "b@example.com".to_string(),
                actor: Some(Box::new(ActorClaim {
                    sub: "a@example.com".to_string(),
                    actor: None,
                })),
            })),
        };
        assert_eq!(deep.depth(), 3);
    }

    #[test]
    fn test_actor_claim_depth_exceeds_max() {
        // Build a chain of MAX_DELEGATION_DEPTH + 1
        let mut actor = ActorClaim {
            sub: "leaf@example.com".to_string(),
            actor: None,
        };
        for i in 0..MAX_DELEGATION_DEPTH {
            actor = ActorClaim {
                sub: format!("actor-{i}@example.com"),
                actor: Some(Box::new(actor)),
            };
        }
        assert!(actor.depth() > MAX_DELEGATION_DEPTH);
    }

    #[test]
    fn test_access_token_claims_optional_fields_omitted() {
        let claims = AccessTokenClaims {
            iss: "https://example.com".to_string(),
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
        };

        let json = serde_json::to_string(&claims).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");

        // Optional None fields should not be present
        assert!(parsed.get("scope").is_none());
        assert!(parsed.get("email").is_none());
        assert!(parsed.get("email_verified").is_none());
        assert!(parsed.get("cnf").is_none());
        assert!(parsed.get("auth_time").is_none());
        assert!(parsed.get("act").is_none());
        // Required fields should be present
        assert_eq!(parsed["iss"], "https://example.com");
        assert_eq!(parsed["sub"], "user-123");
    }
}
