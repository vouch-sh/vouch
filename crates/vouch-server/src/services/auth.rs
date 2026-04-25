// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authentication service for FIDO2/WebAuthn login.
//!
//! Implements:
//! - WebAuthn Level 2 Section 7.2 — Verifying an Authentication Assertion
//! - RFC 8176 — Authentication Method Reference Values
//! - RFC 9068 Section 2.2 — JWT Access Token claims (`amr`, `acr`)
//!
//! This module provides business logic for authenticating users via WebAuthn
//! discoverable credentials. It handles:
//! - Authentication method references (AMR) and assurance levels (ACR)
//! - Authenticator lookup and ownership verification
//! - WebAuthn assertion verification
//! - OAuth access token creation and storage
//!
//! The handlers remain thin, focusing on HTTP concerns.

use crate::AppState;
use crate::crypto::hash_token;
use crate::crypto::webauthn_verify;
use crate::db::{self, Authenticator, SessionPurpose, User};
use crate::services::oidc::{CnfClaim, OidcSigningKey, ScopeSet};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use uuid::Uuid;

use super::{OAuthErrorCode, ServiceError, ServiceResult};

// ============================================================================
// Authentication Method References (RFC 8176)
// ============================================================================

/// Authentication method reference value (RFC 8176).
///
/// Represents a single authentication method used during user authentication.
/// Vouch always uses FIDO2 hardware keys with PIN and user presence, so all
/// three methods are present in every authentication event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// RFC 8176: Proof-of-possession of a hardware-secured key.
    HardwareKey,
    /// RFC 8176: Personal Identification Number or pattern verified on device.
    Pin,
    /// RFC 8176: User presence test (physical interaction with authenticator).
    UserPresence,
}

impl AuthMethod {
    /// Return the wire-format string per RFC 8176.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HardwareKey => "hwk",
            Self::Pin => "pin",
            Self::UserPresence => "user",
        }
    }

    /// All authentication methods used in a FIDO2 hardware key flow.
    ///
    /// Vouch always requires hardware key + PIN + user presence, so this
    /// returns all three methods.
    #[must_use]
    pub const fn all_fido2() -> &'static [Self] {
        &[Self::HardwareKey, Self::Pin, Self::UserPresence]
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for AuthMethod {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AuthMethod {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "hwk" => Ok(Self::HardwareKey),
            "pin" => Ok(Self::Pin),
            "user" => Ok(Self::UserPresence),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["hwk", "pin", "user"],
            )),
        }
    }
}

/// NIST SP 800-63B AAL3: Hardware-based multi-factor authentication.
///
/// FIDO2 hardware key + PIN + user presence meets AAL3 per NIST SP 800-63B.
pub(crate) const ACR_AAL3: &str = "urn:nist:authentication:assurance-level:aal3";

/// Authentication assurance level for an issued token.
///
/// Bundles `hardware_verified`, `amr`, and `acr` into a single type
/// to prevent inconsistent combinations (e.g., `hardware_verified: true`
/// with `amr: None`).
#[derive(Debug, Clone)]
pub(crate) enum HardwareVerification {
    /// FIDO2 hardware key verified by Vouch (UP + UV).
    /// Sets `hardware_verified: true`, `amr: [hwk, pin, user]`,
    /// `acr: urn:nist:...:aal3`.
    Verified,
    /// No hardware verification performed (M2M, JWT bearer, etc.).
    /// Sets `hardware_verified: false`, `amr: None`, `acr: None`.
    NotVerified,
}

impl HardwareVerification {
    /// Whether FIDO2 hardware verification was performed.
    #[must_use]
    pub(crate) fn hardware_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }

    /// RFC 8176 authentication methods reference.
    #[must_use]
    pub(crate) fn amr(&self) -> Option<Vec<AuthMethod>> {
        match self {
            Self::Verified => Some(AuthMethod::all_fido2().to_vec()),
            Self::NotVerified => None,
        }
    }

    /// RFC 9068 authentication context class reference.
    #[must_use]
    pub(crate) fn acr(&self) -> Option<String> {
        match self {
            Self::Verified => Some(ACR_AAL3.to_string()),
            Self::NotVerified => None,
        }
    }
}

/// Parameters for verifying authenticator ownership.
pub(crate) struct AuthenticatorLookupParams<'a> {
    /// The credential ID from the WebAuthn assertion.
    pub credential_id: &'a [u8],
    /// The user ID from the user handle.
    pub user_id: Uuid,
}

/// Result of authenticator lookup and ownership verification.
pub(crate) struct AuthenticatorLookupResult {
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
pub(crate) async fn lookup_and_verify_authenticator(
    state: &AppState,
    params: AuthenticatorLookupParams<'_>,
) -> ServiceResult<AuthenticatorLookupResult> {
    // Get the authenticator and user in a single JOIN query
    let row = db::get_authenticator_with_user_by_credential_id(&state.store, params.credential_id)
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
        .ok_or(ServiceError::NotFound("credential"))?;

    let (authenticator, user) = (row.authenticator, row.user);

    // Verify authenticator belongs to this user (from user_handle)
    if authenticator.user_id != params.user_id.to_string() {
        return Err(ServiceError::Forbidden("user_mismatch"));
    }

    if !user.active {
        return Err(ServiceError::Forbidden("user_deactivated"));
    }

    Ok(AuthenticatorLookupResult {
        authenticator,
        user,
    })
}

/// Parameters for verifying a WebAuthn login assertion.
pub(crate) struct LoginAssertionParams {
    /// Authenticator data from the assertion.
    pub authenticator_data: Vec<u8>,
    /// Client data JSON from the assertion.
    pub client_data_json: Vec<u8>,
    /// Signature from the assertion.
    pub signature: Vec<u8>,
    /// Public key of the authenticator.
    pub public_key: Vec<u8>,
    /// Relying party ID.
    pub rp_id: String,
    /// Expected challenge (raw bytes).
    pub challenge: Vec<u8>,
    /// Current counter value from the database.
    pub stored_counter: u32,
}

/// Result of WebAuthn assertion verification.
pub(crate) struct LoginAssertionResult {
    /// New counter value to store.
    pub new_counter: u32,
    /// Whether user verification was performed.
    pub user_verified: bool,
}

/// Verify a WebAuthn login assertion (WebAuthn Level 2 Section 7.2).
///
/// Runs signature verification on a blocking thread as a fairness
/// optimization: on small (1-vCPU) instances, ECDSA/Ed25519
/// verification (~0.5-2 ms) would monopolize the single worker thread,
/// stalling all other I/O. Unlike the KMS SSH-CA path (which would
/// deadlock without `spawn_blocking`), this is purely about runtime
/// fairness — local crypto doesn't block on async I/O.
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with `InvalidGrant` if verification fails.
pub(crate) async fn verify_login_assertion(
    params: LoginAssertionParams,
) -> ServiceResult<LoginAssertionResult> {
    tokio::task::spawn_blocking(move || {
        let expected_origin = format!("https://{}", params.rp_id);
        let expected_challenge = URL_SAFE_NO_PAD.encode(&params.challenge);

        let result = webauthn_verify::verify_assertion(
            &params.authenticator_data,
            &params.client_data_json,
            &params.signature,
            &params.public_key,
            &params.rp_id,
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
    })
    .await
    .map_err(|e| {
        tracing::error!("WebAuthn verification task failed: {e}");
        ServiceError::Internal("WebAuthn verification failed".to_string())
    })?
}

/// Actor claim for delegation chains (RFC 8693 Section 4.1).
///
/// Used in both token exchange responses and access token JWTs to
/// represent the acting party in a delegation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ActorClaim {
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
    pub(crate) fn depth(&self) -> usize {
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
pub(crate) const MAX_DELEGATION_DEPTH: usize = 5;

/// JWT Access Token claims per RFC 9068 Section 2.2.
///
/// These claims are included in OAuth 2.0 access tokens signed with ES256.
/// The JWT header MUST have `typ: "at+jwt"` (RFC 9068 Section 2.1).
///
/// Note: `authenticator_id` is intentionally excluded from the JWT to
/// prevent information leakage. It is stored server-side in the sessions
/// table and looked up via the token hash.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AccessTokenClaims {
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
    /// RFC 8725 §3.4: Not before time (set to iat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
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
    /// RFC 9068 Section 2.2 / RFC 8176: Authentication methods used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<AuthMethod>>,
    /// RFC 9068 Section 2.2: Authentication context class reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
}

/// Parameters for creating an OAuth access token (RFC 9068).
pub(crate) struct CreateOAuthTokenParams<'a> {
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
    /// mTLS certificate thumbprint for sender-constrained binding (RFC 8705).
    pub mtls_cert_thumbprint: Option<&'a str>,
    /// Actor claim for delegation chains (token exchange).
    pub act: Option<ActorClaim>,
    /// Optional audience override (for token exchange with explicit audience).
    /// When `None`, defaults to `client_id`.
    pub audience: Option<&'a str>,
    /// Time when the End-User authentication occurred (Unix timestamp).
    /// Populated from FIDO2 session creation time for authorization code grants.
    pub auth_time: Option<i64>,
    /// Authentication assurance level — bundles `hardware_verified`, `amr`,
    /// and `acr` to prevent inconsistent combinations.
    pub hardware_verification: HardwareVerification,
    /// Session purpose for the database record.
    pub session_purpose: SessionPurpose,
    /// RFC 9396: Rich authorization details (JSON array, stored in session).
    pub authorization_details: Option<&'a serde_json::Value>,
}

/// Result of creating a session token.
pub(crate) struct CreateSessionResult {
    /// The JWT token.
    pub token: SecretString,
    /// Token lifetime in seconds.
    pub expires_in: u64,
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
pub(crate) async fn create_oauth_access_token(
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
        .is_some_and(|s| s.contains(crate::services::oidc::OAuthScope::Email));

    // RFC 9449 / RFC 8705: Include cnf claim for sender-constrained tokens.
    // DPoP (jkt) takes priority over mTLS (x5t#S256).
    let cnf = match (params.dpop_jkt, params.mtls_cert_thumbprint) {
        (Some(jkt), _) => Some(CnfClaim {
            jkt: Some(jkt.to_string()),
            x5t_s256: None,
        }),
        (None, Some(x5t)) => Some(CnfClaim {
            jkt: None,
            x5t_s256: Some(x5t.to_string()),
        }),
        (None, None) => None,
    };

    let claims = AccessTokenClaims {
        iss: state.config().base_url.clone(),
        sub: params.user_id.to_string(),
        aud,
        exp: expires.as_second(),
        iat: now.as_second(),
        nbf: Some(now.as_second()),
        jti,
        client_id: params.client_id.to_string(),
        scope: params.scope.clone(),
        email: if has_email_scope {
            Some(params.email.to_string())
        } else {
            None
        },
        email_verified: if has_email_scope { Some(true) } else { None },
        hardware_verified: params.hardware_verification.hardware_verified(),
        cnf,
        auth_time: params.auth_time,
        act: params.act,
        amr: params.hardware_verification.amr(),
        acr: params.hardware_verification.acr(),
    };

    let token = state
        .oidc_key
        .sign_access_token_jwt(&claims)
        .await
        .map_err(|e| ServiceError::Internal(format!("Access token signing failed: {e}")))?;

    // Store session in database (authenticator_id is server-side only)
    let token_hash = hash_token(&token);
    db::create_session(
        &state.store,
        params.user_id,
        params.email,
        &token_hash,
        params.authenticator_id,
        expires,
        params.session_purpose,
        params.authorization_details,
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to store session: {e}")))?;

    let expires_in = state.config().session_hours * 3600;

    Ok(CreateSessionResult {
        token: SecretString::from(token),
        expires_in,
    })
}

/// Decoded JWT token — an RFC 9068 OAuth access token (ES256, `at+jwt`).
pub(crate) enum DecodedToken {
    /// OAuth 2.0 access token (ES256, RFC 9068).
    AccessToken(AccessTokenClaims),
}

impl DecodedToken {
    /// RFC 7519 Section 4.1.2: Subject claim.
    #[must_use]
    pub(crate) fn sub(&self) -> &str {
        match self {
            Self::AccessToken(c) => &c.sub,
        }
    }

    /// User email. Returns `None` for access tokens without email scope.
    #[must_use]
    pub(crate) fn email(&self) -> Option<&str> {
        match self {
            Self::AccessToken(c) => c.email.as_deref(),
        }
    }

    /// RFC 6749 Section 3.3: Granted scope.
    #[must_use]
    pub(crate) fn scope(&self) -> Option<&ScopeSet> {
        match self {
            Self::AccessToken(c) => c.scope.as_ref(),
        }
    }

    /// DPoP confirmation claim (None for non-DPoP tokens).
    #[must_use]
    pub(crate) fn cnf(&self) -> Option<&CnfClaim> {
        match self {
            Self::AccessToken(c) => c.cnf.as_ref(),
        }
    }

    /// RFC 7519 Section 4.1.4: Expiration time (Unix timestamp).
    #[must_use]
    pub(crate) fn exp(&self) -> Option<i64> {
        match self {
            Self::AccessToken(c) => Some(c.exp),
        }
    }

    /// RFC 8693 Section 4.1: Actor claim for delegation chains.
    /// Only present in access tokens that resulted from token exchange.
    #[must_use]
    pub(crate) fn act(&self) -> Option<&ActorClaim> {
        match self {
            Self::AccessToken(c) => c.act.as_ref(),
        }
    }

    /// Reconstruct the hardware verification level from token claims.
    #[must_use]
    pub(crate) fn hardware_verification(&self) -> HardwareVerification {
        match self {
            Self::AccessToken(c) if c.hardware_verified => HardwareVerification::Verified,
            Self::AccessToken(_) => HardwareVerification::NotVerified,
        }
    }
}

/// Decode a JWT as an RFC 9068 ES256 access token.
///
/// This is a convenience wrapper around [`crate::crypto::jwt::decode_token`] that
/// constructs a [`TokenValidationContext`] from individual parameters.
///
/// Validates `typ`, `iss`, and optionally `aud` per RFC 8725.
/// Pass `expected_audience` for endpoints that require audience binding (e.g., userinfo).
/// Pass `None` for endpoints that accept tokens for any audience (introspection, revocation).
///
/// Returns `None` for invalid, expired, or unsupported tokens.
pub(crate) fn decode_token(
    token: &str,
    oidc_key: &OidcSigningKey,
    expected_issuer: &str,
) -> Option<DecodedToken> {
    let ctx = crate::crypto::jwt::TokenValidationContext::new(oidc_key, expected_issuer);
    crate::crypto::jwt::decode_token(token, &ctx)
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
    use crate::test_utils::{TEST_ISSUER, make_test_access_token, make_test_oidc_key};

    #[tokio::test]
    async fn test_decode_token_routes_es256_to_access_token() {
        let key = make_test_oidc_key();
        let token = make_test_access_token(&key).await;

        let decoded = decode_token(&token, &key, TEST_ISSUER);
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
        // An ES256 JWT signed with the OIDC key but with typ: "JWT" (ID token)
        // should NOT be decoded as an access token.
        let key = make_test_oidc_key();

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

        let decoded = decode_token(&token, &key, TEST_ISSUER);
        assert!(decoded.is_none(), "ID token should be rejected");
    }

    #[test]
    fn test_decode_token_rejects_garbage() {
        let key = make_test_oidc_key();
        assert!(decode_token("not.a.jwt", &key, TEST_ISSUER).is_none());
        assert!(decode_token("", &key, TEST_ISSUER).is_none());
        assert!(decode_token("abc123", &key, TEST_ISSUER).is_none());
    }

    #[tokio::test]
    async fn test_decode_token_rejects_expired_access_token() {
        let key = make_test_oidc_key();

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
        let decoded = decode_token(&token, &key, TEST_ISSUER);
        assert!(decoded.is_none(), "Expired token should be rejected");
    }

    #[tokio::test]
    async fn test_decoded_token_accessors() {
        let key = make_test_oidc_key();
        let token = make_test_access_token(&key).await;
        let decoded = decode_token(&token, &key, TEST_ISSUER).unwrap();

        assert_eq!(decoded.sub(), "user-123");
        assert_eq!(decoded.email(), Some("test@example.com"));
        assert!(decoded.scope().is_some());
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

    // AMR tests (RFC 8176)

    #[test]
    fn test_auth_method_wire_format() {
        assert_eq!(AuthMethod::HardwareKey.as_str(), "hwk");
        assert_eq!(AuthMethod::Pin.as_str(), "pin");
        assert_eq!(AuthMethod::UserPresence.as_str(), "user");
    }

    #[test]
    fn test_all_fido2() {
        let methods = AuthMethod::all_fido2();
        assert_eq!(methods.len(), 3);
        assert_eq!(methods[0], AuthMethod::HardwareKey);
        assert_eq!(methods[1], AuthMethod::Pin);
        assert_eq!(methods[2], AuthMethod::UserPresence);
    }

    #[test]
    fn test_auth_method_serde_roundtrip() {
        let methods: Vec<AuthMethod> = AuthMethod::all_fido2().to_vec();
        let json = serde_json::to_string(&methods).unwrap();
        assert_eq!(json, r#"["hwk","pin","user"]"#);

        let deserialized: Vec<AuthMethod> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, methods);
    }

    #[test]
    fn test_auth_method_deserialize_rejects_unknown() {
        let result: Result<AuthMethod, _> = serde_json::from_str(r#""mfa""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_method_display() {
        assert_eq!(format!("{}", AuthMethod::HardwareKey), "hwk");
        assert_eq!(format!("{}", AuthMethod::Pin), "pin");
        assert_eq!(format!("{}", AuthMethod::UserPresence), "user");
    }

    #[test]
    fn test_acr_aal3_constant() {
        assert!(ACR_AAL3.starts_with("urn:nist:"));
        assert!(ACR_AAL3.contains("aal3"));
    }

    #[test]
    fn test_access_token_claims_optional_fields_omitted() {
        let claims = AccessTokenClaims {
            iss: "https://example.com".to_string(),
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

        let json = serde_json::to_string(&claims).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");

        // Optional None fields should not be present
        assert!(parsed.get("scope").is_none());
        assert!(parsed.get("email").is_none());
        assert!(parsed.get("email_verified").is_none());
        assert!(parsed.get("cnf").is_none());
        assert!(parsed.get("auth_time").is_none());
        assert!(parsed.get("act").is_none());
        assert!(parsed.get("amr").is_none());
        assert!(parsed.get("acr").is_none());
        // Required fields should be present
        assert_eq!(parsed["iss"], "https://example.com");
        assert_eq!(parsed["sub"], "user-123");
    }
}
