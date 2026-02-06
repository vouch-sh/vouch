// SPDX-License-Identifier: BUSL-1.1
//! Authentication service for FIDO2/WebAuthn login.
//!
//! This module provides business logic for authenticating users via WebAuthn
//! discoverable credentials. It handles:
//! - Authenticator lookup and ownership verification
//! - WebAuthn assertion verification
//! - Session token creation and storage
//!
//! The handlers remain thin, focusing on HTTP concerns.

use crate::AppState;
use crate::db::{self, Authenticator, User};
use crate::handlers::common::{generate_challenge, hash_token};
use crate::webauthn_verify;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use jsonwebtoken::{EncodingKey, Header, encode};
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

/// Verify a WebAuthn login assertion.
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

/// Session claims for JWT tokens.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SessionClaims {
    /// Subject (user ID).
    pub sub: String,
    /// User email.
    pub email: String,
    /// Authenticator ID used for this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_id: Option<String>,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
}

/// Parameters for creating a login session.
pub struct CreateSessionParams<'a> {
    /// User ID.
    pub user_id: &'a str,
    /// User email.
    pub email: &'a str,
    /// Authenticator ID (optional for OIDC-only users).
    pub authenticator_id: Option<&'a str>,
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
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to store session: {e}")))?;

    Ok(CreateSessionResult {
        token,
        expires_at: expires.to_string(),
    })
}

/// Generate a WebAuthn challenge.
///
/// This is a wrapper around the common challenge generation for use in services.
#[must_use]
pub fn new_challenge() -> Vec<u8> {
    generate_challenge()
}
