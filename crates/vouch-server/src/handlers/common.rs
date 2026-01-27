//! Shared utilities for HTTP handlers.

use crate::AppState;
use crate::db;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use axum::Json;
use axum::http::{StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{DecodingKey, Validation};
use vouch_common::{ApiError, extract_aaguid_from_attestation, validate_hardware_attestation};

use super::auth::SessionClaims;

// ============================================================================
// JSON Error Helper
// ============================================================================

/// JSON error response helper.
///
/// Creates a standardized error response tuple suitable for returning from
/// handlers that have `Result<T, (StatusCode, Json<ApiError>)>` return types.
pub fn json_error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError::new(code, message)))
}

// ============================================================================
// Token Hashing
// ============================================================================

/// Hash a token for storage/lookup using SHA-256.
///
/// Returns a base64url-encoded hash of the token. This is used to store
/// tokens securely in the database without keeping the raw token value.
pub fn hash_token(token: &str) -> String {
    let hash = digest::digest(&SHA256, token.as_bytes());
    URL_SAFE_NO_PAD.encode(hash.as_ref())
}

// ============================================================================
// Random Byte Generation
// ============================================================================

/// Generate cryptographically secure random bytes.
///
/// # Panics
///
/// Panics if the system RNG fails, which should never happen on a correctly
/// functioning system. This is acceptable during request handling as an RNG
/// failure indicates a critical system problem.
#[allow(clippy::expect_used)]
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    aws_rand::fill(&mut bytes).expect("RNG failure");
    bytes
}

/// Generate a 32-byte challenge for WebAuthn.
///
/// This is a convenience wrapper around `generate_random_bytes(32)` for
/// WebAuthn challenge generation.
pub fn generate_challenge() -> Vec<u8> {
    generate_random_bytes(32)
}

// ============================================================================
// Session Extraction
// ============================================================================

/// Validated session information.
pub struct ValidatedSession {
    /// JWT claims from the session token.
    pub claims: SessionClaims,
    /// SHA-256 hash of the session token (for database lookups/revocation).
    #[allow(dead_code)]
    pub token_hash: String,
}

/// Extract and validate session from Authorization header.
///
/// This validates the JWT token and checks that a corresponding session
/// exists in the database.
///
/// # Errors
///
/// Returns an error response if:
/// - The Authorization header is missing or invalid
/// - The JWT token is invalid or expired
/// - No session exists in the database for this token
pub async fn extract_session(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<ValidatedSession, (StatusCode, Json<ApiError>)> {
    // Get Authorization header
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let token = auth_header.ok_or_else(|| {
        json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Missing or invalid Authorization header",
        )
    })?;

    // Validate JWT
    let claims = jsonwebtoken::decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret_bytes()),
        &Validation::default(),
    )
    .map_err(|_| {
        json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Invalid or expired token",
        )
    })?
    .claims;

    // Verify session exists in database
    let token_hash = hash_token(token);
    let session = db::get_session_by_token_hash(&state.db, &token_hash)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    if session.is_none() {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Session not found",
        ));
    }

    Ok(ValidatedSession { claims, token_hash })
}

/// Extract session and also fetch the user email.
///
/// This is a convenience function for handlers that need the user's email
/// in addition to the session claims.
///
/// # Errors
///
/// Returns an error response if session extraction fails or if the user
/// is not found in the database.
pub async fn extract_session_with_email(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(SessionClaims, String), (StatusCode, Json<ApiError>)> {
    let session = extract_session(state, headers).await?;

    // Get user email
    let user = db::get_user_by_id(&state.db, &session.claims.sub)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "user_not_found", "User not found"))?;

    Ok((session.claims, user.email))
}

// ============================================================================
// Template Response Macro
// ============================================================================

/// Macro to implement `IntoResponse` for Askama templates.
///
/// This reduces boilerplate when implementing `IntoResponse` for HTML templates.
/// The macro generates an implementation that renders the template and returns
/// either the HTML content or a 500 error if rendering fails.
///
/// # Example
///
/// ```ignore
/// use crate::impl_template_response;
///
/// #[derive(Template)]
/// #[template(path = "example.html")]
/// pub struct ExampleTemplate {
///     pub name: String,
/// }
///
/// impl_template_response!(ExampleTemplate);
/// ```
#[macro_export]
macro_rules! impl_template_response {
    ($($template:ty),* $(,)?) => {
        $(
            impl axum::response::IntoResponse for $template {
                fn into_response(self) -> axum::response::Response {
                    use askama::Template;
                    match self.render() {
                        Ok(html) => axum::response::Html(html).into_response(),
                        Err(e) => {
                            tracing::error!("Template render error: {}", e);
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                }
            }
        )*
    };
}

// ============================================================================
// Registration Validation
// ============================================================================

/// Result of validating a registration attestation.
pub struct ValidatedAttestation {
    /// The AAGUID extracted from the attestation (if available).
    pub aaguid: Option<String>,
    /// The device name determined from the AAGUID.
    pub device_name: String,
}

/// Validate a WebAuthn registration attestation.
///
/// This performs common validation for both CLI and browser registration:
/// 1. Validates the attestation is from a hardware authenticator (not software/platform)
/// 2. Extracts the AAGUID from the attestation
/// 3. Determines the device name from the AAGUID
///
/// Duplicate credential prevention is handled by WebAuthn's `excludeCredentials`
/// mechanism, which checks on the authenticator itself during `navigator.credentials.create()`.
///
/// # Errors
///
/// Returns an error if the attestation is from a software passkey or platform authenticator.
pub fn validate_registration_attestation(
    attestation_object: &[u8],
) -> Result<ValidatedAttestation, (StatusCode, Json<ApiError>)> {
    // Validate attestation format - reject software passkeys and platform authenticators
    let validation = validate_hardware_attestation(attestation_object);
    if let (Some(code), Some(message)) = (validation.error_code(), validation.error_message()) {
        tracing::warn!("Rejected registration: {}", code);
        return Err(json_error(StatusCode::BAD_REQUEST, code, message));
    }

    // Extract AAGUID from the attestation object
    let aaguid = extract_aaguid_from_attestation(attestation_object);

    // Determine device name from AAGUID if known
    let device_name = aaguid
        .as_deref()
        .and_then(vouch_common::lookup_device_model)
        .unwrap_or("Security Key")
        .to_string();

    Ok(ValidatedAttestation {
        aaguid,
        device_name,
    })
}
