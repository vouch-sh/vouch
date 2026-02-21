// SPDX-License-Identifier: BUSL-1.1
//! Shared utilities for HTTP handlers.

use crate::AppState;
use crate::db::{self, SessionPurpose};
use aws_lc_rs::rand as aws_rand;
use axum::Json;
use axum::http::StatusCode;
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use headers::authorization::{Authorization, Bearer};
use jsonwebtoken::DecodingKey;
use time::Duration;
use vouch_common::{ApiError, extract_aaguid_from_attestation, validate_hardware_attestation};

use crate::crypto::jwt::JwtType;
use crate::services::auth::SessionClaims;

// ============================================================================
// Authentication Context for Templates
// ============================================================================

/// Authentication context for templates and handlers.
///
/// Provides a consistent way to pass auth state to templates and handlers.
/// This struct is used by the `header_auth` template macro.
pub struct AuthContext {
    /// Whether the user is authenticated.
    pub authenticated: bool,
    /// The user's ID if authenticated (for authorization checks).
    pub user_id: Option<String>,
    /// The user's email if authenticated.
    pub user_email: Option<String>,
    /// Whether the user belongs to an organization.
    /// Used to show/hide org-specific features like Applications.
    pub has_org: bool,
    /// Whether the user is an organization admin.
    /// Used to show/hide org admin features like connecting GitHub.
    pub is_org_admin: bool,
}

impl AuthContext {
    /// Create an unauthenticated auth context.
    #[must_use]
    pub fn unauthenticated() -> Self {
        Self {
            authenticated: false,
            user_id: None,
            user_email: None,
            has_org: false,
            is_org_admin: false,
        }
    }
}

/// Helper to extract auth context from cookie jar.
///
/// This is a convenience function for handlers that need to pass
/// auth state to templates. It looks up the user to determine org membership.
pub async fn get_auth_context(state: &AppState, jar: &CookieJar) -> AuthContext {
    let session = match extract_session_from_cookie(state, jar).await {
        Ok(s) => s,
        Err(_) => return AuthContext::unauthenticated(),
    };

    // Look up user to check org membership and admin status
    let (has_org, is_org_admin) = match db::get_user_by_id(&state.db, &session.claims.sub).await {
        Ok(Some(user)) => (user.org_id.is_some(), user.is_org_admin),
        _ => (false, false),
    };

    AuthContext {
        authenticated: true,
        user_id: Some(session.claims.sub),
        user_email: Some(session.claims.email),
        has_org,
        is_org_admin,
    }
}

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
#[must_use]
pub fn hash_token(token: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

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
#[must_use]
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
#[must_use]
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

/// Extract and validate session from Authorization header only.
///
/// This validates the JWT token and checks that a corresponding session
/// exists in the database. For APIs that should also accept cookies,
/// use `extract_session` instead.
///
/// # Errors
///
/// Returns an error response if:
/// - The Authorization header is missing or invalid
/// - The JWT token is invalid or expired
/// - No session exists in the database for this token
async fn extract_session_from_header(
    state: &AppState,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<ValidatedSession, (StatusCode, Json<ApiError>)> {
    // Get token from Authorization header
    let TypedHeader(Authorization(bearer)) = auth_header.ok_or_else(|| {
        json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Missing or invalid Authorization header",
        )
    })?;

    let token = bearer.token();

    // Validate JWT with iss/aud/typ checks (RFC 8725 §3.8, §3.9, §3.11)
    let config = state.config();
    let token_data = decode_session_jwt(token, config.jwt_secret_bytes(), &config.base_url)
        .map_err(|_| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Invalid or expired token",
            )
        })?;

    let claims = token_data.claims;

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

    // Gate management endpoints: only FIDO2 sessions are allowed
    if claims.purpose != SessionPurpose::Fido2Session {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "This endpoint requires a FIDO2 session token",
        ));
    }

    Ok(ValidatedSession { claims, token_hash })
}

// ============================================================================
// Cookie-based Session Extraction (for browser UI)
// ============================================================================

/// Extract and validate session from cookie (for browser UI).
///
/// This is similar to `extract_session` but reads from cookies instead of
/// the Authorization header. Used for browser-based pages like `/github/connect`.
///
/// # Errors
///
/// Returns an error response if no valid session cookie is present.
pub async fn extract_session_from_cookie(
    state: &AppState,
    jar: &CookieJar,
) -> Result<ValidatedSession, (StatusCode, Json<ApiError>)> {
    // Get session token from cookie
    let token = jar.get("vouch_session").map(|c| c.value()).ok_or_else(|| {
        json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "No session cookie",
        )
    })?;

    // Validate JWT with iss/aud/typ checks (RFC 8725 §3.8, §3.9, §3.11)
    let config = state.config();
    let token_data = decode_session_jwt(token, config.jwt_secret_bytes(), &config.base_url)
        .map_err(|_| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Invalid or expired session",
            )
        })?;

    let claims = token_data.claims;

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

    // Gate management endpoints: only FIDO2 sessions are allowed (defense-in-depth)
    if claims.purpose != SessionPurpose::Fido2Session {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "This endpoint requires a FIDO2 session token",
        ));
    }

    Ok(ValidatedSession { claims, token_hash })
}

/// Decode and validate a session JWT with iss/aud/typ checks.
///
/// RFC 8725 §3.8: Validates issuer.
/// RFC 8725 §3.9: Validates audience.
/// RFC 8725 §3.11: Validates typ header.
pub(crate) fn decode_session_jwt(
    token: &str,
    jwt_secret: &[u8],
    expected_issuer: &str,
) -> Result<jsonwebtoken::TokenData<SessionClaims>, jsonwebtoken::errors::Error> {
    let validation = crate::crypto::jwt::session_validation(expected_issuer);

    let token_data = jsonwebtoken::decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret),
        &validation,
    )?;

    // RFC 8725 §3.11: Validate typ header
    if token_data.header.typ.as_deref() != Some(JwtType::Session.as_header_str()) {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }

    Ok(token_data)
}

/// Extract and validate session from Bearer token or cookie.
///
/// Tries Authorization header first, then falls back to vouch_session cookie.
/// This allows API endpoints to be called via curl with either:
/// - `Authorization: Bearer <token>` header
/// - `-b ~/.vouch/cookie.txt` cookie file
pub async fn extract_session(
    state: &AppState,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: &CookieJar,
) -> Result<ValidatedSession, (StatusCode, Json<ApiError>)> {
    if auth_header.is_some() {
        extract_session_from_header(state, auth_header).await
    } else {
        extract_session_from_cookie(state, jar).await
    }
}

/// Create a session cookie.
///
/// Returns a Cookie configured with proper security attributes.
#[must_use]
pub fn create_session_cookie(token: &str, max_age_seconds: i64) -> Cookie<'static> {
    Cookie::build(("vouch_session", token.to_owned()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(max_age_seconds))
        .build()
}

/// Create a cookie that clears the session.
///
/// Returns a Cookie that expires the session cookie.
#[must_use]
pub fn clear_session_cookie() -> Cookie<'static> {
    Cookie::build(("vouch_session", ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::ZERO)
        .build()
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
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: &CookieJar,
) -> Result<(SessionClaims, String), (StatusCode, Json<ApiError>)> {
    let session = extract_session(state, auth_header, jar).await?;

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
