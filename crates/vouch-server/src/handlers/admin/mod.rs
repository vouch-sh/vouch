// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Organization admin handlers for SCIM token management, member management,
//! audit log viewing, and device posture policies.
//!
//! These APIs support both JWT Bearer authentication and cookie-based authentication
//! from regular FIDO2 sessions. Only organization admins can access these endpoints.

mod audit;
mod members;
mod policies;
mod scim_tokens;

pub use audit::*;
pub use members::*;
pub use policies::*;
pub use scim_tokens::*;

use crate::AppState;
use crate::db;
use crate::services::error::ServiceError;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use secrecy::SecretString;
use serde::Deserialize;

use super::session::extract_org_admin;

/// Maximum number of SCIM tokens per org (supports key rotation).
pub(crate) const MAX_SCIM_TOKENS: usize = 2;

/// Query parameters for paginated pages.
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub after: Option<String>,
}

/// Result of generating a SCIM token (plaintext + hash for storage).
pub(crate) struct GeneratedScimToken {
    /// Plaintext token to return to the caller (shown once).
    pub(crate) plaintext: SecretString,
    /// SHA-256 hex hash for storage in the database.
    pub(crate) hash: String,
}

/// Generate a random SCIM token and its hash for storage.
pub(crate) fn generate_scim_token() -> Result<GeneratedScimToken, ServiceError> {
    let mut token_bytes = [0u8; 32];
    aws_rand::fill(&mut token_bytes).map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "RNG failure",
        )
    })?;
    let plaintext = format!("vouch_scim_{}", URL_SAFE_NO_PAD.encode(token_bytes));
    let hash = hex::encode(digest::digest(&SHA256, plaintext.as_bytes()));
    Ok(GeneratedScimToken {
        plaintext: SecretString::from(plaintext),
        hash,
    })
}

/// Compute token expiration from a number of days.
///
/// `jiff::Timestamp` only supports time-based units, so we convert days to hours.
pub(crate) fn compute_token_expiry(days: i64) -> Result<Timestamp, ServiceError> {
    let hours = days.checked_mul(24).ok_or_else(|| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_expiration",
            "Expiration overflow",
        )
    })?;
    let duration = jiff::Span::new().hours(hours);
    jiff::Timestamp::now().checked_add(duration).map_err(|e| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_expiration",
            format!("Invalid expiration: {e}"),
        )
    })
}

/// Format a `jiff::Timestamp` as a date string for display.
pub(crate) fn format_timestamp(ts: &Timestamp) -> String {
    ts.strftime("%Y-%m-%d %H:%M UTC").to_string()
}

/// Helper: extract org admin from cookie, verify target is in same org.
pub(crate) async fn extract_admin_and_target(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    jar: &axum_extra::extract::cookie::CookieJar,
    method: &str,
    uri: &str,
    target_user_id: &str,
) -> Result<(db::User, db::User, String), ServiceError> {
    let (admin, org_id) = extract_org_admin(state, headers, jar, method, uri).await?;

    let target = db::get_user_by_id(&state.store, target_user_id)
        .await?
        .ok_or_else(|| ServiceError::api(StatusCode::NOT_FOUND, "not_found", "User not found"))?;

    // Verify target belongs to the same org
    if target.org_id.as_deref() != Some(org_id.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "User not found in organization",
        ));
    }

    Ok((admin, target, org_id))
}
