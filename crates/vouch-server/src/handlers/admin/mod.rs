// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Organization admin browser UI (member management, audit log viewing,
//! device posture policies, SCIM token management) plus the org-admin
//! helpers shared with the `/api/v1/org/*` JSON handlers in
//! [`crate::handlers::api::org`].
//!
//! The page handlers (`AdminPage`) read only the session cookie. The
//! form-post/action handlers accept the session cookie as well as a Bearer
//! or DPoP access token — see `api::org`'s module doc for exactly which
//! auth shapes each entry point covers. Only organization admins can reach
//! any of these endpoints.

mod audit;
mod domains;
pub(crate) mod flash;
mod members;
mod policies;
mod scim_tokens;
mod subdomain;

pub(crate) use audit::*;
pub(crate) use domains::*;
pub(crate) use members::*;
pub(crate) use policies::*;
pub(crate) use scim_tokens::*;
pub(crate) use subdomain::*;

use crate::AppState;
use crate::db;
use crate::db::{ScimScope, ScimScopeSet};
use crate::error::ServiceError;
use aws_lc_rs::digest::{self, SHA256};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use secrecy::SecretString;
use serde::Deserialize;

/// Query parameters for paginated pages.
#[derive(Debug, Deserialize)]
pub(crate) struct PaginationParams {
    pub(crate) after: Option<String>,
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
    let token_bytes = crate::crypto::generate_random_bytes(32).map_err(|_| {
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

/// Maximum length of a SCIM token description, in Unicode characters. Matches
/// the `maxlength` the admin form advertises, which the browser counts in
/// characters rather than UTF-8 bytes.
pub(crate) const MAX_SCIM_TOKEN_DESCRIPTION_CHARS: usize = 256;

/// The four SCIM provisioning scopes plus, if requested, `audit:read`.
/// Shared by the API and UI create handlers so the scope set granted to a
/// new token can't drift between the two entry points.
pub(crate) fn requested_scope(audit_read: bool) -> ScimScopeSet {
    let mut scopes = vec![
        ScimScope::UsersRead,
        ScimScope::UsersWrite,
        ScimScope::GroupsRead,
        ScimScope::GroupsWrite,
    ];
    if audit_read {
        scopes.push(ScimScope::AuditRead);
    }
    ScimScopeSet::from_scopes(scopes)
}

/// Whether a stored scope string grants `audit:read`. Malformed scope
/// strings (should not occur — always written by [`requested_scope`]) are
/// treated as not granting it, matching `ScimAuth`'s fail-closed behavior.
pub(crate) fn has_audit_read(scope: &str) -> bool {
    ScimScopeSet::parse(scope).is_some_and(|s| s.contains(ScimScope::AuditRead))
}

/// Helper: verify the target user belongs to the extracted admin's org.
pub(crate) async fn extract_admin_and_target(
    state: &AppState,
    admin: super::extractors::OrgAdmin,
    target_user_id: &str,
) -> Result<(db::User, db::User, String), ServiceError> {
    let super::extractors::OrgAdmin {
        user: admin,
        org_id,
    } = admin;

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

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use secrecy::ExposeSecret;

    #[test]
    fn test_generate_scim_token_has_prefix_and_hash() {
        let generated = super::generate_scim_token().unwrap();
        let plaintext = generated.plaintext.expose_secret();

        assert!(
            plaintext.starts_with("vouch_scim_"),
            "token must have vouch_scim_ prefix"
        );
        // 32 random bytes → 43 base64url chars + 11 char prefix
        assert!(plaintext.len() > 40, "token must be sufficiently long");
        // Hash should be 64-char hex (SHA-256)
        assert_eq!(generated.hash.len(), 64, "hash must be 64 hex chars");
        // Hash must match the plaintext
        let expected_hash = hex::encode(aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            plaintext.as_bytes(),
        ));
        assert_eq!(generated.hash, expected_hash, "hash must match plaintext");
    }

    #[test]
    fn test_generate_scim_token_unique() {
        let a = super::generate_scim_token().unwrap();
        let b = super::generate_scim_token().unwrap();
        assert_ne!(
            a.plaintext.expose_secret(),
            b.plaintext.expose_secret(),
            "tokens must be unique"
        );
    }

    #[test]
    fn test_compute_token_expiry_valid_days() {
        let expiry = super::compute_token_expiry(30).unwrap();
        let now = jiff::Timestamp::now();
        let diff_secs = expiry.duration_since(now).as_secs();
        let expected_secs = 30 * 24 * 3600;
        assert!(
            diff_secs >= expected_secs - 5 && diff_secs <= expected_secs + 5,
            "30 days should be ~{expected_secs}s, got {diff_secs}s"
        );
    }

    #[test]
    fn test_compute_token_expiry_one_day() {
        let expiry = super::compute_token_expiry(1).unwrap();
        let now = jiff::Timestamp::now();
        let diff_secs = expiry.duration_since(now).as_secs();
        let expected_secs = 24 * 3600;
        assert!(
            diff_secs >= expected_secs - 5 && diff_secs <= expected_secs + 5,
            "1 day should be ~{expected_secs}s, got {diff_secs}s"
        );
    }

    #[test]
    fn test_compute_token_expiry_365_days() {
        let expiry = super::compute_token_expiry(365).unwrap();
        let now = jiff::Timestamp::now();
        let diff_secs = expiry.duration_since(now).as_secs();
        let expected_secs: i64 = 365 * 24 * 3600;
        assert!(
            diff_secs >= expected_secs - 5 && diff_secs <= expected_secs + 5,
            "365 days should be ~{expected_secs}s, got {diff_secs}s"
        );
    }
}
