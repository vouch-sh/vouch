// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 API handlers (RFC 7643/7644).
//!
//! Implements user provisioning for enterprise identity providers.
//!
//! # Module Organization
//!
//! - [`types`] - SCIM types (error, list, user, group)
//! - [`discovery`] - Discovery endpoints (ServiceProviderConfig, Schemas, ResourceTypes)
//! - [`patch`] - Table-driven applier shared by User and Group PATCH
//! - [`users`] - User CRUD operations
//! - [`groups`] - Group CRUD operations

pub(crate) mod discovery;
pub(crate) mod groups;
pub(crate) mod patch;
pub(crate) mod types;
pub(crate) mod users;

use aws_lc_rs::digest::{self, SHA256};
use axum::{
    Json,
    http::{HeaderMap, StatusCode},
};

use crate::AppState;
use crate::db;
use crate::db::{ScimScope, ScimScopeSet};
use vouch_common::protocol;

// Re-export types for convenience (used by tests via `use super::*`)
pub(crate) use types::*;

// Re-export handlers
pub(crate) use discovery::{resource_types, schemas, service_provider_config};
pub(crate) use groups::{create_group, delete_group, get_group, list_groups, patch_group};
pub(crate) use users::{create_user, delete_user, get_user, list_users, patch_user};

// ============================================================================
// Input Validation
// ============================================================================

/// Maximum length for SCIM filter query parameter.
const MAX_FILTER_LEN: usize = 1024;

/// Maximum value for `startIndex` pagination parameter.
///
/// SCIM `startIndex` is 1-indexed, so 10,001 corresponds to offset
/// 10,000 — the maximum the document store accepts. Deeper pagination
/// is rejected up-front to avoid expensive OFFSET scans.
const MAX_START_INDEX: usize = 10_001;

/// Validate a SCIM resource ID path parameter.
/// All resource IDs are UUID v7; reject anything that doesn't parse.
fn validate_resource_id(id: &str) -> Result<(), (StatusCode, Json<ScimError>)> {
    if uuid::Uuid::try_parse(id).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ScimError::new(400, "Invalid resource ID format")),
        ));
    }
    Ok(())
}

/// Validate SCIM list query parameters.
/// Enforces length bounds on `filter` and range bounds on `startIndex`.
fn validate_list_params(
    filter: Option<&str>,
    start_index: usize,
) -> Result<(), (StatusCode, Json<ScimError>)> {
    if let Some(f) = filter
        && f.len() > MAX_FILTER_LEN
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ScimError::new(400, "Filter exceeds maximum length").with_type("invalidFilter")),
        ));
    }
    if start_index > MAX_START_INDEX {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ScimError::new(400, "startIndex exceeds maximum value")),
        ));
    }
    Ok(())
}

/// SCIM 400 response for a write the document store rejected because an
/// index value contained a NUL byte, or `None` for any other database
/// error so the call site keeps its own fallback mapping.
fn invalid_index_value_response(err: &anyhow::Error) -> Option<(StatusCode, Json<ScimError>)> {
    let invalid = err.downcast_ref::<db::InvalidIndexValue>()?;
    Some((
        StatusCode::BAD_REQUEST,
        Json(
            ScimError::new(
                400,
                format!("{} must not contain a NUL (0x00) character", invalid.field),
            )
            .with_type("invalidValue"),
        ),
    ))
}

// ============================================================================
// Authentication
// ============================================================================

/// Authenticated SCIM token information.
pub(crate) struct ScimAuth {
    /// Token ID.
    pub token_id: String,
    /// Organization the token is scoped to. Required; SCIM tokens
    /// without an `org_id` are rejected at authentication.
    pub org_id: String,
    /// Parsed scope set.
    pub scope: ScimScopeSet,
    /// The organization's primary email domain, if it still exists.
    /// Stamped into `email_domain` on SCIM audit writes so org-scoped
    /// audit reads (which filter by domain) can see them.
    pub org_domain: Option<String>,
}

impl ScimAuth {
    /// Check if the token has the required scope.
    pub(crate) fn require_scope(
        &self,
        required: ScimScope,
    ) -> Result<(), (StatusCode, Json<ScimError>)> {
        if self.scope.contains(required) {
            Ok(())
        } else {
            Err((
                StatusCode::FORBIDDEN,
                Json(ScimError::new(
                    403,
                    format!("Token lacks required scope: {}", required.as_str()),
                )),
            ))
        }
    }
}

/// Extract and validate SCIM bearer token (RFC 7644 Section 2).
///
/// SCIM endpoints require authentication via OAuth 2.0 Bearer Token
/// (RFC 6750). The token is validated against the SCIM token store.
/// Returns the token ID and scope for authorization checks.
pub(crate) async fn authenticate_scim(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<ScimAuth, (StatusCode, Json<ScimError>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ScimError::new(401, "Missing Authorization header")),
            )
        })?;

    let token = crate::http::strip_auth_scheme(auth_header, protocol::AUTH_SCHEME_BEARER)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ScimError::new(401, "Invalid Authorization header format")),
            )
        })?;
    let token_hash = hex::encode(digest::digest(&SHA256, token.as_bytes()));

    // Verify token exists and is valid
    let token_record = db::get_scim_token_by_hash(&state.store, &token_hash)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Database error")),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ScimError::new(401, "Invalid token")),
            )
        })?;

    // SCIM is multi-tenant; reject tokens that aren't bound to an org.
    let org_id = token_record.org_id.ok_or_else(|| {
        tracing::warn!(
            token_id = %token_record.id,
            "SCIM token has no org_id; rejecting"
        );
        (
            StatusCode::UNAUTHORIZED,
            Json(ScimError::new(401, "Invalid token")),
        )
    })?;

    // Update last_used_at
    if let Err(e) = db::update_scim_token_last_used(&state.store, &token_record.id).await {
        tracing::warn!("Failed to update SCIM token last_used_at: {e}");
    }

    let scope = ScimScopeSet::parse(&token_record.scope).ok_or_else(|| {
        tracing::error!(
            "Invalid SCIM token scope in database: {}",
            token_record.scope
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError::new(500, "Invalid token scope")),
        )
    })?;

    let org_domain = match db::get_organization_domain(&state.store, &org_id).await {
        Ok(domain) => domain,
        Err(e) => {
            // A transient DB error here must not fail authentication (the
            // token itself is valid) — but swallowing it silently would
            // reintroduce the NULL-`email_domain` bug this lookup exists
            // to fix, so it's worth a warning even though it's non-fatal.
            tracing::warn!(error = %e, org_id = %org_id, "failed to look up org domain for SCIM audit stamping");
            None
        }
    };

    Ok(ScimAuth {
        token_id: token_record.id,
        org_id,
        scope,
        org_domain,
    })
}

#[cfg(test)]
mod tests;
