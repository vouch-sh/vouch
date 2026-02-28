// SPDX-License-Identifier: BUSL-1.1
//! SCIM 2.0 API handlers (RFC 7643/7644).
//!
//! Implements user provisioning for enterprise identity providers.
//!
//! # Module Organization
//!
//! - [`types`] - SCIM types (error, list, user, group)
//! - [`discovery`] - Discovery endpoints (ServiceProviderConfig, Schemas, ResourceTypes)
//! - [`users`] - User CRUD operations
//! - [`groups`] - Group CRUD operations

pub mod discovery;
pub mod groups;
pub mod types;
pub mod users;

use aws_lc_rs::digest::{self, SHA256};
use axum::{
    Json,
    http::{HeaderMap, StatusCode},
};

use crate::AppState;
use crate::db;
use crate::db::{ScimScope, ScimScopeSet};

// Re-export types for convenience (used by tests via `use super::*`)
pub use types::*;

// Re-export handlers
pub use discovery::{resource_types, schemas, service_provider_config};
pub use groups::{create_group, delete_group, get_group, list_groups, patch_group};
pub use users::{create_user, delete_user, get_user, list_users, patch_user};

// ============================================================================
// Input Validation
// ============================================================================

/// Maximum length for a SCIM resource ID path parameter.
/// IDs are UUIDs (36 chars), but allow some headroom for alternate formats.
const MAX_RESOURCE_ID_LEN: usize = 64;

/// Maximum length for SCIM filter query parameter.
const MAX_FILTER_LEN: usize = 1024;

/// Maximum value for `startIndex` pagination parameter.
const MAX_START_INDEX: usize = 1_000_000;

/// Validate a SCIM resource ID path parameter.
/// Returns a SCIM error if the ID is empty or too long.
fn validate_resource_id(id: &str) -> Result<(), (StatusCode, Json<ScimError>)> {
    if id.is_empty() || id.len() > MAX_RESOURCE_ID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ScimError::new(400, "Invalid resource ID")),
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

// ============================================================================
// Authentication
// ============================================================================

/// Authenticated SCIM token information.
pub struct ScimAuth {
    /// Token ID.
    pub token_id: String,
    /// Parsed scope set.
    pub scope: ScimScopeSet,
}

impl ScimAuth {
    /// Check if the token has the required scope.
    pub fn require_scope(&self, required: ScimScope) -> Result<(), (StatusCode, Json<ScimError>)> {
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
pub async fn authenticate_scim(
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

    // Case-insensitive check for "Bearer " prefix, extract token safely
    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
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

    Ok(ScimAuth {
        token_id: token_record.id,
        scope,
    })
}

#[cfg(test)]
mod tests;
