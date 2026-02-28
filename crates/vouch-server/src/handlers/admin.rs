// SPDX-License-Identifier: BUSL-1.1
//! Organization admin handlers for SCIM token management and auth events.
//!
//! These APIs support both JWT Bearer authentication and cookie-based authentication
//! from regular FIDO2 sessions. Only organization admins can access these endpoints.

use crate::AppState;
use crate::db;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use axum::extract::OriginalUri;
use axum::http::Method;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use serde::Deserialize;
use std::sync::Arc;
use vouch_common::ApiError;

use super::json_error;
use super::session::extract_resource_token;

// ============================================================================
// Org Admin Extraction
// ============================================================================

/// Extract and validate an org admin from Bearer token, DPoP token, or cookie.
///
/// Tries Authorization header first, then falls back to vouch_session cookie.
/// Returns the user and their org_id if they are an org admin.
async fn extract_org_admin(
    state: &AppState,
    headers: &HeaderMap,
    jar: &CookieJar,
    method: &str,
    uri: &str,
) -> Result<(db::User, String), (StatusCode, Json<ApiError>)> {
    let token = extract_resource_token(state, headers, jar, method, uri).await?;

    let user = db::get_user_by_id(&state.store, &token.sub)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::UNAUTHORIZED, "unauthorized", "User not found"))?;

    if !user.is_org_admin {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Organization admin access required",
        ));
    }

    let org_id = user.org_id.clone().ok_or_else(|| {
        json_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "User is not associated with an organization",
        )
    })?;

    Ok((user, org_id))
}

// ============================================================================
// SCIM Token Management API
// ============================================================================

/// Request to create a SCIM token.
#[derive(Debug, Deserialize)]
pub struct CreateScimTokenRequest {
    pub description: Option<String>,
    /// Token expiration in days (required, 1-365 days).
    pub expires_in_days: i64,
}

/// Response for created SCIM token.
#[derive(Debug, serde::Serialize)]
pub struct CreateScimTokenResponse {
    pub id: String,
    pub token: String,
    pub description: Option<String>,
    pub expires_at: Option<Timestamp>,
}

/// SCIM token info for listing.
#[derive(Debug, serde::Serialize)]
pub struct ScimTokenInfo {
    pub id: String,
    pub description: Option<String>,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub expires_at: Option<Timestamp>,
}

/// Response for listing SCIM tokens.
#[derive(Debug, serde::Serialize)]
pub struct ListScimTokensResponse {
    pub tokens: Vec<ScimTokenInfo>,
}

/// Create a new SCIM token.
/// POST /api/v1/org/scim-tokens
pub async fn create_scim_token(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<CreateScimTokenRequest>,
) -> Result<Json<CreateScimTokenResponse>, (StatusCode, Json<ApiError>)> {
    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    // Validate description length
    if let Some(ref desc) = req.description
        && desc.len() > 256
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Description must be 256 characters or less",
        ));
    }

    // Validate expiration (required, 1-365 days)
    if req.expires_in_days < 1 || req.expires_in_days > 365 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_expiration",
            "expires_in_days must be between 1 and 365",
        ));
    }

    // Generate a secure random token
    let mut token_bytes = [0u8; 32];
    aws_rand::fill(&mut token_bytes).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "RNG failure",
        )
    })?;
    let token = format!("vouch_scim_{}", URL_SAFE_NO_PAD.encode(token_bytes));

    // Hash the token for storage
    let token_hash = hex::encode(digest::digest(&SHA256, token.as_bytes()));

    // Calculate expiration
    let duration = jiff::Span::new().days(req.expires_in_days);
    let expires_at = jiff::Timestamp::now().checked_add(duration).ok();

    // Store the token
    let token_id = db::create_scim_token(
        &state.store,
        &token_hash,
        req.description.as_deref(),
        expires_at,
        Some(&org_id),
        None, // Default scope: full access
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    tracing::info!("Created SCIM token: {} for org: {}", token_id, org_id);

    Ok(Json(CreateScimTokenResponse {
        id: token_id,
        token,
        description: req.description,
        expires_at,
    }))
}

/// List SCIM tokens for the organization.
/// GET /api/v1/org/scim-tokens
pub async fn list_scim_tokens(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<ListScimTokensResponse>, (StatusCode, Json<ApiError>)> {
    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let tokens = db::list_scim_tokens(&state.store, Some(&org_id))
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    let tokens: Vec<ScimTokenInfo> = tokens
        .into_iter()
        .map(|t| ScimTokenInfo {
            id: t.id,
            description: t.description,
            created_at: t.created_at,
            last_used_at: t.last_used_at,
            expires_at: t.expires_at,
        })
        .collect();

    Ok(Json(ListScimTokensResponse { tokens }))
}

/// Delete a SCIM token.
/// DELETE /api/v1/org/scim-tokens/:id
pub async fn delete_scim_token(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(token_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    // Validate token_id is a UUID before any processing
    if uuid::Uuid::try_parse(&token_id).is_err() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid token ID format",
        ));
    }

    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let deleted = db::delete_scim_token(&state.store, &token_id, &org_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    if !deleted {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "SCIM token not found",
        ));
    }

    tracing::info!("Deleted SCIM token: {}", token_id);

    Ok(StatusCode::NO_CONTENT)
}
