// SPDX-License-Identifier: BUSL-1.1
//! Organization admin handlers for SCIM token management and auth events.
//!
//! These APIs support both JWT Bearer authentication and cookie-based authentication
//! from regular FIDO2 sessions. Only organization admins can access these endpoints.

use crate::AppState;
use crate::db;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use headers::authorization::{Authorization, Bearer};
use serde::Deserialize;
use std::sync::Arc;
use vouch_common::{ApiError, AuthEventInfo, ListAuthEventsResponse};

use super::common::{extract_session, extract_session_from_cookie};
use super::json_error;

// ============================================================================
// Org Admin Extraction
// ============================================================================

/// Extract and validate an org admin from Bearer token or cookie.
///
/// Tries Authorization header first, then falls back to vouch_session cookie.
/// Returns the user and their org_id if they are an org admin.
async fn extract_org_admin(
    state: &AppState,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: &CookieJar,
) -> Result<(db::User, String), (StatusCode, Json<ApiError>)> {
    // Try Bearer token first, then fall back to cookie
    let session = if auth_header.is_some() {
        extract_session(state, auth_header).await?
    } else {
        extract_session_from_cookie(state, jar).await?
    };

    let user = db::get_user_by_id(&state.db, &session.claims.sub)
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
// Auth Events API
// ============================================================================

/// Query params for auth events API.
#[derive(Debug, Deserialize)]
pub struct AuthEventsQuery {
    /// Filter by user ID.
    user_id: Option<String>,
    /// Filter by event type (login_success, login_failed, enrollment, logout).
    event_type: Option<String>,
    /// Filter by client IP.
    client_ip: Option<String>,
    /// Filter by events since this ISO 8601 timestamp.
    since: Option<String>,
    /// Maximum number of events to return (default 100).
    limit: Option<i64>,
}

/// List authentication events for the organization.
/// GET /api/v1/org/auth-events
pub async fn list_auth_events(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Query(query): Query<AuthEventsQuery>,
) -> Result<Json<ListAuthEventsResponse>, (StatusCode, Json<ApiError>)> {
    let (_user, _org_id) = extract_org_admin(&state, auth_header, &jar).await?;

    // Build query params
    let db_query = db::AuthEventQuery {
        user_id: query.user_id.clone(),
        event_type: query.event_type.clone(),
        client_ip: query.client_ip.clone(),
        since: query.since.clone(),
        limit: query.limit,
    };

    // Fetch events
    let events = db::get_auth_events(&state.db, &db_query)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    // Get user emails for the events (for display)
    let mut user_emails: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for event in &events {
        if !user_emails.contains_key(&event.user_id)
            && let Ok(Some(user)) = db::get_user_by_id(&state.db, &event.user_id).await
        {
            user_emails.insert(event.user_id.clone(), user.email);
        }
    }

    // Convert to API response type
    let events: Vec<AuthEventInfo> = events
        .into_iter()
        .map(|e| AuthEventInfo {
            id: e.id,
            user_id: e.user_id.clone(),
            user_email: user_emails.get(&e.user_id).cloned(),
            event_type: e.event_type,
            authenticator_id: e.authenticator_id,
            client_ip: e.client_ip,
            user_agent: e.user_agent,
            client_hostname: e.client_hostname,
            client_os: e.client_os,
            client_arch: e.client_arch,
            client_version: e.client_version,
            success: e.success != 0,
            failure_reason: e.failure_reason,
            created_at: e.created_at,
        })
        .collect();

    Ok(Json(ListAuthEventsResponse { events }))
}

// ============================================================================
// SCIM Token Management API
// ============================================================================

/// Request to create a SCIM token.
#[derive(Debug, Deserialize)]
pub struct CreateScimTokenRequest {
    pub description: Option<String>,
    /// Token expiration in days (optional, None = never expires).
    pub expires_in_days: Option<i64>,
}

/// Response for created SCIM token.
#[derive(Debug, serde::Serialize)]
pub struct CreateScimTokenResponse {
    pub id: String,
    pub token: String,
    pub description: Option<String>,
    pub expires_at: Option<String>,
}

/// SCIM token info for listing.
#[derive(Debug, serde::Serialize)]
pub struct ScimTokenInfo {
    pub id: String,
    pub description: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
}

/// Response for listing SCIM tokens.
#[derive(Debug, serde::Serialize)]
pub struct ListScimTokensResponse {
    pub tokens: Vec<ScimTokenInfo>,
}

/// Create a new SCIM token.
/// POST /api/v1/org/scim-tokens
pub async fn create_scim_token(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Json(req): Json<CreateScimTokenRequest>,
) -> Result<Json<CreateScimTokenResponse>, (StatusCode, Json<ApiError>)> {
    let (_user, org_id) = extract_org_admin(&state, auth_header, &jar).await?;

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

    // Calculate expiration if specified
    let expires_at = req.expires_in_days.map(|days| {
        let duration = jiff::Span::new().days(days);
        jiff::Timestamp::now()
            .checked_add(duration)
            .map(|t| t.to_string())
            .unwrap_or_default()
    });

    // Store the token
    let token_id = db::create_scim_token(
        &state.db,
        &token_hash,
        req.description.as_deref(),
        expires_at.as_deref(),
        Some(&org_id),
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
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
) -> Result<Json<ListScimTokensResponse>, (StatusCode, Json<ApiError>)> {
    let (_user, org_id) = extract_org_admin(&state, auth_header, &jar).await?;

    let tokens = db::list_scim_tokens(&state.db, Some(&org_id))
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
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Path(token_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let (_user, _org_id) = extract_org_admin(&state, auth_header, &jar).await?;

    db::delete_scim_token(&state.db, &token_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    tracing::info!("Deleted SCIM token: {}", token_id);

    Ok(StatusCode::NO_CONTENT)
}
