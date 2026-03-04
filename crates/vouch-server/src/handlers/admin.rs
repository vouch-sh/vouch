// SPDX-License-Identifier: BUSL-1.1
//! Organization admin handlers for SCIM token management and auth events.
//!
//! These APIs support both JWT Bearer authentication and cookie-based authentication
//! from regular FIDO2 sessions. Only organization admins can access these endpoints.

use crate::AppState;
use crate::db;
use crate::services::error::ServiceError;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use axum::extract::OriginalUri;
use axum::http::Method;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use serde::Deserialize;
use std::sync::Arc;

use super::session::extract_org_admin;
use super::{ValidPath, ValidUuid};

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
) -> Result<Json<CreateScimTokenResponse>, ServiceError> {
    // Pure validation first — no DB cost for malformed requests
    if let Some(ref desc) = req.description
        && desc.len() > 256
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Description must be 256 characters or less",
        ));
    }

    if req.expires_in_days < 1 || req.expires_in_days > 365 {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_expiration",
            "expires_in_days must be between 1 and 365",
        ));
    }

    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    // Generate a secure random token
    let mut token_bytes = [0u8; 32];
    aws_rand::fill(&mut token_bytes).map_err(|_| {
        ServiceError::api(
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
    .map_err(|e| ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()))?;

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
) -> Result<Json<ListScimTokensResponse>, ServiceError> {
    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let tokens = db::list_scim_tokens(&state.store, Some(&org_id))
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
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
    ValidPath(token_id): ValidPath<ValidUuid>,
) -> Result<StatusCode, ServiceError> {
    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let deleted = db::delete_scim_token(&state.store, &token_id, &org_id)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    if !deleted {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "SCIM token not found",
        ));
    }

    tracing::info!("Deleted SCIM token: {}", token_id);

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use axum::http::StatusCode;

    use crate::test_utils::*;

    // ValidPath<ValidUuid> is extracted before the handler body runs auth checks,
    // so a malformed UUID must produce 400 regardless of authentication state.

    #[tokio::test]
    async fn test_delete_scim_token_invalid_uuid_returns_400() {
        let (app, _state) = test_app().await;

        let (status, body) = http_delete(&app, "/api/v1/org/scim-tokens/not-a-uuid", &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    #[tokio::test]
    async fn test_delete_scim_token_invalid_uuid_error_is_json() {
        let (app, _state) = test_app().await;

        let (status, body) = http_delete(&app, "/api/v1/org/scim-tokens/not-a-uuid", &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        // ServiceError::api produces {"code": "...", "message": "..."}
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("error response must be valid JSON");
        assert!(
            json.get("code").is_some(),
            "JSON error must contain 'code' field; got: {json}"
        );
    }

    #[tokio::test]
    async fn test_delete_scim_token_valid_uuid_proceeds_to_auth_check() {
        // A valid UUID with no auth should fail with 401, not 400,
        // confirming UUID validation passed and auth ran.
        let (app, _state) = test_app().await;
        let valid_uuid = uuid::Uuid::now_v7();

        let (status, _body) =
            http_delete(&app, &format!("/api/v1/org/scim-tokens/{valid_uuid}"), &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // ================================================================
    // Validation-before-auth tests (Phase 1E defense-in-depth)
    // ================================================================

    #[tokio::test]
    async fn test_create_scim_token_expires_zero_returns_400_without_auth() {
        let (app, _state) = test_app().await;

        let (status, body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "test", "expires_in_days": 0}"#,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "expires_in_days=0 must return 400 (not 401) even without auth: {body}"
        );
    }

    #[tokio::test]
    async fn test_create_scim_token_expires_366_returns_400_without_auth() {
        let (app, _state) = test_app().await;

        let (status, body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "test", "expires_in_days": 366}"#,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "expires_in_days=366 must return 400 (not 401) even without auth: {body}"
        );
    }

    #[tokio::test]
    async fn test_create_scim_token_long_description_returns_400_without_auth() {
        let (app, _state) = test_app().await;

        let long_desc = "x".repeat(257);
        let body_json = format!(
            r#"{{"description": "{}", "expires_in_days": 30}}"#,
            long_desc
        );

        let (status, body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            &body_json,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Description >256 chars must return 400 (not 401) even without auth: {body}"
        );
    }
}
