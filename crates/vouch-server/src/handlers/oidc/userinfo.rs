// SPDX-License-Identifier: BUSL-1.1
//! UserInfo endpoint handler.

use crate::AppState;
use crate::services::oidc::token::validate_session_token;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
};
use serde::Serialize;
use std::sync::Arc;
use vouch_common::ApiError;

/// User info response.
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    sub: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
    hardware_verified: bool,
    hardware_aaguid: Option<String>,
}

/// GET /oauth/userinfo
///
/// Returns information about the authenticated user.
pub async fn userinfo(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<UserInfoResponse>, (StatusCode, Json<ApiError>)> {
    // Get token from Authorization header
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new(
                    "invalid_token",
                    "Missing or invalid bearer token",
                )),
            )
        })?;

    // Validate the session token
    let (user, _session, authenticator) = validate_session_token(&state, token)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("server_error", e.to_string())),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new("invalid_token", "Invalid or expired token")),
            )
        })?;

    Ok(Json(UserInfoResponse {
        sub: user.email.clone(),
        email: user.email,
        email_verified: true,
        name: user.name,
        hardware_verified: true,
        hardware_aaguid: authenticator.aaguid,
    }))
}
