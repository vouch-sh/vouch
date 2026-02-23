// SPDX-License-Identifier: BUSL-1.1
//! Key management handlers during enrollment (using cookie-based authentication).
//!
//! These endpoints allow users to manage their security keys via browser UI.
//! Authentication is via the vouch_session cookie.

use crate::AppState;
use crate::services::keys as key_svc;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;
use vouch_common::{
    ApiError, DeleteKeyResponse, ListKeysResponse, RenameKeyRequest, RenameKeyResponse,
};

use super::json_error;
use super::session::extract_session_from_cookie;

/// List all registered keys for the user (during enrollment).
/// GET /enroll/keys/api
/// Authentication is via vouch_session cookie.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<ListKeysResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session_from_cookie(&state, &jar)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "invalid_session",
                "Invalid or expired session",
            )
        })?;

    let keys = key_svc::list_keys_for_user(
        &state.db,
        &session.claims.sub,
        session.claims.authenticator_id.as_deref(),
    )
    .await
    .map_err(into_handler_error)?;

    Ok(Json(ListKeysResponse { keys }))
}

/// Rename a security key (during enrollment).
/// PATCH /enroll/keys/{id}
/// Authentication is via vouch_session cookie.
pub async fn rename_key(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session_from_cookie(&state, &jar)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "invalid_session",
                "Invalid or expired session",
            )
        })?;

    let message = key_svc::rename_key(&state.db, &session.claims.sub, &key_id, &req.name)
        .await
        .map_err(into_handler_error)?;

    Ok(Json(RenameKeyResponse { message }))
}

/// Delete a security key (during enrollment).
/// DELETE /enroll/keys/{id}
/// Authentication is via vouch_session cookie.
pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
) -> Result<Json<DeleteKeyResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session_from_cookie(&state, &jar)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "invalid_session",
                "Invalid or expired session",
            )
        })?;

    let (key_name, sessions_revoked) = key_svc::delete_key(&state.db, &session.claims.sub, &key_id)
        .await
        .map_err(into_handler_error)?;

    Ok(Json(DeleteKeyResponse {
        message: format!("Key '{}' has been deleted", key_name),
        sessions_revoked,
    }))
}

/// Convert a `ServiceError` into the handler error tuple format.
fn into_handler_error(err: crate::services::error::ServiceError) -> (StatusCode, Json<ApiError>) {
    use crate::services::error::ServiceError;

    let (status, code, message) = match &err {
        ServiceError::NotFound(entity) => (
            StatusCode::NOT_FOUND,
            "not_found",
            format!("{entity} not found"),
        ),
        ServiceError::Validation(msg) => (StatusCode::BAD_REQUEST, "invalid_request", msg.clone()),
        ServiceError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", (*msg).to_string()),
        ServiceError::Unauthorized(msg) => {
            (StatusCode::UNAUTHORIZED, "unauthorized", (*msg).to_string())
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Internal error".to_string(),
        ),
    };

    (status, Json(ApiError::new(code, &message)))
}
