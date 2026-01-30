// SPDX-License-Identifier: BUSL-1.1
//! Key management handlers during enrollment (using cookie-based authentication).
//!
//! These endpoints allow users to manage their security keys via browser UI.
//! Authentication is via the vouch_session cookie.

use crate::AppState;
use crate::db;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;
use vouch_common::{
    ApiError, DeleteKeyResponse, KeyInfo, ListKeysResponse, RenameKeyRequest, RenameKeyResponse,
    lookup_device_model,
};

use super::common::extract_session_from_cookie;
use super::json_error;

/// Data extracted from session.
#[derive(Debug)]
struct SessionAuth {
    user_id: String,
    #[allow(dead_code)]
    email: String,
    /// The authenticator ID from the current session (if available).
    #[allow(dead_code)]
    authenticator_id: Option<String>,
}

/// Validate session from cookie and extract user info.
async fn validate_session_cookie(
    state: &AppState,
    jar: &CookieJar,
) -> Result<SessionAuth, (StatusCode, Json<ApiError>)> {
    // Get session from vouch_session cookie
    let session = extract_session_from_cookie(state, jar).await.map_err(|_| {
        json_error(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "Invalid or expired session",
        )
    })?;

    Ok(SessionAuth {
        user_id: session.claims.sub,
        email: session.claims.email,
        authenticator_id: session.claims.authenticator_id,
    })
}

/// List all registered keys for the user (during enrollment).
/// GET /enroll/keys/api
/// Authentication is via vouch_session cookie.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<ListKeysResponse>, (StatusCode, Json<ApiError>)> {
    let auth = validate_session_cookie(&state, &jar).await?;

    // Get all authenticators for this user
    let authenticators = db::get_authenticators_for_user(&state.db, &auth.user_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    // Convert to KeyInfo, marking the current session's key
    let keys: Vec<KeyInfo> = authenticators
        .into_iter()
        .map(|a| {
            let device_model = a
                .aaguid
                .as_deref()
                .and_then(lookup_device_model)
                .map(String::from);
            let is_current = auth.authenticator_id.as_ref() == Some(&a.id);
            KeyInfo {
                id: a.id,
                name: a.name,
                created_at: a.created_at,
                is_current_session: is_current,
                device_model,
                aaguid: a.aaguid,
            }
        })
        .collect();

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
    let auth = validate_session_cookie(&state, &jar).await?;

    // Validate name
    let name = req.name.trim();
    if name.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "Name cannot be empty",
        ));
    }
    if name.len() > 100 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "Name must be 100 characters or less",
        ));
    }

    // Get the authenticator to verify ownership
    let authenticator = db::get_authenticator_by_id(&state.db, &key_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "not_found", "Key not found"))?;

    // Verify the key belongs to the user
    if authenticator.user_id != auth.user_id {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Key does not belong to this user",
        ));
    }

    // Update the name
    db::update_authenticator_name(&state.db, &key_id, name)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    tracing::info!(
        "Renamed key {} to '{}' for user {}",
        key_id,
        name,
        auth.user_id
    );

    Ok(Json(RenameKeyResponse {
        message: format!("Key renamed to '{}'", name),
    }))
}

/// Delete a security key (during enrollment).
/// DELETE /enroll/keys/{id}
/// Authentication is via vouch_session cookie.
pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
) -> Result<Json<DeleteKeyResponse>, (StatusCode, Json<ApiError>)> {
    let auth = validate_session_cookie(&state, &jar).await?;

    // Get the authenticator to verify ownership
    let authenticator = db::get_authenticator_by_id(&state.db, &key_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "not_found", "Key not found"))?;

    // Verify the key belongs to the user
    if authenticator.user_id != auth.user_id {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Key does not belong to this user",
        ));
    }

    // Check that this isn't the user's last key
    let key_count = db::count_authenticators_for_user(&state.db, &auth.user_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    if key_count <= 1 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "last_key",
            "Cannot delete your last key. Register another key first.",
        ));
    }

    // Count sessions that will be revoked
    let sessions_revoked = db::count_sessions_for_authenticator(&state.db, &key_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    // Delete the authenticator
    db::delete_authenticator(&state.db, &key_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    tracing::info!(
        "Deleted key {} for user {}, revoked {} sessions",
        key_id,
        auth.user_id,
        sessions_revoked
    );

    Ok(Json(DeleteKeyResponse {
        message: format!("Key '{}' has been deleted", authenticator.name),
        sessions_revoked: u64::try_from(sessions_revoked).unwrap_or(0),
    }))
}
