// SPDX-License-Identifier: BUSL-1.1
//! Key management handlers during enrollment (using cookie-based authentication).
//!
//! These endpoints allow users to manage their security keys during the enrollment flow,
//! before they have a session token. Authentication is via the enrollment session cookie.

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

use super::enroll::get_enrollment_session_from_cookie;
use super::json_error;

/// Data extracted from enrollment session.
#[derive(Debug)]
struct EnrollmentAuth {
    user_id: String,
    #[allow(dead_code)]
    email: String,
}

/// Validate enrollment session from cookie and extract user info.
async fn validate_enrollment_cookie(
    state: &AppState,
    jar: &CookieJar,
) -> Result<EnrollmentAuth, (StatusCode, Json<ApiError>)> {
    // Get enrollment session from cookie
    let session = get_enrollment_session_from_cookie(state, jar)
        .await
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "invalid_session",
                "Invalid or expired enrollment session",
            )
        })?;

    Ok(EnrollmentAuth {
        user_id: session.user_id,
        email: session.user_email,
    })
}

/// List all registered keys for the user (during enrollment).
/// GET /enroll/keys/api
/// Authentication is via cookie.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<ListKeysResponse>, (StatusCode, Json<ApiError>)> {
    let auth = validate_enrollment_cookie(&state, &jar).await?;

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

    // Convert to KeyInfo (no current session during enrollment)
    let keys: Vec<KeyInfo> = authenticators
        .into_iter()
        .map(|a| {
            let device_model = a
                .aaguid
                .as_deref()
                .and_then(lookup_device_model)
                .map(String::from);
            KeyInfo {
                id: a.id,
                name: a.name,
                created_at: a.created_at,
                is_current_session: false, // No session during enrollment
                device_model,
                aaguid: a.aaguid,
            }
        })
        .collect();

    Ok(Json(ListKeysResponse { keys }))
}

/// Rename a security key (during enrollment).
/// PATCH /enroll/keys/{id}
/// Authentication is via cookie.
pub async fn rename_key(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResponse>, (StatusCode, Json<ApiError>)> {
    let auth = validate_enrollment_cookie(&state, &jar).await?;

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
/// Authentication is via cookie.
pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
) -> Result<Json<DeleteKeyResponse>, (StatusCode, Json<ApiError>)> {
    let auth = validate_enrollment_cookie(&state, &jar).await?;

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
        "Deleted key {} for user {} during enrollment, revoked {} sessions",
        key_id,
        auth.user_id,
        sessions_revoked
    );

    Ok(Json(DeleteKeyResponse {
        message: format!("Key '{}' has been deleted", authenticator.name),
        sessions_revoked: u64::try_from(sessions_revoked).unwrap_or(0),
    }))
}
