//! Key management handlers during enrollment (using OIDC state authentication).
//!
//! These endpoints allow users to manage their security keys during the enrollment flow,
//! before they have a session token. Authentication is via the OIDC state token.

use crate::AppState;
use crate::db;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use std::sync::Arc;
use vouch_common::{
    ApiError, DeleteKeyResponse, KeyInfo, ListKeysResponse, RenameKeyRequest, RenameKeyResponse,
    lookup_device_model,
};

use super::json_error;

/// Query parameters containing the OIDC state token.
#[derive(Debug, Deserialize)]
pub struct StateQuery {
    pub state: String,
}

/// Data extracted from enrollment state.
#[derive(Debug)]
struct EnrollmentAuth {
    user_id: String,
    #[allow(dead_code)]
    email: String,
}

/// Enrollment data embedded in OIDC state nonce field.
#[derive(Debug, Deserialize)]
struct EnrollmentData {
    email: String,
    #[allow(dead_code)]
    hd: Option<String>,
}

/// Validate OIDC state and extract user info.
async fn validate_enrollment_state(
    state: &AppState,
    oidc_state: &str,
) -> Result<EnrollmentAuth, (StatusCode, Json<ApiError>)> {
    // Look up the OIDC state
    let stored_state = db::get_oidc_state(&state.db, oidc_state)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "invalid_state",
                "Invalid or expired state token",
            )
        })?;

    // Check if expired
    let now = jiff::Timestamp::now();
    let expires_at: jiff::Timestamp = stored_state.expires_at.parse().map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Invalid timestamp",
        )
    })?;

    if now > expires_at {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "expired_state",
            "State has expired",
        ));
    }

    // Extract email from enrollment data stored in nonce
    let email = if stored_state.nonce.is_empty() {
        "user@localhost".to_string()
    } else {
        match serde_json::from_str::<EnrollmentData>(&stored_state.nonce) {
            Ok(data) => data.email,
            Err(_) => stored_state.nonce.clone(),
        }
    };

    // Look up user by email
    let user = db::get_user_by_email(&state.db, &email)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "user_not_found", "User not found"))?;

    Ok(EnrollmentAuth {
        user_id: user.id,
        email,
    })
}

/// List all registered keys for the user (during enrollment).
/// GET /enroll/keys?state=<oidc_state>
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StateQuery>,
) -> Result<Json<ListKeysResponse>, (StatusCode, Json<ApiError>)> {
    let auth = validate_enrollment_state(&state, &query.state).await?;

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
/// PATCH /enroll/keys/{id}?state=<oidc_state>
pub async fn rename_key(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<String>,
    Query(query): Query<StateQuery>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResponse>, (StatusCode, Json<ApiError>)> {
    let auth = validate_enrollment_state(&state, &query.state).await?;

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
/// DELETE /enroll/keys/{id}?state=<oidc_state>
pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<String>,
    Query(query): Query<StateQuery>,
) -> Result<Json<DeleteKeyResponse>, (StatusCode, Json<ApiError>)> {
    let auth = validate_enrollment_state(&state, &query.state).await?;

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
