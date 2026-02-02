// SPDX-License-Identifier: BUSL-1.1
//! Key management handlers for listing, renaming, and removing registered security keys.

use crate::AppState;
use crate::db;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::CookieJar;
use headers::authorization::{Authorization, Bearer};
use std::sync::Arc;
use vouch_common::{
    ApiError, DeleteKeyResponse, KeyInfo, ListKeysResponse, RenameKeyRequest, RenameKeyResponse,
    lookup_device_model,
};

use super::{extract_session, json_error};

/// List all registered keys for the authenticated user.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
) -> Result<Json<ListKeysResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header, &jar).await?;
    let claims = session.claims;

    // Get all authenticators for this user
    let authenticators = db::get_authenticators_for_user(&state.db, &claims.sub)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    // Convert to KeyInfo
    let keys: Vec<KeyInfo> = authenticators
        .into_iter()
        .map(|a| {
            let device_model = a
                .aaguid
                .as_deref()
                .and_then(lookup_device_model)
                .map(String::from);
            KeyInfo {
                id: a.id.clone(),
                name: a.name,
                created_at: a.created_at.to_jiff().to_string(),
                is_current_session: claims.authenticator_id.as_ref() == Some(&a.id),
                device_model,
                aaguid: a.aaguid,
            }
        })
        .collect();

    Ok(Json(ListKeysResponse { keys }))
}

/// Rename a registered key.
pub async fn rename_key(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header, &jar).await?;
    let claims = session.claims;

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

    // Verify the key belongs to the authenticated user
    if authenticator.user_id != claims.sub {
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
        claims.sub
    );

    Ok(Json(RenameKeyResponse {
        message: format!("Key renamed to '{}'", name),
    }))
}

/// Delete a registered key.
pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
) -> Result<Json<DeleteKeyResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header, &jar).await?;
    let claims = session.claims;

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

    // Verify the key belongs to the authenticated user
    if authenticator.user_id != claims.sub {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Key does not belong to this user",
        ));
    }

    // Check that this isn't the user's last key
    let key_count = db::count_authenticators_for_user(&state.db, &claims.sub)
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

    // Delete the authenticator (CASCADE will delete sessions)
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
        claims.sub,
        sessions_revoked
    );

    Ok(Json(DeleteKeyResponse {
        message: format!("Key '{}' has been deleted", authenticator.name),
        sessions_revoked: u64::try_from(sessions_revoked).unwrap_or(0),
    }))
}
