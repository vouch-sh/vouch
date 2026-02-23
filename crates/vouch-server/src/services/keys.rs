// SPDX-License-Identifier: BUSL-1.1
//! Key management service for listing, renaming, and deleting registered security keys.
//!
//! This module contains the shared business logic for key management operations.
//! It is used by both the API key handlers (Bearer token auth) and the enrollment
//! key handlers (cookie-based auth).

use crate::db::{self, Pool};
use crate::services::error::ServiceError;
use vouch_common::{KeyInfo, lookup_device_model};

/// List all registered keys for a user.
///
/// Retrieves all authenticators associated with the given user and converts
/// them to `KeyInfo` structs. If `current_authenticator_id` is provided,
/// the corresponding key will be marked as the current session's key.
///
/// # Errors
///
/// Returns `ServiceError::Internal` if the database query fails.
pub async fn list_keys_for_user(
    db: &Pool,
    user_id: &str,
    current_authenticator_id: Option<&str>,
) -> Result<Vec<KeyInfo>, ServiceError> {
    let authenticators = db::get_authenticators_for_user(db, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get authenticators for user {user_id}: {e}");
            ServiceError::Internal("Failed to retrieve keys".to_string())
        })?;

    Ok(authenticators
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
                is_current_session: current_authenticator_id == Some(a.id.as_str()),
                device_model,
                aaguid: a.aaguid,
            }
        })
        .collect())
}

/// Rename a registered key.
///
/// Validates ownership and name constraints before updating the key name.
///
/// # Errors
///
/// Returns:
/// - `ServiceError::Validation` if the name is empty or too long.
/// - `ServiceError::NotFound` if the key does not exist.
/// - `ServiceError::Forbidden` if the key does not belong to the user.
/// - `ServiceError::Internal` on database errors.
pub async fn rename_key(
    db: &Pool,
    user_id: &str,
    key_id: &str,
    new_name: &str,
) -> Result<String, ServiceError> {
    // Validate name
    let name = new_name.trim();
    if name.is_empty() {
        return Err(ServiceError::Validation("Name cannot be empty".to_string()));
    }
    if name.len() > 100 {
        return Err(ServiceError::Validation(
            "Name must be 100 characters or less".to_string(),
        ));
    }

    // Get the authenticator to verify ownership
    let authenticator = db::get_authenticator_by_id(db, key_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get authenticator {key_id}: {e}");
            ServiceError::Internal("Failed to retrieve key".to_string())
        })?
        .ok_or(ServiceError::NotFound("Key"))?;

    // Verify the key belongs to the user
    if authenticator.user_id != user_id {
        return Err(ServiceError::http(
            axum::http::StatusCode::FORBIDDEN,
            "forbidden",
            "Key does not belong to this user",
        ));
    }

    // Update the name
    db::update_authenticator_name(db, key_id, name)
        .await
        .map_err(|e| {
            tracing::error!("Failed to rename authenticator {key_id}: {e}");
            ServiceError::Internal("Failed to rename key".to_string())
        })?;

    tracing::info!("Renamed key {key_id} to '{name}' for user {user_id}");

    Ok(format!("Key renamed to '{name}'"))
}

/// Delete a registered key.
///
/// Validates ownership, ensures it is not the last key, and deletes the key
/// along with any associated sessions (via CASCADE). Returns the deleted key
/// name and the number of revoked sessions.
///
/// # Errors
///
/// Returns:
/// - `ServiceError::NotFound` if the key does not exist.
/// - `ServiceError::Forbidden` if the key does not belong to the user.
/// - `ServiceError::Validation` if this is the user's last key.
/// - `ServiceError::Internal` on database errors.
pub async fn delete_key(
    db: &Pool,
    user_id: &str,
    key_id: &str,
) -> Result<(String, u64), ServiceError> {
    // Get the authenticator to verify ownership
    let authenticator = db::get_authenticator_by_id(db, key_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get authenticator {key_id}: {e}");
            ServiceError::Internal("Failed to retrieve key".to_string())
        })?
        .ok_or(ServiceError::NotFound("Key"))?;

    // Verify the key belongs to the user
    if authenticator.user_id != user_id {
        return Err(ServiceError::http(
            axum::http::StatusCode::FORBIDDEN,
            "forbidden",
            "Key does not belong to this user",
        ));
    }

    // Check that this isn't the user's last key
    let key_count = db::count_authenticators_for_user(db, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to count authenticators for user {user_id}: {e}");
            ServiceError::Internal("Failed to check key count".to_string())
        })?;

    if key_count <= 1 {
        return Err(ServiceError::http(
            axum::http::StatusCode::BAD_REQUEST,
            "last_key",
            "Cannot delete your last key. Register another key first.",
        ));
    }

    // Count sessions that will be revoked
    let sessions_revoked = db::count_sessions_for_authenticator(db, key_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to count sessions for authenticator {key_id}: {e}");
            ServiceError::Internal("Failed to count sessions".to_string())
        })?;

    // Delete the authenticator (CASCADE will delete sessions)
    db::delete_authenticator(db, key_id).await.map_err(|e| {
        tracing::error!("Failed to delete authenticator {key_id}: {e}");
        ServiceError::Internal("Failed to delete key".to_string())
    })?;

    let sessions = u64::try_from(sessions_revoked).unwrap_or(0);
    tracing::info!("Deleted key {key_id} for user {user_id}, revoked {sessions} sessions");

    Ok((authenticator.name, sessions))
}
