// SPDX-License-Identifier: BUSL-1.1
//! Key management service for listing, renaming, and deleting registered security keys.
//!
//! This module contains the shared business logic for key management operations.
//! It is used by both the API key handlers (Bearer token auth) and the enrollment
//! key handlers (cookie-based auth).

use crate::db::{self, store::DocumentStore};
use crate::services::error::ServiceError;
use vouch_common::{KeyInfo, lookup_device_model};

/// Maximum session age (in seconds) for destructive key operations.
pub const KEY_DELETE_MAX_AGE_SECS: i64 = 60;

/// Require the given issued-at or auth timestamp to be within `max_age_secs` seconds.
///
/// Returns `ServiceError::StepUpRequired` if the timestamp is too old.
/// Used by delete key operations to enforce recency of authentication.
///
/// # Errors
///
/// Returns `ServiceError::StepUpRequired` when `issued_at` is older than `max_age_secs`.
pub fn require_fresh_timestamp(issued_at: i64, max_age_secs: i64) -> Result<(), ServiceError> {
    let now = jiff::Timestamp::now().as_second();
    let session_age = now.saturating_sub(issued_at);
    if session_age > max_age_secs {
        return Err(ServiceError::StepUpRequired {
            acr_values: None,
            max_age: Some(u64::try_from(max_age_secs).unwrap_or(60)),
        });
    }
    Ok(())
}

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
    store: &DocumentStore,
    user_id: &str,
    current_authenticator_id: Option<&str>,
) -> Result<Vec<KeyInfo>, ServiceError> {
    let authenticators = db::get_authenticators_for_user(store, user_id)
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
                created_at: a.created_at,
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
    store: &DocumentStore,
    user_id: &str,
    key_id: &str,
    new_name: &str,
) -> Result<String, ServiceError> {
    // Validate key_id is a UUID before DB lookup
    if uuid::Uuid::try_parse(key_id).is_err() {
        return Err(ServiceError::Validation(
            "Invalid key ID format".to_string(),
        ));
    }

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
    let authenticator = db::get_authenticator_by_id(store, key_id)
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
    db::update_authenticator_name(store, key_id, name)
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
    store: &DocumentStore,
    user_id: &str,
    key_id: &str,
) -> Result<(String, u64), ServiceError> {
    // Validate key_id is a UUID before DB lookup
    if uuid::Uuid::try_parse(key_id).is_err() {
        return Err(ServiceError::Validation(
            "Invalid key ID format".to_string(),
        ));
    }

    // Get the authenticator to verify ownership
    let authenticator = db::get_authenticator_by_id(store, key_id)
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
    let key_count = db::count_authenticators_for_user(store, user_id)
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
    let sessions_revoked = db::count_sessions_for_authenticator(store, key_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to count sessions for authenticator {key_id}: {e}");
            ServiceError::Internal("Failed to count sessions".to_string())
        })?;

    // Delete the authenticator (CASCADE will delete sessions)
    db::delete_authenticator(store, key_id).await.map_err(|e| {
        tracing::error!("Failed to delete authenticator {key_id}: {e}");
        ServiceError::Internal("Failed to delete key".to_string())
    })?;

    let sessions = u64::try_from(sessions_revoked).unwrap_or_default();
    tracing::info!("Deleted key {key_id} for user {user_id}, revoked {sessions} sessions");

    Ok((authenticator.name, sessions))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_iat(seconds_ago: i64) -> i64 {
        jiff::Timestamp::now().as_second() - seconds_ago
    }

    #[test]
    fn test_require_fresh_timestamp_passes_for_fresh() {
        let iat = make_iat(5); // 5 seconds old
        assert!(require_fresh_timestamp(iat, 60).is_ok());
    }

    #[test]
    fn test_require_fresh_timestamp_fails_for_stale() {
        let iat = make_iat(120); // 2 minutes old
        let err = require_fresh_timestamp(iat, 60).unwrap_err();
        assert!(
            matches!(
                err,
                ServiceError::StepUpRequired {
                    max_age: Some(60),
                    ..
                }
            ),
            "Expected StepUpRequired, got: {err:?}"
        );
    }

    #[test]
    fn test_require_fresh_timestamp_boundary_exactly_at_max_age() {
        let iat = make_iat(60); // Exactly 60 seconds old
        // Session age == max_age is NOT > max_age, so it should pass
        assert!(require_fresh_timestamp(iat, 60).is_ok());
    }

    #[test]
    fn test_require_fresh_timestamp_one_second_over() {
        let iat = make_iat(61); // 61 seconds old (1 second over)
        let err = require_fresh_timestamp(iat, 60).unwrap_err();
        assert!(
            matches!(err, ServiceError::StepUpRequired { .. }),
            "Expected StepUpRequired for timestamp 1 second over max_age"
        );
    }
}
