// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Key management service for listing, renaming, and deleting registered security keys.
//!
//! This module contains the shared business logic for key management operations.
//! It is used by both the API key handlers (Bearer token auth) and the enrollment
//! key handlers (cookie-based auth).

use crate::db::documents::authenticator::AuthenticatorDoc;
use crate::db::documents::session::SessionDoc;
use crate::db::documents::user::UserDoc;
use crate::db::{self, store::DocumentStore};
use crate::services::error::ServiceError;
use jiff::Timestamp;
use vouch_common::{KeyInfo, lookup_device_model};

/// Maximum session age (in seconds) for destructive key operations.
pub(crate) const KEY_DELETE_MAX_AGE_SECS: i64 = 60;

/// Outcome of a [`consume_registration_state`] call.
pub(crate) enum RegistrationStateConsumed {
    /// First use — returns the witness for the chokepoint.
    Won(db::ChallengeStateClaim),
    /// Already consumed (replay). The handler emits the audit event and
    /// HTTP error response.
    Replay,
}

/// Atomically consume a registration state JWT for single-use enforcement.
///
/// Returns [`RegistrationStateConsumed::Won`] with the witness on first use,
/// or [`RegistrationStateConsumed::Replay`] if already consumed. The caller
/// is responsible for constructing the appropriate error response and
/// emitting the audit event, since only the handler has access to the user
/// context and the audit store.
///
/// # Errors
///
/// Returns `ServiceError::Internal` if the persistence check itself fails.
pub(crate) async fn consume_registration_state(
    store: &DocumentStore,
    state_jwt: &str,
    exp_seconds: i64,
) -> Result<RegistrationStateConsumed, ServiceError> {
    let expires_at = Timestamp::from_second(exp_seconds).unwrap_or_else(|_| Timestamp::now());

    match db::try_consume_challenge_state(store, state_jwt, expires_at).await {
        Ok(claim) => Ok(RegistrationStateConsumed::Won(claim)),
        Err(db::ClaimError::AlreadyConsumed) => Ok(RegistrationStateConsumed::Replay),
        Err(e) => {
            tracing::error!("Failed to mark registration state used: {e}");
            Err(ServiceError::Internal(
                "Failed to mark registration state used".to_string(),
            ))
        }
    }
}

/// Require the given issued-at or auth timestamp to be within `max_age_secs` seconds.
///
/// Returns `ServiceError::StepUpRequired` if the timestamp is too old.
/// Used by delete key operations to enforce recency of authentication.
///
/// # Errors
///
/// Returns `ServiceError::StepUpRequired` when `issued_at` is older than `max_age_secs`.
pub(crate) fn require_fresh_timestamp(
    issued_at: i64,
    max_age_secs: i64,
) -> Result<(), ServiceError> {
    let now = jiff::Timestamp::now().as_second();
    let session_age = now.saturating_sub(issued_at);
    if session_age > max_age_secs {
        return Err(ServiceError::StepUpRequired {
            acr_values: Some(crate::services::auth::ACR_AAL3.to_string()),
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
pub(crate) async fn list_keys_for_user(
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
pub(crate) async fn rename_key(
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
    if name.chars().count() > 100 {
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
        return Err(ServiceError::api(
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
/// Each attempt runs inside a single transaction with a delete-then-check guard
/// and a `compare_and_update` version bump on the User doc, so two concurrent
/// deletes against the same user serialise on a write-write conflict.  The loser
/// is retried by `with_dsql_retry!` (up to `MAX_DSQL_RETRIES = 3` times, down from
/// the old hand-rolled loop's 5 attempts — accepted behaviour change under heavy
/// contention); once a sibling delete has committed, the retry re-evaluates the
/// last-key guard and returns 400 `last_key`, so exactly one of two concurrent
/// deletes succeeds.
///
/// # Errors
///
/// Returns:
/// - `ServiceError::NotFound` if the key (or user) does not exist.
/// - `ServiceError::Forbidden` if the key does not belong to the user.
/// - `ServiceError::Api(400 "last_key")` if this is the user's last key.
/// - `ServiceError::Api(409 "conflict")` if the retry budget is exhausted.
/// - `ServiceError::Internal` on database errors.
pub(crate) async fn delete_key(
    store: &DocumentStore,
    user_id: &str,
    key_id: &str,
) -> Result<(String, u64), ServiceError> {
    // Validate key_id is a UUID before opening a transaction.
    if uuid::Uuid::try_parse(key_id).is_err() {
        return Err(ServiceError::Validation(
            "Invalid key ID format".to_string(),
        ));
    }

    // Map a DB error from any tx operation into either an OccConflict (if it
    // signals contention with a concurrent writer — Postgres serialization
    // failure, Aurora DSQL OC000/OC001, SQLite BUSY/LOCKED) or a generic 500.
    // OccConflict is retried by with_dsql_retry!; the 500 path propagates.
    let map_db_err = |e: anyhow::Error, msg: &'static str| -> ServiceError {
        tracing::error!("{msg}: {e}");
        if crate::db::pool::is_retryable_db_error(&e) {
            ServiceError::OccConflict
        } else {
            ServiceError::Internal(msg.to_string())
        }
    };

    let result = crate::with_dsql_retry!(async {
        let mut tx = store
            .begin()
            .await
            .map_err(|e| map_db_err(e, "Failed to start transaction"))?;

        // Load the User doc with its version. The version is bumped at the end of
        // the transaction so that two concurrent deletes against the same user
        // serialise on a write-write conflict (needed for PostgreSQL READ COMMITTED;
        // SQLite and Aurora DSQL are already safe via writer serialisation and
        // SERIALIZABLE isolation respectively).
        let user_doc = tx
            .get::<UserDoc>(user_id)
            .await
            .map_err(|e| map_db_err(e, "Failed to load user"))?
            .ok_or(ServiceError::NotFound("User"))?;

        // Load the authenticator and verify ownership within the transaction.
        let auth_doc = tx
            .get::<AuthenticatorDoc>(key_id)
            .await
            .map_err(|e| map_db_err(e, "Failed to retrieve key"))?
            .ok_or(ServiceError::NotFound("Key"))?;

        if auth_doc.data.user_id != user_id {
            return Err(ServiceError::api(
                axum::http::StatusCode::FORBIDDEN,
                "forbidden",
                "Key does not belong to this user",
            ));
        }
        let key_name = auth_doc.data.name.clone();

        // Pre-flight "last key" guard — fast-paths the common single-request case
        // and preserves the 400 / "last_key" response semantics. The count
        // includes the key about to be deleted, so `<= 1` means "this is the only
        // key the user owns."
        let count_before = tx
            .count::<AuthenticatorDoc>("user_id", user_id)
            .await
            .map_err(|e| map_db_err(e, "Failed to check key count"))?;
        if count_before <= 1 {
            return Err(ServiceError::api(
                axum::http::StatusCode::BAD_REQUEST,
                "last_key",
                "Cannot delete your last key. Register another key first.",
            ));
        }

        // Count sessions to report in the response payload. Snapshot taken before
        // the cascade — represents the sessions that will be revoked.
        let sessions_revoked = tx
            .count::<SessionDoc>("authenticator_id", key_id)
            .await
            .map_err(|e| map_db_err(e, "Failed to count sessions"))?;

        // Cascade-delete the authenticator (device_auth refs, sessions, doc).
        db::delete_authenticator_in_tx(&mut tx, key_id)
            .await
            .map_err(|e| map_db_err(e, "Failed to delete key"))?;

        // Post-delete invariant. Under PostgreSQL READ COMMITTED both concurrent
        // transactions would still see count_after == 1 (each observes the other's
        // uncommitted key), so this guard only catches SQLite/DSQL races; the
        // version bump below is what serialises PostgreSQL.
        let count_after = tx
            .count::<AuthenticatorDoc>("user_id", user_id)
            .await
            .map_err(|e| map_db_err(e, "Failed to verify key count"))?;
        if count_after < 1 {
            return Err(ServiceError::api(
                axum::http::StatusCode::BAD_REQUEST,
                "last_key",
                "Cannot delete your last key. Register another key first.",
            ));
        }

        // Version-bump the User doc to serialise concurrent deletes on the user row.
        let ok = tx
            .compare_and_update::<UserDoc>(user_id, user_doc.version, &user_doc.data)
            .await
            .map_err(|e| map_db_err(e, "Failed to version-bump user doc"))?;
        if !ok {
            // OCC conflict — another writer beat us to the User doc.  Signal
            // with_dsql_retry! to re-run the entire block.
            return Err(ServiceError::OccConflict);
        }

        tx.commit()
            .await
            .map_err(|e| map_db_err(e, "Failed to commit key deletion"))?;

        let sessions = u64::try_from(sessions_revoked).unwrap_or_default();
        tracing::info!("Deleted key {key_id} for user {user_id}, revoked {sessions} sessions");

        Ok::<(String, u64), ServiceError>((key_name, sessions))
    });

    // `with_dsql_retry!` exhausts OccConflict after MAX_DSQL_RETRIES attempts.
    // If the final attempt also conflicts, surface as a 409 to the caller.
    result.map_err(|e| match e {
        ServiceError::OccConflict => ServiceError::api(
            axum::http::StatusCode::CONFLICT,
            "conflict",
            "Key deletion conflicted with a concurrent operation. Please retry.",
        ),
        other => other,
    })
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code: panic on assertion failure is acceptable"
)]
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
