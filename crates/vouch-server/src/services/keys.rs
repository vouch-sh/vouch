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
use crate::error::ServiceError;
use crate::infra::i18n::Tr;
use vouch_common::{KeyInfo, ResourceLabel, lookup_device_model};

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
/// `request` is the caller's checked request wrapper, which is what makes
/// spending the state token impossible before the body has been validated —
/// see [`db::ChallengeState`].
///
/// # Errors
///
/// Returns `ServiceError::Internal` if the persistence check itself fails.
pub(crate) async fn consume_registration_state(
    store: &DocumentStore,
    request: &impl db::ChallengeState,
) -> Result<RegistrationStateConsumed, ServiceError> {
    match db::try_consume_challenge_state(store, request).await {
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

/// Require proof that the caller exercised their security key, and did so
/// recently, before a destructive key operation.
///
/// The two halves are separate claims and both are load-bearing:
///
/// * `hardware_verified` — whether a FIDO2 assertion backs this session at
///   all. An enrollment bootstrap session, minted from an upstream IdP
///   sign-in with no ceremony, is `false`.
/// * `auth_time` — *when* that assertion happened. Sessions last hours;
///   deleting a key is a step-up action that wants a ceremony from seconds
///   ago.
///
/// Asking only about recency reads a timestamp as evidence a ceremony
/// occurred. That inference is sound today only because
/// `HardwareVerification` no longer lets an unverified token carry an
/// `auth_time` — it is one refactor away from being wrong again, and it was
/// wrong in issue #1114. Ask the question directly instead.
///
/// Enforced by the `SteppedUpToken` extractor, which is what makes a handler
/// unable to skip it; this function is the rule that extractor applies.
///
/// # Errors
///
/// Returns `ServiceError::StepUpRequired` when the session is not
/// hardware-verified, or when its FIDO2 assertion is older than
/// [`KEY_DELETE_MAX_AGE_SECS`].
pub(crate) fn require_recent_hardware_verification(
    token: &crate::services::auth::ValidatedResourceToken,
) -> Result<(), ServiceError> {
    if !token.hardware_verified {
        tracing::warn!(
            target: "security",
            user_id = %token.sub,
            "refusing a destructive key operation on a session that never \
             exercised the security key"
        );
        return Err(ServiceError::StepUpRequired {
            acr_values: Some(crate::services::auth::ACR_AAL3.to_string()),
            max_age: Some(u64::try_from(KEY_DELETE_MAX_AGE_SECS).unwrap_or(60)),
        });
    }

    // A hardware-verified session always records when. Epoch is the
    // fail-closed reading for a token that somehow lacks it.
    require_fresh_timestamp(token.auth_time.unwrap_or(0), KEY_DELETE_MAX_AGE_SECS)
}

/// Require the given issued-at or auth timestamp to be within `max_age_secs`
/// seconds of the server's current wall clock and not in the future.
///
/// A step-up ceremony dated after now is impossible, so no clock skew is
/// tolerated: both a too-old and a future-dated timestamp fail closed (issue
/// #1144). The bounds check is the [`crate::services::RecencyWindow`] shared
/// with the DPoP proof-age gate.
///
/// # Errors
///
/// Returns `ServiceError::StepUpRequired` when `issued_at` is older than
/// `max_age_secs` or is later than now (a future-dated timestamp).
pub(crate) fn require_fresh_timestamp(
    issued_at: i64,
    max_age_secs: i64,
) -> Result<(), ServiceError> {
    if crate::services::RecencyWindow::no_skew(max_age_secs).accepts(issued_at) {
        return Ok(());
    }
    Err(ServiceError::StepUpRequired {
        acr_values: Some(crate::services::auth::ACR_AAL3.to_string()),
        max_age: Some(u64::try_from(max_age_secs).unwrap_or(60)),
    })
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
/// The new name arrives already validated as a [`ResourceLabel`] (trimmed,
/// non-empty, within the length limit), so this function only checks the key id
/// and ownership before updating.
///
/// # Errors
///
/// Returns:
/// - `ServiceError::Validation` if `key_id` is not a valid UUID.
/// - `ServiceError::NotFound` if the key does not exist *or* belongs to another
///   user. The two are deliberately indistinguishable: a 403 for someone else's
///   key would let any authenticated caller probe whether a given key id exists.
/// - `ServiceError::Internal` on database errors.
pub(crate) async fn rename_key(
    store: &DocumentStore,
    user_id: &str,
    key_id: &str,
    new_name: &ResourceLabel,
) -> Result<String, ServiceError> {
    // Validate key_id is a UUID before DB lookup
    if uuid::Uuid::try_parse(key_id).is_err() {
        return Err(ServiceError::Validation(
            Tr::new("keys-error-invalid-id").to_string(),
        ));
    }

    // The name is already trimmed and length-checked: `ResourceLabel` has no
    // other constructor, so both callers had to validate before reaching here.
    let name = new_name.as_str();

    // Get the authenticator to verify ownership
    let authenticator = db::get_authenticator_by_id(store, key_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get authenticator {key_id}: {e}");
            ServiceError::Internal("Failed to retrieve key".to_string())
        })?
        .ok_or(ServiceError::NotFound("Key"))?;

    // Verify the key belongs to the user. Another user's key is reported as
    // "not found", identically to a key id that does not exist — the caller is
    // authenticated but has no business learning which key ids are real.
    if authenticator.user_id != user_id {
        tracing::debug!("Rename refused: key {key_id} does not belong to user {user_id}");
        return Err(ServiceError::NotFound("Key"));
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
/// - `ServiceError::NotFound` if the key (or user) does not exist, or if the key
///   belongs to another user. The last two are deliberately indistinguishable:
///   a 403 for someone else's key would let any authenticated caller probe
///   whether a given key id exists.
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
            Tr::new("keys-error-invalid-id").to_string(),
        ));
    }

    let result = crate::with_dsql_retry!(async {
        let mut tx = store
            .begin()
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to start transaction"))?;

        // Load the User doc with its version. The version is bumped at the end of
        // the transaction so that two concurrent deletes against the same user
        // serialise on a write-write conflict (needed for PostgreSQL READ COMMITTED;
        // SQLite and Aurora DSQL are already safe via writer serialisation and
        // SERIALIZABLE isolation respectively).
        let user_doc = tx
            .get::<UserDoc>(user_id)
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to load user"))?
            .ok_or(ServiceError::NotFound("User"))?;

        // Load the authenticator and verify ownership within the transaction.
        let auth_doc = tx
            .get::<AuthenticatorDoc>(key_id)
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to retrieve key"))?
            .ok_or(ServiceError::NotFound("Key"))?;

        // Another user's key is reported as "not found", identically to a key
        // id that does not exist — the caller is authenticated but has no
        // business learning which key ids are real.
        if auth_doc.data.user_id != user_id {
            tracing::debug!("Delete refused: key {key_id} does not belong to user {user_id}");
            return Err(ServiceError::NotFound("Key"));
        }
        let key_name = auth_doc.data.name.clone();

        // Pre-flight "last key" guard — fast-paths the common single-request case
        // and preserves the 400 / "last_key" response semantics. The count
        // includes the key about to be deleted, so `<= 1` means "this is the only
        // key the user owns."
        let count_before = tx
            .count::<AuthenticatorDoc>("user_id", user_id)
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to check key count"))?;
        if count_before <= 1 {
            return Err(ServiceError::api(
                axum::http::StatusCode::BAD_REQUEST,
                "last_key",
                Tr::new("keys-error-last-key").to_string(),
            ));
        }

        // Count sessions to report in the response payload. Snapshot taken before
        // the cascade — represents the sessions that will be revoked.
        let sessions_revoked = tx
            .count::<SessionDoc>("authenticator_id", key_id)
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to count sessions"))?;

        // Cascade-delete the authenticator (device_auth refs, sessions, doc).
        db::delete_authenticator(&mut tx, key_id)
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to delete key"))?;

        // Post-delete invariant. Under PostgreSQL READ COMMITTED both concurrent
        // transactions would still see count_after == 1 (each observes the other's
        // uncommitted key), so this guard only catches SQLite/DSQL races; the
        // version bump below is what serialises PostgreSQL.
        let count_after = tx
            .count::<AuthenticatorDoc>("user_id", user_id)
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to verify key count"))?;
        if count_after < 1 {
            return Err(ServiceError::api(
                axum::http::StatusCode::BAD_REQUEST,
                "last_key",
                Tr::new("keys-error-last-key").to_string(),
            ));
        }

        // Version-bump the User doc to serialise concurrent deletes on the user row.
        let ok = tx
            .compare_and_update::<UserDoc>(user_id, user_doc.version, &user_doc.data)
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to version-bump user doc"))?;
        if !ok {
            // OCC conflict — another writer beat us to the User doc.  Signal
            // with_dsql_retry! to re-run the entire block.
            return Err(ServiceError::OccConflict);
        }

        tx.commit()
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to commit key deletion"))?;

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
            Tr::new("keys-error-delete-conflict").to_string(),
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

    /// A key belonging to another user and a key id that does not exist must
    /// produce the same error. Distinguishing them turns `/v1/keys/{id}` into
    /// an oracle telling any authenticated caller which key ids are real.
    #[tokio::test]
    async fn rename_reports_another_users_key_as_not_found() {
        let state = crate::test_utils::test_app_state().await;
        let owner =
            crate::test_utils::create_test_user(&state.store, "rename-owner@example.com").await;
        let caller =
            crate::test_utils::create_test_user(&state.store, "rename-caller@example.com").await;
        let owned_key = crate::test_utils::create_test_authenticator(&state.store, &owner.id).await;
        let absent_key = uuid::Uuid::now_v7().to_string();

        let foreign = rename_key(
            &state.store,
            &caller.id,
            &owned_key,
            &ResourceLabel::parse("renamed").unwrap(),
        )
        .await
        .unwrap_err();
        let missing = rename_key(
            &state.store,
            &caller.id,
            &absent_key,
            &ResourceLabel::parse("renamed").unwrap(),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(foreign, ServiceError::NotFound("Key")),
            "another user's key must be reported as not found, got: {foreign:?}"
        );
        assert!(
            matches!(missing, ServiceError::NotFound("Key")),
            "a nonexistent key must be reported as not found, got: {missing:?}"
        );
    }

    /// Same uniformity requirement on the delete path. The ownership check runs
    /// before the last-key guard, so a foreign key never reaches the 400
    /// `last_key` branch that would itself be a distinguisher.
    #[tokio::test]
    async fn delete_reports_another_users_key_as_not_found() {
        let state = crate::test_utils::test_app_state().await;
        let owner =
            crate::test_utils::create_test_user(&state.store, "delete-owner@example.com").await;
        let caller =
            crate::test_utils::create_test_user(&state.store, "delete-caller@example.com").await;
        let owned_key = crate::test_utils::create_test_authenticator(&state.store, &owner.id).await;
        let absent_key = uuid::Uuid::now_v7().to_string();

        let foreign = delete_key(&state.store, &caller.id, &owned_key)
            .await
            .unwrap_err();
        let missing = delete_key(&state.store, &caller.id, &absent_key)
            .await
            .unwrap_err();

        assert!(
            matches!(foreign, ServiceError::NotFound("Key")),
            "another user's key must be reported as not found, got: {foreign:?}"
        );
        assert!(
            matches!(missing, ServiceError::NotFound("Key")),
            "a nonexistent key must be reported as not found, got: {missing:?}"
        );

        // The victim's key must still exist — a refused delete must not delete.
        assert!(
            crate::db::get_authenticator_by_id(&state.store, &owned_key)
                .await
                .unwrap()
                .is_some(),
            "a refused cross-user delete must leave the key in place"
        );
    }

    /// Epoch (0) is the value `delete_key` feeds to the freshness gate when
    /// `auth_time` is absent — i.e. an enrollment bootstrap session that
    /// never performed FIDO2 (`auth_time.unwrap_or(0)`). It must fail closed
    /// so the gate demands a step-up instead of treating a no-FIDO2 session
    /// as freshly authenticated.
    #[test]
    fn test_require_fresh_timestamp_epoch_is_rejected() {
        let err = require_fresh_timestamp(0, KEY_DELETE_MAX_AGE_SECS).unwrap_err();
        assert!(
            matches!(
                err,
                ServiceError::StepUpRequired {
                    max_age: Some(60),
                    ..
                }
            ),
            "Expected StepUpRequired for epoch (auth_time absent), got: {err:?}"
        );
    }

    /// Mirror of the epoch test for the other impossible-timestamp direction:
    /// a future-dated `auth_time` (e.g. when the server wall clock has
    /// regressed past the token's `auth_time`). `i64::saturating_sub` returns
    /// the negative signed difference (not `0` — it only saturates at
    /// `i64::MIN`/`MAX`), so without a lower bound the `session_age >
    /// max_age_secs` check would admit `-N` as "age 0" fresh and let an
    /// impossibly-timed ceremony satisfy the step-up gate. A freshness gate
    /// must reject it, mirroring the fail-closed `unwrap_or(0)` handling the
    /// caller already applies for an absent `auth_time`.
    #[test]
    fn test_require_fresh_timestamp_future_is_rejected() {
        let future_iat = jiff::Timestamp::now().as_second() + 3600; // 1 h ahead
        let err = require_fresh_timestamp(future_iat, KEY_DELETE_MAX_AGE_SECS).unwrap_err();
        assert!(
            matches!(
                err,
                ServiceError::StepUpRequired {
                    max_age: Some(60),
                    ..
                }
            ),
            "Expected StepUpRequired for future-dated auth_time, got: {err:?}"
        );
    }

    /// A timestamp exactly at `now` (age 0) is the fresh edge case and must
    /// still pass after the new `session_age < 0` lower bound is added — the
    /// bound rejects only strictly-future timestamps, not `now` itself.
    #[test]
    fn test_require_fresh_timestamp_now_passes() {
        let now = jiff::Timestamp::now().as_second();
        assert!(require_fresh_timestamp(now, KEY_DELETE_MAX_AGE_SECS).is_ok());
    }
}
