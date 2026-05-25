// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 challenge state single-use enforcement.

use super::claim::ClaimError;
use super::document_type::DocumentType;
use super::documents::challenge_state::ChallengeStateDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

/// Derive a deterministic document ID from a state JWT.
///
/// The `"challenge_state\0"` domain separator prevents cross-type ID
/// collisions with `deterministic_jti_id` (`db/oauth.rs:794`) and
/// `deterministic_dpop_jti_id` (`db/dpop.rs:21`), which use different
/// prefixes. Output is hex-encoded SHA-256 (64 chars).
fn deterministic_challenge_state_id(state_jwt: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"challenge_state\0");
    ctx.update(state_jwt.as_bytes());
    hex::encode(ctx.finish().as_ref())
}

/// Witness that a state JWT (WebAuthn challenge, registration state, or
/// browser-login state) was atomically marked consumed by this caller.
///
/// Construction is private to this module — the only path to an instance
/// is a successful return from [`try_consume_challenge_state`], whose
/// atomic INSERT on a deterministic PRIMARY KEY guarantees that at most
/// one concurrent caller's insert commits. Holding a `ChallengeStateClaim`
/// is compile-time evidence that this caller "won" the consume.
///
/// Intentionally not `Clone`. The `#[must_use]` ensures the witness is
/// bound at the call site (typically threaded into one of
/// `GrantProof::Fido2Assertion`, `GrantProof::BrowserLogin`, or
/// `GrantProof::EnrollmentComplete`). The same witness type is reused
/// across these three semantically-distinct flows because the security
/// property is identical — the chokepoint variant name carries the
/// semantic context; the witness only proves the consume happened.
#[must_use = "the challenge state was atomically consumed; bind this \
              witness so it can be threaded into TokenIssuanceProof"]
#[derive(Debug)]
pub struct ChallengeStateClaim {
    _private: (),
}

/// Atomically mark a state JWT as consumed (single-use enforcement).
///
/// On success returns a [`ChallengeStateClaim`] witness; on replay returns
/// [`ClaimError::AlreadyConsumed`]. All three backends (SQLite, Postgres,
/// DSQL) detect the collision via a unique-violation on the deterministic
/// PRIMARY KEY.
///
/// **Race safety:** A deterministic document ID derived from the JWT is
/// used as the PRIMARY KEY. Two concurrent calls with the same `state_jwt`
/// will both attempt `insert_with_id` with the same ID. Exactly one will
/// commit; the other will observe a unique violation (`SQLSTATE 23505`)
/// and is reported as `AlreadyConsumed`.
///
/// **DSQL OCC retry interaction:** Under Aurora DSQL's optimistic
/// concurrency control, the losing concurrent transaction first receives
/// a serialization error (`SQLSTATE 40001` / `OC000`/`OC001`). The
/// `with_dsql_retry!` wrapper (`db/store.rs`) retries that transaction.
/// On retry, the INSERT collides with the already-committed row from the
/// winner, producing `SQLSTATE 23505`. `23505` is not retryable, so
/// `with_dsql_retry!` surfaces it as `Err(e)`, which `is_unique_violation`
/// catches. Only one transaction wins; the loser is reported as a replay.
pub async fn try_consume_challenge_state(
    store: &DocumentStore,
    state_jwt: &str,
    expires_at: Timestamp,
) -> std::result::Result<ChallengeStateClaim, ClaimError> {
    let id = deterministic_challenge_state_id(state_jwt);
    let doc = ChallengeStateDoc {
        doc_id: id.clone(),
        expires_at,
        consumed_at: Some(Timestamp::now()),
    };

    match store.insert_with_id(&id, &doc).await {
        Ok(_) => Ok(ChallengeStateClaim { _private: () }),
        Err(e) if super::pool::is_unique_violation(&e) => Err(ClaimError::AlreadyConsumed),
        Err(e) => Err(ClaimError::Database(e.to_string())),
    }
}

/// Delete expired challenge states.
pub async fn delete_expired_challenge_states(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(ChallengeStateDoc::DOC_TYPE).await
}
