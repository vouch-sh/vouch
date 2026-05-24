// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 challenge state single-use enforcement.

use super::document_type::DocumentType;
use super::documents::challenge_state::ChallengeStateDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

/// Derive a deterministic document ID from a registration state JWT.
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

/// Atomically mark a registration state JWT as consumed (single-use enforcement).
///
/// Returns `true` if this is the first use (the document was inserted).
/// Returns `false` if the state has already been consumed (replay detected).
///
/// **Race safety across all three backends (SQLite, Postgres, DSQL):**
///
/// A deterministic document ID derived from the JWT is used as the PRIMARY KEY.
/// Two concurrent calls with the same `state_jwt` will both attempt
/// `insert_with_id` with the same ID. Exactly one will commit; the other will
/// observe a unique violation (`SQLSTATE 23505`) and return `Ok(false)`.
///
/// **DSQL OCC retry interaction:** Under Aurora DSQL's optimistic concurrency
/// control, the losing concurrent transaction first receives a serialization
/// error (`SQLSTATE 40001` / `OC000`/`OC001`). The `with_dsql_retry!` wrapper
/// (`db/store.rs`) retries that transaction. On retry, the INSERT collides with
/// the already-committed row from the winner, producing `SQLSTATE 23505`.
/// `23505` is not retryable, so `with_dsql_retry!` surfaces it as `Err(e)`,
/// which `is_unique_violation` catches and converts to `Ok(false)`. Only one
/// transaction wins; the loser is correctly treated as a replay.
pub async fn try_mark_challenge_used(
    store: &DocumentStore,
    state_jwt: &str,
    expires_at: Timestamp,
) -> Result<bool> {
    let id = deterministic_challenge_state_id(state_jwt);
    let doc = ChallengeStateDoc {
        doc_id: id.clone(),
        expires_at,
        consumed_at: Some(Timestamp::now()),
    };

    match store.insert_with_id(&id, &doc).await {
        Ok(_) => Ok(true),
        Err(e) if super::pool::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Delete expired challenge states.
pub async fn delete_expired_challenge_states(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(ChallengeStateDoc::DOC_TYPE).await
}
