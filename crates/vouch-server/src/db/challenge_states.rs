// SPDX-License-Identifier: BUSL-1.1
//! FIDO2 challenge state single-use enforcement.

use super::document_type::DocumentType;
use super::documents::challenge_state::ChallengeStateDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

/// Atomically mark a FIDO2 challenge as used.
///
/// Returns `true` if the challenge was successfully marked (first use).
/// Returns `false` if a record with the same hash already exists
/// (replay or concurrent use).
///
/// The transaction ensures no TOCTOU race: two concurrent requests
/// with the same challenge cannot both succeed because the second
/// `find_one` will see the first's insert.
pub async fn try_mark_challenge_used(
    store: &DocumentStore,
    state_hash: &str,
    expires_at: Timestamp,
) -> Result<bool> {
    let mut tx = store.begin().await?;

    let existing = tx
        .find_one::<ChallengeStateDoc>("state_hash", state_hash)
        .await?;
    if existing.is_some() {
        return Ok(false);
    }

    let now = Timestamp::now();
    let doc = ChallengeStateDoc {
        state_hash: state_hash.to_string(),
        expires_at,
        consumed_at: Some(now),
    };
    tx.insert(&doc).await?;
    tx.commit().await?;

    Ok(true)
}

/// Delete expired challenge states.
pub async fn delete_expired_challenge_states(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(ChallengeStateDoc::DOC_TYPE).await
}
