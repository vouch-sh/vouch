// SPDX-License-Identifier: BUSL-1.1
//! FIDO2 challenge state single-use enforcement.

use super::document_type::DocumentType;
use super::documents::challenge_state::ChallengeStateDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

/// Record an issued FIDO2 challenge state.
pub async fn store_challenge_state(
    store: &DocumentStore,
    state_hash: &str,
    expires_at: Timestamp,
) -> Result<()> {
    let doc = ChallengeStateDoc {
        state_hash: state_hash.to_string(),
        expires_at,
        consumed_at: None,
    };
    store.insert(&doc).await?;
    Ok(())
}

/// Try to consume a FIDO2 challenge state.
///
/// Returns `true` if the state was successfully consumed (first use).
/// Returns `false` if already consumed, does not exist, or was
/// concurrently consumed by another request (optimistic lock).
pub async fn try_consume_challenge_state(store: &DocumentStore, state_hash: &str) -> Result<bool> {
    let now = Timestamp::now();

    let doc = store
        .find_one::<ChallengeStateDoc>("state_hash", state_hash)
        .await?;
    let Some(doc) = doc else {
        return Ok(false);
    };

    if doc.data.consumed_at.is_some() || doc.data.expires_at <= now {
        return Ok(false);
    }

    let mut data = doc.data;
    data.consumed_at = Some(now);
    store.compare_and_update(&doc.id, doc.version, &data).await
}

/// Delete expired challenge states.
pub async fn delete_expired_challenge_states(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(ChallengeStateDoc::DOC_TYPE).await
}
