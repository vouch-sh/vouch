// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DPoP nonce and JTI database operations (RFC 9449).

use super::claim::ClaimError;
use super::document_type::DocumentType;
use super::documents::dpop::{DpopJtiDoc, DpopNonceDoc};
use super::store::DocumentStore;
use anyhow::{Context, Result};
use aws_lc_rs::rand as aws_rand;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Timestamp, ToSpan};

/// Maximum JTI length.
const MAX_JTI_LENGTH: usize = 256;

/// Derive a deterministic document ID from a DPoP JTI.
///
/// DPoP JTIs are globally unique (RFC 9449 Section 11.1), unlike JWT
/// assertion JTIs which are scoped per-client. The domain separator
/// `"dpop_jti\0"` prevents cross-type ID collisions.
fn deterministic_dpop_jti_id(jti: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"dpop_jti\0");
    ctx.update(jti.as_bytes());
    hex::encode(ctx.finish().as_ref())
}

/// Derive a deterministic document ID from a DPoP nonce. Separate domain
/// from JTIs so the two types' IDs can never collide.
fn deterministic_dpop_nonce_id(nonce: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"dpop_nonce\0");
    ctx.update(nonce.as_bytes());
    hex::encode(ctx.finish().as_ref())
}

/// Generate a random URL-safe string.
fn generate_random_string(len: usize) -> Result<String> {
    let mut bytes = vec![0u8; len];
    aws_rand::fill(&mut bytes).map_err(|_| anyhow::anyhow!("RNG failure"))?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

/// Witness that a DPoP nonce (RFC 9449 §8) has been atomically consumed.
///
/// Construction is private to this module — the only path to an instance is
/// a successful return from [`validate_and_consume_dpop_nonce`], which runs
/// a single `DELETE WHERE id = ? AND expires_at > ?` SQL statement.
/// Returning the witness means *this caller* was the one whose DELETE
/// affected a row — no concurrent consumer can hold the same witness.
///
/// Intentionally not `Clone`. The `#[must_use]` ensures it is bound at the
/// call site even when it isn't threaded further downstream (today its only
/// consumer is the DPoP validation pipeline itself, but the witness exists
/// so future code can require it as a precondition).
#[must_use = "the DPoP nonce was atomically consumed; bind this witness so \
              future code can require it as a precondition"]
#[derive(Debug)]
pub struct DpopNonceClaim {
    _private: (),
}

/// Generate and store a DPoP nonce. Returns the nonce string.
///
/// Stores the nonce under a deterministic document ID derived from the
/// nonce itself, so [`validate_and_consume_dpop_nonce`] can perform an
/// atomic primary-key DELETE without a find-then-delete TOCTOU window.
pub async fn generate_dpop_nonce(store: &DocumentStore, validity_seconds: i64) -> Result<String> {
    let nonce = generate_random_string(32)?;
    let now = Timestamp::now();
    let expires_at = now
        .checked_add(validity_seconds.seconds())
        .context("DPoP nonce expiry timestamp overflow")?;

    let id = deterministic_dpop_nonce_id(&nonce);
    let doc = DpopNonceDoc {
        nonce: nonce.clone(),
        expires_at,
    };
    store.insert_with_id(&id, &doc).await?;
    Ok(nonce)
}

/// Atomically validate and consume a DPoP nonce.
///
/// Uses a single `DELETE WHERE id = ? AND expires_at > ?` statement, so the
/// claim is decided by the database row count — no find-then-delete race.
/// On success returns a [`DpopNonceClaim`] witness; on a "lost" race (nonce
/// not found, expired, or already consumed by a concurrent caller) returns
/// [`ClaimError::AlreadyConsumed`]. The three "lost" cases are deliberately
/// indistinguishable: each is rejected the same way by RFC 9449.
pub async fn validate_and_consume_dpop_nonce(
    store: &DocumentStore,
    nonce: &str,
) -> std::result::Result<DpopNonceClaim, ClaimError> {
    let id = deterministic_dpop_nonce_id(nonce);
    let now = Timestamp::now();
    let won = store
        .delete_if_not_expired(&id, &now)
        .await
        .map_err(|e| ClaimError::Database(e.to_string()))?;
    if won {
        Ok(DpopNonceClaim { _private: () })
    } else {
        Err(ClaimError::AlreadyConsumed)
    }
}

/// Check if JTI exists (replay) and store it atomically.
/// Returns `true` if new, `false` if replay.
///
/// Uses a deterministic document ID derived from the JTI so that
/// concurrent inserts collide on the PRIMARY KEY constraint,
/// preventing TOCTOU races.
pub async fn check_and_store_dpop_jti(
    store: &DocumentStore,
    jti: &str,
    validity_seconds: i64,
) -> Result<bool> {
    if jti.is_empty() {
        return Err(anyhow::anyhow!("DPoP JTI must not be empty"));
    }
    if jti.len() > MAX_JTI_LENGTH {
        return Err(anyhow::anyhow!(
            "DPoP JTI exceeds maximum length ({MAX_JTI_LENGTH})"
        ));
    }

    let now = Timestamp::now();
    let expires_at = now
        .checked_add(validity_seconds.seconds())
        .context("DPoP JTI expiry timestamp overflow")?;

    let id = deterministic_dpop_jti_id(jti);
    let doc = DpopJtiDoc {
        jti: jti.to_string(),
        expires_at,
    };

    match store.insert_with_id(&id, &doc).await {
        Ok(_) => Ok(true),
        Err(e) => {
            if super::pool::is_unique_violation(&e) {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

/// Delete expired nonces. Returns count deleted.
pub async fn delete_expired_dpop_nonces(store: &DocumentStore, _now: &str) -> Result<u64> {
    store.delete_expired(DpopNonceDoc::DOC_TYPE).await
}

/// Delete expired JTIs. Returns count deleted.
pub async fn delete_expired_dpop_jtis(store: &DocumentStore, _now: &str) -> Result<u64> {
    store.delete_expired(DpopJtiDoc::DOC_TYPE).await
}
