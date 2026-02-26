// SPDX-License-Identifier: BUSL-1.1
//! DPoP nonce and JTI database operations (RFC 9449).

use super::document_type::DocumentType;
use super::documents::dpop::{DpopJtiDoc, DpopNonceDoc};
use super::store::DocumentStore;
use anyhow::{Context, Result};
use aws_lc_rs::rand as aws_rand;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Timestamp, ToSpan};

/// Generate a random URL-safe string.
fn generate_random_string(len: usize) -> Result<String> {
    let mut bytes = vec![0u8; len];
    aws_rand::fill(&mut bytes).map_err(|_| anyhow::anyhow!("RNG failure"))?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

/// Generate and store a DPoP nonce. Returns the nonce string.
pub async fn generate_dpop_nonce(store: &DocumentStore, validity_seconds: i64) -> Result<String> {
    let nonce = generate_random_string(32)?;
    let now = Timestamp::now();
    let expires_at = now
        .checked_add(validity_seconds.seconds())
        .context("DPoP nonce expiry timestamp overflow")?;

    let doc = DpopNonceDoc {
        nonce: nonce.clone(),
        expires_at,
    };
    store.insert(&doc).await?;
    Ok(nonce)
}

/// Validate and consume a nonce.
///
/// Returns `true` if valid and consumed, `false` if not found or expired.
pub async fn validate_and_consume_dpop_nonce(store: &DocumentStore, nonce: &str) -> Result<bool> {
    let now = Timestamp::now();

    let doc = store.find_one::<DpopNonceDoc>("nonce", nonce).await?;

    let Some(doc) = doc else {
        return Ok(false);
    };

    // Check expiry
    if doc.data.expires_at <= now {
        // Expired — delete it and return false
        store.delete(&doc.id).await?;
        return Ok(false);
    }

    // Valid — consume by deleting
    store.delete(&doc.id).await?;
    Ok(true)
}

/// Check if JTI exists (replay) and store it.
/// Returns `true` if new, `false` if replay.
///
/// Uses the JTI as the document ID for uniqueness.
pub async fn check_and_store_dpop_jti(
    store: &DocumentStore,
    jti: &str,
    validity_seconds: i64,
) -> Result<bool> {
    let now = Timestamp::now();
    let expires_at = now
        .checked_add(validity_seconds.seconds())
        .context("DPoP JTI expiry timestamp overflow")?;

    // Check if JTI already exists by looking up the index
    let existing = store.find_one::<DpopJtiDoc>("jti", jti).await?;
    if existing.is_some() {
        return Ok(false);
    }

    let doc = DpopJtiDoc {
        jti: jti.to_string(),
        expires_at,
    };

    // Insert — if a race causes a duplicate, treat as replay
    match store.insert(&doc).await {
        Ok(_) => Ok(true),
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("UNIQUE")
                || err_str.contains("duplicate key")
                || err_str.contains("PRIMARY KEY")
            {
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
