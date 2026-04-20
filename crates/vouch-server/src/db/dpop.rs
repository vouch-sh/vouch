// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DPoP nonce and JTI database operations (RFC 9449).

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
