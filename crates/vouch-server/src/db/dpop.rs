// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DPoP nonce and JTI database operations (RFC 9449).

use super::claim::ClaimError;
use super::document_type::DocumentType;
use super::documents::dpop::{DpopJtiDoc, DpopNonceDoc};
use super::store::DocumentStore;
use anyhow::{Context, Result};
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
pub(crate) fn deterministic_dpop_jti_id(jti: &str) -> String {
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

/// Generate and store a DPoP nonce. Returns the nonce string.
///
/// Stores the nonce under a deterministic document ID derived from the
/// nonce itself, so [`validate_and_consume_dpop_nonce`] can perform an
/// atomic primary-key DELETE without a find-then-delete TOCTOU window.
#[expect(clippy::disallowed_methods, reason = "stamps the nonce's expires_at")]
pub async fn generate_dpop_nonce(store: &DocumentStore, validity_seconds: i64) -> Result<String> {
    let nonce = URL_SAFE_NO_PAD.encode(crate::crypto::generate_random_bytes(32)?);
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

/// Atomically validate and consume a DPoP nonce, judged against `now`.
///
/// Uses a single `DELETE WHERE id = ? AND expires_at > ?` statement, so the
/// outcome is decided by the database row count — no find-then-delete race.
/// On a "lost" race (nonce not found, expired, or already consumed by a
/// concurrent caller) returns [`ClaimError::AlreadyConsumed`]. The three
/// lost cases are deliberately indistinguishable: each is rejected the
/// same way by RFC 9449.
///
/// `now` decides the expiry comparison, so a request-path caller passes the
/// request's [`crate::arrival::ArrivalTime`] instant: this comparison is one
/// of three serving a single DPoP decision, alongside the JTI retention
/// commit and the freshness check, and all three must read one instant. A
/// clock stamped here instead is always ≥ arrival, which makes the predicate
/// strictly stricter and rejects a nonce that was still valid when the
/// request arrived but expired during the intervening awaits.
///
/// No witness type is returned because `ValidatedDpopProof` already
/// carries the "DPoP validation succeeded" marker at the call site
/// ([`crate::services::oidc::dpop::validate_dpop_common`]); a separate
/// `DpopNonceClaim` would duplicate that guarantee without any
/// downstream consumer requiring it.
pub async fn validate_and_consume_dpop_nonce(
    store: &DocumentStore,
    nonce: &str,
    now: &Timestamp,
) -> std::result::Result<(), ClaimError> {
    let id = deterministic_dpop_nonce_id(nonce);
    let won = store
        .delete_if_not_expired(&id, now)
        .await
        .map_err(|e| ClaimError::Database(e.to_string()))?;
    if won {
        Ok(())
    } else {
        Err(ClaimError::AlreadyConsumed)
    }
}

/// Witness that a DPoP JTI (RFC 9449 §11.1) was atomically committed by
/// this caller. Construction is private to this module — the only path
/// to an instance is a successful return from
/// [`check_and_store_dpop_jti_at_second`],
/// whose atomic INSERT on the deterministic PRIMARY KEY guarantees that
/// at most one concurrent caller's insert commits.
///
/// Intentionally not `Clone`. `validate_dpop_common` moves the witness into
/// the `ValidatedDpopProof` it returns, so holding a validated proof is
/// itself evidence that this insert won — the replay guarantee travels with
/// the value instead of being asserted alongside it.
#[must_use = "the DPoP JTI was atomically committed; bind this witness so \
              it can be carried into ValidatedDpopProof"]
#[derive(Debug)]
pub struct DpopJtiClaim {
    _private: (),
}

impl DpopJtiClaim {
    /// Test-only constructor. Production code must obtain a claim via
    /// [`check_and_store_dpop_jti_at_second`].
    ///
    /// Gated on `test-utils` as well as `test` because
    /// `ValidatedDpopProof::for_testing` needs it to build a witness for
    /// integration-test fixtures, and `crate::test_utils` compiles under
    /// the feature. `lib.rs` fails the build if the feature is on in a
    /// release profile.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn for_testing() -> Self {
        Self { _private: () }
    }
}

/// Atomically commit a DPoP JTI to the replay-prevention table.
///
/// Uses a deterministic document ID derived from the JTI so that
/// concurrent inserts collide on the PRIMARY KEY constraint, preventing
/// TOCTOU races across SQLite, Postgres, and DSQL.
///
/// On success returns a [`DpopJtiClaim`] witness; on replay returns
/// [`ClaimError::AlreadyConsumed`]. Oversized or empty JTI is
/// `ClaimError::InvalidInput` (client error → 401, not a 500 that would
/// prompt retry).
///
/// The row's `expires_at` is derived from the caller-provided `now_second`
/// (Unix seconds): `expires_at = Timestamp::from_second(now_second) +
/// validity_seconds`.
///
/// Callers that also run a freshness check (e.g.
/// `services::oidc::dpop::validate_dpop_common`) pass the request's arrival
/// instant here *and* to the freshness check, so the replay record and the
/// freshness window share one reference instant. Reading a second clock for
/// either one lets the freshness window's upper bound drift past the record's
/// `expires_at`, reopening a replay gap (RFC 9449 §11.1) — which is why there
/// is no ambient-clock overload.
///
/// `now_second` is in **integer seconds** (the `as_second()` granularity
/// the freshness check uses). Callers that need to cover the
/// `as_second()` floor-truncation slack — the up-to-one-second window in
/// which a replay whose wall-clock `as_second()` is still within the
/// freshness window is accepted despite the sub-second fraction having
/// elapsed — should pass `now.as_second() + 1` (pre-rounded up by the
/// caller) rather than `now.as_second()`. That keeps the row alive until
/// the first second at which the freshness check would reject the proof,
/// fully covering the RFC 9449 §11.1 acceptance window.
pub async fn check_and_store_dpop_jti_at_second(
    store: &DocumentStore,
    jti: &str,
    now_second: i64,
    validity_seconds: i64,
) -> std::result::Result<DpopJtiClaim, ClaimError> {
    let expires_at = Timestamp::from_second(now_second)
        .and_then(|t| t.checked_add(validity_seconds.seconds()))
        .map_err(|e| ClaimError::Database(format!("DPoP JTI expiry overflow: {e}")))?;
    store_dpop_jti_with_expiry(store, jti, expires_at).await
}

/// Validate `jti` and atomically insert a row expiring at `expires_at`.
///
/// The insert body behind [`check_and_store_dpop_jti_at_second`], kept
/// separate so the expiry arithmetic and the storage step stay legible.
async fn store_dpop_jti_with_expiry(
    store: &DocumentStore,
    jti: &str,
    expires_at: Timestamp,
) -> std::result::Result<DpopJtiClaim, ClaimError> {
    if jti.is_empty() {
        return Err(ClaimError::InvalidInput(
            "DPoP JTI must not be empty".to_string(),
        ));
    }
    if jti.len() > MAX_JTI_LENGTH {
        return Err(ClaimError::InvalidInput(format!(
            "DPoP JTI exceeds maximum length ({MAX_JTI_LENGTH})"
        )));
    }

    let id = deterministic_dpop_jti_id(jti);
    let doc = DpopJtiDoc {
        jti: jti.to_string(),
        expires_at,
    };

    match store.insert_with_id(&id, &doc).await {
        Ok(_) => Ok(DpopJtiClaim { _private: () }),
        Err(e) if super::pool::is_unique_violation(&e) => Err(ClaimError::AlreadyConsumed),
        Err(e) => Err(ClaimError::Database(e.to_string())),
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
