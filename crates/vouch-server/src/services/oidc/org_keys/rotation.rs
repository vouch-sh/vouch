// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Operator-driven rotation of per-org issuer signing keys.
//!
//! Staged rotate (a Next key must be published for [`PUBLISH_AHEAD_HOURS`]
//! before promotion), gated revoke of Previous keys (token-drain window), and
//! the emergency path that replaces the whole key set at once. All mutations
//! are OCC transactions guarded by the org's claimed subdomain.

use anyhow::{Context, Result};
use jiff::{Span, Timestamp};

use super::{KeyMaterial, ensure_key, generate_key_material};
use crate::AppState;
use crate::db::audit::AuditStore;
use crate::db::documents::oauth::JwsAlgorithm;
use crate::db::documents::organization::{OrgSigningKeyDoc, OrganizationDoc, SigningKeyState};
use crate::db::store::StoreTransaction;
use crate::db::{self};

/// Hours a Next key must have been published in the JWKS before an operator
/// rotate may promote it to the signer.
///
/// Fixed at 24h (a deliberate product decision): larger than the 1h OIDC discovery
/// `max-age` and well above community-reported AWS JWKS cache TTLs, so relying
/// parties will have seen the new `kid` before signing switches to it. Because
/// the Next key is staged at first use and re-staged by every rotate, this
/// gate only bites on back-to-back rotations.
pub(crate) const PUBLISH_AHEAD_HOURS: i64 = 24;

/// Floor for the revoke gate in hours.
///
/// Ensures that a reduction of `session_hours` below 8h before revoking does
/// not allow deleting a Previous key while tokens it signed are still live.
const RETIREMENT_FLOOR_HOURS: i64 = 8;

/// Margin added to the revoke gate to absorb cache staleness.
///
/// Covers the `ORG_KEYS_CACHE_TTL` (60s) and the OIDC discovery `max-age`
/// (1h), plus a conservative buffer. The gate formula is:
/// `demoted_at + max(session_hours, RETIREMENT_FLOOR_HOURS) + RETIREMENT_MARGIN_HOURS`.
const RETIREMENT_MARGIN_HOURS: i64 = 2;

/// Error type for rotation operations that may be OCC-retried.
///
/// `OccConflict` maps to `with_dsql_retry!`'s retry path; `Other` delegates to
/// `is_retryable_db_error` so that DSQL commit-abort errors (which surface as
/// `anyhow::Error` rather than `compare_and_update → false`) also retry.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OrgRotationError {
    /// Application-level CAS version conflict (`compare_and_update` returned
    /// `false`). Retried by `with_dsql_retry!`.
    #[error("org signing key was modified concurrently; retrying")]
    OccConflict,
    /// Business rejection or infrastructure failure. Not retried unless the
    /// wrapped error carries a retryable DB error code (e.g. DSQL commit-abort).
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl crate::db::pool::RetryableError for OrgRotationError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::OccConflict => true,
            Self::Other(e) => crate::db::pool::is_retryable_db_error(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Typed operation outcomes
// ---------------------------------------------------------------------------

/// Kids involved in one algorithm's rotation: the demoted signer and its
/// promoted successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotatedKids {
    pub old_kid: String,
    pub new_kid: String,
}

/// Result of an operator rotate attempt for an organization (both algorithms).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateOutcome {
    /// Signing switched for both algorithms; the old signers are now Previous
    /// (verify-only) and fresh Next keys are staged.
    Rotated {
        es256: RotatedKids,
        rs256: RotatedKids,
    },
    /// A Next key has not been published for [`PUBLISH_AHEAD_HOURS`] yet;
    /// relying-party caches may not have seen its kid. Retry after `ready_at`.
    NextNotReady { ready_at: Timestamp },
    /// Previous keys from an earlier rotation are still published. They must
    /// be revoked before rotating again (only one Previous key is kept per
    /// algorithm).
    PreviousUnrevoked,
    /// The org has no signing keys yet (they are created on first use of the
    /// discovery/JWKS or token endpoints).
    NotBootstrapped,
    /// The org's subdomain was released (possibly while this rotate was in
    /// flight); nothing may rotate until it is claimed again.
    SubdomainReleased,
}

/// Result of an emergency rotation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmergencyOutcome {
    /// The entire key set was replaced.
    Rotated,
    /// The org's subdomain was released; there is no key set to replace.
    SubdomainReleased,
}

/// Result of an operator revoke attempt for an organization's Previous keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The Previous keys were deleted and removed from the JWKS.
    Revoked {
        es256_kid: Option<String>,
        rs256_kid: Option<String>,
    },
    /// Tokens signed by the Previous keys may still be outstanding. Retry
    /// after `ready_at` (the token-drain gate).
    NotReady { ready_at: Timestamp },
    /// No Previous keys exist.
    NothingToRevoke,
}

// ---------------------------------------------------------------------------
// Shared operation plumbing
// ---------------------------------------------------------------------------

/// Operator identity attached to audit events for key operations.
#[derive(Clone, Copy)]
pub struct Operator<'a> {
    pub user_id: Option<&'a str>,
    pub email: Option<&'a str>,
}

/// Insert an audit event, logging (never propagating) failures — audit writes
/// must not abort a key operation that already committed.
async fn audit_best_effort(
    audit: &AuditStore,
    event_type: &str,
    operator: Operator<'_>,
    data: &serde_json::Value,
) {
    if let Err(e) = audit
        .insert_event(
            event_type,
            operator.user_id,
            operator.email,
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, event_type, "failed to write audit event");
    }
}

/// The instant a key staged at `staged_at` has been published long enough for
/// relying-party JWKS caches to have seen its kid.
pub(super) fn publish_ready_at(staged_at: Timestamp) -> Result<Timestamp> {
    staged_at
        .checked_add(Span::new().hours(PUBLISH_AHEAD_HOURS))
        .context("publish window overflow")
}

/// Upper bound on the revoke gate. A `session_hours` misconfiguration must
/// fail toward a longer gate, but an unbounded value would overflow the span
/// arithmetic — one year is beyond any real session lifetime.
const REVOKE_GATE_CAP_HOURS: i64 = 24 * 365;

/// The instant a key demoted at `demoted_at` may be revoked: the token-drain
/// gate `max(session_hours, RETIREMENT_FLOOR_HOURS) + RETIREMENT_MARGIN_HOURS`
/// (the floor keeps a `session_hours` reduction from shortening the gate under
/// what already-issued tokens need), capped at [`REVOKE_GATE_CAP_HOURS`].
pub(super) fn revoke_ready_at(demoted_at: Timestamp, session_hours: u64) -> Result<Timestamp> {
    // An unrepresentable session_hours clamps LONG (to the cap), never short:
    // deleting a key early breaks live sessions; waiting longer breaks nothing.
    let session_h = i64::try_from(session_hours).unwrap_or(REVOKE_GATE_CAP_HOURS);
    let drain = session_h
        .max(RETIREMENT_FLOOR_HOURS)
        .saturating_add(RETIREMENT_MARGIN_HOURS)
        .min(REVOKE_GATE_CAP_HOURS);
    demoted_at
        .checked_add(Span::new().hours(drain))
        .context("revoke gate overflow")
}

// ---------------------------------------------------------------------------
// Operator rotate — promote Next → Current, demote Current → Previous, restage
// ---------------------------------------------------------------------------

/// Pre-transaction gate check for [`rotate_org_keys`], so key generation is
/// skipped when the rotate would be rejected anyway. Not read-only: it heals
/// a missing Next key (rows created before rotation existed) by staging one,
/// outside any transaction — safe because the staged insert is idempotent.
/// The rotate transaction re-checks every gate authoritatively.
async fn precheck_rotate_and_heal(state: &AppState, org_id: &str) -> Result<Option<RotateOutcome>> {
    let store = &state.store;
    let now = Timestamp::now();
    let mut healed = false;
    let mut latest_ready: Option<Timestamp> = None;
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        if db::get_org_signing_key(store, org_id, alg, SigningKeyState::Previous)
            .await?
            .is_some()
        {
            return Ok(Some(RotateOutcome::PreviousUnrevoked));
        }
        if db::get_org_signing_key(store, org_id, alg, SigningKeyState::Current)
            .await?
            .is_none()
        {
            return Ok(Some(RotateOutcome::NotBootstrapped));
        }
        let ready_at =
            match db::get_org_signing_key(store, org_id, alg, SigningKeyState::Next).await? {
                Some(next) => {
                    let staged_at = next
                        .data
                        .staged_at
                        .context("next key is missing its staged_at timestamp")?;
                    publish_ready_at(staged_at)?
                }
                None => {
                    ensure_key(store, org_id, alg, SigningKeyState::Next).await?;
                    healed = true;
                    publish_ready_at(now)?
                }
            };
        if ready_at > now && latest_ready.is_none_or(|cur| ready_at > cur) {
            latest_ready = Some(ready_at);
        }
    }
    if healed {
        // The heal wrote new Next keys; drop the cached snapshot so the JWKS
        // publishes them immediately instead of after the cache TTL.
        state.org_keys_cache.invalidate(org_id);
    }
    Ok(latest_ready.map(|ready_at| RotateOutcome::NextNotReady { ready_at }))
}

/// Verify inside the transaction that the org still holds its subdomain,
/// and bump the org document's version so a concurrent release — which also
/// writes the org document in the transaction that deletes the rotation keys
/// — must collide with this transaction on every backend instead of
/// interleaving with the key writes.
///
/// Returns `false` when the subdomain is gone (or the org vanished); the
/// caller rejects cleanly and the transaction rolls back with no writes.
async fn guard_subdomain_claimed_in_tx(
    tx: &mut StoreTransaction<'_>,
    org_id: &str,
) -> Result<bool, OrgRotationError> {
    let Some(org_doc) = tx.get::<OrganizationDoc>(org_id).await? else {
        return Ok(false);
    };
    if org_doc.data.subdomain.is_none() {
        return Ok(false);
    }
    if !tx
        .compare_and_update(org_id, org_doc.version, &org_doc.data)
        .await?
    {
        return Err(OrgRotationError::OccConflict);
    }
    Ok(true)
}

/// One algorithm's step inside the rotate transaction.
enum AlgRotation {
    Rotated(RotatedKids),
    Blocked(RotateOutcome),
}

/// Rotate one `(org_id, alg)` pair inside the shared transaction: promote the
/// Next key to Current, demote the old signer to Previous, and restage
/// `fresh` as the new Next.
///
/// Every terminal branch returns before any write, so a benign rejection has
/// no partial writes to roll back. The CAS on the Current key is the sole OCC
/// serialization gate: a loser retries into a terminal short-circuit
/// (`PreviousUnrevoked` — the winner wrote the Previous key) instead of
/// spinning.
async fn rotate_one_alg_in_tx(
    tx: &mut StoreTransaction<'_>,
    org_id: &str,
    alg: JwsAlgorithm,
    fresh: &KeyMaterial,
    now: Timestamp,
) -> Result<AlgRotation, OrgRotationError> {
    let prev_id = db::deterministic_org_key_id(org_id, alg, SigningKeyState::Previous);
    if tx.get::<OrgSigningKeyDoc>(&prev_id).await?.is_some() {
        return Ok(AlgRotation::Blocked(RotateOutcome::PreviousUnrevoked));
    }
    let next_id = db::deterministic_org_key_id(org_id, alg, SigningKeyState::Next);
    let Some(next_doc) = tx.get::<OrgSigningKeyDoc>(&next_id).await? else {
        // Raced a release (which cancels rotation keys); a fresh Next will be
        // re-staged on next use with a fresh publish window.
        return Ok(AlgRotation::Blocked(RotateOutcome::NextNotReady {
            ready_at: publish_ready_at(now)?,
        }));
    };
    let staged_at = next_doc
        .data
        .staged_at
        .context("next key is missing its staged_at timestamp")?;
    let ready_at = publish_ready_at(staged_at)?;
    if ready_at > now {
        return Ok(AlgRotation::Blocked(RotateOutcome::NextNotReady {
            ready_at,
        }));
    }
    let current_id = db::deterministic_org_key_id(org_id, alg, SigningKeyState::Current);
    let Some(current_doc) = tx.get::<OrgSigningKeyDoc>(&current_id).await? else {
        return Ok(AlgRotation::Blocked(RotateOutcome::NotBootstrapped));
    };

    let kids = RotatedKids {
        old_kid: current_doc.data.kid.clone(),
        new_kid: next_doc.data.kid.clone(),
    };

    // Promote: the Next material becomes the Current key.
    let promoted = OrgSigningKeyDoc {
        state: SigningKeyState::Current,
        staged_at: None,
        demoted_at: None,
        ..next_doc.data.clone()
    };
    // Demote: the old signer keeps verifying as the Previous key.
    let demoted = OrgSigningKeyDoc {
        state: SigningKeyState::Previous,
        staged_at: None,
        demoted_at: Some(now),
        ..current_doc.data.clone()
    };

    // CAS is the single serialization gate; losers stop here before any write.
    if !tx
        .compare_and_update(&current_id, current_doc.version, &promoted)
        .await?
    {
        return Err(OrgRotationError::OccConflict);
    }
    tx.insert_with_id(&prev_id, &demoted).await?;
    // Consume the promoted Next and restage the fresh successor in its place,
    // keeping the always-staged invariant at commit.
    tx.delete(&next_id).await?;
    let restaged = OrgSigningKeyDoc {
        staged_at: Some(now),
        ..fresh.doc(org_id, alg, SigningKeyState::Next)
    };
    tx.insert_with_id(&next_id, &restaged).await?;
    Ok(AlgRotation::Rotated(kids))
}

/// Rotate an organization's signing keys — both algorithms, one transaction.
///
/// Auth0-model promotion: the pre-staged Next keys become the signers, the
/// old signers are demoted to Previous (published, verify-only, awaiting an
/// explicit revoke), and fresh Next keys are staged for the following
/// rotation, so the always-staged invariant holds on every exit.
///
/// Gates: both Next keys must have been published for [`PUBLISH_AHEAD_HOURS`]
/// (→ [`RotateOutcome::NextNotReady`]); no unrevoked Previous key may remain
/// (→ [`RotateOutcome::PreviousUnrevoked`]); keys must exist at all
/// (→ [`RotateOutcome::NotBootstrapped`]).
///
/// On success the cache is invalidated and one `org_issuer_key_rotated` audit
/// event per algorithm records the operator and the old/new kids.
///
/// # Errors
/// Returns an error if key generation or the transaction fails after the OCC
/// retry budget is exhausted.
pub async fn rotate_org_keys(
    state: &AppState,
    org_id: &str,
    operator: Operator<'_>,
) -> Result<RotateOutcome> {
    let store = &state.store;
    // Check the subdomain before the heal so a released org cannot have a
    // fresh Next key resurrected by the pre-check. Advisory only — the
    // transaction below re-checks under the org-document anchor.
    let claimed = db::get_organization(store, org_id)
        .await?
        .is_some_and(|org| org.subdomain.is_some());
    if !claimed {
        return Ok(RotateOutcome::SubdomainReleased);
    }
    if let Some(blocked) = precheck_rotate_and_heal(state, org_id).await? {
        return Ok(blocked);
    }

    // Fresh Next material for both algorithms, generated once outside the
    // retry loop and reused verbatim on a retry.
    let fresh_es256 = generate_key_material(JwsAlgorithm::Es256).await?;
    let fresh_rs256 = generate_key_material(JwsAlgorithm::Rs256).await?;

    let result: Result<RotateOutcome, OrgRotationError> = crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;
        let now = Timestamp::now();

        if !guard_subdomain_claimed_in_tx(&mut tx, org_id).await? {
            return Ok(RotateOutcome::SubdomainReleased);
        }

        let es256 =
            match rotate_one_alg_in_tx(&mut tx, org_id, JwsAlgorithm::Es256, &fresh_es256, now)
                .await?
            {
                AlgRotation::Rotated(kids) => kids,
                AlgRotation::Blocked(outcome) => return Ok(outcome),
            };
        let rs256 =
            match rotate_one_alg_in_tx(&mut tx, org_id, JwsAlgorithm::Rs256, &fresh_rs256, now)
                .await?
            {
                AlgRotation::Rotated(kids) => kids,
                AlgRotation::Blocked(outcome) => return Ok(outcome),
            };

        tx.commit().await.map_err(OrgRotationError::Other)?;
        Ok(RotateOutcome::Rotated { es256, rs256 })
    });
    let outcome = result.map_err(anyhow::Error::from)?;

    if let RotateOutcome::Rotated { es256, rs256 } = &outcome {
        state.org_keys_cache.invalidate(org_id);
        for (alg, kids) in [(JwsAlgorithm::Es256, es256), (JwsAlgorithm::Rs256, rs256)] {
            audit_best_effort(
                &state.audit,
                "org_issuer_key_rotated",
                operator,
                &serde_json::json!({
                    "action": "rotate_org_issuer_key",
                    "org_id": org_id,
                    "alg": alg.as_str(),
                    "old_kid": kids.old_kid,
                    "new_kid": kids.new_kid,
                }),
            )
            .await;
        }
        tracing::info!(org_id, "rotated org issuer keys");
    }
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// Operator revoke — delete the Previous keys after the token-drain gate
// ---------------------------------------------------------------------------

/// Revoke an organization's Previous signing keys (operator action).
///
/// Deletes the Previous keys for both algorithms once the token-drain gate
/// ([`revoke_ready_at`]) has elapsed for every Previous key — by then every
/// token the old signers issued has expired, so nothing loses its
/// verification key. Both deletes ride one transaction; the cache is
/// invalidated after commit and one `org_issuer_key_revoked` audit event per
/// deleted key records the operator and kid.
///
/// # Errors
/// Returns an error if the reads, the transaction, or the gate math fail.
pub async fn revoke_org_previous_keys(
    state: &AppState,
    org_id: &str,
    operator: Operator<'_>,
) -> Result<RevokeOutcome> {
    let store = &state.store;
    let session_hours = state.config().session_hours;

    // Read and delete inside one retried transaction: two racing revokes
    // conflict on the deletes, and the retrying loser re-reads empty rows and
    // lands on NothingToRevoke instead of double-reporting the revocation.
    let result: Result<RevokeOutcome, OrgRotationError> = crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;
        let now = Timestamp::now();

        let mut present: Vec<(JwsAlgorithm, String)> = Vec::with_capacity(2);
        let mut latest_ready: Option<Timestamp> = None;
        for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
            let prev_id = db::deterministic_org_key_id(org_id, alg, SigningKeyState::Previous);
            let Some(doc) = tx.get::<OrgSigningKeyDoc>(&prev_id).await? else {
                continue;
            };
            let demoted_at = doc
                .data
                .demoted_at
                .context("previous key is missing its demoted_at timestamp")?;
            let ready_at = revoke_ready_at(demoted_at, session_hours)?;
            if latest_ready.is_none_or(|cur| ready_at > cur) {
                latest_ready = Some(ready_at);
            }
            present.push((alg, doc.data.kid.clone()));
        }

        if present.is_empty() {
            return Ok(RevokeOutcome::NothingToRevoke);
        }
        if let Some(ready_at) = latest_ready
            && ready_at > now
        {
            return Ok(RevokeOutcome::NotReady { ready_at });
        }

        for (alg, _) in &present {
            tx.delete(&db::deterministic_org_key_id(
                org_id,
                *alg,
                SigningKeyState::Previous,
            ))
            .await?;
        }
        tx.commit().await.map_err(OrgRotationError::Other)?;

        let mut es256_kid = None;
        let mut rs256_kid = None;
        for (alg, kid) in present {
            match alg {
                JwsAlgorithm::Rs256 => rs256_kid = Some(kid),
                _ => es256_kid = Some(kid),
            }
        }
        Ok(RevokeOutcome::Revoked {
            es256_kid,
            rs256_kid,
        })
    });
    let outcome = result.map_err(anyhow::Error::from)?;

    if let RevokeOutcome::Revoked {
        es256_kid,
        rs256_kid,
    } = &outcome
    {
        state.org_keys_cache.invalidate(org_id);
        for (alg, kid) in [
            (JwsAlgorithm::Es256, es256_kid),
            (JwsAlgorithm::Rs256, rs256_kid),
        ] {
            let Some(kid) = kid else { continue };
            audit_best_effort(
                &state.audit,
                "org_issuer_key_revoked",
                operator,
                &serde_json::json!({
                    "action": "revoke_org_issuer_key",
                    "org_id": org_id,
                    "alg": alg.as_str(),
                    "kid": kid,
                }),
            )
            .await;
        }
        tracing::info!(org_id, "revoked previous org issuer keys");
    }
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// Emergency rotation — replace the whole key set at once
// ---------------------------------------------------------------------------

/// Replace one algorithm's whole key set inside the emergency transaction:
/// CAS a fresh Current key over the compromised one, delete the Previous key,
/// and restage a fresh Next — a store compromise exposes every sealed DER, so
/// nothing generated before the incident may survive it.
///
/// Returns the compromised (replaced) Current kid.
async fn emergency_one_alg_in_tx(
    tx: &mut StoreTransaction<'_>,
    org_id: &str,
    alg: JwsAlgorithm,
    fresh: &EmergencyKeyPair,
    now: Timestamp,
) -> Result<String, OrgRotationError> {
    let current_id = db::deterministic_org_key_id(org_id, alg, SigningKeyState::Current);
    let Some(current) = tx.get::<OrgSigningKeyDoc>(&current_id).await? else {
        return Err(OrgRotationError::Other(anyhow::anyhow!(
            "emergency: no current {} key for org '{org_id}'",
            alg.as_str()
        )));
    };
    let old_kid = current.data.kid.clone();

    let replacement = fresh.current.doc(org_id, alg, SigningKeyState::Current);
    if !tx
        .compare_and_update(&current_id, current.version, &replacement)
        .await?
    {
        return Err(OrgRotationError::OccConflict);
    }

    tx.delete(&db::deterministic_org_key_id(
        org_id,
        alg,
        SigningKeyState::Previous,
    ))
    .await?;
    let next_id = db::deterministic_org_key_id(org_id, alg, SigningKeyState::Next);
    tx.delete(&next_id).await?;
    let restaged = OrgSigningKeyDoc {
        staged_at: Some(now),
        ..fresh.next.doc(org_id, alg, SigningKeyState::Next)
    };
    tx.insert_with_id(&next_id, &restaged).await?;
    Ok(old_kid)
}

/// Fresh material for one algorithm's emergency replacement: a new Current
/// signer and a new pre-staged Next.
struct EmergencyKeyPair {
    current: KeyMaterial,
    next: KeyMaterial,
}

/// Emergency key rotation for an organization — compromise recovery.
///
/// Replaces the **entire key set** for both ES256 and RS256 in one atomic
/// transaction: fresh Current signers, fresh pre-staged Next keys (the
/// always-staged invariant holds afterwards, though the new Next starts a
/// fresh publish window), and the Previous keys deleted outright. All key
/// material predating the incident is gone from the JWKS after the next cache
/// rebuild.
///
/// The cache is invalidated only after the transaction commits, so this
/// instance never signs with a key the DB no longer trusts. If the function
/// returns `Err` (retry budget exhausted), the DB and cache are unchanged.
///
/// Outstanding tokens signed by the compromised keys will fail verification
/// once relying parties refetch the JWKS — deliberate: keeping a compromised
/// key verifiable would keep attacker-forged tokens verifiable too.
///
/// # Errors
/// Returns an error if key generation or the transaction fails after the OCC
/// retry budget is exhausted.
pub async fn emergency_rotate_org_keys(
    state: &AppState,
    org_id: &str,
    operator: Operator<'_>,
) -> Result<EmergencyOutcome> {
    let store = &state.store;
    // Advisory pre-check; the transaction re-checks under the org-document
    // anchor. Skips four wasted keygens when the org is already released.
    let claimed = db::get_organization(store, org_id)
        .await?
        .is_some_and(|org| org.subdomain.is_some());
    if !claimed {
        return Ok(EmergencyOutcome::SubdomainReleased);
    }

    // Generate all four replacements outside the retry loop.
    let es256 = EmergencyKeyPair {
        current: generate_key_material(JwsAlgorithm::Es256).await?,
        next: generate_key_material(JwsAlgorithm::Es256).await?,
    };
    let rs256 = EmergencyKeyPair {
        current: generate_key_material(JwsAlgorithm::Rs256).await?,
        next: generate_key_material(JwsAlgorithm::Rs256).await?,
    };

    // One transaction across both algorithms: a partial emergency (one alg
    // rotated, the other still compromised) must be impossible. The guard
    // serializes against a concurrent release the same way rotate does.
    let result: Result<Option<(String, String)>, OrgRotationError> =
        crate::with_dsql_retry!(async {
            let mut tx = store.begin().await?;
            let now = Timestamp::now();
            if !guard_subdomain_claimed_in_tx(&mut tx, org_id).await? {
                return Ok(None);
            }
            let old_es256 =
                emergency_one_alg_in_tx(&mut tx, org_id, JwsAlgorithm::Es256, &es256, now).await?;
            let old_rs256 =
                emergency_one_alg_in_tx(&mut tx, org_id, JwsAlgorithm::Rs256, &rs256, now).await?;
            tx.commit().await.map_err(OrgRotationError::Other)?;
            Ok(Some((old_es256, old_rs256)))
        });
    let Some((old_es256_kid, old_rs256_kid)) = result.map_err(anyhow::Error::from)? else {
        return Ok(EmergencyOutcome::SubdomainReleased);
    };

    state.org_keys_cache.invalidate(org_id);

    // One audit event per algorithm, carrying the operator identity — the
    // canonical trail for the emergency; the handler adds no event of its own.
    for (alg, old_kid, new_kid) in [
        (JwsAlgorithm::Es256, &old_es256_kid, &es256.current.kid),
        (JwsAlgorithm::Rs256, &old_rs256_kid, &rs256.current.kid),
    ] {
        audit_best_effort(
            &state.audit,
            "org_issuer_key_emergency_rotation",
            operator,
            &serde_json::json!({
                "action": "emergency_rotate_org_issuer_key",
                "org_id": org_id,
                "alg": alg.as_str(),
                "old_kid": old_kid,
                "new_kid": new_kid,
            }),
        )
        .await;
    }

    tracing::warn!(org_id, "emergency org issuer key rotation completed");
    Ok(EmergencyOutcome::Rotated)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use jiff::{Span, Timestamp};

    use super::super::test_support::{NO_OPERATOR, backdate, setup};
    use super::*;
    use crate::db::documents::organization::SigningKeyState;
    use crate::db::{
        JwsAlgorithm, OrgSigningKeyDoc, deterministic_org_key_id, get_org_signing_key,
        release_subdomain,
    };
    use crate::services::oidc::resolve_org_keys;

    #[test]
    fn publish_window_is_the_locked_twenty_four_hours() {
        // 24h is a deliberate product decision: AWS caches org JWKS documents
        // on an undocumented schedule that community reports put above the
        // advertised 1h, and a longer publish window costs nothing but
        // wall-clock time between back-to-back rotations. Changing this value
        // requires re-validating the AWS federation guidance in
        // docs/src/operations/key-management.md.
        assert_eq!(PUBLISH_AHEAD_HOURS, 24);

        // Functional lower bound: relying parties must see the new kid in the
        // JWKS (cached up to the discovery max-age of 1h) before it signs.
        const DISCOVERY_MAX_AGE_HOURS: i64 = 1;
        const {
            assert!(PUBLISH_AHEAD_HOURS >= DISCOVERY_MAX_AGE_HOURS);
        }
    }

    #[test]
    fn revoke_gate_floors_short_session_lifetimes() {
        let demoted_at = Timestamp::from_second(1_700_000_000).unwrap();

        // session_hours below the floor: the floor applies, so a shortened
        // session config cannot under-cover tokens issued before the change.
        let gated = super::revoke_ready_at(demoted_at, 4).unwrap();
        let floor_hours = RETIREMENT_FLOOR_HOURS
            .checked_add(RETIREMENT_MARGIN_HOURS)
            .unwrap();
        assert_eq!(
            gated,
            demoted_at
                .checked_add(Span::new().hours(floor_hours))
                .unwrap()
        );

        // session_hours above the floor: the real lifetime applies.
        let gated = super::revoke_ready_at(demoted_at, 12).unwrap();
        assert_eq!(
            gated,
            demoted_at.checked_add(Span::new().hours(14)).unwrap()
        );

        // Documented limitation: the floor cannot tell an original 8h config
        // from one reduced from 24h just before revoking. The runbook tells
        // operators to revoke before shrinking session_hours, not after.
        let gated = super::revoke_ready_at(demoted_at, 8).unwrap();
        assert_eq!(
            gated,
            demoted_at
                .checked_add(Span::new().hours(floor_hours))
                .unwrap()
        );
    }

    /// A session_hours value too large for the gate math clamps to the cap —
    /// the failure direction is always a LONGER gate, never a shorter one
    /// (an early revoke breaks live sessions; a late one breaks nothing).
    #[test]
    fn revoke_gate_clamps_absurd_session_hours_long() {
        let demoted_at = Timestamp::from_second(1_700_000_000).unwrap();
        let capped = demoted_at
            .checked_add(Span::new().hours(super::REVOKE_GATE_CAP_HOURS))
            .unwrap();
        assert_eq!(
            super::revoke_ready_at(demoted_at, u64::MAX).unwrap(),
            capped
        );
        // Zero clamps to the floor, like any other short lifetime.
        let floor = demoted_at
            .checked_add(
                Span::new().hours(
                    RETIREMENT_FLOOR_HOURS
                        .checked_add(RETIREMENT_MARGIN_HOURS)
                        .unwrap(),
                ),
            )
            .unwrap();
        assert_eq!(super::revoke_ready_at(demoted_at, 0).unwrap(), floor);
    }

    #[tokio::test]
    async fn rotate_is_gated_until_the_publish_window_elapses() {
        let (state, org_id, org) = setup().await;
        resolve_org_keys(&state, Some(&org)).await.unwrap();

        // Freshly staged next keys: the publish window has not elapsed.
        let outcome = rotate_org_keys(&state, &org_id, NO_OPERATOR).await.unwrap();
        assert!(
            matches!(outcome, RotateOutcome::NextNotReady { .. }),
            "expected NextNotReady, got {outcome:?}"
        );

        // Age both next keys past the window: rotation proceeds.
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Next,
            25,
        )
        .await;
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Rs256,
            SigningKeyState::Next,
            25,
        )
        .await;
        let outcome = rotate_org_keys(&state, &org_id, NO_OPERATOR).await.unwrap();
        let RotateOutcome::Rotated { es256, rs256 } = outcome else {
            panic!("expected Rotated, got {outcome:?}");
        };
        assert_ne!(es256.old_kid, es256.new_kid);
        assert_ne!(rs256.old_kid, rs256.new_kid);

        // The promoted key signs; the demoted key is Previous; a fresh Next
        // was restaged in the same transaction.
        let org = crate::db::get_organization(&state.store, &org_id)
            .await
            .unwrap()
            .unwrap();
        let snap = resolve_org_keys(&state, Some(&org)).await.unwrap().unwrap();
        assert_eq!(snap.signers.es256.key_id(), es256.new_kid);
        assert_eq!(snap.jwks.len(), 6, "Current+Next+Previous for both algs");

        let previous = get_org_signing_key(
            &state.store,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Previous,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(previous.data.kid, es256.old_kid);
        assert!(previous.data.demoted_at.is_some());
    }

    #[tokio::test]
    async fn rotate_is_blocked_while_previous_keys_are_unrevoked() {
        let (state, org_id, org) = setup().await;
        resolve_org_keys(&state, Some(&org)).await.unwrap();
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Next,
            25,
        )
        .await;
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Rs256,
            SigningKeyState::Next,
            25,
        )
        .await;
        rotate_org_keys(&state, &org_id, NO_OPERATOR).await.unwrap();

        // Even with aged next keys, an unrevoked previous blocks the rotate.
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Next,
            25,
        )
        .await;
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Rs256,
            SigningKeyState::Next,
            25,
        )
        .await;
        let outcome = rotate_org_keys(&state, &org_id, NO_OPERATOR).await.unwrap();
        assert_eq!(outcome, RotateOutcome::PreviousUnrevoked);
    }

    #[tokio::test]
    async fn revoke_is_gated_by_the_token_drain_window() {
        let (state, org_id, org) = setup().await;
        resolve_org_keys(&state, Some(&org)).await.unwrap();
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Next,
            25,
        )
        .await;
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Rs256,
            SigningKeyState::Next,
            25,
        )
        .await;
        rotate_org_keys(&state, &org_id, NO_OPERATOR).await.unwrap();

        // Immediately after the rotate the drain window is still open.
        let outcome = revoke_org_previous_keys(&state, &org_id, NO_OPERATOR)
            .await
            .unwrap();
        assert!(
            matches!(outcome, RevokeOutcome::NotReady { .. }),
            "expected NotReady, got {outcome:?}"
        );

        // Age the previous keys past max(session_hours, floor) + margin.
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Previous,
            30,
        )
        .await;
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Rs256,
            SigningKeyState::Previous,
            30,
        )
        .await;
        let outcome = revoke_org_previous_keys(&state, &org_id, NO_OPERATOR)
            .await
            .unwrap();
        let RevokeOutcome::Revoked {
            es256_kid,
            rs256_kid,
        } = outcome
        else {
            panic!("expected Revoked, got {outcome:?}");
        };
        assert!(es256_kid.is_some() && rs256_kid.is_some());

        // Nothing left to revoke afterwards.
        let outcome = revoke_org_previous_keys(&state, &org_id, NO_OPERATOR)
            .await
            .unwrap();
        assert_eq!(outcome, RevokeOutcome::NothingToRevoke);
    }

    #[tokio::test]
    async fn rotate_reports_not_bootstrapped_before_first_use() {
        let (state, org_id, _org) = setup().await;
        // resolve_org_keys was never called, so no keys exist yet.
        let outcome = rotate_org_keys(&state, &org_id, NO_OPERATOR).await.unwrap();
        assert_eq!(outcome, RotateOutcome::NotBootstrapped);
    }

    #[tokio::test]
    async fn rotate_errors_on_a_next_key_missing_its_timestamp() {
        let (state, org_id, org) = setup().await;
        resolve_org_keys(&state, Some(&org)).await.unwrap();

        // Corrupt the next key: clear its staged_at.
        let id = deterministic_org_key_id(&org_id, JwsAlgorithm::Es256, SigningKeyState::Next);
        let doc = state
            .store
            .get::<OrgSigningKeyDoc>(&id)
            .await
            .unwrap()
            .unwrap();
        let mut data = doc.data;
        data.staged_at = None;
        state.store.update(&id, &data).await.unwrap();

        let result = rotate_org_keys(&state, &org_id, NO_OPERATOR).await;
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("staged_at"), "got: {msg}");
    }

    #[tokio::test]
    async fn revoke_errors_on_a_previous_key_missing_its_timestamp() {
        let (state, org_id, org) = setup().await;
        resolve_org_keys(&state, Some(&org)).await.unwrap();
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Next,
            25,
        )
        .await;
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Rs256,
            SigningKeyState::Next,
            25,
        )
        .await;
        rotate_org_keys(&state, &org_id, NO_OPERATOR).await.unwrap();

        let id = deterministic_org_key_id(&org_id, JwsAlgorithm::Es256, SigningKeyState::Previous);
        let doc = state
            .store
            .get::<OrgSigningKeyDoc>(&id)
            .await
            .unwrap()
            .unwrap();
        let mut data = doc.data;
        data.demoted_at = None;
        state.store.update(&id, &data).await.unwrap();

        let result = revoke_org_previous_keys(&state, &org_id, NO_OPERATOR).await;
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("demoted_at"), "got: {msg}");
    }

    #[tokio::test]
    async fn rotate_rejects_a_released_subdomain_without_writes() {
        let (state, org_id, org) = setup().await;
        resolve_org_keys(&state, Some(&org)).await.unwrap();
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Next,
            25,
        )
        .await;
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Rs256,
            SigningKeyState::Next,
            25,
        )
        .await;
        release_subdomain(&state.store, &org_id).await.unwrap();

        let outcome = rotate_org_keys(&state, &org_id, NO_OPERATOR).await.unwrap();
        assert_eq!(outcome, RotateOutcome::SubdomainReleased);

        // Release deleted the Next keys; the rejected rotate must not have
        // resurrected them, demoted anything, or touched the signer.
        for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
            assert!(
                get_org_signing_key(&state.store, &org_id, alg, SigningKeyState::Next)
                    .await
                    .unwrap()
                    .is_none(),
                "{alg:?}: rejected rotate must not resurrect a Next key"
            );
            assert!(
                get_org_signing_key(&state.store, &org_id, alg, SigningKeyState::Previous)
                    .await
                    .unwrap()
                    .is_none(),
                "{alg:?}: rejected rotate must not demote the signer"
            );
            assert!(
                get_org_signing_key(&state.store, &org_id, alg, SigningKeyState::Current)
                    .await
                    .unwrap()
                    .is_some(),
                "{alg:?}: the signer survives release"
            );
        }
    }

    #[tokio::test]
    async fn emergency_rejects_a_released_subdomain() {
        let (state, org_id, org) = setup().await;
        resolve_org_keys(&state, Some(&org)).await.unwrap();
        let before = get_org_signing_key(
            &state.store,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Current,
        )
        .await
        .unwrap()
        .unwrap();
        release_subdomain(&state.store, &org_id).await.unwrap();

        let outcome = emergency_rotate_org_keys(&state, &org_id, NO_OPERATOR)
            .await
            .unwrap();
        assert_eq!(outcome, EmergencyOutcome::SubdomainReleased);

        let after = get_org_signing_key(
            &state.store,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Current,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(after.data.kid, before.data.kid, "signer must be untouched");
    }

    #[tokio::test]
    async fn emergency_fails_when_no_current_key_exists() {
        let (state, org_id, _org) = setup().await;
        // resolve_org_keys was never called, so no keys were bootstrapped.
        let result = emergency_rotate_org_keys(&state, &org_id, NO_OPERATOR).await;
        assert!(result.is_err(), "emergency requires an existing key set");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("no current ES256 key"), "got: {msg}");
    }

    #[tokio::test]
    async fn emergency_replaces_the_entire_key_set() {
        let (state, org_id, org) = setup().await;
        let before = resolve_org_keys(&state, Some(&org)).await.unwrap().unwrap();
        let old_es256_kid = before.signers.es256.key_id().to_string();

        emergency_rotate_org_keys(&state, &org_id, NO_OPERATOR)
            .await
            .unwrap();

        let snap = resolve_org_keys(&state, Some(&org)).await.unwrap().unwrap();
        assert_ne!(snap.signers.es256.key_id(), old_es256_kid);
        // Still Current + Next per algorithm — the always-staged invariant
        // survives an emergency; no Previous keys remain.
        assert_eq!(snap.jwks.len(), 4);
        for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
            assert!(
                get_org_signing_key(&state.store, &org_id, alg, SigningKeyState::Previous)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                get_org_signing_key(&state.store, &org_id, alg, SigningKeyState::Next)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }
}
