// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Per-org issuer subdomains and their signing keys.
//!
//! Claim/release of issuer subdomain labels (deterministic claim slots with
//! global uniqueness, reuse cooldown, tombstones) and persistence of the
//! per-org OIDC signing keys, including the invariant that releasing a
//! subdomain cancels any in-flight key rotation. The parent's domain
//! lifecycle calls the auto-release hooks here when a backing domain is
//! removed or un-verified.

use super::validation::{
    SubdomainLabelError, backing_apex_for_label, eligible_subdomain_labels,
    validate_subdomain_label,
};
use super::{ORG_SCAN_PAGE_SIZE, Organization};
use crate::crypto::alg::JwsAlgorithm;
use crate::db::document_type::Document;
use crate::db::documents::organization::{
    OrgSigningKeyDoc, OrganizationDoc, SigningKeyState, SubdomainClaimDoc,
};
use crate::db::store::{DocumentStore, StoreTransaction};
use anyhow::Result;
use jiff::Timestamp;

// ============================================================================
// Issuer subdomains (per-org OIDC issuer hosts for AWS federation)
// ============================================================================

/// Cooldown before a released subdomain label may be claimed by a *different*
/// organization (30 days).
///
/// A re-claimant gets its own fresh signing keys, but relying parties fetch
/// the JWKS live from the issuer host: an AWS IAM OIDC provider the previous
/// holder never deleted would accept the new claimant's tokens. The cooldown
/// buys the previous holder time to remove that AWS-side trust (and lets RP
/// metadata caches expire). Same-org re-claims are always allowed.
pub const SUBDOMAIN_REUSE_COOLDOWN_SECS: i64 = 2_592_000; // 30 days

/// Errors from [`claim_subdomain`] and [`release_subdomain`] that map to
/// distinct API responses.
#[derive(Debug, thiserror::Error)]
pub enum SubdomainClaimError {
    /// The label failed syntactic validation or is reserved.
    #[error("{0}")]
    InvalidLabel(#[from] SubdomainLabelError),
    /// The label does not match any of the org's verified domains.
    #[error("label is not derived from any verified domain of this organization")]
    NotEligible,
    /// The org already holds a different label; it must be released first.
    #[error("organization already has subdomain '{0}'; release it before claiming another")]
    AlreadyClaimed(String),
    /// Another organization currently holds the label.
    #[error("subdomain is already claimed by another organization")]
    Conflict,
    /// Another organization released the label within the reuse cooldown.
    #[error("subdomain was recently released by another organization and cannot be claimed yet")]
    RecentlyReleased,
    /// The org doc or claim slot lost an OCC version race. Retried by
    /// `with_dsql_retry!`; reaches callers only when the retry budget is
    /// exhausted.
    #[error("subdomain change conflicted with a concurrent operation; please retry")]
    OccConflict,
    /// Database or concurrency failure.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl crate::db::pool::RetryableError for SubdomainClaimError {
    /// OCC version races and transient DB aborts (DSQL OC000/OC001, Postgres
    /// serialization failures, SQLite BUSY/LOCKED) re-run the transaction;
    /// business rejections are terminal.
    fn is_retryable(&self) -> bool {
        match self {
            Self::OccConflict => true,
            Self::Other(e) => crate::db::pool::is_retryable_db_error(e),
            Self::InvalidLabel(_)
            | Self::NotEligible
            | Self::AlreadyClaimed(_)
            | Self::Conflict
            | Self::RecentlyReleased => false,
        }
    }
}

/// Deterministic document ID for the claim slot of a subdomain label.
///
/// Same construction as `deterministic_org_id` in enrollment: the shared
/// primary key is what makes concurrent cross-org claims collide (unique
/// violation on insert, or version conflict on takeover).
pub(super) fn deterministic_subdomain_claim_id(label: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"subdomain_claim\0");
    ctx.update(label.as_bytes());
    hex::encode(ctx.finish().as_ref())
}

/// Deterministic document ID for an org's issuer signing key.
///
/// A key's [`SigningKeyState`] is also its storage location: each `(org_id, alg,
/// state)` triple has exactly one document ID, so retries and concurrent
/// writers collide on the primary key instead of creating duplicates — the
/// same idempotency pattern as [`deterministic_subdomain_claim_id`]. `kid` (a
/// hash of the random public key) is a field, never the ID. `Current` keeps
/// the original pre-rotation hash prefix so existing rows keep their IDs.
pub fn deterministic_org_key_id(org_id: &str, alg: JwsAlgorithm, state: SigningKeyState) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let prefix: &[u8] = match state {
        SigningKeyState::Current => b"org_signing_key\0",
        SigningKeyState::Next => b"org_signing_key_next\0",
        SigningKeyState::Previous => b"org_signing_key_prev\0",
    };
    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(prefix);
    ctx.update(org_id.as_bytes());
    ctx.update(b"\0");
    ctx.update(alg.as_str().as_bytes());
    hex::encode(ctx.finish().as_ref())
}

/// Load the key in `state` for an `(org_id, alg)` pair, if any.
///
/// # Errors
/// Returns an error if the database read fails.
pub async fn get_org_signing_key(
    store: &DocumentStore,
    org_id: &str,
    alg: JwsAlgorithm,
    state: SigningKeyState,
) -> Result<Option<Document<OrgSigningKeyDoc>>> {
    let id = deterministic_org_key_id(org_id, alg, state);
    store.get::<OrgSigningKeyDoc>(&id).await
}

/// Insert a key at the deterministic ID derived from its own state,
/// idempotently.
///
/// Returns `true` if this call created the row, `false` if the ID already
/// held a key (a concurrent writer or retry won the race) — the caller then
/// loads the existing key. Never overwrites an existing key.
///
/// # Errors
/// Returns an error on any database failure other than the row already existing.
pub async fn try_insert_org_signing_key(
    store: &DocumentStore,
    doc: &OrgSigningKeyDoc,
) -> Result<bool> {
    let id = deterministic_org_key_id(&doc.org_id, doc.alg, doc.state);
    match store.insert_with_id(&id, doc).await {
        Ok(_) => Ok(true),
        Err(e) if crate::db::pool::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Delete the in-flight rotation keys (Next and Previous) for both ES256 and
/// RS256 within the given transaction.
///
/// Called by [`release_subdomain`] and [`release_ineligible_subdomain`] when a
/// subdomain is released: after release the org keeps only its Current key.
/// The Next key is deleted too — its publish window is void once the JWKS
/// stops being served, so a same-org reclaim re-stages a fresh Next (with a
/// fresh warm-up clock) on first use instead of trusting a key whose `kid`
/// relying parties may have dropped while the host returned 404.
///
/// Deletion is best-effort per key: a missing row is silently skipped so the
/// function is safe to call even when no rotation is in progress.
///
/// # Errors
/// Returns the first database error that isn't a missing-document no-op.
async fn cancel_org_rotation_in_tx(tx: &mut StoreTransaction<'_>, org_id: &str) -> Result<()> {
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        for state in [SigningKeyState::Next, SigningKeyState::Previous] {
            tx.delete(&deterministic_org_key_id(org_id, alg, state))
                .await?;
        }
    }
    Ok(())
}

/// List all signing key documents for an organization, across all algorithms
/// and rotation states.
///
/// Used by [`crate::services::oidc::resolve_org_keys`] to build a unified cache
/// snapshot that covers Current, Next, and Previous keys — the single DB call
/// that backs both signing and the org JWKS endpoint.
///
/// # Errors
/// Returns an error if the database read fails.
pub async fn list_org_signing_keys(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Vec<Document<OrgSigningKeyDoc>>> {
    store.find_all::<OrgSigningKeyDoc>("org_id", org_id).await
}

/// Claim an issuer subdomain label for an organization.
///
/// The label must be eligible (derived from the registrable apex of a
/// verified domain), globally unique across orgs, and not within another
/// org's release cooldown. A released label can be taken over by a
/// *different* org only when that org's claim is backed by the same apex —
/// i.e. it verified ownership of the domain itself. Re-claiming the org's
/// own current label is idempotent.
///
/// Uniqueness and the cooldown are enforced by the [`SubdomainClaimDoc`]
/// slot stored under a deterministic ID: a fresh claim inserts the slot
/// (concurrent claimants hit the primary-key unique violation), and taking
/// over a released slot goes through `compare_and_update` on the slot's
/// version (concurrent takeovers or a racing release collide there). Both
/// happen in the same transaction as the org-doc update, so the slot and
/// the org's `subdomain` mirror move together. An indexed lookup alone
/// cannot provide this: `document_indexes` is only unique per document,
/// and two orgs updating their own docs never conflict with each other.
///
/// The transaction is wrapped in `with_dsql_retry!`: OCC version races on
/// the org doc or claim slot re-run it from a fresh read, so a loser of a
/// benign race (e.g. a concurrent domain change bumping the org doc)
/// converges instead of surfacing an error. Business rejections propagate
/// immediately.
///
/// Returns the normalized label on success.
pub async fn claim_subdomain(
    store: &DocumentStore,
    org_id: &str,
    label: &str,
) -> Result<String, SubdomainClaimError> {
    let label = validate_subdomain_label(label)?;

    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        let org_doc = tx
            .get::<OrganizationDoc>(org_id)
            .await?
            .ok_or_else(|| SubdomainClaimError::Other(anyhow::anyhow!("organization not found")))?;
        let version = org_doc.version;
        let mut data = org_doc.data;

        if let Some(existing) = &data.subdomain {
            if *existing == label {
                tx.commit().await?;
                return Ok(label.clone());
            }
            return Err(SubdomainClaimError::AlreadyClaimed(existing.clone()));
        }

        let Some(apex) = backing_apex_for_label(&data.domain, &data.additional_domains, &label)
        else {
            return Err(SubdomainClaimError::NotEligible);
        };

        // Take the claim slot. Every branch either writes the slot row or
        // rejects, so concurrent claimants serialize on it.
        let claim_id = deterministic_subdomain_claim_id(&label);
        let slot = SubdomainClaimDoc {
            label: label.clone(),
            org_id: org_id.to_string(),
            apex: apex.clone(),
            released_at: None,
        };
        match tx.get::<SubdomainClaimDoc>(&claim_id).await? {
            None => {
                if let Err(e) = tx.insert_with_id(&claim_id, &slot).await {
                    if crate::db::pool::is_unique_violation(&e) {
                        return Err(SubdomainClaimError::Conflict);
                    }
                    return Err(SubdomainClaimError::Other(e));
                }
            }
            Some(existing_slot) => {
                let slot_version = existing_slot.version;
                let holder = existing_slot.data;
                match holder.released_at {
                    None => {
                        if holder.org_id != org_id {
                            return Err(SubdomainClaimError::Conflict);
                        }
                        // Defensive: slot already ours but the org doc does
                        // not reflect it. The claim transaction writes both
                        // atomically, so this only arises from out-of-band
                        // intervention — fall through and repair the mirror.
                    }
                    Some(released_at) => {
                        let in_cooldown = Timestamp::now().duration_since(released_at).as_secs()
                            < SUBDOMAIN_REUSE_COOLDOWN_SECS;
                        if holder.org_id != org_id {
                            if in_cooldown {
                                return Err(SubdomainClaimError::RecentlyReleased);
                            }
                            // Label ↔ apex is 1:1 by construction, but two
                            // distinct apexes can hyphen-collapse to one label
                            // (acme.com.br vs acme-com.br). A cross-org
                            // takeover must be backed by the same verified
                            // apex — owning the domain is the trust anchor.
                            if holder.apex != apex {
                                return Err(SubdomainClaimError::Conflict);
                            }
                        }
                        // Take over the released slot; the version CAS makes a
                        // concurrent takeover or racing release lose the race
                        // and re-run against the fresh slot state, which then
                        // yields the precise terminal outcome (Conflict or
                        // RecentlyReleased).
                        if !tx
                            .compare_and_update(&claim_id, slot_version, &slot)
                            .await?
                        {
                            return Err(SubdomainClaimError::OccConflict);
                        }
                    }
                }
            }
        }

        data.subdomain = Some(label.clone());
        if !tx.compare_and_update(org_id, version, &data).await? {
            return Err(SubdomainClaimError::OccConflict);
        }

        if let Err(e) = tx.commit().await {
            if crate::db::pool::is_unique_violation(&e) {
                return Err(SubdomainClaimError::Conflict);
            }
            return Err(SubdomainClaimError::Other(e));
        }

        Ok(label.clone())
    })
}

/// Release an organization's issuer subdomain.
///
/// Marks the claim slot released (starting the cross-org reuse cooldown),
/// clears the org's `subdomain` mirror, and **cancels any in-progress rotation**
/// (deletes next and previous signing-key slots for both algorithms) — all in one
/// transaction. Dropping the subdomain field drops its index entry, so discovery
/// for the host stops resolving once relying-party caches expire.
///
/// The transaction is wrapped in `with_dsql_retry!` like [`claim_subdomain`]; OCC
/// version races re-run it from a fresh read. Returns the released label, or `None`
/// if the org had no subdomain.
///
/// Releasing is already disruptive (discovery returns 404 during the cooldown), so
/// dropping a Previous key's still-valid tokens on release is acceptable: the caller
/// should communicate the disruption to end users.
pub async fn release_subdomain(store: &DocumentStore, org_id: &str) -> Result<Option<String>> {
    let result: Result<Option<String>, SubdomainClaimError> = crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        let org_doc = tx
            .get::<OrganizationDoc>(org_id)
            .await?
            .ok_or_else(|| SubdomainClaimError::Other(anyhow::anyhow!("organization not found")))?;
        let version = org_doc.version;
        let mut data = org_doc.data;

        let Some(label) = data.subdomain.take() else {
            return Ok(None);
        };

        if !tx.compare_and_update(org_id, version, &data).await? {
            return Err(SubdomainClaimError::OccConflict);
        }

        let claim_id = deterministic_subdomain_claim_id(&label);
        match tx.get::<SubdomainClaimDoc>(&claim_id).await? {
            Some(slot) if slot.data.org_id == org_id && slot.data.released_at.is_none() => {
                let released = SubdomainClaimDoc {
                    released_at: Some(Timestamp::now()),
                    ..slot.data
                };
                if !tx
                    .compare_and_update(&claim_id, slot.version, &released)
                    .await?
                {
                    return Err(SubdomainClaimError::OccConflict);
                }
            }
            other => {
                // The mirror said we held the label but the slot disagrees.
                // Clearing the mirror is still correct; log for investigation.
                tracing::warn!(
                    org_id,
                    label,
                    slot_state = ?other.map(|s| (s.data.org_id, s.data.released_at)),
                    "org subdomain mirror out of sync with claim slot during release"
                );
            }
        }

        // Cancel any in-flight rotation: delete next and previous slots for both
        // algs atomically with the subdomain release. Idempotent — missing slots
        // are silently skipped.
        cancel_org_rotation_in_tx(&mut tx, org_id)
            .await
            .map_err(SubdomainClaimError::Other)?;

        tx.commit().await?;

        Ok(Some(label))
    });
    result.map_err(anyhow::Error::from)
}

/// The org's claimed subdomain label that has lost its verified-domain
/// backing and must be released, or `None` when the claim (if any) is still
/// backed. Callers use `Some` both to decide the transactional slot-release
/// path is needed (vs. a plain CAS) and as the label to release, so
/// eligibility is computed once per mutation.
pub(super) fn subdomain_to_release(data: &OrganizationDoc) -> Option<String> {
    let label = data.subdomain.as_ref()?;
    if eligible_subdomain_labels(&data.domain, &data.additional_domains).contains(label) {
        return None;
    }
    Some(label.clone())
}

/// Inside `tx`, auto-release the org's issuer subdomain `label` (already known
/// ineligible via [`subdomain_to_release`]): clear the org-doc mirror, tombstone
/// the claim slot, and cancel any in-progress rotation.
///
/// Call after mutating `data`'s domain set and before the org-doc
/// `compare_and_update`: the mirror clear, the slot release, and the rotation
/// cancel then commit atomically with the domain change. The released slot starts
/// the normal reuse cooldown.
///
/// Cancelling rotation on auto-release is safe: auto-release already signals
/// disruption (discovery 404s), so dropping a Previous key's still-valid tokens
/// is acceptable.
///
/// # Errors
/// Returns [`SubdomainClaimError::OccConflict`] when the claim slot loses its
/// CAS race — callers run inside `with_dsql_retry!`, which re-runs the whole
/// transaction from a fresh read. Other failures are terminal.
pub(super) async fn release_ineligible_subdomain(
    tx: &mut StoreTransaction<'_>,
    org_id: &str,
    data: &mut OrganizationDoc,
    label: &str,
) -> Result<(), SubdomainClaimError> {
    data.subdomain = None;

    let claim_id = deterministic_subdomain_claim_id(label);
    match tx.get::<SubdomainClaimDoc>(&claim_id).await? {
        Some(slot) if slot.data.org_id == org_id && slot.data.released_at.is_none() => {
            let released = SubdomainClaimDoc {
                released_at: Some(Timestamp::now()),
                ..slot.data
            };
            if !tx
                .compare_and_update(&claim_id, slot.version, &released)
                .await?
            {
                return Err(SubdomainClaimError::OccConflict);
            }
        }
        other => {
            tracing::warn!(
                org_id,
                label,
                slot_state = ?other.map(|s| (s.data.org_id, s.data.released_at)),
                "org subdomain mirror out of sync with claim slot during auto-release"
            );
        }
    }

    // Cancel in-flight rotation, same as the operator-triggered release path.
    cancel_org_rotation_in_tx(tx, org_id).await?;

    tracing::warn!(
        org_id,
        label,
        "auto-released issuer subdomain: no verified domain backs it anymore"
    );
    Ok(())
}

/// Look up the organization that has claimed `label` as its issuer
/// subdomain, if any. Backed by the `subdomain` document index.
pub async fn find_org_by_subdomain(
    store: &DocumentStore,
    label: &str,
) -> Result<Option<Organization>> {
    let doc = store
        .find_one::<OrganizationDoc>("subdomain", label)
        .await?;
    Ok(doc.map(Organization::from))
}

/// True when any organization currently claims an issuer subdomain.
///
/// Startup guard for unencrypted deployments: pages through org documents
/// (active claims are not separately indexed) and short-circuits on the
/// first claim. Runs once at boot, so the O(orgs) walk is acceptable.
pub async fn any_subdomain_claimed(store: &DocumentStore) -> Result<bool> {
    let mut cursor: Option<String> = None;
    loop {
        let (page, has_more) = store
            .list_all_paginated::<OrganizationDoc>(cursor.as_deref(), ORG_SCAN_PAGE_SIZE)
            .await?;
        if page.is_empty() {
            return Ok(false);
        }
        if page.iter().any(|org| org.data.subdomain.is_some()) {
            return Ok(true);
        }
        if !has_more {
            return Ok(false);
        }
        cursor = page.last().map(|d| d.id.clone());
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::super::{
        add_additional_domain, create_organization, fresh_store, mark_additional_domain_verified,
    };
    use super::*;

    #[tokio::test]
    async fn claim_subdomain_happy_path_and_lookup() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();

        let label = claim_subdomain(&store, &org.id, "ACME-COM").await.unwrap();
        assert_eq!(label, "acme-com");

        let found = find_org_by_subdomain(&store, "acme-com").await.unwrap();
        assert_eq!(found.map(|o| o.id), Some(org.id.clone()));

        // The slot records the backing apex for takeover checks.
        let slot = store
            .get::<SubdomainClaimDoc>(&deterministic_subdomain_claim_id("acme-com"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(slot.data.apex, "acme.com");

        // Idempotent re-claim of the same label.
        let again = claim_subdomain(&store, &org.id, "acme-com").await.unwrap();
        assert_eq!(again, "acme-com");
    }

    #[tokio::test]
    async fn claim_subdomain_rejects_ineligible_label() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        let err = claim_subdomain(&store, &org.id, "widgets-io")
            .await
            .unwrap_err();
        assert!(matches!(err, SubdomainClaimError::NotEligible), "{err}");
        // The bare brand label (pre-apex derivation scheme) is not eligible.
        let err = claim_subdomain(&store, &org.id, "acme").await.unwrap_err();
        assert!(matches!(err, SubdomainClaimError::NotEligible), "{err}");
    }

    #[tokio::test]
    async fn claim_subdomain_rejects_cross_org_conflict() {
        let store = fresh_store().await;
        // Two orgs backed by the same apex: one owns acme.com outright, the
        // other verified a subdomain of it — both derive "acme-com".
        let first = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        let second = create_organization(&store, "widgets.io", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &second.id, "mail.acme.com", "u1", "u1@widgets.io")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &second.id, "mail.acme.com")
            .await
            .unwrap();

        claim_subdomain(&store, &first.id, "acme-com")
            .await
            .unwrap();
        let err = claim_subdomain(&store, &second.id, "acme-com")
            .await
            .unwrap_err();
        assert!(matches!(err, SubdomainClaimError::Conflict), "{err}");
    }

    #[tokio::test]
    async fn claim_subdomain_rejects_second_label_without_release() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "widgets.io", "u1", "u1@acme.com")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &org.id, "widgets.io")
            .await
            .unwrap();

        claim_subdomain(&store, &org.id, "acme-com").await.unwrap();
        let err = claim_subdomain(&store, &org.id, "widgets-io")
            .await
            .unwrap_err();
        assert!(
            matches!(err, SubdomainClaimError::AlreadyClaimed(ref l) if l == "acme-com"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn release_subdomain_drops_index_and_tombstones() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        claim_subdomain(&store, &org.id, "acme-com").await.unwrap();

        let released = release_subdomain(&store, &org.id).await.unwrap();
        assert_eq!(released, Some("acme-com".to_string()));

        // Index entry gone → host lookup stops resolving.
        assert!(
            find_org_by_subdomain(&store, "acme-com")
                .await
                .unwrap()
                .is_none()
        );

        // Releasing again is a no-op.
        assert_eq!(release_subdomain(&store, &org.id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn released_label_blocked_for_other_org_but_not_own() {
        let store = fresh_store().await;
        let first = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        // The second org derives the same label from a verified subdomain of
        // the same apex, so it is eligible to attempt the takeover.
        let second = create_organization(&store, "widgets.io", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &second.id, "mail.acme.com", "u1", "u1@widgets.io")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &second.id, "mail.acme.com")
            .await
            .unwrap();

        claim_subdomain(&store, &first.id, "acme-com")
            .await
            .unwrap();
        release_subdomain(&store, &first.id).await.unwrap();

        // Cross-org re-claim is tombstoned for the cooldown window.
        let err = claim_subdomain(&store, &second.id, "acme-com")
            .await
            .unwrap_err();
        assert!(
            matches!(err, SubdomainClaimError::RecentlyReleased),
            "{err}"
        );

        // Same-org re-claim is always allowed and reactivates the slot.
        let label = claim_subdomain(&store, &first.id, "acme-com")
            .await
            .unwrap();
        assert_eq!(label, "acme-com");
        let slot = store
            .get::<SubdomainClaimDoc>(&deterministic_subdomain_claim_id("acme-com"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(slot.data.org_id, first.id);
        assert!(
            slot.data.released_at.is_none(),
            "own re-claim must reactivate the claim slot"
        );
    }

    #[tokio::test]
    async fn released_label_claimable_by_same_apex_org_after_cooldown() {
        let store = fresh_store().await;
        let claimant = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();

        // Seed a slot released by another org longer ago than the cooldown,
        // backed by the same apex the claimant has verified.
        let expired_release = Timestamp::now()
            .checked_sub(jiff::Span::new().seconds(SUBDOMAIN_REUSE_COOLDOWN_SECS + 60))
            .unwrap();
        store
            .insert_with_id(
                &deterministic_subdomain_claim_id("acme-com"),
                &SubdomainClaimDoc {
                    label: "acme-com".to_string(),
                    org_id: "some-other-org".to_string(),
                    apex: "acme.com".to_string(),
                    released_at: Some(expired_release),
                },
            )
            .await
            .unwrap();

        let label = claim_subdomain(&store, &claimant.id, "acme-com")
            .await
            .unwrap();
        assert_eq!(label, "acme-com");
        let slot = store
            .get::<SubdomainClaimDoc>(&deterministic_subdomain_claim_id("acme-com"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(slot.data.org_id, claimant.id, "slot must transfer holders");
        assert!(slot.data.released_at.is_none());
    }

    #[tokio::test]
    async fn released_label_never_moves_across_apexes() {
        let store = fresh_store().await;
        // acme.com.br (com.br is a public suffix) and acme-com.br are
        // distinct apexes that hyphen-collapse to the same label
        // "acme-com-br". A takeover across that boundary must be refused
        // even after the cooldown — the claimant does not own the domain the
        // label was minted for.
        let claimant = create_organization(&store, "acme-com.br", None, None)
            .await
            .unwrap();

        let expired_release = Timestamp::now()
            .checked_sub(jiff::Span::new().seconds(SUBDOMAIN_REUSE_COOLDOWN_SECS + 60))
            .unwrap();
        store
            .insert_with_id(
                &deterministic_subdomain_claim_id("acme-com-br"),
                &SubdomainClaimDoc {
                    label: "acme-com-br".to_string(),
                    org_id: "some-other-org".to_string(),
                    apex: "acme.com.br".to_string(),
                    released_at: Some(expired_release),
                },
            )
            .await
            .unwrap();

        let err = claim_subdomain(&store, &claimant.id, "acme-com-br")
            .await
            .unwrap_err();
        assert!(matches!(err, SubdomainClaimError::Conflict), "{err}");
    }

    #[tokio::test]
    async fn tombstone_check_finds_releaser_among_many_orgs() {
        let store = fresh_store().await;
        // The cooldown check is an indexed in-transaction lookup; filler
        // orgs verify it finds the releasing org regardless of table size.
        for i in 0..7 {
            create_organization(&store, &format!("filler{i}.com"), None, None)
                .await
                .unwrap();
        }
        let releaser = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        let claimant = create_organization(&store, "widgets.io", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &claimant.id, "mail.acme.com", "u1", "u1@widgets.io")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &claimant.id, "mail.acme.com")
            .await
            .unwrap();

        claim_subdomain(&store, &releaser.id, "acme-com")
            .await
            .unwrap();
        release_subdomain(&store, &releaser.id).await.unwrap();

        let err = claim_subdomain(&store, &claimant.id, "acme-com")
            .await
            .unwrap_err();
        assert!(
            matches!(err, SubdomainClaimError::RecentlyReleased),
            "{err}"
        );
    }

    #[tokio::test]
    async fn claim_subdomain_rejects_invalid_and_reserved_labels() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        assert!(matches!(
            claim_subdomain(&store, &org.id, "a.b").await.unwrap_err(),
            SubdomainClaimError::InvalidLabel(_)
        ));
        assert!(matches!(
            claim_subdomain(&store, &org.id, "www").await.unwrap_err(),
            SubdomainClaimError::InvalidLabel(_)
        ));
    }

    /// Only OCC version races retry; business rejections must propagate
    /// immediately or `with_dsql_retry!` would loop on terminal outcomes.
    #[test]
    fn subdomain_claim_error_retryability() {
        use crate::db::pool::RetryableError;

        assert!(SubdomainClaimError::OccConflict.is_retryable());
        assert!(!SubdomainClaimError::InvalidLabel(SubdomainLabelError::NoLetter).is_retryable());
        assert!(!SubdomainClaimError::NotEligible.is_retryable());
        assert!(!SubdomainClaimError::AlreadyClaimed("acme".into()).is_retryable());
        assert!(!SubdomainClaimError::Conflict.is_retryable());
        assert!(!SubdomainClaimError::RecentlyReleased.is_retryable());
        assert!(!SubdomainClaimError::Other(anyhow::anyhow!("boom")).is_retryable());
    }

    #[test]
    fn org_key_id_is_deterministic_and_distinct() {
        let base = deterministic_org_key_id("org1", JwsAlgorithm::Es256, SigningKeyState::Current);
        // Stable for the same inputs (idempotent creation depends on this).
        assert_eq!(
            base,
            deterministic_org_key_id("org1", JwsAlgorithm::Es256, SigningKeyState::Current)
        );
        // Distinct across org, algorithm, and state.
        assert_ne!(
            base,
            deterministic_org_key_id("org2", JwsAlgorithm::Es256, SigningKeyState::Current)
        );
        assert_ne!(
            base,
            deterministic_org_key_id("org1", JwsAlgorithm::Rs256, SigningKeyState::Current)
        );
        assert_ne!(
            base,
            deterministic_org_key_id("org1", JwsAlgorithm::Es256, SigningKeyState::Next)
        );
        assert_ne!(
            deterministic_org_key_id("org1", JwsAlgorithm::Es256, SigningKeyState::Next),
            deterministic_org_key_id("org1", JwsAlgorithm::Es256, SigningKeyState::Previous)
        );
    }

    #[tokio::test]
    async fn release_subdomain_cancels_in_flight_rotation() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();

        // Simulate a staged rotation by inserting Next keys manually.
        for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
            let doc = OrgSigningKeyDoc {
                org_id: org.id.clone(),
                alg,
                kid: format!("next-{alg}"),
                private_pkcs8_der_b64: "AAAA".to_string().into(),
                state: SigningKeyState::Next,
                staged_at: Some(jiff::Timestamp::now()),
                demoted_at: None,
            };
            try_insert_org_signing_key(&store, &doc).await.unwrap();
        }

        assert!(
            get_org_signing_key(&store, &org.id, JwsAlgorithm::Es256, SigningKeyState::Next)
                .await
                .unwrap()
                .is_some()
        );

        // Claim then release a subdomain — release must cancel the rotation.
        claim_subdomain(&store, &org.id, "acme-com").await.unwrap();
        release_subdomain(&store, &org.id).await.unwrap();

        // Both Next keys must be gone.
        for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
            assert!(
                get_org_signing_key(&store, &org.id, alg, SigningKeyState::Next)
                    .await
                    .unwrap()
                    .is_none(),
                "{alg:?} next key must be deleted on release"
            );
        }
    }

    #[tokio::test]
    async fn org_key_insert_is_idempotent_on_the_deterministic_id() {
        let store = fresh_store().await;
        let doc = OrgSigningKeyDoc {
            org_id: "org1".to_string(),
            alg: JwsAlgorithm::Es256,
            kid: "kid-1".to_string(),
            private_pkcs8_der_b64: "AAAA".to_string().into(),
            state: SigningKeyState::Current,
            staged_at: None,
            demoted_at: None,
        };
        // A retry or concurrent claim re-runs the insert; the deterministic ID
        // makes the second one a no-op instead of a duplicate row.
        assert!(try_insert_org_signing_key(&store, &doc).await.unwrap());
        assert!(!try_insert_org_signing_key(&store, &doc).await.unwrap());
        let all = store
            .find_all::<OrgSigningKeyDoc>("org_id", "org1")
            .await
            .unwrap();
        assert_eq!(all.len(), 1, "only one key row despite two inserts");
    }

    #[tokio::test]
    async fn any_subdomain_claimed_walks_org_pages() {
        let store = fresh_store().await;
        // More orgs than one scan page, claimer created last so the walk
        // must page past the fillers to find it.
        for i in 0..7 {
            create_organization(&store, &format!("filler{i}.com"), None, None)
                .await
                .unwrap();
        }
        assert!(!any_subdomain_claimed(&store).await.unwrap());

        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        claim_subdomain(&store, &org.id, "acme-com").await.unwrap();
        assert!(any_subdomain_claimed(&store).await.unwrap());

        release_subdomain(&store, &org.id).await.unwrap();
        assert!(!any_subdomain_claimed(&store).await.unwrap());
    }
}
