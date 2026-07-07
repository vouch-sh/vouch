// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Organization database operations.

use super::document_type::Document;
use super::documents::oauth::JwsAlgorithm;
use super::documents::organization::{
    AdditionalDomain, AdditionalDomainState, OrgSigningKeyDoc, OrganizationDoc, SigningKeyState,
    SubdomainClaimDoc,
};
use super::store::{DocumentStore, StoreTransaction};
use anyhow::{Result, bail};

mod validation;
use aws_lc_rs::rand as aws_rand;
use jiff::Timestamp;
use validation::backing_apex_for_label;
pub use validation::{
    DomainValidationError, RESERVED_SUBDOMAIN_LABELS, SubdomainLabelError,
    eligible_subdomain_labels, ineligible_subdomain_candidates, normalize_domain, unicode_form,
    validate_subdomain_label,
};

/// Maximum additional (non-primary) email domains per organization.
pub const MAX_ADDITIONAL_DOMAINS: usize = 10;

/// Page size for cursor-paginated scans of organization documents.
///
/// Background tasks and the admin add-domain conflict check walk the org
/// table; paging caps the per-batch memory and DB row-fetch cost regardless
/// of total org count. A dedicated `(domain, pending)` index would replace
/// these scans with O(log N) lookups — defer until org count justifies it.
#[cfg(not(test))]
const ORG_SCAN_PAGE_SIZE: u64 = 256;
/// In tests the page size is small so the pagination loop exercises multiple
/// iterations without needing hundreds of fixture orgs.
#[cfg(test)]
const ORG_SCAN_PAGE_SIZE: u64 = 3;

/// Organization record for domain-based multi-tenancy.
#[derive(Debug, Clone)]
pub struct Organization {
    pub id: String,
    pub domain: String,
    pub name: Option<String>,
    pub created_at: Timestamp,
    pub created_by_user_id: Option<String>,
    pub additional_domains: Vec<AdditionalDomain>,
    pub subdomain: Option<String>,
}

impl From<Document<OrganizationDoc>> for Organization {
    fn from(doc: Document<OrganizationDoc>) -> Self {
        Self {
            id: doc.id,
            domain: doc.data.domain,
            name: doc.data.name,
            created_at: doc.created_at,
            created_by_user_id: doc.data.created_by_user_id,
            additional_domains: doc.data.additional_domains,
            subdomain: doc.data.subdomain,
        }
    }
}

/// Create a new organization.
///
/// Note: Only used in tests. Production code uses `enroll_user_with_org`.
#[cfg(any(test, feature = "test-utils"))]
pub async fn create_organization(
    store: &DocumentStore,
    domain: &str,
    name: Option<&str>,
    created_by_user_id: Option<&str>,
) -> Result<Organization> {
    let doc = OrganizationDoc {
        domain: domain.to_string(),
        name: name.map(String::from),
        created_by_user_id: created_by_user_id.map(String::from),
        additional_domains: Vec::new(),
        subdomain: None,
    };
    let result = store.insert(&doc).await?;
    Ok(Organization::from(result))
}

/// Get an organization's domain by ID.
pub async fn get_organization_domain(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Option<String>> {
    let doc = store.get::<OrganizationDoc>(org_id).await?;
    Ok(doc.map(|d| d.data.domain))
}

/// Get the full organization record by ID.
pub async fn get_organization(store: &DocumentStore, org_id: &str) -> Result<Option<Organization>> {
    let doc = store.get::<OrganizationDoc>(org_id).await?;
    Ok(doc.map(Organization::from))
}

/// List additional domains for an organization.
pub async fn list_additional_domains(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Vec<AdditionalDomain>> {
    let doc = store.get::<OrganizationDoc>(org_id).await?;
    Ok(doc.map(|d| d.data.additional_domains).unwrap_or_default())
}

/// Result of adding an additional domain.
#[derive(Debug)]
pub struct AddedDomain {
    pub domain: String,
    pub verification_token: String,
}

/// Generate a fresh verification token suitable for use in a DNS TXT record.
fn generate_verification_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    aws_rand::fill(&mut bytes).map_err(|_| anyhow::anyhow!("RNG failure"))?;
    Ok(hex::encode(bytes))
}

/// Internal OCC-retry error for organization document CAS mutations.
///
/// Used as the concrete error type inside `with_dsql_retry!` blocks for
/// functions that CAS the org doc as their serialization point. Business
/// rejections use `Other(anyhow::anyhow!(...))` — a plain `anyhow::Error`
/// has no retryable DB error code, so the retry macro lets them through
/// immediately. `OccConflict` is the application-level CAS conflict
/// (`compare_and_update` returned `false`).
#[derive(Debug, thiserror::Error)]
enum OrgCasError {
    /// Application-level OCC version race; retried by `with_dsql_retry!`.
    #[error("organization was modified concurrently; please retry")]
    OccConflict,
    /// Business rejection or infrastructure failure.  Not retried unless the
    /// wrapped `anyhow::Error` carries a retryable DB error code.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl super::pool::RetryableError for OrgCasError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::OccConflict => true,
            Self::Other(e) => super::pool::is_retryable_db_error(e),
        }
    }
}

/// Errors returned by [`add_additional_domain`].
///
/// Business-rejection variants are terminal (not retried); `OccConflict` and
/// DB-retryable `Other` errors are re-run by `with_dsql_retry!`.
#[derive(Debug, thiserror::Error)]
pub enum AddDomainError {
    /// The organization has reached the additional-domain cap.
    #[error("organization already has the maximum of {MAX_ADDITIONAL_DOMAINS} additional domains")]
    MaxDomains,
    /// The submitted domain is already the organization's primary domain.
    #[error("domain is already the organization's primary domain")]
    PrimaryDomain,
    /// The domain is already in this organization's additional-domain list.
    #[error("domain is already attached to this organization")]
    AlreadyAttached,
    /// Another organization has a verified claim on this domain.
    #[error("domain is already claimed by another organization")]
    ClaimedByOtherOrg,
    /// Another organization has a pending (unverified) claim on this domain.
    #[error("domain has a pending verification claim on another organization")]
    PendingOtherOrg,
    /// Another organization has an auto-unverified (DNS-lapsed) claim.
    #[error(
        "domain is held by another organization (auto-unverified after DNS failures); \
         it must be removed or expire before this org can claim it"
    )]
    HeldByOtherOrg,
    /// The submitted domain string failed syntactic validation.
    #[error(transparent)]
    InvalidDomain(#[from] DomainValidationError),
    /// OCC version race; retried by `with_dsql_retry!`, reaches callers only
    /// when the retry budget is exhausted.
    #[error("organization was modified concurrently; please retry")]
    OccConflict,
    /// Database or unexpected infrastructure failure.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl super::pool::RetryableError for AddDomainError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::OccConflict => true,
            Self::Other(e) => super::pool::is_retryable_db_error(e),
            Self::MaxDomains
            | Self::PrimaryDomain
            | Self::AlreadyAttached
            | Self::ClaimedByOtherOrg
            | Self::PendingOtherOrg
            | Self::HeldByOtherOrg
            | Self::InvalidDomain(_) => false,
        }
    }
}

/// Errors returned by [`mark_additional_domain_verified`].
///
/// `ClaimedByOtherOrg` is a terminal business rejection; `OccConflict` and
/// DB-retryable `Other` errors are re-run by `with_dsql_retry!`.
#[derive(Debug, thiserror::Error)]
pub enum MarkVerifiedError {
    /// Another organization verified the domain first (concurrent race).
    #[error(
        "another organization verified this domain first; \
         remove the pending entry from this org and contact support \
         if you believe this is in error"
    )]
    ClaimedByOtherOrg,
    /// OCC version race; retried by `with_dsql_retry!`, reaches callers only
    /// when the retry budget is exhausted.
    #[error("organization was modified concurrently; please retry")]
    OccConflict,
    /// Database or unexpected infrastructure failure.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl super::pool::RetryableError for MarkVerifiedError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::OccConflict => true,
            Self::Other(e) => super::pool::is_retryable_db_error(e),
            Self::ClaimedByOtherOrg => false,
        }
    }
}

/// Add a pending additional domain to an organization.
///
/// The returned token must be published as `_vouch-verification.<domain>`
/// TXT record before [`verify_additional_domain`] will mark the entry verified.
/// Until then, the entry is stored on the org but is not indexed and does
/// not participate in login matching.
pub async fn add_additional_domain(
    store: &DocumentStore,
    org_id: &str,
    domain: &str,
    added_by_user_id: &str,
    added_by_email: &str,
) -> Result<AddedDomain, AddDomainError> {
    let normalized = normalize_domain(domain)?;

    // Pending-claim conflict check (non-transactional courtesy check).
    //
    // Pending entries are not indexed, so we walk organization docs to look
    // for existing pending claims on the same domain. This check runs
    // OUTSIDE the add transaction, so a true cross-org race is possible:
    // two admins from different orgs can both pass this check, both add the
    // domain as pending, and both publish TXT records. Only one will win at
    // verification time — the loser sees the ClaimedByOtherOrg error from
    // `mark_additional_domain_verified` and must remove the orphan from
    // their org's domain list manually (or wait for GC).
    //
    // Folding this into the transaction would require a query path that
    // can scan pending entries; deferred until org count justifies it.
    match find_conflicting_claim_in_other_org(store, org_id, &normalized).await? {
        None | Some(AdditionalDomainState::Verified { .. }) => {}
        Some(AdditionalDomainState::Pending) => {
            return Err(AddDomainError::PendingOtherOrg);
        }
        Some(AdditionalDomainState::Unverified { .. }) => {
            return Err(AddDomainError::HeldByOtherOrg);
        }
    }

    // The transaction body is wrapped in `with_dsql_retry!` so that an OCC
    // version race on `compare_and_update` (another admin mutating the org
    // doc between our read and our write) retries from a fresh read rather
    // than surfacing a "modified concurrently" error to the admin.
    crate::with_dsql_retry!(async {
        let token = generate_verification_token()?;
        let now = Timestamp::now();

        let mut tx = store.begin().await?;

        let org_doc = tx
            .get::<OrganizationDoc>(org_id)
            .await?
            .ok_or_else(|| AddDomainError::Other(anyhow::anyhow!("organization not found")))?;
        let version = org_doc.version;
        let mut data = org_doc.data;

        if data.additional_domains.len() >= MAX_ADDITIONAL_DOMAINS {
            return Err(AddDomainError::MaxDomains);
        }

        if data.domain.eq_ignore_ascii_case(&normalized) {
            return Err(AddDomainError::PrimaryDomain);
        }
        if data
            .additional_domains
            .iter()
            .any(|ad| ad.domain == normalized)
        {
            return Err(AddDomainError::AlreadyAttached);
        }

        // Conflict check against any other org's verified domain (primary or
        // additional). Verified entries appear in the document_indexes table.
        if let Some(other) = tx
            .find_one::<OrganizationDoc>("domain", &normalized)
            .await?
            && other.id != org_id
        {
            return Err(AddDomainError::ClaimedByOtherOrg);
        }

        data.additional_domains.push(AdditionalDomain {
            domain: normalized.clone(),
            verification_token: token.clone(),
            added_at: now,
            added_by_user_id: added_by_user_id.to_string(),
            added_by_email: added_by_email.to_string(),
            consecutive_failures: 0,
            state: AdditionalDomainState::Pending,
        });

        if !tx.compare_and_update(org_id, version, &data).await? {
            return Err(AddDomainError::OccConflict);
        }
        tx.commit().await?;

        Ok(AddedDomain {
            domain: normalized.clone(),
            verification_token: token,
        })
    })
}

/// Re-fetch the verification token for an additional domain that needs DNS
/// verification — either a never-verified pending entry or a previously-verified
/// entry that was flipped to unverified by background re-checks.
///
/// Returns `None` if no matching non-verified entry exists.
pub async fn get_verification_token(
    store: &DocumentStore,
    org_id: &str,
    domain: &str,
) -> Result<Option<String>> {
    let normalized = normalize_domain(domain)?;
    let Some(doc) = store.get::<OrganizationDoc>(org_id).await? else {
        return Ok(None);
    };
    Ok(doc
        .data
        .additional_domains
        .into_iter()
        .find(|ad| {
            ad.domain == normalized && !matches!(ad.state, AdditionalDomainState::Verified { .. })
        })
        .map(|ad| ad.verification_token))
}

/// Mark an additional domain as verified.
///
/// Handles both first-time verification (pending entries) and re-verification
/// of entries that were flipped to unverified by repeated DNS recheck
/// failures. Caller must have already confirmed the DNS TXT record matches
/// the stored token. Re-runs the cross-org conflict check inside the
/// transaction to guard against a TOCTOU race where another org verified
/// the same domain between add and verify.
pub async fn mark_additional_domain_verified(
    store: &DocumentStore,
    org_id: &str,
    domain: &str,
) -> Result<(), MarkVerifiedError> {
    let normalized = normalize_domain(domain).map_err(anyhow::Error::from)?;

    // Wrapped in `with_dsql_retry!` so that a version race on
    // `compare_and_update` retries from a fresh org-doc read rather than
    // surfacing an error to the admin.
    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        let org_doc = tx
            .get::<OrganizationDoc>(org_id)
            .await?
            .ok_or_else(|| MarkVerifiedError::Other(anyhow::anyhow!("organization not found")))?;
        let version = org_doc.version;
        let mut data = org_doc.data;

        let entry = data
            .additional_domains
            .iter_mut()
            .find(|ad| ad.domain == normalized)
            .ok_or_else(|| {
                MarkVerifiedError::Other(anyhow::anyhow!(
                    "domain is not attached to this organization"
                ))
            })?;

        if matches!(entry.state, AdditionalDomainState::Verified { .. }) {
            // Already verified — nothing to do.
            tx.commit().await?;
            return Ok(());
        }

        if let Some(other) = tx
            .find_one::<OrganizationDoc>("domain", &normalized)
            .await?
            && other.id != org_id
        {
            return Err(MarkVerifiedError::ClaimedByOtherOrg);
        }

        // Reset re-verification state so a freshly re-verified entry is treated
        // identically to a brand-new verification by the background task.
        entry.state = AdditionalDomainState::Verified {
            verified_at: Timestamp::now(),
            last_checked_at: None,
        };
        entry.consecutive_failures = 0;

        if !tx.compare_and_update(org_id, version, &data).await? {
            return Err(MarkVerifiedError::OccConflict);
        }
        tx.commit().await?;
        Ok(())
    })
}

/// Outcome of a successful `remove_additional_domain` call.
#[derive(Debug, Clone, Default)]
pub struct DomainRemovalSummary {
    /// Number of org users whose active sessions were revoked because their
    /// email domain matched the removed entry. `org_id` is intentionally
    /// left intact on those users — domain removal does not demote
    /// membership; admins must do that explicitly.
    pub revoked_user_count: u64,
    /// True if the session-revocation pass encountered an error and was
    /// aborted. The count above may be incomplete. The underlying error is
    /// logged via `tracing::warn` for operator follow-up.
    pub revocation_errored: bool,
    /// Issuer subdomain that was automatically released because the removed
    /// domain was the last verified domain backing it. `None` when no
    /// subdomain was claimed or it remains eligible via another domain.
    pub released_subdomain: Option<String>,
}

/// Remove an additional domain from an organization.
///
/// On success returns `Some` with a summary of side effects (currently: the
/// number of users whose sessions were revoked because their email's domain
/// matched the removed entry). Returns `None` if the domain was not attached
/// to the organization.
///
/// Users keep their `org_id` and `is_org_admin` flags — admins can demote
/// them separately via SCIM if desired. Revoking sessions forces a fresh
/// login, at which point the now-removed domain no longer matches and the
/// user lands wherever their email maps in the new state.
pub async fn remove_additional_domain(
    store: &DocumentStore,
    org_id: &str,
    domain: &str,
) -> Result<Option<DomainRemovalSummary>> {
    let normalized = normalize_domain(domain)?;

    // The read + CAS (both transactional and plain paths) is wrapped in
    // `with_dsql_retry!` so that a version race retries from a fresh org-doc
    // read.  Session revocation runs OUTSIDE the retry: per-user session
    // deletes touch different rows, and a failure there must not undo the
    // domain removal (the domain is already gone from login matching).
    //
    // Returns `None` when the domain is not attached, or `Some(released)`
    // where `released: Option<String>` is any auto-released subdomain label.
    let result: Result<Option<Option<String>>, OrgCasError> = crate::with_dsql_retry!(async {
        let org_doc = store
            .get::<OrganizationDoc>(org_id)
            .await?
            .ok_or_else(|| OrgCasError::Other(anyhow::anyhow!("organization not found")))?;
        let version = org_doc.version;
        let mut data = org_doc.data;

        let original_len = data.additional_domains.len();
        data.additional_domains.retain(|ad| ad.domain != normalized);
        if data.additional_domains.len() == original_len {
            return Ok(None);
        }

        // Removing a verified domain may take the claimed issuer subdomain's
        // backing with it; the subdomain must not outlive domain ownership.
        // A transaction is opened ONLY when a release will actually happen:
        // the claim slot and the mirror must move together, but the common
        // no-subdomain path stays a plain CAS (a read-then-write transaction
        // can deadlock concurrent writers on SQLite's deferred locking).
        let released = if let Some(label) = subdomain_to_release(&data) {
            let mut tx = store.begin().await?;
            release_ineligible_subdomain(&mut tx, org_id, &mut data, &label).await?;
            if !tx.compare_and_update(org_id, version, &data).await? {
                return Err(OrgCasError::OccConflict);
            }
            tx.commit().await?;
            Some(label)
        } else {
            if !store.compare_and_update(org_id, version, &data).await? {
                return Err(OrgCasError::OccConflict);
            }
            None
        };

        Ok(Some(released))
    });

    let released_subdomain = match result.map_err(anyhow::Error::from)? {
        None => return Ok(None),
        Some(r) => r,
    };

    // Revoke sessions for org users whose email's domain matches the removed
    // entry. Done OUTSIDE the retry loop: per-user session deletes touch
    // different rows, and a failure here must not undo the removal (the
    // domain is already gone from login matching). Log and continue.
    let (revoked_user_count, revocation_errored) =
        match revoke_sessions_for_domain_users(store, org_id, &normalized).await {
            Ok(n) => (n, false),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    org_id = %org_id,
                    domain = %normalized,
                    "Domain removed, but session revocation for matching users failed"
                );
                (0, true)
            }
        };
    Ok(Some(DomainRemovalSummary {
        revoked_user_count,
        revocation_errored,
        released_subdomain,
    }))
}

/// Revoke active sessions for every user in `org_id` whose email's domain
/// equals `domain` (case-insensitive). Returns the number of users whose
/// sessions were deleted (count of users, not count of sessions).
async fn revoke_sessions_for_domain_users(
    store: &DocumentStore,
    org_id: &str,
    domain: &str,
) -> Result<u64> {
    use super::documents::user::UserDoc;
    let users = store.find_all::<UserDoc>("org_id", org_id).await?;
    let mut revoked: u64 = 0;
    for user in users {
        let matches = user
            .data
            .email
            .rsplit_once('@')
            .is_some_and(|(_, d)| d.eq_ignore_ascii_case(domain));
        if !matches {
            continue;
        }
        match super::sessions::delete_sessions_for_user(store, &user.id).await {
            Ok(_) => {
                tracing::info!(
                    user_id = %user.id,
                    org_id = %org_id,
                    domain = %domain,
                    "Revoked sessions for user after additional-domain removal"
                );
                revoked = revoked.saturating_add(1);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    user_id = %user.id,
                    "Failed to revoke sessions for user during domain removal"
                );
            }
        }
    }
    Ok(revoked)
}

/// An additional-domain entry the cleanup task decided to remove.
#[derive(Debug, Clone)]
pub struct StaleDomainRemoval {
    pub org_id: String,
    pub domain: String,
    /// True when the entry was never verified (squatted pending claim).
    /// False when the entry was verified at some point but later flipped
    /// back to unverified by re-verification failure.
    pub never_verified: bool,
}

/// Drop additional-domain entries from `doc` whose name appears in
/// `drop_candidates`, **except** for entries currently in the
/// [`AdditionalDomainState::Verified`] state, which are always preserved.
///
/// Returns `(domain, never_verified)` for each entry that was actually
/// removed, where `never_verified` mirrors the value supplied in
/// `drop_candidates` (true for pending-squat removals, false for
/// auto-unverified drift).
///
/// This is the body of the [`DocumentStore::modify`] closure inside
/// [`cleanup_stale_additional_domains`]. It is factored out so the
/// "never remove verified" invariant can be tested in isolation. That
/// invariant matters because the candidate set is computed from an earlier
/// `list_all_paginated` snapshot and the doc may have been mutated (e.g.
/// admin verification) between the read and the write — see issue #380.
fn retain_non_verified_dropped(
    doc: &mut OrganizationDoc,
    drop_candidates: &std::collections::HashMap<String, bool>,
) -> Vec<(String, bool)> {
    let mut removed_this_attempt = Vec::new();
    doc.additional_domains.retain(|ad| {
        // Re-check state on the fresh doc body: never remove an entry that
        // has flipped to Verified since list_all_paginated.
        if matches!(ad.state, AdditionalDomainState::Verified { .. }) {
            return true;
        }
        if let Some(&never_verified) = drop_candidates.get(&ad.domain) {
            removed_this_attempt.push((ad.domain.clone(), never_verified));
            false
        } else {
            true
        }
    });
    removed_this_attempt
}

/// Garbage-collect additional-domain entries that have outlived their TTL.
///
/// Two categories are removed:
/// - **Pending squat** ([`AdditionalDomainState::Pending`] with `added_at`
///   older than `pending_ttl`): caps the cost of an admin who adds a domain
///   they don't own and never publishes the TXT record.
/// - **Auto-unverified drift** ([`AdditionalDomainState::Unverified`] whose
///   `last_checked_at` is older than `unverified_ttl`): gives the admin a
///   grace window to fix DNS after a flip, then cleans up.
///
/// [`AdditionalDomainState::Verified`] entries are never removed by this
/// function — re-verification handles drift detection for them.
///
/// Returns the list of removed entries so the caller can emit audit events.
pub async fn cleanup_stale_additional_domains(
    store: &DocumentStore,
    now: Timestamp,
    pending_ttl: jiff::Span,
    unverified_ttl: jiff::Span,
) -> Result<Vec<StaleDomainRemoval>> {
    let pending_cutoff = now
        .checked_sub(pending_ttl)
        .map_err(|e| anyhow::anyhow!("pending TTL cutoff overflow: {e}"))?;
    let unverified_cutoff = now
        .checked_sub(unverified_ttl)
        .map_err(|e| anyhow::anyhow!("unverified TTL cutoff overflow: {e}"))?;

    let mut removed = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let (page, has_more) = store
            .list_all_paginated::<OrganizationDoc>(cursor.as_deref(), ORG_SCAN_PAGE_SIZE)
            .await?;
        if page.is_empty() {
            return Ok(removed);
        }
        let next_cursor = page.last().map(|d| d.id.clone());
        for org in &page {
            let mut to_remove: Vec<(String, bool)> = Vec::new();
            for ad in &org.data.additional_domains {
                match &ad.state {
                    AdditionalDomainState::Verified { .. } => continue,
                    AdditionalDomainState::Pending => {
                        if ad.added_at < pending_cutoff {
                            to_remove.push((ad.domain.clone(), true));
                        }
                    }
                    AdditionalDomainState::Unverified {
                        last_checked_at, ..
                    } => {
                        // last_checked_at is the moment of the failing
                        // recheck that caused the flip.
                        if *last_checked_at < unverified_cutoff {
                            to_remove.push((ad.domain.clone(), false));
                        }
                    }
                }
            }
            if to_remove.is_empty() {
                continue;
            }
            let drop_candidates: std::collections::HashMap<String, bool> =
                to_remove.iter().cloned().collect();
            // Captured by the modify closure so we can record which entries
            // were actually removed on the committed attempt. modify re-reads
            // fresh data on every retry and re-invokes the closure, so we
            // rewrite this on each call; when modify returns Ok(true) the
            // final contents reflect the committed write. Mutex (not RefCell)
            // because the surrounding future must be Send for tokio::spawn.
            let actually_removed: std::sync::Mutex<Vec<(String, bool)>> =
                std::sync::Mutex::new(Vec::new());
            // Per-org error isolation: one failing modify (transient DB
            // error, version conflict, etc.) must not abort cleanup for
            // every org that follows. Log and continue; next tick retries.
            let updated = match store
                .modify::<OrganizationDoc, _>(&org.id, |doc| {
                    let removed_this_attempt = retain_non_verified_dropped(doc, &drop_candidates);
                    // Recover from poisoning rather than panic: the lock is
                    // only held in this synchronous closure and a previous
                    // panic here would already have aborted the modify call.
                    match actually_removed.lock() {
                        Ok(mut guard) => *guard = removed_this_attempt,
                        Err(poisoned) => *poisoned.into_inner() = removed_this_attempt,
                    }
                })
                .await
            {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        org_id = %org.id,
                        "Failed to drop stale additional domains for org; skipping"
                    );
                    continue;
                }
            };
            if updated {
                let committed = actually_removed
                    .into_inner()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                for (domain, never_verified) in committed {
                    removed.push(StaleDomainRemoval {
                        org_id: org.id.clone(),
                        domain,
                        never_verified,
                    });
                }
            }
        }
        if !has_more {
            return Ok(removed);
        }
        cursor = next_cursor;
    }
}

/// A snapshot of one verified additional-domain entry, used by the
/// re-verification task to drive its DNS checks without holding the org doc
/// open while it waits on the network.
#[derive(Debug, Clone)]
pub struct VerifiedDomainRecord {
    pub org_id: String,
    pub domain: String,
    pub verification_token: String,
    pub last_checked_at: Option<Timestamp>,
    pub consecutive_failures: u32,
}

/// Outcome of a single re-verification attempt for [`record_recheck_result`].
#[derive(Debug, Clone, Copy)]
pub enum RecheckOutcome {
    /// TXT record observed and matched.
    Success,
    /// TXT record missing, did not match, or DNS lookup failed.
    Failure,
}

/// Result of [`record_recheck_result`] — whether the entry was flipped to
/// unverified after this attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecheckEffect {
    /// Counters updated, entry still verified.
    StillVerified,
    /// Consecutive-failure threshold reached; entry flipped to unverified.
    FlippedToUnverified {
        /// Issuer subdomain that was automatically released because the
        /// flipped domain was the last verified domain backing it.
        released_subdomain: Option<String>,
    },
    /// Entry was no longer present (removed or already unverified externally).
    NotFound,
}

/// List every verified additional domain across all organizations.
///
/// Used by the background re-verification task. Returned records are snapshots
/// — by the time the caller acts on one the underlying entry may have been
/// modified, which is fine because [`record_recheck_result`] is a no-op when
/// the entry no longer matches.
pub async fn list_all_verified_additional_domains(
    store: &DocumentStore,
) -> Result<Vec<VerifiedDomainRecord>> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let (page, has_more) = store
            .list_all_paginated::<OrganizationDoc>(cursor.as_deref(), ORG_SCAN_PAGE_SIZE)
            .await?;
        if page.is_empty() {
            return Ok(out);
        }
        let next_cursor = page.last().map(|d| d.id.clone());
        for org in &page {
            for ad in &org.data.additional_domains {
                if let AdditionalDomainState::Verified {
                    last_checked_at, ..
                } = ad.state
                {
                    out.push(VerifiedDomainRecord {
                        org_id: org.id.clone(),
                        domain: ad.domain.clone(),
                        verification_token: ad.verification_token.clone(),
                        last_checked_at,
                        consecutive_failures: ad.consecutive_failures,
                    });
                }
            }
        }
        if !has_more {
            return Ok(out);
        }
        cursor = next_cursor;
    }
}

/// Record the result of a background re-verification attempt.
///
/// On `Success`, resets the failure counter and stamps `last_checked_at`. On
/// `Failure`, increments the counter. When the counter reaches
/// [`UNVERIFY_FAILURE_THRESHOLD`] the entry is flipped to unverified — which
/// also drops it from the document's index entries so it stops matching new
/// logins.
///
/// Returns [`RecheckEffect::NotFound`] if the entry has been removed or is
/// already unverified, so callers can stop tracking it.
pub async fn record_recheck_result(
    store: &DocumentStore,
    org_id: &str,
    domain: &str,
    outcome: RecheckOutcome,
) -> Result<RecheckEffect> {
    let normalized = normalize_domain(domain)?;

    // Wrapped in `with_dsql_retry!` so that transient DB aborts and OCC
    // version races retry from a fresh org-doc read rather than either
    // propagating an error or silently returning `StillVerified`. If the
    // retry budget is exhausted (extreme contention), the final
    // `OccConflict` is mapped back to `Ok(StillVerified)` — no flip was
    // performed by this background task, which is the correct outcome.
    let result: Result<RecheckEffect, OrgCasError> = crate::with_dsql_retry!(async {
        let Some(org_doc) = store.get::<OrganizationDoc>(org_id).await? else {
            return Ok(RecheckEffect::NotFound);
        };
        let version = org_doc.version;
        let mut data = org_doc.data;

        let Some(entry) = data
            .additional_domains
            .iter_mut()
            .find(|ad| ad.domain == normalized)
        else {
            return Ok(RecheckEffect::NotFound);
        };

        // Only verified entries are tracked by the background re-check task.
        let AdditionalDomainState::Verified { verified_at, .. } = entry.state else {
            return Ok(RecheckEffect::NotFound);
        };

        let now = Timestamp::now();

        let mut effect = match outcome {
            RecheckOutcome::Success => {
                entry.consecutive_failures = 0;
                entry.state = AdditionalDomainState::Verified {
                    verified_at,
                    last_checked_at: Some(now),
                };
                RecheckEffect::StillVerified
            }
            RecheckOutcome::Failure => {
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                if entry.consecutive_failures
                    >= crate::db::documents::organization::UNVERIFY_FAILURE_THRESHOLD
                {
                    entry.consecutive_failures = 0;
                    entry.state = AdditionalDomainState::Unverified {
                        verified_at,
                        last_checked_at: now,
                    };
                    RecheckEffect::FlippedToUnverified {
                        released_subdomain: None,
                    }
                } else {
                    entry.state = AdditionalDomainState::Verified {
                        verified_at,
                        last_checked_at: Some(now),
                    };
                    RecheckEffect::StillVerified
                }
            }
        };

        // Losing verification may take the claimed issuer subdomain's backing
        // with it; the subdomain must not outlive verified domain ownership.
        // As in `remove_additional_domain`, a transaction is opened ONLY when
        // a release will actually happen — the common recheck path stays a
        // plain CAS so concurrent rechecks can't deadlock on SQLite.
        let flipped = matches!(effect, RecheckEffect::FlippedToUnverified { .. });
        let to_release = if flipped {
            subdomain_to_release(&data)
        } else {
            None
        };

        if let Some(label) = to_release {
            let mut tx = store.begin().await?;
            release_ineligible_subdomain(&mut tx, org_id, &mut data, &label).await?;
            if !tx.compare_and_update(org_id, version, &data).await? {
                return Err(OrgCasError::OccConflict);
            }
            tx.commit().await?;
            if let RecheckEffect::FlippedToUnverified { released_subdomain } = &mut effect {
                *released_subdomain = Some(label);
            }
        } else if !store.compare_and_update(org_id, version, &data).await? {
            return Err(OrgCasError::OccConflict);
        }

        Ok(effect)
    });

    // Expected CAS loss (another background writer beat us) is quiet —
    // their update is the ground truth; no flip occurred here, so
    // StillVerified is the right answer. Infrastructure aborts (DB error)
    // are surfaced so the operator can investigate.
    match result {
        Ok(effect) => Ok(effect),
        Err(OrgCasError::OccConflict) => Ok(RecheckEffect::StillVerified),
        Err(OrgCasError::Other(e)) => Err(e),
    }
}

/// Scan organization docs and return the [`AdditionalDomainState`] of any
/// non-verified claim another org holds on `domain`, or `None` if no conflict
/// exists. Verified conflicts are skipped here — they're caught by the indexed
/// `find_one` path in add/verify.
///
/// Non-verified entries are not indexed, so we page through org documents and
/// short-circuit on the first match. Returning the state directly lets the
/// caller emit a message specific to Pending vs Unverified.
async fn find_conflicting_claim_in_other_org(
    store: &DocumentStore,
    own_org_id: &str,
    domain: &str,
) -> Result<Option<AdditionalDomainState>> {
    let mut cursor: Option<String> = None;
    loop {
        let (page, has_more) = store
            .list_all_paginated::<OrganizationDoc>(cursor.as_deref(), ORG_SCAN_PAGE_SIZE)
            .await?;
        if page.is_empty() {
            return Ok(None);
        }
        let next_cursor = page.last().map(|d| d.id.clone());
        for org in &page {
            if org.id == own_org_id {
                continue;
            }
            for ad in &org.data.additional_domains {
                if ad.domain == domain
                    && !matches!(ad.state, AdditionalDomainState::Verified { .. })
                {
                    return Ok(Some(ad.state.clone()));
                }
            }
        }
        if !has_more {
            return Ok(None);
        }
        cursor = next_cursor;
    }
}

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

impl super::pool::RetryableError for SubdomainClaimError {
    /// OCC version races and transient DB aborts (DSQL OC000/OC001, Postgres
    /// serialization failures, SQLite BUSY/LOCKED) re-run the transaction;
    /// business rejections are terminal.
    fn is_retryable(&self) -> bool {
        match self {
            Self::OccConflict => true,
            Self::Other(e) => super::pool::is_retryable_db_error(e),
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
fn deterministic_subdomain_claim_id(label: &str) -> String {
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
        Err(e) if super::pool::is_unique_violation(&e) => Ok(false),
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
pub(crate) async fn cancel_org_rotation_in_tx(
    tx: &mut StoreTransaction<'_>,
    org_id: &str,
) -> Result<()> {
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
                    if super::pool::is_unique_violation(&e) {
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
            if super::pool::is_unique_violation(&e) {
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
fn subdomain_to_release(data: &OrganizationDoc) -> Option<String> {
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
async fn release_ineligible_subdomain(
    tx: &mut StoreTransaction<'_>,
    org_id: &str,
    data: &mut OrganizationDoc,
    label: &str,
) -> Result<()> {
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
                bail!("subdomain claim was modified concurrently; please retry");
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
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::crypto::document_crypto::PlaintextDocumentCrypto;
    use crate::db::documents::organization::SigningKeyState;
    use crate::test_utils::test_db;
    use std::sync::Arc;

    async fn fresh_store() -> DocumentStore {
        let pool = test_db().await;
        let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            Arc::new(PlaintextDocumentCrypto);
        DocumentStore::new(pool, crypto)
    }
    #[tokio::test]
    async fn add_additional_domain_succeeds_and_is_pending() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        let added = add_additional_domain(
            &store,
            &org.id,
            "Acme.Co.UK",
            "user-1",
            "user-1@example.com",
        )
        .await
        .unwrap();
        assert_eq!(added.domain, "acme.co.uk");
        assert!(!added.verification_token.is_empty());

        let list = list_additional_domains(&store, &org.id).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].domain, "acme.co.uk");
        assert!(matches!(list[0].state, AdditionalDomainState::Pending));
        assert_eq!(list[0].added_by_user_id, "user-1");

        // Pending entry is not indexed — find_one("domain", "acme.co.uk") must return None.
        let found = store
            .find_one::<crate::db::documents::organization::OrganizationDoc>("domain", "acme.co.uk")
            .await
            .unwrap();
        assert!(
            found.is_none(),
            "pending domain must not be reachable via find_one"
        );
    }

    #[tokio::test]
    async fn add_additional_domain_rejects_primary_collision() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        let err =
            add_additional_domain(&store, &org.id, "acme.com", "user-1", "user-1@example.com")
                .await
                .unwrap_err();
        assert!(err.to_string().contains("primary"));
    }

    #[tokio::test]
    async fn add_additional_domain_enforces_cap() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        for i in 0..MAX_ADDITIONAL_DOMAINS {
            let d = format!("alt{i}.example.com");
            add_additional_domain(&store, &org.id, &d, "user-1", "user-1@example.com")
                .await
                .unwrap();
        }
        let err = add_additional_domain(
            &store,
            &org.id,
            "one-too-many.example.com",
            "user-1",
            "user-1@example.com",
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("maximum"));
    }

    #[tokio::test]
    async fn add_additional_domain_rejects_verified_conflict_with_other_org() {
        let store = fresh_store().await;
        let _other = create_organization(&store, "acme.co.uk", None, None)
            .await
            .unwrap();
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        let err = add_additional_domain(
            &store,
            &org.id,
            "acme.co.uk",
            "user-1",
            "user-1@example.com",
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("another organization"));
    }

    #[tokio::test]
    async fn add_additional_domain_rejects_pending_conflict_with_other_org() {
        let store = fresh_store().await;
        let other = create_organization(&store, "first.com", None, None)
            .await
            .unwrap();
        add_additional_domain(
            &store,
            &other.id,
            "shared.example.com",
            "user-other",
            "user-other@example.com",
        )
        .await
        .unwrap();

        let mine = create_organization(&store, "second.com", None, None)
            .await
            .unwrap();
        let err = add_additional_domain(
            &store,
            &mine.id,
            "shared.example.com",
            "user-mine",
            "user-mine@example.com",
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("pending verification"));
    }

    #[tokio::test]
    async fn add_additional_domain_rejects_auto_unverified_conflict_with_other_org() {
        let store = fresh_store().await;
        let other = create_organization(&store, "first.com", None, None)
            .await
            .unwrap();
        add_additional_domain(
            &store,
            &other.id,
            "shared.example.com",
            "user-other",
            "user-other@example.com",
        )
        .await
        .unwrap();
        mark_additional_domain_verified(&store, &other.id, "shared.example.com")
            .await
            .unwrap();
        // Drive the entry to auto-unverified via consecutive failures.
        for _ in 0..crate::db::UNVERIFY_FAILURE_THRESHOLD {
            record_recheck_result(
                &store,
                &other.id,
                "shared.example.com",
                RecheckOutcome::Failure,
            )
            .await
            .unwrap();
        }

        let mine = create_organization(&store, "second.com", None, None)
            .await
            .unwrap();
        let err = add_additional_domain(
            &store,
            &mine.id,
            "shared.example.com",
            "user-mine",
            "user-mine@example.com",
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("auto-unverified") && !msg.contains("pending verification"),
            "expected auto-unverified-specific message, got: {msg}"
        );
    }

    #[tokio::test]
    async fn pending_conflict_check_finds_match_across_page_boundary() {
        // Test page size is 3; create more orgs so the conflict lives on a
        // later page than the first one fetched.
        let store = fresh_store().await;
        for i in 0..ORG_SCAN_PAGE_SIZE.saturating_add(2) {
            let primary = format!("filler{i}.example.com");
            let org = create_organization(&store, &primary, None, None)
                .await
                .unwrap();
            if i == ORG_SCAN_PAGE_SIZE {
                // Place the pending claim deep enough that a single-page scan
                // would miss it.
                add_additional_domain(&store, &org.id, "wanted.example.com", "u", "u@example.com")
                    .await
                    .unwrap();
            }
        }
        let mine = create_organization(&store, "mine.example.com", None, None)
            .await
            .unwrap();
        let err =
            add_additional_domain(&store, &mine.id, "wanted.example.com", "u", "u@example.com")
                .await
                .unwrap_err();
        assert!(
            err.to_string().contains("pending verification"),
            "expected cross-page pending conflict to be detected, got: {err}"
        );
    }

    #[tokio::test]
    async fn mark_verified_makes_domain_findable() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(
            &store,
            &org.id,
            "acme.co.uk",
            "user-1",
            "user-1@example.com",
        )
        .await
        .unwrap();

        mark_additional_domain_verified(&store, &org.id, "Acme.Co.UK")
            .await
            .unwrap();

        let list = list_additional_domains(&store, &org.id).await.unwrap();
        assert!(matches!(
            list[0].state,
            AdditionalDomainState::Verified { .. }
        ));

        let found = store
            .find_one::<crate::db::documents::organization::OrganizationDoc>("domain", "acme.co.uk")
            .await
            .unwrap()
            .expect("verified domain must be indexed");
        assert_eq!(found.id, org.id);
    }

    #[tokio::test]
    async fn remove_additional_domain_removes_entry() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(
            &store,
            &org.id,
            "acme.co.uk",
            "user-1",
            "user-1@example.com",
        )
        .await
        .unwrap();
        mark_additional_domain_verified(&store, &org.id, "acme.co.uk")
            .await
            .unwrap();

        let summary = remove_additional_domain(&store, &org.id, "Acme.Co.UK")
            .await
            .unwrap();
        let summary = summary.expect("entry was attached, must be removed");
        assert_eq!(summary.revoked_user_count, 0);

        let list = list_additional_domains(&store, &org.id).await.unwrap();
        assert!(list.is_empty());

        // No longer indexed.
        let found = store
            .find_one::<crate::db::documents::organization::OrganizationDoc>("domain", "acme.co.uk")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn list_all_verified_returns_only_verified_entries() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "acme.co.uk", "u1", "u1@example.com")
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "acme.eu", "u1", "u1@example.com")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &org.id, "acme.co.uk")
            .await
            .unwrap();

        let listed = list_all_verified_additional_domains(&store).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].domain, "acme.co.uk");
        assert_eq!(listed[0].consecutive_failures, 0);
    }

    #[tokio::test]
    async fn recheck_success_resets_failures_and_stamps_last_checked() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "acme.co.uk", "u1", "u1@example.com")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &org.id, "acme.co.uk")
            .await
            .unwrap();

        // Two failures, then a success — counter must reset.
        record_recheck_result(&store, &org.id, "acme.co.uk", RecheckOutcome::Failure)
            .await
            .unwrap();
        record_recheck_result(&store, &org.id, "acme.co.uk", RecheckOutcome::Failure)
            .await
            .unwrap();

        let effect = record_recheck_result(&store, &org.id, "acme.co.uk", RecheckOutcome::Success)
            .await
            .unwrap();
        assert_eq!(effect, RecheckEffect::StillVerified);

        let list = list_additional_domains(&store, &org.id).await.unwrap();
        assert!(matches!(
            list[0].state,
            AdditionalDomainState::Verified {
                last_checked_at: Some(_),
                ..
            }
        ));
        assert_eq!(list[0].consecutive_failures, 0);
    }

    #[tokio::test]
    async fn recheck_flips_to_unverified_at_threshold() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "acme.co.uk", "u1", "u1@example.com")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &org.id, "acme.co.uk")
            .await
            .unwrap();

        let mut last_effect = RecheckEffect::StillVerified;
        for _ in 0..crate::db::UNVERIFY_FAILURE_THRESHOLD {
            last_effect =
                record_recheck_result(&store, &org.id, "acme.co.uk", RecheckOutcome::Failure)
                    .await
                    .unwrap();
        }
        assert_eq!(
            last_effect,
            RecheckEffect::FlippedToUnverified {
                released_subdomain: None
            }
        );

        let list = list_additional_domains(&store, &org.id).await.unwrap();
        assert!(
            matches!(list[0].state, AdditionalDomainState::Unverified { .. }),
            "entry must be flipped to unverified"
        );

        // No longer indexed.
        let found = store
            .find_one::<crate::db::documents::organization::OrganizationDoc>("domain", "acme.co.uk")
            .await
            .unwrap();
        assert!(
            found.is_none(),
            "unverified domain must drop out of the index"
        );
    }

    #[tokio::test]
    async fn mark_verified_re_verifies_auto_unverified_entry() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "acme.co.uk", "u1", "u1@example.com")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &org.id, "acme.co.uk")
            .await
            .unwrap();

        // Drive the entry to auto-unverified via consecutive failures.
        for _ in 0..crate::db::UNVERIFY_FAILURE_THRESHOLD {
            record_recheck_result(&store, &org.id, "acme.co.uk", RecheckOutcome::Failure)
                .await
                .unwrap();
        }
        let list = list_additional_domains(&store, &org.id).await.unwrap();
        assert!(
            matches!(list[0].state, AdditionalDomainState::Unverified { .. }),
            "expected flipped state"
        );

        // Token is still available for re-verification.
        let token = get_verification_token(&store, &org.id, "acme.co.uk")
            .await
            .unwrap();
        assert!(
            token.is_some(),
            "token must be re-fetchable after auto-unverify"
        );

        // Re-verify with the existing API.
        mark_additional_domain_verified(&store, &org.id, "acme.co.uk")
            .await
            .unwrap();

        let list = list_additional_domains(&store, &org.id).await.unwrap();
        assert!(
            matches!(
                list[0].state,
                AdditionalDomainState::Verified {
                    last_checked_at: None,
                    ..
                }
            ),
            "re-verify must flip back to verified with fresh recheck state"
        );
        assert_eq!(
            list[0].consecutive_failures, 0,
            "failure counter must reset"
        );

        // Indexed again.
        let found = store
            .find_one::<crate::db::documents::organization::OrganizationDoc>("domain", "acme.co.uk")
            .await
            .unwrap();
        assert!(found.is_some(), "re-verified domain must be re-indexed");
    }

    #[tokio::test]
    async fn cleanup_removes_old_pending_squat() {
        use super::super::document_type::DocumentType;
        use super::super::documents::organization::OrganizationDoc;

        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();

        // Insert a stale pending entry directly (added 10 days ago, never verified).
        let stale_added = jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().hours(10 * 24))
            .unwrap();
        let mut doc = store
            .get::<OrganizationDoc>(&org.id)
            .await
            .unwrap()
            .unwrap();
        doc.data.additional_domains.push(AdditionalDomain {
            domain: "squatted.example.com".to_string(),
            verification_token: "tok".to_string(),
            added_at: stale_added,
            added_by_user_id: "u1".to_string(),
            added_by_email: "u1@example.com".to_string(),
            consecutive_failures: 0,
            state: AdditionalDomainState::Pending,
        });
        // Sanity: doc_type matches.
        assert_eq!(<OrganizationDoc as DocumentType>::DOC_TYPE, "organization");
        store.update(&org.id, &doc.data).await.unwrap();

        let removed = cleanup_stale_additional_domains(
            &store,
            jiff::Timestamp::now(),
            jiff::Span::new().hours(7 * 24),
            jiff::Span::new().hours(14 * 24),
        )
        .await
        .unwrap();

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].domain, "squatted.example.com");
        assert!(removed[0].never_verified);
        assert!(
            list_additional_domains(&store, &org.id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cleanup_keeps_fresh_pending() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "fresh.example.com", "u1", "u1@example.com")
            .await
            .unwrap();

        let removed = cleanup_stale_additional_domains(
            &store,
            jiff::Timestamp::now(),
            jiff::Span::new().hours(7 * 24),
            jiff::Span::new().hours(14 * 24),
        )
        .await
        .unwrap();
        assert!(removed.is_empty());
        assert_eq!(
            list_additional_domains(&store, &org.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn cleanup_removes_old_auto_unverified() {
        use super::super::documents::organization::OrganizationDoc;

        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();

        // Insert an entry that was once verified then flipped, with a
        // last_checked_at older than the unverified TTL.
        let old_verified_at = jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().hours(30 * 24))
            .unwrap();
        let old_check = jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().hours(20 * 24))
            .unwrap();
        let mut doc = store
            .get::<OrganizationDoc>(&org.id)
            .await
            .unwrap()
            .unwrap();
        doc.data.additional_domains.push(AdditionalDomain {
            domain: "drifted.example.com".to_string(),
            verification_token: "tok".to_string(),
            added_at: old_verified_at,
            added_by_user_id: "u1".to_string(),
            added_by_email: "u1@example.com".to_string(),
            consecutive_failures: 0,
            state: AdditionalDomainState::Unverified {
                verified_at: old_verified_at,
                last_checked_at: old_check,
            },
        });
        store.update(&org.id, &doc.data).await.unwrap();

        let removed = cleanup_stale_additional_domains(
            &store,
            jiff::Timestamp::now(),
            jiff::Span::new().hours(7 * 24),
            jiff::Span::new().hours(14 * 24),
        )
        .await
        .unwrap();

        assert_eq!(removed.len(), 1);
        assert!(!removed[0].never_verified);
    }

    #[tokio::test]
    async fn cleanup_keeps_verified_entries() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "acme.co.uk", "u1", "u1@example.com")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &org.id, "acme.co.uk")
            .await
            .unwrap();

        let removed = cleanup_stale_additional_domains(
            &store,
            jiff::Timestamp::now(),
            jiff::Span::new().hours(1), // aggressive TTL — verified must still be kept
            jiff::Span::new().hours(1),
        )
        .await
        .unwrap();
        assert!(removed.is_empty());
        assert_eq!(
            list_additional_domains(&store, &org.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// Regression for issue #380. `cleanup_stale_additional_domains` computes
    /// its removal candidate set from a [`list_all_paginated`] snapshot, but
    /// the actual delete happens later inside [`DocumentStore::modify`]. If
    /// the domain transitions Pending → Verified between those two phases,
    /// the modify closure must still preserve it. The closure body
    /// [`retain_non_verified_dropped`] enforces this invariant; this test
    /// exercises it directly with a `drop_candidates` set that targets a
    /// domain whose fresh state is `Verified`.
    #[test]
    fn retain_non_verified_dropped_preserves_freshly_verified_entry() {
        use super::super::documents::organization::{
            AdditionalDomain, AdditionalDomainState, OrganizationDoc,
        };

        let verified_at = jiff::Timestamp::now();
        let added_at = verified_at
            .checked_sub(jiff::Span::new().hours(10 * 24))
            .unwrap();
        let mut doc = OrganizationDoc {
            domain: "acme.com".to_string(),
            name: None,
            created_by_user_id: None,
            additional_domains: vec![
                AdditionalDomain {
                    // Modeled as "was Pending when the snapshot was taken,
                    // now Verified" — i.e., the admin verified it during
                    // the race window.
                    domain: "racy.example.com".to_string(),
                    verification_token: "tok".to_string(),
                    added_at,
                    added_by_user_id: "u1".to_string(),
                    added_by_email: "u1@example.com".to_string(),
                    consecutive_failures: 0,
                    state: AdditionalDomainState::Verified {
                        verified_at,
                        last_checked_at: None,
                    },
                },
                AdditionalDomain {
                    // A genuinely stale Pending entry that should still be
                    // removed even when other candidates are spared.
                    domain: "squat.example.com".to_string(),
                    verification_token: "tok2".to_string(),
                    added_at,
                    added_by_user_id: "u1".to_string(),
                    added_by_email: "u1@example.com".to_string(),
                    consecutive_failures: 0,
                    state: AdditionalDomainState::Pending,
                },
            ],
            subdomain: None,
        };

        let drop_candidates: std::collections::HashMap<String, bool> = vec![
            ("racy.example.com".to_string(), true),
            ("squat.example.com".to_string(), true),
        ]
        .into_iter()
        .collect();

        let removed = retain_non_verified_dropped(&mut doc, &drop_candidates);

        assert_eq!(
            removed,
            vec![("squat.example.com".to_string(), true)],
            "only the still-Pending entry should be reported as removed",
        );
        assert_eq!(doc.additional_domains.len(), 1);
        assert_eq!(doc.additional_domains[0].domain, "racy.example.com");
        assert!(matches!(
            doc.additional_domains[0].state,
            AdditionalDomainState::Verified { .. }
        ));
    }

    #[tokio::test]
    async fn recheck_unknown_domain_returns_not_found() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        let effect = record_recheck_result(
            &store,
            &org.id,
            "ghost.example.com",
            RecheckOutcome::Failure,
        )
        .await
        .unwrap();
        assert_eq!(effect, RecheckEffect::NotFound);
    }

    #[tokio::test]
    async fn remove_additional_domain_unknown_returns_none() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        let summary = remove_additional_domain(&store, &org.id, "never-added.example.com")
            .await
            .unwrap();
        assert!(summary.is_none());
    }

    #[tokio::test]
    async fn remove_additional_domain_revokes_matching_user_sessions() {
        use super::super::documents::session::{SessionDoc, SessionPurpose};
        use super::super::documents::user::UserDoc;
        use super::super::sessions::get_session_by_token_hash;

        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(
            &store,
            &org.id,
            "acme.co.uk",
            "u-admin",
            "admin@example.com",
        )
        .await
        .unwrap();
        mark_additional_domain_verified(&store, &org.id, "acme.co.uk")
            .await
            .unwrap();

        let mk_user = |email: &str| UserDoc {
            email: email.to_string(),
            name: None,
            org_id: Some(org.id.clone()),
            is_org_admin: false,
            active: true,
            external_id: None,
            github_id: None,
            github_login: None,
            github_refresh_token: None,
        };
        let matched_user = store.insert(&mk_user("alice@Acme.Co.UK")).await.unwrap();
        let other_user = store.insert(&mk_user("bob@acme.com")).await.unwrap();

        let in_one_hour = jiff::Timestamp::now()
            .checked_add(jiff::Span::new().hours(1))
            .unwrap();
        let mk_session = |user_id: String, email: String, hash: &str| SessionDoc {
            user_id,
            user_email: email,
            token_hash: hash.to_string(),
            authenticator_id: None,
            session_type: SessionPurpose::OAuthAccessToken,
            expires_at: in_one_hour,
            authorization_details: None,
            hardware_aaguid: None,
            org_domain: None,
        };
        store
            .insert(&mk_session(
                matched_user.id.clone(),
                "alice@Acme.Co.UK".to_string(),
                "hash-alice",
            ))
            .await
            .unwrap();
        store
            .insert(&mk_session(
                other_user.id.clone(),
                "bob@acme.com".to_string(),
                "hash-bob",
            ))
            .await
            .unwrap();

        let summary = remove_additional_domain(&store, &org.id, "acme.co.uk")
            .await
            .unwrap()
            .expect("entry was attached, must be removed");
        assert_eq!(
            summary.revoked_user_count, 1,
            "only the matching user should have sessions revoked"
        );

        assert!(
            get_session_by_token_hash(&store, "hash-alice")
                .await
                .unwrap()
                .is_none(),
            "matching user's session must be revoked"
        );
        assert!(
            get_session_by_token_hash(&store, "hash-bob")
                .await
                .unwrap()
                .is_some(),
            "non-matching user's session must survive"
        );

        // Membership (org_id) is intentionally not changed.
        let matched_after = store
            .get::<UserDoc>(&matched_user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(matched_after.data.org_id, Some(org.id.clone()));
    }

    #[tokio::test]
    async fn eligible_labels_from_primary_and_verified_only() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        // Pending additional domain must NOT contribute a label.
        add_additional_domain(&store, &org.id, "pending.io", "u1", "u1@acme.com")
            .await
            .unwrap();
        // Verified additional domain contributes its apex-derived label.
        add_additional_domain(&store, &org.id, "widgets.co.uk", "u1", "u1@acme.com")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &org.id, "widgets.co.uk")
            .await
            .unwrap();

        let org = get_organization(&store, &org.id).await.unwrap().unwrap();
        let labels = eligible_subdomain_labels(&org.domain, &org.additional_domains);
        assert_eq!(
            labels,
            vec!["acme-com".to_string(), "widgets-co-uk".to_string()]
        );
    }

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
    async fn removing_backing_domain_auto_releases_subdomain() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "widgets.io", "u1", "u1@example.com")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &org.id, "widgets.io")
            .await
            .unwrap();
        claim_subdomain(&store, &org.id, "widgets-io")
            .await
            .unwrap();

        let summary = remove_additional_domain(&store, &org.id, "widgets.io")
            .await
            .unwrap()
            .expect("domain removed");
        assert_eq!(summary.released_subdomain.as_deref(), Some("widgets-io"));

        let refreshed = get_organization(&store, &org.id).await.unwrap().unwrap();
        assert!(refreshed.subdomain.is_none(), "mirror must be cleared");
        let slot = store
            .get::<SubdomainClaimDoc>(&deterministic_subdomain_claim_id("widgets-io"))
            .await
            .unwrap()
            .unwrap();
        assert!(
            slot.data.released_at.is_some(),
            "slot must be released, starting the reuse cooldown"
        );
        // Discovery lookup must stop resolving.
        assert!(
            find_org_by_subdomain(&store, "widgets-io")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn removing_domain_keeps_subdomain_backed_by_another_domain() {
        let store = fresh_store().await;
        // Primary acme.com and verified mail.acme.com share the apex, so
        // both back "acme-com"; removing one backer must not release it.
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "mail.acme.com", "u1", "u1@example.com")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &org.id, "mail.acme.com")
            .await
            .unwrap();
        claim_subdomain(&store, &org.id, "acme-com").await.unwrap();

        let summary = remove_additional_domain(&store, &org.id, "mail.acme.com")
            .await
            .unwrap()
            .expect("domain removed");
        assert!(summary.released_subdomain.is_none());

        let refreshed = get_organization(&store, &org.id).await.unwrap().unwrap();
        assert_eq!(refreshed.subdomain.as_deref(), Some("acme-com"));
    }

    #[tokio::test]
    async fn unverify_flip_auto_releases_subdomain() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "widgets.io", "u1", "u1@example.com")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &org.id, "widgets.io")
            .await
            .unwrap();
        claim_subdomain(&store, &org.id, "widgets-io")
            .await
            .unwrap();

        let mut last_effect = RecheckEffect::StillVerified;
        for _ in 0..crate::db::UNVERIFY_FAILURE_THRESHOLD {
            last_effect =
                record_recheck_result(&store, &org.id, "widgets.io", RecheckOutcome::Failure)
                    .await
                    .unwrap();
        }
        assert_eq!(
            last_effect,
            RecheckEffect::FlippedToUnverified {
                released_subdomain: Some("widgets-io".to_string())
            }
        );

        let refreshed = get_organization(&store, &org.id).await.unwrap().unwrap();
        assert!(refreshed.subdomain.is_none(), "mirror must be cleared");
        let slot = store
            .get::<SubdomainClaimDoc>(&deterministic_subdomain_claim_id("widgets-io"))
            .await
            .unwrap()
            .unwrap();
        assert!(slot.data.released_at.is_some(), "slot must be released");
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

    /// Only `OccConflict` triggers retry; `Other` carries business or infra
    /// errors that must not loop.
    #[test]
    fn org_cas_error_retryability() {
        use crate::db::pool::RetryableError;

        assert!(OrgCasError::OccConflict.is_retryable());
        assert!(!OrgCasError::Other(anyhow::anyhow!("domain is already attached")).is_retryable());
    }

    /// All business-rejection variants of `AddDomainError` are terminal; only
    /// `OccConflict` (and DB-retryable infra errors wrapped in `Other`) loop.
    #[test]
    fn add_domain_error_retryability() {
        use crate::db::pool::RetryableError;

        assert!(AddDomainError::OccConflict.is_retryable());
        assert!(!AddDomainError::MaxDomains.is_retryable());
        assert!(!AddDomainError::PrimaryDomain.is_retryable());
        assert!(!AddDomainError::AlreadyAttached.is_retryable());
        assert!(!AddDomainError::ClaimedByOtherOrg.is_retryable());
        assert!(!AddDomainError::PendingOtherOrg.is_retryable());
        assert!(!AddDomainError::HeldByOtherOrg.is_retryable());
        assert!(!AddDomainError::InvalidDomain(DomainValidationError::NoDot).is_retryable());
        assert!(!AddDomainError::Other(anyhow::anyhow!("boom")).is_retryable());
    }

    /// `ClaimedByOtherOrg` is a terminal business rejection; only
    /// `OccConflict` and DB-retryable infra errors loop.
    #[test]
    fn mark_verified_error_retryability() {
        use crate::db::pool::RetryableError;

        assert!(MarkVerifiedError::OccConflict.is_retryable());
        assert!(!MarkVerifiedError::ClaimedByOtherOrg.is_retryable());
        assert!(!MarkVerifiedError::Other(anyhow::anyhow!("boom")).is_retryable());
    }

    /// When `record_recheck_result` exhausts its retry budget on CAS losses,
    /// it must map the exhaustion to `StillVerified` rather than surfacing an
    /// error. No flip was performed by this task; the winning writer's update
    /// is the ground truth.
    #[test]
    fn record_recheck_occ_exhaustion_maps_to_still_verified() {
        let result: Result<RecheckEffect, OrgCasError> = Err(OrgCasError::OccConflict);
        let effect = match result {
            Ok(e) => e,
            Err(OrgCasError::OccConflict) => RecheckEffect::StillVerified,
            Err(OrgCasError::Other(_)) => RecheckEffect::NotFound,
        };
        assert_eq!(effect, RecheckEffect::StillVerified);
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
