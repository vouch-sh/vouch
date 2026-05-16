// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Organization database operations.

use super::document_type::Document;
use super::documents::organization::{AdditionalDomain, AdditionalDomainState, OrganizationDoc};
use super::store::DocumentStore;
use anyhow::{Result, bail};
use aws_lc_rs::rand as aws_rand;
use jiff::Timestamp;

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

/// Top-level labels that must never be accepted as an additional domain.
///
/// Verifying a TXT record under one of these would force the server's
/// resolver to query internal/loopback infrastructure (SSRF) or reserved
/// namespaces with no public ownership semantics:
///
/// - `localhost`, `local` — loopback / mDNS (RFC 6761, RFC 6762)
/// - `example`, `invalid`, `test` — reserved for documentation (RFC 6761)
/// - `internal` — ICANN-reserved for private use (2024)
/// - `arpa` — reverse-DNS root (covers `home.arpa`, `in-addr.arpa`, `ip6.arpa`)
/// - `onion` — Tor hidden services (RFC 7686)
/// - `alt` — pseudo-TLD reserved by RFC 9476
const RESERVED_TLDS: &[&str] = &[
    "localhost",
    "local",
    "example",
    "invalid",
    "test",
    "internal",
    "arpa",
    "onion",
    "alt",
];

/// Validate the syntactic shape of a domain name.
///
/// Returns the normalized lowercase form on success. Rejects empty input,
/// non-ASCII characters, leading/trailing dots, double dots, labels longer
/// than 63 characters, total length over 253 characters, labels with
/// invalid characters or leading/trailing hyphens, IP-address literals, and
/// reserved top-level labels (see [`RESERVED_TLDS`]).
pub fn normalize_domain(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("domain must not be empty");
    }
    if !trimmed.is_ascii() {
        bail!("domain must be ASCII (use punycode for internationalized domains)");
    }
    // Reject IP literals — these would point the resolver at a specific host
    // and bypass any TLD-level allow/deny logic. Also covers bracketed IPv6.
    let ip_candidate = trimmed.trim_start_matches('[').trim_end_matches(']');
    if ip_candidate.parse::<std::net::IpAddr>().is_ok() {
        bail!("domain must be a hostname, not an IP address");
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.len() > 253 {
        bail!("domain exceeds 253 characters");
    }
    if !lower.contains('.') {
        bail!("domain must contain at least one dot");
    }
    if lower.starts_with('.') || lower.ends_with('.') {
        bail!("domain must not start or end with a dot");
    }
    for label in lower.split('.') {
        if label.is_empty() {
            bail!("domain must not contain empty labels");
        }
        if label.len() > 63 {
            bail!("domain label exceeds 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("domain label must not start or end with a hyphen");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            bail!("domain label contains invalid characters");
        }
    }
    // Reject reserved/internal top-level labels. Iterating the constant is
    // a fixed-cost O(N) scan over a small list — clearer than a HashSet.
    let tld = lower.rsplit('.').next().unwrap_or("");
    if RESERVED_TLDS.contains(&tld) {
        bail!("domain uses a reserved or internal top-level label ('.{tld}')");
    }
    Ok(lower)
}

/// Return the Unicode form of a domain that contains punycode labels, or
/// `None` if the domain has no `xn--` labels (so the ASCII form is also the
/// display form).
///
/// Used by the admin UI to surface the human-readable rendering of an IDN
/// alongside the ASCII form, so a domain like `xn--acme-cua.com` is visibly
/// `àcme.com` to an admin reviewing the org's claims. Decoding failures
/// (malformed punycode) return `None` rather than erroring — display is a
/// hint, not authoritative.
#[must_use]
pub fn unicode_form(domain: &str) -> Option<String> {
    if !domain.split('.').any(|label| label.starts_with("xn--")) {
        return None;
    }
    let (decoded, errors) = idna::domain_to_unicode(domain);
    if errors.is_err() || decoded == domain {
        return None;
    }
    Some(decoded)
}

/// Generate a fresh verification token suitable for use in a DNS TXT record.
fn generate_verification_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    aws_rand::fill(&mut bytes).map_err(|_| anyhow::anyhow!("RNG failure"))?;
    Ok(hex::encode(bytes))
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
) -> Result<AddedDomain> {
    let normalized = normalize_domain(domain)?;

    // Pending-claim conflict check (non-transactional courtesy check).
    //
    // Pending entries are not indexed, so we walk organization docs to look
    // for existing pending claims on the same domain. This check runs
    // OUTSIDE the add transaction, so a true cross-org race is possible:
    // two admins from different orgs can both pass this check, both add the
    // domain as pending, and both publish TXT records. Only one will win at
    // verification time — the loser sees the "claimed by another organization"
    // error from `mark_additional_domain_verified` and must remove the
    // orphan from their org's domain list manually (or wait for GC).
    //
    // Folding this into the transaction would require a query path that
    // can scan pending entries; deferred until org count justifies it.
    let pending_conflict = find_pending_claim_in_other_org(store, org_id, &normalized).await?;
    if pending_conflict {
        bail!("domain has a pending verification claim on another organization");
    }

    let mut tx = store.begin().await?;

    let org_doc = tx
        .get::<OrganizationDoc>(org_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("organization not found"))?;
    let version = org_doc.version;
    let mut data = org_doc.data;

    if data.additional_domains.len() >= MAX_ADDITIONAL_DOMAINS {
        bail!(
            "organization already has the maximum of {MAX_ADDITIONAL_DOMAINS} additional domains"
        );
    }

    if data.domain.eq_ignore_ascii_case(&normalized) {
        bail!("domain is already the organization's primary domain");
    }
    if data
        .additional_domains
        .iter()
        .any(|ad| ad.domain == normalized)
    {
        bail!("domain is already attached to this organization");
    }

    // Conflict check against any other org's verified domain (primary or
    // additional). Verified entries appear in the document_indexes table.
    if let Some(other) = tx
        .find_one::<OrganizationDoc>("domain", &normalized)
        .await?
        && other.id != org_id
    {
        bail!("domain is already claimed by another organization");
    }

    let token = generate_verification_token()?;
    let now = Timestamp::now();
    data.additional_domains.push(AdditionalDomain {
        domain: normalized.clone(),
        verification_token: token.clone(),
        added_at: now,
        added_by_user_id: added_by_user_id.to_string(),
        consecutive_failures: 0,
        state: AdditionalDomainState::Pending,
    });

    if !tx.compare_and_update(org_id, version, &data).await? {
        bail!("organization was modified concurrently; please retry");
    }
    tx.commit().await?;

    Ok(AddedDomain {
        domain: normalized,
        verification_token: token,
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
) -> Result<()> {
    let normalized = normalize_domain(domain)?;

    let mut tx = store.begin().await?;

    let org_doc = tx
        .get::<OrganizationDoc>(org_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("organization not found"))?;
    let version = org_doc.version;
    let mut data = org_doc.data;

    let entry = data
        .additional_domains
        .iter_mut()
        .find(|ad| ad.domain == normalized)
        .ok_or_else(|| anyhow::anyhow!("domain is not attached to this organization"))?;

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
        bail!(
            "another organization verified this domain first; remove the pending entry from this org and contact support if you believe this is in error"
        );
    }

    // Reset re-verification state so a freshly re-verified entry is treated
    // identically to a brand-new verification by the background task.
    entry.state = AdditionalDomainState::Verified {
        verified_at: Timestamp::now(),
        last_checked_at: None,
    };
    entry.consecutive_failures = 0;

    if !tx.compare_and_update(org_id, version, &data).await? {
        bail!("organization was modified concurrently; please retry");
    }
    tx.commit().await?;
    Ok(())
}

/// Outcome of a successful `remove_additional_domain` call.
#[derive(Debug, Clone, Default)]
pub struct DomainRemovalSummary {
    /// Number of org users whose active sessions were revoked because their
    /// email domain matched the removed entry. `org_id` is intentionally
    /// left intact on those users — domain removal does not demote
    /// membership; admins must do that explicitly.
    pub revoked_user_count: u64,
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

    let mut tx = store.begin().await?;

    let org_doc = tx
        .get::<OrganizationDoc>(org_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("organization not found"))?;
    let version = org_doc.version;
    let mut data = org_doc.data;

    let original_len = data.additional_domains.len();
    data.additional_domains.retain(|ad| ad.domain != normalized);
    if data.additional_domains.len() == original_len {
        return Ok(None);
    }

    if !tx.compare_and_update(org_id, version, &data).await? {
        bail!("organization was modified concurrently; please retry");
    }
    tx.commit().await?;

    // Revoke sessions for org users whose email's domain matches the removed
    // entry. Done OUTSIDE the org-doc transaction: per-user session deletes
    // touch different rows, and a failure here must not undo the removal
    // (the domain is already gone from login matching). Log and continue.
    let revoked = revoke_sessions_for_domain_users(store, org_id, &normalized).await;
    let revoked_user_count = match revoked {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(
                error = %e,
                org_id = %org_id,
                domain = %normalized,
                "Domain removed, but session revocation for matching users failed"
            );
            0
        }
    };
    Ok(Some(DomainRemovalSummary { revoked_user_count }))
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

/// Garbage-collect additional-domain entries that have outlived their TTL.
///
/// Two categories are removed:
/// - **Pending squat**: `verified == false` AND `verified_at.is_none()` AND
///   `added_at` older than `pending_ttl`. Caps the cost of an admin who adds
///   a domain they don't own and never publishes the TXT record.
/// - **Auto-unverified drift**: `verified == false` AND `verified_at.is_some()`
///   AND `last_checked_at` older than `unverified_ttl`. Gives the admin a
///   grace period to fix DNS after a flip, then cleans up.
///
/// Verified entries are never removed by this function — they are owned by
/// the admin and re-verification handles drift detection.
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
            let domains_to_drop: std::collections::HashSet<String> =
                to_remove.iter().map(|(d, _)| d.clone()).collect();
            // Per-org error isolation: one failing modify (transient DB
            // error, version conflict, etc.) must not abort cleanup for
            // every org that follows. Log and continue; next tick retries.
            let updated = match store
                .modify::<OrganizationDoc, _>(&org.id, |doc| {
                    doc.additional_domains
                        .retain(|ad| !domains_to_drop.contains(&ad.domain));
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
                for (domain, never_verified) in to_remove {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecheckEffect {
    /// Counters updated, entry still verified.
    StillVerified,
    /// Consecutive-failure threshold reached; entry flipped to unverified.
    FlippedToUnverified,
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

    let mut tx = store.begin().await?;
    let Some(org_doc) = tx.get::<OrganizationDoc>(org_id).await? else {
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

    let effect = match outcome {
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
                RecheckEffect::FlippedToUnverified
            } else {
                entry.state = AdditionalDomainState::Verified {
                    verified_at,
                    last_checked_at: Some(now),
                };
                RecheckEffect::StillVerified
            }
        }
    };

    if !tx.compare_and_update(org_id, version, &data).await? {
        // Lost a race against another writer; the next periodic tick will
        // re-attempt, so swallow the conflict here.
        return Ok(RecheckEffect::StillVerified);
    }
    tx.commit().await?;
    Ok(effect)
}

/// Scan organization docs and return true if any *other* org has a pending
/// additional-domain entry for `domain`.
///
/// Pending entries are not indexed, so we page through org documents and
/// short-circuit on the first match.
async fn find_pending_claim_in_other_org(
    store: &DocumentStore,
    own_org_id: &str,
    domain: &str,
) -> Result<bool> {
    let mut cursor: Option<String> = None;
    loop {
        let (page, has_more) = store
            .list_all_paginated::<OrganizationDoc>(cursor.as_deref(), ORG_SCAN_PAGE_SIZE)
            .await?;
        if page.is_empty() {
            return Ok(false);
        }
        let next_cursor = page.last().map(|d| d.id.clone());
        for org in &page {
            if org.id == own_org_id {
                continue;
            }
            if org.data.additional_domains.iter().any(|ad| {
                ad.domain == domain && !matches!(ad.state, AdditionalDomainState::Verified { .. })
            }) {
                return Ok(true);
            }
        }
        if !has_more {
            return Ok(false);
        }
        cursor = next_cursor;
    }
}

/// Delete an organization and all associated data.
///
/// Performs application-level cascade deletes:
/// 1. Delete GitHub installations
/// 2. Delete SCIM tokens (with audit log SET NULL)
/// 3. Unlink OAuth clients (SET NULL org_id, downgrade scope)
/// 4. Unlink users (SET NULL org_id)
/// 5. Delete the organization
pub async fn delete_organization(store: &DocumentStore, org_id: &str) -> Result<bool> {
    use super::documents::github::GitHubInstallationDoc;
    use super::documents::oauth::OAuthClientDoc;
    use super::documents::scim::ScimTokenDoc;
    use super::documents::user::UserDoc;

    // 1. Delete GitHub installations
    store
        .delete_by_index::<GitHubInstallationDoc>("org_id", org_id)
        .await?;

    // 3. Delete SCIM tokens
    store
        .delete_by_index::<ScimTokenDoc>("org_id", org_id)
        .await?;

    // 4. Unlink OAuth clients (set org_id to None, downgrade scope)
    store
        .update_by_index::<OAuthClientDoc, _>("org_id", org_id, |d| {
            d.org_id = None;
            d.access_scope = super::documents::oauth::AccessScope::Personal;
        })
        .await?;

    // 5. Unlink users (set org_id to None, clear admin flag)
    store
        .update_by_index::<UserDoc, _>("org_id", org_id, |d| {
            d.org_id = None;
            d.is_org_admin = false;
        })
        .await?;

    // 6. Delete the organization
    store.delete(org_id).await?;
    Ok(true)
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
    use crate::test_utils::test_db;
    use std::sync::Arc;

    async fn fresh_store() -> DocumentStore {
        let pool = test_db().await;
        let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            Arc::new(PlaintextDocumentCrypto);
        DocumentStore::new(pool, crypto)
    }

    #[test]
    fn normalize_domain_lowercases() {
        assert_eq!(normalize_domain("Acme.Co.UK").unwrap(), "acme.co.uk");
        assert_eq!(normalize_domain("  EXAMPLE.com  ").unwrap(), "example.com");
    }

    #[test]
    fn normalize_domain_rejects_invalid() {
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("no-dot").is_err());
        assert!(normalize_domain(".leading.com").is_err());
        assert!(normalize_domain("trailing.com.").is_err());
        assert!(normalize_domain("double..dots.com").is_err());
        assert!(normalize_domain("-leading.com").is_err());
        assert!(normalize_domain("trailing-.com").is_err());
        assert!(normalize_domain("under_score.com").is_err());
        assert!(normalize_domain("уникод.com").is_err());
    }

    #[test]
    fn normalize_domain_rejects_ip_literals() {
        assert!(normalize_domain("127.0.0.1").is_err());
        assert!(normalize_domain("10.0.0.5").is_err());
        assert!(normalize_domain("169.254.169.254").is_err());
        assert!(normalize_domain("::1").is_err());
        assert!(normalize_domain("[::1]").is_err());
        assert!(normalize_domain("fe80::1").is_err());
    }

    #[test]
    fn normalize_domain_rejects_reserved_tlds() {
        for d in [
            "internal.corp.localhost",
            "metadata.google.internal",
            "service.local",
            "anything.arpa",
            "1.0.0.127.in-addr.arpa",
            "hostname.home.arpa",
            "thing.example",
            "name.invalid",
            "service.test",
            "abcdef.onion",
            "ipfs.alt",
        ] {
            assert!(
                normalize_domain(d).is_err(),
                "expected {d} to be rejected as reserved TLD"
            );
        }
    }

    #[test]
    fn normalize_domain_accepts_public_domains() {
        assert!(normalize_domain("acme.com").is_ok());
        assert!(normalize_domain("foo.bar.example.co.uk").is_ok());
        // xn-- punycode is allowed (homograph detection is out of scope).
        assert!(normalize_domain("xn--acme-cua.com").is_ok());
    }

    #[test]
    fn unicode_form_decodes_punycode() {
        // xn--bcher-kva is "bücher" in punycode.
        assert_eq!(
            unicode_form("xn--bcher-kva.example.com").as_deref(),
            Some("bücher.example.com"),
        );
    }

    #[test]
    fn unicode_form_returns_none_for_pure_ascii() {
        assert!(unicode_form("acme.com").is_none());
        assert!(unicode_form("foo.bar.example.co.uk").is_none());
    }

    #[test]
    fn unicode_form_returns_none_for_malformed_punycode() {
        // xn-- prefix but invalid encoding — display has no useful form.
        assert!(unicode_form("xn--.com").is_none());
    }

    #[tokio::test]
    async fn add_additional_domain_succeeds_and_is_pending() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        let added = add_additional_domain(&store, &org.id, "Acme.Co.UK", "user-1")
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
        let err = add_additional_domain(&store, &org.id, "acme.com", "user-1")
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
            add_additional_domain(&store, &org.id, &d, "user-1")
                .await
                .unwrap();
        }
        let err = add_additional_domain(&store, &org.id, "one-too-many.example.com", "user-1")
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
        let err = add_additional_domain(&store, &org.id, "acme.co.uk", "user-1")
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
        add_additional_domain(&store, &other.id, "shared.example.com", "user-other")
            .await
            .unwrap();

        let mine = create_organization(&store, "second.com", None, None)
            .await
            .unwrap();
        let err = add_additional_domain(&store, &mine.id, "shared.example.com", "user-mine")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("pending verification"));
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
                add_additional_domain(&store, &org.id, "wanted.example.com", "u")
                    .await
                    .unwrap();
            }
        }
        let mine = create_organization(&store, "mine.example.com", None, None)
            .await
            .unwrap();
        let err = add_additional_domain(&store, &mine.id, "wanted.example.com", "u")
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
        add_additional_domain(&store, &org.id, "acme.co.uk", "user-1")
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
        add_additional_domain(&store, &org.id, "acme.co.uk", "user-1")
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
        add_additional_domain(&store, &org.id, "acme.co.uk", "u1")
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "acme.eu", "u1")
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
        add_additional_domain(&store, &org.id, "acme.co.uk", "u1")
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
        add_additional_domain(&store, &org.id, "acme.co.uk", "u1")
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
        assert_eq!(last_effect, RecheckEffect::FlippedToUnverified);

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
        add_additional_domain(&store, &org.id, "acme.co.uk", "u1")
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
        add_additional_domain(&store, &org.id, "fresh.example.com", "u1")
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
        add_additional_domain(&store, &org.id, "acme.co.uk", "u1")
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
        add_additional_domain(&store, &org.id, "acme.co.uk", "u-admin")
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
}
