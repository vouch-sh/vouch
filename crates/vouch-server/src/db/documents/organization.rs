// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Organization document type.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// An organization (tenant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationDoc {
    pub domain: String,
    pub name: Option<String>,
    pub created_by_user_id: Option<String>,
    /// Additional email domains owned by the organization.
    ///
    /// Each entry must complete DNS TXT ownership verification before it
    /// participates in login matching. Pending entries are stored on the
    /// document but are not indexed.
    #[serde(default)]
    pub additional_domains: Vec<AdditionalDomain>,
    /// Subdomain label claimed as this org's OIDC issuer host for AWS
    /// workload identity federation (e.g. `acme` → `https://acme.us.vouch.sh`).
    ///
    /// Must correspond to the first label of one of the org's verified
    /// domains. Indexed for host→org lookup when serving discovery. The
    /// authoritative uniqueness record is the [`SubdomainClaimDoc`] slot;
    /// this field is the org-side mirror written in the same transaction.
    #[serde(default)]
    pub subdomain: Option<String>,
}

/// The claim slot for an issuer-subdomain label.
///
/// Stored under a **deterministic document ID** derived from the label, so
/// the `documents` primary key is what makes cross-org claims collide:
/// concurrent claimants either hit a unique violation on insert or a
/// version conflict on `compare_and_update` — an indexed lookup alone
/// cannot enforce cross-row uniqueness (the index only unique-constrains
/// per document). Same pattern as `deterministic_org_id` in enrollment.
///
/// The slot survives release (`released_at = Some`) and doubles as the
/// reuse-cooldown tombstone: a different org taking over a released slot
/// must `compare_and_update` the same row, so cooldown checks are atomic
/// with the takeover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainClaimDoc {
    /// The claimed label (normalized lowercase).
    pub label: String,
    /// The organization currently or most recently holding the label.
    pub org_id: String,
    /// `None` while the claim is active; `Some(release time)` after the
    /// holder released it (starts the cross-org reuse cooldown).
    pub released_at: Option<Timestamp>,
}

impl DocumentType for SubdomainClaimDoc {
    const DOC_TYPE: &'static str = "subdomain_claim";

    fn index_entries(&self) -> Vec<IndexEntry> {
        // Looked up exclusively by deterministic document ID.
        Vec::new()
    }
}

/// Lifecycle state of an [`AdditionalDomain`].
///
/// Modeled as an enum so each state carries exactly the timestamps relevant
/// to it — invalid combinations (e.g., "verified but never verified_at") are
/// unrepresentable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AdditionalDomainState {
    /// Added but never verified. TXT record has not been observed.
    Pending,
    /// DNS TXT ownership confirmed; entry participates in login matching.
    Verified {
        verified_at: Timestamp,
        /// Last time the background re-verification task checked this domain.
        /// `None` means it has not yet been re-checked since verification.
        #[serde(default)]
        last_checked_at: Option<Timestamp>,
    },
    /// Was verified at some point but flipped back to unverified after
    /// repeated DNS recheck failures. Eligible for admin re-verification or
    /// auto-removal after the unverified TTL elapses.
    Unverified {
        /// When the entry was originally verified, before being flipped.
        verified_at: Timestamp,
        /// When the failing re-check that caused the flip ran.
        last_checked_at: Timestamp,
    },
}

/// A secondary email domain claimed by an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdditionalDomain {
    /// Normalized lowercase ASCII domain.
    pub domain: String,
    /// Random hex token the admin must publish as `_vouch-verification.<domain>` TXT.
    pub verification_token: String,
    pub added_at: Timestamp,
    pub added_by_user_id: String,
    /// Email of the admin who added this entry, denormalized at write time
    /// so the admin UI doesn't need a per-row user lookup. May go stale if
    /// the user's email is changed later (acceptable: same trade-off as
    /// `SessionDoc.user_email`).
    pub added_by_email: String,
    /// Consecutive re-verification failures. Reset to 0 on a successful check.
    /// At [`UNVERIFY_FAILURE_THRESHOLD`] the entry flips to `Unverified`.
    #[serde(default)]
    pub consecutive_failures: u32,
    pub state: AdditionalDomainState,
}

/// Number of consecutive failed re-verifications before an entry is flipped
/// back to unverified.
pub const UNVERIFY_FAILURE_THRESHOLD: u32 = 3;

impl DocumentType for OrganizationDoc {
    const DOC_TYPE: &'static str = "organization";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let cap = self.additional_domains.len().saturating_add(2);
        let mut entries = Vec::with_capacity(cap);
        entries.push(IndexEntry {
            field: "domain",
            value: self.domain.clone(),
        });
        for ad in &self.additional_domains {
            if matches!(ad.state, AdditionalDomainState::Verified { .. }) {
                entries.push(IndexEntry {
                    field: "domain",
                    value: ad.domain.clone(),
                });
            }
        }
        if let Some(label) = &self.subdomain {
            entries.push(IndexEntry {
                field: "subdomain",
                value: label.clone(),
            });
        }
        entries
    }
}
