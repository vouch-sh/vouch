// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Organization database operations.

use super::document_type::Document;
use super::documents::organization::{AdditionalDomain, AdditionalDomainState, OrganizationDoc};
use super::store::DocumentStore;
use anyhow::Result;

mod validation;
use jiff::Timestamp;
mod domains;
pub use domains::{
    AddDomainError, AddedDomain, DomainRemovalSummary, MAX_ADDITIONAL_DOMAINS, MarkVerifiedError,
    RecheckEffect, RecheckOutcome, StaleDomainRemoval, VerifiedDomainRecord, add_additional_domain,
    cleanup_stale_additional_domains, get_verification_token, list_additional_domains,
    list_all_verified_additional_domains, mark_additional_domain_verified, record_recheck_result,
    remove_additional_domain,
};
mod issuer;
pub use issuer::{
    SUBDOMAIN_REUSE_COOLDOWN_SECS, SubdomainClaimError, any_subdomain_claimed, claim_subdomain,
    deterministic_org_key_id, find_org_by_subdomain, get_org_signing_key, list_org_signing_keys,
    release_subdomain, try_insert_org_signing_key,
};
pub use validation::{
    DomainValidationError, RESERVED_SUBDOMAIN_LABELS, SubdomainLabelError,
    eligible_subdomain_labels, ineligible_subdomain_candidates, normalize_domain, unicode_form,
    validate_subdomain_label,
};

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

impl Organization {
    /// Every domain that participates in login matching for this org: the
    /// primary domain plus any additional domain that has completed DNS
    /// TXT verification. Pending and unverified additional domains are
    /// excluded — mirrors the set `OrganizationDoc::index_entries` indexes.
    ///
    /// Used to scope audit-event reads to an org: filtering by only the
    /// primary domain misses events for users on a verified additional
    /// domain.
    #[must_use]
    pub fn matching_email_domains(&self) -> Vec<String> {
        let mut domains = Vec::with_capacity(self.additional_domains.len().saturating_add(1));
        domains.push(self.domain.clone());
        for ad in &self.additional_domains {
            if matches!(ad.state, AdditionalDomainState::Verified { .. }) {
                domains.push(ad.domain.clone());
            }
        }
        domains
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

/// Whether `org_id` has proven ownership of `domain` — its primary domain
/// or a verified additional domain (see [`OrganizationDoc::verified_domains`]).
///
/// Membership is checked ASCII-case-insensitively, but `domain` is otherwise
/// compared as given — no trimming, and no shape validation like
/// [`normalize_domain`]. Ownership was already decided when a domain
/// entered the set (the primary domain at org creation, an additional
/// domain at DNS TXT verification); re-validating shape here would only
/// create asymmetry, since neither side of the comparison is guaranteed to
/// have passed `normalize_domain` (a primary domain from on-prem/AD-derived
/// enrollment can be a reserved-TLD or IDN address). Not trimming means a
/// candidate with stray whitespace never matches, rather than being
/// silently repaired.
///
/// A nonexistent org is treated as owning nothing rather than an error,
/// since the caller (SCIM user creation) has already authenticated the org
/// via its token and only needs a yes/no membership answer.
pub async fn org_owns_verified_domain(
    store: &DocumentStore,
    org_id: &str,
    domain: &str,
) -> Result<bool> {
    let Some(doc) = store.get::<OrganizationDoc>(org_id).await? else {
        return Ok(false);
    };
    Ok(doc
        .data
        .verified_domains()
        .any(|d| d.eq_ignore_ascii_case(domain)))
}
/// Shared test fixture: a fresh document store on the test database.
#[cfg(test)]
pub(super) async fn fresh_store() -> DocumentStore {
    let pool = crate::test_utils::test_db().await;
    let crypto: std::sync::Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
        std::sync::Arc::new(crate::crypto::document_crypto::PlaintextDocumentCrypto);
    DocumentStore::new(pool, crypto)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::issuer::deterministic_subdomain_claim_id;
    use super::*;
    use crate::db::documents::organization::SubdomainClaimDoc;
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
    async fn org_owns_verified_domain_true_for_primary_domain() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();

        assert!(
            org_owns_verified_domain(&store, &org.id, "acme.com")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn org_owns_verified_domain_true_for_verified_additional_domain() {
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

        assert!(
            org_owns_verified_domain(&store, &org.id, "widgets.io")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn org_owns_verified_domain_false_for_pending_additional_domain() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "widgets.io", "u1", "u1@acme.com")
            .await
            .unwrap();

        assert!(
            !org_owns_verified_domain(&store, &org.id, "widgets.io")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn org_owns_verified_domain_false_for_unowned_domain() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();

        assert!(
            !org_owns_verified_domain(&store, &org.id, "other-corp.com")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn org_owns_verified_domain_false_for_nonexistent_org() {
        let store = fresh_store().await;

        assert!(
            !org_owns_verified_domain(&store, "does-not-exist", "acme.com")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn org_owns_verified_domain_is_case_insensitive() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();

        assert!(
            org_owns_verified_domain(&store, &org.id, "ACME.COM")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn org_owns_verified_domain_does_not_validate_candidate_shape() {
        // A reserved-TLD primary domain (realistic for on-prem/AD-derived
        // enrollment) is stored as-is; the ownership check is set
        // membership, not a re-run of normalize_domain, so it still
        // matches rather than permanently locking the org out.
        let store = fresh_store().await;
        let org = create_organization(&store, "corp.internal", None, None)
            .await
            .unwrap();

        assert!(
            org_owns_verified_domain(&store, &org.id, "corp.internal")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn org_owns_verified_domain_false_for_whitespace_padded_candidate() {
        // No trimming: a candidate that needs whitespace stripped to match
        // is rejected rather than silently repaired.
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();

        assert!(
            !org_owns_verified_domain(&store, &org.id, " acme.com")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn matching_email_domains_includes_primary_and_verified_only() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "verified.io", "u1", "u1@acme.com")
            .await
            .unwrap();
        mark_additional_domain_verified(&store, &org.id, "verified.io")
            .await
            .unwrap();
        add_additional_domain(&store, &org.id, "pending.io", "u1", "u1@acme.com")
            .await
            .unwrap();

        let refreshed = get_organization(&store, &org.id).await.unwrap().unwrap();
        let domains = refreshed.matching_email_domains();

        assert!(
            domains.contains(&"acme.com".to_string()),
            "must include primary domain"
        );
        assert!(
            domains.contains(&"verified.io".to_string()),
            "must include verified additional domain"
        );
        assert!(
            !domains.contains(&"pending.io".to_string()),
            "must exclude pending (unverified) additional domain"
        );
        assert_eq!(domains.len(), 2);
    }
}
