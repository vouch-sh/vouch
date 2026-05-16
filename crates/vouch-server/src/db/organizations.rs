// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Organization database operations.

use super::document_type::Document;
use super::documents::organization::{AdditionalDomain, OrganizationDoc};
use super::store::DocumentStore;
use anyhow::{Result, bail};
use aws_lc_rs::rand as aws_rand;
use jiff::Timestamp;

/// Maximum additional (non-primary) email domains per organization.
pub const MAX_ADDITIONAL_DOMAINS: usize = 10;

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

/// Validate the syntactic shape of a domain name.
///
/// Returns the normalized lowercase form on success. Rejects empty input,
/// non-ASCII characters, leading/trailing dots, double dots, labels longer
/// than 63 characters, total length over 253 characters, and labels with
/// invalid characters or leading/trailing hyphens.
pub fn normalize_domain(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("domain must not be empty");
    }
    if !trimmed.is_ascii() {
        bail!("domain must be ASCII (use punycode for internationalized domains)");
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
    Ok(lower)
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
    // Pending entries are not indexed, so we scan organization docs. The
    // verify step re-runs the verified-conflict check inside its own
    // transaction, so a race here only wastes the loser's DNS setup time.
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
        verified: false,
        added_at: now,
        added_by_user_id: added_by_user_id.to_string(),
        verified_at: None,
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

/// Re-fetch the verification token for a pending additional domain.
///
/// Returns `None` if no pending entry with that domain exists.
pub async fn get_pending_verification_token(
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
        .find(|ad| !ad.verified && ad.domain == normalized)
        .map(|ad| ad.verification_token))
}

/// Mark a pending additional domain as verified.
///
/// Caller must have already confirmed the DNS TXT record matches the
/// stored token. Re-runs the cross-org conflict check inside the
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

    if entry.verified {
        // Already verified — nothing to do.
        tx.commit().await?;
        return Ok(());
    }

    if let Some(other) = tx
        .find_one::<OrganizationDoc>("domain", &normalized)
        .await?
        && other.id != org_id
    {
        bail!("domain has been claimed by another organization since it was added");
    }

    entry.verified = true;
    entry.verified_at = Some(Timestamp::now());

    if !tx.compare_and_update(org_id, version, &data).await? {
        bail!("organization was modified concurrently; please retry");
    }
    tx.commit().await?;
    Ok(())
}

/// Remove an additional domain from an organization.
///
/// Users currently attached via this domain keep their `org_id`; only future
/// logins stop matching.
pub async fn remove_additional_domain(
    store: &DocumentStore,
    org_id: &str,
    domain: &str,
) -> Result<bool> {
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
        return Ok(false);
    }

    if !tx.compare_and_update(org_id, version, &data).await? {
        bail!("organization was modified concurrently; please retry");
    }
    tx.commit().await?;
    Ok(true)
}

/// Scan organization docs and return true if any *other* org has a pending
/// additional-domain entry for `domain`.
///
/// Pending entries are not indexed, so we walk org documents. A dedicated
/// pending-claim index is a future optimization if the org count grows.
async fn find_pending_claim_in_other_org(
    store: &DocumentStore,
    own_org_id: &str,
    domain: &str,
) -> Result<bool> {
    let candidates: Vec<Document<OrganizationDoc>> = store.list_all::<OrganizationDoc>().await?;
    for org in candidates {
        if org.id == own_org_id {
            continue;
        }
        if org
            .data
            .additional_domains
            .iter()
            .any(|ad| !ad.verified && ad.domain == domain)
        {
            return Ok(true);
        }
    }
    Ok(false)
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
        assert!(!list[0].verified);
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
        add_additional_domain(&store, &other.id, "shared.example", "user-other")
            .await
            .unwrap();

        let mine = create_organization(&store, "second.com", None, None)
            .await
            .unwrap();
        let err = add_additional_domain(&store, &mine.id, "shared.example", "user-mine")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("pending verification"));
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
        assert!(list[0].verified);
        assert!(list[0].verified_at.is_some());

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

        let removed = remove_additional_domain(&store, &org.id, "Acme.Co.UK")
            .await
            .unwrap();
        assert!(removed);

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
    async fn remove_additional_domain_unknown_returns_false() {
        let store = fresh_store().await;
        let org = create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        let removed = remove_additional_domain(&store, &org.id, "never-added.example")
            .await
            .unwrap();
        assert!(!removed);
    }
}
