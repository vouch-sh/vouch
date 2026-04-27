// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Organization database operations.

use super::document_type::Document;
use super::documents::organization::OrganizationDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

/// Organization record for domain-based multi-tenancy.
#[derive(Debug)]
pub struct Organization {
    pub id: String,
    pub domain: String,
    pub name: Option<String>,
    pub created_at: Timestamp,
    pub created_by_user_id: Option<String>,
}

impl From<Document<OrganizationDoc>> for Organization {
    fn from(doc: Document<OrganizationDoc>) -> Self {
        Self {
            id: doc.id,
            domain: doc.data.domain,
            name: doc.data.name,
            created_at: doc.created_at,
            created_by_user_id: doc.data.created_by_user_id,
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
    };
    let result = store.insert(&doc).await?;
    Ok(Organization::from(result))
}

/// Ensure an org document with the given ID exists, creating it if absent.
///
/// Used only by the certification test path to seed a stable org record
/// for the cert test user. The ID is treated as both the document ID and
/// domain so that it is deterministic and idempotent across test runs.
pub async fn ensure_cert_org(store: &DocumentStore, org_id: &str) -> Result<()> {
    if store.get::<OrganizationDoc>(org_id).await?.is_some() {
        return Ok(());
    }
    let doc = OrganizationDoc {
        domain: org_id.to_string(),
        name: Some("Certification Test Org".to_string()),
        created_by_user_id: None,
    };
    // Insert with a deterministic ID so concurrent callers converge.
    if let Err(e) = store.insert_with_id(org_id, &doc).await {
        // If another task raced us and won, the org now exists — that's fine.
        if store.get::<OrganizationDoc>(org_id).await?.is_none() {
            return Err(e);
        }
    }
    Ok(())
}

/// Get an organization's domain by ID.
pub async fn get_organization_domain(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Option<String>> {
    let doc = store.get::<OrganizationDoc>(org_id).await?;
    Ok(doc.map(|d| d.data.domain))
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
