// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Enrollment database operations.
//!
//! This module provides enrollment operations that ensure consistency
//! when creating organizations and users during the OIDC enrollment flow.

use super::documents::organization::OrganizationDoc;
use super::documents::user::UserDoc;
use super::store::DocumentStore;
use anyhow::{Context, Result};

/// Derive a deterministic document ID from a domain so that two
/// concurrent enrollments for the same domain collide on the primary
/// key of the `documents` table instead of producing two organizations.
///
/// The unique constraint on `(document_id, index_field, index_value)`
/// does NOT enforce uniqueness across documents on `(index_field,
/// index_value)`, so a check-then-insert flow that generated random IDs
/// could not be made race-free at the SQL level. Hashing the domain
/// into a stable ID closes the TOCTOU window without requiring
/// SERIALIZABLE isolation or an advisory lock.
fn deterministic_org_id(domain: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"organization_domain\0");
    ctx.update(domain.as_bytes());
    hex::encode(ctx.finish().as_ref())
}

/// Result of enrolling a user with their organization.
#[derive(Debug)]
pub struct EnrollmentResult {
    /// The user record (created or existing).
    pub user: EnrolledUser,
    /// The organization ID if the user belongs to one.
    pub org_id: Option<String>,
    /// Whether this user is the organization admin.
    pub is_org_admin: bool,
}

/// User record from enrollment.
#[derive(Debug)]
pub struct EnrolledUser {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub org_id: Option<String>,
    pub is_org_admin: bool,
}

/// Enroll a user with their organization.
///
/// This function:
/// 1. Gets or creates the organization for the user's domain
/// 2. Determines if the user should be an org admin (first user)
/// 3. Creates or gets the user with the org association
/// 4. Updates the org's `created_by_user_id` if first user
///
/// Steps 2-4 run inside a single transaction. Step 1 runs outside the
/// transaction so that a primary-key collision from a concurrent
/// enrollment for the same domain can be recovered from without
/// aborting the user-creation transaction (see the inline comment for
/// the atomicity tradeoff).
pub async fn enroll_user_with_org(
    store: &DocumentStore,
    email: &str,
    name: Option<&str>,
    domain: Option<&str>,
) -> Result<EnrollmentResult> {
    // Step 1: Get or create organization (if domain provided).
    //
    // Runs OUTSIDE the user-creation transaction so that the unique-violation
    // recovery path doesn't abort the transaction. The deterministic ID
    // guarantees that two concurrent enrollees for the same domain race on
    // the documents primary key, and exactly one INSERT wins.
    //
    // Lookup order:
    //   1. By deterministic ID — the fast path for new orgs.
    //   2. By domain index — required for orgs created before this code
    //      existed (random UUIDs); without this fallback the new code
    //      would create a duplicate alongside the legacy row.
    //
    // If user creation later fails, the organization row may persist with
    // `created_by_user_id = None`. That is a benign intermediate state: the
    // next enrollee for the same domain will reuse the row and Step 4 below
    // will set them as admin via `compare_and_update`.
    let (org_id, org_needs_admin) = if let Some(domain) = domain {
        let id = deterministic_org_id(domain);
        let existing = match store.get::<OrganizationDoc>(&id).await? {
            Some(org) => Some(org),
            None => store.find_one::<OrganizationDoc>("domain", domain).await?,
        };

        match existing {
            Some(org) => {
                let needs_admin = org.data.created_by_user_id.is_none();
                (Some(org.id), needs_admin)
            }
            None => {
                let doc = OrganizationDoc {
                    domain: domain.to_string(),
                    name: None,
                    created_by_user_id: None,
                    additional_domains: Vec::new(),
                    subdomain: None,
                };
                match store.insert_with_id(&id, &doc).await {
                    Ok(result) => (Some(result.id), true),
                    Err(e) if super::pool::is_unique_violation(&e) => {
                        // Concurrent enrollee inserted first — re-fetch.
                        let org = match store.get::<OrganizationDoc>(&id).await? {
                            Some(o) => o,
                            None => store
                                .find_one::<OrganizationDoc>("domain", domain)
                                .await?
                                .context("organization vanished after unique violation")?,
                        };
                        let needs_admin = org.data.created_by_user_id.is_none();
                        (Some(org.id), needs_admin)
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    } else {
        (None, false)
    };

    let mut tx = store.begin().await?;

    // Step 2: Determine admin status
    let is_org_admin = if org_needs_admin {
        if let Some(ref oid) = org_id {
            let count = tx.count::<UserDoc>("org_id", oid).await?;
            count == 0
        } else {
            false
        }
    } else {
        false
    };

    // Step 3: Get or create user
    let existing_user = tx.find_one::<UserDoc>("email", email).await?;

    let user = match existing_user {
        Some(doc) => EnrolledUser {
            id: doc.id,
            email: doc.data.email,
            name: doc.data.name,
            org_id: doc.data.org_id,
            is_org_admin: doc.data.is_org_admin,
        },
        None => {
            let doc = UserDoc {
                email: email.to_string(),
                name: name.map(String::from),
                org_id: org_id.clone(),
                is_org_admin,
                active: true,
                external_id: None,
                github_id: None,
                github_login: None,
                github_refresh_token: None,
            };
            let result = tx.insert(&doc).await?;
            EnrolledUser {
                id: result.id,
                email: result.data.email,
                name: result.data.name,
                org_id: result.data.org_id,
                is_org_admin: result.data.is_org_admin,
            }
        }
    };

    // Step 4: Ensure org has an admin. Uses compare_and_update so that
    // only one concurrent enrollee wins the admin slot. On re-run after a
    // crash, this also repairs a missing created_by_user_id.
    if let Some(ref oid) = org_id
        && let Some(org_doc) = tx.get::<OrganizationDoc>(oid).await?
        && org_doc.data.created_by_user_id.is_none()
    {
        let mut data = org_doc.data;
        data.created_by_user_id = Some(user.id.clone());
        // Optimistic lock: if another enrollment already set the admin,
        // compare_and_update returns false (version mismatch) and we
        // harmlessly skip — the first enrollee wins the admin role.
        let won = tx.compare_and_update(oid, org_doc.version, &data).await?;
        if !won {
            tracing::debug!(
                org_id = %oid,
                "Lost race to set org admin during enrollment — another enrollee won"
            );
        }
    }

    tx.commit().await?;

    Ok(EnrollmentResult {
        user,
        org_id,
        is_org_admin,
    })
}

#[cfg(test)]
mod tests {
    use super::deterministic_org_id;

    #[test]
    fn deterministic_org_id_collides_on_equal_domains() {
        // Two callers passing the same domain string must produce the
        // same document ID — this is what makes `store.insert_with_id`
        // surface a unique-violation race instead of silently creating
        // a second organization row.
        assert_eq!(
            deterministic_org_id("acme.example"),
            deterministic_org_id("acme.example"),
        );
    }

    #[test]
    fn deterministic_org_id_differs_for_distinct_domains() {
        assert_ne!(
            deterministic_org_id("acme.example"),
            deterministic_org_id("beta.example"),
        );
    }

    #[test]
    fn deterministic_org_id_is_case_sensitive() {
        // Documents an existing assumption: callers (the OIDC IdP layer
        // in particular) are responsible for normalising the domain to
        // ASCII lowercase before calling `enroll_user_with_org`. If a
        // future caller forgets to normalise, two cases of the same
        // domain will produce two organizations — this assertion is a
        // tripwire that pins the current contract.
        assert_ne!(
            deterministic_org_id("ACME.example"),
            deterministic_org_id("acme.example"),
        );
    }
}
