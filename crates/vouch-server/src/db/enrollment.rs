// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Enrollment database operations.
//!
//! This module provides enrollment operations that ensure consistency
//! when creating organizations and users during the OIDC enrollment flow.

use super::documents::organization::OrganizationDoc;
use super::documents::user::UserDoc;
use super::store::DocumentStore;
use crate::error::ServiceError;
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

/// User record from enrollment.
#[derive(Debug)]
pub struct EnrolledUser {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub org_id: Option<String>,
    pub is_org_admin: bool,
}

/// Get or create the organization row for `domain`, returning its ID.
///
/// Runs OUTSIDE the user-creation transaction so the unique-violation
/// recovery path doesn't abort it. The deterministic ID makes concurrent
/// enrollees for the same domain race on the documents primary key, and
/// exactly one INSERT wins.
///
/// Lookup falls back from the deterministic ID to the domain index: rows
/// with random-UUID IDs (created before deterministic IDs) are only
/// findable by domain, and skipping the fallback would insert a duplicate
/// org.
///
/// If user creation later fails, the organization row may persist with
/// `created_by_user_id = None`. That is benign: the next enrollee for the
/// domain reuses the row and the enrollment transaction claims the admin
/// slot via `compare_and_update`.
async fn get_or_create_org(store: &DocumentStore, domain: &str) -> Result<String> {
    let id = deterministic_org_id(domain);
    let existing = match store.get::<OrganizationDoc>(&id).await? {
        Some(org) => Some(org),
        None => store.find_one::<OrganizationDoc>("domain", domain).await?,
    };
    if let Some(org) = existing {
        return Ok(org.id);
    }

    let doc = OrganizationDoc {
        domain: domain.to_string(),
        name: None,
        created_by_user_id: None,
        additional_domains: Vec::new(),
        subdomain: None,
    };
    match store.insert_with_id(&id, &doc).await {
        Ok(result) => Ok(result.id),
        Err(e) if super::pool::is_unique_violation(&e) => {
            // Concurrent enrollee inserted first — re-fetch.
            let org = match store.get::<OrganizationDoc>(&id).await? {
                Some(o) => o,
                None => store
                    .find_one::<OrganizationDoc>("domain", domain)
                    .await?
                    .context("organization vanished after unique violation")?,
            };
            Ok(org.id)
        }
        Err(e) => Err(e),
    }
}

/// Enroll a user with their organization.
///
/// This function:
/// 1. Gets or creates the organization for the user's domain, outside the
///    user-creation transaction (see [`get_or_create_org`])
/// 2. Inside a single retried transaction: reads one snapshot of the
///    organization row, derives the admin decision from it (first user of
///    an org whose admin slot is open), creates or gets the user, and
///    claims the admin slot via `compare_and_update` against that
///    snapshot's version
///
/// Deriving everything from one in-transaction snapshot means every
/// interleaving with a concurrent enrollee is caught by the single
/// version guard: a lost CAS while claiming admin aborts with
/// [`ServiceError::OccConflict`] and `with_dsql_retry!` re-runs the
/// transaction against fresh state. If the organization row was deleted
/// after step 1, the snapshot is `None` and the user is enrolled without
/// any admin claim.
pub async fn enroll_user_with_org(
    store: &DocumentStore,
    email: &str,
    name: Option<&str>,
    domain: Option<&str>,
) -> Result<EnrolledUser> {
    let org_id = match domain {
        Some(domain) => Some(get_or_create_org(store, domain).await?),
        None => None,
    };

    let result =
        crate::with_dsql_retry!(async {
            let mut tx = store.begin().await.map_err(|e| {
                ServiceError::from_db_contention(e, "Failed to begin enrollment transaction")
            })?;

            // One in-transaction snapshot of the org row: the admin-count
            // predicate, the CAS guard (id + version), and the CAS payload all
            // derive from it.
            let org = match &org_id {
                Some(oid) => tx.get::<OrganizationDoc>(oid).await.map_err(|e| {
                    ServiceError::from_db_contention(e, "Failed to load organization")
                })?,
                None => None,
            };
            // Carried forward only while the admin slot is open; encodes
            // "admin slot open ⇒ org exists" in the type.
            let claimable_org = org.filter(|o| o.data.created_by_user_id.is_none());

            let is_org_admin = match &claimable_org {
                Some(org_doc) => {
                    let count = tx
                        .count::<UserDoc>("org_id", &org_doc.id)
                        .await
                        .map_err(|e| {
                            ServiceError::from_db_contention(e, "Failed to count org users")
                        })?;
                    count == 0
                }
                None => false,
            };

            // Get or create user
            let existing_user = tx.find_one::<UserDoc>("email", email).await.map_err(|e| {
                ServiceError::from_db_contention(e, "Failed to look up user by email")
            })?;

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
                    let result = tx.insert(&doc).await.map_err(|e| {
                        ServiceError::from_db_contention(e, "Failed to insert user")
                    })?;
                    EnrolledUser {
                        id: result.id,
                        email: result.data.email,
                        name: result.data.name,
                        org_id: result.data.org_id,
                        is_org_admin: result.data.is_org_admin,
                    }
                }
            };

            // Claim (or repair) the org admin slot. Winning this CAS is a
            // REQUIREMENT for committing a user row that claims
            // `is_org_admin = true`: the count above is a predicate read that
            // concurrent transactions do not conflict on (write skew under READ
            // COMMITTED), so two first-enrollees can both compute
            // `is_org_admin = true` — the org-row version is the one write both
            // must collide on. A claiming loser aborts so `with_dsql_retry!`
            // re-runs the transaction; the retry re-reads fresh state (the
            // winner's user row and admin slot are now visible) and commits a
            // non-admin user. A non-claiming loser merely raced the
            // opportunistic `created_by_user_id` repair and proceeds.
            // Only a member of this org may occupy its admin slot. An existing
            // user keeps the `org_id` from their own row, so enrolling through
            // a domain that resolves to some other org would otherwise write
            // their id into that org's `created_by_user_id` — filling the slot
            // with a non-member and leaving the org's first real enrollee
            // permanently non-admin. A newly inserted user is always built with
            // this same `org_id`, so the legitimate first-admin claim still
            // passes.
            let claimable_org =
                claimable_org.filter(|org_doc| user.org_id.as_deref() == Some(org_doc.id.as_str()));

            if let Some(org_doc) = claimable_org {
                let mut data = org_doc.data;
                data.created_by_user_id = Some(user.id.clone());
                let won = tx
                    .compare_and_update(&org_doc.id, org_doc.version, &data)
                    .await
                    .map_err(|e| {
                        ServiceError::from_db_contention(e, "Failed to update organization admin")
                    })?;
                if !won && is_org_admin {
                    tracing::debug!(
                        org_id = %org_doc.id,
                        "Lost race to claim org admin during enrollment — retrying as non-admin"
                    );
                    return Err(ServiceError::OccConflict);
                }
                if !won {
                    tracing::debug!(
                        org_id = %org_doc.id,
                        "Lost race to repair org admin during enrollment — another enrollee won"
                    );
                }
            }

            tx.commit().await.map_err(|e| {
                ServiceError::from_db_contention(e, "Failed to commit enrollment transaction")
            })?;

            Ok::<_, ServiceError>(user)
        })?;

    Ok(result)
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
