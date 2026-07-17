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
    // Runs OUTSIDE the user-creation transaction so the unique-violation
    // recovery path doesn't abort it. The deterministic ID makes concurrent
    // enrollees for the same domain race on the documents primary key, and
    // exactly one INSERT wins.
    //
    // Lookup falls back from deterministic ID to the domain index: rows with
    // random-UUID IDs (created before deterministic IDs) are only findable by
    // domain, and skipping the fallback would insert a duplicate org.
    //
    // If user creation later fails, the organization row may persist with
    // `created_by_user_id = None`. That is benign: the next enrollee for the
    // domain reuses the row and Step 4 sets them as admin via
    // `compare_and_update`.
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

    // Map a DB error from any tx operation into either an OccConflict (if it
    // signals writer contention) or a generic 500. OccConflict is retried by
    // with_dsql_retry!; the Internal path propagates.
    let map_db_err = |e: anyhow::Error, msg: &'static str| -> ServiceError {
        tracing::error!("{msg}: {e}");
        if crate::db::pool::is_retryable_db_error(&e) {
            ServiceError::OccConflict
        } else {
            ServiceError::Internal(msg.to_string())
        }
    };

    let result = crate::with_dsql_retry!(async {
        let mut tx = store
            .begin()
            .await
            .map_err(|e| map_db_err(e, "Failed to begin enrollment transaction"))?;

        // Step 2: Determine admin status
        let is_org_admin = if org_needs_admin {
            if let Some(ref oid) = org_id {
                let count = tx
                    .count::<UserDoc>("org_id", oid)
                    .await
                    .map_err(|e| map_db_err(e, "Failed to count org users"))?;
                count == 0
            } else {
                false
            }
        } else {
            false
        };

        // Step 3: Get or create user
        let existing_user = tx
            .find_one::<UserDoc>("email", email)
            .await
            .map_err(|e| map_db_err(e, "Failed to look up user by email"))?;

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
                let result = tx
                    .insert(&doc)
                    .await
                    .map_err(|e| map_db_err(e, "Failed to insert user"))?;
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
            && let Some(org_doc) = tx
                .get::<OrganizationDoc>(oid)
                .await
                .map_err(|e| map_db_err(e, "Failed to load organization"))?
        {
            if org_doc.data.created_by_user_id.is_none() {
                let mut data = org_doc.data;
                data.created_by_user_id = Some(user.id.clone());
                let won = tx
                    .compare_and_update(oid, org_doc.version, &data)
                    .await
                    .map_err(|e| map_db_err(e, "Failed to update organization admin"))?;
                admin_cas_outcome(won, is_org_admin, oid)?;
            } else if is_org_admin {
                // Another enrollee committed the admin slot between Step 2's
                // count and this read (READ COMMITTED lets each statement see
                // newer commits). A stale admin claim must abort and retry.
                admin_cas_outcome(false, true, oid)?;
            }
        }

        tx.commit()
            .await
            .map_err(|e| map_db_err(e, "Failed to commit enrollment transaction"))?;

        Ok::<_, ServiceError>(EnrollmentResult {
            user,
            org_id: org_id.clone(),
            is_org_admin,
        })
    })?;

    Ok(result)
}

/// Decide the outcome of the Step-4 admin CAS on the organization row.
///
/// Winning the CAS is a REQUIREMENT for committing a user row that claims
/// `is_org_admin = true`: the count-based admin decision in Step 2 is a
/// predicate read that concurrent transactions do not conflict on (write
/// skew under READ COMMITTED), so two first-enrollees can both compute
/// `is_org_admin = true`. The org-row CAS is the one write both must
/// collide on. A claiming loser aborts with `OccConflict` so
/// `with_dsql_retry!` re-runs the transaction; the retry re-counts (the
/// winner's user row is now visible), derives `is_org_admin = false`, and
/// commits a non-admin user.
///
/// A non-claiming loser (this enrollee never computed admin status) merely
/// raced the opportunistic `created_by_user_id` repair and proceeds.
fn admin_cas_outcome(won: bool, claimed_admin: bool, org_id: &str) -> Result<(), ServiceError> {
    if won || !claimed_admin {
        if !won {
            tracing::debug!(
                org_id = %org_id,
                "Lost race to repair org admin during enrollment — another enrollee won"
            );
        }
        return Ok(());
    }
    tracing::debug!(
        org_id = %org_id,
        "Lost race to claim org admin during enrollment — retrying as non-admin"
    );
    Err(ServiceError::OccConflict)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::{admin_cas_outcome, deterministic_org_id};

    /// Winning the CAS always commits, whether or not admin was claimed.
    #[test]
    fn admin_cas_outcome_winner_commits() {
        assert!(admin_cas_outcome(true, true, "org-1").is_ok());
        assert!(admin_cas_outcome(true, false, "org-1").is_ok());
    }

    /// A loser that claimed admin must abort with the one retryable error
    /// so `with_dsql_retry!` re-runs the transaction and re-derives the
    /// admin decision from fresh state.
    #[test]
    fn admin_cas_outcome_claiming_loser_is_retryable_conflict() {
        use crate::db::pool::RetryableError;
        use crate::error::ServiceError;

        let err = admin_cas_outcome(false, true, "org-1").expect_err("must abort");
        assert!(matches!(err, ServiceError::OccConflict));
        assert!(err.is_retryable(), "OccConflict must be retryable");
    }

    /// A loser that never claimed admin only raced the opportunistic
    /// `created_by_user_id` repair; committing is harmless.
    #[test]
    fn admin_cas_outcome_non_claiming_loser_commits() {
        assert!(admin_cas_outcome(false, false, "org-1").is_ok());
    }

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
