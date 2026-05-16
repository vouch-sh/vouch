// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Enrollment database operations.
//!
//! This module provides enrollment operations that ensure consistency
//! when creating organizations and users during the OIDC enrollment flow.

use super::documents::organization::OrganizationDoc;
use super::documents::user::UserDoc;
use super::store::DocumentStore;
use anyhow::Result;

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

/// Enroll a user with their organization atomically.
///
/// This function:
/// 1. Gets or creates the organization for the user's domain
/// 2. Determines if the user should be an org admin (first user)
/// 3. Creates or gets the user with the org association
/// 4. Updates the org's `created_by_user_id` if first user
///
/// All steps execute within a single database transaction.
pub async fn enroll_user_with_org(
    store: &DocumentStore,
    email: &str,
    name: Option<&str>,
    domain: Option<&str>,
) -> Result<EnrollmentResult> {
    let mut tx = store.begin().await?;

    // Step 1: Get or create organization (if domain provided)
    let (org_id, org_needs_admin) = if let Some(domain) = domain {
        let existing = tx.find_one::<OrganizationDoc>("domain", domain).await?;

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
                };
                let result = tx.insert(&doc).await?;
                (Some(result.id), true)
            }
        }
    } else {
        (None, false)
    };

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
