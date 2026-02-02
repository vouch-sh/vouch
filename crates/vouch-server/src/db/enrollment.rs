// SPDX-License-Identifier: BUSL-1.1
//! Enrollment database operations with transactional guarantees.
//!
//! This module provides atomic enrollment operations that ensure consistency
//! when creating organizations and users during the OIDC enrollment flow.

use super::Pool;
use super::compat::BuildSql;
use super::schema::{Organizations, Users};
use super::types::DbTimestamp;
use crate::{tx_execute, tx_fetch_one, tx_fetch_optional};
use anyhow::Result;
use jiff::Timestamp;
use sea_query::{Expr, OnConflict, Query};
use uuid::Uuid;

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
#[derive(Debug, sqlx::FromRow)]
pub struct EnrolledUser {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub org_id: Option<String>,
    pub is_org_admin: bool,
}

/// Organization record for enrollment.
#[derive(Debug, sqlx::FromRow)]
struct EnrollmentOrg {
    id: String,
    #[allow(dead_code)]
    domain: String,
    #[allow(dead_code)]
    created_at: DbTimestamp,
    created_by_user_id: Option<String>,
}

/// Enroll a user with their organization in a single transaction.
///
/// This function atomically:
/// 1. Gets or creates the organization for the user's domain
/// 2. Determines if the user should be an org admin (first user in org)
/// 3. Creates or gets the user with the org association
/// 4. Updates the org's `created_by_user_id` if this is the first user
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `email` - User's email address
/// * `name` - Optional display name
/// * `domain` - The hosted domain from OIDC (e.g., "acme.com"), or None for personal accounts
///
/// # Returns
///
/// Returns an `EnrollmentResult` with the user, org_id, and admin status.
///
/// # Errors
///
/// Returns an error if any database operation fails. The transaction is
/// automatically rolled back on error.
pub async fn enroll_user_with_org(
    pool: &Pool,
    email: &str,
    name: Option<&str>,
    domain: Option<&str>,
) -> Result<EnrollmentResult> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();

    // Step 1: Get or create organization (if domain provided)
    let (org_id, org_needs_admin) = if let Some(domain) = domain {
        // Check if org exists
        let select_org_sql = {
            let query = Query::select()
                .columns([
                    Organizations::Id,
                    Organizations::Domain,
                    Organizations::CreatedAt,
                    Organizations::CreatedByUserId,
                ])
                .from(Organizations::Table)
                .and_where(Expr::col(Organizations::Domain).eq(domain))
                .to_owned();
            query.build_sql(db_type)
        };

        let existing_org: Option<EnrollmentOrg> =
            tx_fetch_optional!(tx, sqlx::query_as(&select_org_sql))?;

        match existing_org {
            Some(org) => {
                // Org exists - check if it needs an admin (created_by_user_id is null)
                let needs_admin = org.created_by_user_id.is_none();
                (Some(org.id), needs_admin)
            }
            None => {
                // Create new org
                let org_id = Uuid::now_v7().to_string();
                let now = Timestamp::now().to_string();
                let insert_org_sql = {
                    let query = Query::insert()
                        .into_table(Organizations::Table)
                        .columns([
                            Organizations::Id,
                            Organizations::Domain,
                            Organizations::CreatedAt,
                        ])
                        .values_panic([
                            org_id.clone().into(),
                            domain.into(),
                            now.as_str().into(),
                        ])
                        .to_owned();
                    query.build_sql(db_type)
                };
                tx_execute!(tx, sqlx::query(&insert_org_sql))?;
                (Some(org_id), true) // New org, first user becomes admin
            }
        }
    } else {
        // No domain = personal account, no org
        (None, false)
    };

    // Step 2: Determine admin status
    // User is admin if: org needs an admin AND there are no existing users in the org
    let is_org_admin = if org_needs_admin {
        if let Some(ref oid) = org_id {
            // Count existing users in this org
            let count_sql = {
                let query = Query::select()
                    .expr(Expr::col(Users::Id).count())
                    .from(Users::Table)
                    .and_where(Expr::col(Users::OrgId).eq(oid.as_str()))
                    .to_owned();
                query.build_sql(db_type)
            };
            let (count,): (i64,) = tx_fetch_one!(tx, sqlx::query_as(&count_sql))?;
            count == 0
        } else {
            false
        }
    } else {
        false
    };

    // Step 3: Upsert user with org info
    let user_id = Uuid::now_v7().to_string();
    let now = Timestamp::now().to_string();
    let insert_user_sql = {
        let query = Query::insert()
            .into_table(Users::Table)
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::OrgId,
                Users::IsOrgAdmin,
                Users::CreatedAt,
            ])
            .values_panic([
                user_id.clone().into(),
                email.into(),
                name.into(),
                org_id.clone().into(),
                is_org_admin.into(),
                now.as_str().into(),
            ])
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&insert_user_sql))?;

    // Fetch the user (might be existing user if insert was ignored)
    let fetch_user_sql = {
        let query = Query::select()
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::OrgId,
                Users::IsOrgAdmin,
            ])
            .from(Users::Table)
            .and_where(Expr::col(Users::Email).eq(email))
            .to_owned();
        query.build_sql(db_type)
    };
    let user: EnrolledUser = tx_fetch_one!(tx, sqlx::query_as(&fetch_user_sql))?;

    // Step 4: If this user became the admin, update org's created_by_user_id
    if is_org_admin
        && let Some(ref oid) = org_id
    {
        let update_org_sql = {
            let query = Query::update()
                .table(Organizations::Table)
                .value(Organizations::CreatedByUserId, user.id.clone())
                .and_where(Expr::col(Organizations::Id).eq(oid.as_str()))
                .and_where(Expr::col(Organizations::CreatedByUserId).is_null())
                .to_owned();
            query.build_sql(db_type)
        };
        tx_execute!(tx, sqlx::query(&update_org_sql))?;
    }

    // Commit the transaction
    tx.commit().await?;

    Ok(EnrollmentResult {
        user,
        org_id,
        is_org_admin,
    })
}
