// SPDX-License-Identifier: BUSL-1.1
//! Organization database operations.

use super::Pool;
use crate::{db_execute, db_fetch_all, db_fetch_one, db_fetch_optional, tx_execute, tx_fetch_all};
use anyhow::Result;
use uuid::Uuid;

/// Organization record for domain-based multi-tenancy.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct Organization {
    pub id: String,
    pub domain: String,
    pub name: Option<String>,
    pub created_at: String,
    pub created_by_user_id: Option<String>,
}

/// Get an organization by domain.
pub async fn get_org_by_domain(pool: &Pool, domain: &str) -> Result<Option<Organization>> {
    let org = db_fetch_optional!(
        pool,
        sqlx::query_as::<_, Organization>(
            "SELECT id, domain, name, created_at, created_by_user_id FROM organizations WHERE domain = ?"
        )
        .bind(domain)
    )?;

    Ok(org)
}

/// Get an organization by ID.
#[allow(dead_code)]
pub async fn get_org_by_id(pool: &Pool, org_id: &str) -> Result<Option<Organization>> {
    let org = db_fetch_optional!(
        pool,
        sqlx::query_as::<_, Organization>(
            "SELECT id, domain, name, created_at, created_by_user_id FROM organizations WHERE id = ?"
        )
        .bind(org_id)
    )?;

    Ok(org)
}

/// Create a new organization.
pub async fn create_organization(
    pool: &Pool,
    domain: &str,
    name: Option<&str>,
    created_by_user_id: Option<&str>,
) -> Result<Organization> {
    let id = Uuid::now_v7().to_string();

    db_execute!(
        pool,
        sqlx::query(
            "INSERT INTO organizations (id, domain, name, created_by_user_id) VALUES (?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(domain)
        .bind(name)
        .bind(created_by_user_id)
    )?;

    let org = db_fetch_one!(
        pool,
        sqlx::query_as::<_, Organization>(
            "SELECT id, domain, name, created_at, created_by_user_id FROM organizations WHERE id = ?"
        )
        .bind(&id)
    )?;

    Ok(org)
}

/// Get or create an organization by domain.
/// Returns (org, is_new) tuple where is_new indicates if the org was just created.
pub async fn get_or_create_org_by_domain(
    pool: &Pool,
    domain: &str,
    name: Option<&str>,
    created_by_user_id: Option<&str>,
) -> Result<(Organization, bool)> {
    // Check if org exists
    if let Some(org) = get_org_by_domain(pool, domain).await? {
        return Ok((org, false));
    }

    // Create new org
    let org = create_organization(pool, domain, name, created_by_user_id).await?;
    Ok((org, true))
}

/// Update a user's organization membership.
#[allow(dead_code)]
pub async fn set_user_org(
    pool: &Pool,
    _user_id: &str,
    org_id: Option<&str>,
    is_org_admin: bool,
) -> Result<()> {
    db_execute!(
        pool,
        sqlx::query("UPDATE users SET org_id = ?, is_org_admin = ? WHERE id = ?")
            .bind(org_id)
            .bind(is_org_admin)
    )?;

    Ok(())
}

/// Count users in an organization.
#[allow(dead_code)]
pub async fn count_users_in_org(pool: &Pool, org_id: &str) -> Result<i64> {
    let row: (i64,) = db_fetch_one!(
        pool,
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE org_id = ?").bind(org_id)
    )?;

    Ok(row.0)
}

/// List all organizations.
#[allow(dead_code)]
pub async fn list_organizations(pool: &Pool) -> Result<Vec<Organization>> {
    let orgs = db_fetch_all!(
        pool,
        sqlx::query_as::<_, Organization>(
            "SELECT id, domain, name, created_at, created_by_user_id FROM organizations ORDER BY domain"
        )
    )?;

    Ok(orgs)
}

/// Delete an organization and all associated data.
///
/// Performs application-level cascade deletes for DSQL compatibility:
/// 1. Delete cloud integrations
/// 2. Delete GitHub installations
/// 3. Delete SCIM tokens (with audit log SET NULL)
/// 4. SET NULL for github_credential_events.org_id (preserve audit trail)
/// 5. SET NULL for users.org_id (users are not deleted, just unlinked)
/// 6. Delete the organization
#[allow(dead_code)]
pub async fn delete_organization(pool: &Pool, org_id: &str) -> Result<bool> {
    let mut tx = pool.begin().await?;

    // 1. Delete cloud integrations
    tx_execute!(
        tx,
        sqlx::query("DELETE FROM cloud_integrations WHERE org_id = ?").bind(org_id)
    )?;

    // 2. Delete GitHub installations
    tx_execute!(
        tx,
        sqlx::query("DELETE FROM github_installations WHERE org_id = ?").bind(org_id)
    )?;

    // 3. Delete SCIM tokens (handle audit log SET NULL first)
    let token_ids: Vec<(String,)> = tx_fetch_all!(
        tx,
        sqlx::query_as("SELECT id FROM scim_tokens WHERE org_id = ?").bind(org_id)
    )?;

    for (token_id,) in token_ids {
        tx_execute!(
            tx,
            sqlx::query("UPDATE scim_audit_log SET actor_token_id = NULL WHERE actor_token_id = ?")
                .bind(&token_id)
        )?;
    }
    tx_execute!(
        tx,
        sqlx::query("DELETE FROM scim_tokens WHERE org_id = ?").bind(org_id)
    )?;

    // 4. SET NULL for github_credential_events.org_id (preserve audit trail)
    tx_execute!(
        tx,
        sqlx::query("UPDATE github_credential_events SET org_id = NULL WHERE org_id = ?")
            .bind(org_id)
    )?;

    // 5. SET NULL for users.org_id (unlink users from org, don't delete them)
    tx_execute!(
        tx,
        sqlx::query("UPDATE users SET org_id = NULL, is_org_admin = 0 WHERE org_id = ?")
            .bind(org_id)
    )?;

    // 6. Delete the organization
    let result = tx_execute!(
        tx,
        sqlx::query("DELETE FROM organizations WHERE id = ?").bind(org_id)
    )?;

    tx.commit().await?;
    Ok(result.rows_affected() > 0)
}
