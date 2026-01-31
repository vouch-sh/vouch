// SPDX-License-Identifier: BUSL-1.1
//! Organization database operations.

use anyhow::Result;
use sqlx::SqlitePool;
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
pub async fn get_org_by_domain(pool: &SqlitePool, domain: &str) -> Result<Option<Organization>> {
    let org = sqlx::query_as::<_, Organization>(
        "SELECT id, domain, name, created_at, created_by_user_id FROM organizations WHERE domain = ?",
    )
    .bind(domain)
    .fetch_optional(pool)
    .await?;

    Ok(org)
}

/// Get an organization by ID.
#[allow(dead_code)]
pub async fn get_org_by_id(pool: &SqlitePool, org_id: &str) -> Result<Option<Organization>> {
    let org = sqlx::query_as::<_, Organization>(
        "SELECT id, domain, name, created_at, created_by_user_id FROM organizations WHERE id = ?",
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?;

    Ok(org)
}

/// Create a new organization.
pub async fn create_organization(
    pool: &SqlitePool,
    domain: &str,
    name: Option<&str>,
    created_by_user_id: Option<&str>,
) -> Result<Organization> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO organizations (id, domain, name, created_by_user_id) VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(domain)
    .bind(name)
    .bind(created_by_user_id)
    .execute(pool)
    .await?;

    let org = sqlx::query_as::<_, Organization>(
        "SELECT id, domain, name, created_at, created_by_user_id FROM organizations WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(pool)
    .await?;

    Ok(org)
}

/// Get or create an organization by domain.
/// Returns (org, is_new) tuple where is_new indicates if the org was just created.
pub async fn get_or_create_org_by_domain(
    pool: &SqlitePool,
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
    pool: &SqlitePool,
    _user_id: &str,
    org_id: Option<&str>,
    is_org_admin: bool,
) -> Result<()> {
    sqlx::query("UPDATE users SET org_id = ?, is_org_admin = ? WHERE id = ?")
        .bind(org_id)
        .bind(is_org_admin)
        .execute(pool)
        .await?;

    Ok(())
}

/// Count users in an organization.
#[allow(dead_code)]
pub async fn count_users_in_org(pool: &SqlitePool, org_id: &str) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE org_id = ?")
        .bind(org_id)
        .fetch_one(pool)
        .await?;

    Ok(row.0)
}

/// List all organizations.
#[allow(dead_code)]
pub async fn list_organizations(pool: &SqlitePool) -> Result<Vec<Organization>> {
    let orgs = sqlx::query_as::<_, Organization>(
        "SELECT id, domain, name, created_at, created_by_user_id FROM organizations ORDER BY domain",
    )
    .fetch_all(pool)
    .await?;

    Ok(orgs)
}
