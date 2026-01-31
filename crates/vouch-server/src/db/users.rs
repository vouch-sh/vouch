// SPDX-License-Identifier: BUSL-1.1
//! User database operations.

use anyhow::Result;
use sqlx::SqlitePool;
use uuid::Uuid;

/// User record.
#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    #[allow(dead_code)]
    pub name: Option<String>,
    /// Organization ID (NULL for personal accounts like gmail.com).
    pub org_id: Option<String>,
    /// Whether this user is an admin of their organization.
    pub is_org_admin: bool,
}

/// User with authenticator count for admin listing.
#[derive(Debug, sqlx::FromRow)]
pub struct UserWithAuthCount {
    pub id: String,
    pub email: String,
    #[allow(dead_code)]
    pub name: Option<String>,
    pub created_at: String,
    pub authenticator_count: i64,
    #[allow(dead_code)]
    pub org_id: Option<String>,
    #[allow(dead_code)]
    pub is_org_admin: bool,
}

/// Create or get a user by email.
///
/// Note: This function is primarily used for testing. In production, users are
/// created via the OIDC enrollment flow using `upsert_user_with_org`.
#[allow(dead_code)]
pub async fn upsert_user(pool: &SqlitePool, email: &str, name: Option<&str>) -> Result<User> {
    let id = Uuid::now_v7().to_string();

    // Try to insert, ignore if exists
    sqlx::query("INSERT OR IGNORE INTO users (id, email, name) VALUES (?, ?, ?)")
        .bind(&id)
        .bind(email)
        .bind(name)
        .execute(pool)
        .await?;

    // Fetch the user
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, name, org_id, is_org_admin FROM users WHERE email = ?",
    )
    .bind(email)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

/// Create or get a user by email, associating them with an organization.
pub async fn upsert_user_with_org(
    pool: &SqlitePool,
    email: &str,
    name: Option<&str>,
    org_id: Option<&str>,
    is_org_admin: bool,
) -> Result<User> {
    let id = Uuid::now_v7().to_string();

    // Try to insert with org info, ignore if exists
    sqlx::query(
        "INSERT OR IGNORE INTO users (id, email, name, org_id, is_org_admin) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(email)
    .bind(name)
    .bind(org_id)
    .bind(is_org_admin)
    .execute(pool)
    .await?;

    // Fetch the user
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, name, org_id, is_org_admin FROM users WHERE email = ?",
    )
    .bind(email)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

/// Get a user by email.
#[allow(dead_code)]
pub async fn get_user_by_email(pool: &SqlitePool, email: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, name, org_id, is_org_admin FROM users WHERE email = ?",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Get a user by ID.
pub async fn get_user_by_id(pool: &SqlitePool, user_id: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, name, org_id, is_org_admin FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Delete a user and all associated data.
pub async fn delete_user(pool: &SqlitePool, user_id: &str) -> Result<()> {
    // Due to CASCADE, this will delete authenticators and sessions
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// List all users with their authenticator counts.
pub async fn list_users_with_auth_count(pool: &SqlitePool) -> Result<Vec<UserWithAuthCount>> {
    let users = sqlx::query_as::<_, UserWithAuthCount>(
        "SELECT u.id, u.email, u.name, u.created_at,
                (SELECT COUNT(*) FROM authenticators a WHERE a.user_id = u.id) as authenticator_count,
                u.org_id, u.is_org_admin
         FROM users u
         ORDER BY u.email",
    )
    .fetch_all(pool)
    .await?;

    Ok(users)
}

/// List users in a specific organization with their authenticator counts.
pub async fn list_users_with_auth_count_by_org(
    pool: &SqlitePool,
    org_id: &str,
) -> Result<Vec<UserWithAuthCount>> {
    let users = sqlx::query_as::<_, UserWithAuthCount>(
        "SELECT u.id, u.email, u.name, u.created_at,
                (SELECT COUNT(*) FROM authenticators a WHERE a.user_id = u.id) as authenticator_count,
                u.org_id, u.is_org_admin
         FROM users u
         WHERE u.org_id = ?
         ORDER BY u.email",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(users)
}
