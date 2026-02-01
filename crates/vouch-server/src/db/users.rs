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
///
/// Performs application-level cascade deletes for DSQL compatibility.
/// Order matters - child records must be deleted before parent records.
pub async fn delete_user(pool: &SqlitePool, user_id: &str) -> Result<()> {
    let mut tx = pool.begin().await?;

    // 1. Delete sessions (references user_id and authenticator_id)
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // 2. Delete enrollment sessions
    sqlx::query("DELETE FROM enrollment_sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // 3. Delete auth events
    sqlx::query("DELETE FROM auth_events WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // 4. Delete SCIM group memberships
    sqlx::query("DELETE FROM scim_group_members WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // 5. Handle token exchanges - SET NULL for actor, DELETE for subject
    sqlx::query("UPDATE token_exchanges SET actor_user_id = NULL WHERE actor_user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM token_exchanges WHERE subject_user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // 6. Delete SSH revoked certificates
    sqlx::query("DELETE FROM ssh_revoked_certificates WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // 7. Delete OAuth clients and their children
    // First get all client IDs owned by this user
    let client_ids: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM oauth_clients WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&mut *tx)
            .await?;

    for (client_id,) in client_ids {
        // Delete usage events first
        sqlx::query("DELETE FROM oauth_usage_events WHERE oauth_client_id = ?")
            .bind(&client_id)
            .execute(&mut *tx)
            .await?;
        // Delete secrets
        sqlx::query("DELETE FROM oauth_client_secrets WHERE oauth_client_id = ?")
            .bind(&client_id)
            .execute(&mut *tx)
            .await?;
        // Delete client
        sqlx::query("DELETE FROM oauth_clients WHERE id = ?")
            .bind(&client_id)
            .execute(&mut *tx)
            .await?;
    }

    // 8. Clear authenticator references in device_auth_requests, then delete authenticators
    sqlx::query(
        "UPDATE device_auth_requests SET authenticator_id = NULL
         WHERE authenticator_id IN (SELECT id FROM authenticators WHERE user_id = ?)",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM authenticators WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // 9. Finally delete the user
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
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
