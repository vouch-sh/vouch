// SPDX-License-Identifier: BUSL-1.1
//! User database operations.

use super::Pool;
use super::compat::BuildSql;
use super::schema::Users;
use crate::{db_execute, db_fetch_all, db_fetch_one, db_fetch_optional, tx_execute, tx_fetch_all};
use anyhow::Result;
use sea_query::{OnConflict, Query};
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
pub async fn upsert_user(pool: &Pool, email: &str, name: Option<&str>) -> Result<User> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();

    // Try to insert, ignore if exists using sea-query
    // Build SQL in a block to ensure query is dropped before await
    let sql = {
        let query = Query::insert()
            .into_table(Users::Table)
            .columns([Users::Id, Users::Email, Users::Name])
            .values_panic([id.clone().into(), email.into(), name.into()])
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    // Fetch the user
    let user = db_fetch_one!(
        pool,
        sqlx::query_as::<_, User>(
            "SELECT id, email, name, org_id, is_org_admin FROM users WHERE email = ?"
        )
        .bind(email)
    )?;

    Ok(user)
}

/// Create or get a user by email, associating them with an organization.
pub async fn upsert_user_with_org(
    pool: &Pool,
    email: &str,
    name: Option<&str>,
    org_id: Option<&str>,
    is_org_admin: bool,
) -> Result<User> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();

    // Try to insert with org info, ignore if exists using sea-query
    // Build SQL in a block to ensure query is dropped before await
    let sql = {
        let query = Query::insert()
            .into_table(Users::Table)
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::OrgId,
                Users::IsOrgAdmin,
            ])
            .values_panic([
                id.clone().into(),
                email.into(),
                name.into(),
                org_id.into(),
                is_org_admin.into(),
            ])
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    // Fetch the user
    let user = db_fetch_one!(
        pool,
        sqlx::query_as::<_, User>(
            "SELECT id, email, name, org_id, is_org_admin FROM users WHERE email = ?"
        )
        .bind(email)
    )?;

    Ok(user)
}

/// Get a user by email.
#[allow(dead_code)]
pub async fn get_user_by_email(pool: &Pool, email: &str) -> Result<Option<User>> {
    let user = db_fetch_optional!(
        pool,
        sqlx::query_as::<_, User>(
            "SELECT id, email, name, org_id, is_org_admin FROM users WHERE email = ?"
        )
        .bind(email)
    )?;

    Ok(user)
}

/// Get a user by ID.
pub async fn get_user_by_id(pool: &Pool, user_id: &str) -> Result<Option<User>> {
    let user = db_fetch_optional!(
        pool,
        sqlx::query_as::<_, User>(
            "SELECT id, email, name, org_id, is_org_admin FROM users WHERE id = ?"
        )
        .bind(user_id)
    )?;

    Ok(user)
}

/// Delete a user and all associated data.
///
/// Performs application-level cascade deletes for DSQL compatibility.
/// Order matters - child records must be deleted before parent records.
pub async fn delete_user(pool: &Pool, user_id: &str) -> Result<()> {
    let mut tx = pool.begin().await?;

    // 1. Delete sessions (references user_id and authenticator_id)
    tx_execute!(
        tx,
        sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(user_id)
    )?;

    // 2. Delete enrollment sessions
    tx_execute!(
        tx,
        sqlx::query("DELETE FROM enrollment_sessions WHERE user_id = ?").bind(user_id)
    )?;

    // 3. Delete auth events
    tx_execute!(
        tx,
        sqlx::query("DELETE FROM auth_events WHERE user_id = ?").bind(user_id)
    )?;

    // 4. Delete SCIM group memberships
    tx_execute!(
        tx,
        sqlx::query("DELETE FROM scim_group_members WHERE user_id = ?").bind(user_id)
    )?;

    // 5. Handle token exchanges - SET NULL for actor, DELETE for subject
    tx_execute!(
        tx,
        sqlx::query("UPDATE token_exchanges SET actor_user_id = NULL WHERE actor_user_id = ?")
            .bind(user_id)
    )?;
    tx_execute!(
        tx,
        sqlx::query("DELETE FROM token_exchanges WHERE subject_user_id = ?").bind(user_id)
    )?;

    // 6. Delete SSH revoked certificates
    tx_execute!(
        tx,
        sqlx::query("DELETE FROM ssh_revoked_certificates WHERE user_id = ?").bind(user_id)
    )?;

    // 7. Delete OAuth clients and their children
    // First get all client IDs owned by this user
    let client_ids: Vec<(String,)> = tx_fetch_all!(
        tx,
        sqlx::query_as("SELECT id FROM oauth_clients WHERE user_id = ?").bind(user_id)
    )?;

    for (client_id,) in client_ids {
        // Delete usage events first
        tx_execute!(
            tx,
            sqlx::query("DELETE FROM oauth_usage_events WHERE oauth_client_id = ?")
                .bind(&client_id)
        )?;
        // Delete secrets
        tx_execute!(
            tx,
            sqlx::query("DELETE FROM oauth_client_secrets WHERE oauth_client_id = ?")
                .bind(&client_id)
        )?;
        // Delete client
        tx_execute!(
            tx,
            sqlx::query("DELETE FROM oauth_clients WHERE id = ?").bind(&client_id)
        )?;
    }

    // 8. Clear authenticator references in device_auth_requests, then delete authenticators
    tx_execute!(
        tx,
        sqlx::query(
            "UPDATE device_auth_requests SET authenticator_id = NULL
             WHERE authenticator_id IN (SELECT id FROM authenticators WHERE user_id = ?)"
        )
        .bind(user_id)
    )?;

    tx_execute!(
        tx,
        sqlx::query("DELETE FROM authenticators WHERE user_id = ?").bind(user_id)
    )?;

    // 9. Finally delete the user
    tx_execute!(
        tx,
        sqlx::query("DELETE FROM users WHERE id = ?").bind(user_id)
    )?;

    tx.commit().await?;
    Ok(())
}

/// List all users with their authenticator counts.
pub async fn list_users_with_auth_count(pool: &Pool) -> Result<Vec<UserWithAuthCount>> {
    let users = db_fetch_all!(
        pool,
        sqlx::query_as::<_, UserWithAuthCount>(
            "SELECT u.id, u.email, u.name, u.created_at,
                (SELECT COUNT(*) FROM authenticators a WHERE a.user_id = u.id) as authenticator_count,
                u.org_id, u.is_org_admin
         FROM users u
         ORDER BY u.email"
        )
    )?;

    Ok(users)
}

/// List users in a specific organization with their authenticator counts.
pub async fn list_users_with_auth_count_by_org(
    pool: &Pool,
    org_id: &str,
) -> Result<Vec<UserWithAuthCount>> {
    let users = db_fetch_all!(
        pool,
        sqlx::query_as::<_, UserWithAuthCount>(
            "SELECT u.id, u.email, u.name, u.created_at,
                (SELECT COUNT(*) FROM authenticators a WHERE a.user_id = u.id) as authenticator_count,
                u.org_id, u.is_org_admin
         FROM users u
         WHERE u.org_id = ?
         ORDER BY u.email"
        )
        .bind(org_id)
    )?;

    Ok(users)
}
