// SPDX-License-Identifier: BUSL-1.1
//! Authenticator (WebAuthn credential) database operations.

use super::Pool;
use crate::{db_execute, db_fetch_all, db_fetch_one, db_fetch_optional, tx_execute};
use anyhow::Result;
use uuid::Uuid;

/// Authenticator (credential) record.
#[derive(Debug, sqlx::FromRow)]
pub struct Authenticator {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub credential_id: Vec<u8>,
    #[allow(dead_code)]
    pub public_key: Vec<u8>,
    pub counter: i64,
    pub created_at: String,
    /// AAGUID (Authenticator Attestation GUID) identifies the authenticator model.
    pub aaguid: Option<String>,
    /// User handle stored in discoverable credentials (resident keys).
    #[allow(dead_code)]
    pub user_handle: Option<Vec<u8>>,
}

/// Create a new authenticator.
pub async fn create_authenticator(
    pool: &Pool,
    user_id: &str,
    name: &str,
    credential_id: &[u8],
    public_key: &[u8],
    aaguid: Option<&str>,
    user_handle: Option<&[u8]>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    db_execute!(
        pool,
        sqlx::query(
            "INSERT INTO authenticators (id, user_id, name, credential_id, public_key, counter, aaguid, user_handle) VALUES (?, ?, ?, ?, ?, 0, ?, ?)"
        )
        .bind(&id)
        .bind(user_id)
        .bind(name)
        .bind(credential_id)
        .bind(public_key)
        .bind(aaguid)
        .bind(user_handle)
    )?;

    Ok(id)
}

/// Get authenticators for a user.
pub async fn get_authenticators_for_user(pool: &Pool, user_id: &str) -> Result<Vec<Authenticator>> {
    let authenticators = db_fetch_all!(
        pool,
        sqlx::query_as::<_, Authenticator>(
            "SELECT id, user_id, name, credential_id, public_key, counter, created_at, aaguid, user_handle FROM authenticators WHERE user_id = ?"
        )
        .bind(user_id)
    )?;

    Ok(authenticators)
}

/// Get an authenticator by credential ID.
pub async fn get_authenticator_by_credential_id(
    pool: &Pool,
    credential_id: &[u8],
) -> Result<Option<Authenticator>> {
    let authenticator = db_fetch_optional!(
        pool,
        sqlx::query_as::<_, Authenticator>(
            "SELECT id, user_id, name, credential_id, public_key, counter, created_at, aaguid, user_handle FROM authenticators WHERE credential_id = ?"
        )
        .bind(credential_id)
    )?;

    Ok(authenticator)
}

/// Get an authenticator by ID.
pub async fn get_authenticator_by_id(
    pool: &Pool,
    authenticator_id: &str,
) -> Result<Option<Authenticator>> {
    let authenticator = db_fetch_optional!(
        pool,
        sqlx::query_as::<_, Authenticator>(
            "SELECT id, user_id, name, credential_id, public_key, counter, created_at, aaguid, user_handle FROM authenticators WHERE id = ?"
        )
        .bind(authenticator_id)
    )?;

    Ok(authenticator)
}

/// Update authenticator counter.
pub async fn update_authenticator_counter(
    pool: &Pool,
    authenticator_id: &str,
    counter: i64,
) -> Result<()> {
    db_execute!(
        pool,
        sqlx::query("UPDATE authenticators SET counter = ? WHERE id = ?")
            .bind(counter)
            .bind(authenticator_id)
    )?;

    Ok(())
}

/// Count the number of authenticators for a user.
pub async fn count_authenticators_for_user(pool: &Pool, user_id: &str) -> Result<i64> {
    let row: (i64,) = db_fetch_one!(
        pool,
        sqlx::query_as("SELECT COUNT(*) FROM authenticators WHERE user_id = ?").bind(user_id)
    )?;

    Ok(row.0)
}

/// Count the number of sessions for an authenticator.
pub async fn count_sessions_for_authenticator(pool: &Pool, authenticator_id: &str) -> Result<i64> {
    let row: (i64,) = db_fetch_one!(
        pool,
        sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE authenticator_id = ?")
            .bind(authenticator_id)
    )?;

    Ok(row.0)
}

/// Delete an authenticator by ID.
/// Returns the number of rows affected.
///
/// Performs application-level cascade deletes for DSQL compatibility:
/// 1. Clear authenticator_id references in device_auth_requests
/// 2. Delete sessions using this authenticator
/// 3. Delete the authenticator
pub async fn delete_authenticator(pool: &Pool, authenticator_id: &str) -> Result<u64> {
    let mut tx = pool.begin().await?;

    // 1. Clear authenticator_id references in device_auth_requests
    tx_execute!(
        tx,
        sqlx::query(
            "UPDATE device_auth_requests SET authenticator_id = NULL WHERE authenticator_id = ?"
        )
        .bind(authenticator_id)
    )?;

    // 2. Delete sessions using this authenticator
    tx_execute!(
        tx,
        sqlx::query("DELETE FROM sessions WHERE authenticator_id = ?").bind(authenticator_id)
    )?;

    // 3. Delete the authenticator
    let result = tx_execute!(
        tx,
        sqlx::query("DELETE FROM authenticators WHERE id = ?").bind(authenticator_id)
    )?;

    tx.commit().await?;
    Ok(result.rows_affected())
}

/// Update an authenticator's name.
pub async fn update_authenticator_name(
    pool: &Pool,
    authenticator_id: &str,
    name: &str,
) -> Result<bool> {
    let result = db_execute!(
        pool,
        sqlx::query("UPDATE authenticators SET name = ? WHERE id = ?")
            .bind(name)
            .bind(authenticator_id)
    )?;

    Ok(result.rows_affected() > 0)
}
