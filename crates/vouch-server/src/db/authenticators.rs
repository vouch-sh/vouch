// SPDX-License-Identifier: BUSL-1.1
//! Authenticator (WebAuthn credential) database operations.

use anyhow::Result;
use sqlx::SqlitePool;
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
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    credential_id: &[u8],
    public_key: &[u8],
    aaguid: Option<&str>,
    user_handle: Option<&[u8]>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

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
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get authenticators for a user.
pub async fn get_authenticators_for_user(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<Authenticator>> {
    let authenticators = sqlx::query_as::<_, Authenticator>(
        "SELECT id, user_id, name, credential_id, public_key, counter, created_at, aaguid, user_handle FROM authenticators WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(authenticators)
}

/// Get an authenticator by credential ID.
pub async fn get_authenticator_by_credential_id(
    pool: &SqlitePool,
    credential_id: &[u8],
) -> Result<Option<Authenticator>> {
    let authenticator = sqlx::query_as::<_, Authenticator>(
        "SELECT id, user_id, name, credential_id, public_key, counter, created_at, aaguid, user_handle FROM authenticators WHERE credential_id = ?"
    )
    .bind(credential_id)
    .fetch_optional(pool)
    .await?;

    Ok(authenticator)
}

/// Get an authenticator by ID.
pub async fn get_authenticator_by_id(
    pool: &SqlitePool,
    authenticator_id: &str,
) -> Result<Option<Authenticator>> {
    let authenticator = sqlx::query_as::<_, Authenticator>(
        "SELECT id, user_id, name, credential_id, public_key, counter, created_at, aaguid, user_handle FROM authenticators WHERE id = ?"
    )
    .bind(authenticator_id)
    .fetch_optional(pool)
    .await?;

    Ok(authenticator)
}

/// Update authenticator counter.
pub async fn update_authenticator_counter(
    pool: &SqlitePool,
    authenticator_id: &str,
    counter: i64,
) -> Result<()> {
    sqlx::query("UPDATE authenticators SET counter = ? WHERE id = ?")
        .bind(counter)
        .bind(authenticator_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Count the number of authenticators for a user.
pub async fn count_authenticators_for_user(pool: &SqlitePool, user_id: &str) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM authenticators WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await?;

    Ok(row.0)
}

/// Count the number of sessions for an authenticator.
pub async fn count_sessions_for_authenticator(
    pool: &SqlitePool,
    authenticator_id: &str,
) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE authenticator_id = ?")
        .bind(authenticator_id)
        .fetch_one(pool)
        .await?;

    Ok(row.0)
}

/// Delete an authenticator by ID.
/// Returns the number of rows affected.
/// Note: Due to CASCADE, this will also delete associated sessions.
/// Device auth requests referencing this authenticator will have their reference cleared.
/// This operation is atomic - both FK cleanup and deletion happen together.
pub async fn delete_authenticator(pool: &SqlitePool, authenticator_id: &str) -> Result<u64> {
    let mut tx = pool.begin().await?;

    // Clear authenticator_id references in device_auth_requests
    // (the FK doesn't have ON DELETE CASCADE/SET NULL)
    sqlx::query(
        "UPDATE device_auth_requests SET authenticator_id = NULL WHERE authenticator_id = ?",
    )
    .bind(authenticator_id)
    .execute(&mut *tx)
    .await?;

    let result = sqlx::query("DELETE FROM authenticators WHERE id = ?")
        .bind(authenticator_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(result.rows_affected())
}

/// Update an authenticator's name.
pub async fn update_authenticator_name(
    pool: &SqlitePool,
    authenticator_id: &str,
    name: &str,
) -> Result<bool> {
    let result = sqlx::query("UPDATE authenticators SET name = ? WHERE id = ?")
        .bind(name)
        .bind(authenticator_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}
