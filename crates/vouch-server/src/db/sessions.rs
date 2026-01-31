// SPDX-License-Identifier: BUSL-1.1
//! Session database operations.

use anyhow::Result;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Session record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub authenticator_id: Option<String>,
    pub expires_at: String,
}

/// Create a new session.
/// `authenticator_id` is optional for OIDC-authenticated users who haven't registered a security key yet.
pub async fn create_session(
    pool: &SqlitePool,
    user_id: &str,
    token_hash: &str,
    authenticator_id: Option<&str>,
    expires_at: &str,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, authenticator_id, expires_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(user_id)
    .bind(token_hash)
    .bind(authenticator_id)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a session by token hash.
pub async fn get_session_by_token_hash(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<Session>> {
    let session = sqlx::query_as::<_, Session>(
        "SELECT id, user_id, token_hash, authenticator_id, expires_at FROM sessions WHERE token_hash = ?"
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;

    Ok(session)
}

/// Delete a session by token hash.
pub async fn delete_session_by_token_hash(pool: &SqlitePool, token_hash: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
        .bind(token_hash)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Delete expired sessions.
pub async fn delete_expired_sessions(pool: &SqlitePool, now: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Delete all sessions for a user (for immediate session invalidation on SCIM deactivation).
pub async fn delete_sessions_for_user(pool: &SqlitePool, user_id: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}
