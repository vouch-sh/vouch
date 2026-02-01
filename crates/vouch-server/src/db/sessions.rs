// SPDX-License-Identifier: BUSL-1.1
//! Session database operations.

use super::Pool;
use super::compat::BuildSql;
use super::schema::Sessions;
use crate::{db_execute, db_fetch_optional};
use anyhow::Result;
use sea_query::Query;
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
    pool: &Pool,
    user_id: &str,
    token_hash: &str,
    authenticator_id: Option<&str>,
    expires_at: &str,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();

    // Build SQL in a block to ensure query is dropped before await
    let sql = {
        let query = Query::insert()
            .into_table(Sessions::Table)
            .columns([
                Sessions::Id,
                Sessions::UserId,
                Sessions::TokenHash,
                Sessions::AuthenticatorId,
                Sessions::ExpiresAt,
            ])
            .values_panic([
                id.clone().into(),
                user_id.into(),
                token_hash.into(),
                authenticator_id.into(),
                expires_at.into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Get a session by token hash.
pub async fn get_session_by_token_hash(pool: &Pool, token_hash: &str) -> Result<Option<Session>> {
    let session = db_fetch_optional!(
        pool,
        sqlx::query_as::<_, Session>(
            "SELECT id, user_id, token_hash, authenticator_id, expires_at FROM sessions WHERE token_hash = ?"
        )
        .bind(token_hash)
    )?;

    Ok(session)
}

/// Delete a session by token hash.
pub async fn delete_session_by_token_hash(pool: &Pool, token_hash: &str) -> Result<bool> {
    let result = db_execute!(
        pool,
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?").bind(token_hash)
    )?;

    Ok(result.rows_affected() > 0)
}

/// Delete expired sessions.
pub async fn delete_expired_sessions(pool: &Pool, now: &str) -> Result<u64> {
    let result = db_execute!(
        pool,
        sqlx::query("DELETE FROM sessions WHERE expires_at < ?").bind(now)
    )?;

    Ok(result.rows_affected())
}

/// Delete all sessions for a user (for immediate session invalidation on SCIM deactivation).
pub async fn delete_sessions_for_user(pool: &Pool, user_id: &str) -> Result<u64> {
    let result = db_execute!(
        pool,
        sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(user_id)
    )?;

    Ok(result.rows_affected())
}
