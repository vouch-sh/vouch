// SPDX-License-Identifier: BUSL-1.1
//! Session database operations.

use super::Pool;
use super::schema::Sessions;
use super::types::BuildSql;
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_optional};
use anyhow::Result;
use jiff::Timestamp;
use sea_query::{Expr, Query};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Session purpose — distinguishes FIDO2 login sessions from OAuth access tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SessionPurpose {
    /// FIDO2 hardware-backed login session (CLI login, device code flow).
    #[default]
    #[serde(rename = "fido2_session")]
    Fido2Session,
    /// OAuth 2.0 access token issued via authorization code grant.
    #[serde(rename = "oauth_access_token")]
    OAuthAccessToken,
}

impl SessionPurpose {
    /// Return the string representation for database storage.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fido2Session => "fido2_session",
            Self::OAuthAccessToken => "oauth_access_token",
        }
    }

    /// Parse from a database string value.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "fido2_session" => Some(Self::Fido2Session),
            "oauth_access_token" => Some(Self::OAuthAccessToken),
            _ => None,
        }
    }
}

/// Session record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub authenticator_id: Option<String>,
    pub expires_at: DbTimestamp,
    pub session_type: String,
}

/// Create a new session.
/// `authenticator_id` is optional for OIDC-authenticated users who haven't registered a security key yet.
/// `session_type` distinguishes FIDO2 login sessions from OAuth access tokens.
pub async fn create_session(
    pool: &Pool,
    user_id: &str,
    token_hash: &str,
    authenticator_id: Option<&str>,
    expires_at: &str,
    session_type: &str,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let now = Timestamp::now().to_string();
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
                Sessions::CreatedAt,
                Sessions::SessionType,
            ])
            .values_panic([
                id.clone().into(),
                user_id.into(),
                token_hash.into(),
                authenticator_id.into(),
                expires_at.into(),
                now.as_str().into(),
                session_type.into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Get a session by token hash.
pub async fn get_session_by_token_hash(pool: &Pool, token_hash: &str) -> Result<Option<Session>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                Sessions::Id,
                Sessions::UserId,
                Sessions::TokenHash,
                Sessions::AuthenticatorId,
                Sessions::ExpiresAt,
                Sessions::SessionType,
            ])
            .from(Sessions::Table)
            .and_where(Expr::col(Sessions::TokenHash).eq(token_hash))
            .to_owned();
        query.build_sql(db_type)
    };

    let session = db_fetch_optional!(pool, sqlx::query_as::<_, Session>(&sql))?;

    Ok(session)
}

/// Delete a session by token hash.
pub async fn delete_session_by_token_hash(pool: &Pool, token_hash: &str) -> Result<bool> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(Sessions::Table)
            .and_where(Expr::col(Sessions::TokenHash).eq(token_hash))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected() > 0)
}

/// Delete expired sessions.
pub async fn delete_expired_sessions(pool: &Pool, now: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(Sessions::Table)
            .and_where(Expr::col(Sessions::ExpiresAt).lt(now))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

/// Delete all sessions for a user (for immediate session invalidation on SCIM deactivation).
pub async fn delete_sessions_for_user(pool: &Pool, user_id: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(Sessions::Table)
            .and_where(Expr::col(Sessions::UserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}
