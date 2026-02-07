// SPDX-License-Identifier: BUSL-1.1
//! Server configuration and authentication event database operations.

use super::Pool;
use super::schema::{AuthEvents, ServerConfig};
use super::types::BuildSql;
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_all, db_fetch_optional};
use anyhow::Result;
use jiff::Timestamp;
use sea_query::{Expr, OnConflict, Order, Query};
use uuid::Uuid;

// ============================================================================
// Server Configuration
// ============================================================================

/// Server config record.
#[derive(Debug, sqlx::FromRow)]
pub struct ServerConfigRow {
    #[allow(dead_code)]
    pub key: String,
    pub value: String,
    #[allow(dead_code)]
    pub updated_at: DbTimestamp,
}

/// Get a config value by key.
pub async fn get_config(pool: &Pool, key: &str) -> Result<Option<String>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                ServerConfig::Key,
                ServerConfig::Value,
                ServerConfig::UpdatedAt,
            ])
            .from(ServerConfig::Table)
            .and_where(Expr::col(ServerConfig::Key).eq(key))
            .to_owned();
        query.build_sql(db_type)
    };

    let row = db_fetch_optional!(pool, sqlx::query_as::<_, ServerConfigRow>(&sql))?;

    Ok(row.map(|r| r.value))
}

/// Set a config value.
pub async fn set_config(pool: &Pool, key: &str, value: &str) -> Result<()> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    // Build upsert query using sea-query
    // Build SQL in a block to ensure query is dropped before await
    let sql = {
        let query = Query::insert()
            .into_table(ServerConfig::Table)
            .columns([
                ServerConfig::Key,
                ServerConfig::Value,
                ServerConfig::UpdatedAt,
            ])
            .values_panic([key.into(), value.into(), now.as_str().into()])
            .on_conflict(
                OnConflict::column(ServerConfig::Key)
                    .update_columns([ServerConfig::Value, ServerConfig::UpdatedAt])
                    .to_owned(),
            )
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

// ============================================================================
// Authentication Events
// ============================================================================

/// Authentication event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthEventType {
    #[default]
    LoginSuccess,
    LoginFailed,
    Enrollment,
    #[allow(dead_code)]
    Logout,
}

impl AuthEventType {
    /// Convert to database string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LoginSuccess => "login_success",
            Self::LoginFailed => "login_failed",
            Self::Enrollment => "enrollment",
            Self::Logout => "logout",
        }
    }

    /// Parse from database string.
    #[must_use]
    #[allow(dead_code, clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "login_success" => Some(Self::LoginSuccess),
            "login_failed" => Some(Self::LoginFailed),
            "enrollment" => Some(Self::Enrollment),
            "logout" => Some(Self::Logout),
            _ => None,
        }
    }
}

/// Authentication event record.
#[derive(Debug, sqlx::FromRow)]
pub struct AuthEvent {
    pub id: String,
    pub user_id: String,
    pub event_type: String,
    pub authenticator_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub client_hostname: Option<String>,
    pub client_os: Option<String>,
    pub client_arch: Option<String>,
    pub client_version: Option<String>,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub created_at: DbTimestamp,
}

/// Parameters for creating an authentication event.
#[derive(Debug, Default)]
pub struct AuthEventParams {
    pub user_id: String,
    pub event_type: AuthEventType,
    pub authenticator_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub client_hostname: Option<String>,
    pub client_os: Option<String>,
    pub client_arch: Option<String>,
    pub client_version: Option<String>,
    pub success: bool,
    pub failure_reason: Option<String>,
}

/// Insert a new authentication event.
pub async fn insert_auth_event(pool: &Pool, params: &AuthEventParams) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    // Build SQL in a block to ensure query is dropped before await
    let sql = {
        let query = Query::insert()
            .into_table(AuthEvents::Table)
            .columns([
                AuthEvents::Id,
                AuthEvents::UserId,
                AuthEvents::EventType,
                AuthEvents::AuthenticatorId,
                AuthEvents::ClientIp,
                AuthEvents::UserAgent,
                AuthEvents::ClientHostname,
                AuthEvents::ClientOs,
                AuthEvents::ClientArch,
                AuthEvents::ClientVersion,
                AuthEvents::Success,
                AuthEvents::FailureReason,
                AuthEvents::CreatedAt,
            ])
            .values_panic([
                id.clone().into(),
                params.user_id.clone().into(),
                params.event_type.as_str().into(),
                params.authenticator_id.clone().into(),
                params.client_ip.clone().into(),
                params.user_agent.clone().into(),
                params.client_hostname.clone().into(),
                params.client_os.clone().into(),
                params.client_arch.clone().into(),
                params.client_version.clone().into(),
                params.success.into(),
                params.failure_reason.clone().into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Query parameters for listing authentication events.
#[derive(Debug, Default)]
pub struct AuthEventQuery {
    pub user_id: Option<String>,
    pub event_type: Option<String>,
    pub client_ip: Option<String>,
    pub since: Option<String>,
    pub limit: Option<i64>,
}

/// Get authentication events with optional filtering.
pub async fn get_auth_events(pool: &Pool, query_params: &AuthEventQuery) -> Result<Vec<AuthEvent>> {
    let db_type = pool.db_type();
    let limit = query_params.limit.unwrap_or(100);

    let sql = {
        let mut query = Query::select()
            .columns([
                AuthEvents::Id,
                AuthEvents::UserId,
                AuthEvents::EventType,
                AuthEvents::AuthenticatorId,
                AuthEvents::ClientIp,
                AuthEvents::UserAgent,
                AuthEvents::ClientHostname,
                AuthEvents::ClientOs,
                AuthEvents::ClientArch,
                AuthEvents::ClientVersion,
                AuthEvents::Success,
                AuthEvents::FailureReason,
                AuthEvents::CreatedAt,
            ])
            .from(AuthEvents::Table)
            .to_owned();

        if let Some(user_id) = &query_params.user_id {
            query = query
                .and_where(Expr::col(AuthEvents::UserId).eq(user_id.as_str()))
                .to_owned();
        }

        if let Some(event_type) = &query_params.event_type {
            query = query
                .and_where(Expr::col(AuthEvents::EventType).eq(event_type.as_str()))
                .to_owned();
        }

        if let Some(client_ip) = &query_params.client_ip {
            query = query
                .and_where(Expr::col(AuthEvents::ClientIp).eq(client_ip.as_str()))
                .to_owned();
        }

        if let Some(since) = &query_params.since {
            query = query
                .and_where(Expr::col(AuthEvents::CreatedAt).gte(since.as_str()))
                .to_owned();
        }

        query = query
            .order_by(AuthEvents::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .to_owned();

        query.build_sql(db_type)
    };

    let events = db_fetch_all!(pool, sqlx::query_as::<_, AuthEvent>(&sql))?;

    Ok(events)
}

/// Delete authentication events older than the specified timestamp.
/// Use for retention policy enforcement (e.g., delete events older than 90 days).
pub async fn delete_old_auth_events(pool: &Pool, before: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(AuthEvents::Table)
            .and_where(Expr::col(AuthEvents::CreatedAt).lt(before))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}
