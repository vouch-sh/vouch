// SPDX-License-Identifier: BUSL-1.1
//! Server configuration and authentication event database operations.

use anyhow::Result;
use sqlx::SqlitePool;
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
    pub updated_at: String,
}

/// Get a config value by key.
pub async fn get_config(pool: &SqlitePool, key: &str) -> Result<Option<String>> {
    let row = sqlx::query_as::<_, ServerConfigRow>(
        "SELECT key, value, updated_at FROM server_config WHERE key = ?",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.value))
}

/// Get all config values.
#[allow(dead_code)]
pub async fn get_all_config(pool: &SqlitePool) -> Result<Vec<ServerConfigRow>> {
    let rows =
        sqlx::query_as::<_, ServerConfigRow>("SELECT key, value, updated_at FROM server_config")
            .fetch_all(pool)
            .await?;

    Ok(rows)
}

/// Set a config value.
pub async fn set_config(pool: &SqlitePool, key: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO server_config (key, value, updated_at) VALUES (?, ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a config value.
#[allow(dead_code)]
pub async fn delete_config(pool: &SqlitePool, key: &str) -> Result<()> {
    sqlx::query("DELETE FROM server_config WHERE key = ?")
        .bind(key)
        .execute(pool)
        .await?;

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
    pub success: i64,
    pub failure_reason: Option<String>,
    pub created_at: String,
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
pub async fn insert_auth_event(pool: &SqlitePool, params: &AuthEventParams) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO auth_events (id, user_id, event_type, authenticator_id, client_ip, user_agent, client_hostname, client_os, client_arch, client_version, success, failure_reason)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&params.user_id)
    .bind(params.event_type.as_str())
    .bind(&params.authenticator_id)
    .bind(&params.client_ip)
    .bind(&params.user_agent)
    .bind(&params.client_hostname)
    .bind(&params.client_os)
    .bind(&params.client_arch)
    .bind(&params.client_version)
    .bind(i64::from(params.success))
    .bind(&params.failure_reason)
    .execute(pool)
    .await?;

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
pub async fn get_auth_events(pool: &SqlitePool, query: &AuthEventQuery) -> Result<Vec<AuthEvent>> {
    let mut sql = String::from(
        "SELECT id, user_id, event_type, authenticator_id, client_ip, user_agent, client_hostname, client_os, client_arch, client_version, success, failure_reason, created_at
         FROM auth_events WHERE 1=1",
    );
    let mut binds: Vec<String> = Vec::new();

    if let Some(user_id) = &query.user_id {
        sql.push_str(" AND user_id = ?");
        binds.push(user_id.clone());
    }

    if let Some(event_type) = &query.event_type {
        sql.push_str(" AND event_type = ?");
        binds.push(event_type.clone());
    }

    if let Some(client_ip) = &query.client_ip {
        sql.push_str(" AND client_ip = ?");
        binds.push(client_ip.clone());
    }

    if let Some(since) = &query.since {
        sql.push_str(" AND created_at >= ?");
        binds.push(since.clone());
    }

    sql.push_str(" ORDER BY created_at DESC");

    let limit = query.limit.unwrap_or(100);
    sql.push_str(" LIMIT ?");
    binds.push(limit.to_string());

    // Build the query dynamically
    let mut db_query = sqlx::query_as::<_, AuthEvent>(&sql);
    for bind in binds {
        db_query = db_query.bind(bind);
    }

    let events = db_query.fetch_all(pool).await?;
    Ok(events)
}

/// Delete authentication events older than the specified timestamp.
/// Use for retention policy enforcement (e.g., delete events older than 90 days).
pub async fn delete_old_auth_events(pool: &SqlitePool, before: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM auth_events WHERE created_at < ?")
        .bind(before)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}
