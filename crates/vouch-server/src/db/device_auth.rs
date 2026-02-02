// SPDX-License-Identifier: BUSL-1.1
//! Device Authorization (RFC 8628) database operations.

use super::Pool;
use super::compat::BuildSql;
use super::schema::{DeviceAuthRequests, OidcStates};
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_optional, tx_execute};
use anyhow::Result;
use jiff::Timestamp;
use sea_query::{Expr, Query};
use uuid::Uuid;

/// Device authorization status (RFC 8628 state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAuthStatus {
    /// Waiting for user to authorize.
    Pending,
    /// User has authorized the request.
    Authorized,
    /// User denied the request.
    Denied,
}

impl DeviceAuthStatus {
    /// Parse a status string from the database.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "authorized" => Some(Self::Authorized),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

/// Device authorization request record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct DeviceAuthRequest {
    pub id: String,
    pub device_code_hash: String,
    pub user_code: String,
    pub status: String,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub authenticator_id: Option<String>,
    pub expires_at: DbTimestamp,
    pub interval_seconds: i64,
    pub last_poll_at: Option<DbTimestamp>,
}

impl DeviceAuthRequest {
    /// Get the parsed status enum.
    pub fn status(&self) -> Option<DeviceAuthStatus> {
        DeviceAuthStatus::from_str(&self.status)
    }
}

/// OIDC state record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct OidcState {
    pub id: String,
    pub state: String,
    pub device_auth_id: String,
    pub nonce: String,
    pub expires_at: DbTimestamp,
}

/// Create a new device authorization request.
pub async fn create_device_auth_request(
    pool: &Pool,
    device_code_hash: &str,
    user_code: &str,
    expires_at: &str,
    interval_seconds: i64,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let now = Timestamp::now().to_string();
    let db_type = pool.db_type();

    let sql = {
        let query = Query::insert()
            .into_table(DeviceAuthRequests::Table)
            .columns([
                DeviceAuthRequests::Id,
                DeviceAuthRequests::DeviceCodeHash,
                DeviceAuthRequests::UserCode,
                DeviceAuthRequests::ExpiresAt,
                DeviceAuthRequests::IntervalSeconds,
                DeviceAuthRequests::CreatedAt,
            ])
            .values_panic([
                id.clone().into(),
                device_code_hash.into(),
                user_code.into(),
                expires_at.into(),
                interval_seconds.into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Get a device auth request by device code hash.
pub async fn get_device_auth_by_code_hash(
    pool: &Pool,
    device_code_hash: &str,
) -> Result<Option<DeviceAuthRequest>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                DeviceAuthRequests::Id,
                DeviceAuthRequests::DeviceCodeHash,
                DeviceAuthRequests::UserCode,
                DeviceAuthRequests::Status,
                DeviceAuthRequests::UserId,
                DeviceAuthRequests::UserEmail,
                DeviceAuthRequests::AuthenticatorId,
                DeviceAuthRequests::ExpiresAt,
                DeviceAuthRequests::IntervalSeconds,
                DeviceAuthRequests::LastPollAt,
            ])
            .from(DeviceAuthRequests::Table)
            .and_where(Expr::col(DeviceAuthRequests::DeviceCodeHash).eq(device_code_hash))
            .to_owned();
        query.build_sql(db_type)
    };

    let request = db_fetch_optional!(pool, sqlx::query_as::<_, DeviceAuthRequest>(&sql))?;

    Ok(request)
}

/// Get a device auth request by user code.
pub async fn get_device_auth_by_user_code(
    pool: &Pool,
    user_code: &str,
) -> Result<Option<DeviceAuthRequest>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                DeviceAuthRequests::Id,
                DeviceAuthRequests::DeviceCodeHash,
                DeviceAuthRequests::UserCode,
                DeviceAuthRequests::Status,
                DeviceAuthRequests::UserId,
                DeviceAuthRequests::UserEmail,
                DeviceAuthRequests::AuthenticatorId,
                DeviceAuthRequests::ExpiresAt,
                DeviceAuthRequests::IntervalSeconds,
                DeviceAuthRequests::LastPollAt,
            ])
            .from(DeviceAuthRequests::Table)
            .and_where(Expr::col(DeviceAuthRequests::UserCode).eq(user_code))
            .to_owned();
        query.build_sql(db_type)
    };

    let request = db_fetch_optional!(pool, sqlx::query_as::<_, DeviceAuthRequest>(&sql))?;

    Ok(request)
}

/// Get a device auth request by ID.
pub async fn get_device_auth_by_id(pool: &Pool, id: &str) -> Result<Option<DeviceAuthRequest>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                DeviceAuthRequests::Id,
                DeviceAuthRequests::DeviceCodeHash,
                DeviceAuthRequests::UserCode,
                DeviceAuthRequests::Status,
                DeviceAuthRequests::UserId,
                DeviceAuthRequests::UserEmail,
                DeviceAuthRequests::AuthenticatorId,
                DeviceAuthRequests::ExpiresAt,
                DeviceAuthRequests::IntervalSeconds,
                DeviceAuthRequests::LastPollAt,
            ])
            .from(DeviceAuthRequests::Table)
            .and_where(Expr::col(DeviceAuthRequests::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    let request = db_fetch_optional!(pool, sqlx::query_as::<_, DeviceAuthRequest>(&sql))?;

    Ok(request)
}

/// Authorize a device auth request (mark as authorized with user info).
pub async fn authorize_device_auth(
    pool: &Pool,
    id: &str,
    user_id: &str,
    user_email: &str,
    authenticator_id: &str,
) -> Result<()> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::update()
            .table(DeviceAuthRequests::Table)
            .value(DeviceAuthRequests::Status, "authorized")
            .value(DeviceAuthRequests::UserId, user_id)
            .value(DeviceAuthRequests::UserEmail, user_email)
            .value(DeviceAuthRequests::AuthenticatorId, authenticator_id)
            .and_where(Expr::col(DeviceAuthRequests::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

/// Deny a device auth request.
#[allow(dead_code)]
pub async fn deny_device_auth(pool: &Pool, id: &str) -> Result<()> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::update()
            .table(DeviceAuthRequests::Table)
            .value(DeviceAuthRequests::Status, "denied")
            .and_where(Expr::col(DeviceAuthRequests::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

/// Update the last poll time for a device auth request.
/// Returns true if poll was allowed, false if polling too fast.
pub async fn update_device_auth_poll_time(
    pool: &Pool,
    id: &str,
    interval_seconds: i64,
) -> Result<bool> {
    let now = Timestamp::now();
    let now_str = now.to_string();

    // Get current record
    let request = get_device_auth_by_id(pool, id).await?;
    let Some(request) = request else {
        return Ok(false);
    };

    // Check if polling too fast
    if let Some(last_poll) = &request.last_poll_at {
        let last_poll_ts = last_poll.to_jiff();
        let elapsed = now.as_second() - last_poll_ts.as_second();
        if elapsed < interval_seconds {
            return Ok(false);
        }
    }

    // Update last poll time
    let db_type = pool.db_type();
    let sql = {
        let query = Query::update()
            .table(DeviceAuthRequests::Table)
            .value(DeviceAuthRequests::LastPollAt, now_str.clone())
            .and_where(Expr::col(DeviceAuthRequests::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(true)
}

/// Delete expired device auth requests.
///
/// Performs application-level cascade deletes for DSQL compatibility:
/// 1. Delete oidc_states for expired requests
/// 2. Delete the expired requests
pub async fn delete_expired_device_auth_requests(pool: &Pool, now: &str) -> Result<u64> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();

    // 1. Delete oidc_states for expired device auth requests
    let sql1 = {
        let subquery = Query::select()
            .column(DeviceAuthRequests::Id)
            .from(DeviceAuthRequests::Table)
            .and_where(Expr::col(DeviceAuthRequests::ExpiresAt).lt(now))
            .to_owned();
        let query = Query::delete()
            .from_table(OidcStates::Table)
            .and_where(Expr::col(OidcStates::DeviceAuthId).in_subquery(subquery))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql1))?;

    // 2. Delete the expired requests
    let sql2 = {
        let query = Query::delete()
            .from_table(DeviceAuthRequests::Table)
            .and_where(Expr::col(DeviceAuthRequests::ExpiresAt).lt(now))
            .to_owned();
        query.build_sql(db_type)
    };
    let result = tx_execute!(tx, sqlx::query(&sql2))?;

    tx.commit().await?;
    Ok(result.rows_affected())
}

// ============================================================================
// OIDC State
// ============================================================================

/// Create a new OIDC state.
pub async fn create_oidc_state(
    pool: &Pool,
    state: &str,
    device_auth_id: &str,
    nonce: &str,
    expires_at: &str,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let now = Timestamp::now().to_string();
    let db_type = pool.db_type();

    let sql = {
        let query = Query::insert()
            .into_table(OidcStates::Table)
            .columns([
                OidcStates::Id,
                OidcStates::State,
                OidcStates::DeviceAuthId,
                OidcStates::Nonce,
                OidcStates::ExpiresAt,
                OidcStates::CreatedAt,
            ])
            .values_panic([
                id.clone().into(),
                state.into(),
                device_auth_id.into(),
                nonce.into(),
                expires_at.into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Get an OIDC state by state value.
pub async fn get_oidc_state(pool: &Pool, state: &str) -> Result<Option<OidcState>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                OidcStates::Id,
                OidcStates::State,
                OidcStates::DeviceAuthId,
                OidcStates::Nonce,
                OidcStates::ExpiresAt,
            ])
            .from(OidcStates::Table)
            .and_where(Expr::col(OidcStates::State).eq(state))
            .to_owned();
        query.build_sql(db_type)
    };

    let oidc_state = db_fetch_optional!(pool, sqlx::query_as::<_, OidcState>(&sql))?;

    Ok(oidc_state)
}

/// Delete an OIDC state.
pub async fn delete_oidc_state(pool: &Pool, state: &str) -> Result<()> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(OidcStates::Table)
            .and_where(Expr::col(OidcStates::State).eq(state))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

/// Delete expired OIDC states.
pub async fn delete_expired_oidc_states(pool: &Pool, now: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(OidcStates::Table)
            .and_where(Expr::col(OidcStates::ExpiresAt).lt(now))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}
