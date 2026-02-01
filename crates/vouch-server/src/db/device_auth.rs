// SPDX-License-Identifier: BUSL-1.1
//! Device Authorization (RFC 8628) database operations.

use anyhow::Result;
use jiff::Timestamp;
use sqlx::SqlitePool;
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
    pub expires_at: String,
    pub interval_seconds: i64,
    pub last_poll_at: Option<String>,
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
    pub expires_at: String,
}

/// Create a new device authorization request.
pub async fn create_device_auth_request(
    pool: &SqlitePool,
    device_code_hash: &str,
    user_code: &str,
    expires_at: &str,
    interval_seconds: i64,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO device_auth_requests (id, device_code_hash, user_code, expires_at, interval_seconds) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(device_code_hash)
    .bind(user_code)
    .bind(expires_at)
    .bind(interval_seconds)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a device auth request by device code hash.
pub async fn get_device_auth_by_code_hash(
    pool: &SqlitePool,
    device_code_hash: &str,
) -> Result<Option<DeviceAuthRequest>> {
    let request = sqlx::query_as::<_, DeviceAuthRequest>(
        "SELECT id, device_code_hash, user_code, status, user_id, user_email, authenticator_id, expires_at, interval_seconds, last_poll_at FROM device_auth_requests WHERE device_code_hash = ?"
    )
    .bind(device_code_hash)
    .fetch_optional(pool)
    .await?;

    Ok(request)
}

/// Get a device auth request by user code.
pub async fn get_device_auth_by_user_code(
    pool: &SqlitePool,
    user_code: &str,
) -> Result<Option<DeviceAuthRequest>> {
    let request = sqlx::query_as::<_, DeviceAuthRequest>(
        "SELECT id, device_code_hash, user_code, status, user_id, user_email, authenticator_id, expires_at, interval_seconds, last_poll_at FROM device_auth_requests WHERE user_code = ?"
    )
    .bind(user_code)
    .fetch_optional(pool)
    .await?;

    Ok(request)
}

/// Get a device auth request by ID.
pub async fn get_device_auth_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<DeviceAuthRequest>> {
    let request = sqlx::query_as::<_, DeviceAuthRequest>(
        "SELECT id, device_code_hash, user_code, status, user_id, user_email, authenticator_id, expires_at, interval_seconds, last_poll_at FROM device_auth_requests WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(request)
}

/// Authorize a device auth request (mark as authorized with user info).
pub async fn authorize_device_auth(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    user_email: &str,
    authenticator_id: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE device_auth_requests SET status = 'authorized', user_id = ?, user_email = ?, authenticator_id = ? WHERE id = ?"
    )
    .bind(user_id)
    .bind(user_email)
    .bind(authenticator_id)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Deny a device auth request.
#[allow(dead_code)]
pub async fn deny_device_auth(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("UPDATE device_auth_requests SET status = 'denied' WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Update the last poll time for a device auth request.
/// Returns true if poll was allowed, false if polling too fast.
pub async fn update_device_auth_poll_time(
    pool: &SqlitePool,
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
    if let Some(last_poll) = &request.last_poll_at
        && let Ok(last_poll_ts) = last_poll.parse::<Timestamp>()
    {
        let elapsed = now.as_second() - last_poll_ts.as_second();
        if elapsed < interval_seconds {
            return Ok(false);
        }
    }

    // Update last poll time
    sqlx::query("UPDATE device_auth_requests SET last_poll_at = ? WHERE id = ?")
        .bind(&now_str)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(true)
}

/// Delete expired device auth requests.
///
/// Performs application-level cascade deletes for DSQL compatibility:
/// 1. Delete oidc_states for expired requests
/// 2. Delete the expired requests
pub async fn delete_expired_device_auth_requests(pool: &SqlitePool, now: &str) -> Result<u64> {
    let mut tx = pool.begin().await?;

    // 1. Delete oidc_states for expired device auth requests
    sqlx::query(
        "DELETE FROM oidc_states WHERE device_auth_id IN
         (SELECT id FROM device_auth_requests WHERE expires_at < ?)",
    )
    .bind(now)
    .execute(&mut *tx)
    .await?;

    // 2. Delete the expired requests
    let result = sqlx::query("DELETE FROM device_auth_requests WHERE expires_at < ?")
        .bind(now)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(result.rows_affected())
}

// ============================================================================
// OIDC State
// ============================================================================

/// Create a new OIDC state.
pub async fn create_oidc_state(
    pool: &SqlitePool,
    state: &str,
    device_auth_id: &str,
    nonce: &str,
    expires_at: &str,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO oidc_states (id, state, device_auth_id, nonce, expires_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(state)
    .bind(device_auth_id)
    .bind(nonce)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get an OIDC state by state value.
pub async fn get_oidc_state(pool: &SqlitePool, state: &str) -> Result<Option<OidcState>> {
    let oidc_state = sqlx::query_as::<_, OidcState>(
        "SELECT id, state, device_auth_id, nonce, expires_at FROM oidc_states WHERE state = ?",
    )
    .bind(state)
    .fetch_optional(pool)
    .await?;

    Ok(oidc_state)
}

/// Delete an OIDC state.
pub async fn delete_oidc_state(pool: &SqlitePool, state: &str) -> Result<()> {
    sqlx::query("DELETE FROM oidc_states WHERE state = ?")
        .bind(state)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete expired OIDC states.
pub async fn delete_expired_oidc_states(pool: &SqlitePool, now: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM oidc_states WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}
