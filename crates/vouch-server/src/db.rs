//! Database queries.

use anyhow::Result;
use jiff::Timestamp;
use sqlx::SqlitePool;
use uuid::Uuid;

/// User record.
#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    #[allow(dead_code)]
    pub name: Option<String>,
}

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
}

/// Session record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub authenticator_id: String,
    pub expires_at: String,
}

/// Create or get a user by email.
pub async fn upsert_user(pool: &SqlitePool, email: &str, name: Option<&str>) -> Result<User> {
    let id = Uuid::new_v4().to_string();

    // Try to insert, ignore if exists
    sqlx::query("INSERT OR IGNORE INTO users (id, email, name) VALUES (?, ?, ?)")
        .bind(&id)
        .bind(email)
        .bind(name)
        .execute(pool)
        .await?;

    // Fetch the user
    let user = sqlx::query_as::<_, User>("SELECT id, email, name FROM users WHERE email = ?")
        .bind(email)
        .fetch_one(pool)
        .await?;

    Ok(user)
}

/// Get a user by email.
pub async fn get_user_by_email(pool: &SqlitePool, email: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>("SELECT id, email, name FROM users WHERE email = ?")
        .bind(email)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

/// Get a user by ID.
pub async fn get_user_by_id(pool: &SqlitePool, user_id: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>("SELECT id, email, name FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

/// Create a new authenticator.
pub async fn create_authenticator(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    credential_id: &[u8],
    public_key: &[u8],
    aaguid: Option<&str>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO authenticators (id, user_id, name, credential_id, public_key, counter, aaguid) VALUES (?, ?, ?, ?, ?, 0, ?)"
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(credential_id)
    .bind(public_key)
    .bind(aaguid)
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
        "SELECT id, user_id, name, credential_id, public_key, counter, created_at, aaguid FROM authenticators WHERE user_id = ?"
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
        "SELECT id, user_id, name, credential_id, public_key, counter, created_at, aaguid FROM authenticators WHERE credential_id = ?"
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
        "SELECT id, user_id, name, credential_id, public_key, counter, created_at, aaguid FROM authenticators WHERE id = ?"
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

/// Create a new session.
pub async fn create_session(
    pool: &SqlitePool,
    user_id: &str,
    token_hash: &str,
    authenticator_id: &str,
    expires_at: &str,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();

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

/// Delete expired sessions.
#[allow(dead_code)]
pub async fn delete_expired_sessions(pool: &SqlitePool, now: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

// ============================================================================
// Device Authorization (RFC 8628)
// ============================================================================

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
#[allow(dead_code)]
pub async fn delete_expired_device_auth_requests(pool: &SqlitePool, now: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM device_auth_requests WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?;

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
#[allow(dead_code)]
pub async fn delete_expired_oidc_states(pool: &SqlitePool, now: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM oidc_states WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

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
// Admin Users
// ============================================================================

/// Admin user record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct AdminUser {
    pub id: String,
    pub email: String,
    pub created_at: String,
}

/// Check if an email is an admin.
#[allow(dead_code)]
pub async fn is_admin(pool: &SqlitePool, email: &str) -> Result<bool> {
    let row = sqlx::query_as::<_, AdminUser>(
        "SELECT id, email, created_at FROM admin_users WHERE email = ?",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    Ok(row.is_some())
}

/// Get all admin users.
#[allow(dead_code)]
pub async fn get_admin_users(pool: &SqlitePool) -> Result<Vec<AdminUser>> {
    let admins = sqlx::query_as::<_, AdminUser>(
        "SELECT id, email, created_at FROM admin_users ORDER BY email",
    )
    .fetch_all(pool)
    .await?;

    Ok(admins)
}

/// Add an admin user.
#[allow(dead_code)]
pub async fn add_admin_user(pool: &SqlitePool, email: &str) -> Result<String> {
    let id = Uuid::new_v4().to_string();

    sqlx::query("INSERT OR IGNORE INTO admin_users (id, email) VALUES (?, ?)")
        .bind(&id)
        .bind(email)
        .execute(pool)
        .await?;

    Ok(id)
}

/// Remove an admin user.
#[allow(dead_code)]
pub async fn remove_admin_user(pool: &SqlitePool, email: &str) -> Result<()> {
    sqlx::query("DELETE FROM admin_users WHERE email = ?")
        .bind(email)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// User Management (Admin)
// ============================================================================

/// User with authenticator count for admin listing.
#[derive(Debug, sqlx::FromRow)]
pub struct UserWithAuthCount {
    pub id: String,
    pub email: String,
    #[allow(dead_code)]
    pub name: Option<String>,
    pub created_at: String,
    pub authenticator_count: i64,
}

/// List all users with their authenticator counts.
pub async fn list_users_with_auth_count(pool: &SqlitePool) -> Result<Vec<UserWithAuthCount>> {
    let users = sqlx::query_as::<_, UserWithAuthCount>(
        "SELECT u.id, u.email, u.name, u.created_at,
                (SELECT COUNT(*) FROM authenticators a WHERE a.user_id = u.id) as authenticator_count
         FROM users u
         ORDER BY u.email",
    )
    .fetch_all(pool)
    .await?;

    Ok(users)
}

/// Delete a user and all associated data.
pub async fn delete_user(pool: &SqlitePool, user_id: &str) -> Result<()> {
    // Due to CASCADE, this will delete authenticators and sessions
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Key Management
// ============================================================================

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
pub async fn delete_authenticator(pool: &SqlitePool, authenticator_id: &str) -> Result<u64> {
    // Clear authenticator_id references in device_auth_requests
    // (the FK doesn't have ON DELETE CASCADE/SET NULL)
    sqlx::query(
        "UPDATE device_auth_requests SET authenticator_id = NULL WHERE authenticator_id = ?",
    )
    .bind(authenticator_id)
    .execute(pool)
    .await?;

    let result = sqlx::query("DELETE FROM authenticators WHERE id = ?")
        .bind(authenticator_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}
