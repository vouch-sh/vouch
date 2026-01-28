// SPDX-License-Identifier: BUSL-1.1
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
    /// Organization ID (NULL for personal accounts like gmail.com).
    pub org_id: Option<String>,
    /// Whether this user is an admin of their organization.
    pub is_org_admin: bool,
}

/// Organization record for domain-based multi-tenancy.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct Organization {
    pub id: String,
    pub domain: String,
    pub name: Option<String>,
    pub created_at: String,
    pub created_by_user_id: Option<String>,
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
    /// User handle stored in discoverable credentials (resident keys).
    #[allow(dead_code)]
    pub user_handle: Option<Vec<u8>>,
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
///
/// Note: This function is primarily used for testing. In production, users are
/// created via the OIDC enrollment flow using `upsert_user_with_org`.
#[allow(dead_code)]
pub async fn upsert_user(pool: &SqlitePool, email: &str, name: Option<&str>) -> Result<User> {
    let id = Uuid::now_v7().to_string();

    // Try to insert, ignore if exists
    sqlx::query("INSERT OR IGNORE INTO users (id, email, name) VALUES (?, ?, ?)")
        .bind(&id)
        .bind(email)
        .bind(name)
        .execute(pool)
        .await?;

    // Fetch the user
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, name, org_id, is_org_admin FROM users WHERE email = ?",
    )
    .bind(email)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

/// Create or get a user by email, associating them with an organization.
pub async fn upsert_user_with_org(
    pool: &SqlitePool,
    email: &str,
    name: Option<&str>,
    org_id: Option<&str>,
    is_org_admin: bool,
) -> Result<User> {
    let id = Uuid::now_v7().to_string();

    // Try to insert with org info, ignore if exists
    sqlx::query(
        "INSERT OR IGNORE INTO users (id, email, name, org_id, is_org_admin) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(email)
    .bind(name)
    .bind(org_id)
    .bind(is_org_admin)
    .execute(pool)
    .await?;

    // Fetch the user
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, name, org_id, is_org_admin FROM users WHERE email = ?",
    )
    .bind(email)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

/// Get a user by email.
#[allow(dead_code)]
pub async fn get_user_by_email(pool: &SqlitePool, email: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, name, org_id, is_org_admin FROM users WHERE email = ?",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Get a user by ID.
pub async fn get_user_by_id(pool: &SqlitePool, user_id: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, name, org_id, is_org_admin FROM users WHERE id = ?",
    )
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

/// Create a new session.
pub async fn create_session(
    pool: &SqlitePool,
    user_id: &str,
    token_hash: &str,
    authenticator_id: &str,
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
    let id = Uuid::now_v7().to_string();

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
    #[allow(dead_code)]
    pub org_id: Option<String>,
    #[allow(dead_code)]
    pub is_org_admin: bool,
}

/// List all users with their authenticator counts.
pub async fn list_users_with_auth_count(pool: &SqlitePool) -> Result<Vec<UserWithAuthCount>> {
    let users = sqlx::query_as::<_, UserWithAuthCount>(
        "SELECT u.id, u.email, u.name, u.created_at,
                (SELECT COUNT(*) FROM authenticators a WHERE a.user_id = u.id) as authenticator_count,
                u.org_id, u.is_org_admin
         FROM users u
         ORDER BY u.email",
    )
    .fetch_all(pool)
    .await?;

    Ok(users)
}

/// List users in a specific organization with their authenticator counts.
pub async fn list_users_with_auth_count_by_org(
    pool: &SqlitePool,
    org_id: &str,
) -> Result<Vec<UserWithAuthCount>> {
    let users = sqlx::query_as::<_, UserWithAuthCount>(
        "SELECT u.id, u.email, u.name, u.created_at,
                (SELECT COUNT(*) FROM authenticators a WHERE a.user_id = u.id) as authenticator_count,
                u.org_id, u.is_org_admin
         FROM users u
         WHERE u.org_id = ?
         ORDER BY u.email",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(users)
}

// ============================================================================
// Organization Management
// ============================================================================

/// Get an organization by domain.
pub async fn get_org_by_domain(pool: &SqlitePool, domain: &str) -> Result<Option<Organization>> {
    let org = sqlx::query_as::<_, Organization>(
        "SELECT id, domain, name, created_at, created_by_user_id FROM organizations WHERE domain = ?",
    )
    .bind(domain)
    .fetch_optional(pool)
    .await?;

    Ok(org)
}

/// Get an organization by ID.
#[allow(dead_code)]
pub async fn get_org_by_id(pool: &SqlitePool, org_id: &str) -> Result<Option<Organization>> {
    let org = sqlx::query_as::<_, Organization>(
        "SELECT id, domain, name, created_at, created_by_user_id FROM organizations WHERE id = ?",
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?;

    Ok(org)
}

/// Create a new organization.
pub async fn create_organization(
    pool: &SqlitePool,
    domain: &str,
    name: Option<&str>,
    created_by_user_id: Option<&str>,
) -> Result<Organization> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO organizations (id, domain, name, created_by_user_id) VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(domain)
    .bind(name)
    .bind(created_by_user_id)
    .execute(pool)
    .await?;

    let org = sqlx::query_as::<_, Organization>(
        "SELECT id, domain, name, created_at, created_by_user_id FROM organizations WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(pool)
    .await?;

    Ok(org)
}

/// Get or create an organization by domain.
/// Returns (org, is_new) tuple where is_new indicates if the org was just created.
pub async fn get_or_create_org_by_domain(
    pool: &SqlitePool,
    domain: &str,
    name: Option<&str>,
    created_by_user_id: Option<&str>,
) -> Result<(Organization, bool)> {
    // Check if org exists
    if let Some(org) = get_org_by_domain(pool, domain).await? {
        return Ok((org, false));
    }

    // Create new org
    let org = create_organization(pool, domain, name, created_by_user_id).await?;
    Ok((org, true))
}

/// Update a user's organization membership.
#[allow(dead_code)]
pub async fn set_user_org(
    pool: &SqlitePool,
    _user_id: &str,
    org_id: Option<&str>,
    is_org_admin: bool,
) -> Result<()> {
    sqlx::query("UPDATE users SET org_id = ?, is_org_admin = ? WHERE id = ?")
        .bind(org_id)
        .bind(is_org_admin)
        .execute(pool)
        .await?;

    Ok(())
}

/// Count users in an organization.
#[allow(dead_code)]
pub async fn count_users_in_org(pool: &SqlitePool, org_id: &str) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE org_id = ?")
        .bind(org_id)
        .fetch_one(pool)
        .await?;

    Ok(row.0)
}

/// List all organizations.
#[allow(dead_code)]
pub async fn list_organizations(pool: &SqlitePool) -> Result<Vec<Organization>> {
    let orgs = sqlx::query_as::<_, Organization>(
        "SELECT id, domain, name, created_at, created_by_user_id FROM organizations ORDER BY domain",
    )
    .fetch_all(pool)
    .await?;

    Ok(orgs)
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

// ============================================================================
// SCIM 2.0
// ============================================================================

/// SCIM token record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct ScimToken {
    pub id: String,
    pub token_hash: String,
    pub description: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
}

/// Get a SCIM token by its hash.
pub async fn get_scim_token_by_hash(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<ScimToken>> {
    let token = sqlx::query_as::<_, ScimToken>(
        "SELECT id, token_hash, description, created_at, last_used_at, expires_at FROM scim_tokens WHERE token_hash = ?"
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;

    Ok(token)
}

/// Update SCIM token last used timestamp.
pub async fn update_scim_token_last_used(pool: &SqlitePool, token_id: &str) -> Result<()> {
    sqlx::query("UPDATE scim_tokens SET last_used_at = datetime('now') WHERE id = ?")
        .bind(token_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Create a new SCIM token.
#[allow(dead_code)]
pub async fn create_scim_token(
    pool: &SqlitePool,
    token_hash: &str,
    description: Option<&str>,
    expires_at: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO scim_tokens (id, token_hash, description, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(token_hash)
    .bind(description)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Delete a SCIM token.
#[allow(dead_code)]
pub async fn delete_scim_token(pool: &SqlitePool, token_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM scim_tokens WHERE id = ?")
        .bind(token_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// List all SCIM tokens.
#[allow(dead_code)]
pub async fn list_scim_tokens(pool: &SqlitePool) -> Result<Vec<ScimToken>> {
    let tokens = sqlx::query_as::<_, ScimToken>(
        "SELECT id, token_hash, description, created_at, last_used_at, expires_at FROM scim_tokens ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?;

    Ok(tokens)
}

/// Insert SCIM audit log entry.
pub async fn insert_scim_audit(
    pool: &SqlitePool,
    operation: &str,
    resource_type: &str,
    resource_id: &str,
    actor_token_id: Option<&str>,
    details: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO scim_audit_log (id, operation, resource_type, resource_id, actor_token_id, details) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(operation)
    .bind(resource_type)
    .bind(resource_id)
    .bind(actor_token_id)
    .bind(details)
    .execute(pool)
    .await?;

    Ok(id)
}

/// SCIM user record (includes active and external_id fields).
#[derive(Debug, sqlx::FromRow)]
pub struct ScimUserRecord {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub created_at: String,
    pub active: bool,
    pub external_id: Option<String>,
}

/// List users for SCIM with optional filter.
pub async fn list_scim_users(
    pool: &SqlitePool,
    filter: Option<&str>,
    start_index: usize,
    count: usize,
) -> Result<Vec<ScimUserRecord>> {
    // Parse simple SCIM filter (userName eq "value" or email eq "value")
    let (sql, filter_value) = if let Some(f) = filter {
        if let Some(value) = parse_scim_filter(f, "userName") {
            (
                "SELECT id, email, name, created_at, active, external_id FROM users WHERE email = ? ORDER BY email LIMIT ? OFFSET ?",
                Some(value),
            )
        } else if let Some(value) = parse_scim_filter(f, "email") {
            (
                "SELECT id, email, name, created_at, active, external_id FROM users WHERE email = ? ORDER BY email LIMIT ? OFFSET ?",
                Some(value),
            )
        } else if let Some(value) = parse_scim_filter(f, "externalId") {
            (
                "SELECT id, email, name, created_at, active, external_id FROM users WHERE external_id = ? ORDER BY email LIMIT ? OFFSET ?",
                Some(value),
            )
        } else {
            (
                "SELECT id, email, name, created_at, active, external_id FROM users ORDER BY email LIMIT ? OFFSET ?",
                None,
            )
        }
    } else {
        (
            "SELECT id, email, name, created_at, active, external_id FROM users ORDER BY email LIMIT ? OFFSET ?",
            None,
        )
    };

    let offset = start_index.saturating_sub(1); // SCIM is 1-indexed

    let users = if let Some(val) = filter_value {
        sqlx::query_as::<_, ScimUserRecord>(sql)
            .bind(val)
            .bind(count as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
    } else {
        sqlx::query_as::<_, ScimUserRecord>(sql)
            .bind(count as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
    };

    Ok(users)
}

/// Count users for SCIM pagination.
pub async fn count_scim_users(pool: &SqlitePool, filter: Option<&str>) -> Result<usize> {
    let (sql, filter_value) = if let Some(f) = filter {
        if let Some(value) = parse_scim_filter(f, "userName") {
            ("SELECT COUNT(*) FROM users WHERE email = ?", Some(value))
        } else if let Some(value) = parse_scim_filter(f, "email") {
            ("SELECT COUNT(*) FROM users WHERE email = ?", Some(value))
        } else if let Some(value) = parse_scim_filter(f, "externalId") {
            (
                "SELECT COUNT(*) FROM users WHERE external_id = ?",
                Some(value),
            )
        } else {
            ("SELECT COUNT(*) FROM users", None)
        }
    } else {
        ("SELECT COUNT(*) FROM users", None)
    };

    let count: (i64,) = if let Some(val) = filter_value {
        sqlx::query_as(sql).bind(val).fetch_one(pool).await?
    } else {
        sqlx::query_as(sql).fetch_one(pool).await?
    };

    Ok(count.0 as usize)
}

/// Parse simple SCIM filter (e.g., `userName eq "john@example.com"`).
fn parse_scim_filter(filter: &str, attr: &str) -> Option<String> {
    let pattern = format!("{attr} eq ");
    let filter_lower = filter.to_lowercase();
    let pattern_lower = pattern.to_lowercase();
    if let Some(pos) = filter_lower.find(&pattern_lower) {
        // Get the rest of the string after the pattern
        let rest = filter.get(pos + pattern.len()..)?;
        // Extract quoted value
        if let Some(unquoted) = rest.strip_prefix('"')
            && let Some(end) = unquoted.find('"')
        {
            return unquoted.get(..end).map(|s| s.to_string());
        }
    }
    None
}

/// Get a user by ID for SCIM.
pub async fn get_scim_user(pool: &SqlitePool, user_id: &str) -> Result<Option<ScimUserRecord>> {
    let user = sqlx::query_as::<_, ScimUserRecord>(
        "SELECT id, email, name, created_at, active, external_id FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Create a user via SCIM.
pub async fn create_scim_user(
    pool: &SqlitePool,
    email: &str,
    name: Option<&str>,
    external_id: Option<&str>,
    active: bool,
) -> Result<ScimUserRecord> {
    let id = Uuid::now_v7().to_string();

    sqlx::query("INSERT INTO users (id, email, name, external_id, active) VALUES (?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(email)
        .bind(name)
        .bind(external_id)
        .bind(active)
        .execute(pool)
        .await?;

    // Fetch and return the created user
    let user = sqlx::query_as::<_, ScimUserRecord>(
        "SELECT id, email, name, created_at, active, external_id FROM users WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

/// Update a user via SCIM.
pub async fn update_scim_user(
    pool: &SqlitePool,
    user_id: &str,
    name: Option<&str>,
    external_id: Option<&str>,
    active: bool,
) -> Result<()> {
    sqlx::query("UPDATE users SET name = ?, external_id = ?, active = ? WHERE id = ?")
        .bind(name)
        .bind(external_id)
        .bind(active)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete all sessions for a user (for immediate session invalidation on SCIM deactivation).
pub async fn delete_sessions_for_user(pool: &SqlitePool, user_id: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

// ============================================================================
// OAuth Client Applications (Phase 7)
// ============================================================================

/// OAuth application type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthClientType {
    Web,
    Native,
    Spa,
    Service,
}

impl OAuthClientType {
    /// Convert to database string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
            Self::Spa => "spa",
            Self::Service => "service",
        }
    }

    /// Parse from database string.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "web" => Some(Self::Web),
            "native" => Some(Self::Native),
            "spa" => Some(Self::Spa),
            "service" => Some(Self::Service),
            _ => None,
        }
    }

    /// Whether this client type requires a client secret.
    #[must_use]
    pub fn requires_secret(&self) -> bool {
        matches!(self, Self::Web | Self::Service)
    }

    /// Whether this client type requires PKCE.
    #[must_use]
    #[allow(dead_code)]
    pub fn requires_pkce(&self) -> bool {
        matches!(self, Self::Native | Self::Spa)
    }
}

/// OAuth client application record.
#[derive(Debug, sqlx::FromRow)]
pub struct OAuthClient {
    pub id: String,
    pub user_id: String,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: String,
    pub active: i64,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
}

impl OAuthClient {
    /// Check if this client is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active != 0
    }

    /// Get the application type as enum.
    #[must_use]
    pub fn client_type(&self) -> Option<OAuthClientType> {
        OAuthClientType::from_str(&self.application_type)
    }

    /// Get redirect URIs as a vector.
    #[must_use]
    pub fn get_redirect_uris(&self) -> Vec<String> {
        serde_json::from_str(&self.redirect_uris).unwrap_or_default()
    }

    /// Check if a redirect URI is valid for this client.
    #[must_use]
    pub fn is_valid_redirect_uri(&self, uri: &str) -> bool {
        self.get_redirect_uris().iter().any(|u| u == uri)
    }
}

/// OAuth client secret record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct OAuthClientSecret {
    pub id: String,
    pub oauth_client_id: String,
    pub secret_hash: String,
    pub description: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl OAuthClientSecret {
    /// Check if this secret is valid (not revoked and not expired).
    #[must_use]
    pub fn is_valid(&self, now: &str) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if let Some(expires) = &self.expires_at
            && expires.as_str() < now
        {
            return false;
        }
        true
    }
}

/// OAuth usage event record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct OAuthUsageEvent {
    pub id: String,
    pub oauth_client_id: String,
    pub event_type: String,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: Option<String>,
    pub created_at: String,
}

/// OAuth usage event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum OAuthEventType {
    TokenIssued,
    TokenRefreshed,
    TokenRevoked,
    AuthSuccess,
    AuthFailure,
}

impl OAuthEventType {
    /// Convert to database string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TokenIssued => "token_issued",
            Self::TokenRefreshed => "token_refreshed",
            Self::TokenRevoked => "token_revoked",
            Self::AuthSuccess => "auth_success",
            Self::AuthFailure => "auth_failure",
        }
    }
}

/// Create a new OAuth client application.
pub async fn create_oauth_client(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    description: Option<&str>,
    application_type: OAuthClientType,
    redirect_uris: &[String],
) -> Result<(OAuthClient, String)> {
    let id = Uuid::now_v7().to_string();
    let client_id = Uuid::now_v7().to_string();
    let redirect_uris_json = serde_json::to_string(redirect_uris)?;

    sqlx::query(
        "INSERT INTO oauth_clients (id, user_id, client_id, name, description, application_type, redirect_uris)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(&client_id)
    .bind(name)
    .bind(description)
    .bind(application_type.as_str())
    .bind(&redirect_uris_json)
    .execute(pool)
    .await?;

    let client = get_oauth_client_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Just created OAuth client should exist"))?;

    Ok((client, client_id))
}

/// Get an OAuth client by internal ID.
pub async fn get_oauth_client_by_id(pool: &SqlitePool, id: &str) -> Result<Option<OAuthClient>> {
    let client = sqlx::query_as::<_, OAuthClient>(
        "SELECT id, user_id, client_id, name, description, application_type, redirect_uris, active, created_at, updated_at, last_used_at
         FROM oauth_clients WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(client)
}

/// Get an OAuth client by public client_id.
pub async fn get_oauth_client_by_client_id(
    pool: &SqlitePool,
    client_id: &str,
) -> Result<Option<OAuthClient>> {
    let client = sqlx::query_as::<_, OAuthClient>(
        "SELECT id, user_id, client_id, name, description, application_type, redirect_uris, active, created_at, updated_at, last_used_at
         FROM oauth_clients WHERE client_id = ?",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?;

    Ok(client)
}

/// Get all OAuth clients for a user.
pub async fn get_oauth_clients_for_user(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<OAuthClient>> {
    let clients = sqlx::query_as::<_, OAuthClient>(
        "SELECT id, user_id, client_id, name, description, application_type, redirect_uris, active, created_at, updated_at, last_used_at
         FROM oauth_clients WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(clients)
}

/// Update an OAuth client.
pub async fn update_oauth_client(
    pool: &SqlitePool,
    id: &str,
    name: &str,
    description: Option<&str>,
    redirect_uris: &[String],
) -> Result<()> {
    let redirect_uris_json = serde_json::to_string(redirect_uris)?;

    sqlx::query(
        "UPDATE oauth_clients SET name = ?, description = ?, redirect_uris = ?, updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(name)
    .bind(description)
    .bind(&redirect_uris_json)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Deactivate an OAuth client (soft delete).
#[allow(dead_code)]
pub async fn deactivate_oauth_client(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("UPDATE oauth_clients SET active = 0, updated_at = datetime('now') WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Reactivate an OAuth client.
#[allow(dead_code)]
pub async fn reactivate_oauth_client(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("UPDATE oauth_clients SET active = 1, updated_at = datetime('now') WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete an OAuth client permanently.
pub async fn delete_oauth_client(pool: &SqlitePool, id: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM oauth_clients WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Update last used timestamp for an OAuth client.
pub async fn update_oauth_client_last_used(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("UPDATE oauth_clients SET last_used_at = datetime('now') WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// OAuth Client Secrets
// ============================================================================

/// Create a new client secret.
/// Returns the secret record and the plaintext secret (only shown once).
pub async fn create_oauth_client_secret(
    pool: &SqlitePool,
    oauth_client_id: &str,
    secret_hash: &str,
    description: Option<&str>,
    expires_at: Option<&str>,
) -> Result<OAuthClientSecret> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO oauth_client_secrets (id, oauth_client_id, secret_hash, description, expires_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(oauth_client_id)
    .bind(secret_hash)
    .bind(description)
    .bind(expires_at)
    .execute(pool)
    .await?;

    let secret = sqlx::query_as::<_, OAuthClientSecret>(
        "SELECT id, oauth_client_id, secret_hash, description, created_at, expires_at, revoked_at
         FROM oauth_client_secrets WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(pool)
    .await?;

    Ok(secret)
}

/// Get all secrets for an OAuth client.
pub async fn get_oauth_client_secrets(
    pool: &SqlitePool,
    oauth_client_id: &str,
) -> Result<Vec<OAuthClientSecret>> {
    let secrets = sqlx::query_as::<_, OAuthClientSecret>(
        "SELECT id, oauth_client_id, secret_hash, description, created_at, expires_at, revoked_at
         FROM oauth_client_secrets WHERE oauth_client_id = ? ORDER BY created_at DESC",
    )
    .bind(oauth_client_id)
    .fetch_all(pool)
    .await?;

    Ok(secrets)
}

/// Get a secret by its hash.
pub async fn get_oauth_secret_by_hash(
    pool: &SqlitePool,
    secret_hash: &str,
) -> Result<Option<OAuthClientSecret>> {
    let secret = sqlx::query_as::<_, OAuthClientSecret>(
        "SELECT id, oauth_client_id, secret_hash, description, created_at, expires_at, revoked_at
         FROM oauth_client_secrets WHERE secret_hash = ?",
    )
    .bind(secret_hash)
    .fetch_optional(pool)
    .await?;

    Ok(secret)
}

/// Revoke a client secret.
#[allow(dead_code)]
pub async fn revoke_oauth_client_secret(pool: &SqlitePool, secret_id: &str) -> Result<()> {
    sqlx::query("UPDATE oauth_client_secrets SET revoked_at = datetime('now') WHERE id = ?")
        .bind(secret_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Revoke all secrets for an OAuth client.
pub async fn revoke_all_oauth_client_secrets(
    pool: &SqlitePool,
    oauth_client_id: &str,
) -> Result<u64> {
    let result = sqlx::query(
        "UPDATE oauth_client_secrets SET revoked_at = datetime('now') WHERE oauth_client_id = ? AND revoked_at IS NULL",
    )
    .bind(oauth_client_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

// ============================================================================
// OAuth Usage Events
// ============================================================================

/// Record an OAuth usage event.
pub async fn record_oauth_event(
    pool: &SqlitePool,
    oauth_client_id: &str,
    event_type: OAuthEventType,
    user_id: Option<&str>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    details: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO oauth_usage_events (id, oauth_client_id, event_type, user_id, ip_address, user_agent, details)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(oauth_client_id)
    .bind(event_type.as_str())
    .bind(user_id)
    .bind(ip_address)
    .bind(user_agent)
    .bind(details)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get usage events for an OAuth client.
#[allow(dead_code)]
pub async fn get_oauth_usage_events(
    pool: &SqlitePool,
    oauth_client_id: &str,
    limit: i64,
) -> Result<Vec<OAuthUsageEvent>> {
    let events = sqlx::query_as::<_, OAuthUsageEvent>(
        "SELECT id, oauth_client_id, event_type, user_id, ip_address, user_agent, details, created_at
         FROM oauth_usage_events WHERE oauth_client_id = ? ORDER BY created_at DESC LIMIT ?",
    )
    .bind(oauth_client_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

/// Get usage statistics for an OAuth client.
#[derive(Debug, sqlx::FromRow)]
pub struct OAuthUsageStats {
    pub event_type: String,
    pub count: i64,
}

pub async fn get_oauth_usage_stats(
    pool: &SqlitePool,
    oauth_client_id: &str,
    since: Option<&str>,
) -> Result<Vec<OAuthUsageStats>> {
    let stats = if let Some(since) = since {
        sqlx::query_as::<_, OAuthUsageStats>(
            "SELECT event_type, COUNT(*) as count FROM oauth_usage_events
             WHERE oauth_client_id = ? AND created_at >= ?
             GROUP BY event_type",
        )
        .bind(oauth_client_id)
        .bind(since)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, OAuthUsageStats>(
            "SELECT event_type, COUNT(*) as count FROM oauth_usage_events
             WHERE oauth_client_id = ?
             GROUP BY event_type",
        )
        .bind(oauth_client_id)
        .fetch_all(pool)
        .await?
    };

    Ok(stats)
}

/// Delete old usage events (for retention policy).
pub async fn delete_old_oauth_usage_events(pool: &SqlitePool, before: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM oauth_usage_events WHERE created_at < ?")
        .bind(before)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Validate client credentials (client_id + client_secret).
/// Returns the OAuth client if valid, None otherwise.
pub async fn validate_oauth_client_credentials(
    pool: &SqlitePool,
    client_id: &str,
    secret_hash: &str,
) -> Result<Option<OAuthClient>> {
    // Get the client
    let Some(client) = get_oauth_client_by_client_id(pool, client_id).await? else {
        return Ok(None);
    };

    if !client.is_active() {
        return Ok(None);
    }

    // Get the secret by hash
    let Some(secret) = get_oauth_secret_by_hash(pool, secret_hash).await? else {
        return Ok(None);
    };

    // Verify the secret belongs to this client
    if secret.oauth_client_id != client.id {
        return Ok(None);
    }

    // Check if secret is valid
    let now = Timestamp::now().to_string();
    if !secret.is_valid(&now) {
        return Ok(None);
    }

    // Update last used
    update_oauth_client_last_used(pool, &client.id).await?;

    Ok(Some(client))
}

// ============================================================================
// Token Exchange (RFC 8693)
// ============================================================================

/// Insert a token exchange audit record.
#[allow(clippy::too_many_arguments)]
pub async fn insert_token_exchange(
    pool: &SqlitePool,
    subject_user_id: &str,
    subject_token_hash: &str,
    actor_user_id: Option<&str>,
    issued_token_hash: &str,
    requested_audience: Option<&str>,
    granted_scope: Option<&str>,
    expires_at: &str,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO token_exchanges (id, subject_user_id, subject_token_hash, actor_user_id, issued_token_hash, requested_audience, granted_scope, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(subject_user_id)
    .bind(subject_token_hash)
    .bind(actor_user_id)
    .bind(issued_token_hash)
    .bind(requested_audience)
    .bind(granted_scope)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get token exchange records for a user.
#[allow(dead_code)]
pub async fn get_token_exchanges_for_user(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
) -> Result<Vec<TokenExchangeRecord>> {
    let records = sqlx::query_as::<_, TokenExchangeRecord>(
        "SELECT id, subject_user_id, subject_token_hash, actor_user_id, issued_token_hash, requested_audience, granted_scope, created_at, expires_at
         FROM token_exchanges WHERE subject_user_id = ? ORDER BY created_at DESC LIMIT ?",
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

/// Token exchange audit record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct TokenExchangeRecord {
    pub id: String,
    pub subject_user_id: String,
    pub subject_token_hash: String,
    pub actor_user_id: Option<String>,
    pub issued_token_hash: String,
    pub requested_audience: Option<String>,
    pub granted_scope: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

// ============================================================================
// Delegation Policies
// ============================================================================

/// Delegation policy record.
#[allow(dead_code)]
#[derive(Debug, sqlx::FromRow)]
pub struct DelegationPolicy {
    pub id: String,
    pub name: String,
    pub grantor_pattern: String,
    pub grantee_pattern: String,
    pub allowed_scopes: Option<String>,
    pub max_ttl_seconds: Option<i64>,
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Check if a delegation is allowed by any policy.
///
/// Returns the matching policy if delegation is allowed, None otherwise.
pub async fn check_delegation_policy(
    pool: &SqlitePool,
    grantor_email: &str,
    grantee_audience: Option<&str>,
) -> Result<Option<DelegationPolicy>> {
    // Get all enabled policies
    let policies = sqlx::query_as::<_, DelegationPolicy>(
        "SELECT id, name, grantor_pattern, grantee_pattern, allowed_scopes, max_ttl_seconds, enabled, created_at, updated_at
         FROM delegation_policies WHERE enabled = 1 ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await?;

    for policy in policies {
        // Check grantor pattern
        if !pattern_matches(&policy.grantor_pattern, grantor_email) {
            continue;
        }

        // Check grantee pattern (audience)
        if let Some(audience) = grantee_audience
            && !pattern_matches(&policy.grantee_pattern, audience)
        {
            continue;
        }

        // Policy matches
        return Ok(Some(policy));
    }

    Ok(None)
}

/// Check if a pattern matches a value.
///
/// Patterns can be:
/// - "*" matches anything
/// - "*@domain.com" matches emails with the specified domain
/// - Exact string match
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(domain) = pattern.strip_prefix("*@") {
        // Domain pattern
        if let Some(email_domain) = value.rsplit('@').next() {
            return email_domain.eq_ignore_ascii_case(domain);
        }
        return false;
    }

    // Exact match
    pattern.eq_ignore_ascii_case(value)
}

/// Create a delegation policy.
#[allow(dead_code)]
pub async fn create_delegation_policy(
    pool: &SqlitePool,
    name: &str,
    grantor_pattern: &str,
    grantee_pattern: &str,
    allowed_scopes: Option<&str>,
    max_ttl_seconds: Option<i64>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO delegation_policies (id, name, grantor_pattern, grantee_pattern, allowed_scopes, max_ttl_seconds)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(grantor_pattern)
    .bind(grantee_pattern)
    .bind(allowed_scopes)
    .bind(max_ttl_seconds)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get all delegation policies.
pub async fn get_delegation_policies(pool: &SqlitePool) -> Result<Vec<DelegationPolicy>> {
    let policies = sqlx::query_as::<_, DelegationPolicy>(
        "SELECT id, name, grantor_pattern, grantee_pattern, allowed_scopes, max_ttl_seconds, enabled, created_at, updated_at
         FROM delegation_policies ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(policies)
}

/// Update a delegation policy's enabled status.
#[allow(dead_code)]
pub async fn set_delegation_policy_enabled(
    pool: &SqlitePool,
    id: &str,
    enabled: bool,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE delegation_policies SET enabled = ?, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(if enabled { 1 } else { 0 })
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Delete a delegation policy.
#[allow(dead_code)]
pub async fn delete_delegation_policy(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM delegation_policies WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Admin Sessions
// ============================================================================

/// Admin session record for browser-based OIDC login.
#[allow(dead_code)]
#[derive(Debug, sqlx::FromRow)]
pub struct AdminSession {
    pub id: String,
    pub admin_email: String,
    pub session_token_hash: String,
    pub expires_at: String,
    pub oidc_provider: Option<String>,
    pub oidc_subject: Option<String>,
    pub revoked: i64,
    pub created_at: String,
    pub last_used_at: String,
}

/// Create a new admin session.
pub async fn create_admin_session(
    pool: &SqlitePool,
    admin_email: &str,
    session_token_hash: &str,
    expires_at: &str,
    oidc_provider: Option<&str>,
    oidc_subject: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO admin_sessions (id, admin_email, session_token_hash, expires_at, oidc_provider, oidc_subject)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(admin_email)
    .bind(session_token_hash)
    .bind(expires_at)
    .bind(oidc_provider)
    .bind(oidc_subject)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get an admin session by token hash.
pub async fn get_admin_session_by_token_hash(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<AdminSession>> {
    let session = sqlx::query_as::<_, AdminSession>(
        "SELECT id, admin_email, session_token_hash, expires_at, oidc_provider, oidc_subject, revoked, created_at, last_used_at
         FROM admin_sessions
         WHERE session_token_hash = ? AND revoked = 0",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;

    Ok(session)
}

/// Update admin session last used timestamp.
#[allow(dead_code)]
pub async fn touch_admin_session(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("UPDATE admin_sessions SET last_used_at = datetime('now') WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Revoke an admin session.
pub async fn revoke_admin_session(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("UPDATE admin_sessions SET revoked = 1 WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Revoke all admin sessions for an email.
#[allow(dead_code)]
pub async fn revoke_admin_sessions_for_email(pool: &SqlitePool, email: &str) -> Result<u64> {
    let result = sqlx::query("UPDATE admin_sessions SET revoked = 1 WHERE admin_email = ?")
        .bind(email)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Delete expired admin sessions (for cleanup task).
pub async fn delete_expired_admin_sessions(pool: &SqlitePool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM admin_sessions WHERE expires_at < datetime('now')")
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

// ============================================================================
// Enrollment Sessions
// ============================================================================

/// Enrollment session record (for key management during enrollment).
#[derive(Debug, sqlx::FromRow)]
pub struct EnrollmentSession {
    pub id: String,
    pub user_id: String,
    pub user_email: String,
    #[allow(dead_code)]
    pub session_token_hash: String,
    pub device_auth_id: Option<String>,
    pub expires_at: String,
    #[allow(dead_code)]
    pub created_at: String,
    #[allow(dead_code)]
    pub last_used_at: String,
}

/// Create a new enrollment session.
pub async fn create_enrollment_session(
    pool: &SqlitePool,
    user_id: &str,
    user_email: &str,
    session_token_hash: &str,
    device_auth_id: Option<&str>,
    expires_at: &str,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO enrollment_sessions (id, user_id, user_email, session_token_hash, device_auth_id, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(user_email)
    .bind(session_token_hash)
    .bind(device_auth_id)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get an enrollment session by token hash.
pub async fn get_enrollment_session_by_token_hash(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<EnrollmentSession>> {
    let session = sqlx::query_as::<_, EnrollmentSession>(
        "SELECT id, user_id, user_email, session_token_hash, device_auth_id, expires_at, created_at, last_used_at
         FROM enrollment_sessions
         WHERE session_token_hash = ?",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;

    Ok(session)
}

/// Update enrollment session last used timestamp.
pub async fn touch_enrollment_session(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("UPDATE enrollment_sessions SET last_used_at = datetime('now') WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete an enrollment session.
pub async fn delete_enrollment_session(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM enrollment_sessions WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Delete expired enrollment sessions (for cleanup task).
pub async fn delete_expired_enrollment_sessions(pool: &SqlitePool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM enrollment_sessions WHERE expires_at < datetime('now')")
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

// ============================================================================
// SSH Certificate Revocation
// ============================================================================

/// Revoked SSH certificate record.
#[derive(Debug, sqlx::FromRow)]
pub struct RevokedSshCertificate {
    #[allow(dead_code)]
    pub id: String,
    pub serial: String,
    #[allow(dead_code)]
    pub user_id: String,
    #[allow(dead_code)]
    pub reason: Option<String>,
    #[allow(dead_code)]
    pub revoked_at: String,
    #[allow(dead_code)]
    pub expires_at: String,
    #[allow(dead_code)]
    pub revoked_by: Option<String>,
}

/// Revoke an SSH certificate.
#[allow(dead_code)]
pub async fn revoke_ssh_certificate(
    pool: &SqlitePool,
    serial: &str,
    user_id: &str,
    expires_at: &str,
    reason: Option<&str>,
    revoked_by: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT OR IGNORE INTO ssh_revoked_certificates (id, serial, user_id, expires_at, reason, revoked_by)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(serial)
    .bind(user_id)
    .bind(expires_at)
    .bind(reason)
    .bind(revoked_by)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Check if an SSH certificate is revoked.
pub async fn is_ssh_certificate_revoked(pool: &SqlitePool, serial: &str) -> Result<bool> {
    let result = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM ssh_revoked_certificates WHERE serial = ?",
    )
    .bind(serial)
    .fetch_one(pool)
    .await?;

    Ok(result > 0)
}

/// Get all revoked SSH certificates (for KRL generation).
pub async fn get_revoked_ssh_certificates(pool: &SqlitePool) -> Result<Vec<RevokedSshCertificate>> {
    let certs = sqlx::query_as::<_, RevokedSshCertificate>(
        "SELECT id, serial, user_id, reason, revoked_at, expires_at, revoked_by
         FROM ssh_revoked_certificates
         WHERE expires_at > datetime('now')
         ORDER BY revoked_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(certs)
}

/// Revoke all SSH certificates for a user.
pub async fn revoke_all_ssh_certificates_for_user(
    pool: &SqlitePool,
    user_id: &str,
    reason: Option<&str>,
    revoked_by: Option<&str>,
) -> Result<u64> {
    // Note: This only marks future certificates as needing revocation check.
    // Existing issued certificates are tracked separately via serial numbers.
    // The caller should also add any known serials to the revocation list.
    let result = sqlx::query(
        "INSERT OR IGNORE INTO ssh_revoked_certificates (id, serial, user_id, expires_at, reason, revoked_by)
         SELECT ?, 'user:' || ?, ?, datetime('now', '+1 year'), ?, ?",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(user_id)
    .bind(user_id)
    .bind(reason)
    .bind(revoked_by)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Delete expired SSH certificate revocations (cleanup).
pub async fn delete_expired_ssh_revocations(pool: &SqlitePool) -> Result<u64> {
    let result =
        sqlx::query("DELETE FROM ssh_revoked_certificates WHERE expires_at < datetime('now')")
            .execute(pool)
            .await?;

    Ok(result.rows_affected())
}

// ============================================================================
// SCIM Groups
// ============================================================================

/// SCIM Group record.
#[derive(Debug, sqlx::FromRow)]
pub struct ScimGroupRecord {
    pub id: String,
    pub display_name: String,
    pub external_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// SCIM Group member record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct ScimGroupMemberRecord {
    pub group_id: String,
    pub user_id: String,
    pub created_at: String,
}

/// Create a new SCIM group.
pub async fn create_scim_group(
    pool: &SqlitePool,
    display_name: &str,
    external_id: Option<&str>,
) -> Result<ScimGroupRecord> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO scim_groups (id, display_name, external_id)
         VALUES (?, ?, ?)",
    )
    .bind(&id)
    .bind(display_name)
    .bind(external_id)
    .execute(pool)
    .await?;

    // Return the created group
    get_scim_group(pool, &id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve created group"))
}

/// Get a SCIM group by ID.
pub async fn get_scim_group(pool: &SqlitePool, id: &str) -> Result<Option<ScimGroupRecord>> {
    let group = sqlx::query_as::<_, ScimGroupRecord>(
        "SELECT id, display_name, external_id, created_at, updated_at
         FROM scim_groups WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(group)
}

/// Get a SCIM group by display name.
#[allow(dead_code)]
pub async fn get_scim_group_by_name(
    pool: &SqlitePool,
    display_name: &str,
) -> Result<Option<ScimGroupRecord>> {
    let group = sqlx::query_as::<_, ScimGroupRecord>(
        "SELECT id, display_name, external_id, created_at, updated_at
         FROM scim_groups WHERE display_name = ?",
    )
    .bind(display_name)
    .fetch_optional(pool)
    .await?;

    Ok(group)
}

/// List SCIM groups with pagination.
pub async fn list_scim_groups(
    pool: &SqlitePool,
    filter: Option<&str>,
    start_index: usize,
    count: usize,
) -> Result<Vec<ScimGroupRecord>> {
    let offset = if start_index > 0 { start_index - 1 } else { 0 };

    let groups = if let Some(filter_str) = filter {
        // Parse simple filter: displayName eq "value"
        if let Some(value) = parse_scim_filter(filter_str, "displayName") {
            sqlx::query_as::<_, ScimGroupRecord>(
                "SELECT id, display_name, external_id, created_at, updated_at
                 FROM scim_groups WHERE display_name = ?
                 ORDER BY created_at DESC
                 LIMIT ? OFFSET ?",
            )
            .bind(value)
            .bind(count as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
        } else if let Some(value) = parse_scim_filter(filter_str, "externalId") {
            sqlx::query_as::<_, ScimGroupRecord>(
                "SELECT id, display_name, external_id, created_at, updated_at
                 FROM scim_groups WHERE external_id = ?
                 ORDER BY created_at DESC
                 LIMIT ? OFFSET ?",
            )
            .bind(value)
            .bind(count as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
        } else {
            // Unknown filter, return all
            sqlx::query_as::<_, ScimGroupRecord>(
                "SELECT id, display_name, external_id, created_at, updated_at
                 FROM scim_groups
                 ORDER BY created_at DESC
                 LIMIT ? OFFSET ?",
            )
            .bind(count as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
        }
    } else {
        sqlx::query_as::<_, ScimGroupRecord>(
            "SELECT id, display_name, external_id, created_at, updated_at
             FROM scim_groups
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?",
        )
        .bind(count as i64)
        .bind(offset as i64)
        .fetch_all(pool)
        .await?
    };

    Ok(groups)
}

/// Count SCIM groups (for pagination).
pub async fn count_scim_groups(pool: &SqlitePool, filter: Option<&str>) -> Result<usize> {
    let count = if let Some(filter_str) = filter {
        if let Some(value) = parse_scim_filter(filter_str, "displayName") {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups WHERE display_name = ?")
                .bind(value)
                .fetch_one(pool)
                .await?
        } else if let Some(value) = parse_scim_filter(filter_str, "externalId") {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups WHERE external_id = ?")
                .bind(value)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups")
                .fetch_one(pool)
                .await?
        }
    } else {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups")
            .fetch_one(pool)
            .await?
    };

    Ok(count as usize)
}

/// Update a SCIM group.
/// Uses a single atomic query with COALESCE to update only specified fields.
pub async fn update_scim_group(
    pool: &SqlitePool,
    id: &str,
    display_name: Option<&str>,
    external_id: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE scim_groups SET
            display_name = COALESCE(?, display_name),
            external_id = COALESCE(?, external_id),
            updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(display_name)
    .bind(external_id)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a SCIM group.
pub async fn delete_scim_group(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM scim_groups WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Add a member to a SCIM group.
/// This operation is atomic - both the insert and timestamp update happen together.
pub async fn add_scim_group_member(pool: &SqlitePool, group_id: &str, user_id: &str) -> Result<()> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT OR IGNORE INTO scim_group_members (group_id, user_id)
         VALUES (?, ?)",
    )
    .bind(group_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    // Update group's updated_at
    sqlx::query("UPDATE scim_groups SET updated_at = datetime('now') WHERE id = ?")
        .bind(group_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

/// Remove a member from a SCIM group.
/// This operation is atomic - both the delete and timestamp update happen together.
pub async fn remove_scim_group_member(
    pool: &SqlitePool,
    group_id: &str,
    user_id: &str,
) -> Result<bool> {
    let mut tx = pool.begin().await?;

    let result = sqlx::query("DELETE FROM scim_group_members WHERE group_id = ? AND user_id = ?")
        .bind(group_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    if result.rows_affected() > 0 {
        // Update group's updated_at
        sqlx::query("UPDATE scim_groups SET updated_at = datetime('now') WHERE id = ?")
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    } else {
        tx.commit().await?;
        Ok(false)
    }
}

/// Get all members of a SCIM group.
pub async fn get_scim_group_members(
    pool: &SqlitePool,
    group_id: &str,
) -> Result<Vec<ScimUserRecord>> {
    let users = sqlx::query_as::<_, ScimUserRecord>(
        "SELECT u.id, u.email, u.name, u.external_id, u.active, u.created_at
         FROM users u
         JOIN scim_group_members m ON m.user_id = u.id
         WHERE m.group_id = ?
         ORDER BY u.email",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;

    Ok(users)
}

/// Get all groups a user belongs to.
#[allow(dead_code)]
pub async fn get_user_scim_groups(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<ScimGroupRecord>> {
    let groups = sqlx::query_as::<_, ScimGroupRecord>(
        "SELECT g.id, g.display_name, g.external_id, g.created_at, g.updated_at
         FROM scim_groups g
         JOIN scim_group_members m ON m.group_id = g.id
         WHERE m.user_id = ?
         ORDER BY g.display_name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(groups)
}

/// Replace all members of a SCIM group.
/// This operation is atomic - either all members are replaced or none are.
pub async fn replace_scim_group_members(
    pool: &SqlitePool,
    group_id: &str,
    user_ids: &[String],
) -> Result<()> {
    let mut tx = pool.begin().await?;

    // Delete all existing members
    sqlx::query("DELETE FROM scim_group_members WHERE group_id = ?")
        .bind(group_id)
        .execute(&mut *tx)
        .await?;

    // Add new members
    for user_id in user_ids {
        sqlx::query(
            "INSERT OR IGNORE INTO scim_group_members (group_id, user_id)
             VALUES (?, ?)",
        )
        .bind(group_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }

    // Update group's updated_at
    sqlx::query("UPDATE scim_groups SET updated_at = datetime('now') WHERE id = ?")
        .bind(group_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    /// Create an in-memory SQLite database for testing.
    async fn test_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        pool
    }

    #[tokio::test]
    async fn test_upsert_and_get_user() {
        let pool = test_db().await;

        // Create a user
        let user = upsert_user(&pool, "test@example.com", Some("Test User"))
            .await
            .expect("Failed to create user");

        assert!(!user.id.is_empty());
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.name.as_deref(), Some("Test User"));

        // Get the user
        let fetched = get_user_by_email(&pool, "test@example.com")
            .await
            .expect("Failed to get user")
            .expect("User should exist");

        assert_eq!(fetched.id, user.id);
        assert_eq!(fetched.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_upsert_idempotent() {
        let pool = test_db().await;

        // First call creates user
        let user1 = upsert_user(&pool, "new@example.com", Some("New User"))
            .await
            .expect("Failed to upsert user");

        // Second call returns same user
        let user2 = upsert_user(&pool, "new@example.com", Some("Different Name"))
            .await
            .expect("Failed to upsert user");

        assert_eq!(user1.id, user2.id);
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let pool = test_db().await;

        let user = get_user_by_email(&pool, "nonexistent@example.com")
            .await
            .expect("Query should succeed");

        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_session_lifecycle() {
        let pool = test_db().await;

        // Create user
        let user = upsert_user(&pool, "session@example.com", None)
            .await
            .expect("Failed to create user");
        let user_id = user.id;

        // Create authenticator (simplified - normally needs more fields)
        let auth_id = uuid::Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO authenticators (id, user_id, name, credential_id, public_key, counter, created_at, user_handle) VALUES (?, ?, ?, ?, ?, 0, datetime('now'), ?)"
        )
        .bind(&auth_id)
        .bind(&user_id)
        .bind("Test Key")
        .bind("test-cred-id")
        .bind(vec![0u8; 32])
        .bind(&user_id)
        .execute(&pool)
        .await
        .expect("Failed to create authenticator");

        // Create session
        let token_hash = "test_token_hash_123";
        let session_id = create_session(
            &pool,
            &user_id,
            token_hash,
            &auth_id,
            "2099-12-31T23:59:59Z",
        )
        .await
        .expect("Failed to create session");

        assert!(!session_id.is_empty());

        // Get session
        let session = get_session_by_token_hash(&pool, token_hash)
            .await
            .expect("Failed to get session")
            .expect("Session should exist");

        assert_eq!(session.user_id, user_id);

        // Delete session
        let deleted = delete_session_by_token_hash(&pool, token_hash)
            .await
            .expect("Failed to delete session");

        assert!(deleted);

        // Session should no longer exist
        let session = get_session_by_token_hash(&pool, token_hash)
            .await
            .expect("Failed to get session");

        assert!(session.is_none());
    }

    #[tokio::test]
    async fn test_config_storage() {
        let pool = test_db().await;

        // Initially no config
        let value = get_config(&pool, "test_key")
            .await
            .expect("Failed to get config");
        assert!(value.is_none());

        // Set config
        set_config(&pool, "test_key", "test_value")
            .await
            .expect("Failed to set config");

        // Get config
        let value = get_config(&pool, "test_key")
            .await
            .expect("Failed to get config")
            .expect("Config should exist");

        assert_eq!(value, "test_value");

        // Update config
        set_config(&pool, "test_key", "updated_value")
            .await
            .expect("Failed to update config");

        let value = get_config(&pool, "test_key")
            .await
            .expect("Failed to get config")
            .expect("Config should exist");

        assert_eq!(value, "updated_value");
    }

    // ========================================================================
    // RFC 8628 - Device Authorization Grant Tests
    // ========================================================================

    #[tokio::test]
    async fn test_device_auth_request_lifecycle() {
        let pool = test_db().await;

        // Create device auth request
        let device_code_hash = "hashed_device_code_123";
        let user_code = "ABCD-1234";
        let expires_at = "2099-12-31T23:59:59Z";
        let interval = 5;

        let id =
            create_device_auth_request(&pool, device_code_hash, user_code, expires_at, interval)
                .await
                .expect("Failed to create device auth request");

        assert!(!id.is_empty());

        // Get by device code hash
        let request = get_device_auth_by_code_hash(&pool, device_code_hash)
            .await
            .expect("Failed to get device auth")
            .expect("Device auth should exist");

        assert_eq!(request.user_code, user_code);
        assert_eq!(request.status, "pending");
        assert!(request.user_id.is_none());

        // Get by user code
        let request = get_device_auth_by_user_code(&pool, user_code)
            .await
            .expect("Failed to get device auth by user code")
            .expect("Should find by user code");

        assert_eq!(request.device_code_hash, device_code_hash);

        // Get by ID
        let request = get_device_auth_by_id(&pool, &id)
            .await
            .expect("Failed to get device auth by ID")
            .expect("Should find by ID");

        assert_eq!(request.interval_seconds, interval);
    }

    #[tokio::test]
    async fn test_device_auth_authorization_flow() {
        let pool = test_db().await;

        // Create user first
        let user = upsert_user(&pool, "device@example.com", Some("Device User"))
            .await
            .expect("Failed to create user");

        // Create authenticator
        let auth_id = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO authenticators (id, user_id, name, credential_id, public_key, counter, created_at, user_handle) VALUES (?, ?, ?, ?, ?, 0, datetime('now'), ?)"
        )
        .bind(&auth_id)
        .bind(&user.id)
        .bind("Test Key")
        .bind("test-cred-id-device")
        .bind(vec![0u8; 32])
        .bind(&user.id)
        .execute(&pool)
        .await
        .expect("Failed to create authenticator");

        // Create pending device auth request
        let device_code_hash = "hashed_device_code_456";
        let user_code = "EFGH-5678";
        let id = create_device_auth_request(
            &pool,
            device_code_hash,
            user_code,
            "2099-12-31T23:59:59Z",
            5,
        )
        .await
        .expect("Failed to create device auth request");

        // Verify initially pending
        let request = get_device_auth_by_id(&pool, &id)
            .await
            .expect("Failed to get request")
            .expect("Should exist");
        assert_eq!(request.status, "pending");

        // Authorize the request
        authorize_device_auth(&pool, &id, &user.id, &user.email, &auth_id)
            .await
            .expect("Failed to authorize");

        // Verify status changed to authorized
        let request = get_device_auth_by_id(&pool, &id)
            .await
            .expect("Failed to get request")
            .expect("Should exist");
        assert_eq!(request.status, "authorized");
        assert_eq!(request.user_id, Some(user.id.clone()));
        assert_eq!(request.user_email, Some(user.email.clone()));
        assert_eq!(request.authenticator_id, Some(auth_id));
    }

    #[tokio::test]
    async fn test_device_auth_polling_rate_limit() {
        let pool = test_db().await;

        let device_code_hash = "rate_limit_test";
        let user_code = "RATE-1234";
        let interval = 5; // 5 seconds

        let id = create_device_auth_request(
            &pool,
            device_code_hash,
            user_code,
            "2099-12-31T23:59:59Z",
            interval,
        )
        .await
        .expect("Failed to create device auth request");

        // First poll should succeed
        let allowed = update_device_auth_poll_time(&pool, &id, interval)
            .await
            .expect("Failed to update poll time");
        assert!(allowed, "First poll should be allowed");

        // Immediate second poll should be rate limited
        let allowed = update_device_auth_poll_time(&pool, &id, interval)
            .await
            .expect("Failed to update poll time");
        assert!(!allowed, "Immediate second poll should be rate limited");
    }

    #[tokio::test]
    async fn test_device_auth_not_found() {
        let pool = test_db().await;

        // Get nonexistent device auth
        let request = get_device_auth_by_code_hash(&pool, "nonexistent")
            .await
            .expect("Query should succeed");
        assert!(request.is_none());

        let request = get_device_auth_by_user_code(&pool, "XXXX-0000")
            .await
            .expect("Query should succeed");
        assert!(request.is_none());
    }

    // ========================================================================
    // OIDC State Tests
    // ========================================================================

    #[tokio::test]
    async fn test_oidc_state_lifecycle() {
        let pool = test_db().await;

        // Create device auth request first (FK reference)
        let device_auth_id = create_device_auth_request(
            &pool,
            "device_hash_for_oidc",
            "OIDC-1234",
            "2099-12-31T23:59:59Z",
            5,
        )
        .await
        .expect("Failed to create device auth");

        // Create OIDC state
        let state = "random_state_12345";
        let nonce = "nonce_67890";
        let expires_at = "2099-12-31T23:59:59Z";

        let id = create_oidc_state(&pool, state, &device_auth_id, nonce, expires_at)
            .await
            .expect("Failed to create OIDC state");
        assert!(!id.is_empty());

        // Get OIDC state
        let oidc_state = get_oidc_state(&pool, state)
            .await
            .expect("Failed to get OIDC state")
            .expect("Should exist");

        assert_eq!(oidc_state.state, state);
        assert_eq!(oidc_state.device_auth_id, device_auth_id);
        assert_eq!(oidc_state.nonce, nonce);

        // Delete OIDC state
        delete_oidc_state(&pool, state)
            .await
            .expect("Failed to delete OIDC state");

        // Verify deleted
        let oidc_state = get_oidc_state(&pool, state)
            .await
            .expect("Query should succeed");
        assert!(oidc_state.is_none());
    }

    // ========================================================================
    // OAuth Client Application Tests (Phase 7)
    // ========================================================================

    #[tokio::test]
    async fn test_oauth_client_crud() {
        let pool = test_db().await;

        // Create user
        let user = upsert_user(&pool, "developer@example.com", Some("Developer"))
            .await
            .expect("Failed to create user");

        // Create OAuth client
        let redirect_uris = vec!["https://example.com/callback".to_string()];
        let (client, client_id) = create_oauth_client(
            &pool,
            &user.id,
            "My App",
            Some("A test application"),
            OAuthClientType::Web,
            &redirect_uris,
        )
        .await
        .expect("Failed to create OAuth client");

        assert!(!client_id.is_empty());
        assert_eq!(client.name, "My App");
        assert_eq!(client.application_type, "web");
        assert!(client.is_active());

        // Get by ID
        let fetched = get_oauth_client_by_id(&pool, &client.id)
            .await
            .expect("Failed to get client")
            .expect("Client should exist");
        assert_eq!(fetched.client_id, client_id);

        // Get by client_id
        let fetched = get_oauth_client_by_client_id(&pool, &client_id)
            .await
            .expect("Failed to get client")
            .expect("Client should exist");
        assert_eq!(fetched.name, "My App");

        // Update client
        let new_redirect_uris = vec![
            "https://example.com/callback".to_string(),
            "https://example.com/callback2".to_string(),
        ];
        update_oauth_client(
            &pool,
            &client.id,
            "My Updated App",
            Some("Updated desc"),
            &new_redirect_uris,
        )
        .await
        .expect("Failed to update client");

        let updated = get_oauth_client_by_id(&pool, &client.id)
            .await
            .expect("Failed to get client")
            .expect("Client should exist");
        assert_eq!(updated.name, "My Updated App");
        assert_eq!(updated.get_redirect_uris().len(), 2);

        // Delete client
        let deleted = delete_oauth_client(&pool, &client.id)
            .await
            .expect("Failed to delete client");
        assert_eq!(deleted, 1);

        // Verify deleted
        let client = get_oauth_client_by_id(&pool, &client.id)
            .await
            .expect("Query should succeed");
        assert!(client.is_none());
    }

    #[tokio::test]
    async fn test_oauth_client_types() {
        let pool = test_db().await;

        let user = upsert_user(&pool, "types@example.com", None)
            .await
            .expect("Failed to create user");

        // Test all application types
        for app_type in [
            OAuthClientType::Web,
            OAuthClientType::Native,
            OAuthClientType::Spa,
            OAuthClientType::Service,
        ] {
            let (client, _) = create_oauth_client(
                &pool,
                &user.id,
                &format!("{:?} App", app_type),
                None,
                app_type,
                &[],
            )
            .await
            .expect("Failed to create client");

            assert_eq!(client.client_type(), Some(app_type));

            // Check requires_secret
            let requires_secret = app_type.requires_secret();
            match app_type {
                OAuthClientType::Web | OAuthClientType::Service => assert!(requires_secret),
                OAuthClientType::Native | OAuthClientType::Spa => assert!(!requires_secret),
            }
        }
    }

    #[tokio::test]
    async fn test_oauth_client_list_for_user() {
        let pool = test_db().await;

        let user1 = upsert_user(&pool, "user1@example.com", None)
            .await
            .expect("Failed to create user");
        let user2 = upsert_user(&pool, "user2@example.com", None)
            .await
            .expect("Failed to create user");

        // Create clients for user1
        for i in 0..3 {
            create_oauth_client(
                &pool,
                &user1.id,
                &format!("App {}", i),
                None,
                OAuthClientType::Web,
                &[],
            )
            .await
            .expect("Failed to create client");
        }

        // Create client for user2
        create_oauth_client(
            &pool,
            &user2.id,
            "Other App",
            None,
            OAuthClientType::Web,
            &[],
        )
        .await
        .expect("Failed to create client");

        // Get user1's clients
        let clients = get_oauth_clients_for_user(&pool, &user1.id)
            .await
            .expect("Failed to get clients");
        assert_eq!(clients.len(), 3);

        // Get user2's clients
        let clients = get_oauth_clients_for_user(&pool, &user2.id)
            .await
            .expect("Failed to get clients");
        assert_eq!(clients.len(), 1);
    }

    #[tokio::test]
    async fn test_oauth_client_secret_management() {
        let pool = test_db().await;

        let user = upsert_user(&pool, "secrets@example.com", None)
            .await
            .expect("Failed to create user");

        let (client, _) = create_oauth_client(
            &pool,
            &user.id,
            "Secret App",
            None,
            OAuthClientType::Web,
            &[],
        )
        .await
        .expect("Failed to create client");

        // Create a secret
        let secret_hash = "hashed_secret_12345";
        let secret = create_oauth_client_secret(
            &pool,
            &client.id,
            secret_hash,
            Some("Initial secret"),
            None,
        )
        .await
        .expect("Failed to create secret");

        assert!(!secret.id.is_empty());
        assert_eq!(secret.oauth_client_id, client.id);
        assert!(secret.revoked_at.is_none());

        // Get secrets
        let secrets = get_oauth_client_secrets(&pool, &client.id)
            .await
            .expect("Failed to get secrets");
        assert_eq!(secrets.len(), 1);

        // Revoke all secrets
        let revoked_count = revoke_all_oauth_client_secrets(&pool, &client.id)
            .await
            .expect("Failed to revoke secrets");
        assert_eq!(revoked_count, 1);

        // Verify revoked
        let secrets = get_oauth_client_secrets(&pool, &client.id)
            .await
            .expect("Failed to get secrets");
        assert!(secrets[0].revoked_at.is_some());
    }

    #[tokio::test]
    async fn test_oauth_client_deactivation() {
        let pool = test_db().await;

        let user = upsert_user(&pool, "deactivate@example.com", None)
            .await
            .expect("Failed to create user");

        let (client, _) = create_oauth_client(
            &pool,
            &user.id,
            "Deactivate App",
            None,
            OAuthClientType::Web,
            &[],
        )
        .await
        .expect("Failed to create client");

        assert!(client.is_active());

        // Deactivate
        deactivate_oauth_client(&pool, &client.id)
            .await
            .expect("Failed to deactivate");

        let client = get_oauth_client_by_id(&pool, &client.id)
            .await
            .expect("Failed to get client")
            .expect("Client should exist");
        assert!(!client.is_active());

        // Reactivate
        reactivate_oauth_client(&pool, &client.id)
            .await
            .expect("Failed to reactivate");

        let client = get_oauth_client_by_id(&pool, &client.id)
            .await
            .expect("Failed to get client")
            .expect("Client should exist");
        assert!(client.is_active());
    }

    #[tokio::test]
    async fn test_oauth_usage_recording() {
        let pool = test_db().await;

        let user = upsert_user(&pool, "usage@example.com", None)
            .await
            .expect("Failed to create user");

        let (client, _) = create_oauth_client(
            &pool,
            &user.id,
            "Usage App",
            None,
            OAuthClientType::Web,
            &[],
        )
        .await
        .expect("Failed to create client");

        // Record some events
        record_oauth_event(
            &pool,
            &client.id,
            OAuthEventType::TokenIssued,
            Some(&user.id),
            None,
            None,
            None,
        )
        .await
        .expect("Failed to record event");
        record_oauth_event(
            &pool,
            &client.id,
            OAuthEventType::TokenIssued,
            Some(&user.id),
            None,
            None,
            None,
        )
        .await
        .expect("Failed to record event");
        record_oauth_event(
            &pool,
            &client.id,
            OAuthEventType::TokenRevoked,
            Some(&user.id),
            None,
            None,
            None,
        )
        .await
        .expect("Failed to record event");

        // Get usage stats
        let stats = get_oauth_usage_stats(&pool, &client.id, None)
            .await
            .expect("Failed to get stats");

        assert_eq!(stats.len(), 2); // token_issued and token_revoked

        let token_issued = stats
            .iter()
            .find(|s| s.event_type == "token_issued")
            .unwrap();
        assert_eq!(token_issued.count, 2);

        let token_revoked = stats
            .iter()
            .find(|s| s.event_type == "token_revoked")
            .unwrap();
        assert_eq!(token_revoked.count, 1);
    }

    // ========================================================================
    // SCIM User Tests (RFC 7643/7644)
    // ========================================================================

    #[tokio::test]
    async fn test_scim_user_crud() {
        let pool = test_db().await;

        // Create SCIM user
        let user = create_scim_user(
            &pool,
            "scim@example.com",
            Some("SCIM User"),
            Some("ext-123"),
            true,
        )
        .await
        .expect("Failed to create SCIM user");

        assert!(!user.id.is_empty());
        assert_eq!(user.email, "scim@example.com");
        assert_eq!(user.name, Some("SCIM User".to_string()));
        assert_eq!(user.external_id, Some("ext-123".to_string()));
        assert!(user.active);

        // Get SCIM user
        let fetched = get_scim_user(&pool, &user.id)
            .await
            .expect("Failed to get SCIM user")
            .expect("User should exist");
        assert_eq!(fetched.email, "scim@example.com");

        // Update SCIM user
        update_scim_user(
            &pool,
            &user.id,
            Some("Updated Name"),
            Some("ext-456"),
            false,
        )
        .await
        .expect("Failed to update SCIM user");

        let updated = get_scim_user(&pool, &user.id)
            .await
            .expect("Failed to get user")
            .expect("User should exist");
        assert_eq!(updated.name, Some("Updated Name".to_string()));
        assert_eq!(updated.external_id, Some("ext-456".to_string()));
        assert!(!updated.active);
    }

    #[tokio::test]
    async fn test_scim_user_list_and_filter() {
        let pool = test_db().await;

        // Create multiple users
        for i in 0..5 {
            create_scim_user(&pool, &format!("user{}@example.com", i), None, None, true)
                .await
                .expect("Failed to create user");
        }

        // List all users
        let users = list_scim_users(&pool, None, 1, 100)
            .await
            .expect("Failed to list users");
        assert_eq!(users.len(), 5);

        // Count users
        let count = count_scim_users(&pool, None)
            .await
            .expect("Failed to count users");
        assert_eq!(count, 5);

        // Filter by userName (email)
        let users = list_scim_users(&pool, Some("userName eq \"user2@example.com\""), 1, 100)
            .await
            .expect("Failed to filter users");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].email, "user2@example.com");

        // Pagination
        let page1 = list_scim_users(&pool, None, 1, 2)
            .await
            .expect("Failed to paginate");
        assert_eq!(page1.len(), 2);

        let page2 = list_scim_users(&pool, None, 3, 2)
            .await
            .expect("Failed to paginate");
        assert_eq!(page2.len(), 2);
    }

    #[tokio::test]
    async fn test_scim_session_invalidation_on_deactivation() {
        let pool = test_db().await;

        // Create user with session
        let user = create_scim_user(&pool, "invalidate@example.com", None, None, true)
            .await
            .expect("Failed to create user");

        // Create authenticator
        let auth_id = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO authenticators (id, user_id, name, credential_id, public_key, counter, created_at, user_handle) VALUES (?, ?, ?, ?, ?, 0, datetime('now'), ?)"
        )
        .bind(&auth_id)
        .bind(&user.id)
        .bind("SCIM Key")
        .bind("scim-cred-id")
        .bind(vec![0u8; 32])
        .bind(&user.id)
        .execute(&pool)
        .await
        .expect("Failed to create authenticator");

        // Create session
        create_session(
            &pool,
            &user.id,
            "scim_token_hash",
            &auth_id,
            "2099-12-31T23:59:59Z",
        )
        .await
        .expect("Failed to create session");

        // Verify session exists
        let session = get_session_by_token_hash(&pool, "scim_token_hash")
            .await
            .expect("Failed to get session");
        assert!(session.is_some());

        // Delete all sessions for user (as SCIM would do on deactivation)
        let deleted = delete_sessions_for_user(&pool, &user.id)
            .await
            .expect("Failed to delete sessions");
        assert_eq!(deleted, 1);

        // Verify session deleted
        let session = get_session_by_token_hash(&pool, "scim_token_hash")
            .await
            .expect("Failed to get session");
        assert!(session.is_none());
    }

    #[tokio::test]
    async fn test_scim_audit_logging() {
        let pool = test_db().await;

        // Create a SCIM token first (required for foreign key constraint)
        let token_id = create_scim_token(&pool, "test_token_hash", Some("Test token"), None)
            .await
            .expect("Failed to create SCIM token");

        // Insert audit log with token reference
        let audit_id = insert_scim_audit(
            &pool,
            "CREATE",
            "User",
            "user-123",
            Some(&token_id),
            Some("Created user via SCIM"),
        )
        .await
        .expect("Failed to insert audit log");

        assert!(!audit_id.is_empty());

        // Insert another audit log without token (None is valid)
        let audit_id2 = insert_scim_audit(&pool, "DELETE", "User", "user-789", None, None)
            .await
            .expect("Failed to insert audit log");

        assert!(!audit_id2.is_empty());
        assert_ne!(audit_id, audit_id2);
    }

    // ========================================================================
    // Authentication Event Tests
    // ========================================================================

    #[tokio::test]
    async fn test_auth_event_logging() {
        let pool = test_db().await;

        let user = upsert_user(&pool, "events@example.com", None)
            .await
            .expect("Failed to create user");

        // Log successful login
        let event_id = insert_auth_event(
            &pool,
            &AuthEventParams {
                user_id: user.id.clone(),
                event_type: AuthEventType::LoginSuccess,
                authenticator_id: Some("auth-123".to_string()),
                client_ip: Some("192.168.1.1".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                success: true,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to insert auth event");

        assert!(!event_id.is_empty());

        // Log failed login
        insert_auth_event(
            &pool,
            &AuthEventParams {
                user_id: user.id.clone(),
                event_type: AuthEventType::LoginFailed,
                client_ip: Some("192.168.1.1".to_string()),
                success: false,
                failure_reason: Some("Invalid credential".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to insert auth event");

        // Query events for user
        let events = get_auth_events(
            &pool,
            &AuthEventQuery {
                user_id: Some(user.id.clone()),
                limit: Some(10),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to get events");

        assert_eq!(events.len(), 2);

        // Query by event type
        let events = get_auth_events(
            &pool,
            &AuthEventQuery {
                event_type: Some("login_success".to_string()),
                limit: Some(10),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to get events");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "login_success");
    }

    // ========================================================================
    // Authenticator Tests
    // ========================================================================

    #[tokio::test]
    async fn test_authenticator_crud() {
        let pool = test_db().await;

        let user = upsert_user(&pool, "auth@example.com", None)
            .await
            .expect("Failed to create user");

        // Create authenticator
        let credential_id = vec![1u8, 2, 3, 4, 5];
        let public_key = vec![10u8; 65];
        let user_handle = vec![20u8; 32];

        let auth_id = create_authenticator(
            &pool,
            &user.id,
            "YubiKey 5C",
            &credential_id,
            &public_key,
            Some("2fc0579f-8113-47ea-b116-bb5a8db9202a"),
            Some(&user_handle),
        )
        .await
        .expect("Failed to create authenticator");

        assert!(!auth_id.is_empty());

        // Get by ID
        let auth = get_authenticator_by_id(&pool, &auth_id)
            .await
            .expect("Failed to get authenticator")
            .expect("Authenticator should exist");

        assert_eq!(auth.name, "YubiKey 5C");
        assert_eq!(auth.credential_id, credential_id);
        assert_eq!(auth.counter, 0);

        // Get by credential ID
        let auth = get_authenticator_by_credential_id(&pool, &credential_id)
            .await
            .expect("Failed to get authenticator")
            .expect("Authenticator should exist");

        assert_eq!(auth.id, auth_id);

        // Get all for user
        let auths = get_authenticators_for_user(&pool, &user.id)
            .await
            .expect("Failed to get authenticators");

        assert_eq!(auths.len(), 1);

        // Update counter
        update_authenticator_counter(&pool, &auth_id, 42)
            .await
            .expect("Failed to update counter");

        let auth = get_authenticator_by_id(&pool, &auth_id)
            .await
            .expect("Failed to get authenticator")
            .expect("Authenticator should exist");

        assert_eq!(auth.counter, 42);

        // Delete authenticator
        let deleted = delete_authenticator(&pool, &auth_id)
            .await
            .expect("Failed to delete authenticator");

        assert_eq!(deleted, 1);

        // Verify deleted
        let auth = get_authenticator_by_id(&pool, &auth_id)
            .await
            .expect("Query should succeed");

        assert!(auth.is_none());
    }

    #[tokio::test]
    async fn test_authenticator_count() {
        let pool = test_db().await;

        let user = upsert_user(&pool, "count@example.com", None)
            .await
            .expect("Failed to create user");

        // Initially 0 authenticators
        let count = count_authenticators_for_user(&pool, &user.id)
            .await
            .expect("Failed to count");
        assert_eq!(count, 0);

        // Add authenticators
        for i in 0..3 {
            create_authenticator(
                &pool,
                &user.id,
                &format!("Key {}", i),
                &[i as u8; 10],
                &[0u8; 32],
                None,
                None,
            )
            .await
            .expect("Failed to create authenticator");
        }

        let count = count_authenticators_for_user(&pool, &user.id)
            .await
            .expect("Failed to count");
        assert_eq!(count, 3);
    }

    // ========================================================================
    // SCIM Token Tests
    // ========================================================================

    #[tokio::test]
    async fn test_scim_token_management() {
        let pool = test_db().await;

        // Create SCIM token
        let token_hash = "hashed_scim_token";
        let token_id = create_scim_token(&pool, token_hash, Some("Admin token"), None)
            .await
            .expect("Failed to create SCIM token");

        assert!(!token_id.is_empty());

        // Get by hash
        let token = get_scim_token_by_hash(&pool, token_hash)
            .await
            .expect("Failed to get token")
            .expect("Token should exist");

        assert_eq!(token.description, Some("Admin token".to_string()));
        assert!(token.last_used_at.is_none());

        // Update last used
        update_scim_token_last_used(&pool, &token.id)
            .await
            .expect("Failed to update last used");

        let token = get_scim_token_by_hash(&pool, token_hash)
            .await
            .expect("Failed to get token")
            .expect("Token should exist");

        assert!(token.last_used_at.is_some());

        // List tokens
        let tokens = list_scim_tokens(&pool)
            .await
            .expect("Failed to list tokens");

        assert_eq!(tokens.len(), 1);

        // Delete token
        delete_scim_token(&pool, &token_id)
            .await
            .expect("Failed to delete token");

        let token = get_scim_token_by_hash(&pool, token_hash)
            .await
            .expect("Query should succeed");

        assert!(token.is_none());
    }

    // ========================================================================
    // Cascade Delete Tests
    // ========================================================================

    #[tokio::test]
    async fn test_user_cascade_delete() {
        let pool = test_db().await;

        // Create user with authenticators and sessions
        let user = upsert_user(&pool, "cascade@example.com", None)
            .await
            .expect("Failed to create user");

        let auth_id = create_authenticator(
            &pool,
            &user.id,
            "Cascade Key",
            &[99u8; 10],
            &[0u8; 32],
            None,
            None,
        )
        .await
        .expect("Failed to create authenticator");

        create_session(
            &pool,
            &user.id,
            "cascade_token",
            &auth_id,
            "2099-12-31T23:59:59Z",
        )
        .await
        .expect("Failed to create session");

        // Verify everything exists
        assert!(
            get_authenticator_by_id(&pool, &auth_id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            get_session_by_token_hash(&pool, "cascade_token")
                .await
                .unwrap()
                .is_some()
        );

        // Delete user
        delete_user(&pool, &user.id)
            .await
            .expect("Failed to delete user");

        // Verify cascade (authenticators and sessions should be deleted)
        assert!(
            get_authenticator_by_id(&pool, &auth_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            get_session_by_token_hash(&pool, "cascade_token")
                .await
                .unwrap()
                .is_none()
        );
        assert!(get_user_by_id(&pool, &user.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_oauth_client_cascade_delete() {
        let pool = test_db().await;

        let user = upsert_user(&pool, "oauth_cascade@example.com", None)
            .await
            .expect("Failed to create user");

        let (client, _) = create_oauth_client(
            &pool,
            &user.id,
            "Cascade App",
            None,
            OAuthClientType::Web,
            &[],
        )
        .await
        .expect("Failed to create client");

        // Add secrets and usage events
        create_oauth_client_secret(&pool, &client.id, "secret_hash", None, None)
            .await
            .expect("Failed to create secret");

        record_oauth_event(
            &pool,
            &client.id,
            OAuthEventType::TokenIssued,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("Failed to record event");

        // Delete client
        delete_oauth_client(&pool, &client.id)
            .await
            .expect("Failed to delete client");

        // Verify cascade (secrets should be deleted due to ON DELETE CASCADE)
        let secrets = get_oauth_client_secrets(&pool, &client.id)
            .await
            .expect("Failed to get secrets");
        assert!(secrets.is_empty());
    }
}
