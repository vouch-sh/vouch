// SPDX-License-Identifier: BUSL-1.1
//! OAuth Client Application database operations.

use anyhow::Result;
use jiff::Timestamp;
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// OAuth Client Types
// ============================================================================

/// Access scope for OAuth applications.
///
/// Controls who can authenticate with the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessScope {
    /// Only users in the same organization can authenticate.
    Organization,
    /// Only the app creator can authenticate (default for backwards compatibility).
    #[default]
    Personal,
    /// Any authenticated Vouch user can authenticate.
    Public,
}

impl AccessScope {
    /// Convert to database string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Organization => "organization",
            Self::Personal => "personal",
            Self::Public => "public",
        }
    }

    /// Parse from database string (case-insensitive).
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "organization" => Some(Self::Organization),
            "personal" => Some(Self::Personal),
            "public" => Some(Self::Public),
            _ => None,
        }
    }

    /// Get a human-readable display name for the scope.
    #[must_use]
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Organization => "Organization",
            Self::Personal => "Personal",
            Self::Public => "Public",
        }
    }

    /// Get a description of what this scope means.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Organization => "Only users in your organization can authenticate",
            Self::Personal => "Only you can authenticate",
            Self::Public => "Any Vouch user can authenticate",
        }
    }
}

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

    /// Parse from database string (case-insensitive).
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
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

// ============================================================================
// OAuth Client
// ============================================================================

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
    /// Access scope controlling who can use this application.
    pub access_scope: String,
    /// Organization ID for organization-scoped apps.
    pub org_id: Option<String>,
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

    /// Get the access scope as enum.
    #[must_use]
    pub fn get_access_scope(&self) -> AccessScope {
        AccessScope::from_str(&self.access_scope).unwrap_or_default()
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

/// Create a new OAuth client application.
#[allow(clippy::too_many_arguments)]
pub async fn create_oauth_client(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    description: Option<&str>,
    application_type: OAuthClientType,
    redirect_uris: &[String],
    access_scope: AccessScope,
    org_id: Option<&str>,
) -> Result<(OAuthClient, String)> {
    let id = Uuid::now_v7().to_string();
    let client_id = Uuid::now_v7().to_string();
    let redirect_uris_json = serde_json::to_string(redirect_uris)?;

    sqlx::query(
        "INSERT INTO oauth_clients (id, user_id, client_id, name, description, application_type, redirect_uris, access_scope, org_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(&client_id)
    .bind(name)
    .bind(description)
    .bind(application_type.as_str())
    .bind(&redirect_uris_json)
    .bind(access_scope.as_str())
    .bind(org_id)
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
        "SELECT id, user_id, client_id, name, description, application_type, redirect_uris, active, created_at, updated_at, last_used_at, access_scope, org_id
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
        "SELECT id, user_id, client_id, name, description, application_type, redirect_uris, active, created_at, updated_at, last_used_at, access_scope, org_id
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
        "SELECT id, user_id, client_id, name, description, application_type, redirect_uris, active, created_at, updated_at, last_used_at, access_scope, org_id
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
    access_scope: Option<AccessScope>,
    org_id: Option<&str>,
) -> Result<()> {
    let redirect_uris_json = serde_json::to_string(redirect_uris)?;

    if let Some(scope) = access_scope {
        sqlx::query(
            "UPDATE oauth_clients SET name = ?, description = ?, redirect_uris = ?, access_scope = ?, org_id = ?, updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(name)
        .bind(description)
        .bind(&redirect_uris_json)
        .bind(scope.as_str())
        .bind(org_id)
        .bind(id)
        .execute(pool)
        .await?;
    } else {
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
    }

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
///
/// Performs application-level cascade deletes for DSQL compatibility:
/// 1. Delete usage events
/// 2. Delete secrets
/// 3. Delete the client
pub async fn delete_oauth_client(pool: &SqlitePool, id: &str) -> Result<u64> {
    let mut tx = pool.begin().await?;

    // 1. Delete usage events
    sqlx::query("DELETE FROM oauth_usage_events WHERE oauth_client_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    // 2. Delete secrets
    sqlx::query("DELETE FROM oauth_client_secrets WHERE oauth_client_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    // 3. Delete the client
    let result = sqlx::query("DELETE FROM oauth_clients WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_scope_from_str() {
        assert_eq!(
            AccessScope::from_str("organization"),
            Some(AccessScope::Organization)
        );
        assert_eq!(
            AccessScope::from_str("personal"),
            Some(AccessScope::Personal)
        );
        assert_eq!(AccessScope::from_str("public"), Some(AccessScope::Public));
        assert_eq!(AccessScope::from_str("invalid"), None);
        assert_eq!(AccessScope::from_str(""), None);
    }

    #[test]
    fn test_access_scope_from_str_case_insensitive() {
        assert_eq!(
            AccessScope::from_str("ORGANIZATION"),
            Some(AccessScope::Organization)
        );
        assert_eq!(
            AccessScope::from_str("Personal"),
            Some(AccessScope::Personal)
        );
        assert_eq!(AccessScope::from_str("PUBLIC"), Some(AccessScope::Public));
    }

    #[test]
    fn test_access_scope_as_str() {
        assert_eq!(AccessScope::Organization.as_str(), "organization");
        assert_eq!(AccessScope::Personal.as_str(), "personal");
        assert_eq!(AccessScope::Public.as_str(), "public");
    }

    #[test]
    fn test_access_scope_default() {
        assert_eq!(AccessScope::default(), AccessScope::Personal);
    }

    #[test]
    fn test_access_scope_display_name() {
        assert_eq!(AccessScope::Organization.display_name(), "Organization");
        assert_eq!(AccessScope::Personal.display_name(), "Personal");
        assert_eq!(AccessScope::Public.display_name(), "Public");
    }

    #[test]
    fn test_access_scope_description() {
        assert!(
            AccessScope::Organization
                .description()
                .contains("organization")
        );
        assert!(AccessScope::Personal.description().contains("you"));
        assert!(AccessScope::Public.description().contains("Any"));
    }

    #[test]
    fn test_access_scope_roundtrip() {
        for scope in [
            AccessScope::Organization,
            AccessScope::Personal,
            AccessScope::Public,
        ] {
            let s = scope.as_str();
            let parsed = AccessScope::from_str(s);
            assert_eq!(parsed, Some(scope));
        }
    }
}
