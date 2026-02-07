// SPDX-License-Identifier: BUSL-1.1
//! OAuth Client Application database operations.

use super::Pool;
use super::schema::{OAuthClientSecrets, OAuthClients, OAuthUsageEvents};
use super::types::BuildSql;
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_all, db_fetch_one, db_fetch_optional, tx_execute};
use anyhow::Result;
use jiff::Timestamp;
use sea_query::{Alias, Asterisk, Expr, Func, Order, Query};
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
    pub active: bool,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub last_used_at: Option<DbTimestamp>,
    /// Access scope controlling who can use this application.
    pub access_scope: String,
    /// Organization ID for organization-scoped apps.
    pub org_id: Option<String>,
}

impl OAuthClient {
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
    pool: &Pool,
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
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::insert()
            .into_table(OAuthClients::Table)
            .columns([
                OAuthClients::Id,
                OAuthClients::UserId,
                OAuthClients::ClientId,
                OAuthClients::Name,
                OAuthClients::Description,
                OAuthClients::ApplicationType,
                OAuthClients::RedirectUris,
                OAuthClients::AccessScope,
                OAuthClients::OrgId,
                OAuthClients::CreatedAt,
                OAuthClients::UpdatedAt,
            ])
            .values_panic([
                id.clone().into(),
                user_id.into(),
                client_id.clone().into(),
                name.into(),
                description.into(),
                application_type.as_str().into(),
                redirect_uris_json.into(),
                access_scope.as_str().into(),
                org_id.into(),
                now.as_str().into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    let client = get_oauth_client_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Just created OAuth client should exist"))?;

    Ok((client, client_id))
}

/// Get an OAuth client by internal ID.
pub async fn get_oauth_client_by_id(pool: &Pool, id: &str) -> Result<Option<OAuthClient>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                OAuthClients::Id,
                OAuthClients::UserId,
                OAuthClients::ClientId,
                OAuthClients::Name,
                OAuthClients::Description,
                OAuthClients::ApplicationType,
                OAuthClients::RedirectUris,
                OAuthClients::Active,
                OAuthClients::CreatedAt,
                OAuthClients::UpdatedAt,
                OAuthClients::LastUsedAt,
                OAuthClients::AccessScope,
                OAuthClients::OrgId,
            ])
            .from(OAuthClients::Table)
            .and_where(Expr::col(OAuthClients::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    let client = db_fetch_optional!(pool, sqlx::query_as::<_, OAuthClient>(&sql))?;

    Ok(client)
}

/// Get an OAuth client by public client_id.
pub async fn get_oauth_client_by_client_id(
    pool: &Pool,
    client_id: &str,
) -> Result<Option<OAuthClient>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                OAuthClients::Id,
                OAuthClients::UserId,
                OAuthClients::ClientId,
                OAuthClients::Name,
                OAuthClients::Description,
                OAuthClients::ApplicationType,
                OAuthClients::RedirectUris,
                OAuthClients::Active,
                OAuthClients::CreatedAt,
                OAuthClients::UpdatedAt,
                OAuthClients::LastUsedAt,
                OAuthClients::AccessScope,
                OAuthClients::OrgId,
            ])
            .from(OAuthClients::Table)
            .and_where(Expr::col(OAuthClients::ClientId).eq(client_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let client = db_fetch_optional!(pool, sqlx::query_as::<_, OAuthClient>(&sql))?;

    Ok(client)
}

/// Get all OAuth clients for a user.
pub async fn get_oauth_clients_for_user(pool: &Pool, user_id: &str) -> Result<Vec<OAuthClient>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                OAuthClients::Id,
                OAuthClients::UserId,
                OAuthClients::ClientId,
                OAuthClients::Name,
                OAuthClients::Description,
                OAuthClients::ApplicationType,
                OAuthClients::RedirectUris,
                OAuthClients::Active,
                OAuthClients::CreatedAt,
                OAuthClients::UpdatedAt,
                OAuthClients::LastUsedAt,
                OAuthClients::AccessScope,
                OAuthClients::OrgId,
            ])
            .from(OAuthClients::Table)
            .and_where(Expr::col(OAuthClients::UserId).eq(user_id))
            .order_by(OAuthClients::CreatedAt, Order::Desc)
            .to_owned();
        query.build_sql(db_type)
    };

    let clients = db_fetch_all!(pool, sqlx::query_as::<_, OAuthClient>(&sql))?;

    Ok(clients)
}

/// Update an OAuth client.
pub async fn update_oauth_client(
    pool: &Pool,
    id: &str,
    name: &str,
    description: Option<&str>,
    redirect_uris: &[String],
    access_scope: Option<AccessScope>,
    org_id: Option<&str>,
) -> Result<()> {
    let redirect_uris_json = serde_json::to_string(redirect_uris)?;
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let mut query = Query::update()
            .table(OAuthClients::Table)
            .value(OAuthClients::Name, name)
            .value(OAuthClients::Description, description)
            .value(OAuthClients::RedirectUris, redirect_uris_json.as_str())
            .value(OAuthClients::UpdatedAt, now.as_str())
            .to_owned();

        if let Some(scope) = access_scope {
            query = query
                .value(OAuthClients::AccessScope, scope.as_str())
                .value(OAuthClients::OrgId, org_id)
                .to_owned();
        }

        query = query
            .and_where(Expr::col(OAuthClients::Id).eq(id))
            .to_owned();

        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

/// Delete an OAuth client permanently.
///
/// Performs application-level cascade deletes for DSQL compatibility:
/// 1. Delete usage events
/// 2. Delete secrets
/// 3. Delete the client
pub async fn delete_oauth_client(pool: &Pool, id: &str) -> Result<u64> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();

    // 1. Delete usage events
    let sql1 = {
        let query = Query::delete()
            .from_table(OAuthUsageEvents::Table)
            .and_where(Expr::col(OAuthUsageEvents::OAuthClientId).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql1))?;

    // 2. Delete secrets
    let sql2 = {
        let query = Query::delete()
            .from_table(OAuthClientSecrets::Table)
            .and_where(Expr::col(OAuthClientSecrets::OAuthClientId).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql2))?;

    // 3. Delete the client
    let sql3 = {
        let query = Query::delete()
            .from_table(OAuthClients::Table)
            .and_where(Expr::col(OAuthClients::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };
    let result = tx_execute!(tx, sqlx::query(&sql3))?;

    tx.commit().await?;
    Ok(result.rows_affected())
}

/// Update last used timestamp for an OAuth client.
pub async fn update_oauth_client_last_used(pool: &Pool, id: &str) -> Result<()> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::update()
            .table(OAuthClients::Table)
            .value(OAuthClients::LastUsedAt, now.as_str())
            .and_where(Expr::col(OAuthClients::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

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
    pub created_at: DbTimestamp,
    pub expires_at: Option<DbTimestamp>,
    pub revoked_at: Option<DbTimestamp>,
}

impl OAuthClientSecret {
    /// Check if this secret is valid (not revoked and not expired).
    #[must_use]
    pub fn is_valid(&self, now: &Timestamp) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if let Some(expires) = &self.expires_at
            && expires.to_jiff() < *now
        {
            return false;
        }
        true
    }
}

/// Create a new client secret.
/// Returns the secret record and the plaintext secret (only shown once).
pub async fn create_oauth_client_secret(
    pool: &Pool,
    oauth_client_id: &str,
    secret_hash: &str,
    description: Option<&str>,
    expires_at: Option<&str>,
) -> Result<OAuthClientSecret> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let insert_sql = {
        let query = Query::insert()
            .into_table(OAuthClientSecrets::Table)
            .columns([
                OAuthClientSecrets::Id,
                OAuthClientSecrets::OAuthClientId,
                OAuthClientSecrets::SecretHash,
                OAuthClientSecrets::Description,
                OAuthClientSecrets::ExpiresAt,
                OAuthClientSecrets::CreatedAt,
            ])
            .values_panic([
                id.clone().into(),
                oauth_client_id.into(),
                secret_hash.into(),
                description.into(),
                expires_at.into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&insert_sql))?;

    let select_sql = {
        let query = Query::select()
            .columns([
                OAuthClientSecrets::Id,
                OAuthClientSecrets::OAuthClientId,
                OAuthClientSecrets::SecretHash,
                OAuthClientSecrets::Description,
                OAuthClientSecrets::CreatedAt,
                OAuthClientSecrets::ExpiresAt,
                OAuthClientSecrets::RevokedAt,
            ])
            .from(OAuthClientSecrets::Table)
            .and_where(Expr::col(OAuthClientSecrets::Id).eq(&id))
            .to_owned();
        query.build_sql(db_type)
    };

    let secret = db_fetch_one!(pool, sqlx::query_as::<_, OAuthClientSecret>(&select_sql))?;

    Ok(secret)
}

/// Get all secrets for an OAuth client.
pub async fn get_oauth_client_secrets(
    pool: &Pool,
    oauth_client_id: &str,
) -> Result<Vec<OAuthClientSecret>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                OAuthClientSecrets::Id,
                OAuthClientSecrets::OAuthClientId,
                OAuthClientSecrets::SecretHash,
                OAuthClientSecrets::Description,
                OAuthClientSecrets::CreatedAt,
                OAuthClientSecrets::ExpiresAt,
                OAuthClientSecrets::RevokedAt,
            ])
            .from(OAuthClientSecrets::Table)
            .and_where(Expr::col(OAuthClientSecrets::OAuthClientId).eq(oauth_client_id))
            .order_by(OAuthClientSecrets::CreatedAt, Order::Desc)
            .to_owned();
        query.build_sql(db_type)
    };

    let secrets = db_fetch_all!(pool, sqlx::query_as::<_, OAuthClientSecret>(&sql))?;

    Ok(secrets)
}

/// Get a secret by its hash.
pub async fn get_oauth_secret_by_hash(
    pool: &Pool,
    secret_hash: &str,
) -> Result<Option<OAuthClientSecret>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                OAuthClientSecrets::Id,
                OAuthClientSecrets::OAuthClientId,
                OAuthClientSecrets::SecretHash,
                OAuthClientSecrets::Description,
                OAuthClientSecrets::CreatedAt,
                OAuthClientSecrets::ExpiresAt,
                OAuthClientSecrets::RevokedAt,
            ])
            .from(OAuthClientSecrets::Table)
            .and_where(Expr::col(OAuthClientSecrets::SecretHash).eq(secret_hash))
            .to_owned();
        query.build_sql(db_type)
    };

    let secret = db_fetch_optional!(pool, sqlx::query_as::<_, OAuthClientSecret>(&sql))?;

    Ok(secret)
}

/// Revoke all secrets for an OAuth client.
pub async fn revoke_all_oauth_client_secrets(pool: &Pool, oauth_client_id: &str) -> Result<u64> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::update()
            .table(OAuthClientSecrets::Table)
            .value(OAuthClientSecrets::RevokedAt, now.as_str())
            .and_where(Expr::col(OAuthClientSecrets::OAuthClientId).eq(oauth_client_id))
            .and_where(Expr::col(OAuthClientSecrets::RevokedAt).is_null())
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

// ============================================================================
// OAuth Usage Events
// ============================================================================

/// OAuth usage event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pool: &Pool,
    oauth_client_id: &str,
    event_type: OAuthEventType,
    user_id: Option<&str>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    details: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::insert()
            .into_table(OAuthUsageEvents::Table)
            .columns([
                OAuthUsageEvents::Id,
                OAuthUsageEvents::OAuthClientId,
                OAuthUsageEvents::EventType,
                OAuthUsageEvents::UserId,
                OAuthUsageEvents::IpAddress,
                OAuthUsageEvents::UserAgent,
                OAuthUsageEvents::Details,
                OAuthUsageEvents::CreatedAt,
            ])
            .values_panic([
                id.clone().into(),
                oauth_client_id.into(),
                event_type.as_str().into(),
                user_id.into(),
                ip_address.into(),
                user_agent.into(),
                details.into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Get usage statistics for an OAuth client.
#[derive(Debug, sqlx::FromRow)]
pub struct OAuthUsageStats {
    pub event_type: String,
    pub count: i64,
}

pub async fn get_oauth_usage_stats(
    pool: &Pool,
    oauth_client_id: &str,
    since: Option<&str>,
) -> Result<Vec<OAuthUsageStats>> {
    let db_type = pool.db_type();

    let sql = {
        let mut query = Query::select()
            .column(OAuthUsageEvents::EventType)
            .expr_as(Func::count(Expr::col(Asterisk)), Alias::new("count"))
            .from(OAuthUsageEvents::Table)
            .and_where(Expr::col(OAuthUsageEvents::OAuthClientId).eq(oauth_client_id))
            .to_owned();

        if let Some(since) = since {
            query = query
                .and_where(Expr::col(OAuthUsageEvents::CreatedAt).gte(since))
                .to_owned();
        }

        query = query.group_by_col(OAuthUsageEvents::EventType).to_owned();

        query.build_sql(db_type)
    };

    let stats = db_fetch_all!(pool, sqlx::query_as::<_, OAuthUsageStats>(&sql))?;

    Ok(stats)
}

/// Delete old usage events (for retention policy).
pub async fn delete_old_oauth_usage_events(pool: &Pool, before: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(OAuthUsageEvents::Table)
            .and_where(Expr::col(OAuthUsageEvents::CreatedAt).lt(before))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

/// Validate client credentials (client_id + client_secret).
/// Returns the OAuth client if valid, None otherwise.
pub async fn validate_oauth_client_credentials(
    pool: &Pool,
    client_id: &str,
    secret_hash: &str,
) -> Result<Option<OAuthClient>> {
    // Get the client
    let Some(client) = get_oauth_client_by_client_id(pool, client_id).await? else {
        return Ok(None);
    };

    if !client.active {
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
    let now = Timestamp::now();
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
