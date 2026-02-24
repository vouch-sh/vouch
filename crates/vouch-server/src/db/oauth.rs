// SPDX-License-Identifier: BUSL-1.1
//! OAuth Client Application database operations.

use super::Pool;
use super::schema::{JwtAssertionJtis, OAuthClientSecrets, OAuthClients, OAuthUsageEvents};
use super::types::BuildSql;
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_all, db_fetch_one, db_fetch_optional, tx_execute};
use anyhow::Result;
use jiff::Timestamp;
use sea_query::{Alias, Asterisk, Expr, Func, Order, Query};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// OAuth Client Types
// ============================================================================

/// Access scope for OAuth applications.
///
/// Controls who can authenticate with the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, sqlx::Type)]
#[sqlx(type_name = "text")]
#[sqlx(rename_all = "lowercase")]
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
    /// Return the string representation for sea-query values.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Organization => "organization",
            Self::Personal => "personal",
            Self::Public => "public",
        }
    }

    /// Parse from a string (case-insensitive). Used for form/request parsing.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text")]
#[sqlx(rename_all = "lowercase")]
pub enum OAuthClientType {
    Web,
    Native,
    Spa,
    Service,
}

impl OAuthClientType {
    /// Return the string representation for sea-query values.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
            Self::Spa => "spa",
            Self::Service => "service",
        }
    }

    /// Parse from a string (case-insensitive). Used for form/request parsing.
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
    pub fn requires_pkce(&self) -> bool {
        matches!(self, Self::Native | Self::Spa)
    }
}

/// Token endpoint authentication method (RFC 7523).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenEndpointAuthMethod {
    /// Client authenticates using HTTP Basic with client_id:client_secret.
    #[default]
    ClientSecretBasic,
    /// Client sends client_id and client_secret in the POST body.
    ClientSecretPost,
    /// Client authenticates using a signed JWT assertion (RFC 7523).
    PrivateKeyJwt,
    /// Public client with no authentication.
    None,
}

impl TokenEndpointAuthMethod {
    /// Return the string representation for database storage.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::None => "none",
        }
    }
}

impl std::str::FromStr for TokenEndpointAuthMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "private_key_jwt" => Ok(Self::PrivateKeyJwt),
            "none" => Ok(Self::None),
            _ => Err(format!("Unknown token endpoint auth method: {s}")),
        }
    }
}

impl std::fmt::Display for TokenEndpointAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// FAPI 2.0 Security Profile designation for an OAuth client.
///
/// Controls which FAPI constraints apply during authorization and token requests.
///
/// Reference: <https://openid.net/specs/fapi-security-profile-2_0-final.html>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FapiProfile {
    /// No FAPI profile — standard OAuth 2.0 behavior.
    #[default]
    #[serde(rename = "none")]
    None,
    /// FAPI 2.0 Security Profile — enforces PAR, DPoP, private_key_jwt, PS256/ES256/EdDSA.
    #[serde(rename = "fapi2_security")]
    Fapi2Security,
}

impl FapiProfile {
    /// Parse from the database string representation.
    ///
    /// Unknown values default to `None` for forward compatibility.
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "fapi2_security" => Self::Fapi2Security,
            _ => Self::None,
        }
    }

    /// Return the database string representation.
    #[must_use]
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Fapi2Security => "fapi2_security",
        }
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
    pub application_type: OAuthClientType,
    pub redirect_uris: String,
    pub active: bool,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub last_used_at: Option<DbTimestamp>,
    /// Access scope controlling who can use this application.
    pub access_scope: AccessScope,
    /// Organization ID for organization-scoped apps.
    pub org_id: Option<String>,
    /// RFC 8707: JSON array of registered resource URIs.
    pub resource_uris: String,
    /// RFC 7523: Inline JWKS JSON for private_key_jwt client authentication.
    pub jwks: Option<String>,
    /// RFC 7523: Remote JWKS endpoint for private_key_jwt client authentication.
    pub jwks_uri: Option<String>,
    /// RFC 7523: Timestamp of last JWKS URI fetch.
    pub jwks_uri_cached_at: Option<DbTimestamp>,
    /// RFC 7523: Cached JWKS content fetched from jwks_uri.
    pub jwks_uri_cache: Option<String>,
    /// RFC 7523: Token endpoint authentication method.
    pub token_endpoint_auth_method: String,
    /// RFC 9101: Client's preferred signing algorithm for Request Objects.
    pub request_object_signing_alg: Option<String>,
    /// RFC 9101: Whether this client MUST use JAR for authorization requests.
    pub require_signed_request_object: Option<bool>,
    /// FAPI 2.0: Raw profile string stored in the database (e.g., "none", "fapi2_security").
    ///
    /// Use `fapi_profile()` to get the parsed `FapiProfile` value.
    pub fapi_profile: String,
    /// FAPI 2.0: Whether access tokens must be sender-constrained via DPoP.
    pub dpop_bound_access_tokens: bool,
}

impl OAuthClient {
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

    /// Get resource URIs as a vector (RFC 8707).
    #[must_use]
    pub fn get_resource_uris(&self) -> Vec<String> {
        serde_json::from_str(&self.resource_uris).unwrap_or_default()
    }

    /// Check if a resource URI is registered for this client (RFC 8707).
    ///
    /// Returns `true` if the URI matches one of the registered resource URIs,
    /// or if no resource URIs are registered (open policy).
    #[must_use]
    pub fn is_valid_resource_uri(&self, uri: &str) -> bool {
        let uris = self.get_resource_uris();
        if uris.is_empty() {
            // No resource URIs registered — allow any resource
            return true;
        }
        uris.iter().any(|u| u == uri)
    }

    /// Get the parsed FAPI 2.0 security profile for this client.
    #[must_use]
    pub fn fapi_profile(&self) -> FapiProfile {
        FapiProfile::from_db(&self.fapi_profile)
    }

    /// Returns `true` if this client has FAPI 2.0 Security Profile enabled.
    #[must_use]
    pub fn is_fapi(&self) -> bool {
        self.fapi_profile() != FapiProfile::None
    }
}

/// The columns selected in all `OAuthClient` SELECT queries.
///
/// Centralized here so adding a new column only requires updating one place.
const OAUTH_CLIENT_COLUMNS: &[OAuthClients] = &[
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
    OAuthClients::ResourceUris,
    OAuthClients::Jwks,
    OAuthClients::JwksUri,
    OAuthClients::JwksUriCachedAt,
    OAuthClients::JwksUriCache,
    OAuthClients::TokenEndpointAuthMethod,
    OAuthClients::RequestObjectSigningAlg,
    OAuthClients::RequireSignedRequestObject,
    OAuthClients::FapiProfile,
    OAuthClients::DpopBoundAccessTokens,
];

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
    resource_uris: &[String],
) -> Result<(OAuthClient, String)> {
    let id = Uuid::now_v7().to_string();
    let client_id = Uuid::now_v7().to_string();
    let redirect_uris_json = serde_json::to_string(redirect_uris)?;
    let resource_uris_json = serde_json::to_string(resource_uris)?;
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
                OAuthClients::ResourceUris,
                OAuthClients::TokenEndpointAuthMethod,
                OAuthClients::FapiProfile,
                OAuthClients::DpopBoundAccessTokens,
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
                resource_uris_json.into(),
                TokenEndpointAuthMethod::default().as_str().into(),
                FapiProfile::None.as_db_str().into(),
                false.into(),
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
            .columns(OAUTH_CLIENT_COLUMNS.iter().copied())
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
            .columns(OAUTH_CLIENT_COLUMNS.iter().copied())
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
            .columns(OAUTH_CLIENT_COLUMNS.iter().copied())
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
#[allow(clippy::too_many_arguments)]
pub async fn update_oauth_client(
    pool: &Pool,
    id: &str,
    name: &str,
    description: Option<&str>,
    redirect_uris: &[String],
    access_scope: Option<AccessScope>,
    org_id: Option<&str>,
    resource_uris: &[String],
) -> Result<()> {
    let redirect_uris_json = serde_json::to_string(redirect_uris)?;
    let resource_uris_json = serde_json::to_string(resource_uris)?;
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let mut query = Query::update()
            .table(OAuthClients::Table)
            .value(OAuthClients::Name, name)
            .value(OAuthClients::Description, description)
            .value(OAuthClients::RedirectUris, redirect_uris_json.as_str())
            .value(OAuthClients::ResourceUris, resource_uris_json.as_str())
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

// ============================================================================
// JWKS Cache Operations (RFC 7523)
// ============================================================================

/// Get the effective JWKS for a client (inline or cached from URI).
///
/// Returns the inline `jwks` field if set, otherwise the `jwks_uri_cache`.
#[must_use]
pub fn get_client_jwks(client: &OAuthClient) -> Option<&str> {
    client.jwks.as_deref().or(client.jwks_uri_cache.as_deref())
}

/// Update the cached JWKS fetched from a client's jwks_uri.
pub async fn update_client_jwks_cache(pool: &Pool, id: &str, jwks_json: &str) -> Result<()> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::update()
            .table(OAuthClients::Table)
            .value(OAuthClients::JwksUriCache, jwks_json)
            .value(OAuthClients::JwksUriCachedAt, now.as_str())
            .and_where(Expr::col(OAuthClients::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

/// Test-only helpers for modifying OAuth clients.
#[cfg(test)]
pub mod test_helpers {
    use super::*;

    /// Update the inline JWKS for a client (RFC 7523 private_key_jwt).
    pub async fn update_oauth_client_jwks(pool: &Pool, id: &str, jwks_json: &str) -> Result<()> {
        let db_type = pool.db_type();
        let now = Timestamp::now().to_string();

        let sql = {
            let query = Query::update()
                .table(OAuthClients::Table)
                .value(OAuthClients::Jwks, jwks_json)
                .value(OAuthClients::UpdatedAt, now.as_str())
                .and_where(Expr::col(OAuthClients::Id).eq(id))
                .to_owned();
            query.build_sql(db_type)
        };

        db_execute!(pool, sqlx::query(&sql))?;

        Ok(())
    }

    /// Update the token endpoint authentication method for a client (RFC 7523).
    pub async fn update_oauth_client_auth_method(
        pool: &Pool,
        id: &str,
        method: &str,
    ) -> Result<()> {
        let db_type = pool.db_type();
        let now = Timestamp::now().to_string();

        let sql = {
            let query = Query::update()
                .table(OAuthClients::Table)
                .value(OAuthClients::TokenEndpointAuthMethod, method)
                .value(OAuthClients::UpdatedAt, now.as_str())
                .and_where(Expr::col(OAuthClients::Id).eq(id))
                .to_owned();
            query.build_sql(db_type)
        };

        db_execute!(pool, sqlx::query(&sql))?;

        Ok(())
    }

    /// Update JAR-related fields for a client (RFC 9101).
    pub async fn update_oauth_client_jar_settings(
        pool: &Pool,
        id: &str,
        request_object_signing_alg: Option<&str>,
        require_signed_request_object: bool,
    ) -> Result<()> {
        let db_type = pool.db_type();
        let now = Timestamp::now().to_string();

        let sql = {
            let query = Query::update()
                .table(OAuthClients::Table)
                .value(
                    OAuthClients::RequestObjectSigningAlg,
                    request_object_signing_alg,
                )
                .value(
                    OAuthClients::RequireSignedRequestObject,
                    require_signed_request_object,
                )
                .value(OAuthClients::UpdatedAt, now.as_str())
                .and_where(Expr::col(OAuthClients::Id).eq(id))
                .to_owned();
            query.build_sql(db_type)
        };

        db_execute!(pool, sqlx::query(&sql))?;

        Ok(())
    }

    /// Update FAPI 2.0 profile settings for a client.
    pub async fn update_oauth_client_fapi_settings(
        pool: &Pool,
        id: &str,
        fapi_profile: FapiProfile,
        dpop_bound_access_tokens: bool,
    ) -> Result<()> {
        let db_type = pool.db_type();
        let now = Timestamp::now().to_string();

        let sql = {
            let query = Query::update()
                .table(OAuthClients::Table)
                .value(OAuthClients::FapiProfile, fapi_profile.as_db_str())
                .value(OAuthClients::DpopBoundAccessTokens, dpop_bound_access_tokens)
                .value(OAuthClients::UpdatedAt, now.as_str())
                .and_where(Expr::col(OAuthClients::Id).eq(id))
                .to_owned();
            query.build_sql(db_type)
        };

        db_execute!(pool, sqlx::query(&sql))?;

        Ok(())
    }
}

// ============================================================================
// JWT Assertion JTI Operations (RFC 7523)
// ============================================================================

/// Maximum JTI length to prevent oversized values inflating the table.
const MAX_JTI_LENGTH: usize = 256;

/// Store a JWT assertion JTI for replay prevention.
///
/// Returns `true` if stored successfully (first use), `false` if the
/// (jti, client_id) pair already exists (replay detected). The UNIQUE
/// constraint on (jti, client_id) makes this atomic — no TOCTOU race.
pub async fn store_jwt_assertion_jti(
    pool: &Pool,
    jti: &str,
    client_id: &str,
    expires_at: &str,
) -> Result<bool> {
    if jti.len() > MAX_JTI_LENGTH {
        return Err(anyhow::anyhow!(
            "JTI exceeds maximum length ({MAX_JTI_LENGTH})"
        ));
    }

    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::insert()
            .into_table(JwtAssertionJtis::Table)
            .columns([
                JwtAssertionJtis::Id,
                JwtAssertionJtis::Jti,
                JwtAssertionJtis::ClientId,
                JwtAssertionJtis::CreatedAt,
                JwtAssertionJtis::ExpiresAt,
            ])
            .values_panic([
                id.into(),
                jti.into(),
                client_id.into(),
                now.as_str().into(),
                expires_at.into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    match db_execute!(pool, sqlx::query(&sql)) {
        Ok(_) => Ok(true),
        Err(e) => {
            // Check for unique constraint violation (replay)
            let err_str = e.to_string();
            if err_str.contains("UNIQUE") || err_str.contains("duplicate key") {
                Ok(false)
            } else {
                Err(e.into())
            }
        }
    }
}

/// Delete expired JWT assertion JTI entries.
pub async fn delete_expired_jwt_assertion_jtis(pool: &Pool, now: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(JwtAssertionJtis::Table)
            .and_where(Expr::col(JwtAssertionJtis::ExpiresAt).lte(now))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

// ============================================================================
// Client Credential Validation
// ============================================================================

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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    #[test]
    fn test_token_endpoint_auth_method_from_str_client_secret_basic() {
        let result: Result<TokenEndpointAuthMethod, _> = "client_secret_basic".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::ClientSecretBasic));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_client_secret_post() {
        let result: Result<TokenEndpointAuthMethod, _> = "client_secret_post".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::ClientSecretPost));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_private_key_jwt() {
        let result: Result<TokenEndpointAuthMethod, _> = "private_key_jwt".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::PrivateKeyJwt));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_none() {
        let result: Result<TokenEndpointAuthMethod, _> = "none".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::None));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_rejects_unknown() {
        let result: Result<TokenEndpointAuthMethod, _> = "magic_auth".parse();
        assert!(result.is_err());

        let result2: Result<TokenEndpointAuthMethod, _> = "".parse();
        assert!(result2.is_err());
    }

    #[test]
    fn test_token_endpoint_auth_method_display_roundtrip() {
        let variants = [
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
            TokenEndpointAuthMethod::PrivateKeyJwt,
            TokenEndpointAuthMethod::None,
        ];
        for variant in variants {
            let display_str = variant.to_string();
            let parsed: Result<TokenEndpointAuthMethod, _> = display_str.parse();
            assert_eq!(parsed, Ok(variant));
        }
    }

    #[test]
    fn test_fapi_profile_from_db() {
        assert_eq!(FapiProfile::from_db("none"), FapiProfile::None);
        assert_eq!(FapiProfile::from_db("fapi2_security"), FapiProfile::Fapi2Security);
        // Unknown values default to None for forward compatibility
        assert_eq!(FapiProfile::from_db("unknown"), FapiProfile::None);
        assert_eq!(FapiProfile::from_db(""), FapiProfile::None);
    }

    #[test]
    fn test_fapi_profile_as_db_str() {
        assert_eq!(FapiProfile::None.as_db_str(), "none");
        assert_eq!(FapiProfile::Fapi2Security.as_db_str(), "fapi2_security");
    }

    #[test]
    fn test_fapi_profile_default() {
        assert_eq!(FapiProfile::default(), FapiProfile::None);
    }

    #[test]
    fn test_fapi_profile_roundtrip() {
        for profile in [FapiProfile::None, FapiProfile::Fapi2Security] {
            let db_str = profile.as_db_str();
            let parsed = FapiProfile::from_db(db_str);
            assert_eq!(parsed, profile);
        }
    }

    #[test]
    fn test_fapi_profile_serde_roundtrip() {
        let json = serde_json::to_string(&FapiProfile::Fapi2Security)
            .expect("FapiProfile::Fapi2Security serialization");
        assert_eq!(json, r#""fapi2_security""#);

        let parsed: FapiProfile =
            serde_json::from_str(&json).expect("FapiProfile deserialization");
        assert_eq!(parsed, FapiProfile::Fapi2Security);

        let none_json =
            serde_json::to_string(&FapiProfile::None).expect("FapiProfile::None serialization");
        assert_eq!(none_json, r#""none""#);
    }
}
