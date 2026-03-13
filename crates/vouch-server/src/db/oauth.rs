// SPDX-License-Identifier: BUSL-1.1
//! OAuth Client Application database operations.

use super::audit::{AuditEventFilter, AuditStore};
use super::document_type::{Document, DocumentType};
use super::documents::audit::OAuthUsageData;
use super::documents::jwt_assertion_jti::JwtAssertionJtiDoc;
use super::documents::oauth::{
    AccessScope, FapiProfile, OAuthClientDoc, OAuthClientSecretDoc, OAuthClientType,
    RegistrationSource, TokenEndpointAuthMethod,
};
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

// ============================================================================
// OAuth Client
// ============================================================================

/// OAuth client application record.
#[derive(Debug)]
pub struct OAuthClient {
    pub id: String,
    pub user_id: Option<String>,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub application_type: OAuthClientType,
    pub redirect_uris: Vec<String>,
    pub active: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub access_scope: AccessScope,
    pub org_id: Option<String>,
    pub resource_uris: Vec<String>,
    pub jwks: Option<String>,
    pub jwks_uri: Option<String>,
    pub jwks_uri_cached_at: Option<Timestamp>,
    pub jwks_uri_cache: Option<String>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub request_object_signing_alg: Option<String>,
    pub require_signed_request_object: Option<bool>,
    pub fapi_profile: FapiProfile,
    pub dpop_bound_access_tokens: bool,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub registration_source: Option<RegistrationSource>,
    pub registration_access_token_hash: Option<String>,
    pub registration_metadata: Option<String>,
}

impl From<Document<OAuthClientDoc>> for OAuthClient {
    fn from(doc: Document<OAuthClientDoc>) -> Self {
        Self {
            id: doc.id,
            user_id: doc.data.user_id,
            client_id: doc.data.client_id,
            name: doc.data.name,
            description: doc.data.description,
            application_type: doc.data.application_type,
            redirect_uris: doc.data.redirect_uris,
            active: doc.data.active,
            created_at: doc.created_at,
            updated_at: doc.updated_at,
            last_used_at: doc.last_used_at,
            access_scope: doc.data.access_scope,
            org_id: doc.data.org_id,
            resource_uris: doc.data.resource_uris,
            jwks: doc.data.jwks,
            jwks_uri: doc.data.jwks_uri,
            jwks_uri_cached_at: doc.data.jwks_uri_cached_at,
            jwks_uri_cache: doc.data.jwks_uri_cache,
            token_endpoint_auth_method: doc.data.token_endpoint_auth_method,
            request_object_signing_alg: doc.data.request_object_signing_alg,
            require_signed_request_object: doc.data.require_signed_request_object,
            fapi_profile: doc.data.fapi_profile,
            dpop_bound_access_tokens: doc.data.dpop_bound_access_tokens,
            grant_types: doc.data.grant_types,
            response_types: doc.data.response_types,
            software_id: doc.data.software_id,
            software_version: doc.data.software_version,
            registration_source: doc.data.registration_source,
            registration_access_token_hash: doc.data.registration_access_token_hash,
            registration_metadata: doc.data.registration_metadata,
        }
    }
}

impl OAuthClient {
    #[must_use]
    pub fn is_valid_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }

    #[must_use]
    pub fn is_valid_resource_uri(&self, uri: &str) -> bool {
        if self.resource_uris.is_empty() {
            return true;
        }
        self.resource_uris.iter().any(|u| u == uri)
    }

    #[must_use]
    pub fn is_fapi(&self) -> bool {
        self.fapi_profile != FapiProfile::None
    }
}

/// Parameters for creating a new OAuth client application.
pub struct CreateOAuthClientParams<'a> {
    pub user_id: Option<&'a str>,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub application_type: OAuthClientType,
    pub redirect_uris: &'a [String],
    pub access_scope: AccessScope,
    pub org_id: Option<&'a str>,
    pub resource_uris: &'a [String],
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    pub jwks: Option<&'a str>,
    pub jwks_uri: Option<&'a str>,
    pub fapi_profile: Option<FapiProfile>,
    pub dpop_bound_access_tokens: Option<bool>,
    pub grant_types: Option<&'a [String]>,
    pub response_types: Option<&'a [String]>,
    pub software_id: Option<&'a str>,
    pub software_version: Option<&'a str>,
    pub registration_source: RegistrationSource,
    pub registration_access_token_hash: Option<&'a str>,
    pub registration_metadata: Option<&'a str>,
}

/// Create a new OAuth client application.
pub async fn create_oauth_client(
    store: &DocumentStore,
    params: &CreateOAuthClientParams<'_>,
) -> Result<(OAuthClient, String)> {
    let client_id = uuid::Uuid::now_v7().to_string();

    let doc = OAuthClientDoc {
        user_id: params.user_id.map(String::from),
        client_id: client_id.clone(),
        name: params.name.to_string(),
        description: params.description.map(String::from),
        application_type: params.application_type,
        redirect_uris: params.redirect_uris.to_vec(),
        active: true,
        access_scope: params.access_scope,
        org_id: params.org_id.map(String::from),
        resource_uris: params.resource_uris.to_vec(),
        jwks: params.jwks.map(String::from),
        jwks_uri: params.jwks_uri.map(String::from),
        jwks_uri_cached_at: None,
        jwks_uri_cache: None,
        token_endpoint_auth_method: params.token_endpoint_auth_method.unwrap_or_default(),
        request_object_signing_alg: None,
        require_signed_request_object: None,
        fapi_profile: params.fapi_profile.unwrap_or_default(),
        dpop_bound_access_tokens: params.dpop_bound_access_tokens.unwrap_or(false),
        grant_types: params.grant_types.map(<[String]>::to_vec),
        response_types: params.response_types.map(<[String]>::to_vec),
        software_id: params.software_id.map(String::from),
        software_version: params.software_version.map(String::from),
        registration_source: Some(params.registration_source),
        registration_access_token_hash: params.registration_access_token_hash.map(String::from),
        registration_metadata: params.registration_metadata.map(String::from),
    };

    let result = store.insert(&doc).await?;
    let oauth_client = OAuthClient::from(result);

    Ok((oauth_client, client_id))
}

/// Get an OAuth client by internal ID.
pub async fn get_oauth_client_by_id(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<OAuthClient>> {
    let doc = store.get::<OAuthClientDoc>(id).await?;
    Ok(doc.map(OAuthClient::from))
}

/// Get an OAuth client by public client_id.
pub async fn get_oauth_client_by_client_id(
    store: &DocumentStore,
    client_id: &str,
) -> Result<Option<OAuthClient>> {
    let doc = store
        .find_one::<OAuthClientDoc>("client_id", client_id)
        .await?;
    Ok(doc.map(OAuthClient::from))
}

/// Get all OAuth clients for a user.
pub async fn get_oauth_clients_for_user(
    store: &DocumentStore,
    user_id: &str,
) -> Result<Vec<OAuthClient>> {
    let docs = store.find_all::<OAuthClientDoc>("user_id", user_id).await?;
    Ok(docs.into_iter().map(OAuthClient::from).collect())
}

/// Parameters for updating an OAuth client.
pub struct UpdateOAuthClientParams<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub redirect_uris: &'a [String],
    pub access_scope: Option<AccessScope>,
    pub org_id: Option<&'a str>,
    pub resource_uris: &'a [String],
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub jwks: Option<&'a str>,
    pub jwks_uri: Option<&'a str>,
    pub fapi_profile: FapiProfile,
    pub dpop_bound_access_tokens: bool,
}

/// Update an OAuth client.
///
/// Uses [`DocumentStore::modify`] for read-modify-write with automatic
/// version-conflict retry.
pub async fn update_oauth_client(
    store: &DocumentStore,
    params: &UpdateOAuthClientParams<'_>,
) -> Result<()> {
    store
        .modify::<OAuthClientDoc, _>(params.id, |data| {
            data.name = params.name.to_string();
            data.description = params.description.map(String::from);
            data.redirect_uris = params.redirect_uris.to_vec();
            data.resource_uris = params.resource_uris.to_vec();
            data.token_endpoint_auth_method = params.token_endpoint_auth_method;
            data.jwks = params.jwks.map(String::from);
            data.jwks_uri = params.jwks_uri.map(String::from);
            data.fapi_profile = params.fapi_profile;
            data.dpop_bound_access_tokens = params.dpop_bound_access_tokens;

            if let Some(scope) = params.access_scope {
                data.access_scope = scope;
                data.org_id = params.org_id.map(String::from);
            }
        })
        .await?;
    Ok(())
}

/// Delete an OAuth client permanently.
///
/// Cascade deletes secrets and the client within a single transaction
/// so no orphaned secrets remain on partial failure.
pub async fn delete_oauth_client(store: &DocumentStore, id: &str) -> Result<u64> {
    let mut tx = store.begin().await?;

    // Delete secrets
    tx.delete_by_index::<OAuthClientSecretDoc>("oauth_client_id", id)
        .await?;

    // Delete the client
    tx.delete(id).await?;

    tx.commit().await?;
    Ok(1)
}

/// Update last used timestamp for an OAuth client.
///
/// Performs a lightweight column-level UPDATE (no encrypt/decrypt).
pub async fn update_oauth_client_last_used(store: &DocumentStore, id: &str) -> Result<()> {
    store.update_last_used_at(id).await
}

// ============================================================================
// OAuth Client Secrets
// ============================================================================

/// OAuth client secret record.
#[derive(Debug)]
#[allow(dead_code)]
pub struct OAuthClientSecret {
    pub id: String,
    pub oauth_client_id: String,
    pub secret_hash: String,
    pub description: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

impl From<Document<OAuthClientSecretDoc>> for OAuthClientSecret {
    fn from(doc: Document<OAuthClientSecretDoc>) -> Self {
        Self {
            id: doc.id,
            oauth_client_id: doc.data.oauth_client_id,
            secret_hash: doc.data.secret_hash,
            description: doc.data.description,
            created_at: doc.created_at,
            expires_at: doc.data.expires_at,
            revoked_at: doc.data.revoked_at,
        }
    }
}

impl OAuthClientSecret {
    /// Check if this secret is valid (not revoked/expired).
    #[must_use]
    pub fn is_valid(&self, now: &Timestamp) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if let Some(expires) = self.expires_at
            && expires <= *now
        {
            return false;
        }
        true
    }
}

/// Create a new client secret.
pub async fn create_oauth_client_secret(
    store: &DocumentStore,
    oauth_client_id: &str,
    secret_hash: &str,
    description: Option<&str>,
    expires_at: Option<Timestamp>,
) -> Result<OAuthClientSecret> {
    let doc = OAuthClientSecretDoc {
        oauth_client_id: oauth_client_id.to_string(),
        secret_hash: secret_hash.to_string(),
        description: description.map(String::from),
        expires_at,
        revoked_at: None,
    };
    let result = store.insert(&doc).await?;
    Ok(OAuthClientSecret::from(result))
}

/// Get all secrets for an OAuth client.
pub async fn get_oauth_client_secrets(
    store: &DocumentStore,
    oauth_client_id: &str,
) -> Result<Vec<OAuthClientSecret>> {
    let docs = store
        .find_all::<OAuthClientSecretDoc>("oauth_client_id", oauth_client_id)
        .await?;
    Ok(docs.into_iter().map(OAuthClientSecret::from).collect())
}

/// Get a secret by its hash.
pub async fn get_oauth_secret_by_hash(
    store: &DocumentStore,
    secret_hash: &str,
) -> Result<Option<OAuthClientSecret>> {
    let doc = store
        .find_one::<OAuthClientSecretDoc>("secret_hash", secret_hash)
        .await?;
    Ok(doc.map(OAuthClientSecret::from))
}

/// Revoke all secrets for an OAuth client.
pub async fn revoke_all_oauth_client_secrets(
    store: &DocumentStore,
    oauth_client_id: &str,
) -> Result<u64> {
    let now = Timestamp::now();
    let count = store
        .update_by_index::<OAuthClientSecretDoc, _>("oauth_client_id", oauth_client_id, |data| {
            if data.revoked_at.is_none() {
                data.revoked_at = Some(now);
            }
        })
        .await?;
    Ok(count)
}

/// Get a secret by its internal ID.
pub async fn get_oauth_client_secret_by_id(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<OAuthClientSecret>> {
    let doc = store.get::<OAuthClientSecretDoc>(id).await?;
    Ok(doc.map(OAuthClientSecret::from))
}

/// Revoke a single secret (soft-delete).
///
/// Returns `true` if the secret was found and updated, `false` if not found.
pub async fn revoke_oauth_client_secret(store: &DocumentStore, id: &str) -> Result<bool> {
    store
        .modify::<OAuthClientSecretDoc, _>(id, |data| {
            data.revoked_at = Some(Timestamp::now());
        })
        .await
}

// ============================================================================
// OAuth Usage Events (now via AuditStore)
// ============================================================================

/// OAuth usage event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthEventType {
    TokenIssued,
    TokenRefreshed,
    TokenRevoked,
    AuthSuccess,
    AuthFailure,
    ClientRegistered,
    SecretAdded,
    SecretRevoked,
}

impl OAuthEventType {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TokenIssued => "token_issued",
            Self::TokenRefreshed => "token_refreshed",
            Self::TokenRevoked => "token_revoked",
            Self::AuthSuccess => "auth_success",
            Self::AuthFailure => "auth_failure",
            Self::ClientRegistered => "client_registered",
            Self::SecretAdded => "secret_added",
            Self::SecretRevoked => "secret_revoked",
        }
    }
}

/// Record an OAuth usage event via the audit store.
pub async fn record_oauth_event(
    audit: &AuditStore,
    oauth_client_id: &str,
    event_type: OAuthEventType,
    user_id: Option<&str>,
    ip_address: Option<std::net::IpAddr>,
    user_agent: Option<&str>,
    details: Option<&str>,
) -> Result<String> {
    let geo = ip_address.and_then(crate::geo::lookup);
    let data = OAuthUsageData {
        oauth_client_id: oauth_client_id.to_string(),
        details: details.map(String::from),
        client_ip: ip_address.map(|ip| ip.to_string()),
        user_agent: user_agent.map(String::from),
        country_code: geo.as_ref().map(|g| g.country_code.clone()),
        asn: geo.as_ref().and_then(|g| g.asn),
        org_name: geo.as_ref().and_then(|g| g.org_name.clone()),
    };
    let data_json = serde_json::to_string(&data)?;

    audit
        .insert_event(
            &format!("oauth_{}", event_type.as_str()),
            user_id,
            None,
            &data_json,
        )
        .await
}

/// OAuth usage statistics.
#[derive(Debug)]
pub struct OAuthUsageStats {
    pub event_type: String,
    pub count: i64,
}

/// Get usage statistics for an OAuth client.
///
/// Queries audit events and counts occurrences per event type,
/// filtering to events matching the given `oauth_client_id`.
pub async fn get_oauth_usage_stats(
    audit: &AuditStore,
    oauth_client_id: &str,
    since: Option<&str>,
) -> Result<Vec<OAuthUsageStats>> {
    let mut stats: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

    for event_type in [
        "oauth_token_issued",
        "oauth_token_refreshed",
        "oauth_token_revoked",
        "oauth_auth_success",
        "oauth_auth_failure",
        "oauth_client_registered",
    ] {
        let filter = AuditEventFilter {
            event_types: Some(vec![event_type.to_string()]),
            since: since.map(String::from),
            ..AuditEventFilter::default()
        };
        let events = audit.query_events(&filter).await?;
        for event in &events {
            let Ok(data) = serde_json::from_str::<OAuthUsageData>(&event.data) else {
                continue;
            };
            if data.oauth_client_id == oauth_client_id {
                *stats.entry(event_type.to_string()).or_default() += 1;
            }
        }
    }

    Ok(stats
        .into_iter()
        .map(|(event_type, count)| OAuthUsageStats { event_type, count })
        .collect())
}

/// Delete old usage events (for retention policy).
pub async fn delete_old_oauth_usage_events(audit: &AuditStore, before: Timestamp) -> Result<u64> {
    let before_str = before.to_string();
    let mut total = 0;
    for event_type in [
        "oauth_token_issued",
        "oauth_token_refreshed",
        "oauth_token_revoked",
        "oauth_auth_success",
        "oauth_auth_failure",
        "oauth_client_registered",
    ] {
        total += audit.delete_old_events(event_type, &before_str).await?;
    }
    Ok(total)
}

// ============================================================================
// JWKS Cache Operations (RFC 7523)
// ============================================================================

/// Get the effective JWKS for a client.
#[must_use]
pub fn get_client_jwks(client: &OAuthClient) -> Option<&str> {
    client.jwks.as_deref().or(client.jwks_uri_cache.as_deref())
}

/// Update the cached JWKS fetched from a client's `jwks_uri`.
///
/// Uses optimistic concurrency control. A version conflict on this
/// cache update is logged and silently ignored — the next request
/// will re-fetch the JWKS.
pub async fn update_client_jwks_cache(
    store: &DocumentStore,
    id: &str,
    jwks_json: &str,
) -> Result<()> {
    let jwks_owned = jwks_json.to_string();
    store
        .modify::<OAuthClientDoc, _>(id, |data| {
            data.jwks_uri_cache = Some(jwks_owned.clone());
            data.jwks_uri_cached_at = Some(Timestamp::now());
        })
        .await?;
    Ok(())
}

/// Test-only helpers for modifying OAuth clients.
#[cfg(test)]
pub mod test_helpers {
    use super::*;

    pub async fn update_oauth_client_jwks(
        store: &DocumentStore,
        id: &str,
        jwks_json: &str,
    ) -> Result<()> {
        if let Some(doc) = store.get::<OAuthClientDoc>(id).await? {
            let mut data = doc.data;
            data.jwks = Some(jwks_json.to_string());
            store.update(id, &data).await?;
        }
        Ok(())
    }

    pub async fn update_oauth_client_auth_method(
        store: &DocumentStore,
        id: &str,
        method: &str,
    ) -> Result<()> {
        if let Some(doc) = store.get::<OAuthClientDoc>(id).await? {
            let mut data = doc.data;
            data.token_endpoint_auth_method = match method {
                "private_key_jwt" => TokenEndpointAuthMethod::PrivateKeyJwt,
                "client_secret_post" => TokenEndpointAuthMethod::ClientSecretPost,
                "none" => TokenEndpointAuthMethod::None,
                _ => TokenEndpointAuthMethod::ClientSecretBasic,
            };
            store.update(id, &data).await?;
        }
        Ok(())
    }

    pub async fn update_oauth_client_jar_settings(
        store: &DocumentStore,
        id: &str,
        request_object_signing_alg: Option<&str>,
        require_signed_request_object: bool,
    ) -> Result<()> {
        if let Some(doc) = store.get::<OAuthClientDoc>(id).await? {
            let mut data = doc.data;
            data.request_object_signing_alg = request_object_signing_alg.map(String::from);
            data.require_signed_request_object = Some(require_signed_request_object);
            store.update(id, &data).await?;
        }
        Ok(())
    }

    pub async fn update_oauth_client_fapi_settings(
        store: &DocumentStore,
        id: &str,
        fapi_profile: FapiProfile,
        dpop_bound_access_tokens: bool,
    ) -> Result<()> {
        if let Some(doc) = store.get::<OAuthClientDoc>(id).await? {
            let mut data = doc.data;
            data.fapi_profile = fapi_profile;
            data.dpop_bound_access_tokens = dpop_bound_access_tokens;
            store.update(id, &data).await?;
        }
        Ok(())
    }
}

// ============================================================================
// JWT Assertion JTI Operations (RFC 7523)
// ============================================================================

/// Maximum JTI length.
const MAX_JTI_LENGTH: usize = 256;

/// Store a JWT assertion JTI for replay prevention.
pub async fn store_jwt_assertion_jti(
    store: &DocumentStore,
    jti: &str,
    client_id: &str,
    expires_at: Timestamp,
) -> Result<bool> {
    if jti.len() > MAX_JTI_LENGTH {
        return Err(anyhow::anyhow!(
            "JTI exceeds maximum length ({MAX_JTI_LENGTH})"
        ));
    }

    // Check for existing JTI+client_id combination
    let existing = store
        .find_by_indexes::<JwtAssertionJtiDoc>(&[("jti", jti), ("client_id", client_id)])
        .await?;
    if !existing.is_empty() {
        return Ok(false);
    }

    let doc = JwtAssertionJtiDoc {
        jti: jti.to_string(),
        client_id: client_id.to_string(),
        expires_at,
    };

    match store.insert(&doc).await {
        Ok(_) => Ok(true),
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("UNIQUE") || err_str.contains("duplicate key") {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

/// Delete expired JWT assertion JTI entries.
pub async fn delete_expired_jwt_assertion_jtis(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(JwtAssertionJtiDoc::DOC_TYPE).await
}

// ============================================================================
// Client Credential Validation
// ============================================================================

/// Validate client credentials (client_id + client_secret).
pub async fn validate_oauth_client_credentials(
    store: &DocumentStore,
    client_id: &str,
    secret_hash: &str,
) -> Result<Option<OAuthClient>> {
    let Some(client) = get_oauth_client_by_client_id(store, client_id).await? else {
        return Ok(None);
    };

    if !client.active {
        return Ok(None);
    }

    let Some(secret) = get_oauth_secret_by_hash(store, secret_hash).await? else {
        return Ok(None);
    };

    if secret.oauth_client_id != client.id {
        return Ok(None);
    }

    let now = Timestamp::now();
    if !secret.is_valid(&now) {
        return Ok(None);
    }

    update_oauth_client_last_used(store, &client.id).await?;

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
        let result: Result<AccessScope, _> = "organization".parse();
        assert_eq!(result, Ok(AccessScope::Organization));

        let result: Result<AccessScope, _> = "personal".parse();
        assert_eq!(result, Ok(AccessScope::Personal));

        let result: Result<AccessScope, _> = "public".parse();
        assert_eq!(result, Ok(AccessScope::Public));

        let result: Result<AccessScope, _> = "invalid".parse();
        assert!(result.is_err());

        let result: Result<AccessScope, _> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_access_scope_from_str_case_insensitive() {
        let result: Result<AccessScope, _> = "ORGANIZATION".parse();
        assert_eq!(result, Ok(AccessScope::Organization));

        let result: Result<AccessScope, _> = "Personal".parse();
        assert_eq!(result, Ok(AccessScope::Personal));

        let result: Result<AccessScope, _> = "PUBLIC".parse();
        assert_eq!(result, Ok(AccessScope::Public));
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
    fn test_access_scope_display_roundtrip() {
        for scope in [
            AccessScope::Organization,
            AccessScope::Personal,
            AccessScope::Public,
        ] {
            let display_str = scope.to_string();
            let parsed: Result<AccessScope, _> = display_str.parse();
            assert_eq!(parsed, Ok(scope));
        }
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_basic() {
        let result: Result<TokenEndpointAuthMethod, _> = "client_secret_basic".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::ClientSecretBasic));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_post() {
        let result: Result<TokenEndpointAuthMethod, _> = "client_secret_post".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::ClientSecretPost));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_jwt() {
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
    fn test_token_endpoint_auth_method_rejects_unknown() {
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
    fn test_fapi_profile_as_str() {
        assert_eq!(FapiProfile::None.as_str(), "none");
        assert_eq!(FapiProfile::Fapi2Security.as_str(), "fapi2_security");
    }

    #[test]
    fn test_fapi_profile_default() {
        assert_eq!(FapiProfile::default(), FapiProfile::None);
    }

    #[test]
    fn test_fapi_profile_serde_roundtrip() {
        let json =
            serde_json::to_string(&FapiProfile::Fapi2Security).expect("FapiProfile serialization");
        assert_eq!(json, r#""fapi2_security""#);

        let parsed: FapiProfile = serde_json::from_str(&json).expect("FapiProfile deserialization");
        assert_eq!(parsed, FapiProfile::Fapi2Security);

        let none_json =
            serde_json::to_string(&FapiProfile::None).expect("FapiProfile::None serialization");
        assert_eq!(none_json, r#""none""#);
    }

    // ========================================================================
    // Test Helpers
    // ========================================================================

    use std::sync::Arc;

    use crate::crypto::document_crypto::PlaintextDocumentCrypto;
    use crate::db::Pool;

    async fn test_store() -> DocumentStore {
        let pool = Pool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");

        match &pool {
            Pool::Sqlite(p) => sqlx::migrate!("./migrations/sqlite")
                .run(p)
                .await
                .expect("Failed to run migrations"),
            Pool::Postgres(p) => sqlx::migrate!("./migrations/postgres")
                .run(p)
                .await
                .expect("Failed to run migrations"),
        }

        let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            Arc::new(PlaintextDocumentCrypto);
        DocumentStore::new(pool, crypto)
    }

    async fn create_client_and_secret(
        store: &DocumentStore,
    ) -> (OAuthClient, OAuthClientSecret, String) {
        let (client, _client_id) = create_oauth_client(
            store,
            &CreateOAuthClientParams {
                user_id: Some("test-user"),
                name: "Test App",
                description: None,
                application_type: OAuthClientType::Web,
                redirect_uris: &["https://example.com/callback".to_string()],
                access_scope: AccessScope::Public,
                org_id: None,
                resource_uris: &[],
                token_endpoint_auth_method: None,
                jwks: None,
                jwks_uri: None,
                fapi_profile: None,
                dpop_bound_access_tokens: None,
                grant_types: None,
                response_types: None,
                software_id: None,
                software_version: None,
                registration_source: RegistrationSource::Manual,
                registration_access_token_hash: None,
                registration_metadata: None,
            },
        )
        .await
        .expect("create client");

        let secret_hash = "hash_abc123";
        let secret =
            create_oauth_client_secret(store, &client.id, secret_hash, Some("test secret"), None)
                .await
                .expect("create secret");

        (client, secret, secret_hash.to_string())
    }

    // ========================================================================
    // Secret Retrieval Tests
    // ========================================================================

    #[tokio::test]
    async fn test_get_secret_by_id() {
        let store = test_store().await;
        let (_client, secret, _hash) = create_client_and_secret(&store).await;

        let fetched = get_oauth_client_secret_by_id(&store, &secret.id)
            .await
            .expect("db query");

        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.id, secret.id);
        assert_eq!(fetched.oauth_client_id, secret.oauth_client_id);
        assert_eq!(fetched.description.as_deref(), Some("test secret"));
    }

    #[tokio::test]
    async fn test_get_secret_by_id_not_found() {
        let store = test_store().await;

        let fetched = get_oauth_client_secret_by_id(&store, "nonexistent-id")
            .await
            .expect("db query");

        assert!(fetched.is_none());
    }

    // ========================================================================
    // Secret Revocation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_revoke_secret_sets_revoked_at() {
        let store = test_store().await;
        let (_client, secret, _hash) = create_client_and_secret(&store).await;

        assert!(secret.revoked_at.is_none());

        let updated = revoke_oauth_client_secret(&store, &secret.id)
            .await
            .expect("revoke");
        assert!(updated);

        let fetched = get_oauth_client_secret_by_id(&store, &secret.id)
            .await
            .expect("db query")
            .expect("secret exists");

        assert!(fetched.revoked_at.is_some());
    }

    // ========================================================================
    // is_valid Tests
    // ========================================================================

    #[tokio::test]
    async fn test_secret_is_valid_active() {
        let store = test_store().await;
        let (_client, secret, _hash) = create_client_and_secret(&store).await;

        let now = Timestamp::now();
        assert!(secret.is_valid(&now));
    }

    #[tokio::test]
    async fn test_secret_is_valid_revoked() {
        let store = test_store().await;
        let (_client, secret, _hash) = create_client_and_secret(&store).await;

        revoke_oauth_client_secret(&store, &secret.id)
            .await
            .expect("revoke");

        let fetched = get_oauth_client_secret_by_id(&store, &secret.id)
            .await
            .expect("db query")
            .expect("secret exists");

        let now = Timestamp::now();
        assert!(!fetched.is_valid(&now));
    }

    #[tokio::test]
    async fn test_secret_is_valid_expired() {
        let store = test_store().await;
        let (client, _secret, _hash) = create_client_and_secret(&store).await;

        let past = Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_hours(1))
            .expect("valid timestamp");

        let expired_secret = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_expired",
            Some("expired"),
            Some(past),
        )
        .await
        .expect("create expired secret");

        let now = Timestamp::now();
        assert!(!expired_secret.is_valid(&now));
    }

    // ========================================================================
    // Multiple Secrets Tests
    // ========================================================================

    #[tokio::test]
    async fn test_multiple_secrets_for_client() {
        let store = test_store().await;
        let (client, _secret1, _hash1) = create_client_and_secret(&store).await;

        let _secret2 = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_second",
            Some("second secret"),
            None,
        )
        .await
        .expect("create second secret");

        let secrets = get_oauth_client_secrets(&store, &client.id)
            .await
            .expect("list secrets");

        assert_eq!(secrets.len(), 2);
    }

    // ========================================================================
    // Credential Validation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_validate_credentials_with_either_secret() {
        let store = test_store().await;
        let (client, _secret1, hash1) = create_client_and_secret(&store).await;

        let hash2 = "hash_second_secret";
        let _secret2 = create_oauth_client_secret(&store, &client.id, hash2, Some("second"), None)
            .await
            .expect("create second secret");

        let result1 = validate_oauth_client_credentials(&store, &client.client_id, &hash1)
            .await
            .expect("validate with first");
        assert!(result1.is_some());

        let result2 = validate_oauth_client_credentials(&store, &client.client_id, hash2)
            .await
            .expect("validate with second");
        assert!(result2.is_some());
    }

    #[tokio::test]
    async fn test_validate_credentials_revoked_fails() {
        let store = test_store().await;
        let (client, secret, hash) = create_client_and_secret(&store).await;

        revoke_oauth_client_secret(&store, &secret.id)
            .await
            .expect("revoke");

        let result = validate_oauth_client_credentials(&store, &client.client_id, &hash)
            .await
            .expect("validate");

        assert!(result.is_none());
    }
}
