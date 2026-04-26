// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Trusted JWT issuer database operations (RFC 7523).

use super::document_type::Document;
use super::documents::jwt_issuer::{JwksCache, TrustedJwtIssuerDoc};
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

/// Default subject claim mapping for new trusted issuers.
pub const DEFAULT_SUBJECT_CLAIM_MAPPING: &str = "email";

/// Default maximum token lifetime in seconds.
pub const DEFAULT_MAX_TOKEN_LIFETIME_SECONDS: i32 = 3600;

/// Trusted JWT issuer record (RFC 7523).
#[derive(Debug)]
pub struct TrustedJwtIssuer {
    pub id: String,
    pub issuer: String,
    pub name: String,
    pub description: Option<String>,
    pub jwks_uri: String,
    pub jwks_cache: Option<JwksCache>,
    pub subject_claim_mapping: String,
    pub allowed_scopes: Option<String>,
    pub max_token_lifetime_seconds: i32,
    pub enabled: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<Document<TrustedJwtIssuerDoc>> for TrustedJwtIssuer {
    fn from(doc: Document<TrustedJwtIssuerDoc>) -> Self {
        Self {
            id: doc.id,
            issuer: doc.data.issuer,
            name: doc.data.name,
            description: doc.data.description,
            jwks_uri: doc.data.jwks_uri,
            jwks_cache: doc.data.jwks_cache,
            subject_claim_mapping: doc.data.subject_claim_mapping,
            allowed_scopes: doc.data.allowed_scopes,
            max_token_lifetime_seconds: doc.data.max_token_lifetime_seconds,
            enabled: doc.data.enabled,
            created_at: doc.created_at,
            updated_at: doc.updated_at,
        }
    }
}

/// Create a new trusted JWT issuer.
#[expect(
    clippy::too_many_arguments,
    reason = "JWT issuer record requires all configuration fields"
)]
pub async fn create_trusted_jwt_issuer(
    store: &DocumentStore,
    issuer: &str,
    name: &str,
    description: Option<&str>,
    jwks_uri: &str,
    subject_claim_mapping: Option<&str>,
    allowed_scopes: Option<&str>,
    max_token_lifetime_seconds: Option<i32>,
) -> Result<TrustedJwtIssuer> {
    let mapping = subject_claim_mapping.unwrap_or(DEFAULT_SUBJECT_CLAIM_MAPPING);
    let max_lifetime = max_token_lifetime_seconds.unwrap_or(DEFAULT_MAX_TOKEN_LIFETIME_SECONDS);

    let doc = TrustedJwtIssuerDoc {
        issuer: issuer.to_string(),
        name: name.to_string(),
        description: description.map(String::from),
        jwks_uri: jwks_uri.to_string(),
        jwks_cache: None,
        subject_claim_mapping: mapping.to_string(),
        allowed_scopes: allowed_scopes.map(String::from),
        max_token_lifetime_seconds: max_lifetime,
        enabled: true,
    };
    let result = store.insert(&doc).await?;
    Ok(TrustedJwtIssuer::from(result))
}

/// Get a trusted JWT issuer by its issuer URL.
pub async fn get_trusted_jwt_issuer_by_issuer(
    store: &DocumentStore,
    issuer: &str,
) -> Result<Option<TrustedJwtIssuer>> {
    let doc = store
        .find_one::<TrustedJwtIssuerDoc>("issuer", issuer)
        .await?;
    Ok(doc.map(TrustedJwtIssuer::from))
}

/// List all trusted JWT issuers.
pub async fn list_trusted_jwt_issuers(store: &DocumentStore) -> Result<Vec<TrustedJwtIssuer>> {
    let docs = store.list_all::<TrustedJwtIssuerDoc>().await?;
    Ok(docs.into_iter().map(TrustedJwtIssuer::from).collect())
}

/// Update a trusted JWT issuer.
#[expect(
    clippy::too_many_arguments,
    reason = "JWT issuer record requires all configuration fields"
)]
pub async fn update_trusted_jwt_issuer(
    store: &DocumentStore,
    id: &str,
    name: &str,
    description: Option<&str>,
    jwks_uri: &str,
    subject_claim_mapping: &str,
    allowed_scopes: Option<&str>,
    max_token_lifetime_seconds: i32,
    enabled: bool,
) -> Result<()> {
    if let Some(doc) = store.get::<TrustedJwtIssuerDoc>(id).await? {
        let mut data = doc.data;
        data.name = name.to_string();
        data.description = description.map(String::from);
        data.jwks_uri = jwks_uri.to_string();
        data.subject_claim_mapping = subject_claim_mapping.to_string();
        data.allowed_scopes = allowed_scopes.map(String::from);
        data.max_token_lifetime_seconds = max_token_lifetime_seconds;
        data.enabled = enabled;
        store.update(id, &data).await?;
    }
    Ok(())
}

/// Delete a trusted JWT issuer.
pub async fn delete_trusted_jwt_issuer(store: &DocumentStore, id: &str) -> Result<u64> {
    store.delete(id).await?;
    Ok(1)
}

/// Update the cached JWKS for a trusted issuer.
pub async fn update_issuer_jwks_cache(
    store: &DocumentStore,
    id: &str,
    jwks_value: &serde_json::Value,
) -> Result<()> {
    if let Some(doc) = store.get::<TrustedJwtIssuerDoc>(id).await? {
        let mut data = doc.data;
        data.jwks_cache = Some(JwksCache {
            value: jwks_value.clone(),
            cached_at: Timestamp::now(),
        });
        store.update(id, &data).await?;
    }
    Ok(())
}
