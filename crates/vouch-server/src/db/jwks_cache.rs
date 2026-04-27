// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWKS cache database operations.
//!
//! Provides get/upsert/delete helpers keyed by the parent document's id
//! (OAuth client or trusted JWT issuer). The cache id is namespaced as
//! `"jwks_cache:{parent_id}"` because `documents.id` is the sole PRIMARY KEY
//! and parent rows already occupy their own UUIDv7 ids.

use super::document_type::DocumentType;
use super::documents::jwks_cache::JwksCacheDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

/// Build the namespaced document id for a JWKS cache row.
pub(super) fn cache_id(parent_id: &str) -> String {
    format!("jwks_cache:{parent_id}")
}

/// Retrieve the cached JWKS for a parent document, if present.
///
/// Returns `None` if no cache row exists.
pub async fn get_jwks_cache(
    store: &DocumentStore,
    parent_id: &str,
) -> Result<Option<JwksCacheDoc>> {
    let id = cache_id(parent_id);
    let doc = store.get::<JwksCacheDoc>(&id).await?;
    Ok(doc.map(|d| d.data))
}

/// Insert or update the JWKS cache for a parent document.
///
/// Uses `DocumentStore::upsert` for last-write-wins idempotent semantics.
pub async fn upsert_jwks_cache(
    store: &DocumentStore,
    parent_id: &str,
    jwks_value: &serde_json::Value,
) -> Result<()> {
    let id = cache_id(parent_id);
    let doc = JwksCacheDoc {
        value: jwks_value.clone(),
        cached_at: Timestamp::now(),
    };
    store.upsert(&id, &doc).await
}

/// Delete the JWKS cache for a parent document (idempotent).
///
/// Returns `Ok(())` whether or not the row existed.
pub async fn delete_jwks_cache(store: &DocumentStore, parent_id: &str) -> Result<()> {
    let id = cache_id(parent_id);
    store.delete(&id).await
}

/// Delete all expired JWKS cache rows (called by the background cleanup loop).
pub async fn delete_expired_jwks_caches(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(JwksCacheDoc::DOC_TYPE).await
}
