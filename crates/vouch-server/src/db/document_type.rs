// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Document type trait and generic document wrapper.
//!
//! Every domain-specific document type (users, sessions, authenticators, etc.)
//! implements [`DocumentType`] to declare its storage metadata: document type
//! string, index entries for blind equality lookups, expiration behavior, and
//! schema version for lazy migration.

use jiff::Timestamp;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// A searchable index entry on a document.
///
/// Each entry becomes a row in `document_indexes` with the field name and
/// a (possibly HMAC-hashed) value.
pub struct IndexEntry {
    /// The index field name (e.g., "email", "token_hash", "user_id").
    pub field: &'static str,
    /// The plaintext value to index. The [`DocumentStore`] will HMAC-hash
    /// this before storage in production mode.
    pub value: String,
}

/// Trait implemented by every document type stored in the document store.
///
/// # Required
///
/// - [`DOC_TYPE`](Self::DOC_TYPE): Unique string identifier stored in the
///   `doc_type` column.
/// - [`index_entries`](Self::index_entries): Searchable fields for this
///   document.
///
/// # Optional
///
/// - [`CURRENT_VERSION`](Self::CURRENT_VERSION): Schema version (default 1).
///   Bump when making breaking serde changes.
/// - [`expires_at`](Self::expires_at): Return an ISO 8601 timestamp if this
///   document should be automatically cleaned up.
/// - [`migrate`](Self::migrate): Transform old schema versions to current.
pub trait DocumentType: Serialize + DeserializeOwned + Send + Sync {
    /// Unique document type identifier (e.g., `"user"`, `"session"`).
    const DOC_TYPE: &'static str;

    /// Current schema version. Increment for breaking serde changes.
    const CURRENT_VERSION: u32 = 1;

    /// Index entries for blind equality lookups.
    fn index_entries(&self) -> Vec<IndexEntry>;

    /// Optional expiration timestamp.
    ///
    /// Documents with an expiration will be cleaned up by the background
    /// cleanup task.
    fn expires_at(&self) -> Option<Timestamp> {
        None
    }

    /// Migrate a document from an older schema version.
    ///
    /// The default implementation uses serde defaults (handles additive
    /// changes). Override for breaking changes that require transformation.
    ///
    /// # Errors
    ///
    /// Returns an error if the migration or deserialization fails.
    fn migrate(_version: u32, data: serde_json::Value) -> anyhow::Result<Self> {
        serde_json::from_value(data).map_err(|e| anyhow::anyhow!("document migration failed: {e}"))
    }
}

/// A document retrieved from the store, wrapping the typed data with metadata.
#[derive(Debug, Clone)]
pub struct Document<T> {
    /// UUID v7 document ID.
    pub id: String,
    /// The deserialized document data.
    pub data: T,
    /// Creation timestamp.
    pub created_at: Timestamp,
    /// Last-update timestamp.
    pub updated_at: Timestamp,
    /// Optimistic concurrency version. Incremented on every update.
    pub version: i32,
    /// Lightweight last-used timestamp (column-level, no encrypt/decrypt).
    pub last_used_at: Option<Timestamp>,
}
