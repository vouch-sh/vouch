// SPDX-License-Identifier: BUSL-1.1
//! Session database operations.

use super::document_type::{Document, DocumentType};
use super::documents::session::SessionDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// Re-export SessionPurpose from documents module
pub use super::documents::session::SessionPurpose;

/// Session record.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub user_email: String,
    pub token_hash: String,
    pub authenticator_id: Option<String>,
    pub expires_at: Timestamp,
    pub created_at: Timestamp,
    pub session_type: SessionPurpose,
    /// RFC 9396: Rich authorization details (JSON array).
    pub authorization_details: Option<serde_json::Value>,
}

impl From<Document<SessionDoc>> for Session {
    fn from(doc: Document<SessionDoc>) -> Self {
        Self {
            id: doc.id,
            user_id: doc.data.user_id,
            user_email: doc.data.user_email,
            token_hash: doc.data.token_hash,
            authenticator_id: doc.data.authenticator_id,
            expires_at: doc.data.expires_at,
            created_at: doc.created_at,
            session_type: doc.data.session_type,
            authorization_details: doc.data.authorization_details,
        }
    }
}

/// Create a new session.
///
/// `authenticator_id` is optional for OIDC-authenticated users who haven't
/// registered a security key yet.
/// `user_email` is denormalized into the session document.
#[allow(clippy::too_many_arguments)]
pub async fn create_session(
    store: &DocumentStore,
    user_id: &str,
    user_email: &str,
    token_hash: &str,
    authenticator_id: Option<&str>,
    expires_at: Timestamp,
    session_type: SessionPurpose,
    authorization_details: Option<&serde_json::Value>,
) -> Result<String> {
    let doc = SessionDoc {
        user_id: user_id.to_string(),
        user_email: user_email.to_string(),
        token_hash: token_hash.to_string(),
        authenticator_id: authenticator_id.map(String::from),
        session_type,
        expires_at,
        authorization_details: authorization_details.cloned(),
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Get a session by token hash.
///
/// Only returns sessions that have not yet expired.
pub async fn get_session_by_token_hash(
    store: &DocumentStore,
    token_hash: &str,
) -> Result<Option<Session>> {
    let doc = store
        .find_one::<SessionDoc>("token_hash", token_hash)
        .await?;
    let now = Timestamp::now();
    match doc {
        Some(d) if d.data.expires_at > now => Ok(Some(Session::from(d))),
        _ => Ok(None),
    }
}

/// Delete a session by token hash.
pub async fn delete_session_by_token_hash(store: &DocumentStore, token_hash: &str) -> Result<bool> {
    let count = store
        .delete_by_index::<SessionDoc>("token_hash", token_hash)
        .await?;
    Ok(count > 0)
}

/// Delete expired sessions.
pub async fn delete_expired_sessions(store: &DocumentStore, _now: &str) -> Result<u64> {
    store.delete_expired(SessionDoc::DOC_TYPE).await
}

/// Delete OAuth access token sessions for a user.
///
/// Used by authorization code replay detection (RFC 6749 Section 10.5) to
/// revoke all access tokens that may have been issued from a compromised code.
pub async fn delete_oauth_sessions_for_user(store: &DocumentStore, user_id: &str) -> Result<u64> {
    // Find all sessions for this user, filter for OAuth access tokens, delete
    let sessions = store.find_all::<SessionDoc>("user_id", user_id).await?;
    let mut count: u64 = 0;
    for session in &sessions {
        if session.data.session_type == SessionPurpose::OAuthAccessToken {
            store.delete(&session.id).await?;
            count += 1;
        }
    }
    Ok(count)
}

/// Delete all sessions for a user (for immediate session invalidation).
pub async fn delete_sessions_for_user(store: &DocumentStore, user_id: &str) -> Result<u64> {
    store
        .delete_by_index::<SessionDoc>("user_id", user_id)
        .await
}

/// In-memory cache for session lookups by token hash.
///
/// Reduces DB load on the auth hot path. Entries expire after a
/// configurable TTL (default 30s). Eviction is inline: expired entries
/// are removed on `get` (per-key) and on `insert` (sweep when at
/// capacity). No background threads.
pub struct SessionCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
    max_capacity: u64,
}

struct CacheEntry {
    value: Option<Session>,
    inserted_at: Instant,
}

impl SessionCache {
    /// Create a new session cache.
    ///
    /// * `max_capacity` — maximum entries (e.g. 10 000)
    /// * `ttl_secs` — time-to-live per entry in seconds (e.g. 30)
    #[must_use]
    pub fn new(max_capacity: u64, ttl_secs: u64) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let cap = max_capacity.min(u32::MAX as u64) as usize;
        Self {
            entries: Mutex::new(HashMap::with_capacity(cap)),
            ttl: Duration::from_secs(ttl_secs),
            max_capacity,
        }
    }

    /// Get a cached session by token hash, or fetch from DB on miss.
    pub async fn get_session_by_token_hash(
        &self,
        store: &DocumentStore,
        token_hash: &str,
    ) -> Result<Option<Session>> {
        if let Some(cached) = self.get(token_hash) {
            return Ok(cached);
        }
        let result = get_session_by_token_hash(store, token_hash).await?;
        self.insert(token_hash.to_string(), result.clone());
        Ok(result)
    }

    /// Invalidate a cached session by token hash.
    pub fn invalidate(&self, token_hash: &str) {
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        map.remove(token_hash);
    }

    /// Invalidate all cached sessions (used when bulk-deleting).
    pub fn invalidate_all(&self) {
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        map.clear();
    }

    fn get(&self, key: &str) -> Option<Option<Session>> {
        let Ok(mut map) = self.entries.lock() else {
            return None;
        };
        let entry = map.get(key)?;
        if entry.inserted_at.elapsed() >= self.ttl {
            map.remove(key);
            return None;
        }
        Some(entry.value.clone())
    }

    fn insert(&self, key: String, value: Option<Session>) {
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        if map.len() as u64 >= self.max_capacity {
            let ttl = self.ttl;
            map.retain(|_, e| e.inserted_at.elapsed() < ttl);
        }
        map.insert(
            key,
            CacheEntry {
                value,
                inserted_at: Instant::now(),
            },
        );
    }
}
