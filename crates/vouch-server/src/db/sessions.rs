// SPDX-License-Identifier: BUSL-1.1
//! Session database operations.

use super::document_type::{Document, DocumentType};
use super::documents::session::SessionDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Bumped on every invalidation; prevents stale DB results from
    /// being inserted after a concurrent revocation.
    generation: AtomicU64,
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
            generation: AtomicU64::new(0),
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
        // Snapshot generation before the async DB fetch so we can
        // detect invalidations that occurred during the await.
        let gen_before = self.generation.load(Ordering::SeqCst);
        let result = get_session_by_token_hash(store, token_hash).await?;
        self.insert_if_valid(token_hash.to_string(), result.clone(), gen_before);
        Ok(result)
    }

    /// Invalidate a cached session by token hash.
    pub fn invalidate(&self, token_hash: &str) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        map.remove(token_hash);
    }

    /// Invalidate cached sessions for a specific user.
    pub fn invalidate_for_user(&self, user_id: &str) {
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        map.retain(|_, entry| {
            let Some(session) = entry.value.as_ref() else {
                return true;
            };
            session.user_id != user_id
        });
    }

    /// Invalidate all cached sessions (used when bulk-deleting).
    pub fn invalidate_all(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
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

    /// Expose generation for testing the TOCTOU guard.
    #[cfg(test)]
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Insert a value only if no invalidation has occurred since
    /// `expected_gen` was captured. The generation is re-checked under
    /// the lock so no invalidation can race between the check and the
    /// actual map write.
    fn insert_if_valid(&self, key: String, value: Option<Session>, expected_gen: u64) {
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        // Relaxed is safe: Mutex::lock() provides the acquire barrier.
        if self.generation.load(Ordering::Relaxed) != expected_gen {
            return;
        }
        if self.max_capacity == 0 {
            return;
        }
        if map.len() as u64 >= self.max_capacity {
            let ttl = self.ttl;
            map.retain(|_, e| e.inserted_at.elapsed() < ttl);
            if map.len() as u64 >= self.max_capacity {
                let oldest_key = map
                    .iter()
                    .min_by_key(|(_, entry)| entry.inserted_at)
                    .map(|(k, _)| k.clone());
                if let Some(oldest_key) = oldest_key {
                    map.remove(&oldest_key);
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_session(token_hash: &str) -> Session {
        Session {
            id: "sess-1".to_string(),
            user_id: "user-1".to_string(),
            user_email: "test@example.com".to_string(),
            token_hash: token_hash.to_string(),
            authenticator_id: None,
            expires_at: Timestamp::now(),
            created_at: Timestamp::now(),
            session_type: SessionPurpose::OAuthAccessToken,
            authorization_details: None,
        }
    }

    #[test]
    fn cache_hit_returns_cached_value() {
        let cache = SessionCache::new(100, 30);
        let generation = cache.generation();
        cache.insert_if_valid(
            "hash-a".to_string(),
            Some(fake_session("hash-a")),
            generation,
        );
        let result = cache.get("hash-a");
        assert!(result.is_some());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn cache_miss_returns_none() {
        let cache = SessionCache::new(100, 30);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn negative_cache_entry_returns_none_session() {
        let cache = SessionCache::new(100, 30);
        let generation = cache.generation();
        cache.insert_if_valid("hash-b".to_string(), None, generation);
        let result = cache.get("hash-b");
        assert!(result.is_some(), "cache entry should exist");
        assert!(result.unwrap().is_none(), "cached value should be None");
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache = SessionCache::new(100, 30);
        let generation = cache.generation();
        cache.insert_if_valid(
            "hash-c".to_string(),
            Some(fake_session("hash-c")),
            generation,
        );
        cache.invalidate("hash-c");
        assert!(cache.get("hash-c").is_none());
    }

    #[test]
    fn invalidate_all_clears_cache() {
        let cache = SessionCache::new(100, 30);
        let generation = cache.generation();
        cache.insert_if_valid(
            "hash-d".to_string(),
            Some(fake_session("hash-d")),
            generation,
        );
        cache.insert_if_valid(
            "hash-e".to_string(),
            Some(fake_session("hash-e")),
            generation,
        );
        cache.invalidate_all();
        assert!(cache.get("hash-d").is_none());
        assert!(cache.get("hash-e").is_none());
    }

    /// Regression test: simulates the TOCTOU race where an invalidation
    /// occurs between the generation snapshot and the insert. The stale
    /// session must NOT be written to the cache.
    #[test]
    fn insert_after_invalidate_is_rejected() {
        let cache = SessionCache::new(100, 30);
        let gen_before = cache.generation();

        // Simulate: invalidation happens while DB fetch is in flight
        cache.invalidate("hash-f");

        // Attempt to insert with the stale generation
        cache.insert_if_valid(
            "hash-f".to_string(),
            Some(fake_session("hash-f")),
            gen_before,
        );

        assert!(
            cache.get("hash-f").is_none(),
            "revoked session must not be cached"
        );
    }

    /// Same as above but with `invalidate_all`.
    #[test]
    fn insert_after_invalidate_all_is_rejected() {
        let cache = SessionCache::new(100, 30);

        // Populate a valid entry first
        let generation = cache.generation();
        cache.insert_if_valid(
            "hash-g".to_string(),
            Some(fake_session("hash-g")),
            generation,
        );

        // Snapshot generation, then invalidate_all
        let gen_before = cache.generation();
        cache.invalidate_all();

        // Attempt to insert with the stale generation
        cache.insert_if_valid(
            "hash-g".to_string(),
            Some(fake_session("hash-g")),
            gen_before,
        );

        assert!(
            cache.get("hash-g").is_none(),
            "revoked session must not be cached after invalidate_all"
        );
    }

    /// Insertions with a current (valid) generation after invalidation
    /// should succeed — only stale generations are blocked.
    #[test]
    fn insert_with_fresh_generation_after_invalidate_succeeds() {
        let cache = SessionCache::new(100, 30);
        cache.invalidate("hash-h");

        let fresh_gen = cache.generation();
        cache.insert_if_valid(
            "hash-h".to_string(),
            Some(fake_session("hash-h")),
            fresh_gen,
        );

        let result = cache.get("hash-h");
        assert!(result.is_some());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn ttl_expiry_evicts_entry() {
        let cache = SessionCache::new(100, 0); // 0-second TTL
        let generation = cache.generation();
        cache.insert_if_valid(
            "hash-i".to_string(),
            Some(fake_session("hash-i")),
            generation,
        );
        // With a 0s TTL the entry is immediately expired
        assert!(cache.get("hash-i").is_none());
    }

    #[test]
    fn zero_capacity_cache_is_noop() {
        let cache = SessionCache::new(0, 30);
        let generation = cache.generation();
        cache.insert_if_valid(
            "hash-j".to_string(),
            Some(fake_session("hash-j")),
            generation,
        );
        assert!(cache.get("hash-j").is_none());
    }

    #[test]
    fn eviction_at_capacity() {
        let cache = SessionCache::new(1, 30);
        let generation = cache.generation();
        cache.insert_if_valid("first".to_string(), Some(fake_session("first")), generation);
        let generation = cache.generation();
        cache.insert_if_valid(
            "second".to_string(),
            Some(fake_session("second")),
            generation,
        );
        // "first" should have been evicted to make room for "second"
        assert!(cache.get("first").is_none());
        assert!(cache.get("second").is_some());
    }
}
