// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWKS cache document type for OAuth clients and trusted JWT issuers.
//!
//! Stores fetched JWKS separately from the parent document so that hourly
//! TTL refreshes do not bump the parent's `version`/`updated_at` columns.
//! The cache row is keyed by `"jwks_cache:{parent_id}"` to avoid colliding
//! with the parent row — `documents.id` is the sole PRIMARY KEY.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// Maximum age for stale JWKS before the stale-while-revalidate window closes (24 hours).
pub(crate) const JWKS_STALE_MAX_AGE_SECONDS: i64 = 86400;

/// How long after `cached_at` before the cleanup sweep evicts the row.
///
/// Set above `JWKS_STALE_MAX_AGE_SECONDS` so the cleanup loop never evicts a
/// row that the stale-while-revalidate path could still serve.
pub(crate) const JWKS_CACHE_EVICTION_AFTER_SECONDS: i64 = JWKS_STALE_MAX_AGE_SECONDS + 3600;

/// Cached JWKS for an OAuth client or trusted JWT issuer.
///
/// Stored as a separate document so refreshes don't mutate the parent doc.
/// The document id is `"jwks_cache:{parent_id}"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksCacheDoc {
    pub value: serde_json::Value,
    pub cached_at: Timestamp,
}

impl JwksCacheDoc {
    /// Returns `true` if the cache is younger than `ttl_seconds`.
    #[must_use]
    pub fn is_fresh(&self, ttl_seconds: i64) -> bool {
        self.age_seconds() < ttl_seconds
    }

    /// Returns `true` if the cache is within the maximum stale-while-revalidate window.
    #[must_use]
    pub fn is_within_stale_window(&self, max_age_seconds: i64) -> bool {
        self.age_seconds() < max_age_seconds
    }

    /// Age of the cache in seconds (saturating at 0).
    #[must_use]
    pub fn age_seconds(&self) -> i64 {
        Timestamp::now()
            .as_second()
            .saturating_sub(self.cached_at.as_second())
    }
}

impl DocumentType for JwksCacheDoc {
    const DOC_TYPE: &'static str = "jwks_cache";

    fn index_entries(&self) -> Vec<IndexEntry> {
        Vec::new()
    }

    fn expires_at(&self) -> Option<Timestamp> {
        self.cached_at
            .checked_add(jiff::SignedDuration::from_secs(
                JWKS_CACHE_EVICTION_AFTER_SECONDS,
            ))
            .ok()
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use jiff::Timestamp;

    #[test]
    fn test_expires_at_is_above_stale_max_age() {
        let now = Timestamp::now();
        let doc = JwksCacheDoc {
            value: serde_json::json!({"keys": []}),
            cached_at: now,
        };

        let expires = doc.expires_at().expect("expires_at must be Some");
        let diff = expires.as_second() - now.as_second();

        assert_eq!(
            diff, JWKS_CACHE_EVICTION_AFTER_SECONDS,
            "expires_at must be cached_at + JWKS_CACHE_EVICTION_AFTER_SECONDS"
        );
        assert!(
            diff > JWKS_STALE_MAX_AGE_SECONDS,
            "eviction threshold must exceed stale-while-revalidate window"
        );
    }

    #[test]
    fn test_is_fresh_when_young() {
        let doc = JwksCacheDoc {
            value: serde_json::json!({}),
            cached_at: Timestamp::now(),
        };
        assert!(doc.is_fresh(3600), "just-created cache must be fresh");
    }

    #[test]
    fn test_is_within_stale_window_when_recent() {
        let doc = JwksCacheDoc {
            value: serde_json::json!({}),
            cached_at: Timestamp::now(),
        };
        assert!(
            doc.is_within_stale_window(JWKS_STALE_MAX_AGE_SECONDS),
            "just-created cache must be within stale window"
        );
    }
}
