// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Trusted JWT issuer document type (RFC 7523).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// Cached JWKS fetched from a trusted issuer's `jwks_uri`.
///
/// Grouping the value with its fetch timestamp makes the
/// "present together or absent together" invariant compiler-enforced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksCache {
    pub value: serde_json::Value,
    pub cached_at: Timestamp,
}

impl JwksCache {
    /// Returns true if the cache is younger than `ttl_seconds`.
    #[must_use]
    pub fn is_fresh(&self, ttl_seconds: i64) -> bool {
        self.age_seconds() < ttl_seconds
    }

    /// Returns true if the cache is within the maximum stale window.
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

/// A trusted external JWT issuer for client authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedJwtIssuerDoc {
    pub issuer: String,
    pub name: String,
    pub description: Option<String>,
    pub jwks_uri: String,
    #[serde(default)]
    pub jwks_cache: Option<JwksCache>,
    pub subject_claim_mapping: String,
    /// JSON array of allowed scopes.
    pub allowed_scopes: Option<String>,
    pub max_token_lifetime_seconds: i32,
    pub enabled: bool,
}

impl DocumentType for TrustedJwtIssuerDoc {
    const DOC_TYPE: &'static str = "trusted_jwt_issuer";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![IndexEntry {
            field: "issuer",
            value: self.issuer.clone(),
        }]
    }
}
