// SPDX-License-Identifier: BUSL-1.1
//! Trusted JWT issuer document type (RFC 7523).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// A trusted external JWT issuer for client authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedJwtIssuerDoc {
    pub issuer: String,
    pub name: String,
    pub description: Option<String>,
    pub jwks_uri: String,
    pub jwks_cache: Option<serde_json::Value>,
    pub jwks_cached_at: Option<Timestamp>,
    pub subject_claim_mapping: String,
    /// JSON array of allowed scopes.
    pub allowed_scopes: Option<String>,
    pub max_token_lifetime_seconds: i32,
    pub enabled: bool,
}

impl DocumentType for TrustedJwtIssuerDoc {
    const DOC_TYPE: &'static str = "trusted_jwt_issuer";
    const CURRENT_VERSION: u32 = 2;

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![IndexEntry {
            field: "issuer",
            value: self.issuer.clone(),
        }]
    }

    /// Migrate from v1 where `jwks_cache` was stored as a JSON-encoded string.
    fn migrate(version: u32, mut data: serde_json::Value) -> anyhow::Result<Self> {
        if version < 2
            && let Some(obj) = data.as_object_mut()
            && let Some(serde_json::Value::String(s)) = obj.get("jwks_cache")
        {
            let parsed: serde_json::Value = serde_json::from_str(s)?;
            obj.insert("jwks_cache".to_owned(), parsed);
        }
        serde_json::from_value(data)
            .map_err(|e| anyhow::anyhow!("TrustedJwtIssuerDoc migration failed: {e}"))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn issuer_json(jwks_cache: serde_json::Value) -> serde_json::Value {
        json!({
            "issuer": "https://issuer.example.com",
            "name": "Issuer",
            "description": null,
            "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
            "jwks_cache": jwks_cache,
            "jwks_cached_at": null,
            "subject_claim_mapping": "sub",
            "allowed_scopes": null,
            "max_token_lifetime_seconds": 300,
            "enabled": true
        })
    }

    #[test]
    fn migrate_v1_string_jwks_cache() {
        let v1 = issuer_json(json!("{\"keys\":[{\"kty\":\"EC\",\"kid\":\"cached\"}]}"));

        let doc = TrustedJwtIssuerDoc::migrate(1, v1).expect("migration should succeed");

        assert_eq!(
            doc.jwks_cache
                .as_ref()
                .and_then(|v| v.get("keys"))
                .and_then(serde_json::Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(|v| v.get("kid"))
                .and_then(serde_json::Value::as_str),
            Some("cached"),
        );
    }

    #[test]
    fn migrate_v2_native_jwks_cache() {
        let v2 = issuer_json(json!({"keys":[{"kty":"EC","kid":"cached"}]}));

        let doc = TrustedJwtIssuerDoc::migrate(2, v2).expect("deserialization should succeed");

        assert_eq!(
            doc.jwks_cache
                .as_ref()
                .and_then(|v| v.get("keys"))
                .and_then(serde_json::Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(|v| v.get("kid"))
                .and_then(serde_json::Value::as_str),
            Some("cached"),
        );
    }
}
