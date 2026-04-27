// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Trusted JWT issuer document type (RFC 7523).

use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// A trusted external JWT issuer for client authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedJwtIssuerDoc {
    pub issuer: String,
    pub name: String,
    pub description: Option<String>,
    pub jwks_uri: String,
    pub subject_claim_mapping: String,
    /// JSON array of allowed scopes.
    pub allowed_scopes: Option<String>,
    pub max_token_lifetime_seconds: i32,
    pub enabled: bool,
    /// Organization this issuer is scoped to. `None` means globally trusted (all orgs).
    pub org_id: Option<String>,
}

impl DocumentType for TrustedJwtIssuerDoc {
    const DOC_TYPE: &'static str = "trusted_jwt_issuer";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let mut entries = vec![IndexEntry {
            field: "issuer",
            value: self.issuer.clone(),
        }];
        if let Some(ref org_id) = self.org_id {
            entries.push(IndexEntry {
                field: "org_id",
                value: org_id.clone(),
            });
        }
        entries
    }
}
