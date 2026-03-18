// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authorization code document type (RFC 6749 Section 10.5).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::document_type::{DocumentType, IndexEntry};

/// An OAuth authorization code (single-use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCodeDoc {
    pub code_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
    /// RFC 9396: Rich authorization details (JSON array).
    #[serde(default)]
    pub authorization_details: Option<Value>,
}

impl DocumentType for AuthorizationCodeDoc {
    const DOC_TYPE: &'static str = "authorization_code";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![
            IndexEntry {
                field: "code_hash",
                value: self.code_hash.clone(),
            },
            IndexEntry {
                field: "client_id",
                value: self.client_id.clone(),
            },
            IndexEntry {
                field: "user_id",
                value: self.user_id.clone(),
            },
        ]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}
