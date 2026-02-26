// SPDX-License-Identifier: BUSL-1.1
//! Authorization code document type (RFC 6749 Section 10.5).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// An OAuth authorization code (single-use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCodeDoc {
    pub code_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
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
