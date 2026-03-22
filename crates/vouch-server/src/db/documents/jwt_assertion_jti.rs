// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWT assertion JTI replay cache document type (RFC 7523).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// A JWT assertion JTI (prevents replay attacks).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JwtAssertionJtiDoc {
    pub jti: String,
    pub client_id: String,
    pub expires_at: Timestamp,
}

impl DocumentType for JwtAssertionJtiDoc {
    const DOC_TYPE: &'static str = "jwt_assertion_jti";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![
            IndexEntry {
                field: "jti",
                value: self.jti.clone(),
            },
            IndexEntry {
                field: "client_id",
                value: self.client_id.clone(),
            },
        ]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}
