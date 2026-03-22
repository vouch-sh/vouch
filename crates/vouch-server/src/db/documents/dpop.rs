// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DPoP nonce and JTI cache document types (RFC 9449).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// A DPoP nonce issued by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DpopNonceDoc {
    pub nonce: String,
    pub expires_at: Timestamp,
}

impl DocumentType for DpopNonceDoc {
    const DOC_TYPE: &'static str = "dpop_nonce";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![IndexEntry {
            field: "nonce",
            value: self.nonce.clone(),
        }]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}

/// A DPoP JTI (replay prevention cache entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DpopJtiDoc {
    pub jti: String,
    pub expires_at: Timestamp,
}

impl DocumentType for DpopJtiDoc {
    const DOC_TYPE: &'static str = "dpop_jti";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![IndexEntry {
            field: "jti",
            value: self.jti.clone(),
        }]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}
