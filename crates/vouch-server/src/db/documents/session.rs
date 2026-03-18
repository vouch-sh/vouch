// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session document type.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::document_type::{DocumentType, IndexEntry};

/// Session purpose / grant type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionPurpose {
    #[serde(rename = "oauth_access_token")]
    OAuthAccessToken,
    /// Machine-to-machine access token issued via `client_credentials` grant.
    #[serde(rename = "m2m_access_token")]
    M2MAccessToken,
}

/// An authenticated session (DPoP-bound access token).
///
/// Denormalized: includes `user_email` to avoid a JOIN back to
/// the user document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDoc {
    pub user_id: String,
    pub user_email: String,
    pub token_hash: String,
    pub authenticator_id: Option<String>,
    pub session_type: SessionPurpose,
    pub expires_at: Timestamp,
    /// RFC 9396: Rich authorization details (JSON array).
    #[serde(default)]
    pub authorization_details: Option<Value>,
}

impl DocumentType for SessionDoc {
    const DOC_TYPE: &'static str = "session";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let mut entries = vec![
            IndexEntry {
                field: "user_id",
                value: self.user_id.clone(),
            },
            IndexEntry {
                field: "token_hash",
                value: self.token_hash.clone(),
            },
        ];
        if let Some(ref auth_id) = self.authenticator_id {
            entries.push(IndexEntry {
                field: "authenticator_id",
                value: auth_id.clone(),
            });
        }
        entries
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}
