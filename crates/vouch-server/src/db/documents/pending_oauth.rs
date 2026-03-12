// SPDX-License-Identifier: BUSL-1.1
//! Pending OAuth authorization document type (RFC 6749, RFC 9700).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::document_type::{DocumentType, IndexEntry};

/// A pending OAuth authorization (pre-user-consent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOAuthAuthDoc {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
    /// RFC 8707 resource indicator.
    pub resource: Option<String>,
    /// RFC 9470 ACR values.
    pub acr_values: Option<String>,
    /// RFC 9470 max age.
    pub max_age: Option<i64>,
    /// RFC 9470 prompt.
    pub prompt: Option<String>,
    /// RFC 9449 DPoP key thumbprint.
    pub dpop_jkt: Option<String>,
    /// RFC 9396: Rich authorization details (JSON array).
    #[serde(default)]
    pub authorization_details: Option<Value>,
}

impl DocumentType for PendingOAuthAuthDoc {
    const DOC_TYPE: &'static str = "pending_oauth_auth";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![IndexEntry {
            field: "client_id",
            value: self.client_id.clone(),
        }]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}
