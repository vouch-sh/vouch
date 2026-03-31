// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pushed Authorization Request document type (RFC 9126).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::document_type::{DocumentType, IndexEntry};

/// A pushed authorization request (60-second lifetime).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushedAuthorizationRequestDoc {
    pub request_uri: String,
    pub client_id: String,
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
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
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
    /// RFC 9396: Rich authorization details (JSON array).
    #[serde(default)]
    pub authorization_details: Option<Value>,
    /// JARM: response_mode from the PAR request.
    #[serde(default)]
    pub response_mode: super::oauth::ResponseMode,
}

impl DocumentType for PushedAuthorizationRequestDoc {
    const DOC_TYPE: &'static str = "pushed_authorization_request";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![
            IndexEntry {
                field: "request_uri",
                value: self.request_uri.clone(),
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
