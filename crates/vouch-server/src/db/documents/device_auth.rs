// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device authorization grant document types (RFC 8628).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// Status of a device authorization request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceAuthStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "authorized")]
    Authorized,
    #[serde(rename = "denied")]
    Denied,
    #[serde(rename = "consumed")]
    Consumed,
}

/// A device authorization request (RFC 8628).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthRequestDoc {
    pub device_code_hash: String,
    pub user_code: String,
    pub status: DeviceAuthStatus,
    /// OAuth client_id that initiated this device authorization.
    #[serde(default)]
    pub client_id: Option<String>,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub authenticator_id: Option<String>,
    pub expires_at: Timestamp,
    pub interval_seconds: i32,
    pub last_poll_at: Option<Timestamp>,
    /// Timestamp when the device code was consumed (token issued).
    #[serde(default)]
    pub consumed_at: Option<Timestamp>,
}

impl DocumentType for DeviceAuthRequestDoc {
    const DOC_TYPE: &'static str = "device_auth_request";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let mut entries = vec![
            IndexEntry {
                field: "device_code_hash",
                value: self.device_code_hash.clone(),
            },
            IndexEntry {
                field: "user_code",
                value: self.user_code.clone(),
            },
        ];
        if let Some(ref uid) = self.user_id {
            entries.push(IndexEntry {
                field: "user_id",
                value: uid.clone(),
            });
        }
        entries
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}

/// An OIDC state for the device auth browser flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcStateDoc {
    pub state: String,
    pub device_auth_id: String,
    pub nonce: String,
    /// PKCE code_verifier (RFC 7636). Stored during authorization, sent during
    /// token exchange. Empty for non-OIDC flows (SAML).
    #[serde(default)]
    pub code_verifier: String,
    pub expires_at: Timestamp,
}

impl DocumentType for OidcStateDoc {
    const DOC_TYPE: &'static str = "oidc_state";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![IndexEntry {
            field: "state",
            value: self.state.clone(),
        }]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}
