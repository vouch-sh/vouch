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
    /// Whether the approving browser session proved possession of the key
    /// with a WebAuthn ceremony. The device-code grant copies this onto the
    /// issued token's `hardware_verified` claim, so an approval that never
    /// exercised the authenticator cannot mint a token asserting it did.
    /// Absent from documents written by an older server during a rolling
    /// deploy; the default treats those as unverified.
    #[serde(default)]
    pub hardware_verified: bool,
    /// Unix seconds of the WebAuthn ceremony that approved this request —
    /// the `auth_time` the device-code grant stamps on the issued token.
    /// `Some` whenever `hardware_verified` and this version wrote the row;
    /// `None` on rows predating the field, which the freshness gate on key
    /// deletion reads as epoch (step-up required).
    #[serde(default)]
    pub auth_time: Option<i64>,
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
        // Emit authenticator_id so delete_authenticator's update_by_index
        // can locate and clear this reference during cascade delete (#543).
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

/// An OIDC state for the device auth browser flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OidcStateDoc {
    pub state: String,
    pub device_auth_id: String,
    pub nonce: String,
    /// PKCE code_verifier (RFC 7636). Stored during authorization, sent during
    /// token exchange. Empty for non-OIDC flows (SAML).
    #[serde(default)]
    pub code_verifier: String,
    pub expires_at: Timestamp,
    /// Slug of the OIDC provider that initiated this flow.
    /// Empty string for SAML flows or pre-multi-provider state docs (rolling deploy compat).
    #[serde(default)]
    pub provider_id: String,
    /// Timestamp at which the state was atomically consumed (single-use).
    /// Set by `try_consume_oidc_state`. A state with `consumed_at: Some(_)`
    /// is treated as already-used for replay protection.
    #[serde(default)]
    pub consumed_at: Option<Timestamp>,
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
