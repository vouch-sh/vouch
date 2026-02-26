// SPDX-License-Identifier: BUSL-1.1
//! Authenticator (FIDO2 credential) document type.

use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// A registered FIDO2 authenticator (YubiKey).
///
/// Denormalized: includes `user_email` to eliminate the JOIN
/// previously done by `get_authenticator_with_user_by_credential_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorDoc {
    pub user_id: String,
    pub user_email: String,
    pub name: String,
    /// Base64-encoded FIDO2 credential ID.
    pub credential_id: String,
    /// Base64-encoded COSE public key.
    pub public_key: String,
    pub counter: i32,
    pub aaguid: Option<String>,
    /// Base64-encoded user handle for discoverable credentials.
    pub user_handle: Option<String>,
}

impl DocumentType for AuthenticatorDoc {
    const DOC_TYPE: &'static str = "authenticator";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![
            IndexEntry {
                field: "user_id",
                value: self.user_id.clone(),
            },
            IndexEntry {
                field: "credential_id",
                value: self.credential_id.clone(),
            },
        ]
    }
}
