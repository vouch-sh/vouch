// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticator (FIDO2 credential) document type.

use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// A registered FIDO2 authenticator (YubiKey).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorDoc {
    pub user_id: String,
    /// Unread, and written empty. Kept because servers on earlier releases
    /// deserialize this key as required, and old and new servers read the
    /// same rows during a rolling refresh.
    #[serde(default)]
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
    /// Whether the attestation was cryptographically verified via x5c chain.
    #[serde(default)]
    pub attestation_verified: bool,
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

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only serialization of a literal")]
mod tests {
    use super::AuthenticatorDoc;

    #[test]
    fn serialized_authenticator_keeps_user_email_key() {
        let doc = AuthenticatorDoc {
            user_id: "u".to_string(),
            user_email: String::new(),
            name: "key".to_string(),
            credential_id: "c".to_string(),
            public_key: "p".to_string(),
            counter: 0,
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        };
        let value = serde_json::to_value(&doc).expect("serialize");
        assert!(
            value.get("user_email").is_some(),
            "earlier releases deserialize user_email as required: {value}"
        );
    }
}
