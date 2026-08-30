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
/// Denormalized: includes `user_email`, `hardware_aaguid`, and `org_domain` to
/// avoid lookups (and to capture the session-time snapshot of the federation
/// claims) when issuing tokens.
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
    /// AAGUID of the authenticator that established this session.
    ///
    /// Captured at session creation so claims reflect "what was true when this
    /// session was created" rather than the user's current authenticator state.
    #[serde(default)]
    pub hardware_aaguid: Option<String>,
    /// Organization domain (`hd` claim) at session creation time.
    #[serde(default)]
    pub org_domain: Option<String>,
    /// Hash of the single-use grant code (RFC 6749 authorization code or
    /// RFC 8628 device code) that this session was issued from.
    ///
    /// `None` for grants with no single-use code (FIDO2, client_credentials,
    /// token exchange, browser login, enrollment). Populated only by the
    /// authorization-code and device-code grants so that replay detection
    /// (RFC 6749 §10.5) can revoke **only** the tokens issued from the
    /// replayed code instead of every session for the user.
    #[serde(default)]
    pub source_code_hash: Option<String>,
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
        if let Some(ref code_hash) = self.source_code_hash {
            entries.push(IndexEntry {
                field: "source_code_hash",
                value: code_hash.clone(),
            });
        }
        entries
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// Pre-deployment session records do not have `hardware_aaguid` or
    /// `org_domain`. They must deserialize as `None` so old sessions continue
    /// to work without a backfill migration.
    #[test]
    fn deserializes_legacy_session_without_new_fields() {
        let legacy = r#"{
            "user_id": "u-1",
            "user_email": "a@example.com",
            "token_hash": "h",
            "authenticator_id": "auth-1",
            "session_type": "oauth_access_token",
            "expires_at": "2099-01-01T00:00:00Z"
        }"#;
        let doc: SessionDoc = serde_json::from_str(legacy).expect("parse legacy session");
        assert!(doc.hardware_aaguid.is_none());
        assert!(doc.org_domain.is_none());
        assert!(doc.authorization_details.is_none());
    }

    /// The denormalized fields survive a serde roundtrip on new sessions.
    #[test]
    fn roundtrips_denormalized_fields() {
        let doc = SessionDoc {
            user_id: "u-1".to_string(),
            user_email: "a@example.com".to_string(),
            token_hash: "h".to_string(),
            authenticator_id: Some("auth-1".to_string()),
            session_type: SessionPurpose::OAuthAccessToken,
            expires_at: "2099-01-01T00:00:00Z".parse().expect("parse timestamp"),
            authorization_details: None,
            hardware_aaguid: Some("ee882879-721c-4913-9775-3dfcce97072a".to_string()),
            org_domain: Some("example.com".to_string()),
            source_code_hash: Some("code-hash-abc".to_string()),
        };
        let json = serde_json::to_string(&doc).expect("serialize");
        let back: SessionDoc = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            back.hardware_aaguid.as_deref(),
            Some("ee882879-721c-4913-9775-3dfcce97072a")
        );
        assert_eq!(back.org_domain.as_deref(), Some("example.com"));
        assert_eq!(back.source_code_hash.as_deref(), Some("code-hash-abc"));
    }

    /// The `source_code_hash` index is emitted only when the field is set, so
    /// sessions from grants without a single-use code (the common case) do not
    /// pay for an unused index row, while replay-targeted revocation can find
    /// the sessions issued from a specific code.
    #[test]
    fn index_entries_include_source_code_hash_only_when_set() {
        let mk = |code_hash: Option<String>| SessionDoc {
            user_id: "u-1".to_string(),
            user_email: "a@example.com".to_string(),
            token_hash: "h".to_string(),
            authenticator_id: None,
            session_type: SessionPurpose::OAuthAccessToken,
            expires_at: "2099-01-01T00:00:00Z".parse().expect("parse timestamp"),
            authorization_details: None,
            hardware_aaguid: None,
            org_domain: None,
            source_code_hash: code_hash,
        };
        let with_code = mk(Some("code-hash-abc".to_string()));
        let without_code = mk(None);

        let fields: Vec<&str> = with_code.index_entries().iter().map(|e| e.field).collect();
        assert!(
            fields.contains(&"source_code_hash"),
            "source_code_hash index must be present when set: {fields:?}"
        );
        let fields: Vec<&str> = without_code
            .index_entries()
            .iter()
            .map(|e| e.field)
            .collect();
        assert!(
            !fields.contains(&"source_code_hash"),
            "source_code_hash index must be absent when None: {fields:?}"
        );
    }
}
