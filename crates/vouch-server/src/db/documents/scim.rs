// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM provisioning document types (RFC 7643/7644).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

// ============================================================================
// Document Types
// ============================================================================

/// A SCIM provisioning token.
///
/// `org_id` is `String` (required) because SCIM tokens are org-only entities.
/// The only producer is the org-admin SCIM-token endpoint, which always has
/// an `org_id` in scope. An org-less token has no valid use and cannot exist
/// in a correctly operating system. Making it required turns "forgot to scope"
/// into a compile error. DO NOT change to `Option<String>` for consistency
/// with non-SCIM types — see `UserDoc.org_id` comment for the asymmetry rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimTokenDoc {
    pub token_hash: String,
    pub org_id: String,
    pub description: Option<String>,
    pub expires_at: Option<Timestamp>,
    pub scope: String,
}

impl DocumentType for ScimTokenDoc {
    const DOC_TYPE: &'static str = "scim_token";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![
            IndexEntry {
                field: "token_hash",
                value: self.token_hash.clone(),
            },
            IndexEntry {
                field: "org_id",
                value: self.org_id.clone(),
            },
        ]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }
}

/// A SCIM group.
///
/// `org_id` is `String` (required) for the same reason as `ScimTokenDoc.org_id`:
/// groups are SCIM-only entities that can only be created by an org-scoped token.
/// DO NOT change to `Option<String>` — see `ScimTokenDoc` comment for rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupDoc {
    pub display_name: String,
    pub external_id: Option<String>,
    pub org_id: String,
}

impl DocumentType for ScimGroupDoc {
    const DOC_TYPE: &'static str = "scim_group";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let mut entries = vec![
            IndexEntry {
                field: "display_name",
                value: self.display_name.clone(),
            },
            IndexEntry {
                field: "org_id",
                value: self.org_id.clone(),
            },
        ];
        if let Some(ref ext_id) = self.external_id {
            entries.push(IndexEntry {
                field: "external_id",
                value: ext_id.clone(),
            });
        }
        entries
    }
}

/// A SCIM group membership (linking group to user).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupMemberDoc {
    pub group_id: String,
    pub user_id: String,
}

impl DocumentType for ScimGroupMemberDoc {
    const DOC_TYPE: &'static str = "scim_group_member";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![
            IndexEntry {
                field: "group_id",
                value: self.group_id.clone(),
            },
            IndexEntry {
                field: "user_id",
                value: self.user_id.clone(),
            },
        ]
    }
}
