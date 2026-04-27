// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM provisioning document types (RFC 7643/7644).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

// ============================================================================
// Document Types
// ============================================================================

/// A SCIM provisioning token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimTokenDoc {
    pub token_hash: String,
    pub org_id: Option<String>,
    pub description: Option<String>,
    pub expires_at: Option<Timestamp>,
    pub scope: String,
}

impl DocumentType for ScimTokenDoc {
    const DOC_TYPE: &'static str = "scim_token";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let mut entries = vec![IndexEntry {
            field: "token_hash",
            value: self.token_hash.clone(),
        }];
        if let Some(ref org_id) = self.org_id {
            entries.push(IndexEntry {
                field: "org_id",
                value: org_id.clone(),
            });
        }
        entries
    }

    fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }
}

/// A SCIM group. Always belongs to exactly one organization (the
/// org of the SCIM token that created it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupDoc {
    pub org_id: String,
    pub display_name: String,
    pub external_id: Option<String>,
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
