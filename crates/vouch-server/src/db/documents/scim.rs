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
        // `displayName` is `caseExact: false` per RFC 7643 §2.2 (the default;
        // not overridden in the §4.2 group schema), so the blind-index value
        // is stored lowercased to make `eq` lookups case-insensitive. Unlike
        // the `email`/`userName` indexes — which are ASCII-constrained and
        // canonicalized through the `Email` type — `displayName` is a
        // free-form Unicode string (RFC 7643 §2.3.1), so `to_lowercase`
        // (full Unicode case-folding) is used rather than `to_ascii_lowercase`,
        // which would leave non-ASCII letters (É, Ü, Ñ) unfolded and make
        // `eq` case-sensitive for them. The document body (`display_name`
        // field below) keeps its original casing for display; only the
        // index row is normalized.
        //
        // Legacy rows written before this used `to_ascii_lowercase`; a
        // non-ASCII group from that era is not found by a recased non-ASCII
        // `eq` until the group is next written — the indexed path is
        // authoritative (see `try_indexed_group_lookup`). A re-index
        // migration is infeasible here: production index values are
        // HMAC-hashed and document bodies are encrypted at rest, so neither
        // can be recomputed in SQL. The lazy heal-on-write matches the
        // established precedent for this index
        // (`test_scim_filter_group_display_name_eq_is_indexed_not_rescanned`).
        let mut entries = vec![
            IndexEntry {
                field: "display_name",
                value: self.display_name.to_lowercase(),
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
pub(crate) struct ScimGroupMemberDoc {
    pub(crate) group_id: String,
    pub(crate) user_id: String,
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
