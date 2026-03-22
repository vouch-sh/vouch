// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture policy document types.
//!
//! Two document types support posture policies:
//! - [`PostureConfigDoc`]: Per-org config tracking which preconfigured
//!   policy slugs are active (one per org).
//! - [`CustomPosturePolicyDoc`]: Admin-created custom CEL policies
//!   (zero to many per org).

use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// Per-org configuration for preconfigured posture policy activation.
///
/// Tracks which preconfigured policy slugs (defined in code) are active
/// for a given organization. There is at most one of these per org.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PostureConfigDoc {
    pub org_id: String,
    /// Slugs of active preconfigured policies (e.g., `["disk_encryption", "firewall"]`).
    pub active_slugs: Vec<String>,
}

impl DocumentType for PostureConfigDoc {
    const DOC_TYPE: &'static str = "posture_config";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![IndexEntry {
            field: "org_id",
            value: self.org_id.clone(),
        }]
    }
}

/// An admin-created custom posture policy with a CEL expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPosturePolicyDoc {
    pub name: String,
    pub description: Option<String>,
    pub cel_expression: String,
    pub active: bool,
    pub org_id: String,
}

impl DocumentType for CustomPosturePolicyDoc {
    const DOC_TYPE: &'static str = "custom_posture_policy";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![
            IndexEntry {
                field: "org_id",
                value: self.org_id.clone(),
            },
            IndexEntry {
                field: "active",
                value: self.active.to_string(),
            },
        ]
    }
}
