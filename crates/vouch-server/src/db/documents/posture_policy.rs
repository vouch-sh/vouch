// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture policy document types.
//!
//! Two document types support posture policies:
//! - [`PostureConfigDoc`]: Per-org config tracking which preconfigured
//!   policy slugs are active (one per org).
//! - [`CustomPosturePolicyDoc`]: Admin-authored Dogwood policies (zero
//!   to many per org).

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

/// An admin-created custom posture policy (Dogwood/Cedar policy text).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPosturePolicyDoc {
    pub name: String,
    pub description: Option<String>,
    /// Dogwood policy text. Documents predating the field rename store it
    /// as `cel_expression`; the alias keeps those readable, and text that
    /// no longer validates denies until an admin re-authors it.
    #[serde(alias = "cel_expression")]
    pub policy_text: String,
    pub active: bool,
    pub org_id: String,
    /// The serialized builder `RuleSpec` this text was generated from,
    /// absent for hand-written policies. Advisory only: the engine never
    /// reads it, and a spec that no longer parses just reopens the policy
    /// in the text editor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_spec: Option<String>,
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

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// Documents stored under the older `cel_expression` field name must
    /// still deserialize.
    #[test]
    fn test_legacy_field_name_still_deserializes() {
        let json = r#"{
            "name": "old policy",
            "description": null,
            "cel_expression": "posture.disk_encryption_enabled == true",
            "active": true,
            "org_id": "org-1"
        }"#;
        let doc: CustomPosturePolicyDoc = serde_json::from_str(json).unwrap();
        assert_eq!(doc.policy_text, "posture.disk_encryption_enabled == true");
        assert_eq!(doc.builder_spec, None);
    }

    /// New documents serialize under the new field name.
    #[test]
    fn test_serializes_as_policy_text() {
        let doc = CustomPosturePolicyDoc {
            name: "p".to_string(),
            description: None,
            policy_text: "permit (principal, action, resource);".to_string(),
            active: false,
            org_id: "org-1".to_string(),
            builder_spec: None,
        };
        let json = serde_json::to_value(&doc).unwrap();
        assert!(json.get("policy_text").is_some());
        assert!(json.get("cel_expression").is_none());
        assert!(json.get("builder_spec").is_none());
    }
}
