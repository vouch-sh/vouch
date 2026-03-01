// SPDX-License-Identifier: BUSL-1.1
//! GitHub App installation document type.

use std::collections::HashMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// A GitHub App installation linked to an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubInstallationDoc {
    pub org_id: String,
    pub installation_id: i64,
    pub github_account_login: String,
    pub github_account_type: String,
    pub permissions: HashMap<String, String>,
    pub repository_selection: String,
    pub installed_at: Timestamp,
    pub installed_by_user_id: Option<String>,
    pub suspended_at: Option<Timestamp>,
    pub repositories: Option<Vec<String>>,
}

impl DocumentType for GitHubInstallationDoc {
    const DOC_TYPE: &'static str = "github_installation";
    const CURRENT_VERSION: u32 = 2;

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![
            IndexEntry {
                field: "org_id",
                value: self.org_id.clone(),
            },
            IndexEntry {
                field: "installation_id",
                value: self.installation_id.to_string(),
            },
        ]
    }

    /// Migrate from v1 where `permissions` and `repositories`
    /// were stored as JSON-encoded strings.
    fn migrate(version: u32, mut data: serde_json::Value) -> anyhow::Result<Self> {
        if version < 2
            && let Some(obj) = data.as_object_mut()
        {
            // permissions: String → HashMap<String, String>
            if let Some(serde_json::Value::String(s)) = obj.get("permissions") {
                let parsed: serde_json::Value = serde_json::from_str(s)?;
                obj.insert("permissions".to_owned(), parsed);
            }
            // repositories: Option<String> → Option<Vec<String>>
            if let Some(serde_json::Value::String(s)) = obj.get("repositories") {
                let parsed: serde_json::Value = serde_json::from_str(s)?;
                obj.insert("repositories".to_owned(), parsed);
            }
        }
        serde_json::from_value(data)
            .map_err(|e| anyhow::anyhow!("GitHubInstallationDoc migration failed: {e}"))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn installation_v1_json(perms: &str, repos: serde_json::Value) -> serde_json::Value {
        json!({
            "org_id": "org-1",
            "installation_id": 42,
            "github_account_login": "acme",
            "github_account_type": "Organization",
            "permissions": perms,
            "repository_selection": "all",
            "installed_at": "2025-01-01T00:00:00Z",
            "installed_by_user_id": null,
            "suspended_at": null,
            "repositories": repos
        })
    }

    #[test]
    fn migrate_v1_string_permissions_and_repositories() {
        let v1 = installation_v1_json(
            r#"{"admin":"read","metadata":"read"}"#,
            json!("[\"repo-a\",\"repo-b\"]"),
        );

        let doc = GitHubInstallationDoc::migrate(1, v1).expect("migration should succeed");
        assert_eq!(
            doc.permissions.get("admin").map(String::as_str),
            Some("read"),
        );
        assert_eq!(
            doc.permissions.get("metadata").map(String::as_str),
            Some("read"),
        );
        assert_eq!(
            doc.repositories,
            Some(vec!["repo-a".to_owned(), "repo-b".to_owned()])
        );
    }

    #[test]
    fn migrate_v1_null_repositories() {
        let v1 = installation_v1_json(r#"{"admin":"read"}"#, json!(null));

        let doc = GitHubInstallationDoc::migrate(1, v1).expect("migration should succeed");
        assert_eq!(
            doc.permissions.get("admin").map(String::as_str),
            Some("read"),
        );
        assert_eq!(doc.repositories, None);
    }

    #[test]
    fn migrate_v2_native_types_unchanged() {
        let v2 = json!({
            "org_id": "org-1",
            "installation_id": 42,
            "github_account_login": "acme",
            "github_account_type": "Organization",
            "permissions": {"admin": "read"},
            "repository_selection": "all",
            "installed_at": "2025-01-01T00:00:00Z",
            "installed_by_user_id": null,
            "suspended_at": null,
            "repositories": ["repo-a"]
        });

        let doc = GitHubInstallationDoc::migrate(2, v2).expect("deserialization should succeed");
        assert_eq!(
            doc.permissions.get("admin").map(String::as_str),
            Some("read"),
        );
        assert_eq!(doc.repositories, Some(vec!["repo-a".to_owned()]));
    }
}
