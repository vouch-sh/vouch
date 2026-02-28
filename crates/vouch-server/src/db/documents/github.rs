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
}
