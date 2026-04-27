// SPDX-License-Identifier: Apache-2.0 OR MIT
//! User document type.

use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// A Vouch user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDoc {
    pub email: String,
    pub name: Option<String>,
    /// Optional by design (multi-source). Browser OIDC enrollment without a domain claim,
    /// GitHub OAuth, and the certification cert-test path all legitimately create users with
    /// `org_id = None`. SCIM creation always supplies a value. Do NOT promote to `String`
    /// for "consistency" with `ScimTokenDoc.org_id` — the asymmetry is the multi-tenant model.
    pub org_id: Option<String>,
    pub is_org_admin: bool,
    #[serde(default = "default_active")]
    pub active: bool,
    pub external_id: Option<String>,
    pub github_id: Option<i64>,
    pub github_login: Option<String>,
    pub github_refresh_token: Option<String>,
}

fn default_active() -> bool {
    true
}

impl DocumentType for UserDoc {
    const DOC_TYPE: &'static str = "user";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let mut entries = vec![IndexEntry {
            field: "email",
            value: self.email.clone(),
        }];
        if let Some(ref org_id) = self.org_id {
            entries.push(IndexEntry {
                field: "org_id",
                value: org_id.clone(),
            });
        }
        if let Some(ref external_id) = self.external_id {
            entries.push(IndexEntry {
                field: "external_id",
                value: external_id.clone(),
            });
        }
        if let Some(ref github_login) = self.github_login {
            entries.push(IndexEntry {
                field: "github_login",
                value: github_login.clone(),
            });
        }
        entries
    }
}
