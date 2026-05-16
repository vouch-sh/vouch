// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Organization document type.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// An organization (tenant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationDoc {
    pub domain: String,
    pub name: Option<String>,
    pub created_by_user_id: Option<String>,
    /// Additional email domains owned by the organization.
    ///
    /// Each entry must complete DNS TXT ownership verification before it
    /// participates in login matching. Pending entries are stored on the
    /// document but are not indexed.
    #[serde(default)]
    pub additional_domains: Vec<AdditionalDomain>,
}

/// A secondary email domain claimed by an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdditionalDomain {
    /// Normalized lowercase ASCII domain.
    pub domain: String,
    /// Random hex token the admin must publish as `_vouch-verification.<domain>` TXT.
    pub verification_token: String,
    /// True once the TXT record has been observed by the verification flow.
    #[serde(default)]
    pub verified: bool,
    pub added_at: Timestamp,
    pub added_by_user_id: String,
    #[serde(default)]
    pub verified_at: Option<Timestamp>,
}

impl DocumentType for OrganizationDoc {
    const DOC_TYPE: &'static str = "organization";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let cap = self.additional_domains.len().saturating_add(1);
        let mut entries = Vec::with_capacity(cap);
        entries.push(IndexEntry {
            field: "domain",
            value: self.domain.clone(),
        });
        for ad in &self.additional_domains {
            if ad.verified {
                entries.push(IndexEntry {
                    field: "domain",
                    value: ad.domain.clone(),
                });
            }
        }
        entries
    }
}
