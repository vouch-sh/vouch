// SPDX-License-Identifier: BUSL-1.1
//! Credential-related document types (enrollment, SSH revocation).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// An enrollment session for first-time user setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentSessionDoc {
    pub user_id: String,
    pub user_email: String,
    pub session_token_hash: String,
    pub device_auth_id: Option<String>,
    pub expires_at: Timestamp,
}

impl DocumentType for EnrollmentSessionDoc {
    const DOC_TYPE: &'static str = "enrollment_session";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![
            IndexEntry {
                field: "user_id",
                value: self.user_id.clone(),
            },
            IndexEntry {
                field: "session_token_hash",
                value: self.session_token_hash.clone(),
            },
        ]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}

/// A revoked SSH certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshRevokedCertDoc {
    pub serial: String,
    pub user_id: String,
    pub reason: Option<String>,
    pub revoked_at: Timestamp,
    pub expires_at: Timestamp,
    pub revoked_by: Option<String>,
}

impl DocumentType for SshRevokedCertDoc {
    const DOC_TYPE: &'static str = "ssh_revoked_cert";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![
            IndexEntry {
                field: "serial",
                value: self.serial.clone(),
            },
            IndexEntry {
                field: "user_id",
                value: self.user_id.clone(),
            },
        ]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}
