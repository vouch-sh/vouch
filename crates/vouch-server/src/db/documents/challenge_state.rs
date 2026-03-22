// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 challenge state document type (single-use enforcement).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};

/// A FIDO2 challenge state (single-use).
///
/// Stored after issuing a challenge JWT and consumed atomically
/// when the assertion is exchanged at the token endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChallengeStateDoc {
    /// SHA-256 hash of the challenge state JWT.
    pub state_hash: String,
    /// Expiration time (matches the JWT's 5-minute lifetime).
    pub expires_at: Timestamp,
    /// When this challenge was consumed (None = not yet consumed).
    pub consumed_at: Option<Timestamp>,
}

impl DocumentType for ChallengeStateDoc {
    const DOC_TYPE: &'static str = "challenge_state";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![IndexEntry {
            field: "state_hash",
            value: self.state_hash.clone(),
        }]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}
