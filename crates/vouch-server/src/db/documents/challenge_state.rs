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
    /// Expiration time (matches the JWT's 5-minute lifetime).
    pub expires_at: Timestamp,
}

impl DocumentType for ChallengeStateDoc {
    const DOC_TYPE: &'static str = "challenge_state";

    fn index_entries(&self) -> Vec<IndexEntry> {
        // No secondary indexes: the document ID is a deterministic SHA-256
        // hash of the state JWT (see `deterministic_challenge_state_id` in
        // `db/challenge_states.rs`), so all replay-prevention lookups go
        // through the PRIMARY KEY on `documents.id`. Rows of this type write
        // nothing to `document_indexes`.
        vec![]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}
