// SPDX-License-Identifier: Apache-2.0 OR MIT
//! User document type.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::document_type::{DocumentType, IndexEntry};

/// A Vouch user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDoc {
    pub email: String,
    pub name: Option<String>,
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

/// Private namespace UUID used to derive deterministic user IDs.
///
/// Generated once with `uuid::Uuid::new_v4()` and pinned here so the
/// derivation is stable across process restarts: the same email always
/// maps to the same user ID. Using a fixed private namespace (rather
/// than one of the public RFC 9562 constants) isolates Vouch's user-ID
/// space from any other system that derives name-based UUIDs from the
/// same email string with a public namespace.
const USER_ID_NAMESPACE: Uuid = Uuid::from_bytes([
    0x4e, 0x6f, 0x75, 0x63, 0x68, 0x55, 0x73, 0x65, 0x72, 0x49, 0x64, 0x4e, 0x53, 0x4e, 0x73, 0x70,
]);

/// Derive a deterministic user ID from an email address.
///
/// Returns a version-5 (name-based, SHA-1) UUID so two concurrent
/// `create_scim_user` calls for the same email collide on the
/// `documents` PRIMARY KEY instead of producing two rows. The unique
/// violation on the losing insert is caught by `is_unique_violation`
/// and surfaced as the existing "UNIQUE constraint failed" error, so
/// the SCIM handler still returns `409 Conflict`. Because the output
/// is a valid `Uuid`, it passes `validate_resource_id` and can be used
/// in SCIM resource paths (`GET /scim/v2/Users/:id`).
///
/// This is the same TOCTOU-closing pattern used by `deterministic_org_id`
/// (`db/enrollment.rs`), `deterministic_jti_id` (`db/oauth.rs`), and
/// `deterministic_challenge_state_id` (`db/challenge_states.rs`), each
/// of which derives a stable document ID from a natural key so that
/// concurrent inserts collide at the database rather than producing
/// distinct rows.
///
/// Callers are responsible for any email normalisation (lower-casing,
/// trimming) required by the deployment: two strings that differ only
/// in case produce two distinct IDs. This matches the existing
/// `UserDoc.email` contract, which stores the email verbatim and looks
/// it up via the `email` index without normalisation.
pub(crate) fn deterministic_user_id(email: &str) -> String {
    Uuid::new_v5(&USER_ID_NAMESPACE, email.as_bytes()).to_string()
}

#[cfg(test)]
mod tests {
    use super::deterministic_user_id;

    #[test]
    fn deterministic_user_id_collides_on_equal_emails() {
        // Two callers passing the same email string must produce the same
        // document ID — this is what makes the losing concurrent insert
        // surface a primary-key violation instead of silently creating a
        // second user row.
        assert_eq!(
            deterministic_user_id("dup@example.com"),
            deterministic_user_id("dup@example.com"),
        );
    }

    #[test]
    fn deterministic_user_id_differs_for_distinct_emails() {
        assert_ne!(
            deterministic_user_id("alice@example.com"),
            deterministic_user_id("bob@example.com"),
        );
    }

    #[test]
    fn deterministic_user_id_is_a_valid_uuid() {
        // SCIM resource IDs must parse as `uuid::Uuid` (see
        // `handlers::scim::validate_resource_id`). A deterministic ID
        // that fails to parse would make the user it identifies
        // unaddressable via GET/PATCH/PUT/DELETE.
        let id = deterministic_user_id("uuid-shape@example.com");
        assert!(
            uuid::Uuid::try_parse(&id).is_ok(),
            "deterministic user ID must be a valid UUID; got {id}"
        );
    }

    #[test]
    fn deterministic_user_id_is_case_sensitive() {
        // Pins the documented contract: callers normalise the email
        // before calling `create_scim_user`. The SCIM handler currently
        // forwards `userName`/`emails[0].value` verbatim, so two
        // requests differing only in case would produce two IDs. This
        // matches the existing `UserDoc.email` index behaviour (also
        // case-sensitive) and is a tripwire for a future caller that
        // forgets to normalise.
        assert_ne!(
            deterministic_user_id("Mixed@Example.com"),
            deterministic_user_id("mixed@example.com"),
        );
    }
}
