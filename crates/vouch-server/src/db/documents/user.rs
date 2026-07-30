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

/// Derive a deterministic user ID from an email address.
///
/// Returns an RFC 9562 version-8 (custom-format) UUID whose bytes are
/// the leading 16 bytes of `SHA-256("user_email\0" + email)`, so two
/// concurrent `create_scim_user` calls for the same email collide on
/// the `documents` PRIMARY KEY instead of producing two rows. The
/// unique violation on the losing insert is caught by
/// `is_unique_violation` and surfaced as the existing "UNIQUE
/// constraint failed" error, so the SCIM handler still returns
/// `409 Conflict`. Because the output is a valid `Uuid`, it passes
/// `validate_resource_id` and can be used in SCIM resource paths
/// (`GET /scim/v2/Users/:id`).
///
/// This is the same TOCTOU-closing pattern — and the same
/// SHA-256-with-domain-separator derivation — used by
/// `deterministic_org_id` (`db/enrollment.rs`), `deterministic_jti_id`
/// (`db/oauth.rs`), and `deterministic_challenge_state_id`
/// (`db/challenge_states.rs`). The digest is additionally packed into
/// a UUID here because SCIM resource IDs must parse as `uuid::Uuid`;
/// version 8 is the RFC 9562 version reserved for exactly this kind of
/// custom derivation, avoiding the SHA-1 dependency a version-5 UUID
/// would pull in.
///
/// The email is ASCII-lowercased inside this function before hashing,
/// so two casings of the same address always produce the same ID —
/// a caller that forgets to normalize cannot reopen the cross-case
/// duplicate-row race. Callers still normalize before storage and
/// lookup (`create_scim_user` lowercases first), since the stored
/// `UserDoc.email` and its index row must match the lowercase
/// convention too.
pub(crate) fn deterministic_user_id(email: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let email = email.to_ascii_lowercase();

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"user_email\0");
    ctx.update(email.as_bytes());
    let digest = ctx.finish();

    let mut bytes = [0u8; 16];
    for (dst, src) in bytes.iter_mut().zip(digest.as_ref()) {
        *dst = *src;
    }
    Uuid::new_v8(bytes).to_string()
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
        let parsed = uuid::Uuid::try_parse(&id);
        assert!(
            parsed.is_ok(),
            "deterministic user ID must be a valid UUID; got {id}"
        );
        assert_eq!(
            parsed.ok().map(|u| u.get_version_num()),
            Some(8),
            "deterministic user ID must be an RFC 9562 version-8 UUID"
        );
    }

    #[test]
    fn deterministic_user_id_is_case_insensitive() {
        // The derivation lowercases internally, so every casing of the
        // same address maps to one primary key — a caller that forgets
        // to normalize cannot mint a second user row for the same
        // person via a differently-cased concurrent create.
        assert_eq!(
            deterministic_user_id("Mixed@Example.com"),
            deterministic_user_id("mixed@example.com"),
        );
        assert_eq!(
            deterministic_user_id("MIXED@EXAMPLE.COM"),
            deterministic_user_id("mixed@example.com"),
        );
    }
}
