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
    /// Upstream IdP identities bound to this account, at most one per
    /// issuer (enforced by `enroll_user_with_org`, not the schema).
    /// Empty for accounts that predate identity binding and for
    /// SCIM-provisioned accounts that have not yet signed in through an
    /// IdP — they bind lazily on their first verified-email login.
    #[serde(default)]
    pub idp_identities: Vec<IdpIdentity>,
}

/// An upstream identity: the OIDC `(iss, sub)` pair, or for SAML the
/// IdP entity ID and NameID. This — not the email address — is the
/// durable link between a Vouch account and the person the upstream
/// IdP authenticated. Email is treated as mutable profile data: it can
/// be reassigned or recycled upstream, so it must never be the only
/// thing that maps a login onto an existing account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdpIdentity {
    /// Validated token issuer (OIDC `iss`) or SAML IdP entity ID.
    pub issuer: String,
    /// Subject within that issuer (OIDC `sub` or SAML NameID).
    pub subject: String,
}

/// Combined index value for the `idp_identity` blind index.
///
/// `issuer` and `subject` are joined with a NUL byte, which cannot
/// appear in an issuer URL or SAML entity ID, so the encoding is
/// unambiguous: distinct `(issuer, subject)` pairs never collide. The
/// store HMACs index values before persisting them, so the pair is a
/// blind equality key like every other index.
pub(crate) fn idp_identity_index_value(issuer: &str, subject: &str) -> String {
    format!("{issuer}\u{0}{subject}")
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
        for identity in &self.idp_identities {
            entries.push(IndexEntry {
                field: "idp_identity",
                value: idp_identity_index_value(&identity.issuer, &identity.subject),
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
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::{IdpIdentity, UserDoc, deterministic_user_id, idp_identity_index_value};
    use crate::db::document_type::DocumentType;

    #[test]
    fn legacy_user_json_without_idp_identities_deserializes() {
        // Stored user documents written before identity binding have no
        // `idp_identities` key; they must deserialize to an empty Vec so
        // legacy accounts keep working (lazy bind on first login).
        let json = r#"{
            "email": "legacy@example.com",
            "name": null,
            "org_id": null,
            "is_org_admin": false,
            "external_id": null,
            "github_id": null,
            "github_login": null,
            "github_refresh_token": null
        }"#;
        let doc: Result<UserDoc, _> = serde_json::from_str(json);
        let doc = doc.expect("legacy user JSON must deserialize");
        assert!(doc.idp_identities.is_empty());
    }

    #[test]
    fn index_entries_include_one_row_per_idp_identity() {
        let doc = UserDoc {
            email: "user@example.com".to_string(),
            name: None,
            org_id: None,
            is_org_admin: false,
            active: true,
            external_id: None,
            github_id: None,
            github_login: None,
            github_refresh_token: None,
            idp_identities: vec![
                IdpIdentity {
                    issuer: "https://idp-a.example.com".to_string(),
                    subject: "subject-a".to_string(),
                },
                IdpIdentity {
                    issuer: "https://idp-b.example.com".to_string(),
                    subject: "subject-b".to_string(),
                },
            ],
        };
        let values: Vec<String> = doc
            .index_entries()
            .into_iter()
            .filter(|e| e.field == "idp_identity")
            .map(|e| e.value)
            .collect();
        assert_eq!(
            values,
            vec![
                idp_identity_index_value("https://idp-a.example.com", "subject-a"),
                idp_identity_index_value("https://idp-b.example.com", "subject-b"),
            ]
        );
    }

    #[test]
    fn idp_identity_index_value_distinguishes_issuer_and_subject() {
        // The NUL separator makes the encoding unambiguous for real
        // issuer values (URLs / entity IDs, which cannot contain NUL):
        // moving characters across the boundary changes the value.
        assert_ne!(
            idp_identity_index_value("https://a.example", "sub-1"),
            idp_identity_index_value("https://a.example", "sub-2"),
        );
        assert_ne!(
            idp_identity_index_value("https://a.example", "sub-1"),
            idp_identity_index_value("https://b.example", "sub-1"),
        );
        assert_eq!(
            idp_identity_index_value("https://a.example", "sub-1"),
            "https://a.example\u{0}sub-1",
        );
    }

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
