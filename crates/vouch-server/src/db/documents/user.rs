// SPDX-License-Identifier: Apache-2.0 OR MIT
//! User document type.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::document_type::{DocumentType, IndexEntry};
use crate::email::Email;

/// A Vouch user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDoc {
    /// Canonical (trimmed, ASCII-lowercased) address. The [`Email`] type
    /// canonicalizes on construction and deserialization, so the `email`
    /// index row emitted by [`DocumentType::index_entries`] is normalized
    /// structurally — no call site can store a mixed-case address.
    pub email: Email,
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

/// The upstream identity presented by a single login, before it is known
/// whether the subject is eligible for identity binding.
///
/// `issuer` is known whenever a login went through a configured IdP, for
/// both protocols. `durable_subject` is the OIDC `sub` (always present —
/// OIDC verification is fail-closed on a missing `sub`) or the SAML
/// NameID, but only when the NameID's `Format` guarantees it will not be
/// reassigned or rotated (see `saml_upstream_login` in `handlers/saml.rs`).
/// A SAML login whose NameID format has no such guarantee still carries
/// `issuer`, with `durable_subject: None` — enough for
/// `enroll_user_with_org` to refuse a login that cannot reassert the
/// subject an account is already bound to, without enough to create a new
/// binding from an unstable value.
#[derive(Debug, Clone)]
pub struct UpstreamLogin {
    pub issuer: String,
    pub durable_subject: Option<String>,
}

impl UpstreamLogin {
    /// The durable `(issuer, subject)` pair this login can bind or match
    /// against, when its subject is eligible for identity binding.
    pub(crate) fn as_idp_identity(&self) -> Option<IdpIdentity> {
        self.durable_subject.clone().map(|subject| IdpIdentity {
            issuer: self.issuer.clone(),
            subject,
        })
    }
}

/// Combined index value for the `idp_identity` blind index.
///
/// `issuer` and `subject` are hashed together with NUL domain
/// separators, which cannot appear in an issuer URL or SAML entity ID,
/// so distinct `(issuer, subject)` pairs never collide. Keeping the
/// separator inside the digest is what makes the result storable: a NUL
/// in the index value itself is rejected by Postgres and Aurora DSQL.
/// Hashing also keeps the raw upstream subject out of the index table
/// in plaintext development mode.
///
/// Same SHA-256-with-domain-separator derivation as
/// `deterministic_org_id` (`db/enrollment.rs`), [`deterministic_user_id`],
/// `deterministic_jti_id` (`db/oauth.rs`), and
/// `deterministic_challenge_state_id` (`db/challenge_states.rs`).
pub(crate) fn idp_identity_index_value(issuer: &str, subject: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"idp_identity\0");
    ctx.update(issuer.as_bytes());
    ctx.update(b"\0");
    ctx.update(subject.as_bytes());
    hex::encode(ctx.finish().as_ref())
}

fn default_active() -> bool {
    true
}

impl DocumentType for UserDoc {
    const DOC_TYPE: &'static str = "user";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let mut entries = vec![IndexEntry {
            field: "email",
            value: self.email.as_str().to_string(),
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
/// Taking [`Email`] (canonical by construction) means two casings of the
/// same address always produce the same ID — a caller cannot reopen the
/// cross-case duplicate-row race, because the type system already
/// normalized the value it must store and index.
pub(crate) fn deterministic_user_id(email: &Email) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"user_email\0");
    ctx.update(email.as_str().as_bytes());
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
    use crate::email::Email;

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
            email: Email::new("user@example.com"),
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
        // The NUL domain separator inside the digest makes the encoding
        // unambiguous for real issuer values (URLs / entity IDs, which
        // cannot contain NUL): moving characters across the boundary
        // changes the value.
        assert_ne!(
            idp_identity_index_value("https://a.example", "sub-1"),
            idp_identity_index_value("https://a.example", "sub-2"),
        );
        assert_ne!(
            idp_identity_index_value("https://a.example", "sub-1"),
            idp_identity_index_value("https://b.example", "sub-1"),
        );
        // Shifting the boundary must not collide: the two pairs
        // concatenate identically, so only the separator keeps them apart.
        assert_ne!(
            idp_identity_index_value("https://a.example/x", "sub-1"),
            idp_identity_index_value("https://a.example/", "xsub-1"),
        );
        // The same pair always yields the same key, so the index is a
        // stable point lookup across processes.
        assert_eq!(
            idp_identity_index_value("https://a.example", "sub-1"),
            idp_identity_index_value("https://a.example", "sub-1"),
        );
    }

    #[test]
    fn idp_identity_index_value_is_storable_as_sql_text() {
        // Postgres and Aurora DSQL reject a NUL in a text value, and
        // SQLite accepts it silently, so an unstorable index value would
        // otherwise pass every test here and fail only in production. A
        // subject carrying its own control characters must not be able
        // to reintroduce one.
        let value = idp_identity_index_value("https://a.example", "sub\u{0}\u{1}\n1");
        assert!(
            !value.contains(|c: char| c.is_control()),
            "index value must contain no control characters, got {value:?}"
        );
        assert!(
            value.chars().all(|c| c.is_ascii_hexdigit()),
            "index value must be plain hex, got {value:?}"
        );
    }

    #[test]
    fn deterministic_user_id_collides_on_equal_emails() {
        // Two callers passing the same email string must produce the same
        // document ID — this is what makes the losing concurrent insert
        // surface a primary-key violation instead of silently creating a
        // second user row.
        assert_eq!(
            deterministic_user_id(&Email::new("dup@example.com")),
            deterministic_user_id(&Email::new("dup@example.com")),
        );
    }

    #[test]
    fn deterministic_user_id_differs_for_distinct_emails() {
        assert_ne!(
            deterministic_user_id(&Email::new("alice@example.com")),
            deterministic_user_id(&Email::new("bob@example.com")),
        );
    }

    #[test]
    fn deterministic_user_id_is_a_valid_uuid() {
        // SCIM resource IDs must parse as `uuid::Uuid` (see
        // `handlers::scim::validate_resource_id`). A deterministic ID
        // that fails to parse would make the user it identifies
        // unaddressable via GET/PATCH/PUT/DELETE.
        let id = deterministic_user_id(&Email::new("uuid-shape@example.com"));
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
            deterministic_user_id(&Email::new("Mixed@Example.com")),
            deterministic_user_id(&Email::new("mixed@example.com")),
        );
        assert_eq!(
            deterministic_user_id(&Email::new("MIXED@EXAMPLE.COM")),
            deterministic_user_id(&Email::new("mixed@example.com")),
        );
    }
}
