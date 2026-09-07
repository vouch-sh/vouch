// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Canonical email address handling.
//!
//! Vouch treats email addresses as case-insensitive identifiers: storage,
//! indexed lookup, audit correlation, and domain matching must all agree on
//! one canonical form or the same address keys differently across
//! subsystems (the source of the cross-case duplicate-user and
//! missing-audit-event bugs). [`Email`] is that canonical form; construct
//! one instead of hand-rolling `to_lowercase()` at call sites.

use serde::{Deserialize, Serialize};

/// An email address in canonical form: trimmed and ASCII-lowercased.
///
/// ASCII folding (not full Unicode) is deliberate: stored `UserDoc` index
/// rows and audit HMAC correlation keys were built with ASCII folding, and
/// switching would orphan existing non-ASCII rows. RFC 5321 makes the
/// domain case-insensitive and, in practice, providers treat the local
/// part the same way.
///
/// Deserialization re-canonicalizes, so documents written before this type
/// existed normalize on read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Email(String);

impl Email {
    /// Canonicalize a raw address: trim surrounding whitespace and
    /// ASCII-lowercase.
    pub fn new(raw: impl AsRef<str>) -> Self {
        Self(raw.as_ref().trim().to_ascii_lowercase())
    }

    /// The canonical address as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the canonical `String`.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// The domain part of this address, if any.
    ///
    /// Splits on the **last** `@` (RFC 5321: a quoted local part may itself
    /// contain `@`), the semantics the org-domain and audit layers already
    /// used. First-`@` splitting picks the wrong domain for such addresses.
    ///
    /// Returns `None` when the domain contains a NUL byte: no real domain
    /// can, and 0x00 in a `text` column or bind parameter is a hard error
    /// on Postgres/DSQL (issue #883).
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.0
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .filter(|domain| !domain.contains('\0'))
    }

    /// The canonical (lowercased) domain of a raw address, if any.
    ///
    /// For call sites that only need the domain of a `&str` without
    /// building an [`Email`]. Same last-`@` semantics and NUL rejection
    /// as [`Self::domain`].
    #[must_use]
    pub fn domain_of(raw: &str) -> Option<String> {
        raw.trim()
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_ascii_lowercase())
            .filter(|domain| !domain.contains('\0'))
    }

    /// Whether a raw address has the syntactic shape Vouch stores.
    ///
    /// A **shape check** (not full RFC 5321 validation): the local part must
    /// be non-empty and free of whitespace and angle brackets, and the
    /// domain must contain no NUL byte. This rejects the malformed `userName`
    /// values a mis-mapped provisioning source can produce — `a b@d`,
    /// `@d`, `Display Name <ada@d>` — that defeat [`Self::domain_of`]'s
    /// suffix-only split, while leaving two cases to their existing gates:
    ///
    /// - an **empty domain** (`foo@`) returns `true` so the org-domain
    ///   ownership check inside `create_scim_user` rejects it with the
    ///   distinct `"Email domain is not verified"` message, as before;
    /// - a **NUL in the local part** returns `true` so the store's
    ///   index-value guard ([`super::store`'s `validate_index_entry`][v])
    ///   rejects it, matching the contract pinned by
    ///   `test_scim_create_user_rejects_nul_in_username_local_part`.
    ///
    /// Splits on the **last** `@` (same as [`Self::domain`]/[`Self::domain_of`])
    /// so a quoted local part that itself contains `@` is not mis-split.
    ///
    /// [v]: crate::db::store
    #[must_use]
    pub fn is_valid_address(raw: &str) -> bool {
        let Some((local, domain)) = raw.trim().rsplit_once('@') else {
            return false;
        };
        !local.is_empty()
            && !domain.contains('\0')
            && !local
                .chars()
                .any(|c| c.is_whitespace() || c == '<' || c == '>')
    }
}

impl<'de> Deserialize<'de> for Email {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self::new(String::deserialize(deserializer)?))
    }
}

impl std::fmt::Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<Email> for String {
    fn from(email: Email) -> Self {
        email.0
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::Email;

    #[test]
    fn new_lowercases_and_trims() {
        assert_eq!(
            Email::new("  Alice@Example.COM ").as_str(),
            "alice@example.com"
        );
    }

    #[test]
    fn new_folds_ascii_only() {
        // Unicode stays as-is: stored index rows were built with ASCII folding.
        assert_eq!(
            Email::new("JÜRGEN@Example.com").as_str(),
            "jÜrgen@example.com"
        );
    }

    #[test]
    fn domain_splits_on_last_at() {
        let email = Email::new("\"quoted@local\"@example.com");
        assert_eq!(email.domain(), Some("example.com"));
    }

    #[test]
    fn domain_none_without_at() {
        assert_eq!(Email::new("not-an-email").domain(), None);
    }

    #[test]
    fn domain_none_with_nul_in_domain() {
        // 0x00 in a text column or bind parameter is a hard error on
        // Postgres/DSQL; no real domain contains it.
        assert_eq!(Email::new("alice@exa\0mple.com").domain(), None);
        assert_eq!(Email::domain_of("alice@exa\0mple.com"), None);
    }

    #[test]
    fn domain_of_ignores_nul_in_local_part() {
        // Only the domain part is stored as a domain; a NUL confined to
        // the local part still yields the (clean) domain.
        assert_eq!(
            Email::domain_of("ali\0ce@example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn domain_of_lowercases() {
        assert_eq!(
            Email::domain_of("alice@EXAMPLE.com"),
            Some("example.com".to_string())
        );
        assert_eq!(Email::domain_of("no-domain"), None);
    }

    #[test]
    fn is_valid_address_accepts_well_formed() {
        assert!(Email::is_valid_address("alice@example.com"));
        // Surrounding whitespace is trimmed, matching `Email::new`.
        assert!(Email::is_valid_address("  Alice@Example.COM  "));
        // A last-`@` split keeps a quoted local part containing `@` intact.
        assert!(Email::is_valid_address("\"quoted@local\"@example.com"));
        // Reserved-TLD / single-label domains are not re-validated here;
        // ownership is the ownership layer's job.
        assert!(Email::is_valid_address("alice@corp.internal"));
    }

    #[test]
    fn is_valid_address_rejects_no_at() {
        assert!(!Email::is_valid_address("not-an-email"));
        assert!(!Email::is_valid_address(""));
    }

    #[test]
    fn is_valid_address_rejects_empty_local_part() {
        // `@example.com` has a clean domain suffix but no local part — the
        // exact case the suffix-only `domain_of` check missed.
        assert!(!Email::is_valid_address("@example.com"));
    }

    #[test]
    fn is_valid_address_rejects_whitespace_in_local_part() {
        assert!(!Email::is_valid_address("a b@example.com"));
        // A tab is whitespace too.
        assert!(!Email::is_valid_address("a\tb@example.com"));
        // Display-name-wrapped address: local part spans the embedded name.
        assert!(!Email::is_valid_address("Ada Lovelace ada@example.com"));
    }

    #[test]
    fn is_valid_address_rejects_angle_brackets_in_local_part() {
        // `<ada@example.com>` (no display name, no whitespace) is a
        // display-name-wrapped address the whitespace rule alone misses.
        assert!(!Email::is_valid_address("<ada@example.com>"));
    }

    #[test]
    fn is_valid_address_passes_empty_domain_through_to_ownership_gate() {
        // `foo@` has an empty domain suffix. This is NOT a local-part defect
        // and is rejected by `create_scim_user`'s domain-ownership check
        // with `"Email domain is not verified"`, so the shape check lets it
        // through to preserve that distinct message.
        assert!(
            Email::is_valid_address("foo@"),
            "empty-domain case must fall through to the ownership gate"
        );
    }

    #[test]
    fn is_valid_address_rejects_nul_in_domain() {
        assert!(!Email::is_valid_address("alice@exa\0mple.com"));
    }

    #[test]
    fn is_valid_address_passes_nul_in_local_part_to_store_guard() {
        // A NUL confined to the local part is left to the store's index-value
        // guard (`validate_index_entry`), matching the contract pinned by
        // `test_scim_create_user_rejects_nul_in_username_local_part`.
        assert!(
            Email::is_valid_address("ali\0ce@example.com"),
            "NUL in the local part must pass the shape check to the store guard"
        );
    }

    #[test]
    fn deserialize_canonicalizes() {
        let email: Email = serde_json::from_str("\" Alice@Example.COM \"").expect("deserialize");
        assert_eq!(email.as_str(), "alice@example.com");
    }

    #[test]
    fn serialize_is_transparent() {
        let json = serde_json::to_string(&Email::new("Bob@Example.com")).expect("serialize");
        assert_eq!(json, "\"bob@example.com\"");
    }
}
