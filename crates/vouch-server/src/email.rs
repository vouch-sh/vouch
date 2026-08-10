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
