// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth 2.0 scope types.
//!
//! Provides type-safe representations of OAuth scopes used throughout the OIDC
//! provider. Raw scope strings from HTTP requests are parsed at the boundary
//! via [`ScopeSet::parse()`]; all internal types use [`ScopeSet`].
//!
//! ## Standards
//!
//! - RFC 6749 Section 3.3 — Access Token Scope
//! - OIDC Core Section 3.1.2.1 — `openid` scope requirement

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;
use std::fmt;

/// Individual OAuth 2.0 scope value.
///
/// Vouch supports a fixed set of scopes as advertised in the OIDC Discovery
/// document (`scopes_supported`). Unknown scopes are silently filtered during
/// parsing per RFC 6749 Section 3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OAuthScope {
    /// OIDC Core Section 3.1.2.1: Required scope for OpenID Connect.
    OpenId,
    /// OIDC Core Section 5.4: Grants access to `email` and `email_verified` claims.
    Email,
}

impl OAuthScope {
    /// Return the wire-format string for this scope value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpenId => "openid",
            Self::Email => "email",
        }
    }

    /// Parse a single scope token. Returns `None` for unknown scopes.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "openid" => Some(Self::OpenId),
            "email" => Some(Self::Email),
            _ => None,
        }
    }

    /// All supported scopes (matches discovery `scopes_supported`).
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::OpenId, Self::Email]
    }
}

impl fmt::Display for OAuthScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated set of OAuth 2.0 scopes.
///
/// Serializes as a space-separated string per RFC 6749 Section 3.3.
/// Deterministic ordering: `openid` always first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSet(HashSet<OAuthScope>);

impl ScopeSet {
    /// Create an empty scope set.
    #[must_use]
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    /// Parse a space-separated scope string, filtering to known scopes only.
    ///
    /// Unknown scope values are silently dropped per RFC 6749 Section 3.3.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        Self(s.split_whitespace().filter_map(OAuthScope::parse).collect())
    }

    /// All supported scopes.
    #[must_use]
    pub fn all() -> Self {
        Self(OAuthScope::all().iter().copied().collect())
    }

    /// Check whether a specific scope is present.
    #[must_use]
    pub fn contains(&self, scope: OAuthScope) -> bool {
        self.0.contains(&scope)
    }

    /// Check whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Compute the intersection of two scope sets.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self(self.0.intersection(&other.0).copied().collect())
    }

    /// Return a new scope set with user-specific scopes (`openid`, `email`) removed.
    ///
    /// Used for M2M tokens where user-specific scopes are meaningless.
    #[must_use]
    pub fn without_user_scopes(&self) -> Self {
        Self(
            self.0
                .iter()
                .copied()
                .filter(|s| !matches!(s, OAuthScope::OpenId | OAuthScope::Email))
                .collect(),
        )
    }

    /// Produce a space-separated string (RFC 6749 Section 3.3).
    ///
    /// Ordering is deterministic: `openid` always precedes `email`.
    #[must_use]
    pub fn to_space_separated(&self) -> String {
        let mut parts = Vec::new();
        if self.0.contains(&OAuthScope::OpenId) {
            parts.push("openid");
        }
        if self.0.contains(&OAuthScope::Email) {
            parts.push("email");
        }
        parts.join(" ")
    }
}

impl Serialize for ScopeSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_space_separated())
    }
}

impl<'de> Deserialize<'de> for ScopeSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::parse(&s))
    }
}

impl fmt::Display for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_space_separated())
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_known_scopes() {
        let set = ScopeSet::parse("openid email");
        assert!(set.contains(OAuthScope::OpenId));
        assert!(set.contains(OAuthScope::Email));
    }

    #[test]
    fn test_parse_filters_unknown() {
        let set = ScopeSet::parse("openid admin profile email");
        assert!(set.contains(OAuthScope::OpenId));
        assert!(set.contains(OAuthScope::Email));
        assert_eq!(set.0.len(), 2);
    }

    #[test]
    fn test_parse_empty() {
        let set = ScopeSet::parse("");
        assert!(set.is_empty());
    }

    #[test]
    fn test_intersection() {
        let a = ScopeSet::parse("openid email");
        let b = ScopeSet::parse("openid");
        let result = a.intersection(&b);
        assert!(result.contains(OAuthScope::OpenId));
        assert!(!result.contains(OAuthScope::Email));
    }

    #[test]
    fn test_to_space_separated_deterministic() {
        // Regardless of insertion order, output is always "openid email"
        let set = ScopeSet::parse("email openid");
        assert_eq!(set.to_space_separated(), "openid email");

        let set2 = ScopeSet::parse("openid email");
        assert_eq!(set2.to_space_separated(), "openid email");
    }

    #[test]
    fn test_serde_roundtrip() {
        let original = ScopeSet::parse("openid email");
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"openid email\"");

        let deserialized: ScopeSet = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, original);
    }

    #[test]
    fn test_display() {
        let set = ScopeSet::parse("openid email");
        assert_eq!(format!("{}", set), "openid email");
    }

    #[test]
    fn test_default_is_empty() {
        let set = ScopeSet::default();
        assert!(set.is_empty());
        assert!(!set.contains(OAuthScope::OpenId));
        assert!(!set.contains(OAuthScope::Email));
    }

    #[test]
    fn test_all() {
        let set = ScopeSet::all();
        assert!(set.contains(OAuthScope::OpenId));
        assert!(set.contains(OAuthScope::Email));
    }

    #[test]
    fn test_openid_only() {
        let set = ScopeSet::parse("openid");
        assert_eq!(set.to_space_separated(), "openid");
    }
}
