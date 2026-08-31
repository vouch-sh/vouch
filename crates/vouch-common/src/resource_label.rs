// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A validated display label for a resource a user owns.

use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// A user-assigned display label for a resource the user owns — a security key
/// or a custom device-posture policy.
///
/// A `ResourceLabel` is always trimmed of surrounding whitespace, non-empty,
/// and at most [`ResourceLabel::MAX_CHARS`] Unicode characters (counted in
/// characters, not UTF-8 bytes, so the limit means the same thing in every
/// script). [`ResourceLabel::parse`] is the only constructor, so a value of
/// this type is valid by construction: a handler cannot persist an unvalidated
/// label, and an audit record that stores a `ResourceLabel` cannot capture the
/// raw pre-trim input.
///
/// The wire request types stay `String` so the JSON API can return its own
/// localized `invalid_name` error; handlers call [`ResourceLabel::parse`] and
/// hand the parsed value to the persistence layer, which only accepts this
/// type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ResourceLabel(String);

/// Why a string was rejected as a [`ResourceLabel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceLabelError {
    /// The value was empty or contained only whitespace.
    Empty,
    /// The trimmed value exceeded [`ResourceLabel::MAX_CHARS`] characters.
    TooLong,
}

impl ResourceLabel {
    /// Maximum length, in Unicode characters, of the trimmed label.
    pub const MAX_CHARS: usize = 100;

    /// Trim surrounding whitespace, reject empty and over-length values, and
    /// keep the trimmed form.
    ///
    /// # Errors
    ///
    /// - [`ResourceLabelError::Empty`] if `raw` is empty or all whitespace.
    /// - [`ResourceLabelError::TooLong`] if the trimmed value exceeds
    ///   [`Self::MAX_CHARS`] characters.
    pub fn parse(raw: &str) -> Result<Self, ResourceLabelError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ResourceLabelError::Empty);
        }
        if trimmed.chars().count() > Self::MAX_CHARS {
            return Err(ResourceLabelError::TooLong);
        }
        Ok(Self(trimmed.to_string()))
    }

    /// The validated, trimmed label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the inner `String`.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for ResourceLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// English by design: this text is for the `Error` trait, `serde`
/// deserialization errors, and logs — never a browser. Every UI caller matches
/// the [`ResourceLabelError`] variant and renders its own translated message
/// (e.g. the `keys-error-name-*` Fluent keys); the server JSON handlers discard
/// the error and return an exempt `error_description`.
impl fmt::Display for ResourceLabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("label must not be empty"),
            Self::TooLong => {
                write!(
                    f,
                    "label must be at most {} characters",
                    ResourceLabel::MAX_CHARS
                )
            }
        }
    }
}

impl std::error::Error for ResourceLabelError {}

/// Validate on the way in so a `ResourceLabel` decoded from a signed state
/// token (or any other serialized form) upholds the same invariant as one built
/// through [`ResourceLabel::parse`].
impl<'de> Deserialize<'de> for ResourceLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::{ResourceLabel, ResourceLabelError};

    #[test]
    fn parse_trims_surrounding_whitespace() {
        let label = ResourceLabel::parse("  My Key  ").expect("valid");
        assert_eq!(label.as_str(), "My Key");
    }

    #[test]
    fn parse_rejects_empty() {
        assert_eq!(ResourceLabel::parse(""), Err(ResourceLabelError::Empty));
    }

    #[test]
    fn parse_rejects_whitespace_only() {
        assert_eq!(ResourceLabel::parse("   "), Err(ResourceLabelError::Empty));
    }

    #[test]
    fn parse_accepts_max_length() {
        let name = "a".repeat(ResourceLabel::MAX_CHARS);
        assert_eq!(ResourceLabel::parse(&name).expect("valid").as_str(), name);
    }

    #[test]
    fn parse_rejects_over_max_length() {
        let name = "a".repeat(ResourceLabel::MAX_CHARS + 1);
        assert_eq!(
            ResourceLabel::parse(&name),
            Err(ResourceLabelError::TooLong)
        );
    }

    #[test]
    fn length_limit_counts_characters_not_bytes() {
        // 100 CJK characters is 300 UTF-8 bytes but exactly MAX_CHARS characters,
        // so a byte-based limit would wrongly reject it. (Regression guard for
        // the char-not-byte contract this type centralizes.)
        let cjk = "料".repeat(ResourceLabel::MAX_CHARS);
        assert_eq!(cjk.len(), ResourceLabel::MAX_CHARS * 3);
        assert!(ResourceLabel::parse(&cjk).is_ok());
        let too_long = "料".repeat(ResourceLabel::MAX_CHARS + 1);
        assert_eq!(
            ResourceLabel::parse(&too_long),
            Err(ResourceLabelError::TooLong)
        );
    }

    #[test]
    fn length_measured_after_trim() {
        // MAX_CHARS real characters plus surrounding whitespace is still valid;
        // the whitespace does not count toward the limit.
        let padded = format!("  {}  ", "a".repeat(ResourceLabel::MAX_CHARS));
        assert!(ResourceLabel::parse(&padded).is_ok());
    }

    #[test]
    fn serializes_transparently_as_inner_string() {
        let label = ResourceLabel::parse("My Key").expect("valid");
        assert_eq!(
            serde_json::to_string(&label).expect("serialize"),
            "\"My Key\""
        );
    }

    #[test]
    fn deserialize_validates_and_trims() {
        let label: ResourceLabel = serde_json::from_str("\"  My Key  \"").expect("valid");
        assert_eq!(label.as_str(), "My Key");
    }

    #[test]
    fn deserialize_rejects_empty() {
        let err = serde_json::from_str::<ResourceLabel>("\"   \"").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn deserialize_rejects_over_length() {
        let name = format!("\"{}\"", "a".repeat(ResourceLabel::MAX_CHARS + 1));
        let err = serde_json::from_str::<ResourceLabel>(&name).unwrap_err();
        assert!(err.to_string().contains("at most"));
    }
}
