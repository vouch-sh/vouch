// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FAPI 2.0 interaction tracking via `x-fapi-interaction-id`.
//!
//! The Financial-grade API (FAPI) 2.0 specification requires clients to
//! include a unique `x-fapi-interaction-id` header in each request so that
//! logs on both sides can be correlated. The `x-fapi-end-user-present` header
//! signals whether the end-user is interactively present (i.e., the request
//! originated from a human-facing terminal rather than a background process).
//!
//! # Security note
//!
//! Per the [FAPI 2.0 Implementation Advice][advice], `x-fapi-end-user-present`
//! is **not a security mechanism** — servers cannot independently verify it.
//! The real cryptographic proof of user presence is the `hardware_verified`
//! claim in the access token, which is only set after the server verifies a
//! FIDO2 assertion with both User Presence (UP) and User Verified (UV) flags.
//!
//! This module provides two constructors:
//! - [`FapiInteraction::new`] — terminal heuristic (pre-FIDO2 requests)
//! - [`FapiInteraction::with_presence`] — explicit state (post-FIDO2 requests)
//!
//! [advice]: https://openid.bitbucket.io/fapi/fapi-2_0-implementation_advice.html

use std::io::IsTerminal;

/// Tracks FAPI 2.0 interaction metadata for a single HTTP request.
///
/// Each `FapiInteraction` carries a unique ID and a flag indicating
/// whether the end-user is present at the terminal.
#[derive(Debug, Clone)]
pub struct FapiInteraction {
    /// Unique interaction ID (UUID v7, monotonically increasing).
    interaction_id: String,
    /// Whether stdin is connected to a terminal (end-user is present).
    end_user_present: bool,
}

impl FapiInteraction {
    /// Create a new interaction with a fresh UUID and terminal detection.
    ///
    /// Uses `stdin().is_terminal()` as a heuristic for end-user presence.
    /// Prefer [`with_presence`](Self::with_presence) after a successful FIDO2
    /// assertion, where a hardware touch provides stronger evidence.
    #[must_use]
    pub fn new() -> Self {
        Self {
            interaction_id: uuid::Uuid::now_v7().to_string(),
            end_user_present: std::io::stdin().is_terminal(),
        }
    }

    /// Create a new interaction with an explicit end-user presence state.
    ///
    /// Use after a successful FIDO2 assertion, where hardware touch
    /// provides cryptographic proof of user presence.
    #[must_use]
    pub fn with_presence(end_user_present: bool) -> Self {
        Self {
            interaction_id: uuid::Uuid::now_v7().to_string(),
            end_user_present,
        }
    }

    /// Get the unique interaction ID.
    #[must_use]
    pub fn interaction_id(&self) -> &str {
        &self.interaction_id
    }

    /// Returns `true` if the end-user is interactively present at the terminal.
    #[must_use]
    pub fn end_user_present(&self) -> bool {
        self.end_user_present
    }

    /// Return the FAPI headers as name–value pairs for inclusion in an HTTP request.
    ///
    /// Returns a fixed-size array (no heap allocation):
    /// - `x-fapi-interaction-id`: the unique interaction UUID
    /// - `x-fapi-end-user-present`: `"true"` or `"false"`
    #[must_use]
    pub fn headers(&self) -> [(&str, &str); 2] {
        [
            ("x-fapi-interaction-id", &self.interaction_id),
            (
                "x-fapi-end-user-present",
                if self.end_user_present {
                    "true"
                } else {
                    "false"
                },
            ),
        ]
    }
}

impl Default for FapiInteraction {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_interaction_has_non_empty_id() {
        let interaction = FapiInteraction::new();
        assert!(!interaction.interaction_id().is_empty());
    }

    #[test]
    fn test_interaction_id_is_valid_uuid() {
        let interaction = FapiInteraction::new();
        // UUID v7 is a valid UUID — parse should succeed
        let id = interaction.interaction_id();
        assert_eq!(id.len(), 36, "UUID string should be 36 characters");
        // Check the standard UUID hyphen positions
        assert_eq!(id.as_bytes().get(8), Some(&b'-'));
        assert_eq!(id.as_bytes().get(13), Some(&b'-'));
        assert_eq!(id.as_bytes().get(18), Some(&b'-'));
        assert_eq!(id.as_bytes().get(23), Some(&b'-'));
    }

    #[test]
    fn test_headers_returns_two_entries() {
        let interaction = FapiInteraction::new();
        let headers = interaction.headers();
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn test_headers_contain_correct_names() {
        let interaction = FapiInteraction::new();
        let headers = interaction.headers();
        let names: Vec<&str> = headers.iter().map(|(k, _)| *k).collect();
        assert!(names.contains(&"x-fapi-interaction-id"));
        assert!(names.contains(&"x-fapi-end-user-present"));
    }

    #[test]
    fn test_headers_interaction_id_matches() {
        let interaction = FapiInteraction::new();
        let headers = interaction.headers();
        let id_header = headers
            .iter()
            .find(|(k, _)| *k == "x-fapi-interaction-id")
            .map(|(_, v)| *v);
        assert_eq!(id_header, Some(interaction.interaction_id()));
    }

    #[test]
    fn test_headers_end_user_present_value() {
        let interaction = FapiInteraction::new();
        let headers = interaction.headers();
        let present_header = headers
            .iter()
            .find(|(k, _)| *k == "x-fapi-end-user-present")
            .map(|(_, v)| *v);

        // In a test environment stdin is typically not a terminal
        assert!(
            present_header == Some("true") || present_header == Some("false"),
            "value must be 'true' or 'false'"
        );
    }

    #[test]
    fn test_interaction_ids_are_unique() {
        let i1 = FapiInteraction::new();
        let i2 = FapiInteraction::new();
        // Two interactions must have distinct IDs
        assert_ne!(i1.interaction_id(), i2.interaction_id());
    }

    #[test]
    fn test_default_equals_new() {
        // Default should produce a valid interaction (not panic)
        let i = FapiInteraction::default();
        assert!(!i.interaction_id().is_empty());
    }

    #[test]
    fn test_with_presence_true() {
        let interaction = FapiInteraction::with_presence(true);
        assert!(interaction.end_user_present());
        let headers = interaction.headers();
        let present = headers
            .iter()
            .find(|(k, _)| *k == "x-fapi-end-user-present")
            .map(|(_, v)| *v);
        assert_eq!(present, Some("true"));
    }

    #[test]
    fn test_with_presence_false() {
        let interaction = FapiInteraction::with_presence(false);
        assert!(!interaction.end_user_present());
        let headers = interaction.headers();
        let present = headers
            .iter()
            .find(|(k, _)| *k == "x-fapi-end-user-present")
            .map(|(_, v)| *v);
        assert_eq!(present, Some("false"));
    }

    #[test]
    fn test_with_presence_has_valid_uuid() {
        let interaction = FapiInteraction::with_presence(true);
        let id = interaction.interaction_id();
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes().get(8), Some(&b'-'));
    }
}
