// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Validated server URL type.
//!
//! [`ServerUrl`] wraps a URL string that has been validated for scheme security
//! (HTTPS required for non-loopback hosts) and normalized (trailing slashes trimmed).

use std::fmt;

/// A validated, normalized Vouch server URL.
///
/// Guarantees:
/// - The URL is syntactically valid
/// - HTTPS is used for non-loopback hosts (unless `allow_insecure` was set)
/// - Trailing slashes are trimmed
///
/// Construct via [`ServerUrl::parse`].
#[derive(Debug, Clone)]
pub(crate) struct ServerUrl {
    url: String,
}

impl ServerUrl {
    /// Parse and validate a server URL.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The URL is empty or cannot be parsed
    /// - The URL uses HTTP for a non-loopback host and `allow_insecure` is false
    ///
    /// If the URL uses HTTP for a non-loopback host and `allow_insecure` is true,
    /// a warning is printed to stderr but the URL is accepted.
    pub(crate) fn parse(url: &str, allow_insecure: bool) -> Result<Self, ServerUrlError> {
        if url.is_empty() {
            return Err(ServerUrlError::Empty);
        }

        // Validate URL syntax
        let _parsed = url::Url::parse(url).map_err(|e| ServerUrlError::Invalid(e.to_string()))?;

        // Check scheme security
        match vouch_common::check_url_security(url) {
            vouch_common::UrlSecurity::Secure => {}
            vouch_common::UrlSecurity::InsecureHttp { url: insecure_url } => {
                if allow_insecure {
                    eprintln!(
                        "WARNING: Using insecure HTTP connection to {insecure_url}.\n\
                         Credentials will be transmitted in plaintext.\n"
                    );
                } else {
                    return Err(ServerUrlError::InsecureHttp(insecure_url));
                }
            }
        }

        // Normalize: trim trailing slashes
        let normalized = url.trim_end_matches('/').to_string();

        Ok(Self { url: normalized })
    }

    /// Get the URL as a string slice.
    pub(crate) fn as_str(&self) -> &str {
        &self.url
    }
}

impl fmt::Display for ServerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url)
    }
}

impl AsRef<str> for ServerUrl {
    fn as_ref(&self) -> &str {
        &self.url
    }
}

/// Errors from [`ServerUrl::parse`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum ServerUrlError {
    /// The URL string was empty.
    #[error("server URL is empty")]
    Empty,

    /// The URL could not be parsed.
    #[error("invalid server URL: {0}")]
    Invalid(String),

    /// The URL uses HTTP for a non-loopback host.
    #[error(
        "Server URL uses plain HTTP ({0}).\n\
         Credentials would be sent in plaintext.\n\n\
         Use an https:// URL, or set --allow-insecure / VOUCH_ALLOW_INSECURE=1 for development."
    )]
    InsecureHttp(String),
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_https_url_accepted() {
        let url = ServerUrl::parse("https://example.com", false).unwrap();
        assert_eq!(url.as_str(), "https://example.com");
    }

    #[test]
    fn test_http_localhost_accepted() {
        let url = ServerUrl::parse("http://localhost:3000", false).unwrap();
        assert_eq!(url.as_str(), "http://localhost:3000");
    }

    #[test]
    fn test_http_127_0_0_1_accepted() {
        let url = ServerUrl::parse("http://127.0.0.1:3000", false).unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:3000");
    }

    #[test]
    fn test_http_ipv6_loopback_accepted() {
        let url = ServerUrl::parse("http://[::1]:3000", false).unwrap();
        assert_eq!(url.as_str(), "http://[::1]:3000");
    }

    #[test]
    fn test_http_non_loopback_rejected() {
        let result = ServerUrl::parse("http://example.com", false);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ServerUrlError::InsecureHttp(_)
        ));
    }

    #[test]
    fn test_http_non_loopback_accepted_with_allow_insecure() {
        let url = ServerUrl::parse("http://example.com", true).unwrap();
        assert_eq!(url.as_str(), "http://example.com");
    }

    #[test]
    fn test_trailing_slash_trimmed() {
        let url = ServerUrl::parse("https://example.com/", false).unwrap();
        assert_eq!(url.as_str(), "https://example.com");
    }

    #[test]
    fn test_multiple_trailing_slashes_trimmed() {
        let url = ServerUrl::parse("https://example.com///", false).unwrap();
        assert_eq!(url.as_str(), "https://example.com");
    }

    #[test]
    fn test_empty_string_rejected() {
        let result = ServerUrl::parse("", false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ServerUrlError::Empty));
    }

    #[test]
    fn test_invalid_url_rejected() {
        let result = ServerUrl::parse("not a url", false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ServerUrlError::Invalid(_)));
    }

    #[test]
    fn test_display_matches_as_str() {
        let url = ServerUrl::parse("https://example.com", false).unwrap();
        assert_eq!(format!("{url}"), url.as_str());
    }

    #[test]
    fn test_as_ref_returns_str() {
        let url = ServerUrl::parse("https://example.com", false).unwrap();
        let s: &str = url.as_ref();
        assert_eq!(s, "https://example.com");
    }
}
