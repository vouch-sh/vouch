// SPDX-License-Identifier: BUSL-1.1
//! Resource Indicators for OAuth 2.0 (RFC 8707).
//!
//! Provides a validated `ResourceUri` newtype that enforces RFC 8707 Section 2
//! requirements: the resource parameter must be an absolute URI without a
//! fragment component.

/// A validated resource URI per RFC 8707 Section 2.
///
/// Resource indicators are absolute URIs that identify the protected resource
/// server that will receive the access token. Per the RFC, the URI:
/// - MUST be an absolute URI (has a scheme)
/// - MUST NOT include a fragment component
/// - MUST NOT be empty
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceUri(String);

/// Maximum length for resource URIs (URL practical limit).
const MAX_RESOURCE_URI_LEN: usize = 2048;

/// Errors from parsing a resource URI.
#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    /// The URI string was empty.
    #[error("resource URI must not be empty")]
    Empty,
    /// The URI exceeds the maximum allowed length.
    #[error("resource URI exceeds maximum length of {MAX_RESOURCE_URI_LEN}")]
    TooLong,
    /// The URI is not an absolute URI (missing scheme).
    #[error("resource URI must be an absolute URI with a scheme")]
    NotAbsolute,
    /// The URI contains a fragment component.
    #[error("resource URI must not contain a fragment component")]
    HasFragment,
}

impl ResourceUri {
    /// Parse and validate a resource URI per RFC 8707 Section 2.
    ///
    /// # Errors
    ///
    /// Returns `ResourceError` if the URI is empty, not absolute, or contains
    /// a fragment component.
    pub fn parse(s: &str) -> Result<Self, ResourceError> {
        if s.is_empty() {
            return Err(ResourceError::Empty);
        }

        if s.len() > MAX_RESOURCE_URI_LEN {
            return Err(ResourceError::TooLong);
        }

        let url = url::Url::parse(s).map_err(|_| ResourceError::NotAbsolute)?;

        // RFC 8707 Section 2: "The value of the resource parameter MUST be an
        // absolute URI ... and MUST NOT include a fragment component."
        if url.fragment().is_some() {
            return Err(ResourceError::HasFragment);
        }

        Ok(Self(url.to_string()))
    }

    /// Return the URI as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ResourceUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_https_uri() {
        let uri = ResourceUri::parse("https://api.example.com").unwrap();
        assert_eq!(uri.as_str(), "https://api.example.com/");
    }

    #[test]
    fn test_valid_https_uri_with_path() {
        let uri = ResourceUri::parse("https://api.example.com/v1/resources").unwrap();
        assert_eq!(uri.as_str(), "https://api.example.com/v1/resources");
    }

    #[test]
    fn test_valid_http_uri() {
        let uri = ResourceUri::parse("http://localhost:8080").unwrap();
        assert_eq!(uri.as_str(), "http://localhost:8080/");
    }

    #[test]
    fn test_valid_uri_with_query() {
        let uri = ResourceUri::parse("https://api.example.com/v1?type=resource").unwrap();
        assert_eq!(uri.as_str(), "https://api.example.com/v1?type=resource");
    }

    #[test]
    fn test_rejects_fragment() {
        let result = ResourceUri::parse("https://api.example.com/v1#section");
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::HasFragment => {}
            other => panic!("Expected HasFragment, got: {other:?}"),
        }
    }

    #[test]
    fn test_rejects_relative_uri() {
        let result = ResourceUri::parse("/api/v1/resources");
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::NotAbsolute => {}
            other => panic!("Expected NotAbsolute, got: {other:?}"),
        }
    }

    #[test]
    fn test_rejects_empty_string() {
        let result = ResourceUri::parse("");
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::Empty => {}
            other => panic!("Expected Empty, got: {other:?}"),
        }
    }

    #[test]
    fn test_rejects_bare_string() {
        let result = ResourceUri::parse("not-a-uri");
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::NotAbsolute => {}
            other => panic!("Expected NotAbsolute, got: {other:?}"),
        }
    }

    #[test]
    fn test_display() {
        let uri = ResourceUri::parse("https://api.example.com").unwrap();
        assert_eq!(format!("{uri}"), "https://api.example.com/");
    }
}
