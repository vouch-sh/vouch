// SPDX-License-Identifier: Apache-2.0 OR MIT
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

/// Strip at most one trailing `/` so `https://x/` and `https://x` compare equal.
fn trim_trailing_slash(path: &str) -> &str {
    path.strip_suffix('/').unwrap_or(path)
}

/// True when a resource-narrowed `aud` authorizes a request to `request_path`
/// on the deployment identified by `base_url` (RFC 8707 / RFC 8725 §3.9).
///
/// A narrowed audience covers a request when all of the following hold:
/// - `aud` is an absolute URI without query or fragment components;
/// - its origin (scheme + host + port) equals the deployment's `base_url`
///   origin — audiences naming external resource servers never authorize
///   requests to this deployment;
/// - its path covers the request path at a segment boundary: an audience
///   equal to the deployment root covers every request, while
///   `{base_url}/v1/keys` covers `/v1/keys` and `/v1/keys/register` but not
///   `/v1/keysextra`.
///
/// `request_path` is the request path relative to `base_url` (as passed to
/// `extract_resource_token`); an empty value is treated as `/`, so only a
/// root-scoped audience covers cookie-only extraction paths.
///
/// Trailing slashes are insignificant on both the audience path and the
/// request path. Comparison is on URL-normalized paths (no percent-decoding);
/// audiences are matched as issued.
pub(crate) fn audience_covers_resource(aud: &str, base_url: &str, request_path: &str) -> bool {
    let Ok(aud_url) = url::Url::parse(aud) else {
        // Non-URI audiences (e.g. a token-exchange logical audience like
        // "kubernetes") cannot name this resource server.
        return false;
    };
    let Ok(base) = url::Url::parse(base_url) else {
        return false;
    };

    // Conservative: an audience with a query or fragment never matches.
    if aud_url.query().is_some() || aud_url.fragment().is_some() {
        return false;
    }

    // Scheme + host + port must match the deployment. `Url::origin` handles
    // host case-insensitivity and default-port elision; opaque origins
    // (non-special schemes such as `urn:`) never compare equal.
    if aud_url.origin() != base.origin() {
        return false;
    }

    let aud_path = trim_trailing_slash(aud_url.path());
    let base_path = trim_trailing_slash(base.path());

    // Audience names the deployment root (`resource={base_url}`): covers
    // every path on this deployment.
    if aud_path == base_path {
        return true;
    }

    // Otherwise the audience must extend the base path at a segment boundary;
    // the remainder is the resource path relative to base_url.
    let rel = match aud_path.strip_prefix(base_path) {
        Some(rel) if rel.starts_with('/') => rel,
        _ => return false,
    };

    let request = if request_path.is_empty() {
        "/"
    } else {
        request_path
    };
    let request = trim_trailing_slash(request);

    // Exact resource, or a sub-path at a segment boundary.
    request == rel
        || request
            .strip_prefix(rel)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
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
        assert!(matches!(result.unwrap_err(), ResourceError::HasFragment));
    }

    #[test]
    fn test_rejects_relative_uri() {
        let result = ResourceUri::parse("/api/v1/resources");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ResourceError::NotAbsolute));
    }

    #[test]
    fn test_rejects_empty_string() {
        let result = ResourceUri::parse("");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ResourceError::Empty));
    }

    #[test]
    fn test_rejects_bare_string() {
        let result = ResourceUri::parse("not-a-uri");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ResourceError::NotAbsolute));
    }

    #[test]
    fn test_display() {
        let uri = ResourceUri::parse("https://api.example.com").unwrap();
        assert_eq!(format!("{uri}"), "https://api.example.com/");
    }

    const BASE: &str = "https://vouch.example.com";

    #[test]
    fn test_covers_exact_path() {
        assert!(audience_covers_resource(
            "https://vouch.example.com/v1/keys",
            BASE,
            "/v1/keys"
        ));
    }

    #[test]
    fn test_covers_sub_path() {
        assert!(audience_covers_resource(
            "https://vouch.example.com/v1/keys",
            BASE,
            "/v1/keys/register/start"
        ));
    }

    #[test]
    fn test_rejects_sibling_path() {
        assert!(!audience_covers_resource(
            "https://vouch.example.com/v1/keys",
            BASE,
            "/v1/credentials/ssh"
        ));
    }

    #[test]
    fn test_rejects_segment_boundary_violation() {
        // aud=…/v1/keys must not authorize /v1/keysextra
        assert!(!audience_covers_resource(
            "https://vouch.example.com/v1/keys",
            BASE,
            "/v1/keysextra"
        ));
    }

    #[test]
    fn test_root_audience_covers_everything() {
        assert!(audience_covers_resource(BASE, BASE, "/v1/keys"));
        assert!(audience_covers_resource(BASE, BASE, "/v1/credentials/ssh"));
        assert!(audience_covers_resource(BASE, BASE, ""));
        // With url's host-only normalization (`https://x` parses to path `/`)
        assert!(audience_covers_resource(
            "https://vouch.example.com/",
            BASE,
            "/v1/keys"
        ));
    }

    #[test]
    fn test_trailing_slash_insensitive() {
        assert!(audience_covers_resource(
            "https://vouch.example.com/v1/keys/",
            BASE,
            "/v1/keys"
        ));
        assert!(audience_covers_resource(
            "https://vouch.example.com/v1/keys",
            BASE,
            "/v1/keys/"
        ));
        assert!(audience_covers_resource(
            "https://vouch.example.com/v1/keys",
            "https://vouch.example.com/",
            "/v1/keys"
        ));
    }

    #[test]
    fn test_host_case_and_default_port_normalization() {
        assert!(audience_covers_resource(
            "HTTPS://Vouch.Example.COM:443/v1/keys",
            BASE,
            "/v1/keys"
        ));
    }

    #[test]
    fn test_rejects_external_origin() {
        assert!(!audience_covers_resource(
            "https://api.example.com",
            BASE,
            "/v1/keys"
        ));
        assert!(!audience_covers_resource(
            "https://api.example.com/v1/keys",
            BASE,
            "/v1/keys"
        ));
        // Same host, different scheme or explicit non-default port
        assert!(!audience_covers_resource(
            "http://vouch.example.com",
            BASE,
            "/v1/keys"
        ));
        assert!(!audience_covers_resource(
            "https://vouch.example.com:8443",
            BASE,
            "/v1/keys"
        ));
    }

    #[test]
    fn test_rejects_non_uri_audience() {
        assert!(!audience_covers_resource("kubernetes", BASE, "/v1/keys"));
        assert!(!audience_covers_resource("", BASE, "/v1/keys"));
        assert!(!audience_covers_resource(
            "urn:example:resource",
            BASE,
            "/v1/keys"
        ));
    }

    #[test]
    fn test_rejects_query_and_fragment() {
        assert!(!audience_covers_resource(
            "https://vouch.example.com/v1/keys?x=1",
            BASE,
            "/v1/keys"
        ));
        assert!(!audience_covers_resource(
            "https://vouch.example.com/v1/keys#frag",
            BASE,
            "/v1/keys"
        ));
    }

    #[test]
    fn test_empty_request_path_only_covered_by_root() {
        // Cookie-only extraction passes an empty request path.
        assert!(audience_covers_resource(BASE, BASE, ""));
        assert!(!audience_covers_resource(
            "https://vouch.example.com/v1/keys",
            BASE,
            ""
        ));
    }

    #[test]
    fn test_base_url_with_path_prefix() {
        let base = "https://vouch.example.com/vouch";
        assert!(audience_covers_resource(
            "https://vouch.example.com/vouch/v1/keys",
            base,
            "/v1/keys"
        ));
        assert!(audience_covers_resource(
            "https://vouch.example.com/vouch",
            base,
            "/v1/keys"
        ));
        // aud path must extend the base path at a segment boundary
        assert!(!audience_covers_resource(
            "https://vouch.example.com/vouchextra/v1/keys",
            base,
            "/v1/keys"
        ));
        // aud outside the base path never matches
        assert!(!audience_covers_resource(
            "https://vouch.example.com/v1/keys",
            base,
            "/v1/keys"
        ));
    }
}
