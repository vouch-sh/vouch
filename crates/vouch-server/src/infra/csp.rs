// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Content-Security-Policy source-expression types.
//!
//! `CspOrigin` represents a CSP source expression of the form
//! `scheme://host[:port]` for use in directives like `form-action`. It is the
//! only way the CSP middleware accepts an origin, preventing arbitrary
//! `String`s (paths, javascript: URLs, etc.) from being inserted into a CSP
//! header by mistake.

use std::fmt;

/// A CSP source expression of the form `scheme://host[:port]`.
///
/// Constructed only via [`CspOrigin::from_url`] or [`CspOrigin::parse`], which
/// reject non-http(s) schemes and hostless URLs. The default port for the
/// scheme is omitted; non-default ports are preserved. IPv6 hosts are
/// bracketed; internationalized hostnames are punycode-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CspOrigin(String);

impl CspOrigin {
    /// Build from an already-parsed URL (e.g. an OIDC `authorization_endpoint`).
    ///
    /// Returns `None` for non-http(s) schemes or URLs without a host. Logs a
    /// `tracing::warn!` for the rejection so misconfiguration is visible.
    #[must_use]
    pub fn from_url(url: &url::Url) -> Option<Self> {
        let scheme = url.scheme();
        if scheme != "https" && scheme != "http" {
            tracing::warn!(
                url = %url,
                scheme = %scheme,
                "URL scheme not allowed for CSP origin; expected http(s)"
            );
            return None;
        }
        let Some(host) = url.host_str() else {
            tracing::warn!(url = %url, "URL has no host; cannot form CSP origin");
            return None;
        };
        Some(match url.port() {
            Some(port) => Self(format!("{scheme}://{host}:{port}")),
            None => Self(format!("{scheme}://{host}")),
        })
    }

    /// Parse a raw URL string (e.g. a SAML SSO URL from IdP metadata).
    ///
    /// Returns `None` for parse failures, non-http(s) schemes, or hostless
    /// URLs. Logs a `tracing::warn!` for rejection.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match url::Url::parse(raw) {
            Ok(url) => Self::from_url(&url),
            Err(err) => {
                tracing::warn!(
                    url = %raw,
                    error = %err,
                    "Failed to parse URL for CSP origin"
                );
                None
            }
        }
    }

    /// Borrow the formatted origin string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CspOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    fn parse_url(s: &str) -> url::Url {
        url::Url::parse(s).expect("test URL parses")
    }

    #[test]
    fn from_url_https_default_port() {
        let url = parse_url("https://accounts.google.com/o/oauth2/v2/auth");
        let origin = CspOrigin::from_url(&url).expect("origin");
        assert_eq!(origin.as_str(), "https://accounts.google.com");
    }

    #[test]
    fn from_url_https_explicit_default_port_is_normalized() {
        // url crate normalizes default-port URLs by stripping the port.
        let url = parse_url("https://accounts.google.com:443/o/oauth2/v2/auth");
        let origin = CspOrigin::from_url(&url).expect("origin");
        assert_eq!(origin.as_str(), "https://accounts.google.com");
    }

    #[test]
    fn from_url_https_custom_port() {
        let url = parse_url("https://idp.example.com:8443/realms/x/protocol/openid-connect/auth");
        let origin = CspOrigin::from_url(&url).expect("origin");
        assert_eq!(origin.as_str(), "https://idp.example.com:8443");
    }

    #[test]
    fn from_url_http_localhost_with_port() {
        let url = parse_url("http://localhost:8080/oauth2/auth");
        let origin = CspOrigin::from_url(&url).expect("origin");
        assert_eq!(origin.as_str(), "http://localhost:8080");
    }

    #[test]
    fn from_url_ipv6_bracketed() {
        let url = parse_url("https://[::1]:8443/auth");
        let origin = CspOrigin::from_url(&url).expect("origin");
        assert_eq!(origin.as_str(), "https://[::1]:8443");
    }

    #[test]
    fn from_url_idn_punycode() {
        // Cyrillic domain → punycode.
        let url = parse_url("https://приклад.укр/auth");
        let origin = CspOrigin::from_url(&url).expect("origin");
        assert!(
            origin.as_str().starts_with("https://xn--"),
            "expected punycode-encoded host, got: {}",
            origin.as_str()
        );
    }

    #[test]
    fn from_url_rejects_file_scheme() {
        let url = parse_url("file:///etc/passwd");
        assert!(CspOrigin::from_url(&url).is_none());
    }

    #[test]
    fn from_url_rejects_javascript_scheme() {
        let url = parse_url("javascript:alert(1)");
        assert!(CspOrigin::from_url(&url).is_none());
    }

    #[test]
    fn from_url_rejects_ftp_scheme() {
        // Scheme allowlist must be positive (http | https), not just a
        // blocklist of obviously dangerous schemes. ftp:// is a host-bearing
        // URL that would otherwise pass the host_str() guard.
        let url = parse_url("ftp://files.example.com/pub/");
        assert!(CspOrigin::from_url(&url).is_none());
    }

    #[test]
    fn from_url_rejects_ws_scheme() {
        let url = parse_url("ws://socket.example.com/");
        assert!(CspOrigin::from_url(&url).is_none());
    }

    #[test]
    fn parse_handles_invalid_urls() {
        assert!(CspOrigin::parse("not a url").is_none());
        assert!(CspOrigin::parse("").is_none());
    }

    #[test]
    fn parse_round_trips_valid_url() {
        let origin = CspOrigin::parse("https://idp.example.com/sso/post").expect("origin");
        assert_eq!(origin.as_str(), "https://idp.example.com");
    }

    #[test]
    fn display_matches_as_str() {
        let origin = CspOrigin::parse("https://idp.example.com:8443/sso").expect("origin");
        assert_eq!(format!("{origin}"), origin.as_str());
    }
}
