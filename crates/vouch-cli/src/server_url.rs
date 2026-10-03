// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Validated server URL type.
//!
//! [`ServerUrl`] wraps a URL string that has been validated for scheme security
//! (HTTPS required for non-loopback hosts) and normalized (trailing slashes trimmed).

use std::fmt;

use vouch_common::UrlSecurity;

/// A validated, normalized Vouch server URL.
///
/// Guarantees:
/// - The URL is syntactically valid
/// - HTTPS is used for non-loopback hosts (unless `allow_insecure` was set)
/// - Trailing slashes are trimmed
///
/// Construct via [`ServerUrl::parse`].
#[derive(Debug, Clone)]
pub struct ServerUrl {
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
    pub fn parse(url: &str, allow_insecure: bool) -> Result<Self, ServerUrlError> {
        if url.is_empty() {
            return Err(ServerUrlError::Empty);
        }

        // Validate URL syntax
        let _parsed = url::Url::parse(url).map_err(|e| ServerUrlError::Invalid(e.to_string()))?;

        // Check scheme security
        match vouch_common::check_url_security(url) {
            UrlSecurity::Secure => {}
            UrlSecurity::InsecureHttp { url: insecure_url } => {
                if allow_insecure {
                    crate::tr_eprintln!("server-url-warn-insecure", url = insecure_url.as_str());
                    // Trailing blank line to set the warning apart visually.
                    eprintln!();
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
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// Whether the stored URL `raw` names this server: the same URL once
    /// trailing slashes are trimmed, as [`Self::parse`] normalizes.
    pub fn names(&self, raw: &str) -> bool {
        raw.trim_end_matches('/') == self.url
    }

    /// Whether `rp_id` is one this server may ask an authenticator to sign for.
    ///
    /// WebAuthn Level 2 §5.1.3 lets a relying party name its origin's effective
    /// domain or a registrable domain suffix of it, so a server may name its own
    /// host or a parent domain of it, and nothing else. A browser enforces that
    /// against the page origin. The CLI has no page origin, so the comparison is
    /// made against the server URL this invocation chose.
    ///
    /// Taking the `rp_id` from the challenge unchecked would let a server hand
    /// back another deployment's `rp_id`: the authenticator would then produce an
    /// assertion valid for that deployment, which is the relay this check closes.
    pub fn accepts_rp_id(&self, rp_id: &str) -> bool {
        if rp_id.is_empty() {
            return false;
        }
        let Ok(parsed) = url::Url::parse(&self.url) else {
            return false;
        };
        let Some(host) = parsed.host_str() else {
            return false;
        };
        let host = host.to_ascii_lowercase();
        let rp_id = rp_id.to_ascii_lowercase();
        if host == rp_id {
            return true;
        }
        // A parent domain only: the remainder must end at a label boundary, so
        // `evil-vouch.sh` does not pass for an `rp_id` of `vouch.sh`.
        host.strip_suffix(&rp_id)
            .is_some_and(|rest| rest.ends_with('.'))
    }

    /// Whether `url` is on this server: the same scheme, host, and port, and
    /// a path at or below this URL's path. Used before sending a credential
    /// to a URL the server returned earlier (RFC 7592 `registration_client_uri`).
    pub fn contains(&self, url: &str) -> bool {
        let (Ok(base), Ok(other)) = (url::Url::parse(&self.url), url::Url::parse(url)) else {
            return false;
        };
        if base.scheme() != other.scheme()
            || base.host() != other.host()
            || base.port_or_known_default() != other.port_or_known_default()
        {
            return false;
        }
        let base_path = base.path().trim_end_matches('/');
        let path = other.path();
        path == base_path
            || path
                .strip_prefix(base_path)
                .is_some_and(|rest| rest.starts_with('/'))
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

/// Where this invocation's opt-in to a plain-HTTP server URL comes from.
///
/// Every server URL a token is sent to is judged per invocation, never on
/// the strength of an opt-in given when the URL was stored at login.
#[derive(Debug, Clone, Copy)]
pub enum InsecureOptIn {
    /// A subcommand: clap has already merged `--allow-insecure` and
    /// `VOUCH_ALLOW_INSECURE` into this value.
    Cli(bool),
    /// A helper binary (`docker-credential-vouch`, `git-remote-codecommit`,
    /// `keyring`, `vouch-pnpm-tokenhelper`). These are dispatched on argv0
    /// before clap parses and are run by other tools through argument-less
    /// symlinks, so `VOUCH_ALLOW_INSECURE` in the calling tool's environment
    /// is the only opt-in. It is read when a URL is judged, so a helper
    /// operation that never contacts the server does not fail on it.
    Env,
}

impl InsecureOptIn {
    /// Whether a plain-HTTP URL to a non-loopback host is allowed.
    ///
    /// # Errors
    ///
    /// Returns [`ServerUrlError::OptIn`] when `VOUCH_ALLOW_INSECURE` holds a
    /// value that is neither on nor off; it is never read as either.
    pub fn allowed(self) -> Result<bool, ServerUrlError> {
        match self {
            Self::Cli(allowed) => Ok(allowed),
            Self::Env => vouch_common::allow_insecure_from_env().map_err(ServerUrlError::OptIn),
        }
    }
}

/// Errors from [`ServerUrl::parse`].
#[derive(Debug)]
pub enum ServerUrlError {
    /// The URL string was empty.
    Empty,

    /// The URL could not be parsed.
    Invalid(String),

    /// The URL uses HTTP for a non-loopback host.
    InsecureHttp(String),

    /// `VOUCH_ALLOW_INSECURE` could not be read as on or off. The message is
    /// the environment parser's own, shown verbatim like other environment
    /// errors.
    OptIn(String),
}

impl ServerUrlError {
    /// Whether `e` is a server URL judged unusable for this invocation, as
    /// opposed to there being no stored session at all. Credential helpers
    /// use it to show the URL's own message instead of "not configured".
    pub fn is_in(e: &anyhow::Error) -> bool {
        e.downcast_ref::<Self>().is_some()
    }
}

impl std::fmt::Display for ServerUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "{}", crate::tr!("server-url-err-empty")),
            Self::Invalid(detail) => {
                write!(
                    f,
                    "{}",
                    crate::tr_args!("server-url-err-invalid", detail = detail.as_str())
                )
            }
            Self::InsecureHttp(url) => {
                write!(
                    f,
                    "{}",
                    crate::tr_args!("server-url-err-insecure-http", url = url.as_str())
                )
            }
            Self::OptIn(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for ServerUrlError {}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn contains_accepts_paths_on_the_same_server() {
        let server = ServerUrl::parse("https://vouch.example.com", false).unwrap();
        assert!(server.contains("https://vouch.example.com/oauth/register/abc"));
        assert!(server.contains("https://vouch.example.com:443/oauth/register/abc"));
    }

    #[test]
    fn contains_rejects_other_servers() {
        let server = ServerUrl::parse("https://vouch.example.com", false).unwrap();
        // Another host, a look-alike host, a downgraded scheme, another port.
        assert!(!server.contains("https://attacker.example/oauth/register/abc"));
        assert!(!server.contains("https://vouch.example.com.attacker.example/x"));
        assert!(!server.contains("http://vouch.example.com/oauth/register/abc"));
        assert!(!server.contains("https://vouch.example.com:8443/oauth/register/abc"));
        assert!(!server.contains("not a url"));
    }

    #[test]
    fn contains_respects_a_base_path() {
        let server = ServerUrl::parse("https://example.com/vouch", false).unwrap();
        assert!(server.contains("https://example.com/vouch/oauth/register/abc"));
        assert!(!server.contains("https://example.com/vouchers/oauth/register"));
        assert!(!server.contains("https://example.com/other"));
    }

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
    fn error_display_resolves_from_catalog() {
        assert_eq!(ServerUrlError::Empty.to_string(), "server URL is empty");
        assert_eq!(
            ServerUrlError::Invalid("bad".to_string()).to_string(),
            "invalid server URL: bad"
        );
        let msg = ServerUrlError::InsecureHttp("http://x".to_string()).to_string();
        assert!(
            msg.contains("Server URL uses plain HTTP (http://x)."),
            "{msg}"
        );
        assert!(
            msg.contains("Credentials would be sent in plaintext."),
            "{msg}"
        );
        assert!(
            msg.contains("--allow-insecure / VOUCH_ALLOW_INSECURE=1"),
            "{msg}"
        );
        assert!(
            msg.contains("plaintext.\n\nUse an https://"),
            "blank line between paragraphs must survive Fluent round-trip: {msg:?}"
        );
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

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod rp_id_tests {
    use super::ServerUrl;

    fn server(url: &str) -> ServerUrl {
        ServerUrl::parse(url, true).expect("valid test URL")
    }

    /// WebAuthn Level 2 §5.1.3: the relying party may name its origin's
    /// effective domain.
    #[test]
    fn accepts_the_server_host_itself() {
        assert!(server("https://us.vouch.sh").accepts_rp_id("us.vouch.sh"));
    }

    /// The same section permits a registrable domain suffix, so a parent
    /// domain of the server host is legitimate.
    #[test]
    fn accepts_a_parent_domain() {
        assert!(server("https://us.vouch.sh").accepts_rp_id("vouch.sh"));
    }

    /// The suffix must end on a label boundary. Without that check a
    /// look-alike host would pass for the real registrable domain.
    #[test]
    fn rejects_a_suffix_that_is_not_a_label_boundary() {
        assert!(!server("https://evil-vouch.sh").accepts_rp_id("vouch.sh"));
    }

    /// A child domain is the wrong direction: the authenticator would scope
    /// the credential more narrowly than the origin.
    #[test]
    fn rejects_a_child_domain() {
        assert!(!server("https://vouch.sh").accepts_rp_id("us.vouch.sh"));
    }

    /// An unrelated host is the relay this check exists to stop.
    #[test]
    fn rejects_an_unrelated_host() {
        assert!(!server("https://attacker.example").accepts_rp_id("us.vouch.sh"));
    }

    /// Host names are case-insensitive.
    #[test]
    fn comparison_ignores_case() {
        assert!(server("https://US.Vouch.SH").accepts_rp_id("us.vouch.sh"));
        assert!(server("https://us.vouch.sh").accepts_rp_id("US.VOUCH.SH"));
    }

    /// An empty `rp_id` must not strip to a passing suffix.
    #[test]
    fn rejects_empty_rp_id() {
        assert!(!server("https://us.vouch.sh").accepts_rp_id(""));
    }

    /// Local development: the loopback host is its own relying party, and the
    /// port is not part of an `rp_id`.
    #[test]
    fn accepts_loopback_host_ignoring_port() {
        assert!(server("http://localhost:8080").accepts_rp_id("localhost"));
        assert!(!server("http://localhost:8080").accepts_rp_id("vouch.sh"));
    }
}
