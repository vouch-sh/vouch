// SPDX-License-Identifier: Apache-2.0 OR MIT
//! URL security validation and host normalization.

use url::Url;

/// Result of checking whether a server URL uses secure transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlSecurity {
    /// URL uses HTTPS or targets a loopback address (safe for development).
    Secure,
    /// URL uses plain HTTP to a non-loopback host.
    InsecureHttp {
        /// The original URL that was checked.
        url: String,
    },
}

impl UrlSecurity {
    /// Returns `true` if the URL uses insecure plain HTTP to a non-local host.
    #[must_use]
    pub fn is_insecure(&self) -> bool {
        matches!(self, Self::InsecureHttp { .. })
    }
}

/// Check whether a server URL uses secure transport.
///
/// Returns [`UrlSecurity::Secure`] for HTTPS URLs and HTTP URLs targeting
/// loopback addresses (localhost, 127.0.0.0/8, [::1]). Returns
/// [`UrlSecurity::InsecureHttp`] for HTTP URLs pointing to non-loopback hosts.
///
/// Returns [`UrlSecurity::Secure`] for unparseable URLs (those will fail
/// at the HTTP client layer with a more specific error).
///
/// # Examples
///
/// ```
/// use vouch_common::{check_url_security, UrlSecurity};
///
/// assert_eq!(check_url_security("https://vouch.example.com"), UrlSecurity::Secure);
/// assert_eq!(check_url_security("http://localhost:3000"), UrlSecurity::Secure);
/// assert!(check_url_security("http://vouch.example.com").is_insecure());
/// ```
#[must_use]
pub fn check_url_security(url: &str) -> UrlSecurity {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => return UrlSecurity::Secure, // will fail at HTTP client layer
    };

    if parsed.scheme() != "http" {
        return UrlSecurity::Secure;
    }

    let host = parsed.host_str().unwrap_or_default();

    if is_loopback_host(host) {
        return UrlSecurity::Secure;
    }

    UrlSecurity::InsecureHttp {
        url: url.to_string(),
    }
}

/// Check whether a hostname refers to a loopback/localhost address.
///
/// Recognized as loopback:
/// - `localhost` (case-insensitive, per RFC 4343)
/// - `host.docker.internal` (case-insensitive, resolves to 127.0.0.1 on the host)
/// - Any IPv4 in `127.0.0.0/8` (parsed via [`std::net::Ipv4Addr::is_loopback`])
/// - IPv6 `::1` (with or without brackets)
///
/// Hostnames like `127.evil.com` are **not** treated as loopback because
/// the string is parsed as an IP address first; non-IP hostnames only match
/// the explicit `localhost` / `host.docker.internal` checks.
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if host.eq_ignore_ascii_case("host.docker.internal") {
        return true;
    }
    // Use std::net::Ipv4Addr for rigorous 127.0.0.0/8 check
    // (prevents false-exemption of hostnames like "127.evil.com")
    if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
        return addr.is_loopback();
    }
    // IPv6: url::Url::host_str() returns bracketed form like "[::1]"
    let ipv6_str = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(addr) = ipv6_str.parse::<std::net::Ipv6Addr>() {
        return addr.is_loopback();
    }
    false
}

/// Strip the default HTTPS port (`:443`) from a `host[:port]` value.
///
/// Non-standard ports are preserved so that callers matching or signing hosts
/// treat them as distinct.
#[must_use]
pub fn strip_default_https_port(host: &str) -> &str {
    host.strip_suffix(":443").unwrap_or(host)
}

/// Normalize a git credential `host` value for matching.
///
/// Git's credential protocol passes through whatever the remote URL contained,
/// so the same host can arrive as `GitHub.com`, `github.com:443`, etc. An
/// explicit default HTTPS port is stripped and the hostname ASCII-lowercased
/// (DNS names are case-insensitive per RFC 4343); comparing raw values makes a
/// credential helper silently decline requests it should serve. Non-standard
/// ports are intentionally preserved so helpers decline them.
#[must_use]
pub fn normalize_git_host(host: &str) -> String {
    strip_default_https_port(host).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_default_https_port_removes_443() {
        assert_eq!(strip_default_https_port("github.com:443"), "github.com");
    }

    #[test]
    fn strip_default_https_port_keeps_bare_host() {
        assert_eq!(strip_default_https_port("github.com"), "github.com");
    }

    #[test]
    fn strip_default_https_port_keeps_non_standard_ports() {
        assert_eq!(
            strip_default_https_port("github.com:8443"),
            "github.com:8443"
        );
        assert_eq!(strip_default_https_port("github.com:80"), "github.com:80");
    }

    #[test]
    fn normalize_git_host_lowercases() {
        assert_eq!(normalize_git_host("GitHub.com"), "github.com");
        assert_eq!(
            normalize_git_host("GIT-CODECOMMIT.US-EAST-1.AMAZONAWS.COM"),
            "git-codecommit.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn normalize_git_host_strips_port_and_lowercases() {
        assert_eq!(normalize_git_host("GitHub.com:443"), "github.com");
    }

    #[test]
    fn normalize_git_host_keeps_non_standard_ports() {
        assert_eq!(normalize_git_host("GitHub.com:8443"), "github.com:8443");
    }

    #[test]
    fn https_is_secure() {
        assert_eq!(
            check_url_security("https://vouch.example.com"),
            UrlSecurity::Secure
        );
        assert_eq!(
            check_url_security("https://vouch.example.com:8443"),
            UrlSecurity::Secure
        );
    }

    #[test]
    fn http_localhost_is_secure() {
        assert_eq!(check_url_security("http://localhost"), UrlSecurity::Secure);
        assert_eq!(
            check_url_security("http://localhost:3000"),
            UrlSecurity::Secure
        );
        assert_eq!(
            check_url_security("http://localhost:3000/path"),
            UrlSecurity::Secure
        );
    }

    #[test]
    fn http_loopback_ipv4_is_secure() {
        assert_eq!(check_url_security("http://127.0.0.1"), UrlSecurity::Secure);
        assert_eq!(
            check_url_security("http://127.0.0.1:3000"),
            UrlSecurity::Secure
        );
        assert_eq!(
            check_url_security("http://127.0.0.2:3000"),
            UrlSecurity::Secure
        );
        assert_eq!(
            check_url_security("http://127.255.255.254:3000"),
            UrlSecurity::Secure
        );
    }

    #[test]
    fn http_ipv6_loopback_is_secure() {
        assert_eq!(check_url_security("http://[::1]"), UrlSecurity::Secure);
        assert_eq!(check_url_security("http://[::1]:3000"), UrlSecurity::Secure);
    }

    #[test]
    fn http_remote_is_insecure() {
        assert!(check_url_security("http://vouch.example.com").is_insecure());
        assert!(check_url_security("http://10.0.0.1:3000").is_insecure());
        assert!(check_url_security("http://192.168.1.1:3000").is_insecure());
    }

    #[test]
    fn http_docker_internal_is_secure() {
        assert_eq!(
            check_url_security("http://host.docker.internal:3000"),
            UrlSecurity::Secure
        );
    }

    #[test]
    fn http_127_evil_com_is_insecure() {
        // Must not false-exempt hostnames starting with "127."
        assert!(check_url_security("http://127.evil.com").is_insecure());
    }

    #[test]
    fn unparseable_url_is_secure() {
        assert_eq!(check_url_security("not-a-url"), UrlSecurity::Secure);
        assert_eq!(check_url_security(""), UrlSecurity::Secure);
    }

    // =========================================================================
    // is_loopback_host() direct tests
    // =========================================================================

    #[test]
    fn loopback_localhost() {
        assert!(is_loopback_host("localhost"));
    }

    #[test]
    fn loopback_localhost_case_insensitive() {
        assert!(is_loopback_host("Localhost"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("LocalHost"));
    }

    #[test]
    fn loopback_docker_internal() {
        assert!(is_loopback_host("host.docker.internal"));
    }

    #[test]
    fn loopback_docker_internal_case_insensitive() {
        assert!(is_loopback_host("HOST.DOCKER.INTERNAL"));
        assert!(is_loopback_host("Host.Docker.Internal"));
    }

    #[test]
    fn loopback_127_0_0_1() {
        assert!(is_loopback_host("127.0.0.1"));
    }

    #[test]
    fn loopback_127_range() {
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("127.255.255.254"));
    }

    #[test]
    fn loopback_ipv6_bracketed() {
        assert!(is_loopback_host("[::1]"));
    }

    #[test]
    fn loopback_ipv6_bare() {
        assert!(is_loopback_host("::1"));
    }

    #[test]
    fn not_loopback_example_com() {
        assert!(!is_loopback_host("example.com"));
    }

    #[test]
    fn not_loopback_private_ip() {
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("192.168.1.1"));
    }

    #[test]
    fn not_loopback_127_evil_hostname() {
        assert!(!is_loopback_host("127.evil.com"));
    }

    #[test]
    fn not_loopback_empty_string() {
        assert!(!is_loopback_host(""));
    }

    #[test]
    fn not_loopback_ipv6_non_loopback() {
        assert!(!is_loopback_host("[::2]"));
        assert!(!is_loopback_host("::2"));
        assert!(!is_loopback_host("[fe80::1]"));
    }

    #[test]
    fn not_loopback_localhost_subdomain() {
        assert!(!is_loopback_host("localhost.evil.com"));
    }
}
