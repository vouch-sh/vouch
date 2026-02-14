// SPDX-License-Identifier: Apache-2.0 OR MIT
//! URL security validation for server connections.

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
fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn http_127_evil_com_is_insecure() {
        // Must not false-exempt hostnames starting with "127."
        assert!(check_url_security("http://127.evil.com").is_insecure());
    }

    #[test]
    fn unparseable_url_is_secure() {
        assert_eq!(check_url_security("not-a-url"), UrlSecurity::Secure);
        assert_eq!(check_url_security(""), UrlSecurity::Secure);
    }
}
