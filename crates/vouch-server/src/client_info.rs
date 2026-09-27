// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Transport metadata of the request an audit row describes.
//!
//! [`ClientInfo`] has private fields and one production constructor: its
//! axum extractor. An audit writer that holds one therefore holds the
//! resolved peer IP and the request's headers, never a hand-assembled value
//! with the IP left out. Building one from a bare [`HeaderMap`] (which cannot
//! see the TCP peer) is private to this module.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use serde::Serialize;

use crate::AppState;
use crate::infra::mtls_listener;
use crate::infra::rate_limit::resolve_client_ip;

/// Maximum length for hostname values (RFC 1035: 253 chars).
const MAX_HOSTNAME_LEN: usize = 253;
/// Maximum length for other client metadata header values.
const MAX_CLIENT_HEADER_LEN: usize = 256;

/// Client information extracted from the request.
///
/// `client_ip` comes from the TCP socket (`ConnectInfo<SocketAddr>`), or from
/// `X-Forwarded-For` only when the peer is a configured trusted proxy. This
/// prevents IP spoofing via `X-Forwarded-For` when the server is exposed
/// directly without a trusted reverse proxy.
///
/// Serialized flat into auth-event audit rows, so the field names are the
/// stored JSON keys.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(Default))]
pub struct ClientInfo {
    /// Client IP address from the TCP peer socket (or trusted-proxy XFF).
    client_ip: Option<IpAddr>,
    /// User-Agent header.
    user_agent: Option<String>,
    /// Client hostname (from `Vouch-Client-Hostname` header).
    client_hostname: Option<String>,
    /// Client OS (from `Vouch-Client-OS` header).
    client_os: Option<String>,
    /// Client CPU architecture (from `Vouch-Client-Arch` header).
    client_arch: Option<String>,
    /// Client version (from `Vouch-Client-Version` header).
    client_version: Option<String>,
}

impl ClientInfo {
    /// The requester's IP address.
    #[must_use]
    pub fn client_ip(&self) -> Option<IpAddr> {
        self.client_ip
    }

    /// The requester's `User-Agent` header.
    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }

    /// Header-derived fields only; `client_ip` is left `None` because a
    /// `HeaderMap` cannot see the TCP peer. Private so no caller can mistake
    /// it for a complete `ClientInfo`.
    fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            client_ip: None,
            user_agent: headers
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(String::from),
            client_hostname: extract_validated_header(
                headers,
                "vouch-client-hostname",
                MAX_HOSTNAME_LEN,
            ),
            client_os: extract_validated_header(headers, "vouch-client-os", MAX_CLIENT_HEADER_LEN),
            client_arch: extract_validated_header(
                headers,
                "vouch-client-arch",
                MAX_CLIENT_HEADER_LEN,
            ),
            client_version: extract_validated_header(
                headers,
                "vouch-client-version",
                MAX_CLIENT_HEADER_LEN,
            ),
        }
    }

    /// Test constructor: header-derived fields from `headers`, and the given
    /// `client_ip` in place of the peer the extractor would resolve.
    #[cfg(test)]
    pub(crate) fn for_test(client_ip: Option<IpAddr>, headers: &HeaderMap) -> Self {
        Self {
            client_ip,
            ..Self::from_headers(headers)
        }
    }
}

impl FromRequestParts<Arc<AppState>> for ClientInfo {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let peer_ip = mtls_listener::peer_ip_from_extensions(&parts.extensions);

        let config = state.config.load();
        // mTLS-port requests resolve `client_ip` against the mTLS listener's
        // own trusted set (`VOUCH_MTLS_TRUSTED_PROXIES`, empty for direct-mTLS
        // deployments), not the HTTPS port's `VOUCH_TRUSTED_PROXIES`. A direct
        // mTLS client whose TCP peer IP falls inside the HTTPS port's trusted
        // CIDR would otherwise be treated as a trusted reverse proxy and have
        // its client-supplied `X-Forwarded-For` honored as the audit
        // `client_ip`, breaking audit attribution. See
        // `TrustedProxyKeyExtractor::extract` for the rate-limit side of the
        // same guard.
        let trusted = if mtls_listener::is_mtls_port_request(&parts.extensions) {
            &config.mtls_trusted_proxies
        } else {
            &config.trusted_proxies
        };
        let client_ip = resolve_client_ip(peer_ip, &parts.headers, trusted);

        Ok(Self {
            client_ip,
            ..Self::from_headers(&parts.headers)
        })
    }
}

/// Extract and validate a client metadata header value.
///
/// Returns `None` if the header is missing, empty, exceeds `max_len`,
/// or contains non-printable ASCII characters (control chars, null bytes).
fn extract_validated_header(headers: &HeaderMap, name: &str, max_len: usize) -> Option<String> {
    let value = headers.get(name).and_then(|h| h.to_str().ok())?;
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_len {
        return None;
    }
    if !trimmed.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // ========================================================================
    // ClientInfo Header Extraction Tests
    // ========================================================================

    #[test]
    fn test_extract_user_agent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("vouch-cli/0.1.0 (macos; aarch64)"),
        );

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.user_agent(), Some("vouch-cli/0.1.0 (macos; aarch64)"));
    }

    #[test]
    fn test_extract_no_headers() {
        let headers = HeaderMap::new();
        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_ip, None);
        assert_eq!(info.user_agent, None);
        assert_eq!(info.client_hostname, None);
        assert_eq!(info.client_os, None);
        assert_eq!(info.client_arch, None);
        assert_eq!(info.client_version, None);
    }

    // ========================================================================
    // Vouch-Client-* Header Extraction Tests
    // ========================================================================

    #[test]
    fn test_extract_vouch_client_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "vouch-client-hostname",
            HeaderValue::from_static("dev.local"),
        );
        headers.insert("vouch-client-os", HeaderValue::from_static("macos"));
        headers.insert("vouch-client-arch", HeaderValue::from_static("aarch64"));
        headers.insert("vouch-client-version", HeaderValue::from_static("1.2.3"));

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_hostname.as_deref(), Some("dev.local"));
        assert_eq!(info.client_os.as_deref(), Some("macos"));
        assert_eq!(info.client_arch.as_deref(), Some("aarch64"));
        assert_eq!(info.client_version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn test_extract_vouch_client_header_rejects_too_long() {
        let mut headers = HeaderMap::new();
        let long_value = "a".repeat(MAX_CLIENT_HEADER_LEN + 1);
        headers.insert(
            "vouch-client-os",
            HeaderValue::from_str(&long_value).unwrap(),
        );

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_vouch_client_header_rejects_empty() {
        let mut headers = HeaderMap::new();
        headers.insert("vouch-client-os", HeaderValue::from_static(""));

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_vouch_client_header_trims_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert("vouch-client-os", HeaderValue::from_static("  macos  "));

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_os.as_deref(), Some("macos"));
    }

    #[test]
    fn test_extract_vouch_client_hostname_max_length() {
        let mut headers = HeaderMap::new();
        // Exactly at the 253-char limit should be accepted
        let hostname = "a".repeat(MAX_HOSTNAME_LEN);
        headers.insert(
            "vouch-client-hostname",
            HeaderValue::from_str(&hostname).unwrap(),
        );
        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_hostname.as_deref(), Some(hostname.as_str()));

        // One over should be rejected
        let too_long = "a".repeat(MAX_HOSTNAME_LEN + 1);
        let mut headers2 = HeaderMap::new();
        headers2.insert(
            "vouch-client-hostname",
            HeaderValue::from_str(&too_long).unwrap(),
        );
        let info2 = ClientInfo::from_headers(&headers2);
        assert_eq!(info2.client_hostname, None);
    }

    #[test]
    fn test_extract_validated_header_rejects_control_chars() {
        let mut headers = HeaderMap::new();
        // Tab character (0x09) is a control character
        headers.insert(
            "vouch-client-os",
            HeaderValue::from_bytes(b"mac\tos").unwrap(),
        );

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_validated_header_accepts_printable_ascii() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "vouch-client-version",
            HeaderValue::from_static("1.2.3-beta+build.456"),
        );

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_version.as_deref(), Some("1.2.3-beta+build.456"));
    }

    // ========================================================================
    // ClientInfo extractor: mTLS-port vs. HTTPS-port trusted-set selection
    // ========================================================================
    //
    // `ClientInfo::from_request_parts` resolves `client_ip` through
    // `resolve_client_ip`. It must use the mTLS listener's own
    // (`VOUCH_MTLS_TRUSTED_PROXIES`, empty for direct-mTLS) trusted set for
    // mTLS-port requests, and the HTTPS port's (`VOUCH_TRUSTED_PROXIES`)
    // set for HTTPS-port requests — the audit-side mirror of the
    // `TrustedProxyKeyExtractor` guard. Otherwise a direct mTLS client
    // whose peer IP lands in the HTTPS port's trusted CIDR could forge the
    // audit `client_ip` to any value via `X-Forwarded-For`.

    use crate::infra::mtls_listener::PeerClientCert;
    use crate::test_utils::test_app_state;
    use axum::extract::FromRequestParts;
    use axum::http::Request;
    use axum::http::request::Parts;
    use ipnet::IpNet;
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn cidrs(strs: &[&str]) -> Vec<IpNet> {
        strs.iter().map(|s| s.parse().unwrap()).collect()
    }

    /// Build `Parts` carrying only the given connection extension plus an
    /// `X-Forwarded-For` header, matching one port's connection shape.
    fn parts_with(extension: impl Clone + Send + Sync + 'static, xff: &str) -> Parts {
        let request = Request::builder()
            .header("x-forwarded-for", xff)
            .body(())
            .expect("build request");
        let (mut parts, ()) = request.into_parts();
        parts.extensions.insert(extension);
        parts
    }

    /// Direct mTLS deployment: `trusted_proxies=10.0.0.0/8` (HTTPS port,
    /// reverse-proxied), `mtls_trusted_proxies` empty. A direct mTLS client
    /// at `10.0.0.50` supplying `X-Forwarded-For: 1.2.3.4` must record the
    /// verified mTLS peer IP as `client_ip`, not the forged XFF value.
    #[tokio::test]
    async fn mtls_port_client_info_records_verified_peer_not_xff() {
        let state = test_app_state().await;
        let mut config = (**state.config()).clone();
        config.trusted_proxies = cidrs(&["10.0.0.0/8"]);
        config.mtls_trusted_proxies = Vec::new();
        state.config.store(Arc::new(config));

        let cert = PeerClientCert {
            peer_chain_der: Vec::new(),
            peer_addr: SocketAddr::from(([10, 0, 0, 50], 8443)),
        };
        let mut parts = parts_with(axum::extract::ConnectInfo(cert), "1.2.3.4");

        let info = ClientInfo::from_request_parts(&mut parts, &state)
            .await
            .expect("ClientInfo extraction is infallible");
        assert_eq!(
            info.client_ip(),
            Some("10.0.0.50".parse().unwrap()),
            "mTLS-port audit client_ip must be the verified peer IP, not a forged XFF entry"
        );
    }

    /// L4-proxied mTLS deployment: `mtls_trusted_proxies=10.0.0.0/8` (an L4
    /// proxy at 10.0.0.5 fronts the mTLS listener). The mTLS-port audit
    /// extractor must walk `X-Forwarded-For` and record the real client IP.
    #[tokio::test]
    async fn mtls_port_client_info_honors_xff_when_mtls_trusted_proxies_set() {
        let state = test_app_state().await;
        let mut config = (**state.config()).clone();
        config.trusted_proxies = Vec::new();
        config.mtls_trusted_proxies = cidrs(&["10.0.0.0/8"]);
        state.config.store(Arc::new(config));

        let cert = PeerClientCert {
            peer_chain_der: Vec::new(),
            peer_addr: SocketAddr::from(([10, 0, 0, 5], 8443)),
        };
        let mut parts = parts_with(axum::extract::ConnectInfo(cert), "203.0.113.9");

        let info = ClientInfo::from_request_parts(&mut parts, &state)
            .await
            .expect("ClientInfo extraction is infallible");
        assert_eq!(
            info.client_ip(),
            Some("203.0.113.9".parse().unwrap()),
            "L4-proxied mTLS deployment must walk XFF using the mTLS trusted set for audit"
        );
    }

    /// HTTPS port unchanged: an HTTPS-port request whose peer is in
    /// `trusted_proxies` and whose XFF names an untrusted client records that
    /// XFF entry as `client_ip` — the long-standing reverse-proxy behavior.
    /// Pins that the mTLS-port split does not regress the HTTPS listener's
    /// audit attribution.
    #[tokio::test]
    async fn https_port_client_info_honors_xff_when_peer_in_trusted_proxies() {
        let state = test_app_state().await;
        let mut config = (**state.config()).clone();
        config.trusted_proxies = cidrs(&["10.0.0.0/8"]);
        config.mtls_trusted_proxies = cidrs(&["127.0.0.6/32"]); // must NOT leak to HTTPS
        state.config.store(Arc::new(config));

        let mut parts = parts_with(
            axum::extract::ConnectInfo(SocketAddr::from(([10, 0, 0, 5], 443))),
            "203.0.113.50",
        );

        let info = ClientInfo::from_request_parts(&mut parts, &state)
            .await
            .expect("ClientInfo extraction is infallible");
        assert_eq!(
            info.client_ip(),
            Some("203.0.113.50".parse().unwrap()),
            "HTTPS-port audit client_ip must honor XFF via trusted_proxies"
        );
    }

    /// The mTLS trusted set must not leak into the HTTPS port: an HTTPS-port
    /// request whose peer is in `mtls_trusted_proxies` but NOT in
    /// `trusted_proxies` ignores XFF and records the peer IP.
    #[tokio::test]
    async fn https_port_client_info_ignores_mtls_trusted_set() {
        let state = test_app_state().await;
        let mut config = (**state.config()).clone();
        config.trusted_proxies = Vec::new();
        config.mtls_trusted_proxies = cidrs(&["10.0.0.0/8"]);
        state.config.store(Arc::new(config));

        let mut parts = parts_with(
            axum::extract::ConnectInfo(SocketAddr::from(([10, 0, 0, 50], 443))),
            "1.2.3.4",
        );

        let info = ClientInfo::from_request_parts(&mut parts, &state)
            .await
            .expect("ClientInfo extraction is infallible");
        assert_eq!(
            info.client_ip(),
            Some("10.0.0.50".parse().unwrap()),
            "HTTPS-port audit client_ip must not consult the mTLS trusted set"
        );
    }
}
