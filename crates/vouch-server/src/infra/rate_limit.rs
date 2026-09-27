// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Rate limiting middleware using tower-governor (GCRA algorithm).
//!
//! Provides brute-force protection for authentication and token endpoints,
//! credential issuance, and general API endpoints.
//!
//! Uses the Generic Cell Rate Algorithm (GCRA) which avoids the boundary
//! burst issues of fixed-window approaches.
//!
//! # Design
//!
//! This module wraps `tower-governor` to provide a simple layer factory for
//! axum routes. Rate limiting is keyed by resolved client IP address, which
//! accounts for trusted reverse proxies (ingress controllers, Istio sidecars)
//! via the `VOUCH_TRUSTED_PROXIES` configuration.
//!
//! Three tiers are provided:
//! - **Auth**: Strict limits for login/token endpoints (burst=8, 1 req/2s per IP)
//! - **Credential**: Moderate limits for credential issuance (burst=15, 1 req/2s per IP)
//! - **General**: Relaxed limits for SCIM, admin, and authorize endpoints (burst=20, 1 req/s per IP)
//!
//! `tower-governor` handles its own internal state cleanup via the governor
//! crate's GCRA algorithm, so no external cleanup task is required.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::http::HeaderMap;
use governor::middleware::StateInformationMiddleware;
use ipnet::IpNet;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::KeyExtractor;

use crate::infra::mtls_listener;

/// Key extractor that resolves the real client IP behind trusted proxies.
///
/// Uses `resolve_client_ip()` to walk X-Forwarded-For when the TCP peer
/// is in the trusted CIDR set. Falls back to the TCP peer IP when no
/// trusted proxies are configured or the peer is not trusted.
///
/// Two trusted sets are kept side by side:
/// - `trusted_cidrs` — the HTTPS/plain port's `VOUCH_TRUSTED_PROXIES`, used
///   when the request arrived on the reverse-proxied HTTPS listener.
/// - `mtls_trusted_cidrs` — the mTLS listener's own
///   `VOUCH_MTLS_TRUSTED_PROXIES`, used when the request arrived on the mTLS
///   port. Empty for direct-mTLS deployments (no L4 proxy in front of the
///   mTLS listener), so a direct mTLS client whose TCP peer IP falls inside
///   the HTTPS port's `VOUCH_TRUSTED_PROXIES` CIDR cannot forge its
///   rate-limit bucket key via a client-supplied `X-Forwarded-For`. Set to
///   the L4 proxy's CIDR when an L4/TCP proxy fronts the mTLS listener and
///   appends to `X-Forwarded-For`.
#[derive(Debug, Clone)]
pub struct TrustedProxyKeyExtractor {
    trusted_cidrs: Arc<[IpNet]>,
    mtls_trusted_cidrs: Arc<[IpNet]>,
}

impl TrustedProxyKeyExtractor {
    /// Create a new extractor with the given trusted CIDR lists.
    ///
    /// `trusted_cidrs` is consulted for HTTPS/plain-port requests;
    /// `mtls_trusted_cidrs` is consulted for mTLS-port requests.
    #[must_use]
    pub fn new(trusted_cidrs: Vec<IpNet>, mtls_trusted_cidrs: Vec<IpNet>) -> Self {
        Self {
            trusted_cidrs: Arc::from(trusted_cidrs),
            mtls_trusted_cidrs: Arc::from(mtls_trusted_cidrs),
        }
    }
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn name(&self) -> &'static str {
        "TrustedProxyKeyExtractor"
    }

    fn extract<T>(
        &self,
        req: &http::Request<T>,
    ) -> std::result::Result<Self::Key, tower_governor::GovernorError> {
        let peer_ip = mtls_listener::peer_ip_from_extensions(req.extensions());

        // mTLS-port requests carry `ConnectInfo<PeerClientCert>`; the HTTPS
        // port carries `ConnectInfo<SocketAddr>`. A direct mTLS client's TCP
        // peer IP is the verified client IP — honoring a client-supplied
        // `X-Forwarded-For` on the mTLS port (when the peer happens to fall in
        // the HTTPS port's trusted CIDR) lets the client forge the
        // rate-limit bucket key and the audit `client_ip`. Consult the mTLS
        // listener's own (empty-able) trusted set for mTLS-port requests, and
        // the HTTPS port's `trusted_proxies` for everything else.
        let trusted = if mtls_listener::is_mtls_port_request(req.extensions()) {
            &self.mtls_trusted_cidrs
        } else {
            &self.trusted_cidrs
        };

        resolve_client_ip(peer_ip, req.headers(), trusted)
            .ok_or(tower_governor::GovernorError::UnableToExtractKey)
    }

    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.to_string())
    }
}

/// Type alias for the fully-specified rate limiting layer.
///
/// Uses `StateInformationMiddleware` to include standard rate limit headers
/// in every response:
/// - `x-ratelimit-limit`: request quota
/// - `x-ratelimit-remaining`: remaining requests in the current window
/// - `x-ratelimit-after`: seconds until quota resets (on 429 responses)
/// - `retry-after`: same as `x-ratelimit-after` (on 429 responses)
pub type RateLimitLayer =
    GovernorLayer<TrustedProxyKeyExtractor, StateInformationMiddleware, axum::body::Body>;

/// Build a governor config with the given parameters and trusted CIDRs.
///
/// `trusted_cidrs` is consulted for HTTPS/plain-port requests;
/// `mtls_trusted_cidrs` is consulted for mTLS-port requests.
///
/// # Errors
///
/// Returns an error if the governor config cannot be built (e.g.,
/// `burst_size` is zero).
fn build_config(
    per_second: u64,
    burst_size: u32,
    trusted_cidrs: &[IpNet],
    mtls_trusted_cidrs: &[IpNet],
) -> Result<
    tower_governor::governor::GovernorConfig<TrustedProxyKeyExtractor, StateInformationMiddleware>,
> {
    let extractor =
        TrustedProxyKeyExtractor::new(trusted_cidrs.to_vec(), mtls_trusted_cidrs.to_vec());
    GovernorConfigBuilder::default()
        .per_second(per_second)
        .burst_size(burst_size)
        .key_extractor(extractor)
        .use_headers()
        .finish()
        .context(
            "failed to build rate limiter config \
             (burst_size must be > 0)",
        )
}

/// Build a rate limiting layer for authentication endpoints.
///
/// Burst of 8 requests, replenish 1 every 2 seconds per IP. The FAPI 2.0
/// login flow legitimately makes several rapid requests to rate-limited
/// endpoints (register, challenge, token, DPoP nonce retry), so the burst
/// must accommodate a full login sequence while still preventing
/// brute-force.
///
/// `trusted_cidrs` is consulted for HTTPS/plain-port requests;
/// `mtls_trusted_cidrs` is consulted for mTLS-port requests.
///
/// # Errors
///
/// Returns an error if the rate limiter config cannot be built.
pub fn build_auth_rate_limiter(
    trusted_cidrs: &[IpNet],
    mtls_trusted_cidrs: &[IpNet],
) -> Result<RateLimitLayer> {
    Ok(GovernorLayer::new(build_config(
        2,
        8,
        trusted_cidrs,
        mtls_trusted_cidrs,
    )?))
}

/// Build a rate limiting layer for credential issuance endpoints.
///
/// Burst of 15 requests, replenish 1 every 2 seconds per IP.
/// kubectl spawns multiple parallel `vouch credential eks` processes
/// on startup, so the burst must accommodate concurrent requests.
///
/// `trusted_cidrs` is consulted for HTTPS/plain-port requests;
/// `mtls_trusted_cidrs` is consulted for mTLS-port requests.
///
/// # Errors
///
/// Returns an error if the rate limiter config cannot be built.
pub fn build_credential_rate_limiter(
    trusted_cidrs: &[IpNet],
    mtls_trusted_cidrs: &[IpNet],
) -> Result<RateLimitLayer> {
    Ok(GovernorLayer::new(build_config(
        2,
        15,
        trusted_cidrs,
        mtls_trusted_cidrs,
    )?))
}

/// Build a rate limiting layer for general API endpoints.
///
/// Burst of 20 requests, replenish at 1 per second per IP.
/// Used for SCIM, admin, and authorize endpoints that need protection
/// but handle diverse traffic patterns.
///
/// `trusted_cidrs` is consulted for HTTPS/plain-port requests;
/// `mtls_trusted_cidrs` is consulted for mTLS-port requests.
///
/// # Errors
///
/// Returns an error if the rate limiter config cannot be built.
pub fn build_general_rate_limiter(
    trusted_cidrs: &[IpNet],
    mtls_trusted_cidrs: &[IpNet],
) -> Result<RateLimitLayer> {
    Ok(GovernorLayer::new(build_config(
        1,
        20,
        trusted_cidrs,
        mtls_trusted_cidrs,
    )?))
}

/// Resolve the real client IP address, accounting for trusted reverse proxies.
///
/// When `trusted_cidrs` is empty, returns the TCP peer IP directly (safe for
/// servers exposed without a reverse proxy).
///
/// When `trusted_cidrs` is configured, parses `X-Forwarded-For` rightmost-first
/// and returns the first IP not in the trusted set. If the peer IP itself is not
/// trusted, `X-Forwarded-For` is ignored entirely (fail closed).
///
/// This implements the "rightmost-trusted" algorithm per RFC 7239.
pub(crate) fn resolve_client_ip(
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_cidrs: &[IpNet],
) -> Option<IpAddr> {
    // No trusted proxies configured → use TCP peer directly
    if trusted_cidrs.is_empty() {
        return peer_ip;
    }

    let peer = peer_ip?;

    // If the peer is not in the trusted set, ignore X-Forwarded-For
    if !is_trusted(peer, trusted_cidrs) {
        return Some(peer);
    }

    // Parse X-Forwarded-For header
    let xff = match headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
        Some(val) if !val.trim().is_empty() => val,
        _ => return Some(peer),
    };

    // Walk addresses right-to-left (closest proxy first)
    // Stop at the first IP not in the trusted set — that's the real client
    let addrs: Vec<&str> = xff.split(',').map(str::trim).collect();
    let mut idx = addrs.len();
    while idx > 0 {
        idx = idx.saturating_sub(1);
        let addr_str = addrs.get(idx).copied().unwrap_or("");
        if let Ok(addr) = addr_str.parse::<IpAddr>() {
            let addr = addr.to_canonical();
            if !is_trusted(addr, trusted_cidrs) {
                return Some(addr);
            }
        } else {
            // Unparseable entry — treat as untrusted boundary, stop
            break;
        }
    }

    // All XFF entries are trusted (or empty) — fall back to peer
    Some(peer)
}

/// Check if an IP address falls within any of the trusted CIDRs.
fn is_trusted(addr: IpAddr, trusted_cidrs: &[IpNet]) -> bool {
    trusted_cidrs.iter().any(|cidr| cidr.contains(&addr))
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
    // resolve_client_ip Tests
    // ========================================================================

    fn cidrs(strs: &[&str]) -> Vec<IpNet> {
        strs.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn test_resolve_no_trusted_proxies_returns_peer() {
        let headers = HeaderMap::new();
        let peer = Some("203.0.113.1".parse().unwrap());
        assert_eq!(resolve_client_ip(peer, &headers, &[]), peer);
    }

    // RFC 9700 §4.13 describes exactly this attack on a TLS-terminating
    // reverse proxy deployment: "it is standard practice of reverse proxies to
    // accept X-Forwarded-For headers and just add the origin of the inbound
    // request (making it a list). Depending on the logic performed in the
    // application server, the attacker could simply add an allowed IP address
    // to the header and render the protection useless." The section addresses
    // its "A reverse proxy MUST therefore sanitize any inbound requests" to
    // the proxy; the application-side half is that a header arriving from an
    // untrusted peer carries no weight at all.
    #[test]
    fn test_resolve_untrusted_peer_ignores_xff() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 10.0.0.5"),
        );
        let peer: IpAddr = "203.0.113.1".parse().unwrap();
        // Peer is not in 10.0.0.0/8, so XFF is ignored
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(peer)
        );
    }

    #[test]
    fn test_resolve_single_trusted_proxy() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.1, 10.0.0.5"),
        );
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let expected: IpAddr = "203.0.113.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(expected)
        );
    }

    #[test]
    fn test_resolve_multiple_trusted_proxies() {
        let trusted = cidrs(&["10.0.0.0/8", "172.16.0.0/12"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.1, 172.16.0.5, 10.0.0.5"),
        );
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let expected: IpAddr = "203.0.113.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(expected)
        );
    }

    #[test]
    fn test_resolve_empty_xff_returns_peer() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let headers = HeaderMap::new();
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(peer)
        );
    }

    #[test]
    fn test_resolve_all_xff_trusted_returns_peer() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.2, 10.0.0.3"),
        );
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(peer)
        );
    }

    #[test]
    fn test_resolve_istio_sidecar() {
        // Istio sidecar uses 127.0.0.6 as source
        let trusted = cidrs(&["127.0.0.6/32"]);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.50"));
        let peer: IpAddr = "127.0.0.6".parse().unwrap();
        let expected: IpAddr = "203.0.113.50".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(expected)
        );
    }

    #[test]
    fn test_resolve_no_peer_returns_none() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let headers = HeaderMap::new();
        assert_eq!(resolve_client_ip(None, &headers, &trusted), None);
    }

    // ========================================================================
    // TrustedProxyKeyExtractor: mTLS-port vs. HTTPS-port trusted-set selection
    // ========================================================================
    //
    // The mTLS listener and the HTTPS listener share one axum `Router`, so the
    // same `TrustedProxyKeyExtractor` runs on both ports. It must:
    // - use the HTTPS port's `trusted_proxies` for HTTPS-port requests, and
    // - use the mTLS listener's own (empty-able) `mtls_trusted_proxies` for
    //   mTLS-port requests, so a direct mTLS client whose peer IP falls inside
    //   the HTTPS port's `VOUCH_TRUSTED_PROXIES` CIDR cannot forge its
    //   rate-limit bucket key via a client-supplied `X-Forwarded-For`.
    //
    // The mTLS port is identified by the presence of
    // `ConnectInfo<PeerClientCert>` (the single connection extension axum's
    // `into_make_service_with_connect_info::<PeerClientCert>()` injects there);
    // the HTTPS port injects `ConnectInfo<SocketAddr>` instead.

    use crate::infra::mtls_listener::PeerClientCert;
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    /// Build a request shaped like the real mTLS port: only
    /// `ConnectInfo<PeerClientCert>` is injected (the HTTPS port's
    /// `ConnectInfo<SocketAddr>` is absent), matching
    /// `serve.rs`'s `into_make_service_with_connect_info::<PeerClientCert>()`.
    fn mtls_request(peer_addr: SocketAddr, xff: &str) -> http::Request<()> {
        http::Request::builder()
            .extension(ConnectInfo(PeerClientCert {
                peer_chain_der: Vec::new(),
                peer_addr,
            }))
            .header("x-forwarded-for", xff)
            .body(())
            .expect("build request")
    }

    /// Build a request shaped like the real HTTPS port: only
    /// `ConnectInfo<SocketAddr>` is injected (no `ConnectInfo<PeerClientCert>`),
    /// matching `serve.rs`'s `into_make_service_with_connect_info::<SocketAddr>()`.
    fn https_request(peer_addr: SocketAddr, xff: &str) -> http::Request<()> {
        http::Request::builder()
            .extension(ConnectInfo(peer_addr))
            .header("x-forwarded-for", xff)
            .body(())
            .expect("build request")
    }

    /// The bug report's reproducer: a direct mTLS client whose TCP peer IP
    /// (`10.0.0.50`) falls inside the operator's `VOUCH_TRUSTED_PROXIES`
    /// (`10.0.0.0/8`) supplies `X-Forwarded-For: 1.2.3.4`. The extractor must
    /// return the *verified mTLS peer IP* (`10.0.0.50`), not the forged XFF
    /// entry, because the mTLS listener has its own (empty) trusted set — a
    /// direct mTLS client is not a reverse proxy.
    #[test]
    fn mtls_extractor_returns_verified_peer_when_trusted_proxies_overlap() {
        let extractor = TrustedProxyKeyExtractor::new(
            cidrs(&["10.0.0.0/8"]), // HTTPS port trusts the proxy fleet
            Vec::new(),             // direct mTLS: no L4 proxy in front
        );
        let peer_addr: SocketAddr = "10.0.0.50:8443".parse().unwrap();
        let req = mtls_request(peer_addr, "1.2.3.4");
        let key = extractor.extract(&req).expect("extractor returns a key");
        assert_eq!(key, "10.0.0.50".parse::<IpAddr>().unwrap());
        assert_ne!(key, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    /// When an L4/TCP proxy (nginx `stream`, Envoy TCP, HAProxy TCP) fronts
    /// the mTLS listener, the operator sets `VOUCH_MTLS_TRUSTED_PROXIES` to
    /// the proxy's CIDR. The trusted-proxy XFF walk must then run on the
    /// mTLS port exactly as it does on the HTTPS port (this is the deployment
    /// the empty-by-default `mtls_trusted_proxies` exists to opt into).
    #[test]
    fn mtls_extractor_honors_xff_when_mtls_trusted_proxies_set() {
        let extractor = TrustedProxyKeyExtractor::new(
            cidrs(&["10.0.0.0/8"]), // HTTPS port (unused on the mTLS port)
            cidrs(&["10.0.0.0/8"]), // mTLS port: L4 proxy at 10.0.0.5
        );
        let peer_addr: SocketAddr = "10.0.0.5:8443".parse().unwrap();
        // Proxy supplied the real client IP.
        let req = mtls_request(peer_addr, "203.0.113.9");
        let key = extractor.extract(&req).expect("extractor returns a key");
        assert_eq!(
            key,
            "203.0.113.9".parse::<IpAddr>().unwrap(),
            "L4-proxied mTLS deployment must still walk XFF using the mTLS trusted set"
        );
    }

    /// The HTTPS port is unchanged: an HTTPS-port request whose peer is in
    /// `trusted_proxies` and whose XFF names an untrusted client resolves to
    /// that XFF entry — the long-standing reverse-proxy behavior. This pins
    /// that the mTLS-port split does not regress the HTTPS listener.
    #[test]
    fn https_extractor_honors_xff_when_peer_in_trusted_proxies() {
        let extractor = TrustedProxyKeyExtractor::new(
            cidrs(&["10.0.0.0/8"]),
            cidrs(&["127.0.0.6/32"]), // mTLS set; must NOT be consulted on the HTTPS port
        );
        let peer_addr: SocketAddr = "10.0.0.5:443".parse().unwrap();
        let req = https_request(peer_addr, "203.0.113.50");
        let key = extractor.extract(&req).expect("extractor returns a key");
        assert_eq!(key, "203.0.113.50".parse::<IpAddr>().unwrap());
    }

    /// The mTLS trusted set must not leak into the HTTPS port: an HTTPS-port
    /// request whose peer is in `mtls_trusted_proxies` but NOT in
    /// `trusted_proxies` ignores XFF and returns the peer IP (it is not a
    /// trusted proxy for the HTTPS listener).
    #[test]
    fn https_extractor_ignores_mtls_trusted_set() {
        let extractor = TrustedProxyKeyExtractor::new(
            Vec::new(),             // HTTPS port trusts nothing
            cidrs(&["10.0.0.0/8"]), // mTLS port only
        );
        let peer_addr: SocketAddr = "10.0.0.50:443".parse().unwrap();
        let req = https_request(peer_addr, "1.2.3.4");
        let key = extractor.extract(&req).expect("extractor returns a key");
        assert_eq!(
            key,
            "10.0.0.50".parse::<IpAddr>().unwrap(),
            "peer in the mTLS trusted set must not be trusted on the HTTPS port"
        );
    }

    /// Symmetric inverse: the HTTPS `trusted_proxies` set must not leak into
    /// the mTLS port. A direct mTLS client whose peer is in
    /// `trusted_proxies` with an empty `mtls_trusted_proxies` returns the
    /// peer even when XFF is also entirely trusted-address-shaped (the
    /// `resolve_client_ip` "all XFF trusted → peer" branch must not fire
    /// because the mTLS trusted set is empty and the XFF walk never starts).
    #[test]
    fn mtls_extractor_ignores_https_trusted_set() {
        let extractor = TrustedProxyKeyExtractor::new(
            cidrs(&["10.0.0.0/8", "127.0.0.6/32"]), // HTTPS port
            Vec::new(),                             // mTLS port: empty
        );
        let peer_addr: SocketAddr = "10.0.0.50:8443".parse().unwrap();
        let req = mtls_request(peer_addr, "10.0.0.2, 10.0.0.3");
        let key = extractor.extract(&req).expect("extractor returns a key");
        assert_eq!(key, "10.0.0.50".parse::<IpAddr>().unwrap());
    }

    /// When no connection extension identifies a peer, the extractor fails
    /// closed with `UnableToExtractKey` (tower-governor then answers 500).
    /// This is the pre-`b187859a` behavior for the mTLS port and the
    /// always-behavior for a request that somehow carries neither
    /// connection extension.
    #[test]
    fn extractor_fails_closed_without_peer() {
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["10.0.0.0/8"]), Vec::new());
        let req = http::Request::builder()
            .header("x-forwarded-for", "1.2.3.4")
            .body(())
            .expect("build request");
        let err = extractor.extract(&req).expect_err("no peer → error");
        assert!(
            matches!(err, tower_governor::GovernorError::UnableToExtractKey),
            "expected UnableToExtractKey, got {err:?}"
        );
    }
}
