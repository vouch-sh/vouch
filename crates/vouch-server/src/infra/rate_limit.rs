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
//! Three tiers are provided, as [`RateLimitTier`] constants:
//! - **Auth**: Strict limits for login/token endpoints (burst=8, 1 req/2s per client)
//! - **Credential**: Moderate limits for credential issuance (burst=15, 1 req/2s per client)
//! - **General**: Relaxed limits for SCIM, admin, and authorize endpoints (burst=20, 1 req/s per client)
//!
//! A client is a [`ClientBucket`]: an IPv4 address, or an IPv6 /64, since one
//! host can use a whole /64. The connection caps in `infra/conn_caps.rs` count
//! clients the same way.
//!
//! `governor` keeps one state entry per client and never drops one on its
//! own: only `RateLimiter::retain_recent` removes the entries of clients that
//! have gone idle. Each tier's layer prunes its limiter on a timer, so the map
//! holds the clients seen recently rather than every client since startup.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

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
/// Keys on [`client_ip_from_request`]: the TCP peer IP, or on the HTTPS/plain
/// port the X-Forwarded-For client when the peer is a trusted proxy.
#[derive(Debug, Clone)]
pub struct TrustedProxyKeyExtractor {
    trusted_cidrs: Arc<[IpNet]>,
}

impl TrustedProxyKeyExtractor {
    /// Create a new extractor with the given trusted CIDR list.
    #[must_use]
    pub fn new(trusted_cidrs: Vec<IpNet>) -> Self {
        Self {
            trusted_cidrs: Arc::from(trusted_cidrs),
        }
    }
}

/// The client a rate limit or connection cap counts a request under: an
/// IPv4 address as is, an IPv6 address by its /64, since one host can use a
/// whole /64 and would otherwise get a separate allowance for every address
/// in it. An IPv4-mapped IPv6 address is its IPv4 client, not a member of
/// the one /64 every mapped address shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientBucket(IpAddr);

impl From<IpAddr> for ClientBucket {
    fn from(ip: IpAddr) -> Self {
        const PREFIX_64: u128 = 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000;
        Self(match ip.to_canonical() {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & PREFIX_64)),
        })
    }
}

impl std::fmt::Display for ClientBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            IpAddr::V4(v4) => v4.fmt(f),
            IpAddr::V6(v6) => write!(f, "{v6}/64"),
        }
    }
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = ClientBucket;

    fn name(&self) -> &'static str {
        "TrustedProxyKeyExtractor"
    }

    fn extract<T>(
        &self,
        req: &http::Request<T>,
    ) -> std::result::Result<Self::Key, tower_governor::GovernorError> {
        client_ip_from_request(req.extensions(), req.headers(), &self.trusted_cidrs)
            .map(ClientBucket::from)
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

/// The governor config behind a [`RateLimitLayer`].
type RateLimitConfig =
    tower_governor::governor::GovernorConfig<TrustedProxyKeyExtractor, StateInformationMiddleware>;

/// How often each tier's limiter drops the entries of idle clients.
///
/// An entry is idle once its client's full burst has replenished (16 s for
/// the auth tier, the slowest), after which it holds nothing a fresh entry
/// would not; pruning a minute later bounds the map by the clients seen in
/// the last minute or so.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// A rate-limit tier: one request replenished every `period`, up to `burst`
/// held in reserve, per [`ClientBucket`].
#[derive(Debug, Clone, Copy)]
pub struct RateLimitTier {
    period: Duration,
    burst: u32,
}

impl RateLimitTier {
    /// Authentication endpoints: burst of 8, one every 2 seconds. The FAPI
    /// 2.0 login flow legitimately makes several rapid requests to
    /// rate-limited endpoints (register, challenge, token, DPoP nonce
    /// retry), so the burst must accommodate a full login sequence while
    /// still preventing brute-force.
    pub const AUTH: Self = Self {
        period: Duration::from_secs(2),
        burst: 8,
    };

    /// Credential issuance: burst of 15, one every 2 seconds. kubectl spawns
    /// multiple parallel `vouch credential eks` processes on startup, so the
    /// burst must accommodate concurrent requests.
    pub const CREDENTIAL: Self = Self {
        period: Duration::from_secs(2),
        burst: 15,
    };

    /// General API endpoints: burst of 20, one per second. Used for SCIM,
    /// admin, and authorize endpoints that need protection but handle
    /// diverse traffic patterns.
    pub const GENERAL: Self = Self {
        period: Duration::from_secs(1),
        burst: 20,
    };

    /// A layer enforcing this tier, keyed by the client behind any trusted
    /// proxy in `trusted_cidrs`.
    ///
    /// Must run inside a Tokio runtime; see [`Self::config`].
    ///
    /// # Errors
    ///
    /// Returns an error if the governor config cannot be built (e.g. a
    /// zero burst).
    pub fn layer(self, trusted_cidrs: &[IpNet]) -> Result<RateLimitLayer> {
        Ok(GovernorLayer::new(self.config(trusted_cidrs)?))
    }

    /// This tier's governor config, with a task that prunes its limiter's
    /// idle entries every [`PRUNE_INTERVAL`] and ends once the config is
    /// dropped. Must run inside a Tokio runtime, which spawns the task.
    fn config(self, trusted_cidrs: &[IpNet]) -> Result<Arc<RateLimitConfig>> {
        let config = GovernorConfigBuilder::default()
            .period(self.period)
            .burst_size(self.burst)
            .key_extractor(TrustedProxyKeyExtractor::new(trusted_cidrs.to_vec()))
            .use_headers()
            .finish()
            .context("failed to build rate limiter config (burst_size must be > 0)")?;
        let limiter = Arc::downgrade(config.limiter());
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(PRUNE_INTERVAL);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticks.tick().await;
            loop {
                ticks.tick().await;
                let Some(limiter) = limiter.upgrade() else {
                    return;
                };
                limiter.retain_recent();
                limiter.shrink_to_fit();
            }
        });
        Ok(Arc::new(config))
    }
}

/// Resolve the client IP of a request, accounting for trusted reverse proxies.
///
/// The only crate-visible way to turn a request into a client IP: both the
/// rate-limit key and the audit `client_ip` come from here, so they cannot
/// disagree about which listener may carry a trusted `X-Forwarded-For`.
///
/// On the mTLS port the peer IP is returned as-is. `VOUCH_TRUSTED_PROXIES`
/// describes the HTTPS port's reverse proxies, and no proxy can add a header
/// to a TLS session Vouch terminates itself (see [`ConnectionPeer::Mtls`]).
/// Walking the header there would let a direct mTLS client whose address
/// falls inside that CIDR choose its own rate-limit bucket and audit address.
///
/// [`ConnectionPeer::Mtls`]: mtls_listener::ConnectionPeer::Mtls
pub(crate) fn client_ip_from_request(
    extensions: &axum::http::Extensions,
    headers: &HeaderMap,
    trusted_cidrs: &[IpNet],
) -> Option<IpAddr> {
    match mtls_listener::connection_peer(extensions)? {
        mtls_listener::ConnectionPeer::Tcp(peer) => {
            resolve_client_ip(Some(peer), headers, trusted_cidrs)
        }
        mtls_listener::ConnectionPeer::Mtls(peer) => Some(peer),
    }
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
fn resolve_client_ip(
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
    // client_ip_from_request Tests
    // ========================================================================

    fn forwarded_for(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static(value));
        headers
    }

    #[test]
    fn test_client_ip_from_request_tcp_peer_walks_forwarded_for() {
        let mut ext = http::Extensions::new();
        ext.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [10, 0, 0, 5],
            443,
        ))));
        assert_eq!(
            client_ip_from_request(
                &ext,
                &forwarded_for("203.0.113.50"),
                &cidrs(&["10.0.0.0/8"])
            ),
            Some("203.0.113.50".parse().unwrap())
        );
    }

    #[test]
    fn test_client_ip_from_request_mtls_peer_ignores_forwarded_for() {
        let mut ext = http::Extensions::new();
        ext.insert(axum::extract::ConnectInfo(mtls_listener::PeerClientCert {
            peer_chain_der: Vec::new(),
            peer_addr: std::net::SocketAddr::from(([10, 0, 0, 50], 8443)),
        }));
        assert_eq!(
            client_ip_from_request(&ext, &forwarded_for("1.2.3.4"), &cidrs(&["10.0.0.0/8"])),
            Some("10.0.0.50".parse().unwrap()),
            "a direct mTLS client inside VOUCH_TRUSTED_PROXIES must not choose its own address"
        );
    }

    #[test]
    fn test_client_ip_from_request_no_connection_info_returns_none() {
        let ext = http::Extensions::new();
        assert_eq!(
            client_ip_from_request(&ext, &forwarded_for("1.2.3.4"), &cidrs(&["10.0.0.0/8"])),
            None
        );
    }

    // ========================================================================
    // ClientBucket and the tiers
    // ========================================================================

    fn bucket(ip: &str) -> ClientBucket {
        ClientBucket::from(ip.parse::<IpAddr>().unwrap())
    }

    #[test]
    fn ipv6_addresses_in_one_64_share_a_bucket() {
        assert_eq!(bucket("2001:db8:1:2::1"), bucket("2001:db8:1:2:ffff::9"));
        assert_ne!(bucket("2001:db8:1:2::1"), bucket("2001:db8:1:3::1"));
        assert_eq!(bucket("2001:db8:1:2::1").to_string(), "2001:db8:1:2::/64");
    }

    #[test]
    fn ipv4_addresses_are_their_own_bucket() {
        assert_ne!(bucket("203.0.113.1"), bucket("203.0.113.2"));
        assert_eq!(bucket("203.0.113.1").to_string(), "203.0.113.1");
    }

    #[test]
    fn ipv4_mapped_ipv6_is_its_ipv4_bucket() {
        assert_eq!(bucket("::ffff:203.0.113.1"), bucket("203.0.113.1"));
        assert_ne!(bucket("::ffff:203.0.113.1"), bucket("::ffff:203.0.113.2"));
    }

    /// A request to `/` from `peer`, carrying the connection info the
    /// application listener attaches.
    fn request_from(peer: IpAddr) -> http::Request<axum::body::Body> {
        let mut request = http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(
                peer, 443,
            )));
        request
    }

    async fn status_for(app: &axum::Router, peer: IpAddr) -> http::StatusCode {
        use tower::ServiceExt;
        app.clone()
            .oneshot(request_from(peer))
            .await
            .unwrap()
            .status()
    }

    fn limited(layer: RateLimitLayer) -> axum::Router {
        axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(layer)
    }

    // The auth tier allows a burst of 8. A host that spreads its requests over
    // its /64 gets the same eight, not eight per address.
    #[tokio::test]
    async fn auth_tier_limits_one_ipv6_64_as_one_client() {
        let app = limited(RateLimitTier::AUTH.layer(&[]).unwrap());
        let mut statuses = Vec::new();
        for host in 1..=12u16 {
            let peer = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, host));
            statuses.push(status_for(&app, peer).await);
        }
        let limited_count = statuses
            .iter()
            .filter(|s| **s == http::StatusCode::TOO_MANY_REQUESTS)
            .count();
        assert_eq!(limited_count, 4, "{statuses:?}");
    }

    // governor drops an entry only in `retain_recent`. With a 1 ns period an
    // entry is idle as soon as it is made, on governor's own clock; the prune
    // timer runs on Tokio's, which the paused runtime advances.
    #[tokio::test(start_paused = true)]
    async fn tier_prunes_idle_client_entries() {
        let tier = RateLimitTier {
            period: Duration::from_nanos(1),
            burst: 1,
        };
        let config = tier.config(&[]).unwrap();
        let app = limited(GovernorLayer::new(Arc::clone(&config)));
        for host in 1..=50u8 {
            status_for(&app, IpAddr::from([198, 51, 100, host])).await;
        }
        assert_eq!(config.limiter().len(), 50, "one entry per client");

        tokio::time::sleep(PRUNE_INTERVAL.saturating_add(Duration::from_secs(1))).await;
        tokio::task::yield_now().await;
        assert_eq!(config.limiter().len(), 0, "idle entries are pruned");
    }
}
