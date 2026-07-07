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

/// Key extractor that resolves the real client IP behind trusted proxies.
///
/// Uses `resolve_client_ip()` to walk X-Forwarded-For when the TCP peer
/// is in the trusted CIDR set. Falls back to the TCP peer IP when no
/// trusted proxies are configured or the peer is not trusted.
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

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn name(&self) -> &'static str {
        "TrustedProxyKeyExtractor"
    }

    fn extract<T>(
        &self,
        req: &http::Request<T>,
    ) -> std::result::Result<Self::Key, tower_governor::GovernorError> {
        let peer_ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip().to_canonical());

        resolve_client_ip(peer_ip, req.headers(), &self.trusted_cidrs)
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
/// # Errors
///
/// Returns an error if the governor config cannot be built (e.g.,
/// `burst_size` is zero).
fn build_config(
    per_second: u64,
    burst_size: u32,
    trusted_cidrs: &[IpNet],
) -> Result<
    tower_governor::governor::GovernorConfig<TrustedProxyKeyExtractor, StateInformationMiddleware>,
> {
    let extractor = TrustedProxyKeyExtractor::new(trusted_cidrs.to_vec());
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
/// # Errors
///
/// Returns an error if the rate limiter config cannot be built.
pub fn build_auth_rate_limiter(trusted_cidrs: &[IpNet]) -> Result<RateLimitLayer> {
    Ok(GovernorLayer::new(build_config(2, 8, trusted_cidrs)?))
}

/// Build a rate limiting layer for credential issuance endpoints.
///
/// Burst of 15 requests, replenish 1 every 2 seconds per IP.
/// kubectl spawns multiple parallel `vouch credential eks` processes
/// on startup, so the burst must accommodate concurrent requests.
///
/// # Errors
///
/// Returns an error if the rate limiter config cannot be built.
pub fn build_credential_rate_limiter(trusted_cidrs: &[IpNet]) -> Result<RateLimitLayer> {
    Ok(GovernorLayer::new(build_config(2, 15, trusted_cidrs)?))
}

/// Build a rate limiting layer for general API endpoints.
///
/// Burst of 20 requests, replenish at 1 per second per IP.
/// Used for SCIM, admin, and authorize endpoints that need protection
/// but handle diverse traffic patterns.
///
/// # Errors
///
/// Returns an error if the rate limiter config cannot be built.
pub fn build_general_rate_limiter(trusted_cidrs: &[IpNet]) -> Result<RateLimitLayer> {
    Ok(GovernorLayer::new(build_config(1, 20, trusted_cidrs)?))
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
}
