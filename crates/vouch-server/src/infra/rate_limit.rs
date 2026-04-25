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
use governor::middleware::StateInformationMiddleware;
use ipnet::IpNet;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::KeyExtractor;

use crate::handlers::extractors::resolve_client_ip;

/// Key extractor that resolves the real client IP behind trusted proxies.
///
/// Uses `resolve_client_ip()` to walk X-Forwarded-For when the TCP peer
/// is in the trusted CIDR set. Falls back to the TCP peer IP when no
/// trusted proxies are configured or the peer is not trusted.
#[derive(Debug, Clone)]
pub struct TrustedProxyKeyExtractor {
    trusted_cidrs: Arc<Vec<IpNet>>,
}

impl TrustedProxyKeyExtractor {
    /// Create a new extractor with the given trusted CIDR list.
    #[must_use]
    pub fn new(trusted_cidrs: Vec<IpNet>) -> Self {
        Self {
            trusted_cidrs: Arc::new(trusted_cidrs),
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
