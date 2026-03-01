// SPDX-License-Identifier: BUSL-1.1
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
//! axum routes. Rate limiting is keyed by peer IP address (direct TCP
//! connection address).
//!
//! Three tiers are provided:
//! - **Auth**: Strict limits for login/token endpoints (burst=8, 1 req/2s per IP)
//! - **Credential**: Moderate limits for credential issuance (burst=15, 1 req/2s per IP)
//! - **General**: Relaxed limits for SCIM, admin, and authorize endpoints (burst=20, 1 req/s per IP)
//!
//! `tower-governor` handles its own internal state cleanup via the governor
//! crate's GCRA algorithm, so no external cleanup task is required.

use governor::middleware::StateInformationMiddleware;
use tower_governor::GovernorLayer;
use tower_governor::governor::{GovernorConfig, GovernorConfigBuilder};
use tower_governor::key_extractor::PeerIpKeyExtractor;

/// Type alias for the fully-specified rate limiting layer.
///
/// Uses `StateInformationMiddleware` to include standard rate limit headers
/// in every response:
/// - `x-ratelimit-limit`: request quota
/// - `x-ratelimit-remaining`: remaining requests in the current window
/// - `x-ratelimit-after`: seconds until quota resets (on 429 responses)
/// - `retry-after`: same as `x-ratelimit-after` (on 429 responses)
pub type RateLimitLayer =
    GovernorLayer<PeerIpKeyExtractor, StateInformationMiddleware, axum::body::Body>;

/// Build a rate limiting layer for authentication endpoints.
///
/// Uses `PeerIpKeyExtractor` which keys on the direct TCP peer address.
///
/// Burst of 8 requests, replenish 1 every 2 seconds per IP. The FAPI 2.0
/// login flow legitimately makes several rapid requests to rate-limited
/// endpoints (register, challenge, token, DPoP nonce retry), so the burst
/// must accommodate a full login sequence while still preventing brute-force.
#[must_use]
pub fn build_auth_rate_limiter() -> RateLimitLayer {
    let config = GovernorConfigBuilder::default()
        .per_second(2)
        .burst_size(8)
        .use_headers()
        .finish()
        .unwrap_or_else(|| {
            tracing::warn!(
                "Failed to build auth rate limiter config, \
                 falling back to secure defaults"
            );
            GovernorConfig::secure()
        });
    GovernorLayer::new(config)
}

/// Build a rate limiting layer for credential issuance endpoints.
///
/// Burst of 15 requests, replenish 1 every 2 seconds per IP.
/// kubectl spawns multiple parallel `vouch credential eks` processes
/// on startup, so the burst must accommodate concurrent requests.
#[must_use]
pub fn build_credential_rate_limiter() -> RateLimitLayer {
    let config = GovernorConfigBuilder::default()
        .per_second(2)
        .burst_size(15)
        .use_headers()
        .finish()
        .unwrap_or_else(|| {
            tracing::warn!(
                "Failed to build credential rate limiter config, falling back to secure defaults"
            );
            GovernorConfig::secure()
        });
    GovernorLayer::new(config)
}

/// Build a rate limiting layer for general API endpoints.
///
/// Burst of 20 requests, replenish at 1 per second per IP.
/// Used for SCIM, admin, and authorize endpoints that need protection
/// but handle diverse traffic patterns.
#[must_use]
pub fn build_general_rate_limiter() -> RateLimitLayer {
    let config = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(20)
        .use_headers()
        .finish()
        .unwrap_or_else(|| {
            tracing::warn!(
                "Failed to build general rate limiter config, falling back to secure defaults"
            );
            GovernorConfig::secure()
        });
    GovernorLayer::new(config)
}
