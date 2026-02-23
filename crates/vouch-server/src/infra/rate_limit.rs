// SPDX-License-Identifier: BUSL-1.1
//! Rate limiting middleware using tower-governor (GCRA algorithm).
//!
//! Provides brute-force protection for authentication and token endpoints.
//! Uses the Generic Cell Rate Algorithm (GCRA) which avoids the boundary
//! burst issues of fixed-window approaches.
//!
//! # Design
//!
//! This module wraps `tower-governor` to provide a simple layer factory for
//! axum routes. Rate limiting is keyed by peer IP address (direct TCP
//! connection address).
//!
//! `tower-governor` handles its own internal state cleanup via the governor
//! crate's GCRA algorithm, so no external cleanup task is required.

use governor::clock::QuantaInstant;
use governor::middleware::NoOpMiddleware;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfig;
use tower_governor::key_extractor::PeerIpKeyExtractor;

/// Type alias for the fully-specified rate limiting layer.
pub type AuthRateLimitLayer =
    GovernorLayer<PeerIpKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;

/// Build a rate limiting layer for authentication endpoints.
///
/// Uses `PeerIpKeyExtractor` which keys on the direct TCP peer address.
///
/// Uses the `GovernorConfig::secure()` preset designed for login endpoints:
/// burst of 2 requests, replenish 1 every 4 seconds per IP. This prevents
/// brute-force attacks while allowing a user to quickly retry a mistyped
/// password once before being rate-limited.
#[must_use]
pub fn build_auth_rate_limiter() -> AuthRateLimitLayer {
    GovernorLayer::new(GovernorConfig::secure())
}
