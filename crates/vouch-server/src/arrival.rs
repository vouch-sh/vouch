// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The instant a request arrived, stamped once and passed down explicitly.
//!
//! Every time comparison serving a single request decision reads the same
//! instant: [`arrival_layer`] stamps it at the outermost layer of the router
//! and handlers receive it through the [`ArrivalTime`] extractor. Without a
//! shared origin, two comparisons belonging to one decision observe instants
//! separated by however long the awaits between them took, and the gap is a
//! window — an exchanged token outliving its subject by the inter-read delta,
//! or a replay record retired while its proof is still fresh.
//!
//! Construction is private to this module, so an `ArrivalTime` parameter is
//! evidence that the value came from the middleware rather than from a fresh
//! `Timestamp::now()` at the call site — the same witness pattern as
//! [`crate::crypto::webauthn_verify::AuthTime`].
//!
//! # Which clock a comparison uses
//!
//! - Request-scoped validation (JWT and Request Object temporal claims, DPoP
//!   freshness, the RFC 8693 lifetime cap, session expiry) → `ArrivalTime`.
//! - Optimistic-concurrency commit preconditions → the per-attempt clock
//!   [`crate::db::store::DocumentStore::transition`] hands its closure. An
//!   arrival stamp there would grow stale across retries and redeem an
//!   artifact that expired mid-loop.
//! - Durable artifacts derived from a claim (DPoP JTI retention) → anchored on
//!   the claim, no clock at all.
//! - Background tasks and `created_at`-style stamping → ambient
//!   `Timestamp::now()`.

use axum::extract::FromRequestParts;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::StatusCode;
use jiff::Timestamp;

/// The instant a request arrived at the server.
///
/// The inner value is stamped only by [`arrival_layer`], and there is no
/// public constructor, so a function taking one is reading the clock of the
/// request it is serving rather than its own.
#[derive(Debug, Clone, Copy)]
pub struct ArrivalTime(Timestamp);

impl ArrivalTime {
    /// Stamp the current instant. Private: the arrival middleware is the only
    /// production path to an `ArrivalTime`.
    #[expect(
        clippy::disallowed_methods,
        reason = "the arrival middleware is the one sanctioned request-path stamp"
    )]
    fn stamp() -> Self {
        Self(Timestamp::now())
    }

    /// The arrival instant, at full precision.
    #[must_use]
    pub fn timestamp(self) -> Timestamp {
        self.0
    }

    /// The arrival instant truncated to Unix seconds, for comparison against
    /// JWT `exp` / `nbf` / `iat` claims.
    #[must_use]
    pub fn as_second(self) -> i64 {
        self.0.as_second()
    }

    /// Build an `ArrivalTime` for a specific instant, for tests that drive a
    /// service function directly instead of through the router.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn for_test(at: Timestamp) -> Self {
        Self(at)
    }

    /// Build an `ArrivalTime` from Unix seconds, for boundary tests written
    /// against integer-second claim values.
    ///
    /// # Panics
    ///
    /// Panics if `unix_seconds` is outside jiff's representable range.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "test-only constructor; an out-of-range literal is a test bug"
    )]
    pub fn for_test_second(unix_seconds: i64) -> Self {
        Self(Timestamp::from_second(unix_seconds).expect("test timestamp in range"))
    }
}

/// Stamp the arrival instant into request extensions.
///
/// Mounted as the outermost layer in [`crate::infra::router::build_app`], so
/// the stamp is taken before any other middleware can await.
pub async fn arrival_layer(mut request: Request, next: Next) -> Response {
    request.extensions_mut().insert(ArrivalTime::stamp());
    next.run(request).await
}

/// Generic over router state, and rejecting with a bare [`StatusCode`], so
/// this module depends on nothing above it — `db` and `services` take an
/// `ArrivalTime` without importing handler or error types.
impl<S: Send + Sync> FromRequestParts<S> for ArrivalTime {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Self>().copied().ok_or_else(|| {
            tracing::error!(
                "arrival_layer is not mounted on this router; request-scoped \
                 time comparisons have no origin"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test-only panics on impossible states"
)]
mod tests {
    use super::*;
    use crate::test_utils::{http_get, test_app_state};
    use axum::Router;
    use axum::routing::get;

    /// Echo the arrival instant the extractor produced, so a test can compare
    /// it against the wall clock the request was made at.
    async fn echo_arrival(arrival: ArrivalTime) -> String {
        arrival.as_second().to_string()
    }

    #[tokio::test]
    async fn mounted_layer_supplies_the_request_instant() {
        let state = test_app_state().await;
        let app = Router::new()
            .route("/t", get(echo_arrival))
            .layer(axum::middleware::from_fn(arrival_layer))
            .with_state(state);

        let before = Timestamp::now().as_second();
        let (status, body) = http_get(&app, "/t", &[]).await;
        let after = Timestamp::now().as_second();

        assert_eq!(status, 200);
        let stamped: i64 = body.parse().expect("handler echoed an integer second");
        assert!(
            (before..=after).contains(&stamped),
            "arrival {stamped} must fall inside the request's wall-clock window {before}..={after}"
        );
    }

    #[tokio::test]
    async fn missing_layer_fails_closed() {
        let state = test_app_state().await;
        // Deliberately no `arrival_layer`. A router that forgot to mount it
        // must fail rather than silently substitute a fresh clock reading —
        // the whole point of the witness is that its absence is visible.
        let app = Router::new()
            .route("/t", get(echo_arrival))
            .with_state(state);

        let (status, _body) = http_get(&app, "/t", &[]).await;
        assert_eq!(status, 500);
    }

    #[tokio::test]
    async fn each_request_carries_its_own_stamp() {
        let state = test_app_state().await;
        let app = Router::new()
            .route("/t", get(echo_arrival))
            .layer(axum::middleware::from_fn(arrival_layer))
            .with_state(state);

        let (_, first) = http_get(&app, "/t", &[]).await;
        // A second past the first request's stamp, so the comparison does not
        // depend on sub-second clock granularity (Windows resolves ~15ms).
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let (_, second) = http_get(&app, "/t", &[]).await;

        let first: i64 = first.parse().unwrap();
        let second: i64 = second.parse().unwrap();
        assert!(
            second > first,
            "the layer must stamp per request, not once per process: {first} then {second}"
        );
    }
}
