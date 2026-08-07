// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Prometheus metrics endpoint and HTTP request instrumentation.
//!
//! Exposes a `/metrics` endpoint in Prometheus text format and provides
//! middleware for automatic HTTP request duration and count tracking.
//! The endpoint is gated behind a bearer token for security.

use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

/// State for the authenticated metrics endpoint.
pub struct MetricsState {
    pub handle: PrometheusHandle,
    pub bearer_token: SecretString,
}

/// The one process-global recorder. The `metrics` crate allows a single
/// global recorder per process, so the handle is installed once and shared
/// by every later caller (server rebuilds, tests in one binary).
static RECORDER: std::sync::LazyLock<
    Result<PrometheusHandle, metrics_exporter_prometheus::BuildError>,
> = std::sync::LazyLock::new(|| PrometheusBuilder::new().install_recorder());

/// Install the Prometheus metrics recorder and return a handle for rendering.
///
/// Idempotent: the first call installs the recorder; later calls return a
/// clone of the same handle.
///
/// # Errors
///
/// Returns an error if the global recorder was already installed outside this
/// function, in which case no renderable handle exists.
pub fn install_recorder()
-> Result<PrometheusHandle, &'static metrics_exporter_prometheus::BuildError> {
    RECORDER.as_ref().map(Clone::clone)
}

/// Extract the bearer token from an `Authorization` header value.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let token = crate::http::bearer_token(headers)?;
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Axum handler that validates a bearer token before rendering metrics.
///
/// Returns 401 if the token is missing or invalid (constant-time comparison).
pub async fn authenticated_metrics_handler(
    axum::extract::State(state): axum::extract::State<Arc<MetricsState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(provided) = extract_bearer_token(&headers) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };

    let expected = state.bearer_token.expose_secret().as_bytes();
    let provided_bytes = provided.as_bytes();

    if expected.ct_eq(provided_bytes).into() {
        state.handle.render().into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    }
}

/// Record an authentication event (login success, login failure, etc.).
pub fn record_auth_event(event_type: &str) {
    metrics::counter!(
        "vouch_auth_events_total",
        "event_type" => event_type.to_string()
    )
    .increment(1);
}

/// Record a credential issuance event (ssh, aws, oidc, github).
pub fn record_credential_issuance(credential_type: &str) {
    metrics::counter!(
        "vouch_credential_issuance_total",
        "type" => credential_type.to_string()
    )
    .increment(1);
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    fn headers_with_auth(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", value.parse().expect("valid header value"));
        headers
    }

    /// RFC 9110 Section 11.1: the auth-scheme token is case-insensitive, so
    /// `BEARER`, `bearer`, and `BeArEr` must all match like `Bearer`.
    #[test]
    fn extract_bearer_token_accepts_scheme_case_variants() {
        for scheme in ["Bearer", "BEARER", "bearer", "BeArEr"] {
            let headers = headers_with_auth(&format!("{scheme} tok"));
            assert_eq!(
                extract_bearer_token(&headers),
                Some("tok"),
                "{scheme} scheme must be accepted (RFC 9110 case-insensitivity)"
            );
        }
    }

    #[test]
    fn extract_bearer_token_rejects_unrecognized_scheme() {
        for value in ["Basic dXNlcjpwYXNz", "DPoP tok", "Beareralone"] {
            assert_eq!(extract_bearer_token(&headers_with_auth(value)), None);
        }
    }

    #[test]
    fn extract_bearer_token_rejects_empty_token_and_missing_header() {
        assert_eq!(extract_bearer_token(&headers_with_auth("Bearer ")), None);
        assert_eq!(extract_bearer_token(&HeaderMap::new()), None);
    }
}
