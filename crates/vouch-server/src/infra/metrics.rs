// SPDX-License-Identifier: BUSL-1.1
//! Prometheus metrics endpoint and HTTP request instrumentation.
//!
//! Exposes a `/metrics` endpoint in Prometheus text format and provides
//! middleware for automatic HTTP request duration and count tracking.

use std::time::Instant;

use axum::{
    extract::MatchedPath,
    http::{Request, Response},
    response::IntoResponse,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Install the Prometheus metrics recorder and return a handle for rendering.
///
/// # Errors
///
/// Returns an error if the recorder cannot be installed (e.g., already installed).
pub fn install_recorder() -> Result<PrometheusHandle, metrics_exporter_prometheus::BuildError> {
    PrometheusBuilder::new().install_recorder()
}

/// Axum handler that renders all metrics in Prometheus text exposition format.
pub async fn metrics_handler(
    axum::extract::State(handle): axum::extract::State<PrometheusHandle>,
) -> impl IntoResponse {
    handle.render()
}

/// Tower middleware layer that records HTTP request metrics.
///
/// Records:
/// - `http_requests_total{method, path, status}` - Counter
/// - `http_request_duration_seconds{method, path}` - Histogram
pub fn track_metrics<B>(req: &Request<B>) -> Option<RequestMetricsContext> {
    let method = req.method().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    Some(RequestMetricsContext {
        method,
        path,
        start: Instant::now(),
    })
}

/// Context stored per-request for recording metrics after the response.
pub struct RequestMetricsContext {
    method: String,
    path: String,
    start: Instant,
}

impl RequestMetricsContext {
    /// Record metrics after a response is produced.
    pub fn record<B>(self, response: &Response<B>) {
        let duration = self.start.elapsed().as_secs_f64();
        let status = response.status().as_u16().to_string();
        let labels = [
            ("method", self.method),
            ("path", self.path),
            ("status", status),
        ];
        metrics::counter!("http_requests_total", &labels).increment(1);
        metrics::histogram!("http_request_duration_seconds", &labels[..2]).record(duration);
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

/// Record a credential issuance event (ssh, aws, k8s, github).
pub fn record_credential_issuance(credential_type: &str) {
    metrics::counter!(
        "vouch_credential_issuance_total",
        "type" => credential_type.to_string()
    )
    .increment(1);
}
