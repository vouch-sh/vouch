// SPDX-License-Identifier: BUSL-1.1
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

/// Install the Prometheus metrics recorder and return a handle for rendering.
///
/// # Errors
///
/// Returns an error if the recorder cannot be installed (e.g., already installed).
pub fn install_recorder() -> Result<PrometheusHandle, metrics_exporter_prometheus::BuildError> {
    PrometheusBuilder::new().install_recorder()
}

/// Extract the bearer token from an `Authorization` header value.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
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

/// Record a credential issuance event (ssh, aws, k8s, github).
pub fn record_credential_issuance(credential_type: &str) {
    metrics::counter!(
        "vouch_credential_issuance_total",
        "type" => credential_type.to_string()
    )
    .increment(1);
}
