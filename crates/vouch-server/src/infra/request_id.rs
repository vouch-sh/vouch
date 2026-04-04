// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Request correlation ID middleware.
//!
//! Propagates or generates `x-fapi-interaction-id` headers for request tracking
//! per the FAPI 2.0 Security Profile specification. If the incoming request has
//! an `x-fapi-interaction-id` header, it is propagated to the response. Otherwise,
//! a new UUID v7 is generated.
//!
//! Reference: <https://openid.net/specs/fapi-security-profile-2_0-final.html>

use axum::{
    http::{HeaderName, Request},
    middleware::Next,
    response::IntoResponse,
};
use tower_http::request_id::{
    MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tracing::Instrument;
use uuid::Uuid;

static X_FAPI_INTERACTION_ID: HeaderName = HeaderName::from_static("x-fapi-interaction-id");

/// Generates UUID v7 request IDs (time-ordered).
#[derive(Clone, Default)]
pub struct UuidRequestId;

impl MakeRequestId for UuidRequestId {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let id = Uuid::now_v7().to_string();
        id.parse().ok().map(RequestId::new)
    }
}

/// Create the layer that sets `x-fapi-interaction-id` on incoming requests (if not already present).
pub fn set_request_id_layer() -> SetRequestIdLayer<UuidRequestId> {
    SetRequestIdLayer::new(X_FAPI_INTERACTION_ID.clone(), UuidRequestId)
}

/// Create the layer that propagates `x-fapi-interaction-id` from request to response.
pub fn propagate_request_id_layer() -> PropagateRequestIdLayer {
    PropagateRequestIdLayer::new(X_FAPI_INTERACTION_ID.clone())
}

/// Middleware that creates a tracing span with the FAPI interaction ID.
///
/// Must be placed after [`set_request_id_layer`] in the middleware stack so
/// that the [`RequestId`] extension is available. All downstream middleware
/// and handlers inherit this span, making `interaction_id` appear in every
/// log line and OpenTelemetry span.
pub async fn request_span_middleware(
    req: Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    let interaction_id = req
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .unwrap_or("unknown");

    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    let span = tracing::info_span!(
        "request",
        interaction_id = %interaction_id,
        method = %method,
        path = %path,
    );

    next.run(req).instrument(span).await
}
