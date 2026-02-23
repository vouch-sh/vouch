// SPDX-License-Identifier: BUSL-1.1
//! Request correlation ID middleware.
//!
//! Propagates or generates `x-request-id` headers for request tracking.
//! If the incoming request has an `x-request-id` header, it is propagated
//! to the response. Otherwise, a new UUID v7 is generated.

use axum::http::{HeaderName, Request};
use tower_http::request_id::{
    MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use uuid::Uuid;

static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Generates UUID v7 request IDs (time-ordered).
#[derive(Clone, Default)]
pub struct UuidRequestId;

impl MakeRequestId for UuidRequestId {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let id = Uuid::now_v7().to_string();
        id.parse().ok().map(RequestId::new)
    }
}

/// Create the layer that sets `x-request-id` on incoming requests (if not already present).
pub fn set_request_id_layer() -> SetRequestIdLayer<UuidRequestId> {
    SetRequestIdLayer::new(X_REQUEST_ID.clone(), UuidRequestId)
}

/// Create the layer that propagates `x-request-id` from request to response.
pub fn propagate_request_id_layer() -> PropagateRequestIdLayer {
    PropagateRequestIdLayer::new(X_REQUEST_ID.clone())
}
