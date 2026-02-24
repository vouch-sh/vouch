// SPDX-License-Identifier: BUSL-1.1
//! Request correlation ID middleware.
//!
//! Propagates or generates `x-fapi-interaction-id` headers for request tracking
//! per the FAPI 2.0 Security Profile specification. If the incoming request has
//! an `x-fapi-interaction-id` header, it is propagated to the response. Otherwise,
//! a new UUID v7 is generated.
//!
//! Reference: <https://openid.net/specs/fapi-security-profile-2_0-final.html>

use axum::http::{HeaderName, Request};
use tower_http::request_id::{
    MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
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
