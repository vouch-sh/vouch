// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC Discovery and JWKS endpoint handlers.
//!
//! Implements:
//! - OIDC Discovery 1.0 Section 4 - Obtaining OpenID Provider Configuration Information
//! - RFC 7517 Section 5 - JWK Set Format

use crate::AppState;
use crate::services::oidc::discovery as svc;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use std::sync::Arc;

/// Cache-Control header for OIDC metadata endpoints.
///
/// These documents change infrequently (key rotation, issuer config), so a 1-hour
/// public cache reduces load on relying parties performing discovery.
const OIDC_CACHE_CONTROL: (axum::http::header::HeaderName, &str) =
    (axum::http::header::CACHE_CONTROL, "public, max-age=3600");

/// GET /.well-known/openid-configuration
///
/// OIDC Discovery 1.0 Section 4: The OpenID Provider Metadata is published at a
/// well-known URL derived from the Issuer Identifier.
pub(crate) async fn discovery(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [OIDC_CACHE_CONTROL],
        Json(svc::build_discovery_document(&state)),
    )
}

/// GET /oauth/jwks
///
/// RFC 7517 Section 5: Returns the JWK Set containing the public keys used to
/// verify token signatures.
pub(crate) async fn jwks(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    svc::build_jwks(&state)
        .map(|jwks| ([OIDC_CACHE_CONTROL], Json(jwks)))
        .map_err(|e| {
            tracing::error!("JWKS generation failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}
