// SPDX-License-Identifier: BUSL-1.1
//! OIDC Discovery and JWKS endpoint handlers.

use crate::AppState;
use crate::services::oidc::discovery as svc;
use axum::{Json, extract::State, http::StatusCode};
use std::sync::Arc;

/// GET /.well-known/openid-configuration
///
/// Returns the OIDC discovery document for this provider.
pub async fn discovery(State(state): State<Arc<AppState>>) -> Json<svc::OidcDiscoveryDocument> {
    Json(svc::build_discovery_document(&state))
}

/// GET /oauth/jwks
///
/// Returns the public keys used to sign tokens.
pub async fn jwks(
    State(state): State<Arc<AppState>>,
) -> Result<Json<svc::JwksResponse>, StatusCode> {
    svc::build_jwks(&state).map(Json).map_err(|e| {
        tracing::error!("JWKS generation failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })
}
