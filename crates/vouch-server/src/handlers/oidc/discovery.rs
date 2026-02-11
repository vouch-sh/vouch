// SPDX-License-Identifier: BUSL-1.1
//! OIDC Discovery and JWKS endpoint handlers.
//!
//! Implements:
//! - OIDC Discovery 1.0 Section 4 - Obtaining OpenID Provider Configuration Information
//! - RFC 7517 Section 5 - JWK Set Format

use crate::AppState;
use crate::services::oidc::discovery as svc;
use axum::{Json, extract::State, http::StatusCode};
use std::sync::Arc;

/// GET /.well-known/openid-configuration
///
/// OIDC Discovery 1.0 Section 4: The OpenID Provider Metadata is published at a
/// well-known URL derived from the Issuer Identifier.
pub async fn discovery(State(state): State<Arc<AppState>>) -> Json<svc::OidcDiscoveryDocument> {
    Json(svc::build_discovery_document(&state))
}

/// GET /oauth/jwks
///
/// RFC 7517 Section 5: Returns the JWK Set containing the public keys used to
/// verify token signatures.
pub async fn jwks(
    State(state): State<Arc<AppState>>,
) -> Result<Json<svc::JwksResponse>, StatusCode> {
    svc::build_jwks(&state).map(Json).map_err(|e| {
        tracing::error!("JWKS generation failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })
}
