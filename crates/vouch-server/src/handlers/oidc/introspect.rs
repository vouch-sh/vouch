// SPDX-License-Identifier: BUSL-1.1
//! Token introspection and revocation endpoint handlers.

use crate::AppState;
use crate::services::oidc::introspection::{
    IntrospectionResult, introspect_token as svc_introspect, revoke_token as svc_revoke,
};
use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;

/// Token revocation request (RFC 7009).
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    token: String,
    /// Token type hint (ignored, but included for compatibility).
    #[serde(default)]
    #[allow(dead_code)]
    token_type_hint: Option<String>,
}

/// Token introspection request (RFC 7662).
#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    token: String,
    /// Token type hint (ignored, but included for compatibility).
    #[serde(default)]
    #[allow(dead_code)]
    token_type_hint: Option<String>,
}

/// POST /oauth/revoke
///
/// Revoke an access token (RFC 7009).
/// Returns 200 OK regardless of whether the token was valid (security best practice).
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    axum::Form(params): axum::Form<RevokeRequest>,
) -> StatusCode {
    let _result = svc_revoke(&state, &params.token, params.token_type_hint.as_deref()).await;
    // Always return 200 per RFC 7009
    StatusCode::OK
}

/// POST /oauth/introspect
///
/// Introspect a token (RFC 7662).
/// Returns token metadata if valid, or `{"active": false}` if invalid.
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    axum::Form(params): axum::Form<IntrospectRequest>,
) -> Json<IntrospectionResult> {
    match svc_introspect(&state, &params.token, params.token_type_hint.as_deref()).await {
        Ok(result) => Json(result),
        Err(_) => Json(IntrospectionResult::inactive()),
    }
}
