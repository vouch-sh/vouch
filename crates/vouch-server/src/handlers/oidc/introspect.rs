// SPDX-License-Identifier: BUSL-1.1
//! Token introspection and revocation endpoint handlers.
//!
//! Implements:
//! - RFC 7009 - OAuth 2.0 Token Revocation
//! - RFC 7662 - OAuth 2.0 Token Introspection

use crate::AppState;
use crate::services::oidc::introspection::{
    IntrospectionResult, introspect_token as svc_introspect, revoke_token as svc_revoke,
};
use crate::services::oidc::token::authenticate_client;
use axum::{Json, extract::State, http::HeaderMap, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;

use super::token::extract_client_credentials;

/// Token revocation request (RFC 7009 Section 2.1).
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    /// RFC 7009 Section 2.1: The token that the client wants to get revoked.
    token: String,
    /// RFC 7009 Section 2.1: A hint about the type of the token (ignored, included for compatibility).
    #[serde(default)]
    #[allow(dead_code)]
    token_type_hint: Option<String>,
}

/// Token introspection request (RFC 7662 Section 2.1).
#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    /// RFC 7662 Section 2.1: The string value of the token.
    token: String,
    /// RFC 7662 Section 2.1: A hint about the type of the token (ignored, included for compatibility).
    #[serde(default)]
    #[allow(dead_code)]
    token_type_hint: Option<String>,
}

/// POST /oauth/revoke
///
/// Revoke an access token (RFC 7009 Section 2.1).
/// Returns 200 OK regardless of whether the token was valid (security best practice).
/// Requires client authentication via `Authorization: Basic` header.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Form(params): axum::Form<RevokeRequest>,
) -> StatusCode {
    // RFC 7009 Section 2.1: Authenticate the calling client.
    // Return 200 OK without revoking if authentication fails or is missing,
    // to prevent unauthenticated revocation and oracle attacks.
    let credentials = extract_client_credentials(&headers, None, None);
    match credentials {
        Some(creds) => {
            if authenticate_client(&state, &creds).await.is_err() {
                return StatusCode::OK;
            }
        }
        None => {
            // No credentials provided — do not proceed with revocation
            return StatusCode::OK;
        }
    }

    let _result = svc_revoke(&state, &params.token, params.token_type_hint.as_deref()).await;
    // Always return 200 per RFC 7009 Section 2
    StatusCode::OK
}

/// POST /oauth/introspect
///
/// Introspect a token (RFC 7662).
/// Requires client authentication via `Authorization: Basic` header or body credentials.
/// Returns token metadata if valid, or `{"active": false}` if invalid or auth fails.
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Form(params): axum::Form<IntrospectRequest>,
) -> Json<IntrospectionResult> {
    // RFC 7662 Section 2.1: The introspection endpoint MUST authenticate the caller
    let credentials = extract_client_credentials(&headers, None, None);
    let authenticated_client_id = match credentials {
        Some(creds) => match authenticate_client(&state, &creds).await {
            Ok(client) => Some(client.client.client_id),
            Err(_) => {
                // Return inactive to prevent oracle attacks (RFC 7662)
                return Json(IntrospectionResult::inactive());
            }
        },
        None => {
            // No credentials provided - return inactive per RFC 7662
            return Json(IntrospectionResult::inactive());
        }
    };

    match svc_introspect(
        &state,
        &params.token,
        params.token_type_hint.as_deref(),
        authenticated_client_id.as_deref(),
    )
    .await
    {
        Ok(result) => Json(result),
        Err(_) => Json(IntrospectionResult::inactive()),
    }
}
