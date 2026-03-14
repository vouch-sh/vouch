// SPDX-License-Identifier: BUSL-1.1
//! Token introspection and revocation endpoint handlers.
//!
//! Implements:
//! - RFC 7009 - OAuth 2.0 Token Revocation
//! - RFC 7662 - OAuth 2.0 Token Introspection

use crate::AppState;
use crate::handlers::extractors::ClientInfo;
use crate::services::oidc::introspection::{
    IntrospectionResult, introspect_token as svc_introspect, revoke_token as svc_revoke,
};
use crate::services::oidc::token::authenticate_client;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use secrecy::SecretString;
use serde::Deserialize;
use std::sync::Arc;

use super::client_auth::extract_client_credentials;

/// Token revocation request (RFC 7009 Section 2.1).
///
/// Also accepts `client_id`/`client_secret` for `client_secret_post` authentication
/// (RFC 6749 Section 2.3.1).
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    /// RFC 7009 Section 2.1: The token that the client wants to get revoked.
    token: String,
    /// RFC 7009 Section 2.1: A hint about the type of the token.
    #[serde(default)]
    token_type_hint: Option<String>,
    /// RFC 6749 Section 2.3.1: Client ID for `client_secret_post` authentication.
    #[serde(default)]
    client_id: Option<String>,
    /// RFC 6749 Section 2.3.1: Client secret for `client_secret_post` authentication.
    /// Wrapped in `SecretString` to prevent accidental logging and ensure zeroization on drop.
    #[serde(default)]
    client_secret: Option<SecretString>,
}

/// Token introspection request (RFC 7662 Section 2.1).
///
/// Also accepts `client_id`/`client_secret` for `client_secret_post` authentication
/// (RFC 6749 Section 2.3.1).
#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    /// RFC 7662 Section 2.1: The string value of the token.
    token: String,
    /// RFC 7662 Section 2.1: A hint about the type of the token.
    #[serde(default)]
    token_type_hint: Option<String>,
    /// RFC 6749 Section 2.3.1: Client ID for `client_secret_post` authentication.
    #[serde(default)]
    client_id: Option<String>,
    /// RFC 6749 Section 2.3.1: Client secret for `client_secret_post` authentication.
    /// Wrapped in `SecretString` to prevent accidental logging and ensure zeroization on drop.
    #[serde(default)]
    client_secret: Option<SecretString>,
}

/// POST /oauth/revoke
///
/// Revoke an access token (RFC 7009 Section 2.1).
/// Returns 200 OK regardless of whether the token was valid (security best practice).
/// Requires client authentication via `Authorization: Basic` header.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    headers: HeaderMap,
    axum::Form(params): axum::Form<RevokeRequest>,
) -> Response {
    // RFC 7009 Section 2.1: Authenticate the calling client.
    // Supports both client_secret_basic (header) and client_secret_post (body).
    let credentials =
        extract_client_credentials(&headers, params.client_id.as_deref(), params.client_secret);
    match credentials {
        Some(creds) => {
            if authenticate_client(&state, &creds).await.is_err() {
                // RFC 7009 §2.1: Invalid client credentials → 401
                return (StatusCode::UNAUTHORIZED, [("www-authenticate", "Basic")]).into_response();
            }
        }
        None => {
            // No credentials provided → 401
            return (StatusCode::UNAUTHORIZED, [("www-authenticate", "Basic")]).into_response();
        }
    }

    let _result = svc_revoke(
        &state,
        &params.token,
        params.token_type_hint.as_deref(),
        client_info,
    )
    .await;
    // Always return 200 per RFC 7009 Section 2 (for valid clients)
    StatusCode::OK.into_response()
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
) -> Response {
    // RFC 7662 Section 2.1: The introspection endpoint MUST authenticate the caller.
    // Supports both client_secret_basic (header) and client_secret_post (body).
    let credentials =
        extract_client_credentials(&headers, params.client_id.as_deref(), params.client_secret);
    let authenticated_client_id = match credentials {
        Some(creds) => match authenticate_client(&state, &creds).await {
            Ok(client) => Some(client.client.client_id),
            Err(_) => {
                // RFC 7662 §2.1: Invalid client credentials → 401
                return (StatusCode::UNAUTHORIZED, [("www-authenticate", "Basic")]).into_response();
            }
        },
        None => {
            // No credentials provided → 401
            return (StatusCode::UNAUTHORIZED, [("www-authenticate", "Basic")]).into_response();
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
        Ok(result) => Json(result).into_response(),
        Err(_) => Json(IntrospectionResult::inactive()).into_response(),
    }
}
