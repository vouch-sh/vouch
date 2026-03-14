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

use super::client_auth::{
    ClientAuthFields, authenticate_client_any, extract_client_auth, extract_client_credentials,
};

/// Token revocation request (RFC 7009 Section 2.1).
///
/// Supports `client_secret_basic`, `client_secret_post`, and `private_key_jwt`
/// (RFC 7523) client authentication methods.
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
    /// RFC 7521 Section 4.2: JWT assertion for `private_key_jwt` authentication.
    #[serde(default)]
    client_assertion: Option<String>,
    /// RFC 7521 Section 4.2: Assertion type (must be
    /// `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`).
    #[serde(default)]
    client_assertion_type: Option<String>,
}

impl ClientAuthFields for RevokeRequest {
    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn client_secret(&self) -> Option<SecretString> {
        self.client_secret.clone()
    }

    fn client_assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref()
    }

    fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }
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
/// Supports `client_secret_basic`, `client_secret_post`, and `private_key_jwt` auth.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    headers: HeaderMap,
    axum::Form(params): axum::Form<RevokeRequest>,
) -> Response {
    // RFC 7009 Section 2.1: Authenticate the calling client.
    // Supports client_secret_basic, client_secret_post, and private_key_jwt.
    let auth = match extract_client_auth(&headers, &params) {
        Ok(auth) => auth,
        Err(response) => return response,
    };

    match authenticate_client_any(&state, auth).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            // No credentials provided → 401
            return (StatusCode::UNAUTHORIZED, [("www-authenticate", "Basic")]).into_response();
        }
        Err(response) => return response,
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
