// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Token introspection and revocation endpoint handlers.
//!
//! Implements:
//! - RFC 7009 - OAuth 2.0 Token Revocation
//! - RFC 7662 - OAuth 2.0 Token Introspection

use crate::AppState;
use crate::handlers::extractors::ClientInfo;
use crate::services::oidc::introspection::{
    IntrospectionResult, introspect_token as svc_introspect, revoke_token as svc_revoke,
    wrap_introspection_jwt,
};
use crate::services::oidc::token::ClientAuthError;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use secrecy::SecretString;
use serde::Deserialize;
use std::sync::Arc;

use super::client_auth::{ClientAuthFields, authenticate_client_any, extract_client_auth};

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
/// Supports `client_secret_basic`, `client_secret_post`, and `private_key_jwt`
/// (RFC 7523) client authentication methods.
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
    /// RFC 7521 Section 4.2: JWT assertion for `private_key_jwt` authentication.
    #[serde(default)]
    client_assertion: Option<String>,
    /// RFC 7521 Section 4.2: Assertion type (must be
    /// `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`).
    #[serde(default)]
    client_assertion_type: Option<String>,
}

impl ClientAuthFields for IntrospectRequest {
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

    let (caller_client_id, pending_jti) = match authenticate_client_any(&state, auth).await {
        Ok(Some((_client, client_id, jti))) => (client_id, jti),
        Ok(None) => {
            // No credentials provided → 401
            return (StatusCode::UNAUTHORIZED, [("www-authenticate", "Basic")]).into_response();
        }
        Err(response) => return response,
    };

    let _result = svc_revoke(
        &state,
        &params.token,
        params.token_type_hint.as_deref(),
        client_info,
        &caller_client_id,
    )
    .await;

    // Commit JTI after revocation so clients can retry on failure.
    if let Some(p) = pending_jti {
        match p.commit(&state).await {
            Ok(_claim) => {}
            Err(ClientAuthError::InvalidCredentials) => {
                // JTI was already used — reject so the client generates a new assertion.
                return StatusCode::UNAUTHORIZED.into_response();
            }
            Err(e) => {
                // Transient DB error. Revocation already succeeded — return 200
                // per RFC 7009 §2 and log for ops visibility.
                tracing::warn!("JTI commit failed for revoke (revocation succeeded): {e:?}");
            }
        }
    }

    // Always return 200 per RFC 7009 Section 2 (for valid clients)
    StatusCode::OK.into_response()
}

/// POST /oauth/introspect
///
/// Introspect a token (RFC 7662).
/// Requires client authentication via `Authorization: Basic` header, body
/// credentials, or `private_key_jwt` (RFC 7523).
/// Returns token metadata if valid, or `{"active": false}` if invalid or auth fails.
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Form(params): axum::Form<IntrospectRequest>,
) -> Response {
    // RFC 7662 Section 2.1: The introspection endpoint MUST authenticate the caller.
    // Supports client_secret_basic, client_secret_post, and private_key_jwt.
    let auth = match extract_client_auth(&headers, &params) {
        Ok(auth) => auth,
        Err(response) => return response,
    };

    let (authenticated_client, pending_jti) = match authenticate_client_any(&state, auth).await {
        Ok(Some((client, _client_id, jti))) => (client.client, jti),
        Ok(None) => {
            // No credentials provided → 401
            return (StatusCode::UNAUTHORIZED, [("www-authenticate", "Basic")]).into_response();
        }
        Err(response) => return response,
    };

    let wants_jwt = authenticated_client
        .introspection_signed_response_alg
        .is_some();
    let client_id = authenticated_client.client_id.clone();
    let config = state.config();
    let issuer = config.base_url.clone();

    let result = match svc_introspect(
        &state,
        &params.token,
        params.token_type_hint.as_deref(),
        Some(client_id.as_str()),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => IntrospectionResult::inactive(),
    };

    // Commit JTI after introspection so clients can retry on failure.
    if let Some(p) = pending_jti {
        match p.commit(&state).await {
            Ok(_claim) => {}
            Err(ClientAuthError::InvalidCredentials) => {
                // JTI was already used — reject so the client generates a new assertion.
                return StatusCode::UNAUTHORIZED.into_response();
            }
            Err(e) => {
                // Transient DB error. Introspection already succeeded — return the
                // result per defense-in-depth: prefer denying replay over dropping
                // a valid response. Log for ops visibility.
                tracing::warn!("JTI commit failed for introspect (returning result anyway): {e:?}");
            }
        }
    }

    if wants_jwt {
        // RFC 9701: Return a signed JWT with Content-Type: application/token-introspection+jwt
        match wrap_introspection_jwt(&result, &issuer, &client_id, &state.oidc_key).await {
            Ok(jwt) => (
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/token-introspection+jwt",
                )],
                jwt,
            )
                .into_response(),
            Err(_) => Json(IntrospectionResult::inactive()).into_response(),
        }
    } else {
        Json(result).into_response()
    }
}
