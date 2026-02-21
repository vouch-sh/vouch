// SPDX-License-Identifier: BUSL-1.1
//! Token endpoint handler.

use crate::AppState;
use crate::impl_template_response;
use crate::services::error::OAuthErrorResponse;
use crate::services::oidc::{
    ScopeSet,
    exchange::{TokenExchangeParams, exchange_token},
    token::{
        AuthCodeExchangeParams, ClientCredentials, exchange_authorization_code,
        validate_dpop_if_present,
    },
};
use askama::Template;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Authorization page template.
#[derive(Template)]
#[template(path = "authorize.html")]
pub struct AuthorizeTemplate {
    pub client_id: String,
    pub client_name: Option<String>,
    pub is_org_app: bool,
    pub org_name: Option<String>,
}

impl_template_response!(AuthorizeTemplate);

/// OAuth grant types supported by this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthGrantType {
    /// Standard OAuth 2.0 authorization code grant.
    AuthorizationCode,
    /// Device authorization grant (RFC 8628).
    DeviceCode,
    /// Token exchange grant (RFC 8693).
    TokenExchange,
}

impl OAuthGrantType {
    /// Parse a grant type from a string.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "authorization_code" => Some(Self::AuthorizationCode),
            "urn:ietf:params:oauth:grant-type:device_code" => Some(Self::DeviceCode),
            "urn:ietf:params:oauth:grant-type:token-exchange" => Some(Self::TokenExchange),
            _ => None,
        }
    }
}

/// Token response (RFC 6749 Section 5.1).
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// The access token issued by the authorization server.
    pub access_token: String,
    /// The type of the token issued ("Bearer" or "DPoP").
    pub token_type: String,
    /// The lifetime in seconds of the access token.
    pub expires_in: u64,
    /// OIDC Core Section 3.1.3.3: The ID Token.
    pub id_token: Option<String>,
    /// RFC 6749 Section 3.3: The scope of the access token.
    pub scope: Option<ScopeSet>,
}

/// Token request for all grant types (RFC 6749 Section 4.1.3, RFC 8628 Section 3.4, RFC 8693 Section 2.1).
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// RFC 6749 Section 4.1.3: The grant type.
    pub grant_type: String,
    /// RFC 6749 Section 4.1.3: The authorization code received from the authorization server.
    #[serde(default)]
    pub code: Option<String>,
    /// RFC 6749 Section 4.1.3: The redirect URI used in the authorization request.
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// RFC 6749 Section 4.1.3: The client identifier.
    #[serde(default)]
    pub client_id: Option<String>,
    /// RFC 6749 Section 2.3.1: Client secret (wrapped in `SecretString` to prevent accidental logging).
    #[serde(default)]
    pub client_secret: Option<SecretString>,
    /// RFC 7636 Section 4.5: The code verifier for PKCE.
    #[serde(default)]
    pub code_verifier: Option<String>,
    /// RFC 8628 Section 3.4: The device verification code.
    #[serde(default)]
    pub device_code: Option<String>,
    /// RFC 8693 Section 2.1: The subject token to exchange.
    #[serde(default)]
    pub subject_token: Option<String>,
    /// RFC 8693 Section 2.1: Type identifier for the subject token.
    #[serde(default)]
    pub subject_token_type: Option<String>,
    /// RFC 8693 Section 2.1: Optional actor token (for delegation).
    #[serde(default)]
    pub actor_token: Option<String>,
    /// RFC 8693 Section 2.1: Type identifier for the actor token.
    #[serde(default)]
    pub actor_token_type: Option<String>,
    /// RFC 8693 Section 2.1: The target audience for the requested token.
    #[serde(default)]
    pub audience: Option<String>,
    /// RFC 6749 Section 3.3: The requested scope.
    #[serde(default)]
    pub scope: Option<String>,
    /// RFC 8693 Section 2.1: The desired type of the requested security token (OPTIONAL).
    #[serde(default)]
    pub requested_token_type: Option<String>,
}

/// Token exchange response (RFC 8693 Section 2.2).
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    /// The security token issued by the authorization server.
    pub access_token: String,
    /// RFC 8693 Section 2.2.1: The type of the issued security token.
    pub issued_token_type: String,
    /// The type of the token issued (e.g., "Bearer").
    pub token_type: String,
    /// The lifetime in seconds of the access token.
    pub expires_in: u64,
    /// RFC 6749 Section 3.3: The scope of the access token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeSet>,
}

/// POST /oauth/token
///
/// Unified token endpoint (RFC 6749 Section 3.2) that handles:
/// - `authorization_code` grant (RFC 6749 Section 4.1.3)
/// - `urn:ietf:params:oauth:grant-type:device_code` grant (RFC 8628 Section 3.4)
/// - `urn:ietf:params:oauth:grant-type:token-exchange` grant (RFC 8693 Section 2.1)
pub async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Form(params): axum::Form<TokenRequest>,
) -> Response {
    // RFC 6749 Section 5.2: Return unsupported_grant_type error for unknown grants
    let Some(grant_type) = OAuthGrantType::from_str(&params.grant_type) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(OAuthErrorResponse {
                error: "unsupported_grant_type".to_string(),
                error_description: Some(
                    "Supported grant types: authorization_code, urn:ietf:params:oauth:grant-type:device_code, urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
                ),
                error_uri: None,
            }),
        )
            .into_response();
    };

    match grant_type {
        OAuthGrantType::AuthorizationCode => {
            handle_authorization_code_grant(State(state), headers, params).await
        }
        OAuthGrantType::DeviceCode => handle_device_code_grant(State(state), params).await,
        OAuthGrantType::TokenExchange => handle_token_exchange_grant(State(state), params).await,
    }
}

/// Handle authorization code grant.
async fn handle_authorization_code_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    params: TokenRequest,
) -> Response {
    // RFC 6749 Section 4.1.3: The "code" parameter is REQUIRED
    let code = match &params.code {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(OAuthErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: Some("Missing code parameter".to_string()),
                    error_uri: None,
                }),
            )
                .into_response();
        }
    };

    // Extract client credentials from headers or body
    let credentials =
        extract_client_credentials(&headers, params.client_id.as_deref(), params.client_secret);

    // RFC 9449 Section 5: Validate DPoP proof if present at the token endpoint
    let dpop_header = headers.get("DPoP").and_then(|v| v.to_str().ok());
    let dpop_proof =
        match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/token").await {
            Ok(proof) => proof,
            Err(e) => return e.into_oauth_response().into_response(),
        };

    // Exchange the authorization code
    let exchange_params = AuthCodeExchangeParams {
        code,
        redirect_uri: params.redirect_uri.as_deref(),
        credentials: credentials.as_ref(),
        code_verifier: params.code_verifier.as_deref(),
        dpop_proof,
    };

    match exchange_authorization_code(&state, exchange_params).await {
        Ok(result) => Json(TokenResponse {
            access_token: result.access_token,
            token_type: result.token_type,
            expires_in: result.expires_in,
            id_token: Some(result.id_token),
            scope: Some(result.scope),
        })
        .into_response(),
        Err(e) => e.into_oauth_response().into_response(),
    }
}

/// Handle device code grant.
async fn handle_device_code_grant(
    State(state): State<Arc<AppState>>,
    params: TokenRequest,
) -> Response {
    let device_req = vouch_common::DeviceTokenRequest {
        grant_type: params.grant_type,
        device_code: params.device_code.unwrap_or_default(),
    };
    match super::super::device::device_token(State(state), Json(device_req)).await {
        Ok(resp) => resp.into_response(),
        Err((status, json)) => (status, json).into_response(),
    }
}

/// Handle token exchange grant (RFC 8693).
async fn handle_token_exchange_grant(
    State(state): State<Arc<AppState>>,
    params: TokenRequest,
) -> Response {
    let exchange_params = TokenExchangeParams {
        subject_token: params.subject_token.as_deref().unwrap_or_default(),
        subject_token_type: params.subject_token_type.as_deref().unwrap_or_default(),
        actor_token: params.actor_token.as_deref(),
        actor_token_type: params.actor_token_type.as_deref(),
        audience: params.audience.as_deref(),
        scope: params.scope.as_deref(),
        requested_token_type: params.requested_token_type.as_deref(),
    };

    match exchange_token(&state, exchange_params).await {
        Ok(result) => Json(TokenExchangeResponse {
            access_token: result.access_token,
            issued_token_type: result.issued_token_type,
            token_type: result.token_type,
            expires_in: result.expires_in,
            scope: result.scope,
        })
        .into_response(),
        Err(e) => e.into_oauth_response().into_response(),
    }
}

/// Extract client credentials from Authorization header or request body.
///
/// Supports both `client_secret_basic` (RFC 6749 Section 2.3.1) and
/// `client_secret_post` (RFC 6749 Section 2.3.1) authentication methods.
///
/// The client secret is wrapped in `SecretString` to prevent accidental logging
/// and ensure it is zeroized on drop.
pub fn extract_client_credentials(
    headers: &HeaderMap,
    client_id_param: Option<&str>,
    client_secret_param: Option<SecretString>,
) -> Option<ClientCredentials> {
    // Try Authorization header first (client_secret_basic)
    if let Some(auth_header) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Basic "))
        && let Ok(decoded) = base64::engine::general_purpose::STANDARD
            .decode(auth_header.trim())
            .or_else(|_| URL_SAFE_NO_PAD.decode(auth_header.trim()))
        && let Ok(creds) = String::from_utf8(decoded)
        && let Some((id, secret)) = creds.split_once(':')
    {
        // RFC 6749 Section 2.3.1: URL-decode client_id and client_secret after base64 decoding
        let decoded_id =
            urlencoding::decode(id).map_or_else(|_| id.to_string(), |d| d.into_owned());
        let decoded_secret =
            urlencoding::decode(secret).map_or_else(|_| secret.to_string(), |d| d.into_owned());
        return Some(ClientCredentials {
            client_id: decoded_id,
            client_secret: Some(SecretString::from(decoded_secret)),
        });
    }

    // Fall back to request body parameters (client_secret_post)
    client_id_param.map(|id| ClientCredentials {
        client_id: id.to_string(),
        client_secret: client_secret_param,
    })
}
