// SPDX-License-Identifier: BUSL-1.1
//! Token endpoint handler.

use super::client_auth::{
    ClientAuthFields, ExtractedClientAuth, authenticate_client_any, extract_client_auth,
    extract_client_credentials,
};
use crate::AppState;
use crate::services::error::OAuthErrorResponse;
use crate::services::oidc::{
    ScopeSet,
    client_credentials::exchange_client_credentials,
    exchange::{TokenExchangeParams, exchange_token},
    jwt_bearer::{client_auth::authenticate_client_jwt, grant::exchange_jwt_bearer_grant},
    token::{AuthCodeExchangeParams, exchange_authorization_code, validate_dpop_if_present},
};
use crate::services::{OAuthErrorCode, ServiceError};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// OAuth grant types supported by this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthGrantType {
    /// Standard OAuth 2.0 authorization code grant.
    AuthorizationCode,
    /// Client credentials grant (RFC 6749 Section 4.4).
    ClientCredentials,
    /// Device authorization grant (RFC 8628).
    DeviceCode,
    /// Token exchange grant (RFC 8693).
    TokenExchange,
    /// JWT bearer assertion grant (RFC 7523).
    JwtBearer,
    /// FIDO2 assertion grant (custom extension per RFC 6749 Section 4.5).
    Fido2Assertion,
}

impl OAuthGrantType {
    const SUPPORTED: [Self; 6] = [
        Self::AuthorizationCode,
        Self::ClientCredentials,
        Self::DeviceCode,
        Self::TokenExchange,
        Self::JwtBearer,
        Self::Fido2Assertion,
    ];

    /// Wire-format `grant_type` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::ClientCredentials => "client_credentials",
            Self::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
            Self::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
            Self::JwtBearer => "urn:ietf:params:oauth:grant-type:jwt-bearer",
            Self::Fido2Assertion => "urn:ietf:params:oauth:grant-type:fido2-assertion",
        }
    }

    /// All supported `grant_type` wire values.
    #[must_use]
    pub fn supported_wire_values() -> Vec<&'static str> {
        Self::SUPPORTED.iter().copied().map(Self::as_str).collect()
    }
}

impl std::str::FromStr for OAuthGrantType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::SUPPORTED
            .iter()
            .copied()
            .find(|grant_type| grant_type.as_str() == s)
            .ok_or_else(|| format!("unsupported grant_type: {s}"))
    }
}

/// Token response (RFC 6749 Section 5.1).
#[derive(Serialize)]
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
    /// User email (included in FIDO2 assertion grant responses).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// RFC 9396: Rich authorization details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<serde_json::Value>,
}

// Custom Debug that redacts tokens to prevent accidental log exposure.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("id_token", &"[REDACTED]")
            .field("scope", &self.scope)
            .field("email", &self.email)
            .field("authorization_details", &self.authorization_details)
            .finish()
    }
}

/// Token request for all grant types (RFC 6749 Section 4.1.3, RFC 8628 Section 3.4, RFC 8693 Section 2.1).
#[derive(Deserialize)]
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
    /// RFC 8707 Section 2: Target resource indicator (OPTIONAL).
    #[serde(default)]
    pub resource: Option<String>,
    /// RFC 7521 Section 4.2: Client assertion for JWT client authentication.
    #[serde(default)]
    pub client_assertion: Option<String>,
    /// RFC 7521 Section 4.2: Client assertion type.
    #[serde(default)]
    pub client_assertion_type: Option<String>,
    /// RFC 7521 Section 4.1: The assertion for JWT bearer grants.
    #[serde(default)]
    pub assertion: Option<String>,
    /// RFC 9396: Rich authorization details (JSON array).
    #[serde(default)]
    pub authorization_details: Option<String>,
}

// Custom Debug that redacts secrets to prevent accidental log exposure.
impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &self.code)
            .field("redirect_uri", &self.redirect_uri)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .field("device_code", &self.device_code)
            .field("subject_token", &"[REDACTED]")
            .field("subject_token_type", &self.subject_token_type)
            .field("actor_token", &"[REDACTED]")
            .field("actor_token_type", &self.actor_token_type)
            .field("audience", &self.audience)
            .field("scope", &self.scope)
            .field("requested_token_type", &self.requested_token_type)
            .field("resource", &self.resource)
            .field("client_assertion", &"[REDACTED]")
            .field("client_assertion_type", &self.client_assertion_type)
            .field("assertion", &"[REDACTED]")
            .field("authorization_details", &self.authorization_details)
            .finish()
    }
}

/// Token exchange response (RFC 8693 Section 2.2).
#[derive(Serialize)]
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
    /// RFC 9396: Rich authorization details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<serde_json::Value>,
}

// Custom Debug that redacts access_token to prevent accidental log exposure.
impl std::fmt::Debug for TokenExchangeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeResponse")
            .field("access_token", &"[REDACTED]")
            .field("issued_token_type", &self.issued_token_type)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("authorization_details", &self.authorization_details)
            .finish()
    }
}

// Maximum lengths for token request parameters.
const MAX_TOKEN_REDIRECT_URI_LEN: usize = 2048;
const MAX_TOKEN_CLIENT_ID_LEN: usize = 256;
const MAX_TOKEN_SCOPE_LEN: usize = 512;
const MAX_TOKEN_RESOURCE_LEN: usize = 2048;
/// Maximum length for JWT assertions (RFC 7521).
const MAX_ASSERTION_LEN: usize = 8192;

/// POST /oauth/token
///
/// Unified token endpoint (RFC 6749 Section 3.2) that handles:
/// - `authorization_code` grant (RFC 6749 Section 4.1.3)
/// - `urn:ietf:params:oauth:grant-type:device_code` grant (RFC 8628 Section 3.4)
/// - `urn:ietf:params:oauth:grant-type:token-exchange` grant (RFC 8693 Section 2.1)
pub async fn token(
    State(state): State<Arc<AppState>>,
    client_info: crate::handlers::extractors::ClientInfo,
    headers: HeaderMap,
    axum::Form(params): axum::Form<TokenRequest>,
) -> Response {
    // Input length validation — reject oversized parameters early.
    if let Some(ref v) = params.code_verifier
        && !is_valid_pkce_verifier(v)
    {
        return token_error_response(
            "invalid_request",
            "code_verifier must be 43-128 characters and contain only [A-Za-z0-9\\-._~]",
        );
    }
    if let Some(ref v) = params.redirect_uri
        && v.len() > MAX_TOKEN_REDIRECT_URI_LEN
    {
        return token_error_response(
            "invalid_request",
            &format!("redirect_uri exceeds maximum length of {MAX_TOKEN_REDIRECT_URI_LEN}"),
        );
    }
    if let Some(ref v) = params.client_id
        && v.len() > MAX_TOKEN_CLIENT_ID_LEN
    {
        return token_error_response(
            "invalid_request",
            &format!("client_id exceeds maximum length of {MAX_TOKEN_CLIENT_ID_LEN}"),
        );
    }
    if let Some(ref v) = params.scope
        && v.len() > MAX_TOKEN_SCOPE_LEN
    {
        return token_error_response(
            "invalid_request",
            &format!("scope exceeds maximum length of {MAX_TOKEN_SCOPE_LEN}"),
        );
    }
    if let Some(ref v) = params.resource
        && v.len() > MAX_TOKEN_RESOURCE_LEN
    {
        return token_error_response(
            "invalid_request",
            &format!("resource exceeds maximum length of {MAX_TOKEN_RESOURCE_LEN}"),
        );
    }
    if let Some(ref v) = params.client_assertion
        && v.len() > MAX_ASSERTION_LEN
    {
        return token_error_response(
            "invalid_request",
            &format!("client_assertion exceeds maximum length of {MAX_ASSERTION_LEN}"),
        );
    }
    if let Some(ref v) = params.assertion
        && v.len() > MAX_ASSERTION_LEN
    {
        return token_error_response(
            "invalid_request",
            &format!("assertion exceeds maximum length of {MAX_ASSERTION_LEN}"),
        );
    }
    // RFC 9396: authorization_details size limit (same as MAX_ASSERTION_LEN = 8192)
    if let Some(ref v) = params.authorization_details
        && v.len() > MAX_ASSERTION_LEN
    {
        return token_error_response(
            "invalid_authorization_details",
            &format!("authorization_details exceeds maximum length of {MAX_ASSERTION_LEN}"),
        );
    }

    // RFC 6749 Section 5.2: Return unsupported_grant_type error for unknown grants
    let Ok(grant_type) = params.grant_type.parse::<OAuthGrantType>() else {
        let supported = OAuthGrantType::supported_wire_values().join(", ");
        return (
            StatusCode::BAD_REQUEST,
            Json(OAuthErrorResponse {
                error: "unsupported_grant_type".to_string(),
                error_description: Some(format!("Supported grant types: {supported}")),
                error_uri: None,
            }),
        )
            .into_response();
    };

    match grant_type {
        OAuthGrantType::AuthorizationCode => {
            handle_authorization_code_grant(State(state), headers, params).await
        }
        OAuthGrantType::ClientCredentials => {
            handle_client_credentials_grant(State(state), client_info, headers, params).await
        }
        OAuthGrantType::DeviceCode => handle_device_code_grant(State(state), params).await,
        OAuthGrantType::TokenExchange => {
            handle_token_exchange_grant(State(state), headers, params).await
        }
        OAuthGrantType::JwtBearer => handle_jwt_bearer_grant(State(state), params).await,
        OAuthGrantType::Fido2Assertion => {
            handle_fido2_assertion_grant(State(state), client_info, headers, params).await
        }
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

    // Extract client credentials from headers or body (including JWT assertion)
    let has_jwt_assertion = params.client_assertion.is_some();

    // For JWT assertion, authenticate and extract the client
    let jwt_authenticated = if has_jwt_assertion {
        let client_auth = match extract_client_auth(&headers, &params) {
            Ok(auth) => auth,
            Err(resp) => return resp,
        };
        if let ExtractedClientAuth::JwtAssertion {
            client_assertion,
            client_id,
        } = client_auth
        {
            match authenticate_client_jwt(&state, &client_assertion, client_id.as_deref()).await {
                Ok(client) => Some(client),
                Err(e) => return e.into_service_error().into_oauth_response().into_response(),
            }
        } else {
            None
        }
    } else {
        None
    };

    // For non-JWT auth, extract traditional credentials
    let credentials = if !has_jwt_assertion {
        extract_client_credentials(&headers, params.client_id.as_deref(), params.client_secret)
    } else {
        None
    };

    // RFC 9449 Section 5: Validate DPoP proof if present at the token endpoint
    let dpop_header = headers.get("DPoP").and_then(|v| v.to_str().ok());
    let dpop_proof =
        match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/token").await {
            Ok(proof) => proof,
            Err(crate::services::oidc::dpop::DpopError::UseNonce(nonce)) => {
                return dpop_use_nonce_response(&nonce);
            }
            Err(e) => {
                return ServiceError::oauth(OAuthErrorCode::InvalidDpopProof, e.to_string())
                    .into_oauth_response()
                    .into_response();
            }
        };

    // FAPI 2.0: Require DPoP for FAPI clients (sender-constrained tokens).
    // FAPI 2.0 Section 5.2.2 mandates sender-constrained access tokens.
    // Since we use DPoP (not mTLS), a DPoP proof is required for FAPI clients.
    if let Some(ref auth) = jwt_authenticated
        && let Err(e) = crate::services::oidc::fapi::validate_fapi_token_request(
            &auth.client,
            dpop_proof.is_some(),
        )
    {
        return e.into_oauth_response().into_response();
    }

    // Extract client_id for audience validation (RFC 8725 §3.9)
    let exchange_client_id = jwt_authenticated
        .as_ref()
        .map(|c| c.client.client_id.as_str())
        .or_else(|| credentials.as_ref().map(|c| c.client_id.as_str()))
        .or(params.client_id.as_deref())
        .unwrap_or("");

    // Exchange the authorization code
    let exchange_params = AuthCodeExchangeParams {
        code,
        redirect_uri: params.redirect_uri.as_deref(),
        credentials: credentials.as_ref(),
        code_verifier: params.code_verifier.as_deref(),
        dpop_proof,
        client_id: exchange_client_id,
        resource: params.resource.as_deref(),
        authorization_details: params.authorization_details.as_deref(),
    };

    match exchange_authorization_code(&state, exchange_params).await {
        Ok(result) => {
            crate::infra::metrics::record_auth_event("authorization_code_success");
            token_success_response(TokenResponse {
                access_token: result.access_token,
                token_type: result.token_type,
                expires_in: result.expires_in,
                id_token: Some(result.id_token),
                scope: Some(result.scope),
                email: None,
                authorization_details: result
                    .authorization_details
                    .as_ref()
                    .map(serde_json::Value::from),
            })
        }
        Err(e) => e.into_oauth_response().into_response(),
    }
}

/// Handle client credentials grant (RFC 6749 Section 4.4).
///
/// Requires client authentication via `client_secret_basic` or `client_secret_post`.
/// Issues an access token with `hardware_verified: false` and no ID token.
async fn handle_client_credentials_grant(
    State(state): State<Arc<AppState>>,
    client_info: crate::handlers::extractors::ClientInfo,
    headers: HeaderMap,
    params: TokenRequest,
) -> Response {
    // RFC 6749 Section 4.4.2: Client authentication is REQUIRED
    let client_auth = match extract_client_auth(&headers, &params) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };

    let Some((authenticated_client, _client_id)) =
        (match authenticate_client_any(&state, client_auth).await {
            Ok(result) => result,
            Err(resp) => return resp,
        })
    else {
        return ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "Client authentication required for client_credentials grant",
        )
        .into_oauth_response()
        .into_response();
    };

    // RFC 6749 Section 4.4: client_credentials requires a confidential client
    if authenticated_client.is_public {
        return ServiceError::oauth(
            OAuthErrorCode::UnauthorizedClient,
            "Public clients are not allowed to use client_credentials grant",
        )
        .into_oauth_response()
        .into_response();
    }

    match exchange_client_credentials(
        &state,
        &authenticated_client.client,
        params.scope.as_deref(),
    )
    .await
    {
        Ok(result) => {
            // Record audit event
            if let Err(e) = crate::db::record_oauth_event(
                &state.audit,
                &authenticated_client.client.id,
                crate::db::OAuthEventType::TokenIssued,
                None,
                client_info.client_ip,
                client_info.user_agent.as_deref(),
                Some("grant_type=client_credentials"),
            )
            .await
            {
                tracing::warn!("Failed to record OAuth event: {e}");
            }

            token_success_response(TokenResponse {
                access_token: result.access_token,
                token_type: result.token_type,
                expires_in: result.expires_in,
                id_token: None,
                scope: result.scope,
                email: None,
                authorization_details: None,
            })
        }
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
///
/// RFC 8693 Section 2.1: The token exchange grant requires client
/// authentication. The client_id in the authenticated credentials must
/// match any client_id provided in the request body.
async fn handle_token_exchange_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    params: TokenRequest,
) -> Response {
    // Extract client authentication (supports secret-based and JWT assertion)
    let client_auth = match extract_client_auth(&headers, &params) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };

    // Authenticate client (required for token exchange)
    let Some((authenticated_client, _client_id)) =
        (match authenticate_client_any(&state, client_auth).await {
            Ok(result) => result,
            Err(resp) => return resp,
        })
    else {
        return ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "Client authentication required for token exchange",
        )
        .into_oauth_response()
        .into_response();
    };

    // RFC 9449 Section 5: Validate DPoP proof if present at the token endpoint
    let dpop_header = headers.get("DPoP").and_then(|v| v.to_str().ok());
    let dpop_proof =
        match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/token").await {
            Ok(proof) => proof,
            Err(crate::services::oidc::dpop::DpopError::UseNonce(nonce)) => {
                return dpop_use_nonce_response(&nonce);
            }
            Err(e) => {
                return ServiceError::oauth(OAuthErrorCode::InvalidDpopProof, e.to_string())
                    .into_oauth_response()
                    .into_response();
            }
        };

    let dpop_jkt = dpop_proof.as_ref().map(|p| p.jkt.clone());

    // RFC 8707: If resource is present, use it as audience (unless audience is explicitly set).
    // If both are present, they must match.
    let effective_audience = match (params.audience.as_deref(), params.resource.as_deref()) {
        (Some(aud), Some(res)) if aud != res => {
            return ServiceError::oauth(
                OAuthErrorCode::InvalidTarget,
                "resource and audience parameters must match when both are provided",
            )
            .into_oauth_response()
            .into_response();
        }
        (Some(aud), _) => Some(aud),
        (None, Some(res)) => Some(res),
        (None, None) => None,
    };

    let exchange_params = TokenExchangeParams {
        subject_token: params.subject_token.as_deref().unwrap_or_default(),
        subject_token_type: params.subject_token_type.as_deref().unwrap_or_default(),
        actor_token: params.actor_token.as_deref(),
        actor_token_type: params.actor_token_type.as_deref(),
        audience: effective_audience,
        scope: params.scope.as_deref(),
        requested_token_type: params.requested_token_type.as_deref(),
        client_id: &authenticated_client.client.client_id,
        dpop_jkt: dpop_jkt.as_deref(),
        authorization_details: params.authorization_details.as_deref(),
    };

    match exchange_token(&state, exchange_params).await {
        Ok(result) => token_success_response(TokenExchangeResponse {
            access_token: result.access_token,
            issued_token_type: result.issued_token_type,
            token_type: result.token_type,
            expires_in: result.expires_in,
            scope: result.scope,
            authorization_details: result
                .authorization_details
                .as_ref()
                .map(serde_json::Value::from),
        }),
        Err(e) => e.into_oauth_response().into_response(),
    }
}

/// Implement `ClientAuthFields` for `TokenRequest` to enable shared client
/// authentication extraction.
impl ClientAuthFields for TokenRequest {
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

/// Handle FIDO2 assertion grant.
///
/// Requires `private_key_jwt` client authentication and a FIDO2 assertion
/// in the `assertion` parameter. Optionally requires DPoP for FAPI clients.
async fn handle_fido2_assertion_grant(
    State(state): State<Arc<AppState>>,
    client_info: crate::handlers::extractors::ClientInfo,
    headers: HeaderMap,
    params: TokenRequest,
) -> Response {
    // The assertion parameter is REQUIRED
    let assertion = match &params.assertion {
        Some(a) => a.clone(),
        None => {
            return token_error_response(
                "invalid_request",
                "Missing assertion parameter for fido2-assertion grant",
            );
        }
    };

    // Extract and authenticate client via private_key_jwt
    let client_auth = match extract_client_auth(&headers, &params) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };

    let jwt_authenticated = match client_auth {
        ExtractedClientAuth::JwtAssertion {
            client_assertion,
            client_id,
        } => match authenticate_client_jwt(&state, &client_assertion, client_id.as_deref()).await {
            Ok(client) => client,
            Err(e) => return e.into_service_error().into_oauth_response().into_response(),
        },
        _ => {
            return token_error_response(
                "invalid_client",
                "fido2-assertion grant requires private_key_jwt client authentication",
            );
        }
    };

    // Validate DPoP proof if present
    let dpop_header = headers.get("DPoP").and_then(|v| v.to_str().ok());
    let dpop_proof =
        match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/token").await {
            Ok(proof) => proof,
            Err(crate::services::oidc::dpop::DpopError::UseNonce(nonce)) => {
                return dpop_use_nonce_response(&nonce);
            }
            Err(e) => {
                return ServiceError::oauth(OAuthErrorCode::InvalidDpopProof, e.to_string())
                    .into_oauth_response()
                    .into_response();
            }
        };

    // FAPI 2.0: Require DPoP for FAPI clients
    if let Err(e) = crate::services::oidc::fapi::validate_fapi_token_request(
        &jwt_authenticated.client,
        dpop_proof.is_some(),
    ) {
        return e.into_oauth_response().into_response();
    }

    // Exchange the FIDO2 assertion for an access token
    let exchange_params = crate::services::oidc::fido2_grant::Fido2AssertionParams {
        assertion: &assertion,
        client: &crate::services::oidc::token::AuthenticatedClient {
            client: jwt_authenticated.client,
            is_public: false,
        },
        dpop_proof,
        scope: params.scope.as_deref(),
        authorization_details: params.authorization_details.as_deref(),
        client_info,
    };

    match crate::services::oidc::fido2_grant::exchange_fido2_assertion(&state, exchange_params)
        .await
    {
        Ok(result) => {
            crate::infra::metrics::record_auth_event("fido2_login_success");
            token_success_response(TokenResponse {
                access_token: result.access_token,
                token_type: result.token_type,
                expires_in: result.expires_in,
                id_token: None,
                scope: result.scope,
                email: Some(result.email),
                authorization_details: result.authorization_details,
            })
        }
        Err(e) => {
            crate::infra::metrics::record_auth_event("fido2_login_failure");
            e.into_oauth_response().into_response()
        }
    }
}

/// Handle JWT bearer grant (RFC 7523 Section 2.1).
async fn handle_jwt_bearer_grant(
    State(state): State<Arc<AppState>>,
    params: TokenRequest,
) -> Response {
    // The assertion parameter is REQUIRED for jwt-bearer grants
    let assertion = match &params.assertion {
        Some(a) => a.clone(),
        None => {
            return token_error_response(
                "invalid_request",
                "Missing assertion parameter for jwt-bearer grant",
            );
        }
    };

    match exchange_jwt_bearer_grant(&state, &assertion, params.scope.as_deref()).await {
        Ok(result) => token_success_response(TokenResponse {
            access_token: result.access_token,
            token_type: result.token_type,
            expires_in: result.expires_in,
            id_token: None,
            scope: result.scope,
            email: None,
            authorization_details: None,
        }),
        Err(e) => e.into_oauth_response().into_response(),
    }
}

/// Validate PKCE code_verifier format per RFC 7636 Section 4.1.
///
/// The verifier must be 43-128 characters long and contain only unreserved
/// characters: `[A-Za-z0-9\-._~]`.
fn is_valid_pkce_verifier(verifier: &str) -> bool {
    verifier.len() >= 43
        && verifier.len() <= 128
        && verifier.bytes().all(
            |b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'),
        )
}

/// Build a token success response with RFC 6749 §5.1 cache headers.
///
/// RFC 6749 §5.1: "The authorization server MUST include the HTTP
/// `Cache-Control` response header field with a value of `no-store`
/// in any response containing tokens, credentials, or other sensitive
/// information, as well as the `Pragma` response header field with a
/// value of `no-cache`."
fn token_success_response(body: impl Serialize) -> Response {
    (
        StatusCode::OK,
        [
            ("cache-control", "no-cache, no-store, must-revalidate"),
            ("pragma", "no-cache"),
            ("expires", "0"),
        ],
        Json(body),
    )
        .into_response()
}

/// Build a `use_dpop_nonce` error response with the `DPoP-Nonce` header.
///
/// RFC 9449 Section 4.3: When the server requires a nonce, the error response
/// MUST include the `DPoP-Nonce` header so the client can retry.
fn dpop_use_nonce_response(nonce: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(
            axum::http::header::HeaderName::from_static("dpop-nonce"),
            nonce.to_string(),
        )],
        Json(OAuthErrorResponse {
            error: "use_dpop_nonce".to_string(),
            error_description: Some(
                "Authorization server requires nonce in DPoP proof".to_string(),
            ),
            error_uri: None,
        }),
    )
        .into_response()
}

/// Build an OAuth error response for parameter validation failures.
fn token_error_response(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuthErrorResponse {
            error: error.to_string(),
            error_description: Some(description.to_string()),
            error_uri: None,
        }),
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::OAuthGrantType;

    #[test]
    fn test_oauth_grant_type_from_str_authorization_code() {
        let result: Result<OAuthGrantType, _> = "authorization_code".parse();
        assert_eq!(result, Ok(OAuthGrantType::AuthorizationCode));
    }

    #[test]
    fn test_oauth_grant_type_from_str_device_code() {
        let result: Result<OAuthGrantType, _> =
            "urn:ietf:params:oauth:grant-type:device_code".parse();
        assert_eq!(result, Ok(OAuthGrantType::DeviceCode));
    }

    #[test]
    fn test_oauth_grant_type_from_str_token_exchange() {
        let result: Result<OAuthGrantType, _> =
            "urn:ietf:params:oauth:grant-type:token-exchange".parse();
        assert_eq!(result, Ok(OAuthGrantType::TokenExchange));
    }

    #[test]
    fn test_oauth_grant_type_from_str_jwt_bearer() {
        let result: Result<OAuthGrantType, _> =
            "urn:ietf:params:oauth:grant-type:jwt-bearer".parse();
        assert_eq!(result, Ok(OAuthGrantType::JwtBearer));
    }

    #[test]
    fn test_oauth_grant_type_from_str_fido2_assertion() {
        let result: Result<OAuthGrantType, _> =
            "urn:ietf:params:oauth:grant-type:fido2-assertion".parse();
        assert_eq!(result, Ok(OAuthGrantType::Fido2Assertion));
    }

    #[test]
    fn test_oauth_grant_type_from_str_client_credentials() {
        let result: Result<OAuthGrantType, _> = "client_credentials".parse();
        assert_eq!(result, Ok(OAuthGrantType::ClientCredentials));
    }

    #[test]
    fn test_oauth_grant_type_from_str_rejects_unknown() {
        let result: Result<OAuthGrantType, _> = "password".parse();
        assert!(result.is_err());

        let result2: Result<OAuthGrantType, _> = "".parse();
        assert!(result2.is_err());

        let result3: Result<OAuthGrantType, _> = "jwt-bearer".parse();
        assert!(result3.is_err());
    }
}
