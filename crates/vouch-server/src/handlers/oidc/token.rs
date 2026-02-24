// SPDX-License-Identifier: BUSL-1.1
//! Token endpoint handler.

use crate::AppState;
use crate::services::error::OAuthErrorResponse;
use crate::services::oidc::{
    ScopeSet,
    exchange::{TokenExchangeParams, exchange_token},
    jwt_bearer::{client_auth::authenticate_client_jwt, grant::exchange_jwt_bearer_grant},
    token::{
        AuthCodeExchangeParams, ClientCredentials, authenticate_client,
        exchange_authorization_code, validate_dpop_if_present,
    },
};
use crate::services::{OAuthErrorCode, ServiceError};
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

/// RFC 7521 Section 4.2: Expected client assertion type for JWT bearer.
const JWT_BEARER_CLIENT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// RFC 7523 Section 2.1: Grant type for JWT bearer authorization grants.
const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Extracted client authentication method from a token request.
///
/// Represents the mutually-exclusive authentication methods that a client
/// can use at the token endpoint (RFC 7521 Section 4.2).
enum ExtractedClientAuth {
    /// Client secret via Basic header or body params.
    Secret(ClientCredentials),
    /// JWT assertion (RFC 7523).
    JwtAssertion {
        client_assertion: String,
        client_id: Option<String>,
    },
    /// Public client with only client_id.
    PublicClient { client_id: String },
    /// No authentication provided.
    None,
}

/// OAuth grant types supported by this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthGrantType {
    /// Standard OAuth 2.0 authorization code grant.
    AuthorizationCode,
    /// Device authorization grant (RFC 8628).
    DeviceCode,
    /// Token exchange grant (RFC 8693).
    TokenExchange,
    /// JWT bearer assertion grant (RFC 7523).
    JwtBearer,
}

impl std::str::FromStr for OAuthGrantType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authorization_code" => Ok(Self::AuthorizationCode),
            "urn:ietf:params:oauth:grant-type:device_code" => Ok(Self::DeviceCode),
            "urn:ietf:params:oauth:grant-type:token-exchange" => Ok(Self::TokenExchange),
            JWT_BEARER_GRANT_TYPE => Ok(Self::JwtBearer),
            _ => Err(format!("unsupported grant_type: {s}")),
        }
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
            .finish()
    }
}

// Maximum lengths for token request parameters.
const MAX_CODE_VERIFIER_LEN: usize = 128;
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
    headers: HeaderMap,
    axum::Form(params): axum::Form<TokenRequest>,
) -> Response {
    // Input length validation — reject oversized parameters early.
    if let Some(ref v) = params.code_verifier
        && v.len() > MAX_CODE_VERIFIER_LEN
    {
        return token_error_response(
            "invalid_request",
            &format!("code_verifier exceeds maximum length of {MAX_CODE_VERIFIER_LEN}"),
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

    // RFC 6749 Section 5.2: Return unsupported_grant_type error for unknown grants
    let Ok(grant_type) = params.grant_type.parse::<OAuthGrantType>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(OAuthErrorResponse {
                error: "unsupported_grant_type".to_string(),
                error_description: Some(
                    format!("Supported grant types: authorization_code, urn:ietf:params:oauth:grant-type:device_code, urn:ietf:params:oauth:grant-type:token-exchange, {JWT_BEARER_GRANT_TYPE}"),
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
        OAuthGrantType::TokenExchange => {
            handle_token_exchange_grant(State(state), headers, params).await
        }
        OAuthGrantType::JwtBearer => handle_jwt_bearer_grant(State(state), params).await,
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
            Err(e) => return e.into_oauth_response().into_response(),
        };

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
            Err(e) => return e.into_oauth_response().into_response(),
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

/// Extract client authentication from a token request (RFC 7521 Section 4.2).
///
/// Handles mutual exclusion: a request MUST NOT use more than one client
/// authentication method (e.g., Basic auth header + client_assertion = error).
#[allow(clippy::result_large_err)]
fn extract_client_auth(
    headers: &HeaderMap,
    params: &TokenRequest,
) -> Result<ExtractedClientAuth, Response> {
    let has_basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.starts_with("Basic "));

    let has_client_secret = params.client_secret.is_some();
    let has_client_assertion = params.client_assertion.is_some();

    // RFC 7521 Section 4.2: MUST NOT use more than one method
    if has_client_assertion && (has_basic || has_client_secret) {
        return Err(token_error_response(
            "invalid_request",
            "client_assertion cannot be combined with Basic auth or client_secret",
        ));
    }

    // JWT client assertion
    if let Some(ref assertion) = params.client_assertion {
        // Validate assertion type
        let assertion_type = params.client_assertion_type.as_deref().unwrap_or("");
        if assertion_type != JWT_BEARER_CLIENT_ASSERTION_TYPE {
            return Err(token_error_response(
                "invalid_request",
                &format!(
                    "Unsupported client_assertion_type. Expected: {JWT_BEARER_CLIENT_ASSERTION_TYPE}"
                ),
            ));
        }

        return Ok(ExtractedClientAuth::JwtAssertion {
            client_assertion: assertion.clone(),
            client_id: params.client_id.clone(),
        });
    }

    // Secret-based auth (Basic header or body params)
    if let Some(creds) = extract_client_credentials(
        headers,
        params.client_id.as_deref(),
        params.client_secret.clone(),
    ) {
        if creds.client_secret.is_some() || has_basic {
            return Ok(ExtractedClientAuth::Secret(creds));
        }
        // client_id only, no secret
        return Ok(ExtractedClientAuth::PublicClient {
            client_id: creds.client_id,
        });
    }

    Ok(ExtractedClientAuth::None)
}

/// Authenticate a client using any supported method.
///
/// Dispatches to secret-based or JWT-based authentication depending on
/// the extracted authentication method.
async fn authenticate_client_any(
    state: &Arc<AppState>,
    auth: ExtractedClientAuth,
) -> Result<Option<(crate::services::oidc::token::AuthenticatedClient, String)>, Response> {
    match auth {
        ExtractedClientAuth::Secret(creds) => {
            let client_id = creds.client_id.clone();
            match authenticate_client(state, &creds).await {
                Ok(client) => Ok(Some((client, client_id))),
                Err(e) => Err(e.into_service_error().into_oauth_response().into_response()),
            }
        }
        ExtractedClientAuth::JwtAssertion {
            client_assertion,
            client_id,
        } => match authenticate_client_jwt(state, &client_assertion, client_id.as_deref()).await {
            Ok(client) => {
                let cid = client.client.client_id.clone();
                Ok(Some((client, cid)))
            }
            Err(e) => Err(e.into_service_error().into_oauth_response().into_response()),
        },
        ExtractedClientAuth::PublicClient { client_id } => {
            // Public client — create credentials without a secret for authenticate_client
            let creds = ClientCredentials {
                client_id: client_id.clone(),
                client_secret: None,
            };
            match authenticate_client(state, &creds).await {
                Ok(client) => Ok(Some((client, client_id))),
                Err(e) => Err(e.into_service_error().into_oauth_response().into_response()),
            }
        }
        ExtractedClientAuth::None => Ok(None),
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
        Ok(result) => Json(TokenResponse {
            access_token: result.access_token,
            token_type: result.token_type,
            expires_in: result.expires_in,
            id_token: None,
            scope: result.scope,
        })
        .into_response(),
        Err(e) => e.into_oauth_response().into_response(),
    }
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
    fn test_oauth_grant_type_from_str_rejects_unknown() {
        let result: Result<OAuthGrantType, _> = "client_credentials".parse();
        assert!(result.is_err());

        let result2: Result<OAuthGrantType, _> = "".parse();
        assert!(result2.is_err());

        let result3: Result<OAuthGrantType, _> = "jwt-bearer".parse();
        assert!(result3.is_err());
    }
}
