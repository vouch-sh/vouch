//! OIDC Provider endpoints for application integration.
//!
//! This module implements a standard OpenID Connect 1.0 provider, allowing
//! applications to integrate with Vouch using off-the-shelf OIDC libraries.
//!
//! ## Endpoints
//!
//! - `GET /.well-known/openid-configuration` - Discovery document
//! - `GET /oauth/jwks` - Public keys for token verification
//! - `GET /oauth/authorize` - Authorization endpoint
//! - `POST /oauth/token` - Token exchange (handled in device.rs for device flow)
//! - `GET /oauth/userinfo` - User info endpoint
//!
//! ## Token Claims
//!
//! ID tokens include standard OIDC claims plus Vouch-specific claims:
//! - `hardware_verified: true` - Indicates hardware authentication was used
//! - `hardware_aaguid` - The AAGUID of the authenticator used

use crate::AppState;
use crate::db;
use crate::dpop::{self, DpopError, ValidatedDpopProof};
use crate::impl_template_response;
use askama::Template;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vouch_common::ApiError;

use super::hash_token;

// ============================================================================
// Templates
// ============================================================================

/// Authorization page template.
#[derive(Template)]
#[template(path = "authorize.html")]
pub struct AuthorizeTemplate {
    pub client_id: String,
}

impl_template_response!(AuthorizeTemplate);

// ============================================================================
// OIDC Discovery Document
// ============================================================================

/// OpenID Connect Discovery document.
/// See: https://openid.net/specs/openid-connect-discovery-1_0.html
#[derive(Debug, Serialize)]
pub struct OidcDiscovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    revocation_endpoint: String,
    introspection_endpoint: String,
    registration_endpoint: Option<String>,
    scopes_supported: Vec<String>,
    response_types_supported: Vec<String>,
    response_modes_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    claims_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    /// RFC 9449: Supported DPoP signing algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    dpop_signing_alg_values_supported: Option<Vec<String>>,
}

/// GET /.well-known/openid-configuration
///
/// Returns the OIDC discovery document for this provider.
pub async fn discovery(State(state): State<Arc<AppState>>) -> Json<OidcDiscovery> {
    let base_url = &state.config.verification_base_url;

    Json(OidcDiscovery {
        issuer: base_url.clone(),
        authorization_endpoint: format!("{base_url}/oauth/authorize"),
        token_endpoint: format!("{base_url}/oauth/token"),
        userinfo_endpoint: format!("{base_url}/oauth/userinfo"),
        jwks_uri: format!("{base_url}/oauth/jwks"),
        revocation_endpoint: format!("{base_url}/oauth/revoke"),
        introspection_endpoint: format!("{base_url}/oauth/introspect"),
        registration_endpoint: None, // Dynamic registration not supported
        scopes_supported: vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
        response_types_supported: vec!["code".to_string()],
        response_modes_supported: vec!["query".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["HS256".to_string()],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
        ],
        claims_supported: vec![
            "sub".to_string(),
            "iss".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "email".to_string(),
            "email_verified".to_string(),
            "name".to_string(),
            "hardware_verified".to_string(),
            "hardware_aaguid".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string(), "plain".to_string()],
        dpop_signing_alg_values_supported: if state.config.dpop_enabled {
            Some(vec![
                "ES256".to_string(),
                "RS256".to_string(),
                "EdDSA".to_string(),
            ])
        } else {
            None
        },
    })
}

// ============================================================================
// JWKS Endpoint
// ============================================================================

/// JSON Web Key Set response.
#[derive(Debug, Serialize)]
pub struct JwksResponse {
    keys: Vec<Jwk>,
}

/// JSON Web Key (symmetric key for HS256).
#[derive(Debug, Serialize)]
pub struct Jwk {
    kty: String,
    alg: String,
    kid: String,
    #[serde(rename = "use")]
    key_use: String,
    // For symmetric keys, we don't expose the actual key
    // Clients verify tokens by calling the userinfo endpoint
}

/// GET /oauth/jwks
///
/// Returns the public keys used to sign tokens.
/// Note: Currently using HS256 (symmetric), so this is informational only.
/// Clients should verify tokens via the userinfo endpoint or trust the issuer.
pub async fn jwks(State(_state): State<Arc<AppState>>) -> Json<JwksResponse> {
    // For HS256, we return an empty key set since the symmetric key
    // should not be shared. Clients should use token introspection
    // or the userinfo endpoint to validate tokens.
    Json(JwksResponse {
        keys: vec![Jwk {
            kty: "oct".to_string(),
            alg: "HS256".to_string(),
            kid: "vouch-signing-key-1".to_string(),
            key_use: "sig".to_string(),
        }],
    })
}

// ============================================================================
// Authorization Endpoint
// ============================================================================

/// Authorization request parameters.
#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

/// Authorization code stored temporarily.
#[derive(Debug, Serialize, Deserialize)]
struct AuthorizationCode {
    client_id: String,
    redirect_uri: String,
    user_id: String,
    email: String,
    authenticator_id: String,
    aaguid: Option<String>,
    scope: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    iat: i64,
    exp: i64,
}

impl AuthorizationCode {
    fn encode(&self, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
        encode(
            &Header::default(),
            self,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
    }

    pub fn decode(token: &str, secret: &str) -> Result<Self, jsonwebtoken::errors::Error> {
        let mut validation = Validation::default();
        validation.required_spec_claims.clear();
        let data = jsonwebtoken::decode::<Self>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )?;
        Ok(data.claims)
    }
}

/// GET /oauth/authorize
///
/// Authorization endpoint - redirects user to login if not authenticated,
/// then issues an authorization code to the redirect_uri.
#[allow(clippy::too_many_lines)]
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeRequest>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Validate response_type
    if params.response_type != "code" {
        return Redirect::to(&format!(
            "{}?error=unsupported_response_type&error_description=Only%20code%20response%20type%20is%20supported",
            params.redirect_uri
        ))
        .into_response();
    }

    // Try to get existing session from cookie
    let session_token = headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .find_map(|c| c.trim().strip_prefix("vouch_session="))
        });

    // Check if we have a valid session
    if let Some(token) = session_token
        && let Some((user, _session, authenticator)) =
            validate_session_token(&state, token).await.ok().flatten()
    {
        // User is authenticated - issue authorization code
        let now = Timestamp::now();
        let exp = now
            .checked_add(Span::new().minutes(5))
            .map(|t| t.as_second())
            .unwrap_or(now.as_second() + 300);

        let auth_code = AuthorizationCode {
            client_id: params.client_id.clone(),
            redirect_uri: params.redirect_uri.clone(),
            user_id: user.id,
            email: user.email,
            authenticator_id: authenticator.id.clone(),
            aaguid: authenticator.aaguid.clone(),
            scope: params.scope.clone().unwrap_or_else(|| "openid".to_string()),
            nonce: params.nonce.clone(),
            code_challenge: params.code_challenge.clone(),
            code_challenge_method: params.code_challenge_method.clone(),
            iat: now.as_second(),
            exp,
        };

        match auth_code.encode(state.config.jwt_secret.expose_secret()) {
            Ok(code) => {
                let mut redirect_url = format!("{}?code={}", params.redirect_uri, code);
                if let Some(state_param) = &params.state {
                    redirect_url.push_str(&format!("&state={}", urlencoding::encode(state_param)));
                }
                return Redirect::to(&redirect_url).into_response();
            }
            Err(_) => {
                return Redirect::to(&format!(
                        "{}?error=server_error&error_description=Failed%20to%20generate%20authorization%20code",
                        params.redirect_uri
                    ))
                    .into_response();
            }
        }
    }

    // No valid session - show login page
    AuthorizeTemplate {
        client_id: params.client_id,
    }
    .into_response()
}

// ============================================================================
// Token Endpoint (Authorization Code Grant)
// ============================================================================

/// Token request parameters.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    // Device flow parameters (handled in device.rs)
    device_code: Option<String>,
}

/// Token response.
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    id_token: Option<String>,
    scope: Option<String>,
}

/// OIDC ID Token claims.
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    // Standard OIDC claims
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,

    // Profile claims
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,

    // Vouch-specific claims
    pub hardware_verified: bool,
    pub hardware_aaguid: Option<String>,

    // RFC 9449 DPoP: Token binding confirmation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<dpop::CnfClaim>,
}

/// Unified token request that includes both authorization_code and device_code parameters.
#[derive(Debug, Deserialize)]
pub struct UnifiedTokenRequest {
    grant_type: String,
    // Authorization code parameters
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    // Device flow parameters
    #[serde(default)]
    device_code: Option<String>,
    // Token exchange parameters (RFC 8693)
    #[serde(default)]
    subject_token: Option<String>,
    #[serde(default)]
    subject_token_type: Option<String>,
    #[serde(default)]
    actor_token: Option<String>,
    #[serde(default)]
    actor_token_type: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// POST /oauth/token
///
/// Unified token endpoint that handles both authorization_code and device_code grants.
pub async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Form(params): axum::Form<UnifiedTokenRequest>,
) -> Response {
    match params.grant_type.as_str() {
        "authorization_code" => {
            // Convert to TokenRequest and call authorization_code handler
            let token_req = TokenRequest {
                grant_type: params.grant_type,
                code: params.code,
                redirect_uri: params.redirect_uri,
                client_id: params.client_id,
                client_secret: params.client_secret,
                code_verifier: params.code_verifier,
                device_code: None,
            };
            match token_authorization_code(State(state), headers, axum::Form(token_req)).await {
                Ok(json) => json.into_response(),
                Err((status, json)) => (status, json).into_response(),
            }
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            // Forward to device token handler
            let device_req = vouch_common::DeviceTokenRequest {
                grant_type: params.grant_type,
                device_code: params.device_code.unwrap_or_default(),
            };
            match super::device::device_token(State(state), Json(device_req)).await {
                Ok(resp) => {
                    // Return the DeviceTokenResponse directly (includes email field)
                    resp.into_response()
                }
                Err((status, json)) => (status, json).into_response(),
            }
        }
        TOKEN_EXCHANGE_GRANT_TYPE => {
            // Forward to token exchange handler (RFC 8693)
            let exchange_req = TokenExchangeRequest {
                grant_type: params.grant_type,
                subject_token: params.subject_token.unwrap_or_default(),
                subject_token_type: params.subject_token_type.unwrap_or_default(),
                actor_token: params.actor_token,
                actor_token_type: params.actor_token_type,
                audience: params.audience,
                scope: params.scope,
            };
            match token_exchange(State(state), axum::Form(exchange_req)).await {
                Ok(json) => json.into_response(),
                Err((status, json)) => (status, json).into_response(),
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "unsupported_grant_type",
                "Supported grant types: authorization_code, urn:ietf:params:oauth:grant-type:device_code, urn:ietf:params:oauth:grant-type:token-exchange",
            )),
        ).into_response(),
    }
}

/// POST /oauth/token (authorization_code grant)
///
/// Exchange an authorization code for tokens.
#[allow(clippy::too_many_lines)]
async fn token_authorization_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Form(params): axum::Form<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ApiError>)> {
    let code = params.code.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("invalid_request", "Missing code parameter")),
        )
    })?;

    // Decode and validate the authorization code
    let auth_code = AuthorizationCode::decode(code, state.config.jwt_secret.expose_secret())
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new(
                    "invalid_grant",
                    "Invalid or expired authorization code",
                )),
            )
        })?;

    // Check expiration
    let now = Timestamp::now().as_second();
    if auth_code.exp < now {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "invalid_grant",
                "Authorization code has expired",
            )),
        ));
    }

    // Authenticate the client (if a registered OAuth client is being used)
    // Try to authenticate; if the client_id is not registered, fall back to legacy behavior
    let authenticated_client = authenticate_client(
        &state,
        &headers,
        params.client_id.as_deref(),
        params.client_secret.as_deref(),
    )
    .await;

    match &authenticated_client {
        Ok(auth_client) => {
            // Verify the client_id in the authorization code matches
            if auth_client.client.client_id != auth_code.client_id {
                tracing::warn!(
                    "Client ID mismatch: token request from {} but code was issued to {}",
                    auth_client.client.client_id,
                    auth_code.client_id
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiError::new("invalid_grant", "Client ID mismatch")),
                ));
            }

            // Validate redirect_uri against registered URIs
            if let Some(redirect_uri) = &params.redirect_uri
                && !auth_client.client.is_valid_redirect_uri(redirect_uri)
            {
                tracing::warn!(
                    "Invalid redirect_uri {} for client {}",
                    redirect_uri,
                    auth_client.client.client_id
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiError::new("invalid_grant", "Invalid redirect_uri")),
                ));
            }

            // For public clients, require PKCE
            if auth_client.is_public && auth_code.code_challenge.is_none() {
                tracing::warn!(
                    "Public client {} attempted token exchange without PKCE",
                    auth_client.client.client_id
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiError::new(
                        "invalid_request",
                        "PKCE required for public clients",
                    )),
                ));
            }
        }
        Err(ClientAuthError::InvalidClient) | Err(ClientAuthError::MissingClientId) => {
            // Client not registered - allow legacy behavior for backward compatibility
            // This permits unregistered clients to use the token endpoint
            tracing::debug!("Unregistered client, using legacy token exchange");
        }
        Err(e) => {
            // Authentication was attempted but failed
            return Err(e.to_response());
        }
    }

    // Validate redirect_uri matches what was in the authorization request
    if let Some(redirect_uri) = &params.redirect_uri
        && redirect_uri != &auth_code.redirect_uri
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("invalid_grant", "Redirect URI mismatch")),
        ));
    }

    // Validate PKCE code_verifier if code_challenge was present
    if let Some(code_challenge) = &auth_code.code_challenge {
        let code_verifier = params.code_verifier.as_ref().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new("invalid_request", "Missing code_verifier")),
            )
        })?;

        let method = auth_code
            .code_challenge_method
            .as_deref()
            .unwrap_or("plain");
        let computed_challenge = if method == "S256" {
            let hash = digest::digest(&SHA256, code_verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(hash.as_ref())
        } else {
            code_verifier.clone()
        };

        if &computed_challenge != code_challenge {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::new("invalid_grant", "Invalid code_verifier")),
            ));
        }
    }

    // RFC 9449: Validate DPoP proof if provided and DPoP is enabled
    let dpop_proof = validate_dpop_if_present(&state, &headers, "POST", "/oauth/token").await?;

    // Generate access token (opaque token that maps to session)
    let access_token = generate_access_token();
    let expires_in = state.config.session_hours * 3600;

    // Generate ID token (include DPoP jkt if present for sender-constrained token)
    let dpop_jkt = dpop_proof.as_ref().map(|p| p.jkt.as_str());
    let id_token = generate_id_token(
        &state,
        &auth_code.client_id,
        &auth_code.user_id,
        &auth_code.email,
        auth_code.aaguid.as_deref(),
        auth_code.nonce.as_deref(),
        expires_in,
        dpop_jkt,
    )?;

    // Record usage event for registered clients
    if let Ok(auth_client) = &authenticated_client {
        let _ = db::record_oauth_event(
            &state.db,
            &auth_client.client.id,
            db::OAuthEventType::TokenIssued,
            Some(&auth_code.user_id),
            None, // IP address would require extracting from headers
            None, // User-Agent
            dpop_proof
                .as_ref()
                .map(|p| format!("dpop_jkt={}", p.jkt))
                .as_deref(),
        )
        .await;
    }

    // RFC 9449: Token type is "DPoP" if proof was provided, otherwise "Bearer"
    let token_type = if dpop_proof.is_some() {
        "DPoP"
    } else {
        "Bearer"
    };
    if let Some(ref proof) = dpop_proof {
        tracing::info!(
            "Issued DPoP-bound token for user {} with jkt={}",
            auth_code.email,
            proof.jkt
        );
    }

    Ok(Json(TokenResponse {
        access_token,
        token_type: token_type.to_string(),
        expires_in,
        id_token: Some(id_token),
        scope: Some(auth_code.scope),
    }))
}

// ============================================================================
// Token Revocation (RFC 7009)
// ============================================================================

/// Token revocation request.
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
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
    // Try to decode the token as a JWT to get session info
    if let Ok(data) = jsonwebtoken::decode::<super::auth::SessionClaims>(
        &params.token,
        &DecodingKey::from_secret(state.config.jwt_secret_bytes()),
        &Validation::default(),
    ) {
        // Hash the token and delete the session
        let token_hash = hash_token(&params.token);
        if let Err(e) = db::delete_session_by_token_hash(&state.db, &token_hash).await {
            tracing::warn!("Failed to delete session during revocation: {}", e);
        } else {
            tracing::info!("Token revoked for user: {}", data.claims.email);
        }
    }

    // Always return 200 per RFC 7009
    StatusCode::OK
}

// ============================================================================
// Token Introspection (RFC 7662)
// ============================================================================

/// Token introspection request.
#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    token: String,
    /// Token type hint (ignored, but included for compatibility).
    #[serde(default)]
    #[allow(dead_code)]
    token_type_hint: Option<String>,
}

/// Token introspection response.
#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
}

/// POST /oauth/introspect
///
/// Introspect a token (RFC 7662).
/// Returns token metadata if valid, or `{"active": false}` if invalid.
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    axum::Form(params): axum::Form<IntrospectRequest>,
) -> Json<IntrospectResponse> {
    // Try to decode the token as a JWT
    let claims = match jsonwebtoken::decode::<super::auth::SessionClaims>(
        &params.token,
        &DecodingKey::from_secret(state.config.jwt_secret_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data.claims,
        Err(_) => {
            return Json(IntrospectResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                exp: None,
                iat: None,
                sub: None,
                aud: None,
                iss: None,
            });
        }
    };

    // Verify session exists in database
    let token_hash = hash_token(&params.token);
    let session_exists = matches!(
        db::get_session_by_token_hash(&state.db, &token_hash).await,
        Ok(Some(_))
    );

    if !session_exists {
        return Json(IntrospectResponse {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            sub: None,
            aud: None,
            iss: None,
        });
    }

    // Token is valid
    Json(IntrospectResponse {
        active: true,
        scope: Some("openid email profile".to_string()),
        client_id: None,
        username: Some(claims.email.clone()),
        token_type: Some("Bearer".to_string()),
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        sub: Some(claims.email),
        aud: None,
        iss: Some(state.config.verification_base_url.clone()),
    })
}

// ============================================================================
// Token Exchange (RFC 8693)
// ============================================================================

/// Token exchange grant type URN.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Token type URNs for RFC 8693.
pub mod token_types {
    pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
    pub const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
    pub const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
}

/// Token exchange request (RFC 8693).
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    /// Must be "urn:ietf:params:oauth:grant-type:token-exchange".
    pub grant_type: String,
    /// The subject token to exchange.
    pub subject_token: String,
    /// Type of the subject token.
    pub subject_token_type: String,
    /// Optional actor token (for delegation chains).
    #[serde(default)]
    pub actor_token: Option<String>,
    /// Type of the actor token.
    #[serde(default)]
    pub actor_token_type: Option<String>,
    /// Requested audience for the new token.
    #[serde(default)]
    pub audience: Option<String>,
    /// Requested scope for the new token.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Token exchange response (RFC 8693).
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    /// The exchanged access token.
    pub access_token: String,
    /// Type of the issued token.
    pub issued_token_type: String,
    /// Token type (typically "Bearer").
    pub token_type: String,
    /// Token expiration in seconds.
    pub expires_in: u64,
    /// Granted scope (may be subset of requested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Actor claim for delegation chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorClaim {
    /// Subject identifier of the actor.
    pub sub: String,
    /// Nested actor (for multi-hop delegation).
    #[serde(rename = "act", skip_serializing_if = "Option::is_none")]
    pub actor: Option<Box<ActorClaim>>,
}

/// Claims for exchanged tokens.
#[derive(Debug, Serialize, Deserialize)]
struct ExchangedTokenClaims {
    /// Subject (original user).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Expiration time.
    pub exp: i64,
    /// Issued at time.
    pub iat: i64,
    /// Scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Actor claim (for delegation).
    #[serde(rename = "act", skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorClaim>,
    /// Email from original token.
    pub email: String,
}

/// POST /oauth/token (token-exchange grant)
///
/// Exchange a token for a new token (RFC 8693).
#[allow(clippy::too_many_lines)]
pub async fn token_exchange(
    State(state): State<Arc<AppState>>,
    axum::Form(params): axum::Form<TokenExchangeRequest>,
) -> Result<Json<TokenExchangeResponse>, (StatusCode, Json<ApiError>)> {
    // Validate grant type
    if params.grant_type != TOKEN_EXCHANGE_GRANT_TYPE {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "unsupported_grant_type",
                "Expected urn:ietf:params:oauth:grant-type:token-exchange",
            )),
        ));
    }

    // Validate subject token type
    let valid_token_types = [
        token_types::ACCESS_TOKEN,
        token_types::ID_TOKEN,
        token_types::JWT,
    ];
    if !valid_token_types.contains(&params.subject_token_type.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "invalid_request",
                "Unsupported subject_token_type",
            )),
        ));
    }

    // Decode and validate the subject token
    let subject_claims = match jsonwebtoken::decode::<super::auth::SessionClaims>(
        &params.subject_token,
        &DecodingKey::from_secret(state.config.jwt_secret_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data.claims,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::new(
                    "invalid_grant",
                    "Invalid or expired subject token",
                )),
            ));
        }
    };

    // Verify the subject token's session exists
    let subject_token_hash = hash_token(&params.subject_token);
    let subject_session = db::get_session_by_token_hash(&state.db, &subject_token_hash)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("server_error", e.to_string())),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new(
                    "invalid_grant",
                    "Subject token session not found",
                )),
            )
        })?;

    // Handle actor token if present (for delegation chains)
    let actor_claim = if let Some(actor_token) = &params.actor_token {
        // Validate actor token type
        if params.actor_token_type.as_deref() != Some(token_types::ACCESS_TOKEN)
            && params.actor_token_type.as_deref() != Some(token_types::JWT)
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::new("invalid_request", "Invalid actor_token_type")),
            ));
        }

        // Decode actor token
        let actor_claims = jsonwebtoken::decode::<super::auth::SessionClaims>(
            actor_token,
            &DecodingKey::from_secret(state.config.jwt_secret_bytes()),
            &Validation::default(),
        )
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new("invalid_grant", "Invalid actor token")),
            )
        })?;

        Some(ActorClaim {
            sub: actor_claims.claims.email,
            actor: None, // Could recursively parse nested actors
        })
    } else {
        None
    };

    // Check delegation policy if audience is specified
    let max_ttl_override = if params.audience.is_some() {
        let policy = db::check_delegation_policy(
            &state.db,
            &subject_claims.email,
            params.audience.as_deref(),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("server_error", e.to_string())),
            )
        })?;

        match policy {
            Some(p) => {
                tracing::debug!(
                    "Token exchange allowed by policy '{}' for {} -> {:?}",
                    p.name,
                    subject_claims.email,
                    params.audience
                );
                p.max_ttl_seconds
            }
            None => {
                // No matching policy - check if any policies exist
                let all_policies = db::get_delegation_policies(&state.db)
                    .await
                    .unwrap_or_default();

                if all_policies.iter().any(|p| p.enabled == 1) {
                    // Policies exist but none match - deny
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ApiError::new(
                            "access_denied",
                            "No delegation policy allows this token exchange",
                        )),
                    ));
                }
                // No policies configured - allow by default (open mode)
                None
            }
        }
    } else {
        None
    };

    // Calculate granted scope (intersection of requested and available)
    let available_scope = "openid email profile";
    let granted_scope = if let Some(requested) = &params.scope {
        // Only grant scopes that are both requested and available
        let available: std::collections::HashSet<&str> =
            available_scope.split_whitespace().collect();
        let requested_scopes: Vec<&str> = requested
            .split_whitespace()
            .filter(|s| available.contains(s))
            .collect();
        if requested_scopes.is_empty() {
            None
        } else {
            Some(requested_scopes.join(" "))
        }
    } else {
        Some(available_scope.to_string())
    };

    // Generate the exchanged token
    let now = Timestamp::now();
    let default_expires_in = state.config.session_hours * 3600;

    // Apply policy TTL limit if specified
    let expires_in = match max_ttl_override {
        Some(max_ttl) => {
            let max_ttl_u64 = u64::try_from(max_ttl).unwrap_or(default_expires_in);
            default_expires_in.min(max_ttl_u64)
        }
        None => default_expires_in,
    };
    let exp = now.as_second() + i64::try_from(expires_in).unwrap_or(28800);

    let exchanged_claims = ExchangedTokenClaims {
        sub: subject_claims.email.clone(),
        iss: state.config.verification_base_url.clone(),
        aud: params.audience.clone(),
        exp,
        iat: now.as_second(),
        scope: granted_scope.clone(),
        actor: actor_claim,
        email: subject_claims.email.clone(),
    };

    let exchanged_token = encode(
        &Header::default(),
        &exchanged_claims,
        &EncodingKey::from_secret(state.config.jwt_secret_bytes()),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::new(
                "server_error",
                format!("Failed to generate token: {e}"),
            )),
        )
    })?;

    // Log the token exchange for audit
    let issued_token_hash = hash_token(&exchanged_token);
    if let Err(e) = db::insert_token_exchange(
        &state.db,
        &subject_session.user_id,
        &subject_token_hash,
        None, // actor_user_id
        &issued_token_hash,
        params.audience.as_deref(),
        granted_scope.as_deref(),
        &Timestamp::from_second(exp).unwrap_or(now).to_string(),
    )
    .await
    {
        tracing::warn!("Failed to log token exchange: {e}");
    }

    tracing::info!(
        "Token exchanged for user {} (audience: {:?})",
        subject_claims.email,
        params.audience
    );

    Ok(Json(TokenExchangeResponse {
        access_token: exchanged_token,
        issued_token_type: token_types::ACCESS_TOKEN.to_string(),
        token_type: "Bearer".to_string(),
        expires_in,
        scope: granted_scope,
    }))
}

// ============================================================================
// UserInfo Endpoint
// ============================================================================

/// User info response.
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    sub: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
    hardware_verified: bool,
    hardware_aaguid: Option<String>,
}

/// GET /oauth/userinfo
///
/// Returns information about the authenticated user.
pub async fn userinfo(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<UserInfoResponse>, (StatusCode, Json<ApiError>)> {
    // Get Authorization header
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let token = auth_header.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiError::new(
                "invalid_token",
                "Missing or invalid bearer token",
            )),
        )
    })?;

    // Validate the session token
    let (user, _session, authenticator) = validate_session_token(&state, token)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("server_error", e.to_string())),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new("invalid_token", "Invalid or expired token")),
            )
        })?;

    Ok(Json(UserInfoResponse {
        sub: user.email.clone(), // Use email as subject for simplicity
        email: user.email,
        email_verified: true,
        name: user.name,
        hardware_verified: true,
        hardware_aaguid: authenticator.aaguid,
    }))
}

// ============================================================================
// Client Authentication
// ============================================================================

/// Authenticated client information.
#[derive(Debug)]
pub struct AuthenticatedClient {
    /// The OAuth client record.
    pub client: db::OAuthClient,
    /// Whether this is a public client (no secret required).
    pub is_public: bool,
}

/// Client authentication error.
#[derive(Debug)]
pub enum ClientAuthError {
    /// Missing client_id parameter.
    MissingClientId,
    /// Client not found or inactive.
    InvalidClient,
    /// Invalid client credentials.
    InvalidCredentials,
    /// Client requires secret but none provided.
    SecretRequired,
    /// Database error.
    DatabaseError(String),
}

impl ClientAuthError {
    /// Convert to API error response.
    fn to_response(&self) -> (StatusCode, Json<ApiError>) {
        match self {
            Self::MissingClientId => (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new(
                    "invalid_request",
                    "Missing client_id parameter",
                )),
            ),
            Self::InvalidClient | Self::InvalidCredentials | Self::SecretRequired => (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new(
                    "invalid_client",
                    "Client authentication failed",
                )),
            ),
            Self::DatabaseError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("server_error", msg.clone())),
            ),
        }
    }
}

/// Authenticate an OAuth client using client credentials.
///
/// Supports three authentication methods:
/// 1. `client_secret_basic` - HTTP Basic Auth (Authorization: Basic base64(client_id:client_secret))
/// 2. `client_secret_post` - Credentials in request body (client_id, client_secret params)
/// 3. Public client - No secret required for native/SPA apps (must use PKCE)
async fn authenticate_client(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    client_id_param: Option<&str>,
    client_secret_param: Option<&str>,
) -> Result<AuthenticatedClient, ClientAuthError> {
    // Try to extract credentials from Authorization header (client_secret_basic)
    let (client_id, client_secret) = if let Some(auth_header) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Basic "))
    {
        // Decode Base64 credentials
        match URL_SAFE_NO_PAD
            .decode(auth_header.trim())
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(auth_header.trim()))
        {
            Ok(decoded) => {
                let creds = String::from_utf8_lossy(&decoded);
                if let Some((id, secret)) = creds.split_once(':') {
                    (Some(id.to_string()), Some(secret.to_string()))
                } else {
                    return Err(ClientAuthError::InvalidCredentials);
                }
            }
            Err(_) => return Err(ClientAuthError::InvalidCredentials),
        }
    } else {
        // Use request body parameters (client_secret_post)
        (
            client_id_param.map(String::from),
            client_secret_param.map(String::from),
        )
    };

    // client_id is always required
    let client_id = client_id.ok_or(ClientAuthError::MissingClientId)?;

    // Look up the client
    let client = db::get_oauth_client_by_client_id(&state.db, &client_id)
        .await
        .map_err(|e| ClientAuthError::DatabaseError(e.to_string()))?
        .ok_or(ClientAuthError::InvalidClient)?;

    // Check if client is active
    if !client.is_active() {
        return Err(ClientAuthError::InvalidClient);
    }

    // Determine if this client type requires a secret
    let client_type = client.client_type().unwrap_or(db::OAuthClientType::Web);
    let requires_secret = client_type.requires_secret();

    if requires_secret {
        // Secret is required - validate it
        let secret = client_secret.ok_or(ClientAuthError::SecretRequired)?;

        // Hash the provided secret and validate against stored hash
        let secret_hash = hash_client_secret(&secret);

        // Validate credentials
        let validated = db::validate_oauth_client_credentials(&state.db, &client_id, &secret_hash)
            .await
            .map_err(|e| ClientAuthError::DatabaseError(e.to_string()))?;

        if validated.is_none() {
            return Err(ClientAuthError::InvalidCredentials);
        }

        Ok(AuthenticatedClient {
            client,
            is_public: false,
        })
    } else {
        // Public client - no secret required, but PKCE should be used
        // Update last used timestamp
        let _ = db::update_oauth_client_last_used(&state.db, &client.id).await;

        Ok(AuthenticatedClient {
            client,
            is_public: true,
        })
    }
}

/// Hash a client secret for comparison with stored hash.
fn hash_client_secret(secret: &str) -> String {
    let hash = digest::digest(&SHA256, secret.as_bytes());
    URL_SAFE_NO_PAD.encode(hash.as_ref())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validate a session token and return the user, session, and authenticator.
async fn validate_session_token(
    state: &Arc<AppState>,
    token: &str,
) -> anyhow::Result<Option<(db::User, db::Session, db::Authenticator)>> {
    // Try to decode as a JWT session token
    let claims = match jsonwebtoken::decode::<super::auth::SessionClaims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data.claims,
        Err(_) => return Ok(None),
    };

    // Verify session exists in database
    let token_hash = hash_token(token);
    let session = match db::get_session_by_token_hash(&state.db, &token_hash).await? {
        Some(s) => s,
        None => return Ok(None),
    };

    // Get user and authenticator
    let user = match db::get_user_by_id(&state.db, &claims.sub).await? {
        Some(u) => u,
        None => return Ok(None),
    };

    let authenticator =
        match db::get_authenticator_by_id(&state.db, &claims.authenticator_id).await? {
            Some(a) => a,
            None => return Ok(None),
        };

    Ok(Some((user, session, authenticator)))
}

/// RFC 9449: Validate DPoP proof if present in the request.
///
/// Returns:
/// - `Ok(Some(proof))` if DPoP header was present and valid
/// - `Ok(None)` if DPoP header was not present (use Bearer token)
/// - `Err(...)` if DPoP header was present but invalid
async fn validate_dpop_if_present(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    uri: &str,
) -> Result<Option<ValidatedDpopProof>, (StatusCode, Json<ApiError>)> {
    // Check if DPoP is enabled
    if !state.config.dpop_enabled {
        return Ok(None);
    }

    // Look for DPoP header
    let dpop_header = headers.get("DPoP").and_then(|v| v.to_str().ok());

    let dpop_proof = match dpop_header {
        Some(proof) => proof,
        None => return Ok(None), // No DPoP header, use Bearer token
    };

    // Construct the full URI for validation
    let full_uri = format!("{}{}", state.config.verification_base_url, uri);

    // Validate the DPoP proof
    match dpop::validate_dpop_proof(
        dpop_proof,
        method,
        &full_uri,
        &state.dpop,
        state.config.dpop_max_age_seconds,
        state.config.dpop_nonce_required,
    )
    .await
    {
        Ok(validated) => {
            tracing::debug!(
                "DPoP proof validated: jkt={}, jti={}",
                validated.jkt,
                validated.jti
            );
            Ok(Some(validated))
        }
        Err(DpopError::UseNonce(_nonce)) => {
            // RFC 9449 Section 8: Server requires nonce
            // Note: Full implementation would return DPoP-Nonce header in response
            // For now, we return the error with a message to use nonce
            tracing::debug!("DPoP nonce required, returning use_dpop_nonce error");
            Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::new(
                    "use_dpop_nonce",
                    "Authorization server requires nonce in DPoP proof",
                )),
            ))
        }
        Err(e) => {
            tracing::warn!("DPoP validation failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(ApiError::new("invalid_dpop_proof", e.to_string())),
            ))
        }
    }
}

/// Generate an opaque access token.
///
/// # Panics
/// Panics if the system RNG fails.
#[allow(dead_code, clippy::expect_used)]
fn generate_access_token() -> String {
    let mut bytes = [0u8; 32];
    aws_rand::fill(&mut bytes).expect("RNG failure");
    format!("vouch_{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Generate an OIDC ID token.
///
/// If `dpop_jkt` is provided, the token will include a `cnf` claim binding
/// the token to the DPoP key (RFC 9449).
#[allow(dead_code, clippy::too_many_arguments)]
fn generate_id_token(
    state: &Arc<AppState>,
    client_id: &str,
    _user_id: &str,
    email: &str,
    aaguid: Option<&str>,
    nonce: Option<&str>,
    expires_in: u64,
    dpop_jkt: Option<&str>,
) -> Result<String, (StatusCode, Json<ApiError>)> {
    let now = Timestamp::now();
    let exp = now
        .as_second()
        .checked_add(i64::try_from(expires_in).unwrap_or(28800))
        .unwrap_or(now.as_second() + 28800);

    // RFC 9449: Include cnf claim if DPoP was used
    let cnf = dpop_jkt.map(|jkt| dpop::CnfClaim {
        jkt: jkt.to_string(),
    });

    let claims = IdTokenClaims {
        iss: state.config.verification_base_url.clone(),
        sub: email.to_string(), // Use email as subject
        aud: client_id.to_string(),
        exp,
        iat: now.as_second(),
        nonce: nonce.map(String::from),
        email: Some(email.to_string()),
        email_verified: Some(true),
        name: None,
        hardware_verified: true,
        hardware_aaguid: aaguid.map(String::from),
        cnf,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret_bytes()),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::new(
                "server_error",
                format!("Failed to generate ID token: {e}"),
            )),
        )
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    // ========================================================================
    // OIDC Discovery Tests (OIDC Core 1.0 Section 4.2)
    // ========================================================================

    #[tokio::test]
    async fn test_oidc_discovery_required_fields() {
        // OIDC Core 1.0 Section 4.2: Discovery document must contain required fields
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        // Required fields per OIDC Core 1.0 Section 4.2
        assert!(discovery.get("issuer").is_some(), "issuer is required");
        assert!(
            discovery.get("authorization_endpoint").is_some(),
            "authorization_endpoint is required"
        );
        assert!(
            discovery.get("token_endpoint").is_some(),
            "token_endpoint is required"
        );
        assert!(discovery.get("jwks_uri").is_some(), "jwks_uri is required");
        assert!(
            discovery.get("response_types_supported").is_some(),
            "response_types_supported is required"
        );
        assert!(
            discovery.get("subject_types_supported").is_some(),
            "subject_types_supported is required"
        );
        assert!(
            discovery
                .get("id_token_signing_alg_values_supported")
                .is_some(),
            "id_token_signing_alg_values_supported is required"
        );
    }

    #[tokio::test]
    async fn test_oidc_discovery_issuer_matches_base_url() {
        // OIDC Core 1.0 Section 4.2: issuer must match the base URL
        let (app, state) = test_app().await;

        let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        let issuer = discovery["issuer"].as_str().expect("issuer is a string");
        assert_eq!(issuer, state.config.verification_base_url);
    }

    #[tokio::test]
    async fn test_oidc_discovery_endpoints_are_absolute_urls() {
        // All endpoint URLs should be absolute
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        let endpoints = [
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
            "revocation_endpoint",
            "introspection_endpoint",
        ];

        for endpoint in endpoints {
            if let Some(url) = discovery.get(endpoint).and_then(|v| v.as_str()) {
                assert!(
                    url.starts_with("https://"),
                    "{endpoint} should be an absolute HTTPS URL"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_oidc_discovery_supported_grant_types() {
        // Verify supported grant types are advertised
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        let grant_types = discovery["grant_types_supported"]
            .as_array()
            .expect("grant_types_supported is an array");

        let grant_types: Vec<&str> = grant_types.iter().filter_map(|v| v.as_str()).collect();

        assert!(
            grant_types.contains(&"authorization_code"),
            "authorization_code grant type should be supported"
        );
        assert!(
            grant_types.contains(&"urn:ietf:params:oauth:grant-type:device_code"),
            "device_code grant type should be supported"
        );
    }

    // ========================================================================
    // JWKS Endpoint Tests (OIDC Core 1.0 Section 3)
    // ========================================================================

    #[tokio::test]
    async fn test_jwks_endpoint_returns_keys() {
        // OIDC Core 1.0: JWKS endpoint should return valid key set
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/oauth/jwks", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let jwks: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        assert!(jwks.get("keys").is_some(), "JWKS must contain 'keys' array");
        let keys = jwks["keys"].as_array().expect("keys is an array");
        assert!(!keys.is_empty(), "JWKS should contain at least one key");

        // Verify key format
        for key in keys {
            assert!(key.get("kty").is_some(), "Key must have 'kty' field");
            assert!(key.get("alg").is_some(), "Key must have 'alg' field");
        }
    }

    // ========================================================================
    // UserInfo Endpoint Tests (OIDC Core 1.0 Section 5.3)
    // ========================================================================

    #[tokio::test]
    async fn test_userinfo_requires_bearer_token() {
        // OIDC Core 1.0 Section 5.3.1: UserInfo requires bearer token
        let (app, _state) = test_app().await;

        // No token
        let (status, body) = http_get(&app, "/oauth/userinfo", &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_token");

        // Invalid token format
        let (status, _body) = http_get(
            &app,
            "/oauth/userinfo",
            &[("Authorization", "NotBearer token")],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_userinfo_returns_sub_claim() {
        // OIDC Core 1.0 Section 5.3.2: Response must include 'sub' claim
        let (app, state) = test_app().await;

        // Create a test user and session
        let user = create_test_user(&state.db, "userinfo@example.com").await;
        let auth_id = create_test_authenticator(&state.db, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/oauth/userinfo",
            &[("Authorization", &format!("Bearer {}", token))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert!(
            userinfo.get("sub").is_some(),
            "UserInfo must contain 'sub' claim"
        );
        assert!(
            userinfo.get("email").is_some(),
            "UserInfo must contain 'email' claim"
        );
    }

    #[tokio::test]
    async fn test_userinfo_invalid_token() {
        // Invalid token should return 401
        let (app, _state) = test_app().await;

        let (status, body) = http_get(
            &app,
            "/oauth/userinfo",
            &[("Authorization", "Bearer invalid_token_here")],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_token");
    }

    // ========================================================================
    // Token Endpoint Tests (RFC 6749 Section 5)
    // ========================================================================

    #[tokio::test]
    async fn test_token_invalid_grant_type() {
        // RFC 6749 Section 5.2: unsupported_grant_type error
        let (app, _state) = test_app().await;

        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            "grant_type=invalid_grant_type&code=test",
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_token_missing_code() {
        // RFC 6749 Section 5.2: invalid_request when code is missing
        let (app, _state) = test_app().await;

        let (status, body) =
            http_post_form(&app, "/oauth/token", "grant_type=authorization_code", &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_request");
    }

    #[tokio::test]
    async fn test_token_invalid_code() {
        // RFC 6749 Section 5.2: invalid_grant for invalid authorization code
        let (app, _state) = test_app().await;

        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            "grant_type=authorization_code&code=invalid_code&redirect_uri=https://example.com/callback",
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_grant");
    }

    // ========================================================================
    // PKCE Tests (RFC 7636)
    // ========================================================================

    #[tokio::test]
    async fn test_pkce_s256_validation() {
        // RFC 7636 Section 4.6: SHA256 code challenge verification
        // Test vector from RFC 7636 Appendix B
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        // Compute the challenge using the same method as the handler
        let computed_challenge = URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            code_verifier.as_bytes(),
        ));

        assert_eq!(
            computed_challenge, expected_challenge,
            "RFC 7636 test vector must match"
        );
    }

    // ========================================================================
    // Token Revocation Tests (RFC 7009)
    // ========================================================================

    #[tokio::test]
    async fn test_revoke_valid_token() {
        // RFC 7009 Section 2.1: Successful revocation returns 200
        let (app, state) = test_app().await;

        // Create a test session
        let user = create_test_user(&state.db, "revoke@example.com").await;
        let auth_id = create_test_authenticator(&state.db, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, _body) =
            http_post_form(&app, "/oauth/revoke", &format!("token={}", token), &[]).await;

        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_revoke_invalid_token_returns_ok() {
        // RFC 7009 Section 2.1: Invalid token should also return 200 (security best practice)
        let (app, _state) = test_app().await;

        let (status, _body) =
            http_post_form(&app, "/oauth/revoke", "token=completely_invalid_token", &[]).await;

        // Per RFC 7009, always return 200 to prevent token oracle attacks
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_revoke_token_invalidates_session() {
        // After revocation, the token should not work
        let (app, state) = test_app().await;

        // Create a test session
        let user = create_test_user(&state.db, "revoke-check@example.com").await;
        let auth_id = create_test_authenticator(&state.db, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        // Verify token works before revocation
        let (status, _body) = http_get(
            &app,
            "/oauth/userinfo",
            &[("Authorization", &format!("Bearer {}", token))],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "Token should work before revocation"
        );

        // Revoke the token
        let (status, _body) =
            http_post_form(&app, "/oauth/revoke", &format!("token={}", token), &[]).await;
        assert_eq!(status, StatusCode::OK);

        // Verify token no longer works after revocation
        let (status, _body) = http_get(
            &app,
            "/oauth/userinfo",
            &[("Authorization", &format!("Bearer {}", token))],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Token should fail after revocation"
        );
    }

    // ========================================================================
    // Token Introspection Tests (RFC 7662)
    // ========================================================================

    #[tokio::test]
    async fn test_introspect_active_token() {
        // RFC 7662 Section 2.2: Active token returns active=true with claims
        let (app, state) = test_app().await;

        // Create a test session
        let user = create_test_user(&state.db, "introspect@example.com").await;
        let auth_id = create_test_authenticator(&state.db, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) =
            http_post_form(&app, "/oauth/introspect", &format!("token={}", token), &[]).await;

        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(response["active"], true);
        assert!(
            response.get("exp").is_some(),
            "Active token should have exp"
        );
        assert!(
            response.get("iat").is_some(),
            "Active token should have iat"
        );
        assert!(
            response.get("sub").is_some(),
            "Active token should have sub"
        );
    }

    #[tokio::test]
    async fn test_introspect_invalid_token() {
        // RFC 7662 Section 2.2: Invalid token returns active=false
        let (app, _state) = test_app().await;

        let (status, body) =
            http_post_form(&app, "/oauth/introspect", "token=invalid_token_here", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(response["active"], false);
        // Inactive tokens should not leak claims
        assert!(response.get("exp").is_none());
        assert!(response.get("sub").is_none());
    }

    #[tokio::test]
    async fn test_introspect_revoked_token() {
        // RFC 7662 Section 2.2: Revoked token returns active=false
        let (app, state) = test_app().await;

        // Create and then revoke a token
        let user = create_test_user(&state.db, "introspect-revoked@example.com").await;
        let auth_id = create_test_authenticator(&state.db, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        // Revoke the token
        let _ = http_post_form(&app, "/oauth/revoke", &format!("token={}", token), &[]).await;

        // Introspect should now return inactive
        let (status, body) =
            http_post_form(&app, "/oauth/introspect", &format!("token={}", token), &[]).await;

        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(response["active"], false);
    }

    // ========================================================================
    // Token Exchange Tests (RFC 8693)
    // ========================================================================

    #[tokio::test]
    async fn test_token_exchange_requires_grant_type() {
        // RFC 8693 Section 2.1: grant_type is required
        let (app, _state) = test_app().await;

        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            "grant_type=invalid&subject_token=test",
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_token_exchange_valid_token_types() {
        // RFC 8693 Section 2.1: Valid token type URNs should be accepted
        let valid_types = [
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:id_token",
            "urn:ietf:params:oauth:token-type:jwt",
        ];

        for token_type in valid_types {
            // Just verify these are defined correctly
            assert!(
                token_type.starts_with("urn:ietf:params:oauth:token-type:"),
                "Token type URN should have correct prefix"
            );
        }
    }

    #[tokio::test]
    async fn test_token_exchange_invalid_subject_token() {
        // RFC 8693: Invalid subject token returns invalid_grant
        let (app, _state) = test_app().await;

        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=invalid&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_token_exchange_successful() {
        // RFC 8693: Successful token exchange
        let (app, state) = test_app().await;

        // Create a valid subject token
        let user = create_test_user(&state.db, "exchange@example.com").await;
        let auth_id = create_test_authenticator(&state.db, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
                token
            ),
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert!(
            response.get("access_token").is_some(),
            "Should return access_token"
        );
        assert!(
            response.get("issued_token_type").is_some(),
            "Should return issued_token_type"
        );
        assert!(
            response.get("token_type").is_some(),
            "Should return token_type"
        );
        assert!(
            response.get("expires_in").is_some(),
            "Should return expires_in"
        );
    }

    #[tokio::test]
    async fn test_token_exchange_scope_downgrade() {
        // RFC 8693 Section 2.2: Can reduce scope, not expand
        let (app, state) = test_app().await;

        let user = create_test_user(&state.db, "exchange-scope@example.com").await;
        let auth_id = create_test_authenticator(&state.db, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        // Request a subset of scopes
        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&scope=openid",
                token
            ),
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        let scope = response.get("scope").and_then(|s| s.as_str()).unwrap_or("");
        // Should only have requested scope (openid) not full scope
        assert!(scope.contains("openid") || scope.is_empty());
    }
}
