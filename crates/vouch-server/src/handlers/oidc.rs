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
use askama::Template;
use axum::{
    Json,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use vouch_common::ApiError;

// ============================================================================
// Templates
// ============================================================================

/// Authorization page template.
#[derive(Template)]
#[template(path = "authorize.html")]
pub struct AuthorizeTemplate {
    pub client_id: String,
}

impl IntoResponse for AuthorizeTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

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

            match auth_code.encode(&state.config.jwt_secret) {
                Ok(code) => {
                    let mut redirect_url = format!("{}?code={}", params.redirect_uri, code);
                    if let Some(state_param) = &params.state {
                        redirect_url
                            .push_str(&format!("&state={}", urlencoding::encode(state_param)));
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
}

/// POST /oauth/token (authorization_code grant)
///
/// Exchange an authorization code for tokens.
/// Note: Device code flow is handled in device.rs
#[allow(clippy::too_many_lines, dead_code)]
pub async fn token(
    State(state): State<Arc<AppState>>,
    axum::Form(params): axum::Form<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ApiError>)> {
    // Only handle authorization_code grant here
    // Device code grant is handled in device.rs
    if params.grant_type != "authorization_code" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "unsupported_grant_type",
                "Only authorization_code grant type is supported at this endpoint",
            )),
        ));
    }

    let code = params.code.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("invalid_request", "Missing code parameter")),
        )
    })?;

    // Decode and validate the authorization code
    let auth_code = AuthorizationCode::decode(code, &state.config.jwt_secret).map_err(|_| {
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

    // Validate redirect_uri matches
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
            let mut hasher = Sha256::new();
            hasher.update(code_verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(hasher.finalize())
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

    // Generate access token (opaque token that maps to session)
    let access_token = generate_access_token();
    let expires_in = state.config.session_hours * 3600;

    // Generate ID token
    let id_token = generate_id_token(
        &state,
        &auth_code.client_id,
        &auth_code.user_id,
        &auth_code.email,
        auth_code.aaguid.as_deref(),
        auth_code.nonce.as_deref(),
        expires_in,
    )?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        id_token: Some(id_token),
        scope: Some(auth_code.scope),
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
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
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

/// Hash a token for storage comparison.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Generate an opaque access token.
#[allow(dead_code)]
fn generate_access_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("vouch_{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Generate an OIDC ID token.
#[allow(dead_code)]
fn generate_id_token(
    state: &Arc<AppState>,
    client_id: &str,
    _user_id: &str,
    email: &str,
    aaguid: Option<&str>,
    nonce: Option<&str>,
    expires_in: u64,
) -> Result<String, (StatusCode, Json<ApiError>)> {
    let now = Timestamp::now();
    let exp = now
        .as_second()
        .checked_add(i64::try_from(expires_in).unwrap_or(28800))
        .unwrap_or(now.as_second() + 28800);

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
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
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
