// SPDX-License-Identifier: BUSL-1.1
//! Token endpoint operations.
//!
//! Implements:
//! - RFC 6749 Section 4.1 - Authorization Code Grant
//! - RFC 7636 - PKCE (Proof Key for Code Exchange)
//! - RFC 9449 - DPoP (Demonstrating Proof of Possession)

use crate::AppState;
use crate::db::{self, Authenticator, OAuthClient, OAuthClientType, Session, User};
use crate::dpop::{self, CnfClaim, DpopError, ValidatedDpopProof};
use crate::handlers::auth::SessionClaims;
use crate::handlers::hash_token;
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use super::authorization::{AuthorizationCode, decode_authorization_code};

/// Parameters for exchanging an authorization code for tokens.
#[derive(Debug)]
pub struct AuthCodeExchangeParams<'a> {
    /// The authorization code.
    pub code: &'a str,
    /// The redirect URI (must match original request).
    pub redirect_uri: Option<&'a str>,
    /// Client credentials.
    pub credentials: Option<ClientCredentials<'a>>,
    /// PKCE code verifier.
    pub code_verifier: Option<&'a str>,
    /// Validated DPoP proof (if present).
    pub dpop_proof: Option<ValidatedDpopProof>,
}

/// Client credentials for authentication.
#[derive(Debug)]
pub struct ClientCredentials<'a> {
    /// Client ID.
    pub client_id: &'a str,
    /// Client secret (optional for public clients).
    pub client_secret: Option<&'a str>,
}

/// Result of exchanging an authorization code.
#[derive(Debug)]
pub struct AuthCodeExchangeResult {
    /// The access token.
    pub access_token: String,
    /// Token type ("Bearer" or "DPoP").
    pub token_type: String,
    /// Expiration in seconds.
    pub expires_in: u64,
    /// The ID token (JWT).
    pub id_token: String,
    /// Granted scope.
    pub scope: String,
}

/// Authenticated client information.
#[derive(Debug)]
pub struct AuthenticatedClient {
    /// The OAuth client record.
    pub client: OAuthClient,
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
    /// Convert to `ServiceError`.
    #[must_use]
    pub fn into_service_error(self) -> ServiceError {
        match self {
            Self::MissingClientId => ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "Missing client_id parameter",
            ),
            Self::InvalidClient | Self::InvalidCredentials | Self::SecretRequired => {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidClient,
                    "Client authentication failed",
                )
            }
            Self::DatabaseError(msg) => ServiceError::Internal(msg),
        }
    }
}

/// OIDC ID Token claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer.
    pub iss: String,
    /// Subject.
    pub sub: String,
    /// Audience.
    pub aud: String,
    /// Expiration time.
    pub exp: i64,
    /// Issued at time.
    pub iat: i64,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// Email.
    pub email: Option<String>,
    /// Email verified.
    pub email_verified: Option<bool>,
    /// Name.
    pub name: Option<String>,
    /// Hardware verification flag.
    pub hardware_verified: bool,
    /// Hardware authenticator AAGUID.
    pub hardware_aaguid: Option<String>,
    /// RFC 9449 DPoP: Token binding confirmation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
}

/// Exchange an authorization code for tokens.
///
/// # Arguments
/// * `state` - Application state
/// * `params` - Exchange parameters
///
/// # Returns
/// The token response.
///
/// # Errors
/// Returns `ServiceError` for invalid requests.
#[allow(clippy::too_many_lines)]
pub async fn exchange_authorization_code(
    state: &Arc<AppState>,
    params: AuthCodeExchangeParams<'_>,
) -> ServiceResult<AuthCodeExchangeResult> {
    // Decode and validate the authorization code
    let auth_code = decode_authorization_code(state, params.code)?;

    // Authenticate the client (if credentials provided)
    let authenticated_client = if let Some(creds) = params.credentials {
        match authenticate_client(state, creds).await {
            Ok(client) => {
                // Verify the client_id in the authorization code matches
                if client.client.client_id != auth_code.client_id {
                    tracing::warn!(
                        "Client ID mismatch: token request from {} but code was issued to {}",
                        client.client.client_id,
                        auth_code.client_id
                    );
                    return Err(ServiceError::oauth(
                        OAuthErrorCode::InvalidGrant,
                        "Client ID mismatch",
                    ));
                }

                // For public clients, require PKCE
                if client.is_public && auth_code.code_challenge.is_none() {
                    tracing::warn!(
                        "Public client {} attempted token exchange without PKCE",
                        client.client.client_id
                    );
                    return Err(ServiceError::oauth(
                        OAuthErrorCode::InvalidRequest,
                        "PKCE required for public clients",
                    ));
                }

                Some(client)
            }
            Err(ClientAuthError::InvalidClient | ClientAuthError::MissingClientId) => {
                // Client not registered - allow legacy behavior for backward compatibility
                tracing::debug!("Unregistered client, using legacy token exchange");
                None
            }
            Err(e) => {
                return Err(e.into_service_error());
            }
        }
    } else {
        None
    };

    // Validate redirect_uri matches what was in the authorization request
    if let Some(redirect_uri) = params.redirect_uri
        && redirect_uri != auth_code.redirect_uri
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "Redirect URI mismatch",
        ));
    }

    // Validate PKCE code_verifier if code_challenge was present
    validate_pkce(&auth_code, params.code_verifier)?;

    // Generate access token (opaque token)
    let access_token = generate_access_token();
    let expires_in = state.config.session_hours * 3600;

    // Generate ID token
    let dpop_jkt = params.dpop_proof.as_ref().map(|p| p.jkt.as_str());
    let id_token = generate_id_token(
        state,
        &auth_code.client_id,
        &auth_code.user_id,
        &auth_code.email,
        auth_code.aaguid.as_deref(),
        auth_code.nonce.as_deref(),
        expires_in,
        dpop_jkt,
    )?;

    // Record usage event for registered clients
    if let Some(ref auth_client) = authenticated_client
        && let Err(e) = db::record_oauth_event(
            &state.db,
            &auth_client.client.id,
            db::OAuthEventType::TokenIssued,
            Some(&auth_code.user_id),
            None, // IP address
            None, // User-Agent
            params
                .dpop_proof
                .as_ref()
                .map(|p| format!("dpop_jkt={}", p.jkt))
                .as_deref(),
        )
        .await
    {
        tracing::warn!("Failed to record OAuth event: {e}");
    }

    // Token type is "DPoP" if proof was provided, otherwise "Bearer"
    let token_type = if params.dpop_proof.is_some() {
        "DPoP"
    } else {
        "Bearer"
    };

    if let Some(ref proof) = params.dpop_proof {
        tracing::info!(
            "Issued DPoP-bound token for user {} with jkt={}",
            auth_code.email,
            proof.jkt
        );
    }

    Ok(AuthCodeExchangeResult {
        access_token,
        token_type: token_type.to_string(),
        expires_in,
        id_token,
        scope: auth_code.scope,
    })
}

/// Validate PKCE code verifier against code challenge.
///
/// Uses constant-time comparison to prevent timing side-channel attacks.
fn validate_pkce(auth_code: &AuthorizationCode, code_verifier: Option<&str>) -> ServiceResult<()> {
    let Some(code_challenge) = &auth_code.code_challenge else {
        // No PKCE challenge in authorization code
        return Ok(());
    };

    let code_verifier = code_verifier.ok_or_else(|| {
        ServiceError::oauth(OAuthErrorCode::InvalidRequest, "Missing code_verifier")
    })?;

    let method = auth_code
        .code_challenge_method
        .as_deref()
        .unwrap_or("plain");

    let computed_challenge = if method == "S256" {
        let hash = digest::digest(&SHA256, code_verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(hash.as_ref())
    } else {
        code_verifier.to_string()
    };

    // Use constant-time comparison to prevent timing side-channel attacks
    let is_valid: bool = computed_challenge
        .as_bytes()
        .ct_eq(code_challenge.as_bytes())
        .into();

    if !is_valid {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "Invalid code_verifier",
        ));
    }

    Ok(())
}

/// Authenticate an OAuth client using client credentials.
///
/// Supports:
/// - Confidential clients with client_secret
/// - Public clients (native/SPA) without secret (must use PKCE)
pub async fn authenticate_client(
    state: &Arc<AppState>,
    credentials: ClientCredentials<'_>,
) -> Result<AuthenticatedClient, ClientAuthError> {
    // Look up the client
    let client = db::get_oauth_client_by_client_id(&state.db, credentials.client_id)
        .await
        .map_err(|e| ClientAuthError::DatabaseError(e.to_string()))?
        .ok_or(ClientAuthError::InvalidClient)?;

    // Check if client is active
    if !client.is_active() {
        return Err(ClientAuthError::InvalidClient);
    }

    // Determine if this client type requires a secret
    let client_type = client.client_type().unwrap_or(OAuthClientType::Web);
    let requires_secret = client_type.requires_secret();

    if requires_secret {
        // Secret is required - validate it
        let secret = credentials
            .client_secret
            .ok_or(ClientAuthError::SecretRequired)?;

        // Hash the provided secret and validate against stored hash
        let secret_hash = hash_client_secret(secret);

        // Validate credentials
        let validated =
            db::validate_oauth_client_credentials(&state.db, credentials.client_id, &secret_hash)
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
        if let Err(e) = db::update_oauth_client_last_used(&state.db, &client.id).await {
            tracing::warn!("Failed to update OAuth client last_used: {e}");
        }

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

/// Generate an opaque access token.
///
/// # Panics
/// Panics if the system RNG fails.
#[allow(clippy::expect_used)]
fn generate_access_token() -> String {
    let mut bytes = [0u8; 32];
    aws_rand::fill(&mut bytes).expect("RNG failure");
    format!("vouch_{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Generate an OIDC ID token.
#[allow(clippy::too_many_arguments)]
fn generate_id_token(
    state: &Arc<AppState>,
    client_id: &str,
    _user_id: &str,
    email: &str,
    aaguid: Option<&str>,
    nonce: Option<&str>,
    expires_in: u64,
    dpop_jkt: Option<&str>,
) -> ServiceResult<String> {
    let now = Timestamp::now();
    let exp = now
        .as_second()
        .checked_add(i64::try_from(expires_in).unwrap_or(28800))
        .unwrap_or(now.as_second() + 28800);

    // RFC 9449: Include cnf claim if DPoP was used
    let cnf = dpop_jkt.map(|jkt| CnfClaim {
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
    .map_err(|e| ServiceError::Internal(format!("Failed to generate ID token: {e}")))
}

/// Validate DPoP proof if present in the request.
///
/// # Arguments
/// * `state` - Application state
/// * `dpop_header` - The DPoP header value (if present)
/// * `method` - HTTP method
/// * `uri` - Request URI
///
/// # Returns
/// - `Ok(Some(proof))` if DPoP header was present and valid
/// - `Ok(None)` if DPoP header was not present (use Bearer token)
/// - `Err(...)` if DPoP header was present but invalid
pub async fn validate_dpop_if_present(
    state: &AppState,
    dpop_header: Option<&str>,
    method: &str,
    uri: &str,
) -> ServiceResult<Option<ValidatedDpopProof>> {
    // Check if DPoP is enabled
    if !state.config.dpop_enabled {
        return Ok(None);
    }

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
            tracing::debug!("DPoP nonce required, returning use_dpop_nonce error");
            Err(ServiceError::oauth(
                OAuthErrorCode::UseDpopNonce,
                "Authorization server requires nonce in DPoP proof",
            ))
        }
        Err(e) => {
            tracing::warn!("DPoP validation failed: {}", e);
            Err(ServiceError::oauth(
                OAuthErrorCode::InvalidDpopProof,
                e.to_string(),
            ))
        }
    }
}

/// Validate a session token and return the user, session, and authenticator.
pub async fn validate_session_token(
    state: &Arc<AppState>,
    token: &str,
) -> ServiceResult<Option<(User, Session, Authenticator)>> {
    // Try to decode as a JWT session token
    let claims = match jsonwebtoken::decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data.claims,
        Err(_) => return Ok(None),
    };

    // Verify session exists in database
    let token_hash = hash_token(token);
    let session = match db::get_session_by_token_hash(&state.db, &token_hash)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
    {
        Some(s) => s,
        None => return Ok(None),
    };

    // Get user
    let user = match db::get_user_by_id(&state.db, &claims.sub)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
    {
        Some(u) => u,
        None => return Ok(None),
    };

    // Get authenticator if session has one
    let authenticator_id = match &claims.authenticator_id {
        Some(id) => id,
        None => return Ok(None), // Session without authenticator can't be validated here
    };
    let authenticator = match db::get_authenticator_by_id(&state.db, authenticator_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
    {
        Some(a) => a,
        None => return Ok(None),
    };

    Ok(Some((user, session, authenticator)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_s256_validation() {
        // RFC 7636 Appendix B test vector
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let auth_code = AuthorizationCode {
            client_id: "test".to_string(),
            redirect_uri: "https://example.com".to_string(),
            user_id: "user1".to_string(),
            email: "test@example.com".to_string(),
            authenticator_id: "auth1".to_string(),
            aaguid: None,
            scope: "openid".to_string(),
            nonce: None,
            code_challenge: Some(expected_challenge.to_string()),
            code_challenge_method: Some("S256".to_string()),
            iat: 0,
            exp: i64::MAX,
        };

        let result = validate_pkce(&auth_code, Some(code_verifier));
        assert!(result.is_ok(), "RFC 7636 test vector should validate");
    }

    #[test]
    fn test_pkce_invalid_verifier() {
        let auth_code = AuthorizationCode {
            client_id: "test".to_string(),
            redirect_uri: "https://example.com".to_string(),
            user_id: "user1".to_string(),
            email: "test@example.com".to_string(),
            authenticator_id: "auth1".to_string(),
            aaguid: None,
            scope: "openid".to_string(),
            nonce: None,
            code_challenge: Some("expected_challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            iat: 0,
            exp: i64::MAX,
        };

        let result = validate_pkce(&auth_code, Some("wrong_verifier"));
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_missing_verifier() {
        let auth_code = AuthorizationCode {
            client_id: "test".to_string(),
            redirect_uri: "https://example.com".to_string(),
            user_id: "user1".to_string(),
            email: "test@example.com".to_string(),
            authenticator_id: "auth1".to_string(),
            aaguid: None,
            scope: "openid".to_string(),
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            iat: 0,
            exp: i64::MAX,
        };

        let result = validate_pkce(&auth_code, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_no_challenge() {
        // No PKCE challenge - should succeed
        let auth_code = AuthorizationCode {
            client_id: "test".to_string(),
            redirect_uri: "https://example.com".to_string(),
            user_id: "user1".to_string(),
            email: "test@example.com".to_string(),
            authenticator_id: "auth1".to_string(),
            aaguid: None,
            scope: "openid".to_string(),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            iat: 0,
            exp: i64::MAX,
        };

        let result = validate_pkce(&auth_code, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_access_token() {
        let token = generate_access_token();
        assert!(token.starts_with("vouch_"));
        assert!(token.len() > 40); // vouch_ prefix + base64 encoded 32 bytes
    }
}
