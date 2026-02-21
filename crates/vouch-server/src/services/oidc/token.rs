// SPDX-License-Identifier: BUSL-1.1
//! Token endpoint operations.
//!
//! Implements:
//! - RFC 6749 Section 4.1 - Authorization Code Grant
//! - RFC 7636 - PKCE (Proof Key for Code Exchange)
//! - RFC 9449 - DPoP (Demonstrating Proof of Possession)

use super::authorization::CodeChallengeMethod;
use super::dpop::{self, CnfClaim, DpopError, ValidatedDpopProof};
use super::scope::{OAuthScope, ScopeSet};
use crate::AppState;
use crate::db::{self, Authenticator, OAuthClient, OAuthClientType, Session, SessionPurpose, User};
use crate::handlers::hash_token;
use crate::redact_email;
use crate::services::auth::{CreateSessionParams, SessionClaims, create_login_session};
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use aws_lc_rs::digest::{self, SHA256};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use jsonwebtoken::{DecodingKey, Validation};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use super::authorization::{AuthorizationCode, decode_authorization_code};

/// Parameters for exchanging an authorization code for tokens (RFC 6749 Section 4.1.3).
#[derive(Debug)]
pub struct AuthCodeExchangeParams<'a> {
    /// RFC 6749 Section 4.1.3: The authorization code received from the authorization server.
    pub code: &'a str,
    /// RFC 6749 Section 4.1.3: The redirect URI (REQUIRED if included in authorization request).
    pub redirect_uri: Option<&'a str>,
    /// RFC 6749 Section 2.3: Client credentials for authentication.
    pub credentials: Option<&'a ClientCredentials>,
    /// RFC 7636 Section 4.5: The PKCE code verifier.
    pub code_verifier: Option<&'a str>,
    /// RFC 9449 Section 5: Validated DPoP proof (if present).
    pub dpop_proof: Option<ValidatedDpopProof>,
}

/// Client credentials for authentication (RFC 6749 Section 2.3).
///
/// Supports `client_secret_basic` (RFC 6749 Section 2.3.1) and
/// `client_secret_post` (RFC 6749 Section 2.3.1) authentication methods.
///
/// The client secret is wrapped in `SecretString` to prevent accidental logging
/// and ensure it is zeroized on drop.
#[derive(Debug)]
pub struct ClientCredentials {
    /// Client ID (RFC 6749 Section 2.2).
    pub client_id: String,
    /// Client secret (optional for public clients per RFC 6749 Section 2.1).
    pub client_secret: Option<SecretString>,
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
    pub scope: ScopeSet,
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

/// OIDC ID Token claims (OIDC Core Section 2).
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// OIDC Core Section 2: Issuer Identifier.
    pub iss: String,
    /// OIDC Core Section 2: Subject Identifier.
    pub sub: String,
    /// OIDC Core Section 2: Audience(s).
    pub aud: String,
    /// OIDC Core Section 2: Expiration time.
    pub exp: i64,
    /// OIDC Core Section 2: Issued at time.
    pub iat: i64,
    /// OIDC Core Section 3.1.2.1: Nonce value from the authorization request.
    pub nonce: Option<String>,
    /// OIDC Core Section 5.1: User email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// OIDC Core Section 5.1: Whether the email has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Custom claim: Hardware verification flag (FIDO2 presence proof).
    pub hardware_verified: bool,
    /// Custom claim: Hardware authenticator AAGUID.
    pub hardware_aaguid: Option<String>,
    /// RFC 9449 Section 6: DPoP token binding confirmation.
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

    // RFC 6749 Section 4.1.3: Authenticate the client (if credentials provided)
    let authenticated_client = if let Some(creds) = params.credentials {
        match authenticate_client(state, creds).await {
            Ok(client) => {
                // RFC 6749 Section 4.1.3: Verify the client_id in the authorization code matches
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

                // RFC 7636 Section 4: Require PKCE for public clients and client types that mandate it
                let pkce_required = client.is_public
                    || client
                        .client
                        .client_type()
                        .is_some_and(|t| t.requires_pkce());
                if pkce_required && auth_code.code_challenge.is_none() {
                    tracing::warn!(
                        "Client {} requires PKCE but no code_challenge was present",
                        client.client.client_id
                    );
                    return Err(ServiceError::oauth(
                        OAuthErrorCode::InvalidRequest,
                        "PKCE required for this client type",
                    ));
                }

                Some(client)
            }
            // RFC 6749 Section 4.1.3: Client authentication is REQUIRED
            Err(ClientAuthError::InvalidClient | ClientAuthError::MissingClientId) => {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidClient,
                    "Client authentication required",
                ));
            }
            Err(e) => {
                return Err(e.into_service_error());
            }
        }
    } else {
        None
    };

    // RFC 6749 Section 4.1.3: redirect_uri MUST be present if it was in the authorization request
    if !auth_code.redirect_uri.is_empty() {
        match params.redirect_uri {
            Some(redirect_uri) if redirect_uri != auth_code.redirect_uri => {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidGrant,
                    "Redirect URI mismatch",
                ));
            }
            None => {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidRequest,
                    "redirect_uri is required when it was included in the authorization request",
                ));
            }
            _ => {} // matches
        }
    }

    // Validate PKCE code_verifier if code_challenge was present
    validate_pkce(&auth_code, params.code_verifier)?;

    // Generate access token as a JWT session (stored in DB, validatable by userinfo/introspect)
    let session_result = create_login_session(
        state,
        CreateSessionParams {
            user_id: &auth_code.user_id,
            email: &auth_code.email,
            authenticator_id: Some(&auth_code.authenticator_id),
            purpose: SessionPurpose::OAuthAccessToken,
            scope: Some(auth_code.scope.clone()),
        },
    )
    .await?;
    let access_token = session_result.token;
    let expires_in = state.config().session_hours * 3600;

    // Generate ID token
    let dpop_jkt = params.dpop_proof.as_ref().map(|p| p.jkt.as_str());
    let id_token = generate_id_token(
        state,
        IdTokenParams {
            client_id: &auth_code.client_id,
            email: &auth_code.email,
            aaguid: auth_code.aaguid.as_deref(),
            nonce: auth_code.nonce.as_deref(),
            expires_in,
            dpop_jkt,
            scope: &auth_code.scope,
        },
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

    // RFC 9449 Section 5: Token type is "DPoP" if proof was provided, otherwise "Bearer"
    let token_type = if params.dpop_proof.is_some() {
        "DPoP"
    } else {
        "Bearer"
    };

    if let Some(ref proof) = params.dpop_proof {
        tracing::info!(
            "Issued DPoP-bound token for user {} with jkt={}",
            redact_email(&auth_code.email),
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

/// Validate PKCE code verifier against code challenge (RFC 7636 Section 4.6).
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

    // RFC 7636 Section 4.6: Compute the challenge from the verifier using the method
    let method = auth_code
        .code_challenge_method
        .unwrap_or(CodeChallengeMethod::Plain);

    let computed_challenge = if method == CodeChallengeMethod::S256 {
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

/// Authenticate an OAuth client using client credentials (RFC 6749 Section 2.3).
///
/// Supports:
/// - Confidential clients with `client_secret` (RFC 6749 Section 2.3.1)
/// - Public clients (native/SPA) without secret (must use PKCE per RFC 7636)
pub async fn authenticate_client(
    state: &Arc<AppState>,
    credentials: &ClientCredentials,
) -> Result<AuthenticatedClient, ClientAuthError> {
    // Look up the client
    let client = db::get_oauth_client_by_client_id(&state.db, &credentials.client_id)
        .await
        .map_err(|e| ClientAuthError::DatabaseError(e.to_string()))?
        .ok_or(ClientAuthError::InvalidClient)?;

    // Check if client is active
    if !client.active {
        return Err(ClientAuthError::InvalidClient);
    }

    // Determine if this client type requires a secret
    let client_type = client.client_type().unwrap_or(OAuthClientType::Web);
    let requires_secret = client_type.requires_secret();

    if requires_secret {
        // Secret is required - validate it
        let secret = credentials
            .client_secret
            .as_ref()
            .ok_or(ClientAuthError::SecretRequired)?;

        // Hash the provided secret and validate against stored hash
        let secret_hash = hash_token(secret.expose_secret());

        // Validate credentials
        let validated =
            db::validate_oauth_client_credentials(&state.db, &credentials.client_id, &secret_hash)
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

/// Parameters for ID token generation.
struct IdTokenParams<'a> {
    client_id: &'a str,
    email: &'a str,
    aaguid: Option<&'a str>,
    nonce: Option<&'a str>,
    expires_in: u64,
    dpop_jkt: Option<&'a str>,
    scope: &'a ScopeSet,
}

/// Generate an OIDC ID token.
fn generate_id_token(state: &Arc<AppState>, params: IdTokenParams<'_>) -> ServiceResult<String> {
    let now = Timestamp::now();
    let expires_seconds = i64::try_from(params.expires_in)
        .map_err(|_| ServiceError::Internal("Invalid expires_in value".to_string()))?;
    let exp = now
        .as_second()
        .checked_add(expires_seconds)
        .ok_or_else(|| ServiceError::Internal("Expiration time overflow".to_string()))?;

    // RFC 9449: Include cnf claim if DPoP was used
    let cnf = params.dpop_jkt.map(|jkt| CnfClaim {
        jkt: jkt.to_string(),
    });

    let has_email = params.scope.contains(OAuthScope::Email);

    let claims = IdTokenClaims {
        iss: state.config().base_url.clone(),
        sub: params.email.to_string(), // Use email as subject
        aud: params.client_id.to_string(),
        exp,
        iat: now.as_second(),
        nonce: params.nonce.map(String::from),
        email: if has_email {
            Some(params.email.to_string())
        } else {
            None
        },
        email_verified: if has_email { Some(true) } else { None },
        hardware_verified: true,
        hardware_aaguid: params.aaguid.map(String::from),
        cnf,
    };

    state
        .oidc_key
        .sign_jwt(&claims)
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
    if !state.config().dpop_enabled {
        return Ok(None);
    }

    let dpop_proof = match dpop_header {
        Some(proof) => proof,
        None => return Ok(None), // No DPoP header, use Bearer token
    };

    // Construct the full URI for validation
    let full_uri = format!("{}{}", state.config().base_url, uri);

    // Validate the DPoP proof
    match dpop::validate_dpop_proof(
        dpop_proof,
        method,
        &full_uri,
        &state.dpop,
        state.config().dpop_max_age_seconds,
        state.config().dpop_nonce_required,
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

/// Result of validating a session token for OIDC endpoints.
///
/// Named `OidcValidatedSession` to avoid collision with
/// `handlers::common::ValidatedSession`.
pub struct OidcValidatedSession {
    /// The authenticated user.
    pub user: User,
    /// The database session record.
    pub session: Session,
    /// The authenticator used to create the session, if any.
    /// `None` for OIDC-only enrollment sessions that lack a hardware key.
    pub authenticator: Option<Authenticator>,
    /// Granted OAuth scope from the session JWT. `None` for FIDO2 sessions
    /// and legacy tokens issued before scope tracking.
    pub scope: Option<ScopeSet>,
}

/// Validate a session token and return the user, session, and authenticator.
pub async fn validate_session_token(
    state: &Arc<AppState>,
    token: &str,
) -> ServiceResult<Option<OidcValidatedSession>> {
    // Try to decode as a JWT session token
    let claims = match jsonwebtoken::decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(state.config().jwt_secret_bytes()),
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

    // Get authenticator if session references one.
    // If the JWT references an authenticator that no longer exists (deleted/revoked),
    // the session is invalid — this implements key revocation.
    let authenticator = match &claims.authenticator_id {
        Some(id) => {
            match db::get_authenticator_by_id(&state.db, id)
                .await
                .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
            {
                Some(a) => Some(a),
                None => return Ok(None), // authenticator revoked → session invalid
            }
        }
        None => None,
    };

    Ok(Some(OidcValidatedSession {
        user,
        session,
        authenticator,
        scope: claims.scope,
    }))
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
            scope: ScopeSet::parse("openid"),
            nonce: None,
            code_challenge: Some(expected_challenge.to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
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
            scope: ScopeSet::parse("openid"),
            nonce: None,
            code_challenge: Some("expected_challenge".to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
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
            scope: ScopeSet::parse("openid"),
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
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
            scope: ScopeSet::parse("openid"),
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
    fn test_hash_token_produces_consistent_base64url() {
        // Regression test: hash_token must produce base64url-encoded SHA-256 output.
        // A previous bug used hex encoding at creation time but base64url at validation,
        // causing client secret authentication to always fail.
        let input = "vouch_test_secret_value";
        let hash1 = hash_token(input);
        let hash2 = hash_token(input);

        // Must be deterministic
        assert_eq!(hash1, hash2);

        // SHA-256 produces 32 bytes; base64url-no-pad encodes that as 43 characters
        assert_eq!(hash1.len(), 43, "base64url(SHA-256) should be 43 chars");

        // Must contain only URL-safe base64 characters (no padding)
        assert!(
            hash1
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "hash must use URL-safe base64 characters only"
        );

        // Must NOT be hex-encoded (hex would be 64 chars)
        assert_ne!(hash1.len(), 64, "hash must not be hex-encoded");
    }
}
