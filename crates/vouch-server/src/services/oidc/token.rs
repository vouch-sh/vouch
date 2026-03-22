// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Token endpoint operations.
//!
//! Implements:
//! - RFC 6749 Section 4.1 - Authorization Code Grant
//! - RFC 7636 - PKCE (Proof Key for Code Exchange)
//! - RFC 9449 - DPoP (Demonstrating Proof of Possession)

use super::authorization::CodeChallengeMethod;
use super::authorization_details::AuthorizationDetails;
use super::dpop::{self, CnfClaim, DpopError, ValidatedDpopProof};
use super::scope::{OAuthScope, ScopeSet};
use crate::AppState;
use crate::crypto::hash_token;
use crate::db::{self, Authenticator, OAuthClient, Session, User};
use crate::redact_email;
use crate::services::auth::{CreateOAuthTokenParams, create_oauth_access_token, decode_token};
use crate::services::oidc::amr::AuthMethod;
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use aws_lc_rs::digest::{self, SHA256};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
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
    /// RFC 8725 §3.9: Client ID for audience validation of the authorization code.
    pub client_id: &'a str,
    /// RFC 8707 Section 2: Target resource indicator (OPTIONAL).
    pub resource: Option<&'a str>,
    /// RFC 9396 Section 6: Authorization details for downscoping.
    pub authorization_details: Option<&'a str>,
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
    /// RFC 9396: Rich authorization details.
    pub authorization_details: Option<AuthorizationDetails>,
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
    /// OIDC Core Section 2: Subject Identifier (stable user ID, not email).
    pub sub: String,
    /// OIDC Core Section 2: Audience(s).
    pub aud: String,
    /// OIDC Core Section 2: Expiration time.
    pub exp: i64,
    /// OIDC Core Section 2: Issued at time.
    pub iat: i64,
    /// OIDC Core Section 2: Time when the End-User authentication occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// OIDC Core Section 3.1.2.1: Nonce value from the authorization request.
    pub nonce: Option<String>,
    /// OIDC Core Section 5.1: User email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// OIDC Core Section 5.1: Whether the email has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Custom claim: Hardware verification flag (FIDO2 presence proof).
    ///
    /// This is the **cryptographic** proof of user presence. It is only set to
    /// `true` after the server verifies a FIDO2 assertion where both the User
    /// Presence (UP) and User Verified (UV) flags are set in the authenticator
    /// data. This is enforced by passing `require_user_verification: true` to
    /// the WebAuthn verification step.
    ///
    /// Unlike the client-side `x-fapi-end-user-present` header (which is a
    /// non-verifiable hint per FAPI 2.0 Implementation Advice), this claim
    /// is backed by the authenticator's cryptographic attestation.
    pub hardware_verified: bool,
    /// Custom claim: Hardware authenticator AAGUID.
    pub hardware_aaguid: Option<String>,
    /// RFC 9449 Section 6: DPoP token binding confirmation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
    /// RFC 9068 Section 2.2 / RFC 8176: Authentication methods used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<AuthMethod>>,
    /// RFC 9068 Section 2.2: Authentication context class reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// OIDC Core Section 3.1.3.6: Access Token hash value.
    /// Base64url encoding of the left half of SHA-256(access_token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
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
    let auth_code = decode_authorization_code(state, params.code, params.client_id).await?;

    // RFC 6749 Section 10.5: Enforce single-use authorization codes.
    // Try to consume the code; if already consumed this is a replay attack.
    let code_hash = hash_token(params.code);
    match db::try_consume_authorization_code(&state.store, &code_hash).await {
        Ok(true) => { /* First use — proceed */ }
        Ok(false) => {
            // Code was already consumed or doesn't exist.
            // Single atomic query combines consumed check + owner lookup
            if let Ok(Some((user_id, _client_id))) =
                db::get_consumed_code_owner(&state.store, &code_hash).await
            {
                tracing::warn!(
                    target: "security",
                    client_id = %auth_code.client_id,
                    "Authorization code replay detected — code already consumed"
                );

                // RFC 6749 Section 10.5: "If the authorization server observes
                // multiple attempts to exchange an authorization code, the
                // authorization server SHOULD attempt to revoke all access tokens
                // already granted based on the compromised authorization code."
                match db::delete_oauth_sessions_for_user(&state.store, &user_id).await {
                    Ok(count) if count > 0 => {
                        state.session_cache.invalidate_for_user(&user_id);
                        tracing::warn!(
                            target: "security",
                            user_id = %user_id,
                            revoked_count = count,
                            "Revoked OAuth tokens due to authorization code replay"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("Failed to revoke tokens during replay detection: {e}");
                    }
                }
            }
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Authorization code has already been used",
            ));
        }
        Err(e) => {
            tracing::error!("Failed to consume authorization code: {}", e);
            return Err(ServiceError::Internal(
                "Failed to validate authorization code".to_string(),
            ));
        }
    }

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
                let pkce_required =
                    client.is_public || client.client.application_type.requires_pkce();
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

    // FAPI 2.0 / RFC 9449 Section 10: Verify DPoP authorization code binding.
    // If the authorization code was bound to a DPoP key at PAR time, the same
    // key must be used at the token endpoint.
    if let Some(ref bound_jkt) = auth_code.dpop_jkt {
        let proof_jkt = match &params.dpop_proof {
            Some(proof) => &proof.jkt,
            None => {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidGrant,
                    "Authorization code is bound to a DPoP key but no DPoP proof was provided",
                ));
            }
        };
        // Constant-time comparison to prevent timing attacks
        let is_match: bool = bound_jkt.as_bytes().ct_eq(proof_jkt.as_bytes()).into();
        if !is_match {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "DPoP key does not match the key bound during authorization",
            ));
        }
    }

    // RFC 9470 Section 4: Defense-in-depth ACR validation.
    // If the authorization code carried acr_values, verify that Vouch's AAL3
    // is among the requested values. The authorization endpoint already checks
    // this, but we verify again here to prevent code injection attacks.
    if let Some(ref acr_values) = auth_code.acr_values {
        let acr_ok = acr_values
            .split_whitespace()
            .any(|v| v == crate::services::oidc::amr::ACR_AAL3);
        if !acr_ok {
            return Err(ServiceError::oauth(
                OAuthErrorCode::UnmetAuthenticationRequirements,
                "The requested authentication context class cannot be satisfied",
            ));
        }
    }

    // RFC 9396: Retrieve authorization_details from server-side storage.
    let granted_ad_value = db::get_authorization_code_details(&state.store, &code_hash)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?;
    let granted_ad = granted_ad_value
        .as_ref()
        .and_then(|v| AuthorizationDetails::try_from(v).ok());

    // RFC 9396 Section 6: If the token request includes authorization_details,
    // it MUST be a subset of the granted details (downscoping).
    let (effective_ad, effective_ad_value);
    if let Some(requested_raw) = params.authorization_details {
        let requested_ad = AuthorizationDetails::parse(requested_raw)?;
        match &granted_ad {
            Some(granted) => {
                if !requested_ad.is_subset_of(granted) {
                    return Err(ServiceError::oauth(
                        OAuthErrorCode::InvalidAuthorizationDetails,
                        "Requested authorization_details is not a \
                         subset of the granted authorization_details",
                    ));
                }
            }
            None => {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidAuthorizationDetails,
                    "authorization_details was not granted \
                     during authorization",
                ));
            }
        }
        effective_ad_value = Some(serde_json::Value::from(&requested_ad));
        effective_ad = Some(requested_ad);
    } else {
        effective_ad_value = granted_ad_value;
        effective_ad = granted_ad;
    }

    // RFC 8707: Resource narrowing — determine the audience for the access token.
    // The resource from the auth code (granted at authorization time) takes precedence.
    let audience = match (auth_code.resource.as_deref(), params.resource) {
        // Both present: must match
        (Some(granted), Some(requested)) if granted != requested => {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidTarget,
                "Resource parameter does not match the value from the authorization request",
            ));
        }
        (Some(granted), _) => Some(granted),
        // Can't add resource at token time if not granted during authorization
        (None, Some(_)) => {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidTarget,
                "Resource was not requested during authorization",
            ));
        }
        (None, None) => None,
    };

    // Generate access token as an RFC 9068 JWT (ES256, verifiable via JWKS)
    let dpop_jkt = params.dpop_proof.as_ref().map(|p| p.jkt.as_str());
    let session_result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id: &auth_code.user_id,
            email: &auth_code.email,
            authenticator_id: Some(&auth_code.authenticator_id),
            client_id: &auth_code.client_id,
            scope: Some(auth_code.scope.clone()),
            dpop_jkt,
            act: None,
            audience,
            auth_time: Some(auth_code.auth_time.unwrap_or(auth_code.iat)),
            amr: Some(AuthMethod::all_fido2().to_vec()),
            acr: Some(crate::services::oidc::amr::ACR_AAL3.to_string()),
            hardware_verified: true,
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: effective_ad_value.as_ref(),
        },
    )
    .await?;
    let access_token = session_result.token;
    let expires_in = session_result.expires_in;

    // Extract the per-client ID token signing algorithm.
    // Public clients (no credentials) fall back to "RS256" per OIDC Core default.
    let id_token_alg = authenticated_client
        .as_ref()
        .map(|c| c.client.id_token_signed_response_alg.as_str())
        .unwrap_or("RS256");

    // Generate ID token (with at_hash computed from the access token)
    let id_token = generate_id_token(
        state,
        IdTokenParams {
            client_id: &auth_code.client_id,
            user_id: &auth_code.user_id,
            email: &auth_code.email,
            aaguid: auth_code.aaguid.as_deref(),
            nonce: auth_code.nonce.as_deref(),
            expires_in,
            dpop_jkt,
            scope: &auth_code.scope,
            auth_time: Some(auth_code.auth_time.unwrap_or(auth_code.iat)),
            amr: Some(AuthMethod::all_fido2().to_vec()),
            acr: Some(crate::services::oidc::amr::ACR_AAL3.to_string()),
            access_token: Some(access_token.expose_secret()),
            id_token_alg,
        },
    )
    .await?;

    // Record usage event for registered clients
    if let Some(ref auth_client) = authenticated_client
        && let Err(e) = db::record_oauth_event(
            &state.audit,
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
        access_token: access_token.expose_secret().to_string(),
        token_type: token_type.to_string(),
        expires_in,
        id_token,
        scope: auth_code.scope,
        authorization_details: effective_ad,
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

    // RFC 9700 Section 2.1.1: Only S256 is supported.
    // Default to S256 for backward compatibility with codes that don't store the method.
    let _method = auth_code
        .code_challenge_method
        .unwrap_or(CodeChallengeMethod::S256);

    let computed_challenge = {
        let hash = digest::digest(&SHA256, code_verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(hash.as_ref())
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
    let client = db::get_oauth_client_by_client_id(&state.store, &credentials.client_id)
        .await
        .map_err(|e| ClientAuthError::DatabaseError(e.to_string()))?
        .ok_or(ClientAuthError::InvalidClient)?;

    // Check if client is active
    if !client.active {
        return Err(ClientAuthError::InvalidClient);
    }

    // Determine if this client type requires a secret
    let requires_secret = client.application_type.requires_secret();

    if requires_secret {
        // Secret is required - validate it
        let secret = credentials
            .client_secret
            .as_ref()
            .ok_or(ClientAuthError::SecretRequired)?;

        // Hash the provided secret and validate against stored hash
        let secret_hash = hash_token(secret.expose_secret());

        // Validate credentials
        let validated = db::validate_oauth_client_credentials(
            &state.store,
            &credentials.client_id,
            &secret_hash,
        )
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
        if let Err(e) = db::update_oauth_client_last_used(&state.store, &client.id).await {
            tracing::warn!("Failed to update OAuth client last_used: {e}");
        }

        Ok(AuthenticatedClient {
            client,
            is_public: true,
        })
    }
}

/// Compute `at_hash` per OIDC Core Section 3.1.3.6.
///
/// Returns the base64url encoding (no padding) of the left half of SHA-256
/// of the access token string. For SHA-256 (32 bytes), the left half is 16 bytes,
/// producing a 22-character base64url string.
fn compute_at_hash(access_token: &str) -> Option<String> {
    let hash = digest::digest(&SHA256, access_token.as_bytes());
    let left_half = hash.as_ref().get(..16)?;
    Some(URL_SAFE_NO_PAD.encode(left_half))
}

/// Parameters for ID token generation.
struct IdTokenParams<'a> {
    client_id: &'a str,
    user_id: &'a str,
    email: &'a str,
    aaguid: Option<&'a str>,
    nonce: Option<&'a str>,
    expires_in: u64,
    dpop_jkt: Option<&'a str>,
    scope: &'a ScopeSet,
    /// Time when the user authenticated (FIDO2 session creation time).
    auth_time: Option<i64>,
    /// RFC 8176: Authentication methods reference.
    amr: Option<Vec<AuthMethod>>,
    /// RFC 9068 Section 2.2: Authentication context class reference.
    acr: Option<String>,
    /// Access token string, used to compute `at_hash` (OIDC Core Section 3.1.3.6).
    access_token: Option<&'a str>,
    /// OIDC Core: Algorithm for signing this ID token.
    id_token_alg: &'a str,
}

/// Generate an OIDC ID token.
async fn generate_id_token(
    state: &Arc<AppState>,
    params: IdTokenParams<'_>,
) -> ServiceResult<String> {
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
        sub: params.user_id.to_string(),
        aud: params.client_id.to_string(),
        exp,
        iat: now.as_second(),
        auth_time: params.auth_time,
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
        amr: params.amr,
        acr: params.acr,
        at_hash: params.access_token.and_then(compute_at_hash),
    };

    // Use RS256 if requested and an RSA key is available; otherwise fall back to ES256.
    // The registration endpoint already rejects RS256 when no RSA key is configured,
    // but manually-created clients and older records carry the RS256 default and must
    // not cause a 500 when no RSA key is provisioned.
    if params.id_token_alg == "RS256" {
        if let Some(rsa_key) = state.oidc_rsa_key.as_ref() {
            return rsa_key
                .sign_jwt(&claims)
                .await
                .map_err(|e| ServiceError::Internal(format!("Failed to generate ID token: {e}")));
        }
        tracing::warn!(
            "RS256 requested but no RSA key configured; falling back to ES256 for ID token"
        );
    }
    state
        .oidc_key
        .sign_jwt(&claims)
        .await
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
/// - `Err(DpopError::UseNonce(nonce))` if the server requires a nonce
/// - `Err(...)` if DPoP header was present but invalid
pub async fn validate_dpop_if_present(
    state: &AppState,
    dpop_header: Option<&str>,
    method: &str,
    uri: &str,
) -> Result<Option<ValidatedDpopProof>, DpopError> {
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
        &state.store,
        state.config().dpop_max_age_seconds,
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
        Err(e) => {
            if matches!(&e, DpopError::UseNonce(_)) {
                tracing::debug!("DPoP nonce required, returning use_dpop_nonce error");
            } else {
                tracing::warn!("DPoP validation failed: {}", e);
            }
            Err(e)
        }
    }
}

/// Result of validating a session token for OIDC endpoints.
pub struct OidcValidatedSession {
    /// The authenticated user.
    pub user: User,
    /// The database session record.
    pub session: Session,
    /// The authenticator used to create the session, if any.
    /// `None` for OIDC-only enrollment sessions that lack a hardware key.
    pub authenticator: Option<Authenticator>,
    /// Granted OAuth scope from the access token JWT.
    pub scope: Option<ScopeSet>,
}

/// Validate a session token and return the user, session, and authenticator.
///
/// Accepts ES256 RFC 9068 access tokens only. The `authenticator_id` is
/// looked up from the server-side session record (not from the JWT).
pub async fn validate_session_token(
    state: &Arc<AppState>,
    token: &str,
) -> ServiceResult<Option<OidcValidatedSession>> {
    // Decode the token as an ES256 RFC 9068 access token
    let config = state.config();
    let decoded = match decode_token(token, &state.oidc_key, &config.base_url) {
        Some(d) => d,
        None => return Ok(None),
    };

    // Verify session exists in database
    let token_hash = hash_token(token);
    let session = match state
        .session_cache
        .get_session_by_token_hash(&state.store, &token_hash)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
    {
        Some(s) => s,
        None => return Ok(None),
    };

    // M2M tokens (client_credentials grant) are not valid at user-facing endpoints.
    // Reject them explicitly rather than relying on get_user_by_id returning None.
    if session.session_type == db::SessionPurpose::M2MAccessToken {
        return Ok(None);
    }

    // Get user from the sub claim
    let user = match db::get_user_by_id(&state.store, decoded.sub())
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
    {
        Some(u) => u,
        None => return Ok(None),
    };

    // Get authenticator from the server-side session record.
    // The authenticator_id is stored server-side and is NOT included in the JWT
    // to prevent information leakage.
    let authenticator_id = session.authenticator_id.as_deref();

    // If the session references an authenticator that no longer exists (deleted/revoked),
    // the session is invalid — this implements key revocation.
    let authenticator = match authenticator_id {
        Some(id) => {
            match db::get_authenticator_by_id(&state.store, id)
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
        scope: decoded.scope().cloned(),
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_s256_validation() {
        // RFC 7636 Appendix B test vector
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let auth_code = AuthorizationCode {
            iss: "https://test.example.com".to_string(),
            aud: "test".to_string(),
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
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            iat: 0,
            exp: i64::MAX,
            auth_time: None,
        };

        let result = validate_pkce(&auth_code, Some(code_verifier));
        assert!(result.is_ok(), "RFC 7636 test vector should validate");
    }

    #[test]
    fn test_pkce_invalid_verifier() {
        let auth_code = AuthorizationCode {
            iss: "https://test.example.com".to_string(),
            aud: "test".to_string(),
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
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            iat: 0,
            exp: i64::MAX,
            auth_time: None,
        };

        let result = validate_pkce(&auth_code, Some("wrong_verifier"));
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_missing_verifier() {
        let auth_code = AuthorizationCode {
            iss: "https://test.example.com".to_string(),
            aud: "test".to_string(),
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
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            iat: 0,
            exp: i64::MAX,
            auth_time: None,
        };

        let result = validate_pkce(&auth_code, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_no_challenge() {
        // No PKCE challenge - should succeed
        let auth_code = AuthorizationCode {
            iss: "https://test.example.com".to_string(),
            aud: "test".to_string(),
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
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            iat: 0,
            exp: i64::MAX,
            auth_time: None,
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

    #[test]
    fn test_compute_at_hash_deterministic() {
        // at_hash should be deterministic for the same input
        let token = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.test.sig";
        let hash1 = compute_at_hash(token);
        let hash2 = compute_at_hash(token);
        assert!(hash1.is_some());
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_at_hash_format() {
        // SHA-256 left half = 16 bytes → base64url-no-pad = 22 characters
        let token = "some-access-token-string";
        let hash = compute_at_hash(token).expect("should produce hash");
        assert_eq!(
            hash.len(),
            22,
            "at_hash should be 22 chars (16 bytes base64url)"
        );
        // Must contain only base64url characters (no padding)
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "at_hash must use URL-safe base64 characters only"
        );
    }

    #[test]
    fn test_compute_at_hash_different_tokens() {
        let hash1 = compute_at_hash("token-a").expect("hash");
        let hash2 = compute_at_hash("token-b").expect("hash");
        assert_ne!(
            hash1, hash2,
            "different tokens should produce different hashes"
        );
    }
}
