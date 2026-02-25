// SPDX-License-Identifier: BUSL-1.1
//! RFC 7591 — OAuth 2.0 Dynamic Client Registration.
//!
//! Implements the `POST /oauth/register` endpoint logic:
//! - Request validation and metadata defaulting
//! - Grant/response type consistency checks
//! - Redirect URI validation (delegates to existing helpers)
//! - JWKS/JWKS_URI mutual exclusivity
//! - FAPI 2.0 enforcement at registration time
//! - Software statement JWT verification (against trusted_jwt_issuers)
//! - Client creation and credential generation
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc7591>

use crate::AppState;
use crate::crypto::{generate_random_bytes, hash_token};
use crate::db::{
    self, CreateOAuthClientParams, FapiProfile, OAuthClientType, OAuthEventType,
    RegistrationSource, TokenEndpointAuthMethod,
};
use crate::services::error::{OAuthErrorCode, ServiceError};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ============================================================================
// Allowed Grant and Response Types
// ============================================================================

/// Grant types that this server accepts for dynamic registration.
const ALLOWED_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
];

/// Response types that this server accepts for dynamic registration.
const ALLOWED_RESPONSE_TYPES: &[&str] = &["code"];

/// Maximum number of redirect URIs per client.
const MAX_REDIRECT_URIS: usize = 25;

/// Maximum number of contacts per client.
const MAX_CONTACTS: usize = 10;

/// Length of generated client secrets in bytes.
const SECRET_LENGTH: usize = 32;

/// Length of generated registration access tokens in bytes.
const REGISTRATION_TOKEN_LENGTH: usize = 32;

// ============================================================================
// Request / Response Types
// ============================================================================

/// RFC 7591 Section 2: Client Registration Request.
///
/// Per RFC 7591 Section 2: "The authorization server MUST ignore any
/// metadata it does not understand", so we do NOT use `deny_unknown_fields`.
#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    /// RFC 7591 Section 2: Array of redirection URI strings.
    pub redirect_uris: Option<Vec<String>>,
    /// RFC 7591 Section 2: Authentication method for the token endpoint.
    pub token_endpoint_auth_method: Option<String>,
    /// RFC 7591 Section 2: Array of OAuth 2.0 grant type strings.
    pub grant_types: Option<Vec<String>>,
    /// RFC 7591 Section 2: Array of OAuth 2.0 response type strings.
    pub response_types: Option<Vec<String>>,
    /// RFC 7591 Section 2: Human-readable name of the client.
    pub client_name: Option<String>,
    /// RFC 7591 Section 2: URL of the client's home page.
    pub client_uri: Option<String>,
    /// RFC 7591 Section 2: URL of the client's logo.
    pub logo_uri: Option<String>,
    /// RFC 7591 Section 2: URL of the client's terms of service.
    pub tos_uri: Option<String>,
    /// RFC 7591 Section 2: URL of the client's privacy policy.
    pub policy_uri: Option<String>,
    /// RFC 7591 Section 2: Space-delimited scope string.
    pub scope: Option<String>,
    /// RFC 7591 Section 2: Array of contact email addresses.
    pub contacts: Option<Vec<String>>,
    /// RFC 7591 Section 2: Client's JSON Web Key Set (inline).
    pub jwks: Option<serde_json::Value>,
    /// RFC 7591 Section 2: URL for the client's JSON Web Key Set.
    pub jwks_uri: Option<String>,
    /// RFC 7591 Section 2: Unique identifier for the client software.
    pub software_id: Option<String>,
    /// RFC 7591 Section 2: Version of the client software.
    pub software_version: Option<String>,
    /// RFC 7591 Section 2.3: Software statement JWT.
    pub software_statement: Option<String>,
    /// FAPI 2.0: Whether access tokens must be DPoP-bound.
    pub dpop_bound_access_tokens: Option<bool>,
}

/// RFC 7591 Section 3.2.1: Client Information Response.
#[derive(Debug, Serialize)]
pub struct RegistrationResponse {
    /// RFC 7591 Section 3.2.1: REQUIRED. OAuth 2.0 client identifier.
    pub client_id: String,
    /// RFC 7591 Section 3.2.1: OAuth 2.0 client secret (for confidential clients).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// RFC 7591 Section 3.2.1: 0 = does not expire. REQUIRED when client_secret issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    /// RFC 7591 Section 3.2.1: Time at which the client_id was issued (epoch seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<i64>,
    /// RFC 7592: Registration access token for future management.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    /// RFC 7592: Client configuration endpoint URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,

    // --- Echoed metadata ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    pub token_endpoint_auth_method: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens: Option<bool>,
}

// ============================================================================
// Core Registration Logic
// ============================================================================

/// Register a new OAuth client per RFC 7591.
///
/// # Arguments
/// * `state` — Application state (DB, config, etc.)
/// * `request` — The registration request body
/// * `authenticated_user_id` — User ID from the Bearer token (always required)
///
/// # Errors
/// Returns `ServiceError::OAuth` with the appropriate RFC 7591 error code.
pub async fn register_client(
    state: &Arc<AppState>,
    mut request: RegistrationRequest,
    authenticated_user_id: &str,
) -> Result<RegistrationResponse, ServiceError> {
    // 1. Software statement: verify and apply precedence
    if let Some(statement_jwt) = request.software_statement.take() {
        apply_software_statement(state, &mut request, &statement_jwt).await?;
    }

    // 2. Reject implicit grant (deprecated by RFC 9700)
    if let Some(ref grant_types) = request.grant_types
        && grant_types.iter().any(|g| g == "implicit")
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "The 'implicit' grant type is not supported (deprecated by RFC 9700)",
        ));
    }
    if let Some(ref response_types) = request.response_types {
        for rt in response_types {
            if rt == "token"
                || rt == "id_token"
                || rt == "id_token token"
                || rt == "code token"
                || rt == "code id_token token"
            {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    "Implicit response types ('token', 'id_token') are not supported \
                     (deprecated by RFC 9700)",
                ));
            }
        }
    }

    // 3. Apply defaults
    let grant_types = request
        .grant_types
        .take()
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);
    let response_types = request
        .response_types
        .take()
        .unwrap_or_else(|| vec!["code".to_string()]);
    let auth_method_str = request
        .token_endpoint_auth_method
        .take()
        .unwrap_or_else(|| "client_secret_basic".to_string());

    // 4. Validate grant types are in the allowed set
    for gt in &grant_types {
        if !ALLOWED_GRANT_TYPES.contains(&gt.as_str()) {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!("Unsupported grant type: '{gt}'"),
            ));
        }
    }

    // 5. Validate response types are in the allowed set
    for rt in &response_types {
        if !ALLOWED_RESPONSE_TYPES.contains(&rt.as_str()) {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!("Unsupported response type: '{rt}'"),
            ));
        }
    }

    // 6. Grant/response type consistency
    let has_auth_code = grant_types.iter().any(|g| g == "authorization_code");
    let has_code_response = response_types.iter().any(|r| r == "code");
    if has_auth_code && !has_code_response {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "grant_types includes 'authorization_code' but response_types is missing 'code'",
        ));
    }

    // 7. Redirect URIs: required when authorization_code grant is present
    let redirect_uris = request.redirect_uris.take().unwrap_or_default();
    if has_auth_code && redirect_uris.is_empty() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "redirect_uris is required when grant_types includes 'authorization_code'",
        ));
    }

    // Cardinality limit
    if redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!("Too many redirect_uris (max {MAX_REDIRECT_URIS})"),
        ));
    }

    // Validate redirect URIs (reuse existing validation + fragment check)
    for uri in &redirect_uris {
        validate_registration_redirect_uri(uri)?;
    }

    // 8. JWKS mutual exclusivity
    let jwks_value = request.jwks.take();
    let jwks_uri = request.jwks_uri.take();
    if jwks_value.is_some() && jwks_uri.is_some() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "jwks and jwks_uri are mutually exclusive",
        ));
    }

    // Validate JWKS JSON structure if provided
    let jwks_string = if let Some(ref jwks) = jwks_value {
        if !jwks
            .get("keys")
            .is_some_and(|k| k.is_array() && !k.as_array().is_some_and(|a| a.is_empty()))
        {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                "jwks must be a JSON object with a non-empty \"keys\" array",
            ));
        }
        Some(serde_json::to_string(jwks).map_err(|_| {
            ServiceError::oauth(OAuthErrorCode::InvalidClientMetadata, "Invalid JWKS JSON")
        })?)
    } else {
        None
    };

    // Validate JWKS URI is HTTPS
    if let Some(ref uri) = jwks_uri {
        match url::Url::parse(uri) {
            Ok(parsed) if parsed.scheme() == "https" => {}
            _ => {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    "jwks_uri must be a valid https:// URL",
                ));
            }
        }
    }

    // 9. Auth method validation
    let auth_method: TokenEndpointAuthMethod = auth_method_str.parse().map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!("Unsupported token_endpoint_auth_method: '{auth_method_str}'"),
        )
    })?;

    if auth_method == TokenEndpointAuthMethod::PrivateKeyJwt
        && jwks_value.is_none()
        && jwks_uri.is_none()
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "private_key_jwt requires jwks or jwks_uri",
        ));
    }

    // 10. URI field validation (must be HTTPS)
    validate_https_uri("client_uri", request.client_uri.as_deref())?;
    validate_https_uri("logo_uri", request.logo_uri.as_deref())?;
    validate_https_uri("tos_uri", request.tos_uri.as_deref())?;
    validate_https_uri("policy_uri", request.policy_uri.as_deref())?;

    // 11. Contacts validation
    if let Some(ref contacts) = request.contacts {
        if contacts.len() > MAX_CONTACTS {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!("Too many contacts (max {MAX_CONTACTS})"),
            ));
        }
        for contact in contacts {
            if !contact.contains('@') {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    format!("Invalid contact email: '{contact}'"),
                ));
            }
        }
    }

    // 12. FAPI 2.0 enforcement
    let dpop_bound = request.dpop_bound_access_tokens.unwrap_or(false);
    let fapi_profile = if dpop_bound {
        // Require FAPI constraints
        if auth_method != TokenEndpointAuthMethod::PrivateKeyJwt {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                "FAPI 2.0 requires token_endpoint_auth_method 'private_key_jwt'",
            ));
        }
        if jwks_value.is_none() && jwks_uri.is_none() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                "FAPI 2.0 requires jwks or jwks_uri",
            ));
        }
        FapiProfile::Fapi2Security
    } else {
        FapiProfile::None
    };

    // 13. Infer application type
    let has_client_credentials_only = grant_types.len() == 1
        && grant_types
            .first()
            .is_some_and(|g| g == "client_credentials");
    let is_public = auth_method == TokenEndpointAuthMethod::None;
    let has_loopback = redirect_uris.iter().any(|u| {
        url::Url::parse(u)
            .ok()
            .and_then(|p| p.host_str().map(|h| h.to_string()))
            .is_some_and(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]")
    });

    let app_type = if has_client_credentials_only {
        OAuthClientType::Service
    } else if is_public && has_loopback {
        OAuthClientType::Native
    } else if is_public {
        OAuthClientType::Spa
    } else {
        OAuthClientType::Web
    };

    // Build the client name (fallback to software_id or "Unnamed Client")
    let client_name = request.client_name.as_deref().unwrap_or("Unnamed Client");

    // Build registration metadata JSON (cosmetic fields)
    let registration_metadata = build_registration_metadata(&request);
    let registration_metadata_str = serde_json::to_string(&registration_metadata).ok();

    // Serialize grant/response types as JSON arrays for storage
    let grant_types_json = serde_json::to_string(&grant_types).ok();
    let response_types_json = serde_json::to_string(&response_types).ok();

    // 14. Generate registration access token
    let reg_token = generate_registration_token()?;
    let reg_token_hash = hash_token(&reg_token);

    // 15. Create the client
    let (client, client_id) = db::create_oauth_client(
        &state.db,
        &CreateOAuthClientParams {
            user_id: authenticated_user_id,
            name: client_name,
            description: None,
            application_type: app_type,
            redirect_uris: &redirect_uris,
            access_scope: db::AccessScope::Personal,
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: Some(auth_method.as_str()),
            jwks: jwks_string.as_deref(),
            jwks_uri: jwks_uri.as_deref(),
            fapi_profile: Some(fapi_profile),
            dpop_bound_access_tokens: Some(dpop_bound),
            grant_types: grant_types_json.as_deref(),
            response_types: response_types_json.as_deref(),
            software_id: request.software_id.as_deref(),
            software_version: request.software_version.as_deref(),
            registration_source: RegistrationSource::Dynamic,
            registration_access_token_hash: Some(&reg_token_hash),
            registration_metadata: registration_metadata_str.as_deref(),
        },
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create dynamically registered client: {e}");
        ServiceError::Internal("Failed to create client".to_string())
    })?;

    // 16. Generate client_secret for confidential clients
    let client_secret = if matches!(
        auth_method,
        TokenEndpointAuthMethod::ClientSecretBasic | TokenEndpointAuthMethod::ClientSecretPost
    ) {
        let secret_bytes = generate_random_bytes(SECRET_LENGTH)
            .map_err(|_| ServiceError::Internal("Failed to generate client secret".to_string()))?;
        let secret = format!("vouch_{}", URL_SAFE_NO_PAD.encode(secret_bytes));
        let secret_hash = hash_token(&secret);

        db::create_oauth_client_secret(
            &state.db,
            &client.id,
            &secret_hash,
            Some("Dynamic registration"),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create client secret for dynamic registration: {e}");
            ServiceError::Internal("Failed to create client secret".to_string())
        })?;

        Some(secret)
    } else {
        None
    };

    // 17. Record audit event
    let base_url = &state.config().base_url;
    if let Err(e) = db::record_oauth_event(
        &state.db,
        &client.id,
        OAuthEventType::ClientRegistered,
        Some(authenticated_user_id),
        None,
        None,
        Some("RFC 7591 dynamic registration"),
    )
    .await
    {
        tracing::warn!("Failed to record client registration event: {e}");
    }

    // Derive client_id_issued_at from created_at
    let client_id_issued_at = client.created_at.to_jiff().as_second();

    tracing::info!(
        "Dynamic client registration: client_id={}, user={}, app_type={:?}",
        client_id,
        authenticated_user_id,
        app_type
    );

    // 18. Build response
    Ok(RegistrationResponse {
        client_id,
        client_secret: client_secret.clone(),
        client_secret_expires_at: if client_secret.is_some() {
            Some(0) // 0 = does not expire
        } else {
            None
        },
        client_id_issued_at: Some(client_id_issued_at),
        registration_access_token: Some(reg_token),
        registration_client_uri: Some(format!("{base_url}/oauth/register/{}", client.client_id)),
        redirect_uris: if redirect_uris.is_empty() {
            None
        } else {
            Some(redirect_uris)
        },
        token_endpoint_auth_method: auth_method.as_str().to_string(),
        grant_types,
        response_types,
        client_name: Some(client_name.to_string()),
        client_uri: request.client_uri,
        logo_uri: request.logo_uri,
        tos_uri: request.tos_uri,
        policy_uri: request.policy_uri,
        scope: request.scope,
        contacts: request.contacts,
        jwks: jwks_value,
        jwks_uri,
        software_id: request.software_id,
        software_version: request.software_version,
        dpop_bound_access_tokens: if dpop_bound { Some(true) } else { None },
    })
}

// ============================================================================
// Validation Helpers
// ============================================================================

/// Validate a single redirect URI for dynamic registration.
///
/// Per RFC 7591 Section 2 and RFC 8252:
/// - HTTPS is always valid
/// - HTTP is only allowed for loopback (localhost, 127.0.0.1, [::1])
/// - Custom schemes are allowed for native apps
/// - Fragments are forbidden (RFC 6749 Section 3.1.2)
fn validate_registration_redirect_uri(uri: &str) -> Result<(), ServiceError> {
    // Check for fragments (forbidden per RFC 6749 Section 3.1.2)
    if uri.contains('#') {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRedirectUri,
            format!("Redirect URI must not contain a fragment component: '{uri}'"),
        ));
    }

    match url::Url::parse(uri) {
        Ok(parsed) => {
            match parsed.scheme() {
                "https" => Ok(()),
                "http" => {
                    // RFC 8252 Section 7.3: HTTP only for loopback
                    let host = parsed.host_str().unwrap_or("");
                    if matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
                        Ok(())
                    } else {
                        Err(ServiceError::oauth(
                            OAuthErrorCode::InvalidRedirectUri,
                            format!(
                                "http:// redirect URIs are only allowed for loopback \
                                 addresses (localhost, 127.0.0.1, [::1]): '{uri}'"
                            ),
                        ))
                    }
                }
                // Custom schemes are allowed for native apps (RFC 8252 Section 7.1)
                _ => Ok(()),
            }
        }
        Err(_) => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRedirectUri,
            format!("Invalid redirect URI: '{uri}'"),
        )),
    }
}

/// Public alias for  exposed for property-based testing.
///
/// Only available when the `test-utils` feature is enabled.
#[cfg(feature = "test-utils")]
pub fn validate_redirect_uri_for_test(uri: &str) -> Result<(), ServiceError> {
    validate_registration_redirect_uri(uri)
}

/// Validate that a URI field is HTTPS (if present).
fn validate_https_uri(field_name: &str, uri: Option<&str>) -> Result<(), ServiceError> {
    if let Some(uri) = uri {
        match url::Url::parse(uri) {
            Ok(parsed) if parsed.scheme() == "https" => Ok(()),
            _ => Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!("{field_name} must be a valid https:// URL"),
            )),
        }
    } else {
        Ok(())
    }
}

/// Build the registration_metadata JSON blob from cosmetic request fields.
fn build_registration_metadata(request: &RegistrationRequest) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    if let Some(ref v) = request.client_uri {
        metadata.insert(
            "client_uri".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = request.logo_uri {
        metadata.insert("logo_uri".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = request.tos_uri {
        metadata.insert("tos_uri".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = request.policy_uri {
        metadata.insert(
            "policy_uri".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = request.contacts {
        metadata.insert(
            "contacts".to_string(),
            serde_json::Value::Array(
                v.iter()
                    .map(|c| serde_json::Value::String(c.clone()))
                    .collect(),
            ),
        );
    }
    if let Some(ref v) = request.scope {
        metadata.insert("scope".to_string(), serde_json::Value::String(v.clone()));
    }
    serde_json::Value::Object(metadata)
}

/// Generate a secure random registration access token (RFC 7592 prep).
fn generate_registration_token() -> Result<String, ServiceError> {
    let bytes = generate_random_bytes(REGISTRATION_TOKEN_LENGTH).map_err(|_| {
        ServiceError::Internal("Failed to generate registration access token".to_string())
    })?;
    Ok(format!("vouch_reg_{}", URL_SAFE_NO_PAD.encode(bytes)))
}

// ============================================================================
// Software Statement Verification
// ============================================================================

/// Verify a software statement JWT and apply its claims to the request.
///
/// Per RFC 7591 Section 2.3:
/// - Software statement is a JWT signed by the software publisher
/// - Claims in the statement take precedence over request body values
/// - The issuer must be a trusted JWT issuer in our database
async fn apply_software_statement(
    state: &Arc<AppState>,
    request: &mut RegistrationRequest,
    statement_jwt: &str,
) -> Result<(), ServiceError> {
    use crate::services::oidc::jwt_bearer::validate::{
        decode_claims_unverified, map_algorithm, parse_assertion_header, validate_jwt_assertion,
    };

    // Parse header to get algorithm
    let header = parse_assertion_header(statement_jwt).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidSoftwareStatement,
            "Malformed software statement JWT",
        )
    })?;

    // Decode claims to find the issuer (without signature verification)
    let unverified_claims = decode_claims_unverified(statement_jwt).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidSoftwareStatement,
            "Cannot decode software statement claims",
        )
    })?;

    // Look up the trusted issuer
    let issuer = db::get_trusted_jwt_issuer_by_issuer(&state.db, &unverified_claims.iss)
        .await
        .map_err(|e| {
            tracing::error!("Failed to look up trusted JWT issuer: {e}");
            ServiceError::Internal("Database error".to_string())
        })?
        .ok_or_else(|| {
            ServiceError::oauth(
                OAuthErrorCode::UnapprovedSoftwareStatement,
                format!(
                    "Software statement issuer '{}' is not trusted",
                    unverified_claims.iss
                ),
            )
        })?;

    if !issuer.enabled {
        return Err(ServiceError::oauth(
            OAuthErrorCode::UnapprovedSoftwareStatement,
            "Software statement issuer is disabled",
        ));
    }

    // Get the JWKS for this issuer (cached or from URI)
    let jwks_json = issuer.jwks_cache.as_deref().ok_or_else(|| {
        ServiceError::oauth(
            OAuthErrorCode::UnapprovedSoftwareStatement,
            "No JWKS available for software statement issuer",
        )
    })?;

    // Parse JWKS and find the right key
    let jwks: serde_json::Value = serde_json::from_str(jwks_json)
        .map_err(|_| ServiceError::Internal("Invalid JWKS cache for trusted issuer".to_string()))?;

    let keys = jwks.get("keys").and_then(|k| k.as_array()).ok_or_else(|| {
        ServiceError::Internal("Trusted issuer JWKS has no keys array".to_string())
    })?;

    // Try each key until one verifies
    let algorithm = map_algorithm(&header.alg).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidSoftwareStatement,
            format!(
                "Unsupported algorithm in software statement: {}",
                header.alg
            ),
        )
    })?;

    let base_url = &state.config().base_url;
    let token_endpoint = format!("{base_url}/oauth/token");
    let audiences = [base_url.as_str(), token_endpoint.as_str()];

    let max_lifetime = i64::from(issuer.max_token_lifetime_seconds);

    let mut verified = false;
    for key in keys {
        if let Some(decoding_key) = serde_json::to_string(key)
            .ok()
            .and_then(|s| jsonwebtoken::DecodingKey::from_jwk(&serde_json::from_str(&s).ok()?).ok())
            && validate_jwt_assertion(
                statement_jwt,
                &header,
                &decoding_key,
                algorithm,
                &audiences,
                max_lifetime,
            )
            .is_ok()
        {
            verified = true;
            break;
        }
    }

    if !verified {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidSoftwareStatement,
            "Software statement signature verification failed",
        ));
    }

    // Apply software statement claims as overrides (statement takes precedence)
    // Parse the payload to get software-specific claims
    let payload_part = statement_jwt.split('.').nth(1).ok_or_else(|| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidSoftwareStatement,
            "Malformed software statement",
        )
    })?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_part)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload_part))
        .map_err(|_| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidSoftwareStatement,
                "Invalid software statement payload encoding",
            )
        })?;

    let statement_claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidSoftwareStatement,
                "Invalid software statement payload JSON",
            )
        })?;

    // Override request fields with statement claims (RFC 7591 Section 2.3)
    if let Some(v) = statement_claims.get("client_name").and_then(|v| v.as_str()) {
        request.client_name = Some(v.to_string());
    }
    if let Some(v) = statement_claims.get("client_uri").and_then(|v| v.as_str()) {
        request.client_uri = Some(v.to_string());
    }
    if let Some(v) = statement_claims
        .get("redirect_uris")
        .and_then(|v| v.as_array())
    {
        let uris: Vec<String> = v
            .iter()
            .filter_map(|u| u.as_str().map(String::from))
            .collect();
        if !uris.is_empty() {
            request.redirect_uris = Some(uris);
        }
    }
    if let Some(v) = statement_claims
        .get("grant_types")
        .and_then(|v| v.as_array())
    {
        let types: Vec<String> = v
            .iter()
            .filter_map(|t| t.as_str().map(String::from))
            .collect();
        if !types.is_empty() {
            request.grant_types = Some(types);
        }
    }
    if let Some(v) = statement_claims.get("software_id").and_then(|v| v.as_str()) {
        request.software_id = Some(v.to_string());
    }
    if let Some(v) = statement_claims
        .get("software_version")
        .and_then(|v| v.as_str())
    {
        request.software_version = Some(v.to_string());
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    // =========================================================================
    // Redirect URI Validation Tests
    // =========================================================================

    #[test]
    fn test_accepts_https_redirect_uri() {
        let result = validate_registration_redirect_uri("https://example.com/callback");
        assert!(result.is_ok());
    }

    #[test]
    fn test_accepts_http_localhost_redirect_uri() {
        let result = validate_registration_redirect_uri("http://127.0.0.1:8080/callback");
        assert!(result.is_ok());
    }

    #[test]
    fn test_accepts_http_localhost_hostname() {
        let result = validate_registration_redirect_uri("http://localhost:8080/callback");
        assert!(result.is_ok());
    }

    #[test]
    fn test_accepts_custom_scheme_redirect_uri() {
        let result = validate_registration_redirect_uri("myapp://auth");
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_http_non_loopback() {
        let result = validate_registration_redirect_uri("http://example.com/callback");
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::InvalidRedirectUri);
            }
            other => panic!("Expected OAuth error, got: {other:?}"),
        }
    }

    #[test]
    fn test_rejects_redirect_uri_with_fragment() {
        let result = validate_registration_redirect_uri("https://example.com/callback#anchor");
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::InvalidRedirectUri);
            }
            other => panic!("Expected OAuth error, got: {other:?}"),
        }
    }

    #[test]
    fn test_rejects_invalid_redirect_uri() {
        let result = validate_registration_redirect_uri("not a valid uri !!!");
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::InvalidRedirectUri);
            }
            other => panic!("Expected OAuth error, got: {other:?}"),
        }
    }

    // =========================================================================
    // Redirect URI Validation — Additional Edge Cases
    // =========================================================================

    /// RFC 8252 Section 7.3: IPv6 loopback [::1] must be accepted over HTTP.
    #[test]
    fn test_accepts_http_ipv6_loopback_redirect_uri() {
        let result = validate_registration_redirect_uri("http://[::1]:7777/callback");
        assert!(
            result.is_ok(),
            "IPv6 loopback [::1] must be accepted: {result:?}"
        );
    }

    /// HTTP redirect URIs with a path component at loopback must be accepted.
    #[test]
    fn test_accepts_http_loopback_with_path() {
        let result = validate_registration_redirect_uri("http://127.0.0.1/callback/deep/path");
        assert!(result.is_ok());
    }

    /// HTTPS URIs with query strings must be accepted (query is not a fragment).
    #[test]
    fn test_accepts_https_redirect_uri_with_query() {
        let result = validate_registration_redirect_uri("https://example.com/cb?foo=bar");
        assert!(result.is_ok());
    }

    /// The fragment check is string-based and must catch '#' before URL parsing.
    #[test]
    fn test_rejects_redirect_uri_with_fragment_before_parse() {
        // A URI that would otherwise be valid https but contains '#'
        let result = validate_registration_redirect_uri("https://example.com/cb#");
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, description } => {
                assert_eq!(code, OAuthErrorCode::InvalidRedirectUri);
                assert!(description.contains("fragment"));
            }
            other => panic!("Expected OAuth error, got: {other:?}"),
        }
    }

    /// HTTP to a non-loopback private IP (e.g., 192.168.x.x) must be rejected.
    #[test]
    fn test_rejects_http_private_ip_redirect_uri() {
        let result = validate_registration_redirect_uri("http://192.168.1.1/callback");
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::InvalidRedirectUri);
            }
            other => panic!("Expected OAuth error, got: {other:?}"),
        }
    }

    /// An empty string is not a valid redirect URI.
    #[test]
    fn test_rejects_empty_redirect_uri() {
        let result = validate_registration_redirect_uri("");
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::InvalidRedirectUri);
            }
            other => panic!("Expected OAuth error, got: {other:?}"),
        }
    }

    // =========================================================================
    // HTTPS URI Validation Tests
    // =========================================================================

    #[test]
    fn test_accepts_https_uri() {
        let result = validate_https_uri("client_uri", Some("https://example.com"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_http_uri() {
        let result = validate_https_uri("client_uri", Some("http://example.com"));
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::InvalidClientMetadata);
            }
            other => panic!("Expected OAuth error, got: {other:?}"),
        }
    }

    #[test]
    fn test_accepts_none_uri() {
        let result = validate_https_uri("client_uri", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_invalid_uri() {
        let result = validate_https_uri("client_uri", Some("not a url"));
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::InvalidClientMetadata);
            }
            other => panic!("Expected OAuth error, got: {other:?}"),
        }
    }

    // =========================================================================
    // HTTPS URI Validation — Additional Cases
    // =========================================================================

    /// The error message must include the field name for debuggability.
    #[test]
    fn test_https_uri_error_includes_field_name() {
        let result = validate_https_uri("logo_uri", Some("http://example.com/logo.png"));
        match result.unwrap_err() {
            ServiceError::OAuth { description, .. } => {
                assert!(
                    description.contains("logo_uri"),
                    "Error description must include field name: '{description}'"
                );
            }
            other => panic!("Expected OAuth error, got: {other:?}"),
        }
    }

    /// Custom (non-http/https) schemes must be rejected for URI fields.
    #[test]
    fn test_https_uri_rejects_custom_scheme() {
        let result = validate_https_uri("tos_uri", Some("ftp://example.com/tos"));
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::InvalidClientMetadata);
            }
            other => panic!("Expected OAuth error, got: {other:?}"),
        }
    }

    /// An empty string for a URI field must be rejected (invalid URL).
    #[test]
    fn test_https_uri_rejects_empty_string() {
        let result = validate_https_uri("policy_uri", Some(""));
        assert!(result.is_err());
    }

    // =========================================================================
    // Registration Metadata Tests
    // =========================================================================

    #[test]
    fn test_build_metadata_includes_all_fields() {
        let request = RegistrationRequest {
            redirect_uris: None,
            token_endpoint_auth_method: None,
            grant_types: None,
            response_types: None,
            client_name: Some("My App".to_string()),
            client_uri: Some("https://example.com".to_string()),
            logo_uri: Some("https://example.com/logo.png".to_string()),
            tos_uri: Some("https://example.com/tos".to_string()),
            policy_uri: Some("https://example.com/privacy".to_string()),
            scope: Some("openid profile".to_string()),
            contacts: Some(vec!["admin@example.com".to_string()]),
            jwks: None,
            jwks_uri: None,
            software_id: None,
            software_version: None,
            software_statement: None,
            dpop_bound_access_tokens: None,
        };

        let metadata = build_registration_metadata(&request);

        assert!(metadata.is_object());
        let obj = metadata.as_object().unwrap();
        assert_eq!(obj.get("client_uri").unwrap(), "https://example.com");
        assert_eq!(obj.get("logo_uri").unwrap(), "https://example.com/logo.png");
        assert_eq!(obj.get("tos_uri").unwrap(), "https://example.com/tos");
        assert_eq!(
            obj.get("policy_uri").unwrap(),
            "https://example.com/privacy"
        );
        assert_eq!(obj.get("scope").unwrap(), "openid profile");
        let contacts = obj.get("contacts").unwrap().as_array().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0], "admin@example.com");
    }

    #[test]
    fn test_build_metadata_empty_request() {
        let request = RegistrationRequest {
            redirect_uris: None,
            token_endpoint_auth_method: None,
            grant_types: None,
            response_types: None,
            client_name: None,
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            scope: None,
            contacts: None,
            jwks: None,
            jwks_uri: None,
            software_id: None,
            software_version: None,
            software_statement: None,
            dpop_bound_access_tokens: None,
        };

        let metadata = build_registration_metadata(&request);

        assert!(metadata.is_object());
        let obj = metadata.as_object().unwrap();
        assert!(
            obj.is_empty(),
            "Expected empty metadata object, got: {obj:?}"
        );
    }

    // =========================================================================
    // Registration Metadata — Additional Cases
    // =========================================================================

    /// `client_name` is NOT stored in the metadata blob (it has its own column).
    #[test]
    fn test_build_metadata_excludes_client_name() {
        let request = RegistrationRequest {
            redirect_uris: None,
            token_endpoint_auth_method: None,
            grant_types: None,
            response_types: None,
            client_name: Some("Should Not Appear".to_string()),
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            scope: None,
            contacts: None,
            jwks: None,
            jwks_uri: None,
            software_id: None,
            software_version: None,
            software_statement: None,
            dpop_bound_access_tokens: None,
        };

        let metadata = build_registration_metadata(&request);
        let obj = metadata.as_object().unwrap();
        assert!(
            !obj.contains_key("client_name"),
            "client_name must not be in the metadata blob"
        );
    }

    /// Multiple contacts must all appear in the metadata array.
    #[test]
    fn test_build_metadata_multiple_contacts() {
        let request = RegistrationRequest {
            redirect_uris: None,
            token_endpoint_auth_method: None,
            grant_types: None,
            response_types: None,
            client_name: None,
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            scope: None,
            contacts: Some(vec![
                "a@example.com".to_string(),
                "b@example.com".to_string(),
                "c@example.com".to_string(),
            ]),
            jwks: None,
            jwks_uri: None,
            software_id: None,
            software_version: None,
            software_statement: None,
            dpop_bound_access_tokens: None,
        };

        let metadata = build_registration_metadata(&request);
        let obj = metadata.as_object().unwrap();
        let contacts = obj.get("contacts").unwrap().as_array().unwrap();
        assert_eq!(contacts.len(), 3);
        assert_eq!(contacts[0], "a@example.com");
        assert_eq!(contacts[1], "b@example.com");
        assert_eq!(contacts[2], "c@example.com");
    }

    /// Partial metadata — only scope present — produces a single-key object.
    #[test]
    fn test_build_metadata_scope_only() {
        let request = RegistrationRequest {
            redirect_uris: None,
            token_endpoint_auth_method: None,
            grant_types: None,
            response_types: None,
            client_name: None,
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            scope: Some("openid".to_string()),
            contacts: None,
            jwks: None,
            jwks_uri: None,
            software_id: None,
            software_version: None,
            software_statement: None,
            dpop_bound_access_tokens: None,
        };

        let metadata = build_registration_metadata(&request);
        let obj = metadata.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        assert_eq!(obj.get("scope").unwrap(), "openid");
    }

    // =========================================================================
    // Request Deserialization Tests
    // =========================================================================

    #[test]
    fn test_request_deserialize_minimal() {
        let json = "{}";
        let result: Result<RegistrationRequest, _> = serde_json::from_str(json);
        assert!(result.is_ok(), "Empty JSON should deserialize successfully");
        let req = result.unwrap();
        assert!(req.redirect_uris.is_none());
        assert!(req.grant_types.is_none());
        assert!(req.client_name.is_none());
    }

    #[test]
    fn test_request_deserialize_with_unknown_fields() {
        // RFC 7591 Section 2: "The authorization server MUST ignore any metadata it does not
        // understand" — unknown fields must not cause deserialization to fail.
        let json = r#"{
            "redirect_uris": ["https://example.com/callback"],
            "client_name": "My App",
            "unknown_field_from_future_spec": "should be ignored",
            "another_unknown": 42,
            "nested_unknown": {"key": "value"}
        }"#;

        let result: Result<RegistrationRequest, _> = serde_json::from_str(json);
        assert!(
            result.is_ok(),
            "Unknown fields must be ignored per RFC 7591: {result:?}"
        );
        let req = result.unwrap();
        assert_eq!(
            req.redirect_uris,
            Some(vec!["https://example.com/callback".to_string()])
        );
        assert_eq!(req.client_name, Some("My App".to_string()));
    }

    #[test]
    fn test_request_deserialize_full() {
        let json = r#"{
            "redirect_uris": ["https://example.com/callback", "https://example.com/callback2"],
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": "Full Example App",
            "client_uri": "https://example.com",
            "logo_uri": "https://example.com/logo.png",
            "tos_uri": "https://example.com/tos",
            "policy_uri": "https://example.com/privacy",
            "scope": "openid profile email",
            "contacts": ["admin@example.com", "security@example.com"],
            "software_id": "4NRB1-0XZABZI9E6-5SM3R",
            "software_version": "2.1",
            "dpop_bound_access_tokens": false
        }"#;

        let result: Result<RegistrationRequest, _> = serde_json::from_str(json);
        assert!(
            result.is_ok(),
            "Full request should deserialize: {result:?}"
        );
        let req = result.unwrap();

        assert_eq!(
            req.redirect_uris,
            Some(vec![
                "https://example.com/callback".to_string(),
                "https://example.com/callback2".to_string(),
            ])
        );
        assert_eq!(
            req.token_endpoint_auth_method,
            Some("client_secret_basic".to_string())
        );
        assert_eq!(
            req.grant_types,
            Some(vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ])
        );
        assert_eq!(req.response_types, Some(vec!["code".to_string()]));
        assert_eq!(req.client_name, Some("Full Example App".to_string()));
        assert_eq!(req.client_uri, Some("https://example.com".to_string()));
        assert_eq!(
            req.logo_uri,
            Some("https://example.com/logo.png".to_string())
        );
        assert_eq!(req.tos_uri, Some("https://example.com/tos".to_string()));
        assert_eq!(
            req.policy_uri,
            Some("https://example.com/privacy".to_string())
        );
        assert_eq!(req.scope, Some("openid profile email".to_string()));
        assert_eq!(
            req.contacts,
            Some(vec![
                "admin@example.com".to_string(),
                "security@example.com".to_string(),
            ])
        );
        assert_eq!(req.software_id, Some("4NRB1-0XZABZI9E6-5SM3R".to_string()));
        assert_eq!(req.software_version, Some("2.1".to_string()));
        assert_eq!(req.dpop_bound_access_tokens, Some(false));
    }

    // =========================================================================
    // Request Deserialization — Additional Edge Cases
    // =========================================================================

    /// `dpop_bound_access_tokens: true` must deserialize correctly.
    #[test]
    fn test_request_deserialize_dpop_true() {
        let json = r#"{"dpop_bound_access_tokens": true}"#;
        let req: RegistrationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.dpop_bound_access_tokens, Some(true));
    }

    /// Inline JWKS must deserialize as a JSON object.
    #[test]
    fn test_request_deserialize_jwks_inline() {
        let json = r#"{
            "jwks": {
                "keys": [
                    {"kty": "RSA", "n": "abc", "e": "AQAB"}
                ]
            }
        }"#;
        let req: RegistrationRequest = serde_json::from_str(json).unwrap();
        assert!(req.jwks.is_some());
        let jwks = req.jwks.unwrap();
        assert!(jwks.get("keys").is_some());
        assert!(jwks.get("keys").unwrap().is_array());
    }

    /// `jwks_uri` must deserialize as a plain string.
    #[test]
    fn test_request_deserialize_jwks_uri() {
        let json = r#"{"jwks_uri": "https://example.com/.well-known/jwks.json"}"#;
        let req: RegistrationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.jwks_uri,
            Some("https://example.com/.well-known/jwks.json".to_string())
        );
        assert!(req.jwks.is_none());
    }

    /// `software_statement` must deserialize as a plain string (JWT is opaque here).
    #[test]
    fn test_request_deserialize_software_statement() {
        let json = r#"{"software_statement": "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJleGFtcGxlIn0.sig"}"#;
        let req: RegistrationRequest = serde_json::from_str(json).unwrap();
        assert!(req.software_statement.is_some());
        assert!(
            req.software_statement
                .unwrap()
                .starts_with("eyJhbGciOiJSUzI1NiJ9")
        );
    }

    /// An empty contacts array is a valid (though unusual) value.
    #[test]
    fn test_request_deserialize_empty_contacts() {
        let json = r#"{"contacts": []}"#;
        let req: RegistrationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.contacts, Some(vec![]));
    }

    // =========================================================================
    // Registration Response Serialization Tests
    // =========================================================================

    /// Optional fields marked `skip_serializing_if = "Option::is_none"` must be
    /// absent from the JSON when `None`, not serialized as `null`.
    #[test]
    fn test_response_serialization_omits_none_fields() {
        let response = RegistrationResponse {
            client_id: "test-client-id".to_string(),
            client_secret: None,
            client_secret_expires_at: None,
            client_id_issued_at: Some(1_700_000_000),
            registration_access_token: Some("vouch_reg_abc123".to_string()),
            registration_client_uri: Some(
                "https://example.com/oauth/register/test-client-id".to_string(),
            ),
            redirect_uris: None,
            token_endpoint_auth_method: "none".to_string(),
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            client_name: Some("Test App".to_string()),
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            scope: None,
            contacts: None,
            jwks: None,
            jwks_uri: None,
            software_id: None,
            software_version: None,
            dpop_bound_access_tokens: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Required fields must be present
        assert!(value.get("client_id").is_some());
        assert!(value.get("token_endpoint_auth_method").is_some());
        assert!(value.get("grant_types").is_some());
        assert!(value.get("response_types").is_some());

        // Optional None fields must be absent
        assert!(
            value.get("client_secret").is_none(),
            "client_secret must be absent when None"
        );
        assert!(value.get("client_secret_expires_at").is_none());
        assert!(value.get("redirect_uris").is_none());
        assert!(value.get("client_uri").is_none());
        assert!(value.get("logo_uri").is_none());
        assert!(value.get("tos_uri").is_none());
        assert!(value.get("policy_uri").is_none());
        assert!(value.get("scope").is_none());
        assert!(value.get("contacts").is_none());
        assert!(value.get("jwks").is_none());
        assert!(value.get("jwks_uri").is_none());
        assert!(value.get("software_id").is_none());
        assert!(value.get("software_version").is_none());
        assert!(value.get("dpop_bound_access_tokens").is_none());
    }

    /// When `client_secret` is present, `client_secret_expires_at` must also be present
    /// (RFC 7591 Section 3.2.1 requires it when a secret is issued).
    #[test]
    fn test_response_serialization_includes_secret_fields_when_present() {
        let response = RegistrationResponse {
            client_id: "test-client".to_string(),
            client_secret: Some("s3cr3t".to_string()),
            client_secret_expires_at: Some(0),
            client_id_issued_at: Some(1_700_000_000),
            registration_access_token: None,
            registration_client_uri: None,
            redirect_uris: Some(vec!["https://example.com/cb".to_string()]),
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            client_name: None,
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            scope: None,
            contacts: None,
            jwks: None,
            jwks_uri: None,
            software_id: None,
            software_version: None,
            dpop_bound_access_tokens: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["client_secret"], "s3cr3t");
        assert_eq!(value["client_secret_expires_at"], 0);
        assert_eq!(value["redirect_uris"].as_array().unwrap().len(), 1);
    }

    // =========================================================================
    // Constants Tests
    // =========================================================================

    #[test]
    fn test_allowed_grant_types_includes_expected() {
        assert!(
            ALLOWED_GRANT_TYPES.contains(&"authorization_code"),
            "authorization_code must be an allowed grant type"
        );
        assert!(
            ALLOWED_GRANT_TYPES.contains(&"client_credentials"),
            "client_credentials must be an allowed grant type"
        );
        assert!(
            ALLOWED_GRANT_TYPES.contains(&"urn:ietf:params:oauth:grant-type:device_code"),
            "device_code URN must be an allowed grant type"
        );
        assert!(
            ALLOWED_GRANT_TYPES.contains(&"refresh_token"),
            "refresh_token must be an allowed grant type"
        );
    }

    #[test]
    fn test_allowed_response_types_includes_code() {
        assert!(
            ALLOWED_RESPONSE_TYPES.contains(&"code"),
            "'code' must be in the allowed response types set"
        );
    }

    // =========================================================================
    // Constants — Additional Checks
    // =========================================================================

    /// `implicit` must NOT be in the allowed grant types list.
    #[test]
    fn test_implicit_grant_not_allowed() {
        assert!(
            !ALLOWED_GRANT_TYPES.contains(&"implicit"),
            "The implicit grant type must not be allowed (deprecated by RFC 9700)"
        );
    }

    /// `token` response type must NOT be in the allowed set.
    #[test]
    fn test_token_response_type_not_allowed() {
        assert!(
            !ALLOWED_RESPONSE_TYPES.contains(&"token"),
            "'token' response type must not be allowed (implicit flow)"
        );
    }

    /// `id_token` response type must NOT be in the allowed set.
    #[test]
    fn test_id_token_response_type_not_allowed() {
        assert!(
            !ALLOWED_RESPONSE_TYPES.contains(&"id_token"),
            "'id_token' response type must not be allowed (implicit flow)"
        );
    }

    /// MAX_REDIRECT_URIS must be a positive non-trivial limit.
    #[test]
    fn test_max_redirect_uris_is_reasonable() {
        const {
            assert!(MAX_REDIRECT_URIS >= 5, "should allow at least 5 URIs");
            assert!(MAX_REDIRECT_URIS <= 100, "should not be excessively large");
        }
    }

    /// MAX_CONTACTS must be a positive non-trivial limit.
    #[test]
    fn test_max_contacts_is_reasonable() {
        const {
            assert!(MAX_CONTACTS >= 2, "should allow at least 2 contacts");
        }
    }

    // =========================================================================
    // generate_registration_token Tests
    // =========================================================================

    /// Token must start with the "vouch_reg_" prefix.
    #[test]
    fn test_generate_registration_token_has_prefix() {
        let token = generate_registration_token().unwrap();
        assert!(
            token.starts_with("vouch_reg_"),
            "Registration token must start with 'vouch_reg_': got '{token}'"
        );
    }

    /// Tokens must be sufficiently long for security (prefix + 32 bytes base64url ≈ 53 chars).
    #[test]
    fn test_generate_registration_token_length() {
        let token = generate_registration_token().unwrap();
        // "vouch_reg_" = 10 chars; base64url(32 bytes) = 43 chars → total ≥ 50
        assert!(
            token.len() >= 50,
            "Registration token too short: {} chars",
            token.len()
        );
    }

    /// Two generated tokens must not be identical (random generation).
    #[test]
    fn test_generate_registration_token_is_unique() {
        let t1 = generate_registration_token().unwrap();
        let t2 = generate_registration_token().unwrap();
        assert_ne!(t1, t2, "Registration tokens must be unique");
    }

    /// Token suffix must be valid base64url (no '+', '/', '=' padding).
    #[test]
    fn test_generate_registration_token_suffix_is_base64url() {
        let token = generate_registration_token().unwrap();
        let suffix = token.strip_prefix("vouch_reg_").unwrap();
        assert!(
            !suffix.contains('+') && !suffix.contains('/') && !suffix.contains('='),
            "Token suffix must be base64url-encoded (no +, /, =): '{suffix}'"
        );
    }

    // =========================================================================
    // RegistrationSource Tests
    // =========================================================================

    /// `RegistrationSource::Manual` must serialize to "manual".
    #[test]
    fn test_registration_source_manual_as_str() {
        assert_eq!(RegistrationSource::Manual.as_str(), "manual");
    }

    /// `RegistrationSource::Dynamic` must serialize to "dynamic".
    #[test]
    fn test_registration_source_dynamic_as_str() {
        assert_eq!(RegistrationSource::Dynamic.as_str(), "dynamic");
    }

    /// Default registration source must be Manual (for backward-compatibility).
    #[test]
    fn test_registration_source_default_is_manual() {
        let default = RegistrationSource::default();
        assert_eq!(default.as_str(), "manual");
    }
}
