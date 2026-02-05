// SPDX-License-Identifier: BUSL-1.1
//! OIDC Discovery and JWKS generation.
//!
//! Implements:
//! - OpenID Connect Discovery 1.0 Section 4
//! - RFC 7517 JSON Web Key (JWK) format

use crate::AppState;
use crate::services::ServiceError;
use serde::Serialize;
use std::sync::Arc;

/// OpenID Connect Discovery document.
/// See: https://openid.net/specs/openid-connect-discovery-1_0.html
#[derive(Debug, Serialize)]
pub struct OidcDiscoveryDocument {
    /// Issuer identifier (must match tokens).
    pub issuer: String,
    /// URL of the authorization endpoint.
    pub authorization_endpoint: String,
    /// URL of the token endpoint.
    pub token_endpoint: String,
    /// URL of the userinfo endpoint.
    pub userinfo_endpoint: String,
    /// URL of the JWKS endpoint.
    pub jwks_uri: String,
    /// URL of the token revocation endpoint.
    pub revocation_endpoint: String,
    /// URL of the token introspection endpoint.
    pub introspection_endpoint: String,
    /// URL of the device authorization endpoint (RFC 8628).
    pub device_authorization_endpoint: String,
    /// URL of the dynamic registration endpoint (optional).
    pub registration_endpoint: Option<String>,
    /// Supported scopes.
    pub scopes_supported: Vec<String>,
    /// Supported response types.
    pub response_types_supported: Vec<String>,
    /// Supported response modes.
    pub response_modes_supported: Vec<String>,
    /// Supported grant types.
    pub grant_types_supported: Vec<String>,
    /// Supported subject types.
    pub subject_types_supported: Vec<String>,
    /// Supported ID token signing algorithms.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Supported token endpoint auth methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Supported claims.
    pub claims_supported: Vec<String>,
    /// Supported PKCE code challenge methods.
    pub code_challenge_methods_supported: Vec<String>,
    /// RFC 9449: Supported DPoP signing algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// RFC 9207: Authorization Response Issuer Identifier support.
    /// Indicates that the authorization server includes the `iss` parameter
    /// in authorization responses to prevent mix-up attacks.
    pub authorization_response_iss_parameter_supported: bool,
}

/// JSON Web Key Set response.
#[derive(Debug, Serialize)]
pub struct JwksResponse {
    /// The keys in this key set.
    pub keys: Vec<super::keys::EcJwk>,
}

/// Build the OIDC discovery document for this server.
///
/// # Arguments
/// * `state` - Application state containing configuration
///
/// # Returns
/// The OIDC discovery document with all endpoints and capabilities advertised.
#[must_use]
pub fn build_discovery_document(state: &Arc<AppState>) -> OidcDiscoveryDocument {
    let base_url = &state.config().base_url;

    OidcDiscoveryDocument {
        issuer: base_url.clone(),
        authorization_endpoint: format!("{base_url}/oauth/authorize"),
        token_endpoint: format!("{base_url}/oauth/token"),
        userinfo_endpoint: format!("{base_url}/oauth/userinfo"),
        jwks_uri: format!("{base_url}/oauth/jwks"),
        revocation_endpoint: format!("{base_url}/oauth/revoke"),
        introspection_endpoint: format!("{base_url}/oauth/introspect"),
        device_authorization_endpoint: format!("{base_url}/oauth/device"),
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
        id_token_signing_alg_values_supported: vec!["ES256".to_string()],
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
        dpop_signing_alg_values_supported: if state.config().dpop_enabled {
            Some(vec![
                "ES256".to_string(),
                "RS256".to_string(),
                "EdDSA".to_string(),
            ])
        } else {
            None
        },
        // RFC 9207: Advertise that we include `iss` in authorization responses
        authorization_response_iss_parameter_supported: true,
    }
}

/// Build the JSON Web Key Set for token verification.
///
/// # Arguments
/// * `state` - Application state containing the OIDC signing key
///
/// # Returns
/// The JWKS containing the public key used to sign tokens.
///
/// # Errors
/// Returns `ServiceError` if the public key cannot be exported.
pub fn build_jwks(state: &Arc<AppState>) -> Result<JwksResponse, ServiceError> {
    let jwk = state.oidc_key.public_key_jwk().map_err(|e| {
        tracing::error!("Failed to get OIDC public key JWK: {}", e);
        ServiceError::Internal("Failed to export OIDC public key".to_string())
    })?;

    Ok(JwksResponse { keys: vec![jwk] })
}
