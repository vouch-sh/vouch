// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC Discovery and JWKS generation.
//!
//! Implements:
//! - OpenID Connect Discovery 1.0 Section 4
//! - RFC 7517 JSON Web Key (JWK) format
//! - RFC 9396 OAuth 2.0 Rich Authorization Requests (authorization_details supported)

use crate::AppState;
use crate::services::ServiceError;
use crate::services::oidc::amr::ACR_AAL3;
use crate::services::oidc::scope::OAuthScope;
use serde::Serialize;
use std::sync::Arc;

/// OpenID Connect Discovery document (OIDC Discovery 1.0 Section 3).
///
/// All fields defined in OpenID Provider Metadata:
/// <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>
#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct OidcDiscoveryDocument {
    /// OIDC Discovery 1.0 Section 3: REQUIRED. Issuer Identifier (must match tokens).
    pub issuer: String,
    /// OIDC Discovery 1.0 Section 3: REQUIRED. URL of the authorization endpoint.
    pub authorization_endpoint: String,
    /// OIDC Discovery 1.0 Section 3: REQUIRED. URL of the token endpoint.
    pub token_endpoint: String,
    /// OIDC Discovery 1.0 Section 3: RECOMMENDED. URL of the UserInfo endpoint.
    pub userinfo_endpoint: String,
    /// OIDC Discovery 1.0 Section 3: REQUIRED. URL of the JWKS endpoint.
    pub jwks_uri: String,
    /// RFC 7009 Section 2.1: URL of the token revocation endpoint.
    pub revocation_endpoint: String,
    /// RFC 7662 Section 2: URL of the token introspection endpoint.
    pub introspection_endpoint: String,
    /// RFC 8628 Section 4: URL of the device authorization endpoint.
    pub device_authorization_endpoint: String,
    /// OIDC Discovery 1.0 Section 3: OPTIONAL. URL of the dynamic registration endpoint.
    pub registration_endpoint: Option<String>,
    /// OIDC Discovery 1.0 Section 3: RECOMMENDED. Supported OAuth 2.0 scope values.
    pub scopes_supported: Vec<String>,
    /// OIDC Discovery 1.0 Section 3: REQUIRED. Supported OAuth 2.0 response_type values.
    pub response_types_supported: Vec<String>,
    /// OIDC Discovery 1.0 Section 3: OPTIONAL. Supported OAuth 2.0 response_mode values.
    pub response_modes_supported: Vec<String>,
    /// OIDC Discovery 1.0 Section 3: OPTIONAL. Supported OAuth 2.0 grant_type values.
    pub grant_types_supported: Vec<String>,
    /// OIDC Discovery 1.0 Section 3: REQUIRED. Supported Subject Identifier types.
    pub subject_types_supported: Vec<String>,
    /// OIDC Discovery 1.0 Section 3: REQUIRED. Supported JWS alg values for ID Tokens.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// OIDC Discovery 1.0 Section 3: OPTIONAL. Supported token endpoint auth methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// OIDC Discovery 1.0 Section 3: RECOMMENDED. Supported Claim Names.
    pub claims_supported: Vec<String>,
    /// RFC 7636 Section 6.2: Supported PKCE code challenge methods.
    pub code_challenge_methods_supported: Vec<String>,
    /// RFC 9449 Section 5.1: Supported DPoP JWS signing algorithms.
    ///
    /// RS256 is excluded per FAPI 2.0 Section 5.2.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// OIDC Discovery 1.0 Section 3: OPTIONAL. Supported ACR values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values_supported: Option<Vec<String>>,
    /// RFC 9207 Section 3: Authorization Response Issuer Identifier support.
    /// Indicates that the authorization server includes the `iss` parameter
    /// in authorization responses to prevent mix-up attacks.
    pub authorization_response_iss_parameter_supported: bool,
    /// RFC 8707 Section 2: Indicates support for the `resource` parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_indicators_supported: Option<bool>,
    /// RFC 7523: Supported JWS algorithms for JWT client authentication.
    ///
    /// Includes PS256 and EdDSA per FAPI 2.0 requirements; RS256 is excluded
    /// per FAPI 2.0 Section 5.2.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// RFC 9126: URL of the Pushed Authorization Request endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
    /// RFC 9126: Whether PAR is required for all authorization requests.
    pub require_pushed_authorization_requests: bool,
    /// RFC 9101: Whether the server supports the `request` parameter.
    pub request_parameter_supported: bool,
    /// RFC 9101: Supported JWS algorithms for Request Object signing.
    ///
    /// Includes EdDSA and PS256 per FAPI 2.0; RS256 is excluded per FAPI 2.0 Section 5.2.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    /// RFC 9101: Whether all authorization requests must use signed Request Objects.
    pub require_signed_request_object: bool,
    /// RFC 9396 §11.3: Supported authorization detail types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details_types_supported: Option<Vec<String>>,
    /// OAuth 2.0 Mutual TLS Client Authentication — not supported.
    ///
    /// Explicitly advertised as `false` so FAPI 2.0 conformance tools know we do
    /// not support mTLS certificate-bound access tokens (we use DPoP instead).
    pub tls_client_certificate_bound_access_tokens: bool,
}

/// JSON Web Key Set response (RFC 7517 Section 5).
#[derive(Debug, Serialize)]
pub struct JwksResponse {
    /// RFC 7517 Section 5.1: The "keys" parameter is an array of JWK values.
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
        registration_endpoint: Some(format!("{base_url}/oauth/register")),
        scopes_supported: OAuthScope::all()
            .iter()
            .map(|s| s.as_str().to_string())
            .collect(),
        response_types_supported: vec!["code".to_string()],
        response_modes_supported: vec!["query".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "client_credentials".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            "urn:ietf:params:oauth:grant-type:fido2-assertion".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["ES256".to_string()],
        token_endpoint_auth_methods_supported: vec![
            "none".to_string(),
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
            "private_key_jwt".to_string(),
        ],
        claims_supported: vec![
            "sub".to_string(),
            "iss".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "auth_time".to_string(),
            "nonce".to_string(),
            "at_hash".to_string(),
            "email".to_string(),
            "email_verified".to_string(),
            "hardware_verified".to_string(),
            "hardware_aaguid".to_string(),
            "amr".to_string(),
            "acr".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string()],
        // RS256 excluded per FAPI 2.0 Section 5.2.2.
        dpop_signing_alg_values_supported: Some(vec![
            "ES256".to_string(),
            "PS256".to_string(),
            "EdDSA".to_string(),
        ]),
        acr_values_supported: Some(vec![ACR_AAL3.to_string()]),
        // RFC 9207: Advertise that we include `iss` in authorization responses
        authorization_response_iss_parameter_supported: true,
        // RFC 8707: Advertise resource indicator support
        resource_indicators_supported: Some(true),
        // RFC 7523: JWT client auth signing algorithms.
        // PS256 and EdDSA added per FAPI 2.0; RS256 excluded per FAPI 2.0 Section 5.2.2.
        token_endpoint_auth_signing_alg_values_supported: Some(vec![
            "ES256".to_string(),
            "PS256".to_string(),
            "EdDSA".to_string(),
        ]),
        // RFC 9126: Pushed Authorization Request endpoint
        pushed_authorization_request_endpoint: Some(format!("{base_url}/oauth/par")),
        require_pushed_authorization_requests: false,
        // RFC 9101: JWT-Secured Authorization Request support
        request_parameter_supported: true,
        // Request Object signing algorithms: EdDSA added per FAPI 2.0; RS256 excluded
        // per FAPI 2.0 Section 5.2.2.
        request_object_signing_alg_values_supported: Some(vec![
            "ES256".to_string(),
            "PS256".to_string(),
            "EdDSA".to_string(),
        ]),
        require_signed_request_object: false,
        // RFC 9396 §11.3: Server accepts any authorization detail type (opaque)
        authorization_details_types_supported: None,
        // We use DPoP (not mTLS) for sender-constrained tokens.
        tls_client_certificate_bound_access_tokens: false,
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
