// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC Discovery and JWKS generation.
//!
//! Implements:
//! - OpenID Connect Discovery 1.0 Section 4
//! - RFC 7517 JSON Web Key (JWK) format
//! - RFC 9396 OAuth 2.0 Rich Authorization Requests (authorization_details supported)

use crate::AppState;
use crate::assurance::ACR_AAL3;
use crate::crypto::alg::JwsAlgorithm;
use crate::db::{FapiProfile, ResponseMode, TokenEndpointAuthMethod};
use crate::error::ServiceError;
use crate::services::oidc::OAuthScope;
use crate::services::oidc::authorization::CodeChallengeMethod;
use crate::services::oidc::grant_type::OAuthGrantType;
use serde::Serialize;
use std::sync::Arc;

/// OpenID Connect Discovery document (OIDC Discovery 1.0 Section 3).
///
/// All fields defined in OpenID Provider Metadata:
/// <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>
#[derive(Debug, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "OIDC discovery document has many boolean capability flags by spec"
)]
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
    pub id_token_signing_alg_values_supported: Vec<JwsAlgorithm>,
    /// OIDC Discovery 1.0 Section 3: OPTIONAL. Supported token endpoint auth methods.
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    /// RFC 8414 Section 2: Supported revocation endpoint auth methods.
    pub revocation_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    /// RFC 8414 Section 2: Supported introspection endpoint auth methods.
    pub introspection_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    /// OIDC Discovery 1.0 Section 3: RECOMMENDED. Supported Claim Names.
    pub claims_supported: Vec<String>,
    /// OIDC Discovery 1.0 Section 3: OPTIONAL. Whether the server supports
    /// the `claims` request parameter (OIDC Core Section 5.5).
    pub claims_parameter_supported: bool,
    /// RFC 7636 Section 6.2: Supported PKCE code challenge methods.
    pub code_challenge_methods_supported: Vec<String>,
    /// RFC 9449 Section 5.1: Supported DPoP JWS signing algorithms.
    ///
    /// See [`JwsAlgorithm::FAPI_ALLOWED`] for the FAPI 2.0 citation excluding RS256.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<JwsAlgorithm>>,
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
    /// The union of every [`FapiProfile`]'s allowed set — see
    /// [`FapiProfile::client_assertion_algorithms_union`]. FAPI 2.0 clients are
    /// restricted to [`JwsAlgorithm::FAPI_ALLOWED`] at enforcement time; this field
    /// additionally advertises `RS256` because non-FAPI clients may use it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<JwsAlgorithm>>,
    /// RFC 9126: URL of the Pushed Authorization Request endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
    /// RFC 9126: Whether PAR is required for all authorization requests.
    pub require_pushed_authorization_requests: bool,
    /// RFC 9101: Whether the server supports the `request` parameter.
    pub request_parameter_supported: bool,
    /// RFC 9101: Supported JWS algorithms for Request Object signing.
    ///
    /// RS256 is included because [`JwsAlgorithm::FAPI_ALLOWED`] restricts DPoP and token
    /// endpoint auth signing, not JAR signing. The validation layer enforces PS256/ES256/EdDSA
    /// for FAPI-profile clients; RS256 JARs from non-FAPI clients are accepted and advertised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<JwsAlgorithm>>,
    /// JARM: Supported JWS algorithms for authorization response signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_signing_alg_values_supported: Option<Vec<JwsAlgorithm>>,
    /// RFC 9101: Whether all authorization requests must use signed Request Objects.
    pub require_signed_request_object: bool,
    /// OIDC Core Section 6.2 / OIDC Discovery Section 3: Whether the server supports
    /// the `request_uri` parameter for fetching Request Object JWTs from URLs.
    pub request_uri_parameter_supported: bool,
    /// OIDC Discovery Section 3: Whether clients must pre-register `request_uris`.
    ///
    /// Set to `false` so the OIDC conformance suite (which does not pre-register
    /// `request_uris`) can use URL-based request_uri without registration.
    pub require_request_uri_registration: bool,
    /// RFC 9396 §11.3: Supported authorization detail types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details_types_supported: Option<Vec<String>>,
    /// OAuth 2.0 Mutual TLS Client Authentication (RFC 8705 Section 3).
    ///
    /// `true` when Client Certificate CA is configured, `false` otherwise.
    pub tls_client_certificate_bound_access_tokens: bool,
    /// RFC 8705 Section 5: mTLS endpoint aliases.
    ///
    /// Present when mTLS is configured, pointing to the mTLS port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_endpoint_aliases: Option<MtlsEndpointAliases>,
    /// RFC 9701 Section 7.1: Supported introspection response signing algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_signing_alg_values_supported: Option<Vec<JwsAlgorithm>>,
    /// OIDC Discovery 1.0 Section 3: OPTIONAL. Supported JWS alg values for UserInfo signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<JwsAlgorithm>>,
    /// RP-Initiated Logout 1.0 Section 2.4: URL of the end-session endpoint.
    pub end_session_endpoint: String,
}

/// RFC 8705 Section 5: mTLS endpoint aliases.
///
/// Clients that use mTLS for client authentication or certificate-bound
/// tokens should use these endpoint URLs instead of the standard ones.
#[derive(Debug, Serialize)]
pub struct MtlsEndpointAliases {
    /// Token endpoint on the mTLS port.
    pub token_endpoint: String,
    /// Revocation endpoint on the mTLS port.
    pub revocation_endpoint: String,
    /// Introspection endpoint on the mTLS port.
    pub introspection_endpoint: String,
    /// Device authorization endpoint on the mTLS port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    /// Registration endpoint on the mTLS port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// Pushed Authorization Request endpoint on the mTLS port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
    /// UserInfo endpoint on the mTLS port.
    pub userinfo_endpoint: String,
}

/// JSON Web Key Set response (RFC 7517 Section 5).
#[derive(Debug, Serialize)]
pub struct JwksResponse {
    /// RFC 7517 Section 5.1: The "keys" parameter is an array of JWK values.
    pub keys: Vec<crate::crypto::jwk::Jwk>,
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

    let auth_methods = {
        let mut methods = vec![
            TokenEndpointAuthMethod::None,
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
            TokenEndpointAuthMethod::PrivateKeyJwt,
        ];
        // mTLS client auth methods are available whenever TLS is fully
        // configured (cert AND key) — the mTLS listener only starts then.
        if state.config().tls_configured() {
            methods.push(TokenEndpointAuthMethod::TlsClientAuth);
            methods.push(TokenEndpointAuthMethod::SelfSignedTlsClientAuth);
        }
        methods
    };

    OidcDiscoveryDocument {
        issuer: base_url.to_string(),
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
        response_types_supported: super::SUPPORTED_RESPONSE_TYPES
            .iter()
            .map(ToString::to_string)
            .collect(),
        response_modes_supported: ResponseMode::supported_wire_values()
            .into_iter()
            .map(String::from)
            .collect(),
        grant_types_supported: OAuthGrantType::supported_wire_values()
            .into_iter()
            .map(String::from)
            .collect(),
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: if state.oidc_rsa_key.is_some() {
            vec![JwsAlgorithm::Rs256, JwsAlgorithm::Es256]
        } else {
            vec![JwsAlgorithm::Es256]
        },
        token_endpoint_auth_methods_supported: auth_methods.clone(),
        revocation_endpoint_auth_methods_supported: auth_methods.clone(),
        introspection_endpoint_auth_methods_supported: auth_methods,
        claims_supported: super::token::ADVERTISED_ID_TOKEN_CLAIMS
            .iter()
            .map(ToString::to_string)
            .collect(),
        claims_parameter_supported: false,
        code_challenge_methods_supported: CodeChallengeMethod::SUPPORTED
            .iter()
            .map(|m| m.as_str().to_string())
            .collect(),
        dpop_signing_alg_values_supported: Some(JwsAlgorithm::FAPI_ALLOWED.to_vec()),
        acr_values_supported: Some(vec![ACR_AAL3.to_string()]),
        // RFC 9207: Advertise that we include `iss` in authorization responses
        authorization_response_iss_parameter_supported: true,
        // RFC 8707: Advertise resource indicator support
        resource_indicators_supported: Some(true),
        // RFC 7523: JWT client auth signing algorithms — the union of every
        // FapiProfile's allowed set (RS256 comes in via the non-FAPI profile).
        // Structurally derived, not an independently maintained list: see
        // FapiProfile::client_assertion_algorithms_union.
        token_endpoint_auth_signing_alg_values_supported: Some(
            FapiProfile::client_assertion_algorithms_union(),
        ),
        // RFC 9126: Pushed Authorization Request endpoint
        pushed_authorization_request_endpoint: Some(format!("{base_url}/oauth/par")),
        require_pushed_authorization_requests: false,
        // RFC 9101: JWT-Secured Authorization Request support
        request_parameter_supported: true,
        // RS256 is advertised for non-FAPI clients (OIDC Basic Profile conformance requires it).
        // The JAR validator enforces PS256/ES256/EdDSA for FAPI-profile clients via
        // validate_fapi_algorithm(); non-FAPI clients may use RS256 and it validates correctly.
        request_object_signing_alg_values_supported: Some(vec![
            JwsAlgorithm::Rs256,
            JwsAlgorithm::Es256,
            JwsAlgorithm::Ps256,
            JwsAlgorithm::EdDsa,
        ]),
        require_signed_request_object: false,
        // OIDC Core Section 6.2: Advertise URL-based request_uri support.
        request_uri_parameter_supported: true,
        // OIDC Discovery Section 3: pre-registration not required (conformance suite
        // does not register request_uris during dynamic registration).
        require_request_uri_registration: false,
        // JARM: supported signing algorithms for authorization responses.
        authorization_signing_alg_values_supported: Some(if state.oidc_rsa_key.is_some() {
            vec![JwsAlgorithm::Rs256, JwsAlgorithm::Es256]
        } else {
            vec![JwsAlgorithm::Es256]
        }),
        // RFC 9396 §11.3: Server accepts any authorization detail type (opaque)
        authorization_details_types_supported: None,
        // RFC 8705: advertise mTLS support when TLS is fully configured.
        tls_client_certificate_bound_access_tokens: state.config().tls_configured(),
        mtls_endpoint_aliases: build_mtls_aliases(state, base_url),
        // RFC 9701: ES256 is the only supported introspection signing algorithm.
        introspection_signing_alg_values_supported: Some(vec![JwsAlgorithm::Es256]),
        // OIDC Core Section 5.3.4: Supported UserInfo signing algorithms.
        userinfo_signing_alg_values_supported: Some(if state.oidc_rsa_key.is_some() {
            vec![JwsAlgorithm::Rs256, JwsAlgorithm::Es256]
        } else {
            vec![JwsAlgorithm::Es256]
        }),
        // RP-Initiated Logout 1.0 Section 2.4.
        end_session_endpoint: format!("{base_url}/oauth/logout"),
    }
}

/// Build mTLS endpoint aliases when TLS is configured.
///
/// The mTLS base URL is always derived from `base_url` with the port replaced
/// by `mtls_port` (default 8443). Returns `None` when TLS is not configured.
fn build_mtls_aliases(state: &Arc<AppState>, base_url: &str) -> Option<MtlsEndpointAliases> {
    let config = state.config();

    // Only advertise mTLS aliases when TLS is active on this server
    // (cert AND key — a partial config never starts the mTLS listener).
    if !config.tls_configured() {
        return None;
    }

    // Derive mTLS base URL by replacing the port with mtls_port.
    let mtls_base = if let Ok(mut url) = url::Url::parse(base_url) {
        // url::Url::set_port returns Result<(), ()>; failure means non-special URL,
        // already validated upstream.
        let _set = url.set_port(Some(config.mtls_port));
        url.to_string().trim_end_matches('/').to_string()
    } else {
        tracing::warn!(
            "Could not parse base_url '{}' for mTLS aliases, using port append",
            base_url
        );
        format!("{base_url}:{}", config.mtls_port)
    };

    Some(MtlsEndpointAliases {
        token_endpoint: format!("{mtls_base}/oauth/token"),
        revocation_endpoint: format!("{mtls_base}/oauth/revoke"),
        introspection_endpoint: format!("{mtls_base}/oauth/introspect"),
        device_authorization_endpoint: Some(format!("{mtls_base}/oauth/device")),
        registration_endpoint: Some(format!("{mtls_base}/oauth/register")),
        pushed_authorization_request_endpoint: Some(format!("{mtls_base}/oauth/par")),
        userinfo_endpoint: format!("{mtls_base}/oauth/userinfo"),
    })
}

/// Minimal OIDC discovery document served on org issuer-subdomain hosts.
///
/// Org subdomains exist solely as per-org trust anchors for AWS workload
/// identity federation: AWS IAM reads only `issuer` and `jwks_uri` when an
/// OIDC identity provider is created. The remaining fields are the
/// REQUIRED-by-spec floor (OIDC Discovery 1.0 Section 3). Deliberately not
/// the full FAPI document — advertising primary-host endpoints under an
/// org issuer would be spec-ambiguous, and none of those endpoints are
/// served on org hosts anyway.
#[derive(Debug, Serialize)]
pub struct WifDiscoveryDocument {
    /// Issuer Identifier: `https://{label}.{primary_host}`.
    pub issuer: String,
    /// JWKS URL on the same host; serves the org's own keys (the shared
    /// platform keys only in the dev plaintext fallback).
    pub jwks_uri: String,
    /// Spec-required floor; no authorization endpoint exists on org hosts.
    pub response_types_supported: Vec<String>,
    /// Spec-required floor.
    pub subject_types_supported: Vec<String>,
    /// Algorithms the keys behind this issuer's JWKS actually sign with:
    /// per-org key sets always hold ES256 + RS256; the plaintext-store
    /// fallback advertises what the platform keys support.
    pub id_token_signing_alg_values_supported: Vec<JwsAlgorithm>,
    /// Claims present in the AWS tokens.
    pub claims_supported: Vec<String>,
}

/// Build the WIF-only discovery document for an org issuer host.
///
/// `issuer` must come from [`crate::config::ServerConfig::org_issuer`] (stored
/// label + configured base URL) — never from the request `Host` header.
#[must_use]
pub fn build_wif_discovery_document(state: &Arc<AppState>, issuer: &str) -> WifDiscoveryDocument {
    WifDiscoveryDocument {
        issuer: issuer.to_string(),
        jwks_uri: format!("{issuer}/oauth/jwks"),
        response_types_supported: vec!["id_token".to_string()],
        subject_types_supported: vec!["public".to_string()],
        // This document is only served for claimed org subdomains. With an
        // encrypted store the org's own key set (always ES256 + RS256) backs
        // the JWKS; otherwise the shared platform keys do.
        id_token_signing_alg_values_supported: if state.store.is_encrypted()
            || state.oidc_rsa_key.is_some()
        {
            vec![JwsAlgorithm::Rs256, JwsAlgorithm::Es256]
        } else {
            vec![JwsAlgorithm::Es256]
        },
        claims_supported: vec![
            "sub".to_string(),
            "iss".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "email".to_string(),
        ],
    }
}

/// Build the JSON Web Key Set for token verification.
///
/// # Arguments
/// * `state` - Application state containing the OIDC signing keys
///
/// # Returns
/// The JWKS containing all public keys used to sign tokens.
/// RSA key (RS256) is listed first per OIDC Core Section 3.1.3.7 (RS256 is the default).
/// EC key (ES256) is always present (used for access tokens).
///
/// # Errors
/// Returns `ServiceError` if a public key cannot be exported.
pub fn build_jwks(state: &Arc<AppState>) -> Result<JwksResponse, ServiceError> {
    let mut keys = Vec::new();

    // RSA key first (primary for ID tokens per OIDC Core Section 3.1.3.7)
    if let Some(rsa_key) = &state.oidc_rsa_key {
        keys.push(crate::crypto::jwk::Jwk::Rsa(
            rsa_key.public_key_jwk().map_err(|e| {
                tracing::error!("Failed to get OIDC RSA public key JWK: {}", e);
                ServiceError::Internal("Failed to export OIDC RSA public key".to_string())
            })?,
        ));
    }

    // EC key (always present, used for access tokens)
    keys.push(crate::crypto::jwk::Jwk::Ec(
        state.oidc_key.public_key_jwk().map_err(|e| {
            tracing::error!("Failed to get OIDC public key JWK: {}", e);
            ServiceError::Internal("Failed to export OIDC public key".to_string())
        })?,
    ));

    Ok(JwksResponse { keys })
}
