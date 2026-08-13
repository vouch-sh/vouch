// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7591/7592 — OAuth 2.0 Dynamic Client Registration and Management.
//!
//! Implements:
//! - `POST /oauth/register` — Client Registration (RFC 7591)
//! - `GET /oauth/register/:client_id` — Client Configuration Read (RFC 7592)
//!
//! Registration logic includes:
//! - Request validation and metadata defaulting
//! - Grant/response type consistency checks
//! - Redirect URI validation (delegates to existing helpers)
//! - JWKS/JWKS_URI mutual exclusivity
//! - FAPI 2.0 enforcement at registration time
//! - Client creation and credential generation
//!
//! References:
//! - <https://www.rfc-editor.org/rfc/rfc7591>
//! - <https://www.rfc-editor.org/rfc/rfc7592>

use crate::AppState;
use crate::crypto::{generate_random_bytes, hash_token};
use crate::db::{
    self, CreateOAuthClientParams, FapiProfile, JwsAlgorithm, OAuthClient, OAuthClientType,
    OAuthEventType, RegistrationSource, TokenEndpointAuthMethod, UpdateClientRegistrationParams,
};
use crate::error::{OAuthErrorCode, ServiceError};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;

// ============================================================================
// Allowed Grant and Response Types
// ============================================================================

/// Grant types that this server accepts for dynamic registration.
/// Note: `refresh_token` is accepted in registration but the server never
/// issues refresh tokens — clients that request it will simply never
/// receive one in token responses.
const ALLOWED_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:ietf:params:oauth:grant-type:fido2-assertion",
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
#[derive(Debug, Default, Deserialize)]
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
    /// FAPI 2.0: Whether access tokens must be DPoP-bound.
    pub dpop_bound_access_tokens: Option<bool>,
    /// OIDC Core Section 3.1.3.7: ID token signing algorithm.
    pub id_token_signed_response_alg: Option<String>,
    /// RFC 8705 Section 2.1.1: subject DN for tls_client_auth.
    pub tls_client_auth_subject_dn: Option<String>,
    /// RFC 8705 Section 2.1.1: SAN DNS name for tls_client_auth.
    pub tls_client_auth_san_dns: Option<String>,
    /// RFC 8705 Section 2.1.1: SAN URI for tls_client_auth.
    pub tls_client_auth_san_uri: Option<String>,
    /// RFC 8705 Section 2.1.1: SAN IP for tls_client_auth.
    pub tls_client_auth_san_ip: Option<String>,
    /// RFC 8705 Section 2.1.1: SAN email for tls_client_auth.
    pub tls_client_auth_san_email: Option<String>,
    /// RFC 8705 Section 3: certificate-bound access tokens.
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
    /// JARM: signing algorithm for authorization responses.
    pub authorization_signed_response_alg: Option<String>,
    /// RFC 9701 Section 6.1: Introspection response signing algorithm.
    pub introspection_signed_response_alg: Option<String>,
    /// RFC 9101: Algorithm for Request Object signing.
    pub request_object_signing_alg: Option<String>,
    /// RFC 9101: Whether this client requires signed request objects.
    pub require_signed_request_object: Option<bool>,
    /// OIDC Core Section 5.3.4: UserInfo response signing algorithm.
    pub userinfo_signed_response_alg: Option<String>,
    /// OIDC Core Section 6.2: Pre-registered request_uri values (optional allowlist).
    ///
    /// Each URI must be HTTPS. When present, only these URLs are accepted as `request_uri`.
    pub request_uris: Option<Vec<String>>,
    /// RP-Initiated Logout 1.0 Section 2: Registered post-logout redirect URIs.
    ///
    /// When present, only these URIs are accepted as `post_logout_redirect_uri` in
    /// the end-session request. Absent means no redirect-back after logout.
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

impl RegistrationRequest {
    /// Build the JSON blob stored in `OAuthClient::registration_metadata`.
    ///
    /// Includes only fields that don't have their own database column:
    /// `client_uri`, `logo_uri`, `tos_uri`, `policy_uri`, `contacts`, `scope`.
    /// Fields with dedicated columns (e.g. `client_name`, `software_id`) are excluded.
    fn registration_metadata(&self) -> serde_json::Value {
        let mut metadata = serde_json::Map::new();
        if let Some(ref v) = self.client_uri {
            metadata.insert(
                "client_uri".to_string(),
                serde_json::Value::String(v.clone()),
            );
        }
        if let Some(ref v) = self.logo_uri {
            metadata.insert("logo_uri".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.tos_uri {
            metadata.insert("tos_uri".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.policy_uri {
            metadata.insert(
                "policy_uri".to_string(),
                serde_json::Value::String(v.clone()),
            );
        }
        if let Some(ref v) = self.contacts {
            metadata.insert(
                "contacts".to_string(),
                serde_json::Value::Array(
                    v.iter()
                        .map(|c| serde_json::Value::String(c.clone()))
                        .collect(),
                ),
            );
        }
        if let Some(ref v) = self.scope {
            metadata.insert("scope".to_string(), serde_json::Value::String(v.clone()));
        }
        serde_json::Value::Object(metadata)
    }
}

/// RFC 7591 Section 3.2.1: Client Information Response.
#[derive(Serialize)]
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
    /// OIDC: Algorithm used for signing ID tokens.
    pub id_token_signed_response_alg: String,
    /// JARM: signing algorithm for authorization responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_signed_response_alg: Option<String>,
    /// RFC 9701 Section 6.1: Introspection response signing algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_signed_response_alg: Option<String>,
    /// RFC 9101: Algorithm for Request Object signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,
    /// RFC 9101: Whether signed request objects are required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_signed_request_object: Option<bool>,
    /// OIDC Core Section 5.3.4: UserInfo response signing algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,
    /// OIDC Core Section 6.2: Pre-registered request_uri values (echoed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uris: Option<Vec<String>>,
    /// RP-Initiated Logout 1.0: Registered post-logout redirect URIs (echoed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

// Custom Debug that redacts client_secret and registration_access_token to
// prevent accidental log exposure. Both are minted here and returned to the
// client in plaintext exactly once.
impl std::fmt::Debug for RegistrationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationResponse")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("client_secret_expires_at", &self.client_secret_expires_at)
            .field("client_id_issued_at", &self.client_id_issued_at)
            .field("registration_access_token", &"[REDACTED]")
            .field("registration_client_uri", &self.registration_client_uri)
            .field("redirect_uris", &self.redirect_uris)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field("grant_types", &self.grant_types)
            .field("response_types", &self.response_types)
            .field("client_name", &self.client_name)
            .field("client_uri", &self.client_uri)
            .field("logo_uri", &self.logo_uri)
            .field("tos_uri", &self.tos_uri)
            .field("policy_uri", &self.policy_uri)
            .field("scope", &self.scope)
            .field("contacts", &self.contacts)
            .field("jwks", &self.jwks)
            .field("jwks_uri", &self.jwks_uri)
            .field("software_id", &self.software_id)
            .field("software_version", &self.software_version)
            .field("dpop_bound_access_tokens", &self.dpop_bound_access_tokens)
            .field(
                "id_token_signed_response_alg",
                &self.id_token_signed_response_alg,
            )
            .field(
                "authorization_signed_response_alg",
                &self.authorization_signed_response_alg,
            )
            .field(
                "introspection_signed_response_alg",
                &self.introspection_signed_response_alg,
            )
            .field(
                "request_object_signing_alg",
                &self.request_object_signing_alg,
            )
            .field(
                "require_signed_request_object",
                &self.require_signed_request_object,
            )
            .field(
                "userinfo_signed_response_alg",
                &self.userinfo_signed_response_alg,
            )
            .field("request_uris", &self.request_uris)
            .field("post_logout_redirect_uris", &self.post_logout_redirect_uris)
            .finish()
    }
}

// ============================================================================
// Core Registration Logic
// ============================================================================

/// Register a new OAuth client per RFC 7591.
///
/// # Arguments
/// * `state` — Application state (DB, config, etc.)
/// * `request` — The registration request body
/// * `authenticated_user_id` — Optional user ID from the Bearer token; `None` for open registration
///
/// # Errors
/// Returns `ServiceError::OAuth` with the appropriate RFC 7591 error code.
#[expect(
    clippy::too_many_lines,
    reason = "single-pass RFC 7591 registration metadata validation"
)]
pub async fn register_client(
    state: &Arc<AppState>,
    mut request: RegistrationRequest,
    authenticated_user_id: Option<&str>,
) -> Result<RegistrationResponse, ServiceError> {
    // 1. Validate grant/response types, apply defaults, check consistency
    let validated = validate_grant_and_response_types(&mut request)?;

    // 7. Validate redirect URIs
    let redirect_uris = validate_redirect_uris(&mut request, validated.auth_code_grant)?;

    // 8-9. Validate JWKS and auth method
    let jwks_auth = validate_jwks_and_auth_method(&mut request, &validated.auth_method_str)?;

    // 10-11. Validate contacts and URI fields
    validate_contacts_and_uris(&request)?;

    // 12. FAPI 2.0 enforcement
    let dpop_bound = request.dpop_bound_access_tokens.unwrap_or(false);
    let cert_bound = request
        .tls_client_certificate_bound_access_tokens
        .unwrap_or(false);
    let is_fapi2 = dpop_bound || cert_bound;
    let fapi_profile = if is_fapi2 {
        // Require FAPI-compliant auth method
        let is_fapi_auth = matches!(
            jwks_auth.auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt
                | TokenEndpointAuthMethod::TlsClientAuth
                | TokenEndpointAuthMethod::SelfSignedTlsClientAuth
        );
        if !is_fapi_auth {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                "FAPI 2.0 requires token_endpoint_auth_method \
                 'private_key_jwt', 'tls_client_auth', or \
                 'self_signed_tls_client_auth'",
            ));
        }
        if jwks_auth.jwks_value.is_none() && jwks_auth.jwks_uri.is_none() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                "FAPI 2.0 requires jwks or jwks_uri",
            ));
        }
        FapiProfile::Fapi2Security
    } else {
        FapiProfile::None
    };

    // OIDC Core Section 3.1.3.7: Default is RS256, but fall back to ES256 if no RSA key.
    let explicit_alg: Option<JwsAlgorithm> =
        if let Some(ref s) = request.id_token_signed_response_alg {
            let parsed = s.parse::<JwsAlgorithm>().map_err(|_| {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    format!(
                        "Unsupported id_token_signed_response_alg: '{s}'. \
                     Supported: RS256, ES256"
                    ),
                )
            })?;
            // Only RS256 and ES256 are accepted for ID tokens.
            if !matches!(parsed, JwsAlgorithm::Rs256 | JwsAlgorithm::Es256) {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    format!(
                        "Unsupported id_token_signed_response_alg: '{s}'. \
                     Supported: RS256, ES256"
                    ),
                ));
            }

            // FAPI 2.0 Section 5.4: RS256 is not permitted for FAPI clients.
            reject_rs256_for_fapi(parsed, fapi_profile, "id_token_signed_response_alg")?;

            // If RS256 is explicitly requested but no RSA key is configured, reject.
            // An unspecified algorithm falls back to ES256 automatically (see below).
            if parsed == JwsAlgorithm::Rs256 && state.oidc_rsa_key.is_none() {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    "RS256 is not available (no RSA signing key configured)",
                ));
            }

            Some(parsed)
        } else {
            None
        };

    // When the client didn't specify, use RS256 if available, otherwise ES256.
    // FAPI 2.0 Section 5.4: FAPI clients always use ES256.
    let id_token_alg = if fapi_profile != FapiProfile::None {
        JwsAlgorithm::Es256
    } else {
        explicit_alg.unwrap_or_else(|| {
            if state.oidc_rsa_key.is_some() {
                JwsAlgorithm::Rs256
            } else {
                JwsAlgorithm::Es256
            }
        })
    };

    // 12b. Validate authorization_signed_response_alg (JARM).
    // Serde rejects "none" and symmetric (HS*) algorithms since they are not
    // valid JwsAlgorithm variants. Only RS256 and ES256 are accepted for JARM.
    let jarm_alg: Option<JwsAlgorithm> =
        if let Some(ref s) = request.authorization_signed_response_alg {
            let parsed = s.parse::<JwsAlgorithm>().map_err(|_| {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    format!(
                        "Unsupported authorization_signed_response_alg: '{s}'. \
                     Must be an asymmetric algorithm such as RS256 or ES256"
                    ),
                )
            })?;
            // Only RS256 and ES256 are accepted for JARM responses.
            if !matches!(parsed, JwsAlgorithm::Rs256 | JwsAlgorithm::Es256) {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    format!(
                        "Unsupported authorization_signed_response_alg: '{s}'. \
                     Supported: RS256, ES256"
                    ),
                ));
            }
            // FAPI 2.0 Section 5.4.1: RS256 is not permitted for FAPI clients.
            reject_rs256_for_fapi(parsed, fapi_profile, "authorization_signed_response_alg")?;
            if parsed == JwsAlgorithm::Rs256 && state.oidc_rsa_key.is_none() {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    "RS256 is not available for authorization_signed_response_alg \
                 (no RSA signing key configured)",
                ));
            }
            Some(parsed)
        } else {
            None
        };

    // 12c. Validate introspection_signed_response_alg (RFC 9701).
    // Only ES256 is supported — the server's primary P-256 ECDSA key.
    let introspection_alg: Option<JwsAlgorithm> =
        if let Some(ref s) = request.introspection_signed_response_alg {
            let parsed = s.parse::<JwsAlgorithm>().map_err(|_| {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    format!(
                        "Unsupported introspection_signed_response_alg: '{s}'. \
                     Supported: ES256"
                    ),
                )
            })?;
            if parsed != JwsAlgorithm::Es256 {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    format!(
                        "Unsupported introspection_signed_response_alg: '{s}'. \
                     Supported: ES256"
                    ),
                ));
            }
            Some(parsed)
        } else {
            None
        };

    // 12c-2. Validate userinfo_signed_response_alg (OIDC Core Section 5.3.4).
    let rsa_key = if state.oidc_rsa_key.is_some() {
        RsaSigningKey::Available
    } else {
        RsaSigningKey::Unavailable
    };
    let userinfo_alg = validate_userinfo_signed_response_alg(
        request.userinfo_signed_response_alg.as_deref(),
        rsa_key,
        fapi_profile,
    )?;

    // 12b-2. Validate request_uris (OIDC Core Section 6.2).
    let validated_request_uris = validate_request_uris(request.request_uris.as_deref())?;

    // 12b-3. Validate post_logout_redirect_uris (RP-Initiated Logout 1.0 Section 2).
    let validated_post_logout_redirect_uris = validate_post_logout_redirect_uris_registration(
        request.post_logout_redirect_uris.as_deref(),
    )?;

    // 12d. Validate request_object_signing_alg (RFC 9101).
    let req_obj_alg: Option<JwsAlgorithm> = if let Some(ref s) = request.request_object_signing_alg
    {
        let parsed = s.parse::<JwsAlgorithm>().map_err(|_| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!("Unsupported request_object_signing_alg: '{s}'"),
            )
        })?;
        // FAPI 2.0 Section 5.4: RS256 is not permitted for FAPI clients.
        reject_rs256_for_fapi(parsed, fapi_profile, "request_object_signing_alg")?;
        Some(parsed)
    } else {
        None
    };

    // Determine require_signed_request_object:
    // - Explicit request value takes precedence
    // - FAPI 2.0 Message Signing requires signed request objects (JAR/RFC 9101)
    //   only when the client registers a request_object_signing_alg
    // - FAPI 2.0 Security Profile uses unsigned PAR (RFC 9126) without JAR
    let require_signed = request
        .require_signed_request_object
        .unwrap_or(fapi_profile != FapiProfile::None && req_obj_alg.is_some());

    // 13. Infer application type
    let app_type = determine_client_type(
        &validated.grant_types,
        jwks_auth.auth_method,
        &redirect_uris,
    );

    // Build the client name (fallback to software_id or "Unnamed Client")
    let client_name = request.client_name.as_deref().unwrap_or("Unnamed Client");

    // Build registration metadata JSON (cosmetic fields)
    let registration_metadata = request.registration_metadata();

    // 14. Generate registration access token
    let reg_token = generate_registration_token()?;
    let reg_token_hash = hash_token(&reg_token);

    // 15. Create the client
    let (client, client_id) = db::create_oauth_client(
        &state.store,
        &CreateOAuthClientParams {
            user_id: authenticated_user_id,
            name: client_name,
            description: None,
            application_type: app_type,
            redirect_uris: &redirect_uris,
            access_scope: if authenticated_user_id.is_some() {
                db::AccessScope::Personal
            } else {
                db::AccessScope::Public
            },
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: Some(jwks_auth.auth_method),
            jwks: jwks_auth.jwks_value.as_ref(),
            jwks_uri: jwks_auth.jwks_uri.as_deref(),
            fapi_profile: Some(fapi_profile),
            dpop_bound_access_tokens: Some(dpop_bound),
            grant_types: Some(&validated.grant_types),
            response_types: Some(&validated.response_types),
            software_id: request.software_id.as_deref(),
            software_version: request.software_version.as_deref(),
            registration_source: RegistrationSource::Dynamic,
            registration_access_token_hash: Some(&reg_token_hash),
            registration_metadata: Some(&registration_metadata),
            id_token_signed_response_alg: id_token_alg,
            tls_client_auth_subject_dn: request.tls_client_auth_subject_dn.as_deref(),
            tls_client_auth_san_dns: request.tls_client_auth_san_dns.as_deref(),
            tls_client_auth_san_uri: request.tls_client_auth_san_uri.as_deref(),
            tls_client_auth_san_ip: request.tls_client_auth_san_ip.as_deref(),
            tls_client_auth_san_email: request.tls_client_auth_san_email.as_deref(),
            tls_client_certificate_bound_access_tokens: request
                .tls_client_certificate_bound_access_tokens,
            authorization_signed_response_alg: jarm_alg,
            introspection_signed_response_alg: introspection_alg,
            request_object_signing_alg: req_obj_alg,
            require_signed_request_object: if require_signed { Some(true) } else { None },
            userinfo_signed_response_alg: userinfo_alg,
            request_uris: validated_request_uris.clone(),
            post_logout_redirect_uris: validated_post_logout_redirect_uris.clone(),
        },
    )
    .await
    .map_err(|e| {
        // The store rejects NUL bytes in index values (issue #883); for a
        // registration request the only client-supplied one is software_id.
        if let Some(invalid) = e.downcast_ref::<db::InvalidIndexValue>() {
            return ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!("{} must not contain a NUL (0x00) character", invalid.field),
            );
        }
        tracing::error!("Failed to create dynamically registered client: {e}");
        ServiceError::Internal("Failed to create client".to_string())
    })?;

    // 16. Generate client_secret for confidential clients
    let client_secret = if matches!(
        jwks_auth.auth_method,
        TokenEndpointAuthMethod::ClientSecretBasic | TokenEndpointAuthMethod::ClientSecretPost
    ) {
        let secret_bytes = generate_random_bytes(SECRET_LENGTH)
            .map_err(|_| ServiceError::Internal("Failed to generate client secret".to_string()))?;
        let secret = format!("vouch_{}", URL_SAFE_NO_PAD.encode(secret_bytes));
        let secret_hash = hash_token(&secret);

        db::create_oauth_client_secret(
            &state.store,
            &client.id,
            &secret_hash,
            Some("Dynamic registration"),
            None,
        )
        .await?;

        Some(secret)
    } else {
        None
    };

    // 17. Record audit event
    let base_url = &state.config().base_url;
    db::record_oauth_event(
        &state.audit,
        &state.store,
        &db::RecordOAuthEventParams {
            oauth_client_id: &client.id,
            event_type: OAuthEventType::ClientRegistered,
            user_id: authenticated_user_id,
            ip_address: None,
            user_agent: None,
            details: Some("RFC 7591 dynamic registration"),
        },
    )
    .await;

    // Derive client_id_issued_at from created_at
    let client_id_issued_at = client.created_at.as_second();

    tracing::info!(
        "Dynamic client registration: client_id={}, user={}, app_type={:?}",
        client_id,
        authenticated_user_id.unwrap_or("(open)"),
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
        token_endpoint_auth_method: jwks_auth.auth_method.as_str().to_string(),
        grant_types: validated.grant_types,
        response_types: validated.response_types,
        client_name: Some(client_name.to_string()),
        client_uri: request.client_uri,
        logo_uri: request.logo_uri,
        tos_uri: request.tos_uri,
        policy_uri: request.policy_uri,
        scope: request.scope,
        contacts: request.contacts,
        jwks: jwks_auth.jwks_value,
        jwks_uri: jwks_auth.jwks_uri,
        software_id: request.software_id,
        software_version: request.software_version,
        dpop_bound_access_tokens: if dpop_bound { Some(true) } else { None },
        id_token_signed_response_alg: id_token_alg.to_string(),
        authorization_signed_response_alg: jarm_alg.map(|a| a.to_string()),
        introspection_signed_response_alg: introspection_alg.map(|a| a.to_string()),
        request_object_signing_alg: req_obj_alg.map(|a| a.to_string()),
        require_signed_request_object: if require_signed { Some(true) } else { None },
        userinfo_signed_response_alg: userinfo_alg.map(|a| a.to_string()),
        request_uris: validated_request_uris,
        post_logout_redirect_uris: validated_post_logout_redirect_uris,
    })
}

// ============================================================================
// Registration Validation Helpers
// ============================================================================

/// Whether the requested grant types include `authorization_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationCodeGrant {
    Present,
    Absent,
}

/// Validated grant/response types and auth method from a registration request.
#[derive(Debug)]
struct ValidatedGrantTypes {
    grant_types: Vec<String>,
    response_types: Vec<String>,
    auth_method_str: String,
    auth_code_grant: AuthorizationCodeGrant,
}

/// Reject RS256 when the client is registering under any FAPI 2.0 profile.
///
/// FAPI 2.0 Security Profile §5.4 forbids RS256 for any JWT minted on behalf
/// of a FAPI client (id_token, JARM authorization response, userinfo, request
/// object). Returns `Ok(())` for non-FAPI clients or non-RS256 algorithms.
fn reject_rs256_for_fapi(
    alg: JwsAlgorithm,
    fapi_profile: FapiProfile,
    field: &'static str,
) -> Result<(), ServiceError> {
    if alg == JwsAlgorithm::Rs256 && fapi_profile != FapiProfile::None {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!("RS256 is not permitted for FAPI 2.0 clients on {field}. Use ES256"),
        ));
    }
    Ok(())
}

/// Whether the server has an RSA signing key configured (and can thus
/// offer RS256 for signed responses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RsaSigningKey {
    Available,
    Unavailable,
}

/// Validate `userinfo_signed_response_alg` — only RS256 and ES256 are accepted.
///
/// Returns the parsed algorithm, or `None` if the field is absent.
fn validate_userinfo_signed_response_alg(
    raw: Option<&str>,
    rsa_key: RsaSigningKey,
    fapi_profile: FapiProfile,
) -> Result<Option<JwsAlgorithm>, ServiceError> {
    let Some(s) = raw else { return Ok(None) };
    let parsed = s.parse::<JwsAlgorithm>().map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!("Unsupported userinfo_signed_response_alg: '{s}'. Supported: RS256, ES256"),
        )
    })?;
    reject_rs256_for_fapi(parsed, fapi_profile, "userinfo_signed_response_alg")?;
    match parsed {
        JwsAlgorithm::Rs256 if rsa_key == RsaSigningKey::Unavailable => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "RS256 is not available for userinfo_signed_response_alg \
             (no RSA signing key configured)",
        )),
        JwsAlgorithm::Rs256 | JwsAlgorithm::Es256 => Ok(Some(parsed)),
        _ => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!("Unsupported userinfo_signed_response_alg: '{s}'. Supported: RS256, ES256"),
        )),
    }
}

/// Validate `request_uris` — each must be HTTPS, max 10 entries.
///
/// Returns the validated list, or `None` if the field is absent.
fn validate_request_uris(uris: Option<&[String]>) -> Result<Option<Vec<String>>, ServiceError> {
    let Some(uris) = uris else { return Ok(None) };
    const MAX_REQUEST_URIS: usize = 10;
    if uris.len() > MAX_REQUEST_URIS {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!("Too many request_uris: maximum is {MAX_REQUEST_URIS}"),
        ));
    }
    for uri in uris {
        if !uri.starts_with("https://") {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!("request_uri '{uri}' must use HTTPS"),
            ));
        }
    }
    Ok(Some(uris.to_vec()))
}

/// Validate `post_logout_redirect_uris` for RFC 7591 registration.
///
/// Each URI must be a valid http or https URL without a fragment.
/// HTTP is only allowed for loopback addresses. Max 10 entries.
///
/// Returns the validated list, or `None` if the field is absent or empty.
fn validate_post_logout_redirect_uris_registration(
    uris: Option<&[String]>,
) -> Result<Option<Vec<String>>, ServiceError> {
    let Some(uris) = uris else { return Ok(None) };
    if uris.is_empty() {
        return Ok(None);
    }
    if uris.len() > db::MAX_POST_LOGOUT_REDIRECT_URIS {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!(
                "Too many post_logout_redirect_uris: maximum is {}",
                db::MAX_POST_LOGOUT_REDIRECT_URIS
            ),
        ));
    }
    let invalid: Vec<&str> = uris
        .iter()
        .filter(|uri| !db::is_valid_post_logout_redirect_uri_str(uri))
        .map(String::as_str)
        .collect();
    if !invalid.is_empty() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!(
                "Invalid post_logout_redirect_uri(s): {}. Each URI must be https:// \
                 or a loopback http:// URL without a fragment.",
                invalid.join(", ")
            ),
        ));
    }
    Ok(Some(uris.to_vec()))
}

/// Reject implicit grant, apply defaults, validate allowed types, check consistency.
fn validate_grant_and_response_types(
    request: &mut RegistrationRequest,
) -> Result<ValidatedGrantTypes, ServiceError> {
    // Reject implicit grant (deprecated by RFC 9700)
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

    for gt in &grant_types {
        if !ALLOWED_GRANT_TYPES.contains(&gt.as_str()) {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!("Unsupported grant type: '{gt}'"),
            ));
        }
    }
    for rt in &response_types {
        if !ALLOWED_RESPONSE_TYPES.contains(&rt.as_str()) {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!("Unsupported response type: '{rt}'"),
            ));
        }
    }

    let auth_code_grant = if grant_types.iter().any(|g| g == "authorization_code") {
        AuthorizationCodeGrant::Present
    } else {
        AuthorizationCodeGrant::Absent
    };
    let has_code_response = response_types.iter().any(|r| r == "code");
    if auth_code_grant == AuthorizationCodeGrant::Present && !has_code_response {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "grant_types includes 'authorization_code' but response_types is missing 'code'",
        ));
    }

    Ok(ValidatedGrantTypes {
        grant_types,
        response_types,
        auth_method_str,
        auth_code_grant,
    })
}

/// Validate redirect URIs: required for auth_code grant, cardinality, format.
fn validate_redirect_uris(
    request: &mut RegistrationRequest,
    auth_code_grant: AuthorizationCodeGrant,
) -> Result<Vec<String>, ServiceError> {
    let redirect_uris = request.redirect_uris.take().unwrap_or_default();
    if auth_code_grant == AuthorizationCodeGrant::Present && redirect_uris.is_empty() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "redirect_uris is required when grant_types includes 'authorization_code'",
        ));
    }
    if redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!("Too many redirect_uris (max {MAX_REDIRECT_URIS})"),
        ));
    }
    for uri in &redirect_uris {
        validate_registration_redirect_uri(uri)?;
    }
    Ok(redirect_uris)
}

/// Validated JWKS and auth method from a registration request.
#[derive(Debug)]
struct ValidatedJwksAuth {
    jwks_value: Option<serde_json::Value>,
    jwks_uri: Option<String>,
    auth_method: TokenEndpointAuthMethod,
}

/// Validate JWKS field mutual exclusivity, structure, and HTTPS URI constraint.
///
/// Shared by both initial registration and the update path. Does not validate the
/// relationship to `token_endpoint_auth_method` — that is handled by
/// `validate_jwks_and_auth_method` for the initial registration path.
fn validate_jwks_fields(
    jwks: Option<&serde_json::Value>,
    jwks_uri: Option<&str>,
) -> Result<(), ServiceError> {
    if jwks.is_some() && jwks_uri.is_some() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "jwks and jwks_uri are mutually exclusive",
        ));
    }
    if let Some(jwks) = jwks
        && !jwks
            .get("keys")
            .is_some_and(|k| k.is_array() && !k.as_array().is_some_and(|a| a.is_empty()))
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "jwks must be a JSON object with a non-empty \"keys\" array",
        ));
    }
    if let Some(uri) = jwks_uri {
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
    Ok(())
}

/// Validate JWKS mutual exclusivity, structure, and auth method.
fn validate_jwks_and_auth_method(
    request: &mut RegistrationRequest,
    auth_method_str: &str,
) -> Result<ValidatedJwksAuth, ServiceError> {
    let jwks_value = request.jwks.take();
    let jwks_uri = request.jwks_uri.take();

    validate_jwks_fields(jwks_value.as_ref(), jwks_uri.as_deref())?;

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

    // RFC 8705 Section 2.1.1: tls_client_auth requires at least one identity field
    if auth_method == TokenEndpointAuthMethod::TlsClientAuth {
        let has_identity = request.tls_client_auth_subject_dn.is_some()
            || request.tls_client_auth_san_dns.is_some()
            || request.tls_client_auth_san_email.is_some()
            || request.tls_client_auth_san_uri.is_some()
            || request.tls_client_auth_san_ip.is_some();
        if !has_identity {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                "tls_client_auth requires at least one identity field \
                 (tls_client_auth_subject_dn, tls_client_auth_san_dns, \
                 tls_client_auth_san_email, tls_client_auth_san_uri, \
                 or tls_client_auth_san_ip)",
            ));
        }
    }

    Ok(ValidatedJwksAuth {
        jwks_value,
        jwks_uri,
        auth_method,
    })
}

/// Validate HTTPS URI fields and contacts.
fn validate_contacts_and_uris(request: &RegistrationRequest) -> Result<(), ServiceError> {
    validate_https_uri("client_uri", request.client_uri.as_deref())?;
    validate_https_uri("logo_uri", request.logo_uri.as_deref())?;
    validate_https_uri("tos_uri", request.tos_uri.as_deref())?;
    validate_https_uri("policy_uri", request.policy_uri.as_deref())?;
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
    Ok(())
}

/// Infer OAuth client application type from grants, auth method, and URIs.
fn determine_client_type(
    grant_types: &[String],
    auth_method: TokenEndpointAuthMethod,
    redirect_uris: &[String],
) -> OAuthClientType {
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

    if has_client_credentials_only {
        OAuthClientType::Service
    } else if is_public && has_loopback {
        OAuthClientType::Native
    } else if is_public {
        OAuthClientType::Spa
    } else {
        OAuthClientType::Web
    }
}

// ============================================================================
// Client Configuration Read (RFC 7592 Section 2.1)
// ============================================================================

/// Read the configuration of a dynamically registered client (RFC 7592).
///
/// Authenticates the caller using the registration access token, then returns
/// the current client metadata. The response omits the
/// `registration_access_token` (RFC 7592 Section 3).
///
/// # Errors
///
/// - A 401 `invalid_token` API error if the Bearer token is missing or invalid.
/// - `ServiceError::NotFound` if the `client_id` does not exist.
pub async fn read_client_configuration(
    state: &Arc<AppState>,
    client_id: &str,
    registration_access_token: &str,
) -> Result<RegistrationResponse, ServiceError> {
    let client =
        lookup_and_verify_registration_token(state, client_id, registration_access_token).await?;

    let base_url = &state.config().base_url;
    Ok(build_client_response(client, base_url))
}

/// Delete a dynamically registered client (RFC 7592 Section 2.3).
///
/// Authenticates the caller using the registration access token, deletes
/// the client (cascade-deletes secrets), and records an audit event.
///
/// # Errors
///
/// - A 401 `invalid_token` API error if the Bearer token is missing or invalid.
/// - `ServiceError::NotFound` if the `client_id` does not exist.
pub async fn delete_client_configuration(
    state: &Arc<AppState>,
    client_id: &str,
    registration_access_token: &str,
) -> Result<(), ServiceError> {
    let client =
        lookup_and_verify_registration_token(state, client_id, registration_access_token).await?;

    db::delete_oauth_client(&state.store, &client.id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete dynamically registered client {client_id}: {e}");
            ServiceError::Internal("Failed to delete client".to_string())
        })?;

    db::record_oauth_event(
        &state.audit,
        &state.store,
        &db::RecordOAuthEventParams {
            oauth_client_id: &client.id,
            event_type: OAuthEventType::ClientDeleted,
            user_id: client.user_id.as_deref(),
            ip_address: None,
            user_agent: None,
            details: Some("RFC 7592 client configuration DELETE"),
        },
    )
    .await;

    tracing::info!(
        "Dynamic client deleted: client_id={}, user={}",
        client_id,
        client.user_id.as_deref().unwrap_or("(none)"),
    );

    Ok(())
}

/// Update a dynamically registered client (RFC 7592 Section 2.2).
///
/// Authenticates the caller using the registration access token, updates
/// the client's mutable registration fields, rotates the token, and
/// returns the updated metadata.
///
/// # Errors
///
/// - A 401 `invalid_token` API error if the Bearer token is invalid.
/// - `ServiceError::NotFound` if the `client_id` does not exist.
/// - `ServiceError::OAuth` if the request body contains invalid metadata.
pub async fn update_client_configuration(
    state: &Arc<AppState>,
    client_id: &str,
    registration_access_token: &str,
    request: RegistrationRequest,
) -> Result<RegistrationResponse, ServiceError> {
    let client =
        lookup_and_verify_registration_token(state, client_id, registration_access_token).await?;

    // Validate grant/response types (take() empties the request fields)
    let mut mutable_request = request;
    let validated = validate_grant_and_response_types(&mut mutable_request)?;

    // Validate redirect URIs (same cardinality + format rules as initial registration)
    let redirect_uris = validate_redirect_uris(&mut mutable_request, validated.auth_code_grant)?;

    // Build updated registration metadata (cosmetic fields)
    let registration_metadata = mutable_request.registration_metadata();

    // Validate JWKS and jwks_uri field format: mutually exclusive, valid
    // structure, HTTPS URI.
    validate_jwks_fields(
        mutable_request.jwks.as_ref(),
        mutable_request.jwks_uri.as_deref(),
    )?;

    // PUT is a full replacement, so re-check the auth-method/JWKS
    // relationship enforced at initial registration against the client's
    // (immutable) registered auth method. Without this, a private_key_jwt
    // client could clear its JWKS and end up unable to authenticate.
    if client.token_endpoint_auth_method == TokenEndpointAuthMethod::PrivateKeyJwt
        && mutable_request.jwks.is_none()
        && mutable_request.jwks_uri.is_none()
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "private_key_jwt requires jwks or jwks_uri",
        ));
    }

    // Validate userinfo_signed_response_alg (same rules as initial registration).
    // The client's FAPI profile is immutable post-registration (RFC 7592), so we
    // re-apply the original profile's algorithm restrictions to any updates.
    let rsa_key = if state.oidc_rsa_key.is_some() {
        RsaSigningKey::Available
    } else {
        RsaSigningKey::Unavailable
    };
    let userinfo_alg = validate_userinfo_signed_response_alg(
        mutable_request.userinfo_signed_response_alg.as_deref(),
        rsa_key,
        client.fapi_profile,
    )?;

    // Validate request_uris (same rules as initial registration).
    let validated_request_uris = validate_request_uris(mutable_request.request_uris.as_deref())?;

    // Validate post_logout_redirect_uris (RP-Initiated Logout 1.0 Section 2).
    let validated_post_logout_redirect_uris = validate_post_logout_redirect_uris_registration(
        mutable_request.post_logout_redirect_uris.as_deref(),
    )?;

    // Validate contacts and URI fields with the same rules as initial
    // registration (`register_client`), so an RFC 7592 PUT cannot smuggle an
    // invalid logo_uri or a non-@ contact past registration-time validation.
    validate_contacts_and_uris(&mutable_request)?;

    // Rotate the registration access token per RFC 7592 Section 2.2
    let new_reg_token = generate_registration_token()?;
    let new_reg_token_hash = hash_token(&new_reg_token);

    // token_endpoint_auth_method is intentionally NOT updated — it is immutable
    // per RFC 7592 (clients cannot change their auth method after registration).
    let updated = db::update_oauth_client_registration(
        &state.store,
        &client.id,
        &UpdateClientRegistrationParams {
            redirect_uris: &redirect_uris,
            grant_types: Some(&validated.grant_types),
            response_types: Some(&validated.response_types),
            jwks: mutable_request.jwks.as_ref(),
            jwks_uri: mutable_request.jwks_uri.as_deref(),
            registration_access_token_hash: &new_reg_token_hash,
            registration_metadata: Some(&registration_metadata),
            userinfo_signed_response_alg: userinfo_alg,
            request_uris: validated_request_uris.as_deref(),
            post_logout_redirect_uris: validated_post_logout_redirect_uris.clone(),
        },
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to update client {client_id}: {e}");
        ServiceError::Internal("Failed to update client".to_string())
    })?;

    db::record_oauth_event(
        &state.audit,
        &state.store,
        &db::RecordOAuthEventParams {
            oauth_client_id: &client.id,
            event_type: OAuthEventType::ClientUpdated,
            user_id: client.user_id.as_deref(),
            ip_address: None,
            user_agent: None,
            details: Some("RFC 7592 client configuration PUT"),
        },
    )
    .await;

    tracing::info!(
        "Dynamic client updated: client_id={}, user={}",
        client_id,
        client.user_id.as_deref().unwrap_or("(none)"),
    );

    let base_url = &state.config().base_url;
    let mut response = build_client_response(updated, base_url);
    response.registration_access_token = Some(new_reg_token);

    Ok(response)
}

/// Look up a client by `client_id` and verify the registration access token.
async fn lookup_and_verify_registration_token(
    state: &Arc<AppState>,
    client_id: &str,
    token: &str,
) -> Result<OAuthClient, ServiceError> {
    let client = db::get_oauth_client_by_client_id(&state.store, client_id)
        .await
        .map_err(|e| {
            tracing::error!("DB error looking up client {client_id}: {e}");
            ServiceError::Internal("Database error".to_string())
        })?
        .ok_or(ServiceError::NotFound("Client"))?;

    if !client.active {
        return Err(ServiceError::NotFound("Client"));
    }

    let stored_hash = client
        .registration_access_token_hash
        .as_deref()
        .ok_or_else(|| {
            // RFC 7592 §2 / RFC 6750 §3.1: registration endpoints are OAuth
            // protected resources, so bearer-token failures are
            // `invalid_token`, not the client-authentication error
            // `invalid_client`.
            ServiceError::api(
                StatusCode::UNAUTHORIZED,
                OAuthErrorCode::InvalidToken.as_str(),
                "Client has no registration access token",
            )
        })?;

    let provided_hash = hash_token(token);
    let is_match: bool = provided_hash
        .as_bytes()
        .ct_eq(stored_hash.as_bytes())
        .into();

    if !is_match {
        return Err(ServiceError::api(
            StatusCode::UNAUTHORIZED,
            OAuthErrorCode::InvalidToken.as_str(),
            "Invalid registration access token",
        ));
    }

    Ok(client)
}

/// Build a `RegistrationResponse` from a stored `OAuthClient`.
///
/// Per RFC 7592 Section 3, the response omits the `registration_access_token`
/// but includes the `registration_client_uri`.
fn build_client_response(client: OAuthClient, base_url: &str) -> RegistrationResponse {
    let grant_types = client.grant_types.unwrap_or_default();
    let response_types = client.response_types.unwrap_or_default();
    let metadata = client
        .registration_metadata
        .unwrap_or(serde_json::Value::Null);

    let client_id_issued_at = client.created_at.as_second();
    let registration_client_uri = format!("{base_url}/oauth/register/{}", client.client_id);
    let redirect_uris = if client.redirect_uris.is_empty() {
        None
    } else {
        Some(client.redirect_uris)
    };

    RegistrationResponse {
        client_id: client.client_id,
        client_secret: None,
        client_secret_expires_at: None,
        client_id_issued_at: Some(client_id_issued_at),
        registration_access_token: None,
        registration_client_uri: Some(registration_client_uri),
        redirect_uris,
        token_endpoint_auth_method: client.token_endpoint_auth_method.as_str().to_string(),
        grant_types,
        response_types,
        client_name: Some(client.name),
        client_uri: metadata_string(&metadata, "client_uri"),
        logo_uri: metadata_string(&metadata, "logo_uri"),
        tos_uri: metadata_string(&metadata, "tos_uri"),
        policy_uri: metadata_string(&metadata, "policy_uri"),
        scope: metadata_string(&metadata, "scope"),
        contacts: metadata_string_array(&metadata, "contacts"),
        jwks: client.jwks,
        jwks_uri: client.jwks_uri,
        software_id: client.software_id,
        software_version: client.software_version,
        dpop_bound_access_tokens: if client.dpop_bound_access_tokens {
            Some(true)
        } else {
            None
        },
        id_token_signed_response_alg: client.id_token_signed_response_alg.to_string(),
        authorization_signed_response_alg: client
            .authorization_signed_response_alg
            .map(|a| a.to_string()),
        introspection_signed_response_alg: client
            .introspection_signed_response_alg
            .map(|a| a.to_string()),
        request_object_signing_alg: client.request_object_signing_alg.map(|a| a.to_string()),
        require_signed_request_object: client.require_signed_request_object,
        userinfo_signed_response_alg: client.userinfo_signed_response_alg.map(|a| a.to_string()),
        request_uris: client.request_uris,
        post_logout_redirect_uris: client.post_logout_redirect_uris,
    }
}

/// Extract a string field from the registration metadata JSON object.
fn metadata_string(metadata: &serde_json::Value, key: &str) -> Option<String> {
    metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(String::from)
}

/// Extract a string array field from the registration metadata JSON object.
fn metadata_string_array(metadata: &serde_json::Value, key: &str) -> Option<Vec<String>> {
    metadata.get(key).and_then(|v| {
        v.as_array().map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str().map(String::from))
                .collect()
        })
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

/// Generate a secure random registration access token (RFC 7592 prep).
fn generate_registration_token() -> Result<String, ServiceError> {
    let bytes = generate_random_bytes(REGISTRATION_TOKEN_LENGTH).map_err(|_| {
        ServiceError::Internal("Failed to generate registration access token".to_string())
    })?;
    Ok(format!("vouch_reg_{}", URL_SAFE_NO_PAD.encode(bytes)))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
