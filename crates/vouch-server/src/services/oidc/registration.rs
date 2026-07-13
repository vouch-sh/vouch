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
    if let Err(e) = db::record_oauth_event(
        &state.audit,
        &client.id,
        OAuthEventType::ClientRegistered,
        authenticated_user_id,
        None,
        None,
        Some("RFC 7591 dynamic registration"),
    )
    .await
    {
        tracing::warn!("Failed to record client registration event: {e}");
    }

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
/// - `ServiceError::Unauthorized` if the Bearer token is missing or invalid.
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
/// - `ServiceError::Unauthorized` if the Bearer token is missing or invalid.
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

    if let Err(e) = db::record_oauth_event(
        &state.audit,
        &client.id,
        OAuthEventType::ClientDeleted,
        client.user_id.as_deref(),
        None,
        None,
        Some("RFC 7592 client configuration DELETE"),
    )
    .await
    {
        tracing::warn!("Failed to record client deletion event: {e}");
    }

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
/// - `ServiceError::Unauthorized` if the Bearer token is invalid.
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

    // Validate JWKS and jwks_uri (same rules as initial registration):
    // mutually exclusive, valid structure, HTTPS URI.
    validate_jwks_fields(
        mutable_request.jwks.as_ref(),
        mutable_request.jwks_uri.as_deref(),
    )?;

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

    if let Err(e) = db::record_oauth_event(
        &state.audit,
        &client.id,
        OAuthEventType::ClientUpdated,
        client.user_id.as_deref(),
        None,
        None,
        Some("RFC 7592 client configuration PUT"),
    )
    .await
    {
        tracing::warn!("Failed to record client update event: {e}");
    }

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

    let stored_hash =
        client
            .registration_access_token_hash
            .as_deref()
            .ok_or(ServiceError::Unauthorized(
                "Client has no registration access token",
            ))?;

    let provided_hash = hash_token(token);
    let is_match: bool = provided_hash
        .as_bytes()
        .ct_eq(stored_hash.as_bytes())
        .into();

    if !is_match {
        return Err(ServiceError::Unauthorized(
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
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    fn assert_oauth_error<T: std::fmt::Debug>(
        result: Result<T, ServiceError>,
        expected: OAuthErrorCode,
    ) {
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == expected),
            "Expected {expected:?}",
        );
    }

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
        assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
    }

    #[test]
    fn test_rejects_redirect_uri_with_fragment() {
        let result = validate_registration_redirect_uri("https://example.com/callback#anchor");
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
    }

    #[test]
    fn test_rejects_invalid_redirect_uri() {
        let result = validate_registration_redirect_uri("not a valid uri !!!");
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
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
        let err = validate_registration_redirect_uri("https://example.com/cb#").unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidRedirectUri)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description.contains("fragment"))
        );
    }

    /// HTTP to a non-loopback private IP (e.g., 192.168.x.x) must be rejected.
    #[test]
    fn test_rejects_http_private_ip_redirect_uri() {
        let result = validate_registration_redirect_uri("http://192.168.1.1/callback");
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
    }

    /// An empty string is not a valid redirect URI.
    #[test]
    fn test_rejects_empty_redirect_uri() {
        let result = validate_registration_redirect_uri("");
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
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
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
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
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    // =========================================================================
    // HTTPS URI Validation — Additional Cases
    // =========================================================================

    /// The error message must include the field name for debuggability.
    #[test]
    fn test_https_uri_error_includes_field_name() {
        let err = validate_https_uri("logo_uri", Some("http://example.com/logo.png")).unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description.contains("logo_uri"))
        );
    }

    /// Custom (non-http/https) schemes must be rejected for URI fields.
    #[test]
    fn test_https_uri_rejects_custom_scheme() {
        let result = validate_https_uri("tos_uri", Some("ftp://example.com/tos"));
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
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
            dpop_bound_access_tokens: None,
            id_token_signed_response_alg: None,
            ..Default::default()
        };

        let metadata = request.registration_metadata();

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
            dpop_bound_access_tokens: None,
            id_token_signed_response_alg: None,
            ..Default::default()
        };

        let metadata = request.registration_metadata();

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
            dpop_bound_access_tokens: None,
            id_token_signed_response_alg: None,
            ..Default::default()
        };

        let metadata = request.registration_metadata();
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
            dpop_bound_access_tokens: None,
            id_token_signed_response_alg: None,
            ..Default::default()
        };

        let metadata = request.registration_metadata();
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
            dpop_bound_access_tokens: None,
            id_token_signed_response_alg: None,
            ..Default::default()
        };

        let metadata = request.registration_metadata();
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
            "grant_types": ["authorization_code", "client_credentials"],
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
                "client_credentials".to_string(),
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
            id_token_signed_response_alg: "ES256".to_string(),
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Required fields must be present
        assert!(value.get("client_id").is_some());
        assert!(value.get("token_endpoint_auth_method").is_some());
        assert!(value.get("grant_types").is_some());
        assert!(value.get("response_types").is_some());
        assert_eq!(value["id_token_signed_response_alg"], "ES256");

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
            id_token_signed_response_alg: "ES256".to_string(),
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
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
            "refresh_token must be accepted in registration (though never issued)"
        );
    }

    /// Every grant the token endpoint dispatches must also be registrable.
    /// `ALLOWED_GRANT_TYPES` is a deliberate superset (it adds `refresh_token`),
    /// so this guards one direction: no dispatchable grant is unregistrable.
    #[test]
    fn every_dispatched_grant_is_registrable() {
        for grant in crate::services::oidc::grant_type::OAuthGrantType::supported_wire_values() {
            assert!(
                ALLOWED_GRANT_TYPES.contains(&grant),
                "token-endpoint grant {grant} must also be an allowed registration grant"
            );
        }
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

    // =========================================================================
    // validate_grant_and_response_types
    // =========================================================================

    fn make_request_with_grant_response(
        grant_types: Option<Vec<&str>>,
        response_types: Option<Vec<&str>>,
    ) -> RegistrationRequest {
        RegistrationRequest {
            redirect_uris: None,
            token_endpoint_auth_method: None,
            grant_types: grant_types.map(|v| v.iter().map(|s| s.to_string()).collect()),
            response_types: response_types.map(|v| v.iter().map(|s| s.to_string()).collect()),
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
            id_token_signed_response_alg: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_validate_grant_and_response_types_defaults() {
        let mut req = make_request_with_grant_response(None, None);
        let result = validate_grant_and_response_types(&mut req);
        let validated = result.expect("Defaults must be accepted");
        assert!(
            validated
                .grant_types
                .contains(&"authorization_code".to_string())
        );
        assert!(validated.response_types.contains(&"code".to_string()));
        assert_eq!(validated.auth_method_str, "client_secret_basic");
        assert_eq!(validated.auth_code_grant, AuthorizationCodeGrant::Present);
    }

    #[test]
    fn test_validate_grant_and_response_types_implicit_grant_rejected() {
        let mut req = make_request_with_grant_response(Some(vec!["implicit"]), None);
        let result = validate_grant_and_response_types(&mut req);
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_grant_and_response_types_implicit_response_token_rejected() {
        let mut req = make_request_with_grant_response(None, Some(vec!["token"]));
        let result = validate_grant_and_response_types(&mut req);
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_grant_and_response_types_implicit_response_id_token_rejected() {
        let mut req = make_request_with_grant_response(None, Some(vec!["id_token"]));
        let result = validate_grant_and_response_types(&mut req);
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_grant_and_response_types_unknown_grant_rejected() {
        let mut req = make_request_with_grant_response(Some(vec!["magic_grant"]), None);
        let err = validate_grant_and_response_types(&mut req).unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description.contains("magic_grant"))
        );
    }

    #[test]
    fn test_validate_grant_and_response_types_unknown_response_type_rejected() {
        let mut req = make_request_with_grant_response(None, Some(vec!["magic_response"]));
        let err = validate_grant_and_response_types(&mut req).unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description.contains("magic_response"))
        );
    }

    #[test]
    fn test_validate_grant_and_response_types_auth_code_without_code_response() {
        // authorization_code grant requires "code" response type.
        let mut req =
            make_request_with_grant_response(Some(vec!["authorization_code"]), Some(vec!["code"]));
        // Deliberately overwrite response_types to omit "code" after construction
        req.response_types = Some(vec!["token".to_string()]); // will fail earlier for "token"
        // Use a minimal non-implicit, non-code type — but those are all rejected.
        // Instead, craft a request where the authorization_code grant is present but response_types != ["code"].
        // The only allowed response type is "code", so we must test via a two-step approach:
        // Force grant_types to include authorization_code while response_types is empty.
        let mut req2 = RegistrationRequest {
            redirect_uris: None,
            token_endpoint_auth_method: None,
            grant_types: Some(vec!["authorization_code".to_string()]),
            response_types: Some(vec![]), // empty but won't hit implicit check
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
            id_token_signed_response_alg: None,
            ..Default::default()
        };
        let result = validate_grant_and_response_types(&mut req2);
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_grant_and_response_types_client_credentials_valid() {
        let mut req =
            make_request_with_grant_response(Some(vec!["client_credentials"]), Some(vec!["code"]));
        let result = validate_grant_and_response_types(&mut req);
        let validated = result.expect("client_credentials + code must be valid");
        assert_eq!(validated.auth_code_grant, AuthorizationCodeGrant::Absent);
        assert!(
            validated
                .grant_types
                .contains(&"client_credentials".to_string())
        );
    }

    #[test]
    fn test_validate_grant_and_response_types_auth_method_extracted() {
        let mut req = make_request_with_grant_response(None, None);
        req.token_endpoint_auth_method = Some("private_key_jwt".to_string());
        let validated = validate_grant_and_response_types(&mut req).unwrap();
        assert_eq!(validated.auth_method_str, "private_key_jwt");
    }

    // =========================================================================
    // validate_redirect_uris
    // =========================================================================

    fn make_request_with_redirect_uris(uris: Option<Vec<&str>>) -> RegistrationRequest {
        RegistrationRequest {
            redirect_uris: uris.map(|v| v.iter().map(|s| s.to_string()).collect()),
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
            dpop_bound_access_tokens: None,
            id_token_signed_response_alg: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_validate_redirect_uris_required_for_auth_code_empty() {
        let mut req = make_request_with_redirect_uris(None);
        let result = validate_redirect_uris(&mut req, AuthorizationCodeGrant::Present);
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_redirect_uris_not_required_without_auth_code() {
        let mut req = make_request_with_redirect_uris(None);
        let result = validate_redirect_uris(&mut req, AuthorizationCodeGrant::Absent);
        let uris =
            result.expect("Empty redirect_uris allowed without the authorization_code grant");
        assert!(uris.is_empty());
    }

    #[test]
    fn test_validate_redirect_uris_too_many() {
        let many: Vec<&str> = (0..=MAX_REDIRECT_URIS)
            .map(|_| "https://example.com/callback")
            .collect();
        let mut req = make_request_with_redirect_uris(Some(many));
        let result = validate_redirect_uris(&mut req, AuthorizationCodeGrant::Absent);
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_redirect_uris_valid_uris_pass_through() {
        let mut req = make_request_with_redirect_uris(Some(vec![
            "https://example.com/callback",
            "http://localhost:8080/callback",
        ]));
        let result = validate_redirect_uris(&mut req, AuthorizationCodeGrant::Present);
        let uris = result.expect("Valid URIs must pass");
        assert_eq!(uris.len(), 2);
    }

    #[test]
    fn test_validate_redirect_uris_invalid_uri_rejected() {
        let mut req = make_request_with_redirect_uris(Some(vec!["not a uri !!"]));
        let result = validate_redirect_uris(&mut req, AuthorizationCodeGrant::Absent);
        assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
    }

    // =========================================================================
    // validate_jwks_and_auth_method
    // =========================================================================

    fn make_request_with_jwks(
        jwks: Option<serde_json::Value>,
        jwks_uri: Option<&str>,
    ) -> RegistrationRequest {
        RegistrationRequest {
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
            jwks,
            jwks_uri: jwks_uri.map(String::from),
            software_id: None,
            software_version: None,
            dpop_bound_access_tokens: None,
            id_token_signed_response_alg: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_validate_jwks_and_auth_method_mutual_exclusivity() {
        let jwks = serde_json::json!({"keys": [{"kty": "EC"}]});
        let mut req = make_request_with_jwks(Some(jwks), Some("https://example.com/jwks"));
        let err = validate_jwks_and_auth_method(&mut req, "client_secret_basic").unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description.contains("mutually exclusive"))
        );
    }

    #[test]
    fn test_validate_jwks_and_auth_method_empty_keys_rejected() {
        let jwks = serde_json::json!({"keys": []});
        let mut req = make_request_with_jwks(Some(jwks), None);
        let result = validate_jwks_and_auth_method(&mut req, "client_secret_basic");
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_jwks_and_auth_method_jwks_uri_not_https() {
        let mut req = make_request_with_jwks(None, Some("http://example.com/jwks"));
        let err = validate_jwks_and_auth_method(&mut req, "client_secret_basic").unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description.contains("https"))
        );
    }

    #[test]
    fn test_validate_jwks_and_auth_method_private_key_jwt_without_jwks() {
        let mut req = make_request_with_jwks(None, None);
        let result = validate_jwks_and_auth_method(&mut req, "private_key_jwt");
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_jwks_and_auth_method_private_key_jwt_with_jwks_uri_valid() {
        let mut req = make_request_with_jwks(None, Some("https://example.com/jwks.json"));
        let result = validate_jwks_and_auth_method(&mut req, "private_key_jwt");
        let validated = result.expect("private_key_jwt + jwks_uri must succeed");
        assert_eq!(
            validated.auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt
        );
        assert_eq!(
            validated.jwks_uri,
            Some("https://example.com/jwks.json".to_string())
        );
    }

    #[test]
    fn test_validate_jwks_and_auth_method_private_key_jwt_with_inline_jwks_valid() {
        let jwks = serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256"}]});
        let mut req = make_request_with_jwks(Some(jwks.clone()), None);
        let result = validate_jwks_and_auth_method(&mut req, "private_key_jwt");
        let validated = result.expect("private_key_jwt + inline jwks must succeed");
        assert_eq!(
            validated.auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt
        );
        assert!(validated.jwks_value.is_some());
    }

    #[test]
    fn test_validate_jwks_and_auth_method_none_auth_method() {
        let mut req = make_request_with_jwks(None, None);
        let result = validate_jwks_and_auth_method(&mut req, "none");
        let validated = result.expect("none auth method must be accepted");
        assert_eq!(validated.auth_method, TokenEndpointAuthMethod::None);
    }

    #[test]
    fn test_validate_jwks_and_auth_method_unknown_auth_method_rejected() {
        let mut req = make_request_with_jwks(None, None);
        let result = validate_jwks_and_auth_method(&mut req, "unknown_method");
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    // =========================================================================
    // validate_jwks_and_auth_method — tls_client_auth (RFC 8705 Section 2.1.1)
    // =========================================================================

    /// tls_client_auth with a subject_dn identity field is accepted.
    #[test]
    fn test_validate_tls_client_auth_accepted() {
        let mut req = RegistrationRequest {
            tls_client_auth_subject_dn: Some("CN=test-client".to_string()),
            ..Default::default()
        };
        let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
        let validated = result.expect("tls_client_auth + subject_dn must succeed");
        assert_eq!(
            validated.auth_method,
            TokenEndpointAuthMethod::TlsClientAuth
        );
    }

    /// tls_client_auth without any identity field must be rejected with invalid_client_metadata.
    #[test]
    fn test_validate_tls_client_auth_requires_identity_field() {
        let mut req = RegistrationRequest {
            // No tls_client_auth_* identity fields set
            ..Default::default()
        };
        let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    /// tls_client_auth with san_dns identity field is accepted.
    #[test]
    fn test_validate_tls_client_auth_with_san_dns_accepted() {
        let mut req = RegistrationRequest {
            tls_client_auth_san_dns: Some("client.example.com".to_string()),
            ..Default::default()
        };
        let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
        assert!(
            result.is_ok(),
            "tls_client_auth + san_dns must succeed, got: {result:?}"
        );
    }

    /// tls_client_auth with san_email identity field is accepted (RFC 8705 Section 2.1.1).
    #[test]
    fn test_validate_tls_client_auth_with_san_email() {
        let mut req = RegistrationRequest {
            tls_client_auth_san_email: Some("client@example.com".to_string()),
            ..Default::default()
        };
        let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
        let validated = result.expect("tls_client_auth + san_email must succeed");
        assert_eq!(
            validated.auth_method,
            TokenEndpointAuthMethod::TlsClientAuth
        );
    }

    /// tls_client_auth with san_uri identity field is accepted (RFC 8705 Section 2.1.1).
    #[test]
    fn test_validate_tls_client_auth_with_san_uri() {
        let mut req = RegistrationRequest {
            tls_client_auth_san_uri: Some("https://client.example.com/".to_string()),
            ..Default::default()
        };
        let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
        let validated = result.expect("tls_client_auth + san_uri must succeed");
        assert_eq!(
            validated.auth_method,
            TokenEndpointAuthMethod::TlsClientAuth
        );
    }

    /// tls_client_auth with san_ip identity field is accepted (RFC 8705 Section 2.1.1).
    #[test]
    fn test_validate_tls_client_auth_with_san_ip() {
        let mut req = RegistrationRequest {
            tls_client_auth_san_ip: Some("192.0.2.1".to_string()),
            ..Default::default()
        };
        let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
        let validated = result.expect("tls_client_auth + san_ip must succeed");
        assert_eq!(
            validated.auth_method,
            TokenEndpointAuthMethod::TlsClientAuth
        );
    }

    /// self_signed_tls_client_auth does not require identity fields — accepted without them.
    #[test]
    fn test_validate_self_signed_tls_client_auth_accepted_without_identity() {
        let mut req = make_request_with_jwks(None, None);
        let result = validate_jwks_and_auth_method(&mut req, "self_signed_tls_client_auth");
        let validated = result.expect("self_signed_tls_client_auth must succeed without identity");
        assert_eq!(
            validated.auth_method,
            TokenEndpointAuthMethod::SelfSignedTlsClientAuth
        );
    }

    // =========================================================================
    // validate_contacts_and_uris
    // =========================================================================

    fn make_request_with_uris(
        client_uri: Option<&str>,
        logo_uri: Option<&str>,
        tos_uri: Option<&str>,
        policy_uri: Option<&str>,
        contacts: Option<Vec<&str>>,
    ) -> RegistrationRequest {
        RegistrationRequest {
            redirect_uris: None,
            token_endpoint_auth_method: None,
            grant_types: None,
            response_types: None,
            client_name: None,
            client_uri: client_uri.map(String::from),
            logo_uri: logo_uri.map(String::from),
            tos_uri: tos_uri.map(String::from),
            policy_uri: policy_uri.map(String::from),
            scope: None,
            contacts: contacts.map(|v| v.iter().map(|s| s.to_string()).collect()),
            jwks: None,
            jwks_uri: None,
            software_id: None,
            software_version: None,
            dpop_bound_access_tokens: None,
            id_token_signed_response_alg: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_validate_contacts_and_uris_all_none_valid() {
        let req = make_request_with_uris(None, None, None, None, None);
        let result = validate_contacts_and_uris(&req);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_contacts_and_uris_all_https_valid() {
        let req = make_request_with_uris(
            Some("https://example.com"),
            Some("https://example.com/logo.png"),
            Some("https://example.com/tos"),
            Some("https://example.com/privacy"),
            Some(vec!["admin@example.com"]),
        );
        let result = validate_contacts_and_uris(&req);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_contacts_and_uris_http_client_uri_rejected() {
        let req = make_request_with_uris(Some("http://example.com"), None, None, None, None);
        let result = validate_contacts_and_uris(&req);
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_contacts_and_uris_http_logo_uri_rejected() {
        let req =
            make_request_with_uris(None, Some("http://example.com/logo.png"), None, None, None);
        let result = validate_contacts_and_uris(&req);
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_contacts_and_uris_http_tos_uri_rejected() {
        let req = make_request_with_uris(None, None, Some("http://example.com/tos"), None, None);
        let result = validate_contacts_and_uris(&req);
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_contacts_and_uris_http_policy_uri_rejected() {
        let req =
            make_request_with_uris(None, None, None, Some("http://example.com/privacy"), None);
        let result = validate_contacts_and_uris(&req);
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_contacts_and_uris_too_many_contacts() {
        let contacts: Vec<&str> = (0..=MAX_CONTACTS).map(|_| "user@example.com").collect();
        let req = make_request_with_uris(None, None, None, None, Some(contacts));
        let result = validate_contacts_and_uris(&req);
        assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
    }

    #[test]
    fn test_validate_contacts_and_uris_invalid_email_format() {
        let req = make_request_with_uris(None, None, None, None, Some(vec!["notanemail"]));
        let err = validate_contacts_and_uris(&req).unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description.contains("notanemail"))
        );
    }

    // =========================================================================
    // determine_client_type
    // =========================================================================

    #[test]
    fn test_determine_client_type_client_credentials_only_is_service() {
        let grant_types = vec!["client_credentials".to_string()];
        let result = determine_client_type(
            &grant_types,
            TokenEndpointAuthMethod::ClientSecretBasic,
            &[],
        );
        assert_eq!(result, OAuthClientType::Service);
    }

    #[test]
    fn test_determine_client_type_public_with_loopback_is_native() {
        let grant_types = vec!["authorization_code".to_string()];
        let redirect_uris = vec!["http://localhost:7777/callback".to_string()];
        let result =
            determine_client_type(&grant_types, TokenEndpointAuthMethod::None, &redirect_uris);
        assert_eq!(result, OAuthClientType::Native);
    }

    #[test]
    fn test_determine_client_type_public_with_127_0_0_1_is_native() {
        let grant_types = vec!["authorization_code".to_string()];
        let redirect_uris = vec!["http://127.0.0.1:3000/callback".to_string()];
        let result =
            determine_client_type(&grant_types, TokenEndpointAuthMethod::None, &redirect_uris);
        assert_eq!(result, OAuthClientType::Native);
    }

    #[test]
    fn test_determine_client_type_public_no_loopback_is_spa() {
        let grant_types = vec!["authorization_code".to_string()];
        let redirect_uris = vec!["https://app.example.com/callback".to_string()];
        let result =
            determine_client_type(&grant_types, TokenEndpointAuthMethod::None, &redirect_uris);
        assert_eq!(result, OAuthClientType::Spa);
    }

    #[test]
    fn test_determine_client_type_public_no_redirect_uris_is_spa() {
        let grant_types = vec!["authorization_code".to_string()];
        let result = determine_client_type(&grant_types, TokenEndpointAuthMethod::None, &[]);
        assert_eq!(result, OAuthClientType::Spa);
    }

    #[test]
    fn test_determine_client_type_confidential_is_web() {
        let grant_types = vec!["authorization_code".to_string()];
        let redirect_uris = vec!["https://app.example.com/callback".to_string()];
        let result = determine_client_type(
            &grant_types,
            TokenEndpointAuthMethod::ClientSecretBasic,
            &redirect_uris,
        );
        assert_eq!(result, OAuthClientType::Web);
    }

    #[test]
    fn test_determine_client_type_private_key_jwt_is_web() {
        let grant_types = vec!["authorization_code".to_string()];
        let redirect_uris = vec!["https://app.example.com/callback".to_string()];
        let result = determine_client_type(
            &grant_types,
            TokenEndpointAuthMethod::PrivateKeyJwt,
            &redirect_uris,
        );
        assert_eq!(result, OAuthClientType::Web);
    }

    #[test]
    fn test_determine_client_type_client_credentials_with_multiple_grants_not_service() {
        // Only single-grant client_credentials → Service. Multiple grants → Web.
        let grant_types = vec![
            "client_credentials".to_string(),
            "authorization_code".to_string(),
        ];
        let redirect_uris = vec!["https://app.example.com/callback".to_string()];
        let result = determine_client_type(
            &grant_types,
            TokenEndpointAuthMethod::ClientSecretBasic,
            &redirect_uris,
        );
        assert_eq!(result, OAuthClientType::Web);
    }

    // =========================================================================
    // FAPI 2.0 Section 5.4: RS256 rejection across all client-configurable
    // signing algorithm fields (issue #393).
    //
    // Each test asserts the specific field name appears in the error message
    // so future refactors that drop the field-specific message would break the
    // test, not just the helper.
    // =========================================================================

    fn assert_rs256_fapi_error(result: Result<(), ServiceError>, field: &str) {
        let err = result.expect_err("RS256 + FAPI must be rejected");
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata),
            "Expected InvalidClientMetadata OAuth error, got {err:?}"
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description.contains(field)),
            "Error description must name the field '{field}': {err:?}"
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description.contains("RS256")),
            "Error description must mention RS256: {err:?}"
        );
    }

    #[test]
    fn test_reject_rs256_for_fapi_rejects_jarm() {
        let result = reject_rs256_for_fapi(
            JwsAlgorithm::Rs256,
            FapiProfile::Fapi2Security,
            "authorization_signed_response_alg",
        );
        assert_rs256_fapi_error(result, "authorization_signed_response_alg");
    }

    #[test]
    fn test_reject_rs256_for_fapi_rejects_userinfo() {
        let result = reject_rs256_for_fapi(
            JwsAlgorithm::Rs256,
            FapiProfile::Fapi2Security,
            "userinfo_signed_response_alg",
        );
        assert_rs256_fapi_error(result, "userinfo_signed_response_alg");
    }

    #[test]
    fn test_reject_rs256_for_fapi_rejects_id_token() {
        let result = reject_rs256_for_fapi(
            JwsAlgorithm::Rs256,
            FapiProfile::Fapi2Security,
            "id_token_signed_response_alg",
        );
        assert_rs256_fapi_error(result, "id_token_signed_response_alg");
    }

    #[test]
    fn test_reject_rs256_for_fapi_rejects_request_object() {
        let result = reject_rs256_for_fapi(
            JwsAlgorithm::Rs256,
            FapiProfile::Fapi2Security,
            "request_object_signing_alg",
        );
        assert_rs256_fapi_error(result, "request_object_signing_alg");
    }

    #[test]
    fn test_reject_rs256_for_fapi_allows_rs256_for_non_fapi() {
        // Non-FAPI clients are permitted to use RS256 (subject to other checks
        // like RSA key availability handled by the calling block).
        let result = reject_rs256_for_fapi(
            JwsAlgorithm::Rs256,
            FapiProfile::None,
            "authorization_signed_response_alg",
        );
        assert!(result.is_ok(), "Non-FAPI + RS256 must be allowed");
    }

    #[test]
    fn test_reject_rs256_for_fapi_allows_es256_for_fapi() {
        // ES256 is the canonical FAPI-permitted algorithm.
        let result = reject_rs256_for_fapi(
            JwsAlgorithm::Es256,
            FapiProfile::Fapi2Security,
            "authorization_signed_response_alg",
        );
        assert!(result.is_ok(), "FAPI + ES256 must be allowed");
    }

    #[test]
    fn test_validate_userinfo_signed_response_alg_rejects_rs256_for_fapi() {
        // Integration of reject_rs256_for_fapi into the userinfo validator.
        // Passing has_rsa_key=true isolates the FAPI rejection from the
        // "no RSA key configured" path.
        let result = validate_userinfo_signed_response_alg(
            Some("RS256"),
            RsaSigningKey::Available,
            FapiProfile::Fapi2Security,
        );
        assert_rs256_fapi_error(result.map(|_| ()), "userinfo_signed_response_alg");
    }

    #[test]
    fn test_validate_userinfo_signed_response_alg_allows_es256_for_fapi() {
        // ES256 is allowed for FAPI clients regardless of RSA key availability.
        let result = validate_userinfo_signed_response_alg(
            Some("ES256"),
            RsaSigningKey::Unavailable,
            FapiProfile::Fapi2Security,
        );
        let alg = result.expect("ES256 must be accepted for FAPI userinfo");
        assert_eq!(alg, Some(JwsAlgorithm::Es256));
    }
}
