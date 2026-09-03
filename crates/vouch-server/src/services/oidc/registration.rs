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
use crate::crypto::alg::JwsAlgorithm;
use crate::crypto::{generate_random_bytes, hash_token};
use crate::db::{
    self, CreateOAuthClientParams, FapiProfile, OAuthClient, OAuthClientType, OAuthEventType,
    RegistrationSource, TokenEndpointAuthMethod, UpdateClientRegistrationParams,
};
use crate::error::{OAuthErrorCode, ServiceError};
use crate::services::oidc::grant_type::OAuthGrantType;
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;

// ============================================================================
// Allowed Grant and Response Types
// ============================================================================

/// Grant types accepted in registration beyond what the token endpoint
/// dispatches ([`OAuthGrantType`]). `refresh_token` is accepted so
/// standard client libraries can register unmodified, but the server
/// never issues refresh tokens — clients that request it simply never
/// receive one in token responses.
const REGISTRATION_ONLY_GRANT_TYPES: &[&str] = &["refresh_token"];

/// Every grant type this server accepts for dynamic registration: the
/// token endpoint's dispatch set plus the registration-only extras.
fn allowed_grant_types() -> Vec<&'static str> {
    let mut allowed = OAuthGrantType::supported_wire_values();
    allowed.extend_from_slice(REGISTRATION_ONLY_GRANT_TYPES);
    allowed
}

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
    /// OIDC Registration Section 2: `"native"` or `"web"`; the default when
    /// omitted is `"web"`. Decides whether a custom URI scheme may be
    /// registered, so it is read before the redirect URIs are validated.
    pub application_type: Option<String>,
    /// RFC 7591 Section 2: Authentication method for the token endpoint.
    pub token_endpoint_auth_method: Option<String>,
    /// RFC 7591 Section 2: Array of OAuth 2.0 grant type strings.
    pub grant_types: Option<Vec<String>>,
    /// RFC 7591 Section 2: Array of OAuth 2.0 response type strings.
    pub response_types: Option<Vec<String>>,
    /// RFC 7591 Section 2: Human-readable name of the client.
    #[serde(default, deserialize_with = "empty_string_as_none")]
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
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub scope: Option<String>,
    /// RFC 7591 Section 2: Array of contact email addresses.
    pub contacts: Option<Vec<String>>,
    /// RFC 7591 Section 2: Client's JSON Web Key Set (inline).
    pub jwks: Option<serde_json::Value>,
    /// RFC 7591 Section 2: URL for the client's JSON Web Key Set.
    pub jwks_uri: Option<String>,
    /// RFC 7591 Section 2: Unique identifier for the client software.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub software_id: Option<String>,
    /// RFC 7591 Section 2: Version of the client software.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub software_version: Option<String>,
    /// FAPI 2.0: Whether access tokens must be DPoP-bound.
    pub dpop_bound_access_tokens: Option<bool>,
    /// OIDC Core Section 3.1.3.7: ID token signing algorithm.
    pub id_token_signed_response_alg: Option<String>,
    /// RFC 8705 Section 2.1.2: subject DN for tls_client_auth.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub tls_client_auth_subject_dn: Option<String>,
    /// RFC 8705 Section 2.1.2: SAN DNS name for tls_client_auth.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub tls_client_auth_san_dns: Option<String>,
    /// RFC 8705 Section 2.1.2: SAN URI for tls_client_auth.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub tls_client_auth_san_uri: Option<String>,
    /// RFC 8705 Section 2.1.2: SAN IP for tls_client_auth.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub tls_client_auth_san_ip: Option<String>,
    /// RFC 8705 Section 2.1.2: SAN email for tls_client_auth.
    #[serde(default, deserialize_with = "empty_string_as_none")]
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

/// Deserialize an optional string, reading an empty value as absent.
///
/// RFC 7591 is silent here: its JSON body has no counterpart to RFC 6749 §3.1
/// and §3.2's "Parameters sent without a value MUST be treated as if they were
/// omitted from the request", which
/// [`crate::handlers::extractors::OAuthForm`] applies to the form-encoded
/// endpoints. So the choice is ours, and it is made the same way: a stored
/// empty string is a third state next to "absent" and "set" that means nothing
/// the two do not, so the field is not stored at all.
///
/// Carried by the fields where an empty value would otherwise be persisted:
/// the RFC 8705 §2.1.2 certificate-subject parameters, where an empty string
/// matches no certificate and would satisfy the exactly-one rule with a value
/// that still leaves the client unable to authenticate; and `client_name`,
/// `scope`, `software_id`, and `software_version`, which have no validator to
/// pass. An emptied `client_name` therefore takes the same
/// `"Unnamed Client"` fallback an omitted one does, and the other three go to
/// NULL — `software_id` is indexed, so this also keeps an empty key out of the
/// index.
///
/// The remaining metadata fields keep serde's plain `Option<String>`, because
/// an empty value there already reaches a validator that rejects it outright
/// (an empty `logo_uri` is not a valid HTTPS URL, an empty `application_type`
/// is not "native" or "web", an empty signing algorithm is not a supported
/// one). Reading those as absent would turn an explicit
/// `invalid_client_metadata` into a silent default and hide the client's bug.
///
/// A whitespace-only value stays present, matching the form-encoded rule that
/// reads `%20` as a value rather than as nothing.
fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.filter(|s| !s.is_empty()))
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
        // An empty list carries nothing an absent key does not, so it is not
        // stored. Individual empty members never reach here: an address without
        // an `@` is refused by `validate_contacts_and_uris`.
        if let Some(ref v) = self.contacts
            && !v.is_empty()
        {
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
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "vouch_common::serialize_opt_secret_string"
    )]
    pub client_secret: Option<SecretString>,
    /// RFC 7591 Section 3.2.1: 0 = does not expire. REQUIRED when client_secret issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    /// RFC 7591 Section 3.2.1: Time at which the client_id was issued (epoch seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<i64>,
    /// RFC 7592: Registration access token for future management.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "vouch_common::serialize_opt_secret_string"
    )]
    pub registration_access_token: Option<SecretString>,
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

    // 8-9. Validate JWKS and auth method. This runs before the redirect URIs
    // because the application type decides whether a custom URI scheme may be
    // registered, and inferring that type needs the auth method.
    let jwks_auth = validate_jwks_and_auth_method(&mut request, &validated.auth_method_str)?;

    // 7. Resolve the application type, then validate redirect URIs against it.
    let app_type = resolve_client_type(
        request.application_type.as_deref(),
        &validated.grant_types,
        jwks_auth.auth_method,
        request.redirect_uris.as_deref().unwrap_or_default(),
    )?;
    let redirect_uris = validate_redirect_uris(&mut request, validated.auth_code_grant, app_type)?;

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
        if !jwks_auth.auth_method.is_fapi_compatible() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                "FAPI 2.0 requires token_endpoint_auth_method \
                 'private_key_jwt', 'tls_client_auth', or \
                 'self_signed_tls_client_auth'",
            ));
        }
        if jwks_auth.keys.is_none() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                "FAPI 2.0 requires jwks or jwks_uri",
            ));
        }
        // Only for private_key_jwt: its JWKS carries client-assertion signing
        // keys, so an inline JWKS must have at least one key usable with
        // FAPI_ALLOWED (ES256/PS256/EdDSA) — see JwkSet::has_fapi_allowed_key.
        // Without this, a client could register as FAPI 2.0 with an
        // RS256-only JWKS and be unable to authenticate at the token endpoint
        // from the start. tls_client_auth/self_signed_tls_client_auth JWKS
        // conveys certificates via x5c instead (RFC 8705 §2.2.2), so this
        // check does not apply to them.
        if jwks_auth.auth_method == TokenEndpointAuthMethod::PrivateKeyJwt
            && let Some(jwks) = jwks_auth
                .keys
                .as_ref()
                .and_then(crate::db::ClientKeys::inline)
            && !jwks.has_fapi_allowed_key()
        {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                "FAPI 2.0 requires a JWKS key usable with ES256, PS256, or EdDSA",
            ));
        }
        FapiProfile::Fapi2Security
    } else {
        FapiProfile::None
    };

    // 12b. Validate the signed-response algorithms (OIDC Core §3.1.3.7 and
    // §5.3.4, JARM §2.3.2, RFC 9701 §6.1).
    let rsa_key = if state.oidc_rsa_key.is_some() {
        RsaSigningKey::Available
    } else {
        RsaSigningKey::Unavailable
    };
    let algs = validate_signed_response_algs(&request, rsa_key, fapi_profile)?;
    // A new client that names no algorithm gets the server default.
    let id_token_alg =
        resolve_id_token_alg(algs.id_token, fapi_profile, default_id_token_alg(rsa_key));

    // 12b-2. Validate request_uris (OIDC Core Section 6.2).
    let validated_request_uris = validate_request_uris(request.request_uris.as_deref())?;

    // 12b-3. Validate post_logout_redirect_uris (RP-Initiated Logout 1.0 Section 2).
    let validated_post_logout_redirect_uris = validate_post_logout_redirect_uris_registration(
        request.post_logout_redirect_uris.as_deref(),
    )?;

    // 12d. Validate the RFC 9101 Request Object commitment against the key
    // material this request carries. Shared with the update path.
    let request_object = validate_request_object_signing(
        request.request_object_signing_alg.as_deref(),
        request.require_signed_request_object,
        fapi_profile,
        jwks_auth.keys.as_ref(),
    )?;
    let req_obj_alg = request_object.alg;
    let require_signed = request_object.require_signed;

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
            token_endpoint_auth_method: jwks_auth.auth_method,
            keys: jwks_auth.keys.as_ref(),
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
            authorization_signed_response_alg: algs.authorization,
            introspection_signed_response_alg: algs.introspection,
            request_object_signing_alg: req_obj_alg,
            require_signed_request_object: if require_signed { Some(true) } else { None },
            userinfo_signed_response_alg: algs.userinfo,
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

        Some(SecretString::from(secret))
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
        registration_access_token: Some(reg_token.into()),
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
        jwks: jwks_auth
            .keys
            .as_ref()
            .and_then(crate::db::ClientKeys::inline)
            .and_then(|set| serde_json::to_value(set).ok()),
        jwks_uri: jwks_auth
            .keys
            .as_ref()
            .and_then(crate::db::ClientKeys::uri)
            .map(String::from),
        software_id: request.software_id,
        software_version: request.software_version,
        dpop_bound_access_tokens: if dpop_bound { Some(true) } else { None },
        id_token_signed_response_alg: id_token_alg.to_string(),
        authorization_signed_response_alg: algs.authorization.map(|a| a.to_string()),
        introspection_signed_response_alg: algs.introspection.map(|a| a.to_string()),
        request_object_signing_alg: req_obj_alg.map(|a| a.to_string()),
        require_signed_request_object: if require_signed { Some(true) } else { None },
        userinfo_signed_response_alg: algs.userinfo.map(|a| a.to_string()),
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

/// Validate an explicit `id_token_signed_response_alg`.
///
/// Returns the parsed algorithm, or `None` when the field is absent — the
/// caller supplies the fallback, because initial registration and an RFC 7592
/// update fall back to different values. See [`resolve_id_token_alg`].
fn validate_id_token_signed_response_alg(
    raw: Option<&str>,
    rsa_key: RsaSigningKey,
    fapi_profile: FapiProfile,
) -> Result<Option<JwsAlgorithm>, ServiceError> {
    let Some(s) = raw else { return Ok(None) };
    let unsupported = || {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!("Unsupported id_token_signed_response_alg: '{s}'. Supported: RS256, ES256"),
        )
    };
    let parsed = s.parse::<JwsAlgorithm>().map_err(|_| unsupported())?;
    // Only RS256 and ES256 are accepted for ID tokens.
    if !matches!(parsed, JwsAlgorithm::Rs256 | JwsAlgorithm::Es256) {
        return Err(unsupported());
    }
    // FAPI 2.0 Section 5.4: RS256 is not permitted for FAPI clients.
    reject_rs256_for_fapi(parsed, fapi_profile, "id_token_signed_response_alg")?;
    if parsed == JwsAlgorithm::Rs256 && rsa_key == RsaSigningKey::Unavailable {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "RS256 is not available (no RSA signing key configured)",
        ));
    }
    Ok(Some(parsed))
}

/// The ID token signing algorithm a client ends up with.
///
/// `fallback` is what an omitted field resolves to. The `id_token_signed_
/// response_alg` column is non-nullable, so "omitted" has no cleared state to
/// fall back to and each path picks its own:
///
/// * Initial registration falls back to the server default — OIDC Core
///   §3.1.3.7 names RS256, and this server substitutes ES256 when it has no
///   RSA signing key.
/// * An RFC 7592 update falls back to the algorithm the client registered.
///   §2.2 asks that an omitted field be deleted, but immediately allows the
///   other reading: "The authorization server MAY ignore any null or empty
///   value in the request just as any other value." Re-deriving the server
///   default instead would move a client that chose ES256 onto RS256 on any
///   PUT that did not restate the field — a silent downgrade of ID token
///   signing, on a server that always has an RSA key available. Ignoring the
///   omission is the conformant reading that does not weaken the client.
///
/// FAPI 2.0 §5.4 pins FAPI clients to ES256 either way.
fn resolve_id_token_alg(
    explicit: Option<JwsAlgorithm>,
    fapi_profile: FapiProfile,
    fallback: JwsAlgorithm,
) -> JwsAlgorithm {
    if fapi_profile != FapiProfile::None {
        return JwsAlgorithm::Es256;
    }
    explicit.unwrap_or(fallback)
}

/// The ID token signing algorithm a new registration gets when it names none.
///
/// OIDC Core §3.1.3.7 names RS256 the default; ES256 stands in when the
/// server has no RSA signing key.
fn default_id_token_alg(rsa_key: RsaSigningKey) -> JwsAlgorithm {
    match rsa_key {
        RsaSigningKey::Available => JwsAlgorithm::Rs256,
        RsaSigningKey::Unavailable => JwsAlgorithm::Es256,
    }
}

/// Validate `authorization_signed_response_alg` (JARM §2.3.2).
///
/// Only RS256 and ES256 are accepted. Serde rejects "none" and the symmetric
/// HS* algorithms before this point, since they are not `JwsAlgorithm`
/// variants.
///
/// Returns the parsed algorithm, or `None` if the field is absent.
fn validate_authorization_signed_response_alg(
    raw: Option<&str>,
    rsa_key: RsaSigningKey,
    fapi_profile: FapiProfile,
) -> Result<Option<JwsAlgorithm>, ServiceError> {
    let Some(s) = raw else { return Ok(None) };
    let parsed = s.parse::<JwsAlgorithm>().map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!(
                "Unsupported authorization_signed_response_alg: '{s}'. \
                 Must be an asymmetric algorithm such as RS256 or ES256"
            ),
        )
    })?;
    if !matches!(parsed, JwsAlgorithm::Rs256 | JwsAlgorithm::Es256) {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!(
                "Unsupported authorization_signed_response_alg: '{s}'. Supported: RS256, ES256"
            ),
        ));
    }
    // FAPI 2.0 Section 5.4.1: RS256 is not permitted for FAPI clients.
    reject_rs256_for_fapi(parsed, fapi_profile, "authorization_signed_response_alg")?;
    if parsed == JwsAlgorithm::Rs256 && rsa_key == RsaSigningKey::Unavailable {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "RS256 is not available for authorization_signed_response_alg \
             (no RSA signing key configured)",
        ));
    }
    Ok(Some(parsed))
}

/// Validate `introspection_signed_response_alg` (RFC 9701 §6.1).
///
/// Only ES256 is supported — the server's primary P-256 ECDSA key.
///
/// Returns the parsed algorithm, or `None` if the field is absent.
fn validate_introspection_signed_response_alg(
    raw: Option<&str>,
) -> Result<Option<JwsAlgorithm>, ServiceError> {
    let Some(s) = raw else { return Ok(None) };
    let unsupported = || {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!("Unsupported introspection_signed_response_alg: '{s}'. Supported: ES256"),
        )
    };
    let parsed = s.parse::<JwsAlgorithm>().map_err(|_| unsupported())?;
    if parsed != JwsAlgorithm::Es256 {
        return Err(unsupported());
    }
    Ok(Some(parsed))
}

/// The signed-response algorithms a client registers.
#[derive(Debug, Clone, Copy)]
struct SignedResponseAlgs {
    /// The explicitly requested value, if any. Unlike the other three, this
    /// one has no cleared state, so the caller resolves an omission with
    /// [`resolve_id_token_alg`].
    id_token: Option<JwsAlgorithm>,
    authorization: Option<JwsAlgorithm>,
    introspection: Option<JwsAlgorithm>,
    userinfo: Option<JwsAlgorithm>,
}

/// Validate every signed-response algorithm a registration request carries.
///
/// Shared by initial registration and the RFC 7592 update path, so an
/// algorithm one accepts cannot be one the other rejects. `fapi_profile` is
/// the profile the client will hold: derived from the request at registration,
/// and the registered profile on an update, where it is immutable.
fn validate_signed_response_algs(
    request: &RegistrationRequest,
    rsa_key: RsaSigningKey,
    fapi_profile: FapiProfile,
) -> Result<SignedResponseAlgs, ServiceError> {
    Ok(SignedResponseAlgs {
        id_token: validate_id_token_signed_response_alg(
            request.id_token_signed_response_alg.as_deref(),
            rsa_key,
            fapi_profile,
        )?,
        authorization: validate_authorization_signed_response_alg(
            request.authorization_signed_response_alg.as_deref(),
            rsa_key,
            fapi_profile,
        )?,
        introspection: validate_introspection_signed_response_alg(
            request.introspection_signed_response_alg.as_deref(),
        )?,
        userinfo: validate_userinfo_signed_response_alg(
            request.userinfo_signed_response_alg.as_deref(),
            rsa_key,
            fapi_profile,
        )?,
    })
}

/// A client's RFC 9101 Request Object commitment.
#[derive(Debug, Clone, Copy)]
struct RequestObjectSigning {
    alg: Option<JwsAlgorithm>,
    require_signed: bool,
}

/// Validate `request_object_signing_alg` and `require_signed_request_object`
/// (RFC 9101) against the key material the same request carries.
///
/// A client that commits to Request Objects needs key material the verifier can
/// select for them. RFC 9101 §6.2 governs the runtime side — "The signature
/// MUST be validated using a key associated with the client and the algorithm
/// specified in the 'alg' Header Parameter" — and is silent on whether an
/// unsatisfiable registration must be refused; this refuses it for the same
/// reason `JwkSet::has_fapi_allowed_key` and `JwkSet::has_x5c` refuse theirs.
/// Accepted unchecked, the pairing leaves the client unable to reach the
/// authorization endpoint at all: the signed path fails key resolution, and
/// `require_signed_request_object` refuses the plain one.
///
/// Both values and the JWKS come from the same request, so this holds for an
/// RFC 7592 PUT — a full replacement — as much as for initial registration.
fn validate_request_object_signing(
    raw_alg: Option<&str>,
    raw_require_signed: Option<bool>,
    fapi_profile: FapiProfile,
    keys: Option<&crate::db::ClientKeys>,
) -> Result<RequestObjectSigning, ServiceError> {
    let alg = match raw_alg {
        None => None,
        Some(s) => {
            let parsed = s.parse::<JwsAlgorithm>().map_err(|_| {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidClientMetadata,
                    format!("Unsupported request_object_signing_alg: '{s}'"),
                )
            })?;
            // FAPI 2.0 Section 5.4: RS256 is not permitted for FAPI clients.
            reject_rs256_for_fapi(parsed, fapi_profile, "request_object_signing_alg")?;
            Some(parsed)
        }
    };

    // An explicit value wins. Otherwise FAPI 2.0 Message Signing requires
    // signed request objects (JAR/RFC 9101) only once the client names a
    // request_object_signing_alg; the FAPI 2.0 Security Profile uses unsigned
    // PAR (RFC 9126) without JAR.
    let require_signed =
        raw_require_signed.unwrap_or(fapi_profile != FapiProfile::None && alg.is_some());

    // `require_signed_request_object` commits a client to signing without
    // necessarily naming an algorithm, hence the separate presence check.
    if require_signed || alg.is_some() {
        if keys.is_none() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                "A client registering request_object_signing_alg or \
                 require_signed_request_object must also register jwks or jwks_uri",
            ));
        }
        // A remote jwks_uri can't be inspected synchronously, so the
        // per-algorithm check only guards the inline case.
        if let Some(alg) = alg
            && let Some(jwks) = keys.and_then(crate::db::ClientKeys::inline)
            && !jwks.has_key_for(alg)
        {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!(
                    "The submitted jwks holds no key usable for \
                     request_object_signing_alg '{alg}'; it needs a key of type \
                     {} whose alg (if declared) is '{alg}' and whose use (if \
                     declared) is 'sig'",
                    crate::db::KeyType::for_alg(alg)
                ),
            ));
        }
    }

    Ok(RequestObjectSigning {
        alg,
        require_signed,
    })
}

/// Validate `request_uris` — each must be HTTPS, max 10 entries.
///
/// Returns the validated list, or `None` if the field is absent.
fn validate_request_uris(uris: Option<&[String]>) -> Result<Option<Vec<String>>, ServiceError> {
    let Some(uris) = uris else { return Ok(None) };
    // An empty allowlist is the same state as no allowlist, so it is not
    // stored — as in `validate_post_logout_redirect_uris_registration`.
    if uris.is_empty() {
        return Ok(None);
    }
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

    let allowed_grants = allowed_grant_types();
    for gt in &grant_types {
        if !allowed_grants.contains(&gt.as_str()) {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!("Unsupported grant type: '{gt}'"),
            ));
        }
    }
    for rt in &response_types {
        if !crate::services::oidc::SUPPORTED_RESPONSE_TYPES.contains(&rt.as_str()) {
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
    application_type: OAuthClientType,
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
        db::validate_redirect_uri(uri, application_type).map_err(|e| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidRedirectUri,
                format!("Invalid redirect URI '{uri}': {e}"),
            )
        })?;
    }
    Ok(redirect_uris)
}

/// Validated JWKS and auth method from a registration request.
#[derive(Debug)]
struct ValidatedJwksAuth {
    /// RFC 7591 §2 key material, in whichever of the two forms was sent.
    keys: Option<crate::db::ClientKeys>,
    auth_method: TokenEndpointAuthMethod,
}

/// Validate the structure of whichever key form was supplied, and the HTTPS
/// constraint on a JWKS URI.
///
/// Mutual exclusivity is no longer checked here: [`crate::db::ClientKeys`] is
/// the only shape this receives, and it cannot hold both.
///
/// Shared by both initial registration and the update path. Does not validate the
/// relationship to `token_endpoint_auth_method` — that is handled by
/// `validate_jwks_and_auth_method` for the initial registration path.
fn validate_jwks_shape(keys: Option<&crate::db::ClientKeys>) -> Result<(), ServiceError> {
    let jwks = keys.and_then(crate::db::ClientKeys::inline);
    let jwks_uri = keys.and_then(crate::db::ClientKeys::uri);
    if let Some(jwks) = jwks {
        // A key set with no keys parses but can never authenticate anyone.
        // Everything else the old shape check covered — that this is an object
        // with a "keys" array, and that no member has an invalid type — is now
        // established by `ClientKeys::from_stored`, which parses on the way in.
        if jwks.keys.is_empty() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                "jwks must be a JSON object with a non-empty \"keys\" array",
            ));
        }
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
    // Pairing the two parameters is the mutual-exclusion check: RFC 7591 §2
    // says they "MUST NOT both be present in the same request or response",
    // and `ClientKeys` is the only shape the rest of the code accepts.
    let keys = crate::db::ClientKeys::from_stored(request.jwks.take(), request.jwks_uri.take())
        .map_err(|e| ServiceError::oauth(OAuthErrorCode::InvalidClientMetadata, e.to_string()))?;
    validate_jwks_shape(keys.as_ref())?;

    let auth_method: TokenEndpointAuthMethod = auth_method_str.parse().map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!("Unsupported token_endpoint_auth_method: '{auth_method_str}'"),
        )
    })?;

    // private_key_jwt authenticates with a client-assertion signing key, and
    // self_signed_tls_client_auth's certificate is carried in the JWKS's
    // `x5c` member (RFC 8705 §2.2.2) — both need key material to
    // authenticate at all. tls_client_auth authenticates via PKI subject
    // DN/SAN instead, so it needs none.
    if matches!(
        auth_method,
        TokenEndpointAuthMethod::PrivateKeyJwt | TokenEndpointAuthMethod::SelfSignedTlsClientAuth
    ) && keys.is_none()
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "private_key_jwt and self_signed_tls_client_auth require jwks or jwks_uri",
        ));
    }

    // self_signed_tls_client_auth's certificate is carried by a key's `x5c`
    // member; an inline JWKS with none anywhere would pass the presence
    // check above but leave the client unable to ever complete mTLS
    // authentication — see JwkSet::has_x5c. A remote jwks_uri can't be
    // inspected synchronously, so this only guards the inline case, same as
    // the FAPI algorithm-usability check.
    if auth_method == TokenEndpointAuthMethod::SelfSignedTlsClientAuth
        && let Some(jwks) = keys.as_ref().and_then(crate::db::ClientKeys::inline)
        && !jwks.has_x5c()
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "self_signed_tls_client_auth requires a JWKS key with an x5c certificate",
        ));
    }

    validate_tls_client_auth_identity(auth_method, request)?;

    Ok(ValidatedJwksAuth { keys, auth_method })
}

/// Enforce the certificate-subject metadata rule on a `tls_client_auth` client.
///
/// RFC 8705 §2.1.2:
///
/// > A client using the "tls_client_auth" authentication method MUST use
/// > exactly one of the below metadata parameters to indicate the certificate
/// > subject value that the authorization server is to expect when
/// > authenticating the respective client.
///
/// Zero is refused because `verify_tls_client_auth` reads an all-absent client
/// as `CertificateNotRegistered`, so the client could never authenticate at the
/// token endpoint. More than one is refused because that same function consults
/// the parameters in a fixed precedence order and returns on the first one
/// present, silently ignoring the rest.
///
/// Shared by initial registration and the RFC 7592 §2.2 PUT. The PUT is a full
/// replacement — omitted fields are cleared — so without this check there it
/// could move a working client into the exact state registration refuses.
///
/// Returns `Ok(())` for every other authentication method, which does not use
/// these parameters.
fn validate_tls_client_auth_identity(
    auth_method: TokenEndpointAuthMethod,
    request: &RegistrationRequest,
) -> Result<(), ServiceError> {
    if auth_method != TokenEndpointAuthMethod::TlsClientAuth {
        return Ok(());
    }

    // Listed in the precedence order `verify_tls_client_auth` consults them.
    let mut present: Vec<&str> = Vec::new();
    for (name, value) in [
        (
            "tls_client_auth_subject_dn",
            &request.tls_client_auth_subject_dn,
        ),
        ("tls_client_auth_san_dns", &request.tls_client_auth_san_dns),
        (
            "tls_client_auth_san_email",
            &request.tls_client_auth_san_email,
        ),
        ("tls_client_auth_san_uri", &request.tls_client_auth_san_uri),
        ("tls_client_auth_san_ip", &request.tls_client_auth_san_ip),
    ] {
        if value.is_some() {
            present.push(name);
        }
    }

    match present.len() {
        1 => Ok(()),
        0 => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "tls_client_auth requires exactly one identity field \
             (tls_client_auth_subject_dn, tls_client_auth_san_dns, \
             tls_client_auth_san_email, tls_client_auth_san_uri, \
             or tls_client_auth_san_ip)",
        )),
        count => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!(
                "tls_client_auth requires exactly one identity field, but {count} were \
                 supplied: {}",
                present.join(", ")
            ),
        )),
    }
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
/// Parse the client-declared `application_type` (OIDC Registration §2).
///
/// > application_type
/// >    OPTIONAL.  Kind of the application.  The default, if omitted, is
/// >    "web".  The defined values are "native" or "web".
///
/// Only those two values are defined, so anything else is invalid metadata
/// rather than a silent fallback.
fn parse_declared_client_type(declared: &str) -> Result<OAuthClientType, ServiceError> {
    match declared {
        "native" => Ok(OAuthClientType::Native),
        "web" => Ok(OAuthClientType::Web),
        other => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            format!("Unsupported application_type '{other}': expected 'native' or 'web'"),
        )),
    }
}

/// The error returned when an RFC 7592 PUT tries to change a field that is
/// fixed at registration.
///
/// RFC 7591 §3.2.2 defines the code: "invalid_client_metadata — The value of
/// one of the client metadata fields is invalid and the server has rejected
/// this request."
fn immutable_field_error(field: &str, registered: &str) -> ServiceError {
    ServiceError::oauth(
        OAuthErrorCode::InvalidClientMetadata,
        format!(
            "{field} cannot be changed after registration (registered value: \
             '{registered}'). Omit the field or resend the registered value."
        ),
    )
}

/// Refuse an RFC 7592 update that tries to change a field fixed at registration.
///
/// These four fix the client's security class rather than describe it:
/// `token_endpoint_auth_method` decides how the client proves who it is,
/// `application_type` decides whether PKCE is mandatory and which redirect URI
/// schemes are legal, and the two sender-constraining flags are what
/// `register_client` reads to derive the `fapi_profile` a client keeps for
/// life. Writing any of them here would let a client relax its own security
/// class using nothing but its registration access token.
///
/// Restating the current value succeeds, because RFC 7592 §2.2 obliges a
/// client to do exactly that: "This request MUST include all client metadata
/// fields as returned to the client from a previous registration, read, or
/// update operation." Only a differing value is refused, and an omitted field
/// leaves the registered value alone — an immutable field has no "cleared"
/// state to fall back to.
///
/// Must run before [`validate_grant_and_response_types`], which takes
/// `token_endpoint_auth_method` out of the request and substitutes a default.
fn reject_immutable_changes(
    request: &RegistrationRequest,
    client: &OAuthClient,
) -> Result<(), ServiceError> {
    if let Some(ref declared) = request.token_endpoint_auth_method {
        let registered = client.token_endpoint_auth_method.as_str();
        if declared != registered {
            return Err(immutable_field_error(
                "token_endpoint_auth_method",
                registered,
            ));
        }
    }

    if let Some(ref declared) = request.application_type
        && parse_declared_client_type(declared)? != client.application_type
    {
        return Err(immutable_field_error(
            "application_type",
            client.application_type.as_str(),
        ));
    }

    // RFC 9449 §5 and RFC 8705 §3 sender constraints. `register_client` reads
    // the pair to decide `fapi_profile`, so a PUT that flipped either would
    // leave a client whose stored profile no longer matches the binding it
    // declares — a state initial registration cannot produce.
    if let Some(declared) = request.dpop_bound_access_tokens
        && declared != client.dpop_bound_access_tokens
    {
        return Err(immutable_field_error(
            "dpop_bound_access_tokens",
            &client.dpop_bound_access_tokens.to_string(),
        ));
    }
    if let Some(declared) = request.tls_client_certificate_bound_access_tokens
        && declared != client.tls_client_certificate_bound_access_tokens
    {
        return Err(immutable_field_error(
            "tls_client_certificate_bound_access_tokens",
            &client
                .tls_client_certificate_bound_access_tokens
                .to_string(),
        ));
    }

    Ok(())
}

/// The application type to validate this registration's redirect URIs against.
///
/// The client's own `application_type` wins when it sends one, since OIDC
/// Registration §2 defines it as the client stating what it is. Otherwise it is
/// inferred from the rest of the request, which is what this server did before
/// it read the field at all.
fn resolve_client_type(
    declared: Option<&str>,
    grant_types: &[String],
    auth_method: TokenEndpointAuthMethod,
    redirect_uris: &[String],
) -> Result<OAuthClientType, ServiceError> {
    match declared {
        Some(value) => parse_declared_client_type(value),
        None => Ok(determine_client_type(
            grant_types,
            auth_method,
            redirect_uris,
        )),
    }
}

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
    // RFC 8252 §7: a native app receives its redirect either on the loopback
    // interface or through a private-use URI scheme, so either shape is the
    // signal. Without the scheme half, an app registering only
    // `com.example.app://cb` would be classified as a browser app and then
    // refused the very scheme that classification exists to permit.
    let has_native_redirect = redirect_uris.iter().any(|u| {
        url::Url::parse(u).is_ok_and(|parsed| match parsed.scheme() {
            "http" => parsed.host_str().is_some_and(db::is_loopback_redirect_host),
            "https" => false,
            _ => true,
        })
    });

    if has_client_credentials_only {
        OAuthClientType::Service
    } else if is_public && has_native_redirect {
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
/// - A 401 `invalid_token` API error if the Bearer token is missing, invalid,
///   or belongs to a non-existent, inactive, or non-dynamically-registered
///   client (RFC 7592 §2.1/§5 make all of these indistinguishable to avoid
///   disclosing client existence).
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
/// - A 401 `invalid_token` API error if the Bearer token is missing, invalid,
///   or belongs to a non-existent, inactive, or non-dynamically-registered
///   client (RFC 7592 §2.3/§5 make all of these indistinguishable to avoid
///   disclosing client existence).
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
/// - A 401 `invalid_token` API error if the Bearer token is missing, invalid,
///   or belongs to a non-existent, inactive, or non-dynamically-registered
///   client (RFC 7592 §2.2/§5 make all of these indistinguishable to avoid
///   disclosing client existence).
/// - `ServiceError::OAuth` if the request body contains invalid metadata.
pub async fn update_client_configuration(
    state: &Arc<AppState>,
    client_id: &str,
    registration_access_token: &str,
    request: RegistrationRequest,
) -> Result<RegistrationResponse, ServiceError> {
    let client =
        lookup_and_verify_registration_token(state, client_id, registration_access_token).await?;

    let mut mutable_request = request;

    // Refuse a request that changes a field fixed at registration, rather than
    // returning 200 for an update that silently did nothing. Runs first
    // because validate_grant_and_response_types take()s
    // token_endpoint_auth_method and substitutes a default.
    reject_immutable_changes(&mutable_request, &client)?;

    // Validate grant/response types (take() empties the request fields)
    let validated = validate_grant_and_response_types(&mut mutable_request)?;

    // Validate redirect URIs (same cardinality + format rules as initial
    // registration). `application_type` is immutable and any restatement has
    // already been checked against it, so the registered type is what the
    // URIs are validated against — the type the client keeps.
    let redirect_uris = validate_redirect_uris(
        &mut mutable_request,
        validated.auth_code_grant,
        client.application_type,
    )?;

    // Build updated registration metadata (cosmetic fields)
    let registration_metadata = mutable_request.registration_metadata();

    // Pairing the two parameters is the mutual-exclusion check (RFC 7591 §2);
    // the shape checks follow.
    let keys = crate::db::ClientKeys::from_stored(
        mutable_request.jwks.take(),
        mutable_request.jwks_uri.take(),
    )
    .map_err(|e| ServiceError::oauth(OAuthErrorCode::InvalidClientMetadata, e.to_string()))?;
    validate_jwks_shape(keys.as_ref())?;

    // PUT is a full replacement, so re-check the auth-method/JWKS
    // relationship enforced at initial registration against the client's
    // (immutable) registered auth method and FAPI profile. A private_key_jwt
    // or self_signed_tls_client_auth client (FAPI or not) needs key material
    // to authenticate at all — the former for client-assertion signing keys,
    // the latter for its certificate, carried in the JWKS's `x5c` member
    // (RFC 8705 §2.2.2). A FAPI 2.0 client of any auth method needs it too —
    // register_client requires jwks/jwks_uri for every FAPI client, not just
    // these two (RFC 7592 §2.2: omitted fields are treated as cleared, so a
    // PUT that drops both would otherwise silently strip a client's only key
    // material).
    if (client.is_fapi()
        || matches!(
            client.token_endpoint_auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt
                | TokenEndpointAuthMethod::SelfSignedTlsClientAuth
        ))
        && keys.is_none()
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "FAPI 2.0, private_key_jwt, or self_signed_tls_client_auth requires jwks or jwks_uri",
        ));
    }

    // self_signed_tls_client_auth's certificate is carried by a key's `x5c`
    // member (RFC 8705 §2.2.2 describes this representation); an inline JWKS
    // replacing the client's key material with none would pass the presence
    // check above but leave the client unable to ever complete mTLS
    // authentication again — see JwkSet::has_x5c. Applies regardless of
    // FAPI status, unlike the algorithm-usability check below (this auth
    // method exists for non-FAPI clients too). A remote jwks_uri can't be
    // inspected synchronously, so this only guards the inline case.
    if client.token_endpoint_auth_method == TokenEndpointAuthMethod::SelfSignedTlsClientAuth
        && let Some(jwks) = keys.as_ref().and_then(crate::db::ClientKeys::inline)
        && !jwks.has_x5c()
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "self_signed_tls_client_auth requires a JWKS key with an x5c certificate",
        ));
    }

    // FAPI 2.0's profile is immutable post-registration (see the comment
    // below), so `client.fapi_profile` already reflects what this update
    // preserves. Only for private_key_jwt: its JWKS carries client-assertion
    // signing keys, so an inline JWKS replacing the client's key material
    // must have at least one key usable with FAPI_ALLOWED — see
    // JwkSet::has_fapi_allowed_key. tls_client_auth/self_signed_tls_client_auth
    // JWKS conveys certificates via x5c instead (RFC 8705 §2.2.2), so this
    // check does not apply to them. A remote jwks_uri can't be inspected
    // synchronously, so this only guards the inline case, same as
    // registration and the admin application API.
    if client.is_fapi()
        && client.token_endpoint_auth_method == TokenEndpointAuthMethod::PrivateKeyJwt
        && let Some(jwks) = keys.as_ref().and_then(crate::db::ClientKeys::inline)
        && !jwks.has_fapi_allowed_key()
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "FAPI 2.0 requires a JWKS key usable with ES256, PS256, or EdDSA",
        ));
    }

    // The five RFC 8705 §2.1.2 certificate-subject parameters are written as a
    // full replacement below, so a PUT that omits them clears them. Checked
    // against the client's registered (immutable) auth method, which is what
    // decides whether the parameters are required at all.
    validate_tls_client_auth_identity(client.token_endpoint_auth_method, &mutable_request)?;

    // Validate the signed-response algorithms with the same validators initial
    // registration uses. The client's FAPI profile is immutable
    // post-registration, so the original profile's restrictions still apply.
    let rsa_key = if state.oidc_rsa_key.is_some() {
        RsaSigningKey::Available
    } else {
        RsaSigningKey::Unavailable
    };
    let algs = validate_signed_response_algs(&mutable_request, rsa_key, client.fapi_profile)?;
    // An update that names no algorithm keeps the one the client registered,
    // rather than re-deriving the server default and moving an ES256 client
    // onto RS256 — see resolve_id_token_alg.
    let id_token_alg = resolve_id_token_alg(
        algs.id_token,
        client.fapi_profile,
        client.id_token_signed_response_alg,
    );

    // The RFC 9101 Request Object commitment and the JWKS backing it are both
    // replaced by this request, so they are checked against each other rather
    // than against what the client registered. A JWKS with no key the verifier
    // could select for the named algorithm shuts both doors at the
    // authorization endpoint, which is how a routine key rotation that swaps
    // key type silently bricks a working client.
    let request_object = validate_request_object_signing(
        mutable_request.request_object_signing_alg.as_deref(),
        mutable_request.require_signed_request_object,
        client.fapi_profile,
        keys.as_ref(),
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

    // RFC 7592 §2.2 is a full replacement: "Valid values of client metadata
    // fields in this request MUST replace, not augment, the values previously
    // associated with this client. Omitted fields MUST be treated as null or
    // empty values by the server, indicating the client's request to delete
    // them from the client's registration." Every field below therefore takes
    // the request's value, cleared when the request omits it — the exceptions
    // being the immutable fields, which are absent from these params and
    // whose restatement `reject_immutable_changes` has already checked, and
    // `client_name`, whose column cannot hold NULL and so falls back to the
    // registration default.
    let updated = db::update_oauth_client_registration(
        &state.store,
        &client.id,
        &UpdateClientRegistrationParams {
            redirect_uris: &redirect_uris,
            grant_types: Some(&validated.grant_types),
            response_types: Some(&validated.response_types),
            keys: keys.as_ref(),
            registration_access_token_hash: &new_reg_token_hash,
            registration_metadata: Some(&registration_metadata),
            userinfo_signed_response_alg: algs.userinfo,
            request_uris: validated_request_uris.as_deref(),
            post_logout_redirect_uris: validated_post_logout_redirect_uris.clone(),
            client_name: mutable_request.client_name.as_deref(),
            software_id: mutable_request.software_id.as_deref(),
            software_version: mutable_request.software_version.as_deref(),
            id_token_signed_response_alg: id_token_alg,
            authorization_signed_response_alg: algs.authorization,
            introspection_signed_response_alg: algs.introspection,
            request_object_signing_alg: request_object.alg,
            require_signed_request_object: if request_object.require_signed {
                Some(true)
            } else {
                None
            },
            tls_client_auth_subject_dn: mutable_request.tls_client_auth_subject_dn.as_deref(),
            tls_client_auth_san_dns: mutable_request.tls_client_auth_san_dns.as_deref(),
            tls_client_auth_san_uri: mutable_request.tls_client_auth_san_uri.as_deref(),
            tls_client_auth_san_ip: mutable_request.tls_client_auth_san_ip.as_deref(),
            tls_client_auth_san_email: mutable_request.tls_client_auth_san_email.as_deref(),
        },
    )
    .await
    .map_err(|e| {
        // `software_id` is indexed, and the store rejects NUL bytes in index
        // values (issue #883). It is the one client-supplied index value a
        // PUT can write, so this is a bad request, not a server fault.
        if let Some(invalid) = e.downcast_ref::<db::InvalidIndexValue>() {
            return ServiceError::oauth(
                OAuthErrorCode::InvalidClientMetadata,
                format!("{} must not contain a NUL (0x00) character", invalid.field),
            );
        }
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
    response.registration_access_token = Some(new_reg_token.into());

    Ok(response)
}

/// Look up a client by `client_id` and verify its registration access token.
///
/// Per RFC 7592 §2.1/2.2/2.3 and the security rationale in §5, *every* failure
/// case returns the **same** HTTP 401 `invalid_token` response, so that a
/// caller who only knows the public `client_id` cannot distinguish:
/// - a `client_id` that does not exist,
/// - a client that is inactive / was deprovisioned,
/// - a client created through the admin UI (no registration access token), and
/// - a dynamically-registered client presented with the wrong bearer token.
///
/// Any distinction (e.g. a 404 for a missing client, or a different 401 message
/// for an admin-created client) leaks client existence and type, which §5
/// forbids. Detailed diagnostics are emitted to the server log only.
///
/// A genuine database outage is the one exception: it surfaces as an HTTP 500
/// `server_error` because it is a transient fault independent of the queried
/// `client_id` and carries no information about whether the client exists.
///
/// On the `client_id`-does-not-exist branch the presented token is additionally
/// revoked, per the `SHOULD` that accompanies the 401 in §2.1/2.2/2.3. A token
/// offered against a `client_id` that was never issued it is either a guess or a
/// leaked credential; either way it has no legitimate use, and it may still be
/// live for the client it really belongs to. Revocation is best-effort and never
/// changes the response — see [`db::revoke_registration_access_token`].
async fn lookup_and_verify_registration_token(
    state: &Arc<AppState>,
    client_id: &str,
    token: &str,
) -> Result<OAuthClient, ServiceError> {
    // RFC 6750 §3.1: registration endpoints are OAuth protected resources, so a
    // bearer-token failure is `invalid_token`, not the client-authentication
    // error `invalid_client`. The exact same response is reused for every
    // rejection below to avoid disclosing client existence or type.
    let invalid_token = || {
        ServiceError::api(
            StatusCode::UNAUTHORIZED,
            OAuthErrorCode::InvalidToken.as_str(),
            "Invalid registration access token",
        )
    };

    let client = match db::get_oauth_client_by_client_id(&state.store, client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            tracing::debug!("RFC 7592 token verification failed: client_id {client_id} not found");
            revoke_token_for_unknown_client(state, token).await;
            return Err(invalid_token());
        }
        Err(e) => {
            // A real database failure is not an auth determination; keep it as
            // an internal error so monitoring sees the outage rather than
            // misclassifying it as an invalid registration access token.
            tracing::error!("DB error looking up client {client_id}: {e}");
            return Err(ServiceError::Internal("Database error".to_string()));
        }
    };

    if !client.active {
        tracing::debug!("RFC 7592 token verification failed: client_id {client_id} is inactive");
        return Err(invalid_token());
    }

    let stored_hash = match client.registration_access_token_hash.as_deref() {
        Some(hash) => hash,
        None => {
            tracing::debug!(
                "RFC 7592 token verification failed: client_id {client_id} has no \
                 registration access token (admin-created client)"
            );
            return Err(invalid_token());
        }
    };

    let provided_hash = hash_token(token);
    let is_match: bool = provided_hash
        .as_bytes()
        .ct_eq(stored_hash.as_bytes())
        .into();

    if !is_match {
        tracing::debug!(
            "RFC 7592 token verification failed: bearer token does not match the stored \
             hash for client_id {client_id}"
        );
        return Err(invalid_token());
    }

    Ok(client)
}

/// Revoke a registration access token presented against an unknown `client_id`.
///
/// RFC 7592 §2.1 (and identically §2.2, and §2.3 with "if possible"):
///
/// > If the client does not exist on this server, the server MUST respond with
/// > HTTP 401 Unauthorized and the registration access token used to make this
/// > request SHOULD be immediately revoked.
///
/// Best-effort by construction: the outcome never reaches the response, so a
/// failed revocation cannot turn into a distinguisher, and a database error here
/// must not mask the 401 the caller is owed. The token is hashed the same way it
/// was stored, so a miss costs one indexed lookup and nothing else.
async fn revoke_token_for_unknown_client(state: &Arc<AppState>, token: &str) {
    match db::revoke_registration_access_token(&state.store, &hash_token(token)).await {
        Ok(Some(owner_id)) => {
            tracing::warn!(
                "RFC 7592: revoked the registration access token of client {owner_id} after it \
                 was presented against a client_id that does not exist"
            );
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("RFC 7592: failed to revoke a misdirected registration token: {e}");
        }
    }
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
        jwks: client
            .keys
            .as_ref()
            .and_then(crate::db::ClientKeys::inline)
            .and_then(|set| serde_json::to_value(set).ok()),
        jwks_uri: client
            .keys
            .as_ref()
            .and_then(crate::db::ClientKeys::uri)
            .map(String::from),
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

/// The shared redirect-URI rule as it applies to a native client, exposed for
/// property-based testing.
///
/// Only available when the `test-utils` feature is enabled.
#[cfg(feature = "test-utils")]
pub fn validate_redirect_uri_for_test(uri: &str) -> Result<(), ServiceError> {
    db::validate_redirect_uri(uri, crate::db::OAuthClientType::Native).map_err(|e| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidRedirectUri,
            format!("Invalid redirect URI '{uri}': {e}"),
        )
    })
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
