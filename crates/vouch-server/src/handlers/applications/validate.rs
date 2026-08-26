// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared input validation and record construction for OAuth application
//! create/update.
//!
//! The API handlers (`api.rs`) and web form handlers (`web.rs`) accept the
//! same application fields and enforce identical rules; only the error
//! rendering differs (JSON [`ServiceError`] vs HTML template). Each function
//! here is called by both the API and the web variant of the handler, so the
//! FAPI-sensitive field wiring is maintained in exactly one place.

use axum::http::StatusCode;

use crate::db::{
    AccessScope, CreateOAuthClientParams, FapiProfile, JwsAlgorithm, OAuthClient, OAuthClientType,
    RegistrationSource, TokenEndpointAuthMethod, jwks_has_fapi_allowed_key, jwks_has_x5c,
};
use crate::error::ServiceError;
use crate::services::oidc::ResourceUri;

use super::{validate_post_logout_redirect_uris, validate_redirect_uris};

/// A validation failure: a machine-readable code plus a human message.
#[derive(Debug)]
pub(super) enum AppValidationError {
    EmptyName,
    InvalidApplicationType,
    InvalidAccessScope,
    InvalidFapiProfile(String),
    MissingRedirectUris,
    InvalidRedirectUris(Vec<String>),
    InvalidPostLogoutRedirectUris(Vec<String>),
    InvalidResourceUri {
        uri: String,
        detail: String,
    },
    /// RFC 7591 §2: `jwks` and `jwks_uri` MUST NOT both be present.
    JwksMutuallyExclusive,
    FapiRequiresConfidentialClient,
    FapiMissingJwks,
    AuthMethodMissingJwks,
    FapiDowngradeUnsupported,
    FapiJwksNoAllowedAlgorithm,
    SelfSignedJwksMissingX5c,
    JwksNotJson,
    JwksMissingKeys,
    JwksInvalidKeyShape,
    InvalidJwksUri,
}

impl AppValidationError {
    /// Machine-readable error code (stable API contract).
    pub(super) fn code(&self) -> &'static str {
        match self {
            Self::EmptyName => "invalid_name",
            Self::InvalidApplicationType => "invalid_type",
            Self::InvalidAccessScope => "invalid_access_scope",
            Self::InvalidFapiProfile(_) => "invalid_fapi_profile",
            Self::MissingRedirectUris | Self::InvalidRedirectUris(_) => "invalid_redirect_uris",
            Self::JwksMutuallyExclusive => "invalid_client_metadata",
            Self::InvalidPostLogoutRedirectUris(_) => "invalid_post_logout_redirect_uris",
            Self::InvalidResourceUri { .. } => "invalid_resource_uri",
            Self::FapiRequiresConfidentialClient => "invalid_fapi_profile",
            Self::FapiMissingJwks | Self::AuthMethodMissingJwks => "missing_jwks",
            Self::FapiDowngradeUnsupported => "fapi_downgrade_unsupported",
            Self::FapiJwksNoAllowedAlgorithm => "fapi_jwks_algorithm_unsupported",
            Self::SelfSignedJwksMissingX5c => "self_signed_jwks_missing_x5c",
            Self::JwksNotJson | Self::JwksMissingKeys | Self::JwksInvalidKeyShape => "invalid_jwks",
            Self::InvalidJwksUri => "invalid_jwks_uri",
        }
    }

    /// Human-readable error message.
    pub(super) fn message(&self) -> String {
        match self {
            Self::EmptyName => "Application name is required".to_string(),
            Self::InvalidApplicationType => {
                "Invalid application type. Must be: web, native, spa, or service".to_string()
            }
            Self::InvalidAccessScope => {
                "Invalid access_scope. Valid values: personal, organization, public".to_string()
            }
            Self::InvalidFapiProfile(p) => {
                format!("Invalid fapi_profile '{p}'. Valid values: none, fapi2_security")
            }
            Self::MissingRedirectUris => "At least one redirect URI is required".to_string(),
            Self::JwksMutuallyExclusive => {
                "Provide either a JWKS or a JWKS URI, not both".to_string()
            }
            Self::InvalidRedirectUris(invalid) => format!(
                "Invalid redirect URI(s): {}. Each URI must use https://, or http:// with \
                 localhost, 127.0.0.1, or [::1], and must not contain a fragment. \
                 A custom scheme is accepted only for native applications.",
                invalid.join(", ")
            ),
            Self::InvalidPostLogoutRedirectUris(invalid) => format!(
                "Invalid post_logout_redirect_uri(s): {}. \
                 Each URI must be a valid http:// or https:// URL without a fragment.",
                invalid.join(", ")
            ),
            Self::InvalidResourceUri { uri, detail } => format!(
                "Invalid resource URI '{uri}': {detail}. \
                 Resource URIs must be absolute URIs without fragment components."
            ),
            Self::FapiRequiresConfidentialClient => {
                "FAPI 2.0 Security Profile requires a confidential client type (web or service)"
                    .to_string()
            }
            Self::FapiMissingJwks => {
                "FAPI 2.0 requires jwks or jwks_uri for private_key_jwt authentication".to_string()
            }
            Self::AuthMethodMissingJwks => {
                "This application authenticates with a method that requires key material \
                 (private_key_jwt or self_signed_tls_client_auth), so it must keep a jwks or \
                 jwks_uri. Provide one, or change its authentication method first."
                    .to_string()
            }
            Self::FapiDowngradeUnsupported => {
                "A FAPI 2.0 application cannot be changed to a standard profile. \
                 Create a new standard application instead."
                    .to_string()
            }
            Self::FapiJwksNoAllowedAlgorithm => {
                "FAPI 2.0 requires a JWKS key usable with ES256, PS256, or EdDSA \
                 (RFC 7523 client-assertion signing). None of the configured keys \
                 are usable: each either declares an alg outside that set, has a \
                 kty the signing-key matcher can't select for those algorithms, or \
                 is marked for a non-signing use. Add a compatible key, or adjust \
                 an existing one's alg/kty/use."
                    .to_string()
            }
            Self::SelfSignedJwksMissingX5c => {
                "This application authenticates with self_signed_tls_client_auth, whose \
                 certificate is carried in a JWKS key's x5c member (RFC 8705 §2.2.2). None \
                 of the configured keys carry one, so the application could never complete \
                 mTLS authentication. Add a key with an x5c certificate."
                    .to_string()
            }
            Self::JwksNotJson => "JWKS must be valid JSON".to_string(),
            Self::JwksMissingKeys => {
                "JWKS must be a JSON object with a non-empty \"keys\" array".to_string()
            }
            Self::JwksInvalidKeyShape => {
                "JWKS contains a key with an invalid field type (e.g. \"alg\" or \"use\" \
                 must be a string)"
                    .to_string()
            }
            Self::InvalidJwksUri => "JWKS URI must be a valid https:// URL".to_string(),
        }
    }
}

impl From<AppValidationError> for ServiceError {
    fn from(err: AppValidationError) -> Self {
        ServiceError::api(StatusCode::BAD_REQUEST, err.code(), err.message())
    }
}

/// Raw application fields for create requests.
pub(super) struct CreateAppInput<'a> {
    pub name: &'a str,
    pub application_type: &'a str,
    pub redirect_uris: &'a [String],
    pub resource_uris: &'a [String],
    /// `None` means not provided (field absent); `Some(&[])` is accepted (no post-logout URIs).
    pub post_logout_redirect_uris: Option<&'a [String]>,
    pub access_scope: Option<&'a str>,
    pub fapi_profile: Option<&'a str>,
    pub jwks: Option<&'a str>,
    pub jwks_uri: Option<&'a str>,
}

/// Validated create fields, ready for `CreateOAuthClientParams`.
#[derive(Debug)]
pub(super) struct ValidatedCreateApp<'a> {
    /// Trimmed, non-empty application name.
    pub name: &'a str,
    pub app_type: OAuthClientType,
    pub access_scope: AccessScope,
    pub is_fapi: bool,
    /// RFC 7591 §2 key material: a parsed inline JWKS with a non-empty `keys`
    /// array, or a trimmed https JWKS URI. Never both.
    pub keys: Option<crate::db::ClientKeys>,
}

/// Validate the format of a create-application request.
///
/// Pure format validation — safe to call before authentication so malformed
/// requests incur no DB cost. Handler-specific checks (access scope, org
/// membership) stay in the handlers.
pub(super) fn validate_create_application<'a>(
    input: CreateAppInput<'a>,
) -> Result<ValidatedCreateApp<'a>, AppValidationError> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err(AppValidationError::EmptyName);
    }

    let app_type = input
        .application_type
        .parse::<OAuthClientType>()
        .map_err(|_| AppValidationError::InvalidApplicationType)?;

    // For non-service apps, at least one redirect URI is required
    if !matches!(app_type, OAuthClientType::Service) && input.redirect_uris.is_empty() {
        return Err(AppValidationError::MissingRedirectUris);
    }

    validate_redirect_uris(input.redirect_uris, app_type)
        .map_err(AppValidationError::InvalidRedirectUris)?;

    if let Some(uris) = input.post_logout_redirect_uris {
        validate_post_logout_redirect_uris(uris)
            .map_err(AppValidationError::InvalidPostLogoutRedirectUris)?;
    }

    // Validate resource URIs per RFC 8707 (absolute URI, no fragment).
    validate_resource_uris(input.resource_uris)?;

    let access_scope = match input.access_scope {
        None => AccessScope::default(),
        Some(s) => s
            .parse::<AccessScope>()
            .map_err(|_| AppValidationError::InvalidAccessScope)?,
    };

    let is_fapi = match input.fapi_profile {
        None => false,
        Some(p) => validate_fapi_profile_value(p)?,
    };

    // FAPI validation: must be a confidential client type
    if is_fapi && !matches!(app_type, OAuthClientType::Web | OAuthClientType::Service) {
        return Err(AppValidationError::FapiRequiresConfidentialClient);
    }

    let jwks_trimmed = trim_nonempty(input.jwks);
    let jwks_uri = trim_nonempty(input.jwks_uri);

    // FAPI validation: require JWKS or JWKS URI
    if is_fapi && jwks_trimmed.is_none() && jwks_uri.is_none() {
        return Err(AppValidationError::FapiMissingJwks);
    }

    let jwks = jwks_trimmed.map(parse_jwks).transpose()?;
    validate_jwks_uri(jwks_uri)?;

    // FAPI validation: an inline JWKS must have at least one key the
    // FAPI_ALLOWED validator can actually select (see jwks_has_fapi_allowed_key).
    // A jwks_uri can't be inspected synchronously, so this only guards the
    // inline case; the same is true of validate_update_fapi.
    if is_fapi
        && let Some(ref parsed_jwks) = jwks
        && !crate::db::parse_jwks_set(parsed_jwks).is_ok_and(|set| jwks_has_fapi_allowed_key(&set))
    {
        return Err(AppValidationError::FapiJwksNoAllowedAlgorithm);
    }

    Ok(ValidatedCreateApp {
        name,
        app_type,
        access_scope,
        is_fapi,
        keys: client_keys(jwks, jwks_uri)?,
    })
}

/// Pair the two key parameters into the one value the rest of the code takes.
///
/// RFC 7591 §2: "The "jwks_uri" and "jwks" parameters MUST NOT both be present
/// in the same request or response." This path used to parse both and keep
/// them, which is how a self-service application could hold a state dynamic
/// client registration rejects.
fn client_keys(
    jwks: Option<serde_json::Value>,
    jwks_uri: Option<&str>,
) -> Result<Option<crate::db::ClientKeys>, AppValidationError> {
    crate::db::ClientKeys::from_stored(jwks, jwks_uri.map(String::from))
        .map_err(|_| AppValidationError::JwksMutuallyExclusive)
}

/// Raw application fields for update requests.
///
/// `None` means the field was not provided (API PATCH semantics); web form
/// handlers pass `Some` for fields the form always submits.
pub(super) struct UpdateAppInput<'a> {
    pub redirect_uris: Option<&'a [String]>,
    pub resource_uris: Option<&'a [String]>,
    /// `None` = field absent (preserve existing). `Some(&[])` = explicitly clear the list.
    pub post_logout_redirect_uris: Option<&'a [String]>,
    pub access_scope: Option<&'a str>,
    pub fapi_profile: Option<&'a str>,
    pub jwks: Option<&'a str>,
    pub jwks_uri: Option<&'a str>,
}

/// Validated update fields (format phase only).
#[derive(Debug)]
pub(super) struct ValidatedUpdateApp<'a> {
    pub is_fapi: bool,
    /// Whether `fapi_profile` was present in the request at all. A provided
    /// non-FAPI value is an explicit transition away from FAPI; an absent
    /// field preserves the existing profile.
    pub fapi_profile_provided: bool,
    /// Parsed access scope (`None` = field absent, preserve existing).
    pub access_scope: Option<AccessScope>,
    /// RFC 7591 §2 key material: a parsed inline JWKS with a non-empty `keys`
    /// array, or a trimmed https JWKS URI. Never both.
    pub keys: Option<crate::db::ClientKeys>,
    /// Redirect URIs from the request (`None` = field absent, `Some(&[])` = explicitly cleared).
    pub redirect_uris: Option<&'a [String]>,
    /// Post-logout redirect URIs (`None` = preserve existing, `Some(&[])` = explicitly clear).
    pub post_logout_redirect_uris: Option<&'a [String]>,
}

/// Validate the format of an update-application request.
///
/// Fields are validated only if provided; absent fields keep their existing
/// values. Pure format validation — safe to call before authentication.
/// FAPI rules that depend on the existing client record are checked by
/// [`validate_update_fapi`] after the ownership check.
pub(super) fn validate_update_format<'a>(
    input: UpdateAppInput<'a>,
) -> Result<ValidatedUpdateApp<'a>, AppValidationError> {
    // Redirect URIs are validated in `validate_update_fapi`, which is the stage
    // that has the persisted client type — the type decides whether a custom
    // URI scheme may be registered, and an update cannot change it.

    if let Some(uris) = input.resource_uris {
        validate_resource_uris(uris)?;
    }

    if let Some(uris) = input.post_logout_redirect_uris
        && !uris.is_empty()
    {
        validate_post_logout_redirect_uris(uris)
            .map_err(AppValidationError::InvalidPostLogoutRedirectUris)?;
    }

    let access_scope = match input.access_scope {
        None => None,
        Some(s) => Some(
            s.parse::<AccessScope>()
                .map_err(|_| AppValidationError::InvalidAccessScope)?,
        ),
    };

    let is_fapi = match input.fapi_profile {
        None => false,
        Some(p) => validate_fapi_profile_value(p)?,
    };

    let jwks = trim_nonempty(input.jwks).map(parse_jwks).transpose()?;
    let jwks_uri = trim_nonempty(input.jwks_uri);
    validate_jwks_uri(jwks_uri)?;

    Ok(ValidatedUpdateApp {
        is_fapi,
        fapi_profile_provided: input.fapi_profile.is_some(),
        access_scope,
        keys: client_keys(jwks, jwks_uri)?,
        redirect_uris: input.redirect_uris,
        post_logout_redirect_uris: input.post_logout_redirect_uris,
    })
}

/// The FAPI profile the client will have once this update is applied: the
/// requested profile when `fapi_profile` was provided, otherwise the client's
/// current profile (an absent field preserves it — see [`ValidatedUpdateApp`]).
///
/// Shared by [`validate_update_fapi`] (to decide whether the FAPI-specific
/// checks apply) and [`compute_fapi_update_fields`] (to build the persisted
/// `fapi_profile`), so the two cannot disagree about what "the client will be
/// FAPI after this update" means.
fn effective_fapi_profile(validated: &ValidatedUpdateApp<'_>, client: &OAuthClient) -> FapiProfile {
    if validated.is_fapi {
        FapiProfile::Fapi2Security
    } else if validated.fapi_profile_provided {
        FapiProfile::None
    } else {
        client.fapi_profile
    }
}

/// The token endpoint auth method the client will have once this update is
/// applied.
///
/// An explicit `fapi_profile` upgrade forces `private_key_jwt` only when the
/// client's stored method isn't already FAPI-compatible — a stored mTLS
/// method (`tls_client_auth`, `self_signed_tls_client_auth`) is preserved
/// rather than silently converted, since that conversion would end mTLS
/// authentication for a method RFC 7592 otherwise treats as immutable. A
/// stored non-FAPI-compatible method (e.g. `client_secret_basic`) is still
/// forced to `private_key_jwt`, so an upgrade from a secret-based method
/// keeps the existing lockout protection: it has no signing key to fall back
/// on otherwise.
///
/// Shared by [`validate_update_fapi`] (to decide whether the JWKS
/// algorithm-usability check applies) and [`compute_fapi_update_fields`] (to
/// build the persisted `token_endpoint_auth_method`), so the two cannot
/// disagree about what "the client will authenticate with after this
/// update" means — mirrors [`effective_fapi_profile`] above.
fn effective_token_endpoint_auth_method(
    validated: &ValidatedUpdateApp<'_>,
    client: &OAuthClient,
) -> TokenEndpointAuthMethod {
    if validated.is_fapi && !client.token_endpoint_auth_method.is_fapi_compatible() {
        TokenEndpointAuthMethod::PrivateKeyJwt
    } else {
        client.token_endpoint_auth_method
    }
}

/// Validate semantic rules for an update against the existing client record.
///
/// Call after authentication and the ownership check.  This covers rules that
/// depend on persisted state (e.g. the client's application_type) and
/// therefore cannot run in the pre-auth format pass.
pub(super) fn validate_update_fapi(
    validated: &ValidatedUpdateApp<'_>,
    client: &OAuthClient,
) -> Result<(), AppValidationError> {
    // An explicit empty redirect_uris list is only valid for service apps.
    // We skip this check in the pre-auth format pass (application_type=None
    // there), and enforce it here once we have the persisted client type.
    if let Some(uris) = validated.redirect_uris {
        if uris.is_empty() && !matches!(client.application_type, OAuthClientType::Service) {
            return Err(AppValidationError::MissingRedirectUris);
        }
        validate_redirect_uris(uris, client.application_type)
            .map_err(AppValidationError::InvalidRedirectUris)?;
    }

    // A FAPI client authenticates with private_key_jwt and therefore has no
    // client secret. Moving it to a standard profile would switch it to
    // client_secret_basic without minting one, so every subsequent token
    // request would fail with invalid_client and the application would be
    // unusable with no way back. Refuse the explicit transition outright —
    // this check is about the request declaring a downgrade, not about the
    // effective post-merge profile below.
    if !validated.is_fapi && validated.fapi_profile_provided && client.is_fapi() {
        return Err(AppValidationError::FapiDowngradeUnsupported);
    }

    // Everything below applies whenever the client is FAPI *after* this
    // update — whether the request just declared it, or it stays FAPI
    // because `fapi_profile` was omitted. A JWKS-only edit to an
    // already-FAPI client must be validated exactly like a fresh upgrade:
    // its new JWKS can strand the client the same way.
    if effective_fapi_profile(validated, client) == FapiProfile::None {
        return Ok(());
    }

    // FAPI validation: must be a confidential client type
    if !matches!(
        client.application_type,
        OAuthClientType::Web | OAuthClientType::Service
    ) {
        return Err(AppValidationError::FapiRequiresConfidentialClient);
    }

    // FAPI validation: require JWKS or JWKS URI (request or existing)
    if validated.keys.is_none()
        && client
            .keys
            .as_ref()
            .and_then(crate::db::ClientKeys::inline)
            .is_none()
        && client
            .keys
            .as_ref()
            .and_then(crate::db::ClientKeys::uri)
            .is_none()
    {
        return Err(AppValidationError::FapiMissingJwks);
    }

    // Only for private_key_jwt: its JWKS carries client-assertion signing
    // keys, so an inline JWKS (submitted or already on the client) must have
    // at least one key usable with FAPI_ALLOWED. tls_client_auth/
    // self_signed_tls_client_auth JWKS conveys certificates via x5c instead
    // (RFC 8705 §2.2.2), so this check does not apply to them. Uses the same
    // effective-auth-method computation `compute_fapi_update_fields` persists
    // by, so the two cannot disagree about which clients this check covers.
    if effective_token_endpoint_auth_method(validated, client)
        == TokenEndpointAuthMethod::PrivateKeyJwt
        && let Some(jwks) = validated
            .keys
            .as_ref()
            .and_then(crate::db::ClientKeys::inline)
            .or(client.keys.as_ref().and_then(crate::db::ClientKeys::inline))
        && !crate::db::parse_jwks_set(jwks).is_ok_and(|set| jwks_has_fapi_allowed_key(&set))
    {
        return Err(AppValidationError::FapiJwksNoAllowedAlgorithm);
    }

    Ok(())
}

/// Caller-specific inputs for manual application creation.
///
/// Everything else in [`CreateOAuthClientParams`] is identical between the
/// API and web-form create paths and is wired by [`build_create_params`].
pub(super) struct CreateAppContext<'a> {
    pub user_id: &'a str,
    pub description: Option<&'a str>,
    pub redirect_uris: &'a [String],
    pub resource_uris: &'a [String],
    /// `None` or empty → no post-logout redirect URIs stored.
    pub post_logout_redirect_uris: Option<&'a [String]>,
    pub access_scope: AccessScope,
    pub org_id: Option<&'a str>,
}

/// Build the [`CreateOAuthClientParams`] for a manually registered
/// application (API or web form).
///
/// FAPI 2.0 clients get `private_key_jwt` authentication, their validated
/// JWKS, and DPoP-bound access tokens wired at creation time. All fields not
/// derived from the validated input or the caller context are fixed for
/// manual registration (RFC 7591 dynamic registration is a separate
/// subsystem with its own defaults).
pub(super) fn build_create_params<'a>(
    validated: &'a ValidatedCreateApp<'a>,
    ctx: CreateAppContext<'a>,
) -> CreateOAuthClientParams<'a> {
    let is_fapi = validated.is_fapi;
    CreateOAuthClientParams {
        user_id: Some(ctx.user_id),
        name: validated.name,
        description: ctx.description,
        application_type: validated.app_type,
        redirect_uris: ctx.redirect_uris,
        access_scope: ctx.access_scope,
        org_id: ctx.org_id,
        resource_uris: ctx.resource_uris,
        // RFC 7591 §2 (https://www.rfc-editor.org/rfc/rfc7591#section-2):
        // > "none": The client is a public client as defined in OAuth 2.0,
        // > Section 2.1, and does not have a client secret.
        token_endpoint_auth_method: if is_fapi {
            TokenEndpointAuthMethod::PrivateKeyJwt
        } else if validated.app_type.requires_secret() {
            TokenEndpointAuthMethod::ClientSecretBasic
        } else {
            TokenEndpointAuthMethod::None
        },
        keys: if is_fapi {
            validated.keys.as_ref()
        } else {
            None
        },
        fapi_profile: if is_fapi {
            Some(FapiProfile::Fapi2Security)
        } else {
            None
        },
        dpop_bound_access_tokens: if is_fapi { Some(true) } else { None },
        grant_types: None,
        response_types: None,
        software_id: None,
        software_version: None,
        registration_source: RegistrationSource::Manual,
        registration_access_token_hash: None,
        registration_metadata: None,
        id_token_signed_response_alg: JwsAlgorithm::Rs256,
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        tls_client_auth_san_ip: None,
        tls_client_auth_san_email: None,
        tls_client_certificate_bound_access_tokens: None,
        authorization_signed_response_alg: None,
        introspection_signed_response_alg: None,
        request_object_signing_alg: None,
        require_signed_request_object: None,
        userinfo_signed_response_alg: None,
        request_uris: None,
        post_logout_redirect_uris: ctx
            .post_logout_redirect_uris
            .filter(|v| !v.is_empty())
            .map(<[String]>::to_vec),
    }
}

/// FAPI-related fields for an update, merged against the existing client.
#[derive(Debug)]
pub(super) struct FapiUpdateFields<'a> {
    pub fapi_profile: FapiProfile,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub keys: Option<&'a crate::db::ClientKeys>,
    pub dpop_bound_access_tokens: bool,
}

/// Merge the FAPI-related fields of an update request with the existing
/// client record.
///
/// An absent `fapi_profile` preserves the client's current profile, auth
/// method, JWKS, and DPoP binding. A provided FAPI profile enforces DPoP and
/// an auth method — see [`effective_token_endpoint_auth_method`] for the
/// forcing rule. A provided non-FAPI value clears the profile, JWKS, and
/// DPoP binding of a client that was not already FAPI; downgrading a FAPI
/// client is rejected upstream by [`validate_update_fapi`].
pub(super) fn compute_fapi_update_fields<'a>(
    validated: &'a ValidatedUpdateApp<'_>,
    client: &'a OAuthClient,
) -> Result<FapiUpdateFields<'a>, AppValidationError> {
    let is_fapi = validated.is_fapi;
    let fapi_profile = effective_fapi_profile(validated, client);
    let token_endpoint_auth_method = effective_token_endpoint_auth_method(validated, client);

    // One value, so the merge cannot take the inline key set from the update
    // and the URI from the stored client and end up holding both — which the
    // two independent branches this replaces could do.
    let keys = if validated.keys.is_some() {
        validated.keys.as_ref()
    } else if !is_fapi && validated.fapi_profile_provided {
        None
    } else {
        client.keys.as_ref()
    };

    // Leaving the FAPI profile stops *mandating* DPoP; it does not mean the
    // operator asked to turn it off. `dpop_bound_access_tokens` is not part of
    // the update request, so forcing it false here silently downgrades every
    // token the client is issued from sender-constrained to bearer.
    let dpop_bound_access_tokens = if is_fapi {
        true
    } else {
        client.dpop_bound_access_tokens
    };

    // A `private_key_jwt` client authenticates with a key and has no secret to
    // fall back on; a `self_signed_tls_client_auth` client's certificate is
    // carried in the JWKS's `x5c` member (RFC 8705 §2.2.2). Either way, a
    // result with neither `jwks` nor `jwks_uri` can never authenticate again
    // and cannot be repaired through this endpoint. Refuse rather than
    // persist it, whatever combination of fields produced it.
    if matches!(
        token_endpoint_auth_method,
        TokenEndpointAuthMethod::PrivateKeyJwt | TokenEndpointAuthMethod::SelfSignedTlsClientAuth
    ) && keys.is_none()
    {
        return Err(AppValidationError::AuthMethodMissingJwks);
    }

    // self_signed_tls_client_auth's certificate is carried by a key's `x5c`
    // member; an inline JWKS with none anywhere would pass the presence
    // check above but leave the client unable to ever complete mTLS
    // authentication — see db::jwks_has_x5c. Applies to both a freshly
    // submitted and a stored (pre-existing) inline JWKS, and regardless of
    // FAPI status (this auth method exists for non-FAPI clients too) —
    // this function runs on every update, unlike the FAPI-gated checks in
    // `validate_update_fapi`. A remote jwks_uri can't be inspected
    // synchronously, so this only guards the inline case.
    if token_endpoint_auth_method == TokenEndpointAuthMethod::SelfSignedTlsClientAuth
        && let Some(jwks) = keys.and_then(crate::db::ClientKeys::inline)
        && !crate::db::parse_jwks_set(jwks).is_ok_and(|set| jwks_has_x5c(&set))
    {
        return Err(AppValidationError::SelfSignedJwksMissingX5c);
    }

    Ok(FapiUpdateFields {
        fapi_profile,
        token_endpoint_auth_method,
        keys,
        dpop_bound_access_tokens,
    })
}

fn trim_nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

/// Parse a `fapi_profile` string into a boolean `is_fapi` flag.
///
/// Returns `Ok(true)` for `"fapi2_security"` and `Ok(false)` for the
/// accepted non-FAPI sentinels: `"none"` (the canonical `FapiProfile` wire
/// value) and `""` (the web form's radio-button value for the standard
/// profile). Any other value is rejected with
/// [`AppValidationError::InvalidFapiProfile`].
fn validate_fapi_profile_value(p: &str) -> Result<bool, AppValidationError> {
    match p {
        "fapi2_security" => Ok(true),
        "none" | "" => Ok(false),
        _ => Err(AppValidationError::InvalidFapiProfile(p.to_string())),
    }
}

fn validate_resource_uris(uris: &[String]) -> Result<(), AppValidationError> {
    for uri in uris {
        if let Err(e) = ResourceUri::parse(uri) {
            return Err(AppValidationError::InvalidResourceUri {
                uri: uri.clone(),
                detail: e.to_string(),
            });
        }
    }
    Ok(())
}

fn parse_jwks(jwks_json: &str) -> Result<serde_json::Value, AppValidationError> {
    let val = serde_json::from_str::<serde_json::Value>(jwks_json)
        .map_err(|_| AppValidationError::JwksNotJson)?;
    if !val
        .get("keys")
        .is_some_and(|k| k.is_array() && !k.as_array().is_some_and(|a| a.is_empty()))
    {
        return Err(AppValidationError::JwksMissingKeys);
    }
    // Reject a type-invalid member (e.g. "alg": true) through the same typed
    // representation the RFC 7523 client-assertion verifier uses at runtime
    // — see db::JwkSet. Otherwise the application would be created/updated
    // here but permanently unable to authenticate once the runtime verifier
    // fails to parse the same document.
    if crate::db::parse_jwks_set(&val).is_err() {
        return Err(AppValidationError::JwksInvalidKeyShape);
    }
    Ok(val)
}

fn validate_jwks_uri(jwks_uri: Option<&str>) -> Result<(), AppValidationError> {
    if let Some(uri) = jwks_uri {
        match url::Url::parse(uri) {
            Ok(parsed) if parsed.scheme() == "https" => {}
            _ => return Err(AppValidationError::InvalidJwksUri),
        }
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    fn fapi_jwks_json() -> String {
        serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}]}).to_string()
    }

    #[test]
    fn create_params_wire_fapi_fields() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        let jwks = fapi_jwks_json();
        let validated = validate_create_application(CreateAppInput {
            name: "Payments",
            application_type: "web",
            redirect_uris: &redirect_uris,
            resource_uris: &[],
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: Some("fapi2_security"),
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid FAPI create input");

        let params = build_create_params(
            &validated,
            CreateAppContext {
                user_id: "user-1",
                description: None,
                redirect_uris: &redirect_uris,
                resource_uris: &[],
                post_logout_redirect_uris: None,
                access_scope: AccessScope::Personal,
                org_id: None,
            },
        );

        assert_eq!(
            params.token_endpoint_auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt
        );
        assert_eq!(params.fapi_profile, Some(FapiProfile::Fapi2Security));
        assert_eq!(params.dpop_bound_access_tokens, Some(true));
        assert!(params.keys.is_some(), "validated JWKS must be stored");
        assert_eq!(params.registration_source, RegistrationSource::Manual);
        assert_eq!(params.id_token_signed_response_alg, JwsAlgorithm::Rs256);
    }

    #[test]
    fn create_params_omit_fapi_fields_for_standard_clients() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        // A JWKS provided without the FAPI profile is not stored.
        let jwks = fapi_jwks_json();
        let validated = validate_create_application(CreateAppInput {
            name: "Plain App",
            application_type: "web",
            redirect_uris: &redirect_uris,
            resource_uris: &[],
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: None,
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid create input");

        let params = build_create_params(
            &validated,
            CreateAppContext {
                user_id: "user-1",
                description: Some("desc"),
                redirect_uris: &redirect_uris,
                resource_uris: &[],
                post_logout_redirect_uris: None,
                access_scope: AccessScope::Personal,
                org_id: None,
            },
        );

        assert_eq!(
            params.token_endpoint_auth_method,
            TokenEndpointAuthMethod::ClientSecretBasic
        );
        assert_eq!(params.fapi_profile, None);
        assert_eq!(params.dpop_bound_access_tokens, None);
        assert!(params.keys.is_none());
        assert!(params.keys.and_then(crate::db::ClientKeys::uri).is_none());
    }

    #[test]
    fn create_params_public_types_get_auth_method_none() {
        let redirect_uris = vec!["https://app.example.com/cb".to_string()];
        for app_type in ["spa", "native"] {
            let validated = validate_create_application(CreateAppInput {
                name: "Public App",
                application_type: app_type,
                redirect_uris: &redirect_uris,
                resource_uris: &[],
                post_logout_redirect_uris: None,
                access_scope: None,
                fapi_profile: None,
                jwks: None,
                jwks_uri: None,
            })
            .expect("valid create input");

            let params = build_create_params(
                &validated,
                CreateAppContext {
                    user_id: "user-1",
                    description: None,
                    redirect_uris: &redirect_uris,
                    resource_uris: &[],
                    post_logout_redirect_uris: None,
                    access_scope: AccessScope::Personal,
                    org_id: None,
                },
            );

            assert_eq!(
                params.token_endpoint_auth_method,
                TokenEndpointAuthMethod::None,
                "{app_type} clients are public (RFC 7591 §2 \"none\")"
            );
        }
    }

    #[test]
    fn create_params_drop_empty_post_logout_uris() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        let post_logout = vec!["https://example.com/bye".to_string()];
        let validated = validate_create_application(CreateAppInput {
            name: "App",
            application_type: "web",
            redirect_uris: &redirect_uris,
            resource_uris: &[],
            post_logout_redirect_uris: Some(&post_logout),
            access_scope: None,
            fapi_profile: None,
            jwks: None,
            jwks_uri: None,
        })
        .expect("valid create input");

        let ctx = |uris: Option<&'static [String]>| CreateAppContext {
            user_id: "user-1",
            description: None,
            redirect_uris: &redirect_uris,
            resource_uris: &[],
            post_logout_redirect_uris: uris,
            access_scope: AccessScope::Personal,
            org_id: None,
        };

        assert_eq!(
            build_create_params(&validated, ctx(None)).post_logout_redirect_uris,
            None
        );
        assert_eq!(
            build_create_params(&validated, ctx(Some(&[]))).post_logout_redirect_uris,
            None,
            "empty list must not be stored as an empty array"
        );

        let params = build_create_params(
            &validated,
            CreateAppContext {
                user_id: "user-1",
                description: None,
                redirect_uris: &redirect_uris,
                resource_uris: &[],
                post_logout_redirect_uris: Some(&post_logout),
                access_scope: AccessScope::Personal,
                org_id: None,
            },
        );
        assert_eq!(params.post_logout_redirect_uris, Some(post_logout.clone()));
    }

    async fn fapi_test_client(state: &crate::AppState, email: &str) -> crate::db::OAuthClient {
        let user = create_test_user(&state.store, email).await;
        let created = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
                jwks: TestJwks::Custom(serde_json::json!({"keys": [{"kty": "EC"}]})),
                dpop_bound_access_tokens: true,
                fapi_profile: Some(FapiProfile::Fapi2Security),
                with_secret: false,
                ..Default::default()
            },
        )
        .await;
        crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists")
    }

    /// A FAPI client whose stored JWKS predates the algorithm-usability
    /// guard: its only key is pinned to `alg: RS256`, unusable under
    /// `FAPI_ALLOWED`.
    async fn stale_jwks_fapi_client(
        state: &crate::AppState,
        email: &str,
    ) -> crate::db::OAuthClient {
        let user = create_test_user(&state.store, email).await;
        let jwks = serde_json::json!({
            "keys": [{"kty": "RSA", "alg": "RS256", "n": "n", "e": "AQAB"}]
        });
        let created = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
                jwks: TestJwks::Custom(jwks),
                dpop_bound_access_tokens: true,
                fapi_profile: Some(FapiProfile::Fapi2Security),
                with_secret: false,
                ..Default::default()
            },
        )
        .await;
        crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists")
    }

    /// A FAPI client whose stored JWKS predates the strict write-path shape
    /// gate: its only key has a type-invalid `alg` (a boolean, not a
    /// string), so it fails `parse_jwks_set` rather than merely lacking a
    /// usable algorithm. Distinguishes "wrong algorithm" (`stale_jwks_fapi_client`)
    /// from "malformed shape" as the reason the stored JWKS is unusable.
    async fn type_invalid_shape_jwks_fapi_client(
        state: &crate::AppState,
        email: &str,
    ) -> crate::db::OAuthClient {
        let user = create_test_user(&state.store, email).await;
        let jwks = serde_json::json!({"keys": [{"kty": "EC", "alg": true}]});
        let created = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
                jwks: TestJwks::Custom(jwks),
                dpop_bound_access_tokens: true,
                fapi_profile: Some(FapiProfile::Fapi2Security),
                with_secret: false,
                ..Default::default()
            },
        )
        .await;
        crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists")
    }

    // A non-FAPI client that authenticates with `private_key_jwt` and carries
    // JWKS — the shape produced by authenticated dynamic registration (RFC
    // 7591) when the caller supplies `token_endpoint_auth_method=private_key_jwt`
    // + `jwks` without requesting a FAPI profile.
    async fn non_fapi_pkjwt_client(state: &crate::AppState, email: &str) -> crate::db::OAuthClient {
        let user = create_test_user(&state.store, email).await;
        let created = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
                jwks: TestJwks::Custom(serde_json::json!({"keys": [{"kty": "EC"}]})),
                fapi_profile: None,
                with_secret: false,
                ..Default::default()
            },
        )
        .await;
        crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists")
    }

    // A non-FAPI client authenticating with `self_signed_tls_client_auth` —
    // the shape produced by RFC 7591 dynamic registration when the caller
    // supplies that auth method plus a JWKS carrying its certificate,
    // without requesting a FAPI profile.
    async fn non_fapi_self_signed_client(
        state: &crate::AppState,
        email: &str,
    ) -> crate::db::OAuthClient {
        let user = create_test_user(&state.store, email).await;
        let created = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::SelfSignedTlsClientAuth),
                jwks: TestJwks::Custom(
                    serde_json::json!({"keys": [{"kty": "RSA", "x5c": ["ZmFrZS1jZXJ0"]}]}),
                ),
                fapi_profile: None,
                with_secret: false,
                ..Default::default()
            },
        )
        .await;
        crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists")
    }

    fn update_input(fapi_profile: Option<&str>) -> ValidatedUpdateApp<'_> {
        validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile,
            jwks: None,
            jwks_uri: None,
        })
        .expect("valid update input")
    }

    #[tokio::test]
    async fn fapi_update_absent_profile_preserves_existing() {
        let state = test_app_state().await;
        let client = fapi_test_client(&state, "fapi-keep@example.com").await;

        let validated = update_input(None);
        let fields = compute_fapi_update_fields(&validated, &client).expect("merge should succeed");

        assert_eq!(fields.fapi_profile, FapiProfile::Fapi2Security);
        assert_eq!(
            fields.token_endpoint_auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt
        );
        assert!(
            fields.keys.is_some_and(|k| k.inline().is_some()),
            "existing JWKS preserved"
        );
        assert!(fields.dpop_bound_access_tokens);
    }

    // Regression for #743: a FAPI client has no client secret, so switching it
    // to client_secret_basic left it unable to authenticate at all. The
    // transition is refused rather than silently producing a broken client.
    #[tokio::test]
    async fn fapi_update_explicit_non_fapi_is_rejected() {
        let state = test_app_state().await;
        let client = fapi_test_client(&state, "fapi-disable@example.com").await;

        let validated = update_input(Some("none"));
        let err =
            validate_update_fapi(&validated, &client).expect_err("FAPI downgrade must be rejected");

        assert_eq!(err.code(), "fapi_downgrade_unsupported");
    }

    // The guard must not fire for a client that was never FAPI: explicitly
    // setting `standard` on a standard client stays a no-op update.
    #[tokio::test]
    async fn non_fapi_client_may_be_set_to_standard() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "std-restate@example.com").await;
        let created = create_test_client(&state.store, &user.id, TestClientSpec::default()).await;
        let client = crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists");

        let validated = update_input(Some("none"));
        validate_update_fapi(&validated, &client).expect("standard -> standard is allowed");

        let fields = compute_fapi_update_fields(&validated, &client).expect("merge should succeed");
        assert_eq!(fields.fapi_profile, FapiProfile::None);
        assert_eq!(
            fields.token_endpoint_auth_method, client.token_endpoint_auth_method,
            "a non-FAPI client keeps its existing auth method"
        );
        assert!(!fields.dpop_bound_access_tokens);
    }

    #[tokio::test]
    async fn fapi_update_enables_fapi_on_standard_client() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "fapi-enable@example.com").await;
        let created = create_test_client(&state.store, &user.id, TestClientSpec::default()).await;
        let client = crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists");

        let jwks = fapi_jwks_json();
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: Some("fapi2_security"),
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid update input");
        let fields = compute_fapi_update_fields(&validated, &client).expect("merge should succeed");

        assert_eq!(fields.fapi_profile, FapiProfile::Fapi2Security);
        assert_eq!(
            fields.token_endpoint_auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt
        );
        assert!(
            fields.keys.is_some_and(|k| k.inline().is_some()),
            "request JWKS used"
        );
        assert!(fields.dpop_bound_access_tokens);
    }

    /// RFC 7591 §2: "The "jwks_uri" and "jwks" parameters MUST NOT both be
    /// present in the same request or response." The self-service path parsed
    /// both and kept them, so an application here could hold a state dynamic
    /// client registration rejects. Pairing them into `ClientKeys` is what
    /// rejects it, on create and on update alike.
    #[test]
    fn supplying_both_key_forms_is_rejected() {
        let jwks = fapi_jwks_json();

        let update = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: None,
            jwks: Some(&jwks),
            jwks_uri: Some("https://client.example/jwks.json"),
        });
        assert!(
            matches!(update, Err(AppValidationError::JwksMutuallyExclusive)),
            "an update carrying both key forms must be rejected"
        );
    }

    // ========================================================================
    // FAPI upgrade requires a usable key (#1003 round 2) — a JWKS made only of
    // alg-pinned keys outside FAPI_ALLOWED (ES256/PS256/EdDSA) leaves a FAPI
    // client with no algorithm it can both present and match a key for: the
    // client-assertion validator rejects RS256 for FAPI clients
    // (jwt_bearer/client_auth.rs), and key selection skips a JWK whose
    // declared alg differs from the assertion's (jwt_bearer/jwks.rs) — so an
    // RS256-only key can never be selected for the algorithms FAPI does
    // allow. This mirrors FapiDowngradeUnsupported: refuse the transition
    // instead of persisting an application that can no longer authenticate.
    // ========================================================================

    fn rs256_only_jwks_json() -> String {
        serde_json::json!({"keys": [{"kty": "RSA", "alg": "RS256", "n": "n", "e": "AQAB"}]})
            .to_string()
    }

    // An RSA key with no `alg` constraint: RS256-shaped key material, but usable
    // with PS256 because nothing pins it to RS256. Distinguishes "no key at all
    // works" from "the alg happens to be spelled out and disallowed" — the guard
    // must key off the declared alg, not the key type.
    fn unpinned_rsa_jwks_json() -> String {
        serde_json::json!({"keys": [{"kty": "RSA", "n": "n", "e": "AQAB"}]}).to_string()
    }

    fn eddsa_jwks_json() -> String {
        serde_json::json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": "x"}]})
            .to_string()
    }

    #[tokio::test]
    async fn fapi_upgrade_rejected_when_jwks_has_no_allowed_algorithm_key() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "fapi-upgrade-rs256@example.com").await;
        let created = create_test_client(&state.store, &user.id, TestClientSpec::default()).await;
        let client = crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists");

        let jwks = rs256_only_jwks_json();
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: Some("fapi2_security"),
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid update input");

        let err = validate_update_fapi(&validated, &client)
            .expect_err("RS256-only JWKS must be rejected for a FAPI upgrade");
        assert_eq!(err.code(), "fapi_jwks_algorithm_unsupported");
    }

    #[tokio::test]
    async fn fapi_upgrade_accepted_when_jwks_has_an_allowed_algorithm_key() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "fapi-upgrade-es256@example.com").await;
        let created = create_test_client(&state.store, &user.id, TestClientSpec::default()).await;
        let client = crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists");

        let jwks = fapi_jwks_json();
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: Some("fapi2_security"),
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid update input");

        validate_update_fapi(&validated, &client)
            .expect("a JWKS with no alg constraint must pass the FAPI upgrade guard");
    }

    #[tokio::test]
    async fn fapi_upgrade_accepted_when_jwks_has_unpinned_rsa_key() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "fapi-upgrade-rsa-unpinned@example.com").await;
        let created = create_test_client(&state.store, &user.id, TestClientSpec::default()).await;
        let client = crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists");

        let jwks = unpinned_rsa_jwks_json();
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: Some("fapi2_security"),
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid update input");

        validate_update_fapi(&validated, &client)
            .expect("an unpinned RSA key (usable with PS256) must pass the FAPI upgrade guard");
    }

    #[tokio::test]
    async fn fapi_upgrade_accepted_when_jwks_has_eddsa_key() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "fapi-upgrade-eddsa@example.com").await;
        let created = create_test_client(&state.store, &user.id, TestClientSpec::default()).await;
        let client = crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists");

        let jwks = eddsa_jwks_json();
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: Some("fapi2_security"),
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid update input");

        validate_update_fapi(&validated, &client)
            .expect("an OKP/EdDSA key must pass the FAPI upgrade guard");
    }

    // The guard also fires on an explicit re-confirmation (fapi_profile
    // resubmitted, not just a fresh non-FAPI -> FAPI transition): swapping the
    // JWKS of an already-FAPI client to an RS256-only key would strand it
    // exactly the same way.
    #[tokio::test]
    async fn fapi_reconfirm_rejected_when_new_jwks_has_no_allowed_algorithm_key() {
        let state = test_app_state().await;
        let client = fapi_test_client(&state, "fapi-reconfirm-rs256@example.com").await;

        let jwks = rs256_only_jwks_json();
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: Some("fapi2_security"),
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid update input");

        let err = validate_update_fapi(&validated, &client)
            .expect_err("RS256-only JWKS must be rejected on FAPI re-confirmation");
        assert_eq!(err.code(), "fapi_jwks_algorithm_unsupported");
    }

    // A JWKS-only update that omits `fapi_profile` must still be validated:
    // the field's absence preserves the client's existing profile, so a
    // client that stays FAPI must have its new JWKS checked for a usable
    // algorithm exactly as it would be on an explicit upgrade.
    #[tokio::test]
    async fn fapi_jwks_only_update_rejected_when_new_jwks_has_no_allowed_algorithm_key() {
        let state = test_app_state().await;
        let client = fapi_test_client(&state, "fapi-jwks-only-rs256@example.com").await;

        let jwks = rs256_only_jwks_json();
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: None,
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid update input");

        let err = validate_update_fapi(&validated, &client).expect_err(
            "RS256-only JWKS must be rejected on a JWKS-only update to an already-FAPI client",
        );
        assert_eq!(err.code(), "fapi_jwks_algorithm_unsupported");
    }

    #[tokio::test]
    async fn fapi_jwks_only_update_accepted_when_new_jwks_has_an_allowed_algorithm_key() {
        let state = test_app_state().await;
        let client = fapi_test_client(&state, "fapi-jwks-only-eddsa@example.com").await;

        let jwks = eddsa_jwks_json();
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: None,
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid update input");

        validate_update_fapi(&validated, &client).expect(
            "a JWKS-only update with an allowed-algorithm key must pass on an already-FAPI client",
        );
    }

    // No false positive: an ordinary update that never touches the JWKS must
    // still pass for an already-FAPI client with a valid existing JWKS — the
    // effective-profile check must not re-reject a client that was already fine.
    #[tokio::test]
    async fn fapi_metadata_only_update_unaffected_by_effective_profile_check() {
        let state = test_app_state().await;
        let client = fapi_test_client(&state, "fapi-metadata-only@example.com").await;

        let redirect_uris = vec![
            "https://example.com/callback".to_string(),
            "https://example.com/callback2".to_string(),
        ];
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: Some(&redirect_uris),
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: None,
            jwks: None,
            jwks_uri: None,
        })
        .expect("valid update input");

        validate_update_fapi(&validated, &client)
            .expect("a redirect_uris-only update must not be affected by the FAPI JWKS checks");
    }

    // The algorithm-usability check is private_key_jwt-only: a FAPI
    // self_signed_tls_client_auth client's JWKS conveys certificates via
    // x5c, not client-assertion signing keys, so an alg-pinned RS256 x5c
    // entry must not block an otherwise-unrelated admin edit.
    #[tokio::test]
    async fn fapi_metadata_only_update_accepted_for_mtls_client_with_rs256_alg_pinned_x5c_jwks() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "fapi-mtls-admin-edit@example.com").await;
        let created = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::SelfSignedTlsClientAuth),
                jwks: TestJwks::Custom(
                    serde_json::json!({"keys": [{"kty": "RSA", "alg": "RS256", "x5c": ["ZmFrZS1jZXJ0"]}]}),
                ),
                dpop_bound_access_tokens: true,
                fapi_profile: Some(FapiProfile::Fapi2Security),
                with_secret: false,
                ..Default::default()
            },
        )
        .await;
        let client = crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists");

        let redirect_uris = vec!["https://example.com/callback".to_string()];
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: Some(&redirect_uris),
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: None,
            jwks: None,
            jwks_uri: None,
        })
        .expect("valid update input");

        validate_update_fapi(&validated, &client).expect(
            "a metadata-only update to a FAPI mTLS client must not be blocked by the \
             private_key_jwt-only algorithm guard",
        );
    }

    // An explicit `fapi_profile: fapi2_security` re-declaration must not
    // flip a FAPI mTLS client's auth method to private_key_jwt: that would
    // silently end mTLS authentication for a method RFC 7592 otherwise
    // treats as immutable. Uses the same RS256-only x5c JWKS as the
    // metadata-only case above to also prove the algorithm-usability check
    // (private_key_jwt-only) still doesn't fire.
    #[tokio::test]
    async fn fapi_reconfirm_preserves_mtls_auth_method_and_skips_algorithm_check() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "fapi-mtls-reconfirm@example.com").await;
        let created = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::SelfSignedTlsClientAuth),
                jwks: TestJwks::Custom(
                    serde_json::json!({"keys": [{"kty": "RSA", "alg": "RS256", "x5c": ["ZmFrZS1jZXJ0"]}]}),
                ),
                dpop_bound_access_tokens: true,
                fapi_profile: Some(FapiProfile::Fapi2Security),
                with_secret: false,
                ..Default::default()
            },
        )
        .await;
        let client = crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists");

        let validated = update_input(Some("fapi2_security"));
        validate_update_fapi(&validated, &client).expect(
            "re-declaring fapi2_security on a FAPI mTLS client must not trigger the \
             private_key_jwt-only algorithm guard",
        );

        let fields = compute_fapi_update_fields(&validated, &client).expect("merge should succeed");
        assert_eq!(
            fields.token_endpoint_auth_method,
            TokenEndpointAuthMethod::SelfSignedTlsClientAuth,
            "re-declaring the FAPI profile must preserve the client's mTLS auth method, \
             not force it to private_key_jwt"
        );
    }

    // Reverse edge: a request that omits `fapi_profile` AND `jwks` still
    // validates the STORED jwks, because the client remains FAPI regardless.
    // Simulates a client whose stored JWKS predates this guard (e.g. created
    // before it existed) — any subsequent update must surface the problem
    // rather than silently continue to accept an unusable key.
    #[tokio::test]
    async fn fapi_metadata_only_update_rejected_when_stored_jwks_has_no_allowed_algorithm_key() {
        let state = test_app_state().await;
        let client = stale_jwks_fapi_client(&state, "fapi-stale-jwks@example.com").await;

        let validated = update_input(None);
        let err = validate_update_fapi(&validated, &client)
            .expect_err("a metadata-only update must surface a pre-existing unusable stored JWKS");
        assert_eq!(err.code(), "fapi_jwks_algorithm_unsupported");
    }

    // Same reverse edge, but the stored JWKS predates the strict shape gate
    // (item 1) rather than merely using the wrong algorithm: a type-invalid
    // member (a boolean `alg`) fails `parse_jwks_set` entirely. The
    // fallback in `validate_update_fapi` treats a parse failure as "no
    // usable key" (documented on `db::parse_jwks_set`), so this collapses
    // to the same `fapi_jwks_algorithm_unsupported` error as a wrong
    // algorithm, without panicking.
    #[tokio::test]
    async fn fapi_metadata_only_update_rejected_when_stored_jwks_has_type_invalid_shape() {
        let state = test_app_state().await;
        let client =
            type_invalid_shape_jwks_fapi_client(&state, "fapi-stale-shape@example.com").await;

        let validated = update_input(None);
        let err = validate_update_fapi(&validated, &client)
            .expect_err("a metadata-only update must surface a pre-existing malformed stored JWKS");
        assert_eq!(err.code(), "fapi_jwks_algorithm_unsupported");
    }

    // Same reverse edge, but with `fapi_profile` explicitly re-confirmed and
    // JWKS left unspecified — the check must still fall back to the stored
    // JWKS rather than treating "no jwks in this request" as "nothing to
    // check".
    #[tokio::test]
    async fn fapi_reconfirm_rejected_when_stored_jwks_has_no_allowed_algorithm_key() {
        let state = test_app_state().await;
        let client = stale_jwks_fapi_client(&state, "fapi-reconfirm-stale-jwks@example.com").await;

        let validated = update_input(Some("fapi2_security"));
        let err = validate_update_fapi(&validated, &client).expect_err(
            "an explicit re-confirmation with no new jwks must still check the stored JWKS",
        );
        assert_eq!(err.code(), "fapi_jwks_algorithm_unsupported");
    }

    // No new restriction for non-FAPI clients: RS256 stays allowed, and a
    // JWKS-only update never triggers the FAPI-only checks.
    #[tokio::test]
    async fn fapi_jwks_only_update_accepted_for_non_fapi_client() {
        let state = test_app_state().await;
        let client = non_fapi_pkjwt_client(&state, "nonfapi-jwks-only-rs256@example.com").await;

        let jwks = rs256_only_jwks_json();
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: None,
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid update input");

        validate_update_fapi(&validated, &client)
            .expect("RS256 must remain unrestricted for a non-FAPI client's JWKS-only update");
    }

    #[test]
    fn fapi_create_rejected_when_jwks_has_no_allowed_algorithm_key() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        let jwks = rs256_only_jwks_json();
        let err = validate_create_application(CreateAppInput {
            name: "Payments",
            application_type: "web",
            redirect_uris: &redirect_uris,
            resource_uris: &[],
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: Some("fapi2_security"),
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect_err("RS256-only JWKS must be rejected at FAPI creation");
        assert_eq!(err.code(), "fapi_jwks_algorithm_unsupported");
    }

    #[test]
    fn fapi_create_accepted_when_jwks_has_unpinned_rsa_key() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        let jwks = unpinned_rsa_jwks_json();
        validate_create_application(CreateAppInput {
            name: "Payments",
            application_type: "web",
            redirect_uris: &redirect_uris,
            resource_uris: &[],
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: Some("fapi2_security"),
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("an unpinned RSA key (usable with PS256) must pass FAPI creation");
    }

    #[test]
    fn fapi_create_accepted_when_jwks_has_eddsa_key() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        let jwks = eddsa_jwks_json();
        validate_create_application(CreateAppInput {
            name: "Payments",
            application_type: "web",
            redirect_uris: &redirect_uris,
            resource_uris: &[],
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: Some("fapi2_security"),
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("an OKP/EdDSA key must pass FAPI creation");
    }

    /// Parses a test-fixture JWKS through the same typed representation the
    /// function under test now requires.
    fn jwk_set(json: serde_json::Value) -> crate::db::JwkSet {
        crate::db::parse_jwks_set(&json).expect("test fixture JWKS must parse")
    }

    #[test]
    fn jwks_has_fapi_allowed_key_covers_alg_and_kty_cases() {
        let no_alg = serde_json::json!({"keys": [{"kty": "EC"}]});
        assert!(
            jwks_has_fapi_allowed_key(&jwk_set(no_alg)),
            "no alg field survives"
        );

        // The nuance that motivated this guard: an RSA key normally used for
        // RS256 survives if it declares no alg constraint, because it can then
        // be presented with PS256 instead.
        let unpinned_rsa = serde_json::json!({"keys": [{"kty": "RSA"}]});
        assert!(
            jwks_has_fapi_allowed_key(&jwk_set(unpinned_rsa)),
            "an RSA key with no alg field survives (usable with PS256)"
        );

        let es256 = serde_json::json!({"keys": [{"kty": "EC", "alg": "ES256"}]});
        assert!(jwks_has_fapi_allowed_key(&jwk_set(es256)));

        let ps256 = serde_json::json!({"keys": [{"kty": "RSA", "alg": "PS256"}]});
        assert!(jwks_has_fapi_allowed_key(&jwk_set(ps256)));

        let eddsa = serde_json::json!({"keys": [{"kty": "OKP", "alg": "EdDSA"}]});
        assert!(jwks_has_fapi_allowed_key(&jwk_set(eddsa)));

        let rs256_only = serde_json::json!({"keys": [{"kty": "RSA", "alg": "RS256"}]});
        assert!(!jwks_has_fapi_allowed_key(&jwk_set(rs256_only)));

        // A kty the runtime matcher never selects for ES256/PS256/EdDSA (e.g. a
        // symmetric "oct" key) must not survive just because it omits alg —
        // it's unmatchable at runtime regardless.
        let unmatchable_kty_no_alg = serde_json::json!({"keys": [{"kty": "oct"}]});
        assert!(
            !jwks_has_fapi_allowed_key(&jwk_set(unmatchable_kty_no_alg)),
            "a kty outside EC/RSA/OKP must not survive on a missing alg"
        );

        // An allowed alg must not rescue a kty that can't carry it: the
        // runtime matcher selects EC for ES256, RSA for PS256, and OKP for
        // EdDSA, so any other pairing is unmatchable at runtime even though
        // the declared alg is FAPI-allowed.
        let oct_with_allowed_alg = serde_json::json!({"keys": [{"kty": "oct", "alg": "ES256"}]});
        assert!(
            !jwks_has_fapi_allowed_key(&jwk_set(oct_with_allowed_alg)),
            "an oct key must not survive by declaring an allowed alg"
        );

        let rsa_with_es256 = serde_json::json!({"keys": [{"kty": "RSA", "alg": "ES256"}]});
        assert!(
            !jwks_has_fapi_allowed_key(&jwk_set(rsa_with_es256)),
            "an RSA key declaring ES256 is unmatchable at runtime"
        );

        let ec_with_ps256 = serde_json::json!({"keys": [{"kty": "EC", "alg": "PS256"}]});
        assert!(
            !jwks_has_fapi_allowed_key(&jwk_set(ec_with_ps256)),
            "an EC key declaring PS256 is unmatchable at runtime"
        );

        let okp_with_es256 = serde_json::json!({"keys": [{"kty": "OKP", "alg": "ES256"}]});
        assert!(
            !jwks_has_fapi_allowed_key(&jwk_set(okp_with_es256)),
            "an OKP key declaring ES256 is unmatchable at runtime"
        );

        let mixed = serde_json::json!({
            "keys": [{"kty": "RSA", "alg": "RS256"}, {"kty": "EC", "alg": "ES256"}]
        });
        assert!(
            jwks_has_fapi_allowed_key(&jwk_set(mixed)),
            "one usable key is enough"
        );

        // The runtime matcher also filters on `use`: an otherwise-usable key
        // marked for encryption is never selected for signature verification.
        let enc_only = serde_json::json!({
            "keys": [{"kty": "EC", "alg": "ES256", "use": "enc"}]
        });
        assert!(
            !jwks_has_fapi_allowed_key(&jwk_set(enc_only)),
            "a use: enc key must not survive even with an allowed alg"
        );

        let explicit_sig = serde_json::json!({
            "keys": [{"kty": "EC", "alg": "ES256", "use": "sig"}]
        });
        assert!(
            jwks_has_fapi_allowed_key(&jwk_set(explicit_sig)),
            "an explicit use: sig key survives"
        );

        let empty = serde_json::json!({"keys": []});
        assert!(!jwks_has_fapi_allowed_key(&jwk_set(empty)));
    }

    #[test]
    fn jwks_missing_keys_field_fails_to_parse() {
        // RFC 7517 §5 (<https://www.rfc-editor.org/rfc/rfc7517#section-5>):
        // "A JWK Set is a JSON object that represents a set of JWKs. The
        // JSON object MUST have a 'keys' member, with its value being an
        // array of JWKs." The typed parse rejects an object that omits it,
        // rather than the previous loose check silently treating it as "no
        // usable key."
        let no_keys_field = serde_json::json!({});
        assert!(crate::db::parse_jwks_set(&no_keys_field).is_err());
    }

    #[test]
    fn jwks_with_type_invalid_member_fails_to_parse() {
        // A non-string "alg"/"use" must fail the typed parse instead of
        // being silently read as absent — the bug class this guard closes.
        let bad_alg = serde_json::json!({"keys": [{"kty": "EC", "alg": true}]});
        assert!(crate::db::parse_jwks_set(&bad_alg).is_err());

        let bad_use = serde_json::json!({"keys": [{"kty": "EC", "use": 123}]});
        assert!(crate::db::parse_jwks_set(&bad_use).is_err());
    }

    // ========================================================================
    // JWKS / jwks_uri preservation on update — the merge logic must follow
    // the same "absent vs provided" distinction as `dpop_bound_access_tokens`
    // so that a non-FAPI `private_key_jwt` client (e.g. one created via
    // authenticated dynamic registration) does not silently lose its JWKS
    // when an unrelated PATCH omits `fapi_profile`.
    // ========================================================================

    // Regression: an absent `fapi_profile` must preserve the existing JWKS of
    // a non-FAPI `private_key_jwt` client. The docstring promises this but the
    // old implementation cleared JWKS for any non-FAPI profile.
    #[tokio::test]
    async fn non_fapi_client_preserves_jwks_when_fapi_profile_absent() {
        let state = test_app_state().await;
        let client = non_fapi_pkjwt_client(&state, "pkjwt-keep@example.com").await;
        assert!(
            client.keys.as_ref().is_some_and(|k| k.inline().is_some()),
            "client must start with JWKS"
        );

        let validated = update_input(None);
        validate_update_fapi(&validated, &client).expect("absent profile is valid");
        let fields = compute_fapi_update_fields(&validated, &client).expect("merge should succeed");

        assert_eq!(fields.fapi_profile, FapiProfile::None);
        assert_eq!(
            fields.token_endpoint_auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt,
            "auth method preserved for non-FAPI client"
        );
        assert!(
            fields.keys.is_some_and(|k| k.inline().is_some()),
            "existing JWKS must be preserved when fapi_profile is absent"
        );
        assert_eq!(
            fields.keys.and_then(crate::db::ClientKeys::inline),
            client.keys.as_ref().and_then(crate::db::ClientKeys::inline),
            "same JWKS value"
        );
        assert!(
            !fields.dpop_bound_access_tokens,
            "dpop preserved from client (false)"
        );
    }

    // A non-FAPI client with `jwks_uri` (instead of inline `jwks`) must also
    // preserve it when `fapi_profile` is absent.
    #[tokio::test]
    async fn non_fapi_client_preserves_jwks_uri_when_fapi_profile_absent() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "pkjwt-uri@example.com").await;
        let created = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
                jwks_uri: Some("https://client.example/jwks.json".to_string()),
                fapi_profile: None,
                with_secret: false,
                ..Default::default()
            },
        )
        .await;
        let client = crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists");
        assert_eq!(
            client.keys.as_ref().and_then(crate::db::ClientKeys::uri),
            Some("https://client.example/jwks.json"),
            "client must start with jwks_uri"
        );

        let validated = update_input(None);
        let fields = compute_fapi_update_fields(&validated, &client).expect("merge should succeed");

        assert_eq!(
            fields.keys.and_then(crate::db::ClientKeys::uri),
            Some("https://client.example/jwks.json"),
            "existing jwks_uri must be preserved when fapi_profile is absent"
        );
    }

    // Explicitly setting `fapi_profile: "none"` clears JWKS, which for a
    // `private_key_jwt` client leaves it with no way to authenticate and no way
    // back through this endpoint. The merge must refuse rather than persist it.
    #[tokio::test]
    async fn explicit_none_is_refused_when_it_would_strip_a_pkjwt_client_of_keys() {
        let state = test_app_state().await;
        let client = non_fapi_pkjwt_client(&state, "pkjwt-clear@example.com").await;
        assert!(
            client.keys.as_ref().is_some_and(|k| k.inline().is_some()),
            "client must start with JWKS"
        );

        let validated = update_input(Some("none"));
        validate_update_fapi(&validated, &client).expect("non-FAPI -> non-FAPI is allowed");

        let err = compute_fapi_update_fields(&validated, &client)
            .expect_err("must refuse to leave a private_key_jwt client without keys");
        assert!(matches!(err, AppValidationError::AuthMethodMissingJwks));
    }

    // Same as above for `self_signed_tls_client_auth`: its certificate is
    // carried in the JWKS's x5c member (RFC 8705 §2.2.2), so clearing it
    // leaves the client just as unable to authenticate. A client registered
    // dynamically (RFC 7591) with this auth method and no FAPI profile can
    // reach the admin update path, where nothing but this guard stops a bare
    // `fapi_profile: "none"` re-declaration from silently dropping its only
    // key material — `validate_update_fapi` returns early for non-FAPI
    // clients before any JWKS-presence check runs.
    #[tokio::test]
    async fn explicit_none_is_refused_when_it_would_strip_a_self_signed_client_of_keys() {
        let state = test_app_state().await;
        let client = non_fapi_self_signed_client(&state, "self-signed-clear@example.com").await;
        assert!(
            client.keys.as_ref().is_some_and(|k| k.inline().is_some()),
            "client must start with JWKS"
        );

        let validated = update_input(Some("none"));
        validate_update_fapi(&validated, &client).expect("non-FAPI -> non-FAPI is allowed");

        let err = compute_fapi_update_fields(&validated, &client)
            .expect_err("must refuse to leave a self_signed_tls_client_auth client without keys");
        assert!(matches!(err, AppValidationError::AuthMethodMissingJwks));
    }

    // A JWKS-only update can swap in a JWKS that still satisfies the bare
    // presence check but carries no x5c anywhere — `jwks_has_x5c` must catch
    // this the same way the FAPI algorithm-usability check catches an
    // RS256-only JWKS for private_key_jwt.
    #[tokio::test]
    async fn self_signed_jwks_only_update_rejected_when_new_jwks_has_no_x5c() {
        let state = test_app_state().await;
        let client = non_fapi_self_signed_client(&state, "self-signed-swap@example.com").await;

        let jwks = serde_json::json!({"keys": [{"kty": "RSA", "n": "n", "e": "AQAB"}]}).to_string();
        let validated = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: None,
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect("valid update input");

        let err = compute_fapi_update_fields(&validated, &client)
            .expect_err("a certificate-less JWKS must be rejected for self_signed_tls_client_auth");
        assert!(matches!(err, AppValidationError::SelfSignedJwksMissingX5c));
        assert_eq!(err.code(), "self_signed_jwks_missing_x5c");
    }

    // Leaving the FAPI profile stops mandating DPoP but must not silently turn
    // it off: that downgrades every issued token from sender-constrained to
    // bearer, and `dpop_bound_access_tokens` is not part of the request.
    #[tokio::test]
    async fn explicit_none_preserves_dpop_binding() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "dpop-preserve@example.com").await;
        let created = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                dpop_bound_access_tokens: true,
                fapi_profile: None,
                ..Default::default()
            },
        )
        .await;
        let client = crate::db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists");
        assert!(client.dpop_bound_access_tokens);

        let validated = update_input(Some("none"));
        let fields = compute_fapi_update_fields(&validated, &client).expect("merge should succeed");

        assert_eq!(fields.fapi_profile, FapiProfile::None);
        assert!(
            fields.dpop_bound_access_tokens,
            "DPoP binding must survive an unrelated profile update"
        );
    }

    // Guard against a naive fix that clears JWKS whenever
    // `fapi_profile_provided` is true: re-confirming an existing FAPI client
    // with `fapi_profile: "fapi2_security"` (no `jwks` in the request) must
    // preserve the client's existing JWKS.
    #[tokio::test]
    async fn fapi_client_reconfirmed_preserves_existing_jwks() {
        let state = test_app_state().await;
        let client = fapi_test_client(&state, "fapi-reconfirm@example.com").await;
        assert!(
            client.keys.as_ref().is_some_and(|k| k.inline().is_some()),
            "client must start with JWKS"
        );

        let validated = update_input(Some("fapi2_security"));
        validate_update_fapi(&validated, &client).expect("FAPI -> FAPI is allowed");
        let fields = compute_fapi_update_fields(&validated, &client).expect("merge should succeed");

        assert_eq!(fields.fapi_profile, FapiProfile::Fapi2Security);
        assert!(
            fields.keys.is_some_and(|k| k.inline().is_some()),
            "existing JWKS must be preserved when re-confirming FAPI without JWKS"
        );
        assert_eq!(
            fields.keys.and_then(crate::db::ClientKeys::inline),
            client.keys.as_ref().and_then(crate::db::ClientKeys::inline),
            "same JWKS value"
        );
    }

    // ========================================================================
    // access_scope / fapi_profile enum validation — invalid values must be
    // rejected, not silently coerced to defaults.
    // ========================================================================

    fn base_create_input<'a>(
        redirect_uris: &'a [String],
        access_scope: Option<&'a str>,
        fapi_profile: Option<&'a str>,
    ) -> CreateAppInput<'a> {
        CreateAppInput {
            name: "App",
            application_type: "web",
            redirect_uris,
            resource_uris: &[],
            post_logout_redirect_uris: None,
            access_scope,
            fapi_profile,
            jwks: None,
            jwks_uri: None,
        }
    }

    #[test]
    fn create_rejects_invalid_access_scope() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        let err = validate_create_application(base_create_input(
            &redirect_uris,
            Some("organizaton"),
            None,
        ))
        .expect_err("typo must be rejected");
        assert_eq!(err.code(), "invalid_access_scope");
        assert!(err.message().contains("personal"));
    }

    #[test]
    fn create_accepts_valid_access_scope_values() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        for (s, expected) in &[
            ("personal", AccessScope::Personal),
            ("organization", AccessScope::Organization),
            ("public", AccessScope::Public),
            ("PERSONAL", AccessScope::Personal), // case-insensitive
        ] {
            let validated =
                validate_create_application(base_create_input(&redirect_uris, Some(s), None))
                    .expect("valid scope");
            assert_eq!(validated.access_scope, *expected, "scope {s}");
        }
    }

    #[test]
    fn create_absent_access_scope_defaults_to_personal() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        let validated = validate_create_application(base_create_input(&redirect_uris, None, None))
            .expect("valid input");
        assert_eq!(validated.access_scope, AccessScope::Personal);
    }

    #[test]
    fn create_rejects_invalid_fapi_profile() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        let err = validate_create_application(base_create_input(
            &redirect_uris,
            None,
            Some("fapi_security"),
        ))
        .expect_err("typo must be rejected");
        assert_eq!(err.code(), "invalid_fapi_profile");
        assert!(err.message().contains("fapi_security"));
    }

    #[test]
    fn create_accepts_valid_non_fapi_profile_sentinels() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        for s in &["none", ""] {
            let validated =
                validate_create_application(base_create_input(&redirect_uris, None, Some(s)))
                    .expect("valid non-FAPI sentinel");
            assert!(!validated.is_fapi, "sentinel '{s}' must not set is_fapi");
        }
    }

    // A type-invalid JWK member (e.g. a boolean "alg") must be rejected at
    // creation, through the same typed representation the RFC 7523
    // client-assertion verifier uses at runtime — otherwise the application
    // is created but can never authenticate.
    #[test]
    fn create_rejects_jwks_with_type_invalid_key_member() {
        let redirect_uris = vec!["https://example.com/cb".to_string()];
        let jwks = serde_json::json!({"keys": [{"kty": "EC", "alg": true}]}).to_string();
        let err = validate_create_application(CreateAppInput {
            name: "App",
            application_type: "web",
            redirect_uris: &redirect_uris,
            resource_uris: &[],
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: None,
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect_err("type-invalid JWK member must be rejected");
        assert!(matches!(err, AppValidationError::JwksInvalidKeyShape));
        assert_eq!(err.code(), "invalid_jwks");
    }

    fn base_update_input<'a>(
        access_scope: Option<&'a str>,
        fapi_profile: Option<&'a str>,
    ) -> UpdateAppInput<'a> {
        UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope,
            fapi_profile,
            jwks: None,
            jwks_uri: None,
        }
    }

    #[test]
    fn update_rejects_invalid_access_scope() {
        let err = validate_update_format(base_update_input(Some("publik"), None))
            .expect_err("typo must be rejected");
        assert_eq!(err.code(), "invalid_access_scope");
    }

    #[test]
    fn update_absent_access_scope_is_none() {
        let validated = validate_update_format(base_update_input(None, None)).expect("valid input");
        assert!(
            validated.access_scope.is_none(),
            "absent field must be None"
        );
    }

    #[test]
    fn update_rejects_invalid_fapi_profile() {
        let err = validate_update_format(base_update_input(None, Some("fapi1_adv")))
            .expect_err("invalid profile must be rejected");
        assert_eq!(err.code(), "invalid_fapi_profile");
    }

    #[test]
    fn update_rejects_jwks_with_type_invalid_key_member() {
        let jwks = serde_json::json!({"keys": [{"kty": "EC", "use": 123}]}).to_string();
        let err = validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
            access_scope: None,
            fapi_profile: None,
            jwks: Some(&jwks),
            jwks_uri: None,
        })
        .expect_err("type-invalid JWK member must be rejected");
        assert!(matches!(err, AppValidationError::JwksInvalidKeyShape));
        assert_eq!(err.code(), "invalid_jwks");
    }
}
