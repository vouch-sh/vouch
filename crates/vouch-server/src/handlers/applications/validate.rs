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
    RegistrationSource, TokenEndpointAuthMethod,
};
use crate::error::ServiceError;
use crate::services::oidc::ResourceUri;

use super::{validate_post_logout_redirect_uris, validate_redirect_uris};

/// A validation failure: a machine-readable code plus a human message.
#[derive(Debug)]
pub(super) enum AppValidationError {
    EmptyName,
    InvalidApplicationType,
    MissingRedirectUris,
    InvalidRedirectUris(Vec<String>),
    InvalidPostLogoutRedirectUris(Vec<String>),
    InvalidResourceUri { uri: String, detail: String },
    FapiRequiresConfidentialClient,
    FapiMissingJwks,
    JwksNotJson,
    JwksMissingKeys,
    InvalidJwksUri,
}

impl AppValidationError {
    /// Machine-readable error code (stable API contract).
    pub(super) fn code(&self) -> &'static str {
        match self {
            Self::EmptyName => "invalid_name",
            Self::InvalidApplicationType => "invalid_type",
            Self::MissingRedirectUris | Self::InvalidRedirectUris(_) => "invalid_redirect_uris",
            Self::InvalidPostLogoutRedirectUris(_) => "invalid_post_logout_redirect_uris",
            Self::InvalidResourceUri { .. } => "invalid_resource_uri",
            Self::FapiRequiresConfidentialClient => "invalid_fapi_profile",
            Self::FapiMissingJwks => "missing_jwks",
            Self::JwksNotJson | Self::JwksMissingKeys => "invalid_jwks",
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
            Self::MissingRedirectUris => "At least one redirect URI is required".to_string(),
            Self::InvalidRedirectUris(invalid) => format!(
                "Invalid redirect URI(s): {}. Each URI must be a valid http:// or https:// URL.",
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
            Self::JwksNotJson => "JWKS must be valid JSON".to_string(),
            Self::JwksMissingKeys => {
                "JWKS must be a JSON object with a non-empty \"keys\" array".to_string()
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
    pub fapi_profile: Option<&'a str>,
    pub jwks: Option<&'a str>,
    pub jwks_uri: Option<&'a str>,
}

/// Validated create fields, ready for `CreateOAuthClientParams`.
pub(super) struct ValidatedCreateApp<'a> {
    /// Trimmed, non-empty application name.
    pub name: &'a str,
    pub app_type: OAuthClientType,
    pub is_fapi: bool,
    /// Parsed JWKS with a non-empty `keys` array (if provided).
    pub jwks: Option<serde_json::Value>,
    /// Trimmed, https-validated JWKS URI (if provided).
    pub jwks_uri: Option<&'a str>,
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

    validate_redirect_uris(input.redirect_uris).map_err(AppValidationError::InvalidRedirectUris)?;

    if let Some(uris) = input.post_logout_redirect_uris {
        validate_post_logout_redirect_uris(uris)
            .map_err(AppValidationError::InvalidPostLogoutRedirectUris)?;
    }

    // Validate resource URIs per RFC 8707 (absolute URI, no fragment).
    validate_resource_uris(input.resource_uris)?;

    let is_fapi = input.fapi_profile.is_some_and(|p| p == "fapi2_security");

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

    Ok(ValidatedCreateApp {
        name,
        app_type,
        is_fapi,
        jwks,
        jwks_uri,
    })
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
    pub fapi_profile: Option<&'a str>,
    pub jwks: Option<&'a str>,
    pub jwks_uri: Option<&'a str>,
}

/// Validated update fields (format phase only).
pub(super) struct ValidatedUpdateApp<'a> {
    pub is_fapi: bool,
    /// Whether `fapi_profile` was present in the request at all. A provided
    /// non-FAPI value is an explicit transition away from FAPI; an absent
    /// field preserves the existing profile.
    pub fapi_profile_provided: bool,
    /// Parsed JWKS with a non-empty `keys` array (if provided).
    pub jwks: Option<serde_json::Value>,
    /// Trimmed, https-validated JWKS URI (if provided).
    pub jwks_uri: Option<&'a str>,
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
    if let Some(uris) = input.redirect_uris {
        // Only validate URIs if the list is non-empty.  An empty list is
        // accepted here and checked later by `validate_update_fapi` against
        // the persisted client type.
        if !uris.is_empty() {
            validate_redirect_uris(uris).map_err(AppValidationError::InvalidRedirectUris)?;
        }
    }

    if let Some(uris) = input.resource_uris {
        validate_resource_uris(uris)?;
    }

    if let Some(uris) = input.post_logout_redirect_uris
        && !uris.is_empty()
    {
        validate_post_logout_redirect_uris(uris)
            .map_err(AppValidationError::InvalidPostLogoutRedirectUris)?;
    }

    let is_fapi = input.fapi_profile.is_some_and(|p| p == "fapi2_security");

    let jwks = trim_nonempty(input.jwks).map(parse_jwks).transpose()?;
    let jwks_uri = trim_nonempty(input.jwks_uri);
    validate_jwks_uri(jwks_uri)?;

    Ok(ValidatedUpdateApp {
        is_fapi,
        fapi_profile_provided: input.fapi_profile.is_some(),
        jwks,
        jwks_uri,
        redirect_uris: input.redirect_uris,
        post_logout_redirect_uris: input.post_logout_redirect_uris,
    })
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
    if let Some(uris) = validated.redirect_uris
        && uris.is_empty()
        && !matches!(client.application_type, OAuthClientType::Service)
    {
        return Err(AppValidationError::MissingRedirectUris);
    }

    if !validated.is_fapi {
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
    if validated.jwks.is_none()
        && validated.jwks_uri.is_none()
        && client.jwks.is_none()
        && client.jwks_uri.is_none()
    {
        return Err(AppValidationError::FapiMissingJwks);
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
        token_endpoint_auth_method: if is_fapi {
            Some(TokenEndpointAuthMethod::PrivateKeyJwt)
        } else {
            None
        },
        jwks: if is_fapi {
            validated.jwks.as_ref()
        } else {
            None
        },
        jwks_uri: if is_fapi { validated.jwks_uri } else { None },
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
pub(super) struct FapiUpdateFields<'a> {
    pub fapi_profile: FapiProfile,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub jwks: Option<&'a serde_json::Value>,
    pub jwks_uri: Option<&'a str>,
    pub dpop_bound_access_tokens: bool,
}

/// Merge the FAPI-related fields of an update request with the existing
/// client record.
///
/// An absent `fapi_profile` preserves the client's current profile, auth
/// method, JWKS, and DPoP binding. A provided FAPI profile enforces
/// `private_key_jwt` + DPoP; a provided non-FAPI value transitions the
/// client back to standard `client_secret_basic` with no JWKS.
pub(super) fn compute_fapi_update_fields<'a>(
    validated: &'a ValidatedUpdateApp<'_>,
    client: &'a OAuthClient,
) -> FapiUpdateFields<'a> {
    let is_fapi = validated.is_fapi;

    let fapi_profile = if is_fapi {
        FapiProfile::Fapi2Security
    } else if validated.fapi_profile_provided {
        // Explicitly set to non-FAPI
        FapiProfile::None
    } else {
        client.fapi_profile
    };

    let token_endpoint_auth_method = if is_fapi {
        TokenEndpointAuthMethod::PrivateKeyJwt
    } else if validated.fapi_profile_provided && client.is_fapi() {
        // Transitioning from FAPI to Standard
        TokenEndpointAuthMethod::ClientSecretBasic
    } else {
        client.token_endpoint_auth_method
    };

    let jwks = if validated.jwks.is_some() {
        validated.jwks.as_ref()
    } else if fapi_profile == FapiProfile::Fapi2Security {
        client.jwks.as_ref()
    } else {
        None
    };

    let jwks_uri = if validated.jwks_uri.is_some() {
        validated.jwks_uri
    } else if fapi_profile == FapiProfile::Fapi2Security {
        client.jwks_uri.as_deref()
    } else {
        None
    };

    let dpop_bound_access_tokens = if is_fapi {
        true
    } else if validated.fapi_profile_provided {
        false
    } else {
        client.dpop_bound_access_tokens
    };

    FapiUpdateFields {
        fapi_profile,
        token_endpoint_auth_method,
        jwks,
        jwks_uri,
        dpop_bound_access_tokens,
    }
}

fn trim_nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
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
            Some(TokenEndpointAuthMethod::PrivateKeyJwt)
        );
        assert_eq!(params.fapi_profile, Some(FapiProfile::Fapi2Security));
        assert_eq!(params.dpop_bound_access_tokens, Some(true));
        assert!(params.jwks.is_some(), "validated JWKS must be stored");
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

        assert_eq!(params.token_endpoint_auth_method, None);
        assert_eq!(params.fapi_profile, None);
        assert_eq!(params.dpop_bound_access_tokens, None);
        assert!(params.jwks.is_none());
        assert!(params.jwks_uri.is_none());
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

    fn update_input(fapi_profile: Option<&str>) -> ValidatedUpdateApp<'_> {
        validate_update_format(UpdateAppInput {
            redirect_uris: None,
            resource_uris: None,
            post_logout_redirect_uris: None,
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
        let fields = compute_fapi_update_fields(&validated, &client);

        assert_eq!(fields.fapi_profile, FapiProfile::Fapi2Security);
        assert_eq!(
            fields.token_endpoint_auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt
        );
        assert!(fields.jwks.is_some(), "existing JWKS preserved");
        assert!(fields.dpop_bound_access_tokens);
    }

    #[tokio::test]
    async fn fapi_update_explicit_non_fapi_transitions_to_standard() {
        let state = test_app_state().await;
        let client = fapi_test_client(&state, "fapi-disable@example.com").await;

        let validated = update_input(Some("standard"));
        let fields = compute_fapi_update_fields(&validated, &client);

        assert_eq!(fields.fapi_profile, FapiProfile::None);
        assert_eq!(
            fields.token_endpoint_auth_method,
            TokenEndpointAuthMethod::ClientSecretBasic
        );
        assert!(fields.jwks.is_none(), "JWKS dropped on FAPI exit");
        assert!(fields.jwks_uri.is_none());
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
            fapi_profile: Some("fapi2_security"),
            jwks: Some(&jwks),
            jwks_uri: Some("https://client.example/jwks.json"),
        })
        .expect("valid update input");
        let fields = compute_fapi_update_fields(&validated, &client);

        assert_eq!(fields.fapi_profile, FapiProfile::Fapi2Security);
        assert_eq!(
            fields.token_endpoint_auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt
        );
        assert!(fields.jwks.is_some(), "request JWKS used");
        assert_eq!(fields.jwks_uri, Some("https://client.example/jwks.json"));
        assert!(fields.dpop_bound_access_tokens);
    }
}
