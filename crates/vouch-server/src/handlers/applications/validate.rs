// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared input validation for OAuth application create/update.
//!
//! The API handlers (`api.rs`) and web form handlers (`web.rs`) accept the
//! same application fields and enforce identical rules; only the error
//! rendering differs (JSON [`ServiceError`] vs HTML template). Each function
//! here is called by both the API and the web variant of the handler.

use axum::http::StatusCode;

use crate::db::{OAuthClient, OAuthClientType};
use crate::services::error::ServiceError;
use crate::services::oidc::ResourceUri;

use super::validate_redirect_uris;

/// A validation failure: a machine-readable code plus a human message.
#[derive(Debug)]
pub(super) enum AppValidationError {
    EmptyName,
    InvalidApplicationType,
    MissingRedirectUris,
    InvalidRedirectUris(Vec<String>),
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
    pub fapi_profile: Option<&'a str>,
    pub jwks: Option<&'a str>,
    pub jwks_uri: Option<&'a str>,
}

/// Validated update fields (format phase only).
pub(super) struct ValidatedUpdateApp<'a> {
    pub is_fapi: bool,
    /// Parsed JWKS with a non-empty `keys` array (if provided).
    pub jwks: Option<serde_json::Value>,
    /// Trimmed, https-validated JWKS URI (if provided).
    pub jwks_uri: Option<&'a str>,
    /// Redirect URIs from the request (`None` = field absent, `Some(&[])` = explicitly cleared).
    pub redirect_uris: Option<&'a [String]>,
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

    let is_fapi = input.fapi_profile.is_some_and(|p| p == "fapi2_security");

    let jwks = trim_nonempty(input.jwks).map(parse_jwks).transpose()?;
    let jwks_uri = trim_nonempty(input.jwks_uri);
    validate_jwks_uri(jwks_uri)?;

    Ok(ValidatedUpdateApp {
        is_fapi,
        jwks,
        jwks_uri,
        redirect_uris: input.redirect_uris,
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
