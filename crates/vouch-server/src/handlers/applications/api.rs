// SPDX-License-Identifier: Apache-2.0 OR MIT
//! API handlers for OAuth Application Registration.
//!
//! These handlers return JSON responses for programmatic access to
//! application management.

use crate::AppState;
use crate::db::{
    self, AccessScope, CreateOAuthClientParams, FapiProfile, OAuthClientType, OAuthEventType,
    RegistrationSource, TokenEndpointAuthMethod, UpdateOAuthClientParams,
};
use axum::extract::OriginalUri;
use axum::http::Method;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

use super::types::{
    AddSecretRequest, AddSecretResponse, ApplicationResponse, CreateApplicationRequest,
    CreateApplicationResponse, ListApplicationsResponse, ListSecretsResponse, SecretInfo,
    UpdateApplicationRequest,
};
use super::{MAX_ACTIVE_SECRETS, generate_client_secret, validate_redirect_uris};
use crate::handlers::hash_token;
use crate::handlers::session::extract_resource_token;
use crate::handlers::{ValidPath, ValidUuid};
use crate::services::error::ServiceError;
use crate::services::oidc::ResourceUri;

/// List user's applications (API).
/// GET /api/v1/applications
pub async fn list_applications_api(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListApplicationsResponse>, ServiceError> {
    let token =
        extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let applications = db::get_oauth_clients_for_user(&state.store, &token.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list applications: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .into_iter()
        .map(ApplicationResponse::from)
        .collect();

    Ok(Json(ListApplicationsResponse { applications }))
}

/// Create a new application (API).
/// POST /api/v1/applications
pub async fn create_application_api(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateApplicationRequest>,
) -> Result<Json<CreateApplicationResponse>, ServiceError> {
    // ── Pure format validation first — no DB cost for malformed requests ──
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "Application name is required",
        ));
    }

    let app_type = req
        .application_type
        .parse::<OAuthClientType>()
        .map_err(|_| {
            ServiceError::api(
                StatusCode::BAD_REQUEST,
                "invalid_type",
                "Invalid application type. Must be: web, native, spa, or service",
            )
        })?;

    // For non-service apps, at least one redirect URI is required
    if !matches!(app_type, OAuthClientType::Service) && req.redirect_uris.is_empty() {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uris",
            "At least one redirect URI is required",
        ));
    }

    // Validate redirect URIs are valid URLs
    if let Err(invalid) = validate_redirect_uris(&req.redirect_uris) {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uris",
            format!(
                "Invalid redirect URI(s): {}. Each URI must be a valid http:// or https:// URL.",
                invalid.join(", ")
            ),
        ));
    }

    // RFC 8707: Resource URIs default to empty if not provided.
    let resource_uris = req.resource_uris.as_deref().unwrap_or(&[]);

    // Validate resource URIs per RFC 8707 (absolute URI, no fragment).
    for uri_str in resource_uris {
        if let Err(e) = ResourceUri::parse(uri_str) {
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "invalid_resource_uri",
                format!("Invalid resource URI '{uri_str}': {e}"),
            ));
        }
    }

    // Determine FAPI profile
    let is_fapi = req
        .fapi_profile
        .as_deref()
        .is_some_and(|p| p == "fapi2_security");

    // FAPI validation: must be a confidential client type
    if is_fapi && !matches!(app_type, OAuthClientType::Web | OAuthClientType::Service) {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_fapi_profile",
            "FAPI 2.0 Security Profile requires a confidential client type (web or service)",
        ));
    }

    // FAPI validation: require JWKS or JWKS URI
    let jwks_trimmed_str = req.jwks.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let jwks_uri_trimmed = req
        .jwks_uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if is_fapi && jwks_trimmed_str.is_none() && jwks_uri_trimmed.is_none() {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "missing_jwks",
            "FAPI 2.0 requires jwks or jwks_uri for private_key_jwt authentication",
        ));
    }

    // Validate and parse JWKS JSON if provided
    let jwks_value = if let Some(jwks_json) = jwks_trimmed_str {
        match serde_json::from_str::<serde_json::Value>(jwks_json) {
            Ok(val) => {
                if !val
                    .get("keys")
                    .is_some_and(|k| k.is_array() && !k.as_array().is_some_and(|a| a.is_empty()))
                {
                    return Err(ServiceError::api(
                        StatusCode::BAD_REQUEST,
                        "invalid_jwks",
                        "JWKS must be a JSON object with a non-empty \"keys\" array",
                    ));
                }
                Some(val)
            }
            Err(_) => {
                return Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "invalid_jwks",
                    "JWKS must be valid JSON",
                ));
            }
        }
    } else {
        None
    };

    // Validate JWKS URI if provided
    if let Some(jwks_uri_val) = jwks_uri_trimmed {
        match url::Url::parse(jwks_uri_val) {
            Ok(parsed) if parsed.scheme() == "https" => {}
            _ => {
                return Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "invalid_jwks_uri",
                    "JWKS URI must be a valid https:// URL",
                ));
            }
        }
    }

    // ── Authentication — validated input is good, now check credentials ──
    let token =
        extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    // Parse access scope (default to personal if not provided)
    let access_scope = req
        .access_scope
        .as_ref()
        .and_then(|s| s.parse::<AccessScope>().ok())
        .unwrap_or_default();

    // Get user to check org membership
    let user = db::get_user_by_id(&state.store, &token.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| ServiceError::api(StatusCode::NOT_FOUND, "not_found", "User not found"))?;

    // Validate: Organization scope requires user to have an org
    if access_scope == AccessScope::Organization && user.org_id.is_none() {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_access_scope",
            "Organization scope requires organization membership",
        ));
    }

    // Set org_id only for organization-scoped apps
    let org_id = if access_scope == AccessScope::Organization {
        user.org_id.as_deref()
    } else {
        None
    };

    // Create the application with FAPI settings included at creation time
    let (client, client_id) = db::create_oauth_client(
        &state.store,
        &CreateOAuthClientParams {
            user_id: Some(&token.sub),
            name,
            description: req.description.as_deref(),
            application_type: app_type,
            redirect_uris: &req.redirect_uris,
            access_scope,
            org_id,
            resource_uris,
            token_endpoint_auth_method: if is_fapi {
                Some(TokenEndpointAuthMethod::PrivateKeyJwt)
            } else {
                None
            },
            jwks: if is_fapi { jwks_value.as_ref() } else { None },
            jwks_uri: if is_fapi { jwks_uri_trimmed } else { None },
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
            id_token_signed_response_alg: "RS256",
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
        },
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create OAuth client: {e}");
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Internal database error",
        )
    })?;

    // Generate client secret for confidential clients (skip for FAPI — they use private_key_jwt)
    let client_secret = if app_type.requires_secret() && !is_fapi {
        let secret = generate_client_secret();
        let secret_hash = hash_token(&secret);

        db::create_oauth_client_secret(
            &state.store,
            &client.id,
            &secret_hash,
            Some("Initial secret"),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create client secret: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

        Some(secret)
    } else {
        None
    };

    tracing::info!("Created OAuth application: {} ({})", name, client_id);

    let jwks_configured = client.jwks.is_some() || client.jwks_uri.is_some();
    let response_jwks_uri = client.jwks_uri.clone();

    Ok(Json(CreateApplicationResponse {
        id: client.id,
        client_id,
        client_secret,
        name: name.to_string(),
        application_type: req.application_type,
        access_scope: access_scope.as_str().to_string(),
        resource_uris: resource_uris.to_vec(),
        token_endpoint_auth_method: client.token_endpoint_auth_method.as_str().to_string(),
        fapi_profile: client.fapi_profile.as_str().to_string(),
        jwks_configured,
        jwks_uri: response_jwks_uri,
    }))
}

/// Get application details (API).
/// GET /api/v1/applications/:id
pub async fn get_application_api(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    ValidPath(app_id): ValidPath<ValidUuid>,
) -> Result<Json<ApplicationResponse>, ServiceError> {
    let token =
        extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    // Verify ownership
    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    Ok(Json(ApplicationResponse::from(client)))
}

/// Update an application (API).
/// PATCH /api/v1/applications/:id
pub async fn update_application_api(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    ValidPath(app_id): ValidPath<ValidUuid>,
    Json(req): Json<UpdateApplicationRequest>,
) -> Result<Json<ApplicationResponse>, ServiceError> {
    // ── Pure format validation first — no DB cost for malformed requests ──
    // Validate request-provided redirect URIs (if any)
    if let Some(ref uris) = req.redirect_uris
        && let Err(invalid) = validate_redirect_uris(uris)
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uris",
            format!(
                "Invalid redirect URI(s): {}. Each URI must be a valid http:// or https:// URL.",
                invalid.join(", ")
            ),
        ));
    }

    // Validate request-provided resource URIs (if any)
    if let Some(ref uris) = req.resource_uris {
        for uri_str in uris {
            if let Err(e) = ResourceUri::parse(uri_str) {
                return Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "invalid_resource_uri",
                    format!("Invalid resource URI '{uri_str}': {e}"),
                ));
            }
        }
    }

    // Validate and parse JWKS JSON format if provided
    let jwks_trimmed_str = req.jwks.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let jwks_uri_trimmed = req
        .jwks_uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let jwks_value = if let Some(jwks_json) = jwks_trimmed_str {
        match serde_json::from_str::<serde_json::Value>(jwks_json) {
            Ok(val) => {
                if !val
                    .get("keys")
                    .is_some_and(|k| k.is_array() && !k.as_array().is_some_and(|a| a.is_empty()))
                {
                    return Err(ServiceError::api(
                        StatusCode::BAD_REQUEST,
                        "invalid_jwks",
                        "JWKS must be a JSON object with a non-empty \"keys\" array",
                    ));
                }
                Some(val)
            }
            Err(_) => {
                return Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "invalid_jwks",
                    "JWKS must be valid JSON",
                ));
            }
        }
    } else {
        None
    };

    // Validate JWKS URI format if provided
    if let Some(jwks_uri_val) = jwks_uri_trimmed {
        match url::Url::parse(jwks_uri_val) {
            Ok(parsed) if parsed.scheme() == "https" => {}
            _ => {
                return Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "invalid_jwks_uri",
                    "JWKS URI must be a valid https:// URL",
                ));
            }
        }
    }

    // ── Authentication — validated input is good, now check credentials ──
    let token =
        extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    // Get existing application
    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application for update: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    // Verify ownership
    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    // Parse access scope if provided
    let access_scope = req
        .access_scope
        .as_ref()
        .and_then(|s| s.parse::<AccessScope>().ok());

    // Get user to check org membership if changing to organization scope
    let user = if access_scope == Some(AccessScope::Organization) {
        Some(
            db::get_user_by_id(&state.store, &token.sub)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to get user for scope validation: {e}");
                    ServiceError::api(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "db_error",
                        "Internal database error",
                    )
                })?
                .ok_or_else(|| {
                    ServiceError::api(StatusCode::NOT_FOUND, "not_found", "User not found")
                })?,
        )
    } else {
        None
    };

    // Validate: Organization scope requires user to have an org
    if access_scope == Some(AccessScope::Organization)
        && user.as_ref().is_some_and(|u| u.org_id.is_none())
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_access_scope",
            "Organization scope requires organization membership",
        ));
    }

    // Set org_id only for organization-scoped apps
    let org_id = if access_scope == Some(AccessScope::Organization) {
        user.as_ref().and_then(|u| u.org_id.as_deref())
    } else {
        None
    };

    // Apply updates (merge request values with existing client record)
    let name = req.name.as_deref().unwrap_or(&client.name);
    let description = req.description.as_deref().or(client.description.as_deref());
    let redirect_uris = req
        .redirect_uris
        .clone()
        .unwrap_or_else(|| client.redirect_uris.clone());

    // RFC 8707: Resource URIs default to existing if not provided.
    let resource_uris = req
        .resource_uris
        .as_deref()
        .map(|u| u.to_vec())
        .unwrap_or_else(|| client.resource_uris.clone());

    // Determine FAPI profile
    let is_fapi = req
        .fapi_profile
        .as_deref()
        .is_some_and(|p| p == "fapi2_security");

    // FAPI validation: must be a confidential client type
    if is_fapi
        && !matches!(
            client.application_type,
            OAuthClientType::Web | OAuthClientType::Service
        )
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_fapi_profile",
            "FAPI 2.0 Security Profile requires a confidential client type (web or service)",
        ));
    }

    // FAPI validation: require JWKS or JWKS URI (request or existing)
    if is_fapi
        && jwks_value.is_none()
        && jwks_uri_trimmed.is_none()
        && client.jwks.is_none()
        && client.jwks_uri.is_none()
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "missing_jwks",
            "FAPI 2.0 requires jwks or jwks_uri for private_key_jwt authentication",
        ));
    }

    // Compute FAPI-related values
    let fapi_profile = if is_fapi {
        FapiProfile::Fapi2Security
    } else if req.fapi_profile.is_some() {
        // Explicitly set to non-FAPI
        FapiProfile::None
    } else {
        client.fapi_profile
    };

    let token_endpoint_auth_method = if is_fapi {
        TokenEndpointAuthMethod::PrivateKeyJwt
    } else if !is_fapi && req.fapi_profile.is_some() && client.is_fapi() {
        // Transitioning from FAPI to Standard
        TokenEndpointAuthMethod::ClientSecretBasic
    } else {
        client.token_endpoint_auth_method
    };

    let effective_jwks = if jwks_value.is_some() {
        jwks_value.as_ref()
    } else if fapi_profile == FapiProfile::Fapi2Security {
        client.jwks.as_ref()
    } else {
        None
    };

    let effective_jwks_uri = if jwks_uri_trimmed.is_some() {
        jwks_uri_trimmed
    } else if fapi_profile == FapiProfile::Fapi2Security {
        client.jwks_uri.as_deref()
    } else {
        None
    };

    let dpop_bound = if is_fapi {
        true
    } else if req.fapi_profile.is_some() {
        false
    } else {
        client.dpop_bound_access_tokens
    };

    db::update_oauth_client(
        &state.store,
        &UpdateOAuthClientParams {
            id: &app_id,
            name,
            description,
            redirect_uris: &redirect_uris,
            access_scope,
            org_id,
            resource_uris: &resource_uris,
            token_endpoint_auth_method,
            jwks: effective_jwks,
            jwks_uri: effective_jwks_uri,
            fapi_profile,
            dpop_bound_access_tokens: dpop_bound,
        },
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to update OAuth client: {e}");
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Internal database error",
        )
    })?;

    // Fetch updated client
    let updated = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch updated application: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    tracing::info!("Updated OAuth application: {} ({})", name, client.client_id);

    Ok(Json(ApplicationResponse::from(updated)))
}

/// Delete an application (API).
/// DELETE /api/v1/applications/:id
pub async fn delete_application_api(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    ValidPath(app_id): ValidPath<ValidUuid>,
) -> Result<StatusCode, ServiceError> {
    let token =
        extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    // Verify ownership
    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application for deletion: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    db::delete_oauth_client(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete OAuth client: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    tracing::info!("Deleted OAuth application: {}", client.client_id);

    Ok(StatusCode::NO_CONTENT)
}

/// Add a new client secret (API).
/// POST /api/v1/applications/:id/secrets
pub async fn add_secret_api(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    ValidPath(app_id): ValidPath<ValidUuid>,
    Json(req): Json<AddSecretRequest>,
) -> Result<(StatusCode, Json<AddSecretResponse>), ServiceError> {
    let token =
        extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    if !client.application_type.requires_secret() {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "no_secret",
            "This application type does not use client secrets",
        ));
    }

    if client.is_fapi()
        && client.token_endpoint_auth_method == db::TokenEndpointAuthMethod::PrivateKeyJwt
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "no_secret",
            "FAPI clients using private_key_jwt do not use client secrets",
        ));
    }

    let now = jiff::Timestamp::now();
    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get secrets: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    let active_count = secrets.iter().filter(|s| s.is_valid(&now)).count();
    if active_count >= MAX_ACTIVE_SECRETS {
        return Err(ServiceError::api(
            StatusCode::CONFLICT,
            "max_secrets_reached",
            "Maximum of 2 active secrets allowed",
        ));
    }

    let secret = generate_client_secret();
    let secret_hash = hash_token(&secret);

    let record = db::create_oauth_client_secret(
        &state.store,
        &app_id,
        &secret_hash,
        req.description.as_deref(),
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create secret: {e}");
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Internal database error",
        )
    })?;

    if let Err(e) = db::record_oauth_event(
        &state.audit,
        &app_id,
        OAuthEventType::SecretAdded,
        Some(&token.sub),
        None,
        None,
        Some("Secret added"),
    )
    .await
    {
        tracing::warn!("Failed to record OAuth event: {e}");
    }

    tracing::info!("Added secret for OAuth application: {}", client.client_id);

    Ok((
        StatusCode::CREATED,
        Json(AddSecretResponse {
            secret_id: record.id,
            client_secret: secret,
            created_at: record.created_at,
            expires_at: record.expires_at,
        }),
    ))
}

/// List secrets for an application (API).
/// GET /api/v1/applications/:id/secrets
pub async fn list_secrets_api(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    ValidPath(app_id): ValidPath<ValidUuid>,
) -> Result<Json<ListSecretsResponse>, ServiceError> {
    let token =
        extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    let now = jiff::Timestamp::now();
    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get secrets: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    let secret_infos = secrets
        .into_iter()
        .map(|s| SecretInfo {
            active: s.is_valid(&now),
            id: s.id,
            description: s.description,
            created_at: s.created_at,
            expires_at: s.expires_at,
        })
        .collect();

    Ok(Json(ListSecretsResponse {
        secrets: secret_infos,
    }))
}

/// Delete (revoke) a secret (API).
/// DELETE /api/v1/applications/:id/secrets/:secret_id
pub async fn delete_secret_api(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    ValidPath((app_id, secret_id)): ValidPath<(ValidUuid, ValidUuid)>,
) -> Result<StatusCode, ServiceError> {
    let token =
        extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    let secret = db::get_oauth_client_secret_by_id(&state.store, &secret_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get secret: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Secret not found"))?;

    if secret.oauth_client_id != *app_id {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Secret not found",
        ));
    }

    if secret.revoked_at.is_some() {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Secret not found",
        ));
    }

    let now = jiff::Timestamp::now();
    let all_secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get secrets: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    let other_active = all_secrets
        .iter()
        .filter(|s| s.id != *secret_id && s.is_valid(&now))
        .count();

    if other_active == 0 {
        return Err(ServiceError::api(
            StatusCode::CONFLICT,
            "last_secret",
            "Cannot delete the last active secret",
        ));
    }

    db::revoke_oauth_client_secret(&state.store, &secret_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke secret: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    if let Err(e) = db::record_oauth_event(
        &state.audit,
        &app_id,
        OAuthEventType::SecretRevoked,
        Some(&token.sub),
        None,
        None,
        Some("Secret revoked"),
    )
    .await
    {
        tracing::warn!("Failed to record OAuth event: {e}");
    }

    tracing::info!(
        "Revoked secret {} for OAuth application: {}",
        secret_id,
        client.client_id
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Revoke all tokens for an application (API).
/// `POST /api/v1/applications/:id/revoke`
pub async fn revoke_tokens_api(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    ValidPath(app_id): ValidPath<ValidUuid>,
) -> Result<StatusCode, ServiceError> {
    let token =
        extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    // Verify ownership
    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application for token revocation: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    // Revoke all secrets (effectively revoking all tokens)
    db::revoke_all_oauth_client_secrets(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke all secrets: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    // Log the event
    if let Err(e) = db::record_oauth_event(
        &state.audit,
        &app_id,
        OAuthEventType::TokenRevoked,
        Some(&token.sub),
        None,
        None,
        Some("All tokens revoked"),
    )
    .await
    {
        tracing::warn!("Failed to record OAuth event: {e}");
    }

    tracing::info!(
        "Revoked all tokens for OAuth application: {}",
        client.client_id
    );

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use axum::http::StatusCode;

    use crate::test_utils::*;

    // ========================================================================
    // Helper: create a test app owned by a user, returning (app_id, token)
    // ========================================================================

    async fn setup_user_with_app(state: &crate::AppState, email: &str) -> (String, String) {
        let user = create_test_user(&state.store, email).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(state, &user.id, &user.email, &auth_id).await;
        let client = create_test_oauth_client(&state.store, &user.id).await;
        (client.app_id, token)
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    // ========================================================================
    // POST /api/v1/applications/:id/secrets — Add Secret
    // ========================================================================

    #[tokio::test]
    async fn test_add_secret_success() {
        let (app, state) = test_app().await;
        let (app_id, token) = setup_user_with_app(&state, "add-secret@example.com").await;
        let auth = bearer(&token);

        let (status, body) = http_post_json(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert!(json.get("secret_id").is_some());
        assert!(json.get("client_secret").is_some());
        assert!(json.get("created_at").is_some());

        let secret_value = json["client_secret"].as_str().unwrap();
        assert!(secret_value.starts_with("vouch_"));
    }

    #[tokio::test]
    async fn test_add_secret_with_description() {
        let (app, state) = test_app().await;
        let (app_id, token) = setup_user_with_app(&state, "add-desc@example.com").await;
        let auth = bearer(&token);

        let (status, _body) = http_post_json(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            r#"{"description": "CI/CD pipeline"}"#,
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // Verify description appears in list
        let (status, body) = http_get(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        let secrets = json["secrets"].as_array().unwrap();
        let has_desc = secrets
            .iter()
            .any(|s| s["description"].as_str() == Some("CI/CD pipeline"));
        assert!(has_desc, "Description should be visible in list");
    }

    #[tokio::test]
    async fn test_add_secret_max_reached() {
        let (app, state) = test_app().await;
        let (app_id, token) = setup_user_with_app(&state, "max-secrets@example.com").await;
        let auth = bearer(&token);

        // App already has 1 secret from creation. Add a second.
        let (status, _) = http_post_json(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // Third should fail (max is 2 active)
        let (status, body) = http_post_json(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(json["code"], "max_secrets_reached");
    }

    #[tokio::test]
    async fn test_add_secret_after_revoking_one() {
        let (app, state) = test_app().await;
        let (app_id, token) = setup_user_with_app(&state, "revoke-add@example.com").await;
        let auth = bearer(&token);

        // Add second secret (now at max)
        let (status, body) = http_post_json(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let second: serde_json::Value = serde_json::from_str(&body).unwrap();
        let second_id = second["secret_id"].as_str().unwrap();

        // Revoke the second secret
        let (status, _) = http_delete(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Now we should be able to add another
        let (status, _) = http_post_json(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_add_secret_unauthenticated() {
        let (app, state) = test_app().await;
        let (app_id, _token) = setup_user_with_app(&state, "unauth@example.com").await;

        let (status, _body) = http_post_json(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            r#"{}"#,
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_add_secret_wrong_owner() {
        let (app, state) = test_app().await;

        // Create app owned by user1
        let user1 = create_test_user(&state.store, "owner@example.com").await;
        let client = create_test_oauth_client(&state.store, &user1.id).await;

        // Authenticate as user2
        let user2 = create_test_user(&state.store, "other@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user2.id).await;
        let token2 = create_test_session(&state, &user2.id, &user2.email, &auth_id).await;
        let auth = bearer(&token2);

        let (status, _) = http_post_json(
            &app,
            &format!("/api/v1/applications/{}/secrets", client.app_id),
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_add_secret_nonexistent_app() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "noapp@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
        let auth = bearer(&token);

        let bogus_id = uuid::Uuid::now_v7();
        let (status, _) = http_post_json(
            &app,
            &format!("/api/v1/applications/{bogus_id}/secrets"),
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_add_secret_invalid_app_id() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "badid@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
        let auth = bearer(&token);

        let (status, _) = http_post_json(
            &app,
            "/api/v1/applications/not-a-uuid/secrets",
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // ========================================================================
    // ValidPath<ValidUuid> rejection — other endpoints
    // Each handler that uses ValidPath<ValidUuid> must return 400 for
    // a malformed UUID path segment, before any auth or DB check.
    // ========================================================================

    async fn authed_user(state: &crate::AppState, email: &str) -> String {
        let user = create_test_user(&state.store, email).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(state, &user.id, &user.email, &auth_id).await;
        bearer(&token)
    }

    #[tokio::test]
    async fn test_get_application_invalid_uuid_returns_400() {
        let (app, state) = test_app().await;
        let auth = authed_user(&state, "get-badid@example.com").await;

        let (status, body) = http_get(
            &app,
            "/api/v1/applications/not-a-uuid",
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    #[tokio::test]
    async fn test_delete_application_invalid_uuid_returns_400() {
        let (app, state) = test_app().await;
        let auth = authed_user(&state, "del-badid@example.com").await;

        let (status, body) = http_delete(
            &app,
            "/api/v1/applications/not-a-uuid",
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    #[tokio::test]
    async fn test_list_secrets_invalid_uuid_returns_400() {
        let (app, state) = test_app().await;
        let auth = authed_user(&state, "list-badid@example.com").await;

        let (status, body) = http_get(
            &app,
            "/api/v1/applications/not-a-uuid/secrets",
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    #[tokio::test]
    async fn test_revoke_tokens_invalid_uuid_returns_400() {
        let (app, state) = test_app().await;
        let auth = authed_user(&state, "revoke-badid@example.com").await;

        let (status, body) = http_post_json(
            &app,
            "/api/v1/applications/not-a-uuid/revoke",
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    #[tokio::test]
    async fn test_delete_secret_invalid_app_id_returns_400() {
        let (app, state) = test_app().await;
        let auth = authed_user(&state, "del-sec-badappid@example.com").await;
        let valid_uuid = uuid::Uuid::now_v7();

        let (status, body) = http_delete(
            &app,
            &format!("/api/v1/applications/not-a-uuid/secrets/{valid_uuid}"),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    #[tokio::test]
    async fn test_delete_secret_invalid_secret_id_returns_400() {
        let (app, state) = test_app().await;
        let auth = authed_user(&state, "del-sec-badsecid@example.com").await;
        let valid_uuid = uuid::Uuid::now_v7();

        let (status, body) = http_delete(
            &app,
            &format!("/api/v1/applications/{valid_uuid}/secrets/not-a-uuid"),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    #[tokio::test]
    async fn test_invalid_uuid_error_response_is_json() {
        // ValidPath must return a JSON error body (not a plain string or HTML)
        // when the path param fails UUID validation.
        let (app, state) = test_app().await;
        let auth = authed_user(&state, "json-err@example.com").await;

        let (status, body) = http_post_json(
            &app,
            "/api/v1/applications/not-a-uuid/secrets",
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        // ServiceError::api produces {"code": "...", "message": "..."}
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("error response must be valid JSON");
        assert!(
            json.get("code").is_some(),
            "JSON error response must contain 'code' field; got: {json}"
        );
    }

    // ========================================================================
    // GET /api/v1/applications/:id/secrets — List Secrets
    // ========================================================================

    #[tokio::test]
    async fn test_list_secrets_single() {
        let (app, state) = test_app().await;
        let (app_id, token) = setup_user_with_app(&state, "list-one@example.com").await;
        let auth = bearer(&token);

        let (status, body) = http_get(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        let secrets = json["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 1);

        let s = &secrets[0];
        assert!(s.get("id").is_some());
        assert!(s.get("created_at").is_some());
        assert_eq!(s["active"], true);
        // secret_hash must NOT be exposed
        assert!(s.get("secret_hash").is_none());
    }

    #[tokio::test]
    async fn test_list_secrets_shows_revoked() {
        let (app, state) = test_app().await;
        let (app_id, token) = setup_user_with_app(&state, "list-revoked@example.com").await;
        let auth = bearer(&token);

        // Add second secret
        let (_, body) = http_post_json(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;
        let second: serde_json::Value = serde_json::from_str(&body).unwrap();
        let second_id = second["secret_id"].as_str().unwrap();

        // Revoke it
        let (status, _) = http_delete(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // List should show both (1 active, 1 revoked)
        let (status, body) = http_get(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        let secrets = json["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 2);

        let active_count = secrets.iter().filter(|s| s["active"] == true).count();
        let revoked_count = secrets.iter().filter(|s| s["active"] == false).count();
        assert_eq!(active_count, 1);
        assert_eq!(revoked_count, 1);
    }

    #[tokio::test]
    async fn test_list_secrets_wrong_owner() {
        let (app, state) = test_app().await;

        let user1 = create_test_user(&state.store, "owner2@example.com").await;
        let client = create_test_oauth_client(&state.store, &user1.id).await;

        let user2 = create_test_user(&state.store, "other2@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user2.id).await;
        let token2 = create_test_session(&state, &user2.id, &user2.email, &auth_id).await;
        let auth = bearer(&token2);

        let (status, _) = http_get(
            &app,
            &format!("/api/v1/applications/{}/secrets", client.app_id),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ========================================================================
    // DELETE /api/v1/applications/:id/secrets/:secret_id — Delete Secret
    // ========================================================================

    #[tokio::test]
    async fn test_delete_secret_success() {
        let (app, state) = test_app().await;
        let (app_id, token) = setup_user_with_app(&state, "del-ok@example.com").await;
        let auth = bearer(&token);

        // Add second secret
        let (_, body) = http_post_json(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;
        let second: serde_json::Value = serde_json::from_str(&body).unwrap();
        let second_id = second["secret_id"].as_str().unwrap();

        // Delete the second secret
        let (status, _) = http_delete(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Verify it shows as inactive in list
        let (_, body) = http_get(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            &[("Authorization", &auth)],
        )
        .await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let secrets = json["secrets"].as_array().unwrap();
        let deleted = secrets.iter().find(|s| s["id"] == second_id).unwrap();
        assert_eq!(deleted["active"], false);
    }

    #[tokio::test]
    async fn test_delete_last_secret_rejected() {
        let (app, state) = test_app().await;
        let (app_id, token) = setup_user_with_app(&state, "del-last@example.com").await;
        let auth = bearer(&token);

        // Get the only secret's ID
        let (_, body) = http_get(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            &[("Authorization", &auth)],
        )
        .await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let secret_id = json["secrets"][0]["id"].as_str().unwrap();

        // Try to delete it
        let (status, body) = http_delete(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets/{secret_id}"),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(json["code"], "last_secret");
    }

    #[tokio::test]
    async fn test_delete_already_revoked() {
        let (app, state) = test_app().await;
        let (app_id, token) = setup_user_with_app(&state, "del-revoked@example.com").await;
        let auth = bearer(&token);

        // Add and then revoke a secret
        let (_, body) = http_post_json(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;
        let second: serde_json::Value = serde_json::from_str(&body).unwrap();
        let second_id = second["secret_id"].as_str().unwrap();

        let (status, _) = http_delete(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Try to delete again
        let (status, _) = http_delete(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_secret_wrong_app() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "wrong-app@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
        let auth = bearer(&token);

        // Create two apps
        let client1 = create_test_oauth_client(&state.store, &user.id).await;
        let client2 = create_test_oauth_client(&state.store, &user.id).await;

        // Get secret from app2
        let (_, body) = http_get(
            &app,
            &format!("/api/v1/applications/{}/secrets", client2.app_id),
            &[("Authorization", &auth)],
        )
        .await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let secret2_id = json["secrets"][0]["id"].as_str().unwrap();

        // Try to delete app2's secret via app1's route
        let (status, _) = http_delete(
            &app,
            &format!(
                "/api/v1/applications/{}/secrets/{secret2_id}",
                client1.app_id
            ),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_secret_wrong_owner() {
        let (app, state) = test_app().await;

        let user1 = create_test_user(&state.store, "del-owner1@example.com").await;
        let client = create_test_oauth_client(&state.store, &user1.id).await;

        let user2 = create_test_user(&state.store, "del-owner2@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user2.id).await;
        let token2 = create_test_session(&state, &user2.id, &user2.email, &auth_id).await;
        let auth = bearer(&token2);

        // Get secret ID from app (via db directly, since API would 404)
        let secrets = crate::db::get_oauth_client_secrets(&state.store, &client.app_id)
            .await
            .unwrap();
        let secret_id = &secrets[0].id;

        let (status, _) = http_delete(
            &app,
            &format!("/api/v1/applications/{}/secrets/{secret_id}", client.app_id),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ========================================================================
    // Edge Case: last-secret protection with revoked secrets
    // ========================================================================

    #[tokio::test]
    async fn test_cannot_delete_sole_active_when_other_revoked() {
        let (app, state) = test_app().await;
        let (app_id, token) = setup_user_with_app(&state, "sole-active@example.com").await;
        let auth = bearer(&token);

        // Add second secret (now 2 active)
        let (_, body) = http_post_json(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            r#"{}"#,
            &[("Authorization", &auth)],
        )
        .await;
        let second: serde_json::Value = serde_json::from_str(&body).unwrap();
        let second_id = second["secret_id"].as_str().unwrap();

        // Revoke the second (now 1 active + 1 revoked)
        let (status, _) = http_delete(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Get the remaining active secret's ID
        let (_, body) = http_get(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets"),
            &[("Authorization", &auth)],
        )
        .await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let secrets = json["secrets"].as_array().unwrap();
        let active_secret = secrets
            .iter()
            .find(|s| s["active"] == true)
            .expect("should have 1 active secret");
        let active_id = active_secret["id"].as_str().unwrap();

        // Trying to delete the sole active secret should fail,
        // even though there's a revoked secret present
        let (status, body) = http_delete(
            &app,
            &format!("/api/v1/applications/{app_id}/secrets/{active_id}"),
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(json["code"], "last_secret");
    }

    // ========================================================================
    // Validation-before-auth tests (Phase 1C defense-in-depth)
    // ========================================================================

    #[tokio::test]
    async fn test_create_app_empty_name_returns_400_without_auth() {
        let (app, _state) = test_app().await;

        let (status, body) = http_post_json(
            &app,
            "/api/v1/applications",
            r#"{"name": "  ", "application_type": "web", "redirect_uris": ["https://example.com/cb"]}"#,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Empty name must return 400 (not 401) even without auth: {body}"
        );
    }

    #[tokio::test]
    async fn test_create_app_invalid_type_returns_400_without_auth() {
        let (app, _state) = test_app().await;

        let (status, body) = http_post_json(
            &app,
            "/api/v1/applications",
            r#"{"name": "Test", "application_type": "invalid", "redirect_uris": ["https://example.com/cb"]}"#,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Invalid app type must return 400 (not 401) even without auth: {body}"
        );
    }

    #[tokio::test]
    async fn test_create_app_malformed_redirect_uri_returns_400_without_auth() {
        let (app, _state) = test_app().await;

        let (status, body) = http_post_json(
            &app,
            "/api/v1/applications",
            r#"{"name": "Test", "application_type": "web", "redirect_uris": ["not-a-url"]}"#,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Malformed redirect URI must return 400 (not 401) even without auth: {body}"
        );
    }

    #[tokio::test]
    async fn test_create_app_invalid_jwks_returns_400_without_auth() {
        let (app, _state) = test_app().await;

        let (status, body) = http_post_json(
            &app,
            "/api/v1/applications",
            r#"{"name": "Test", "application_type": "web", "redirect_uris": ["https://example.com/cb"], "jwks": "not-json"}"#,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Invalid JWKS must return 400 (not 401) even without auth: {body}"
        );
    }
}
