// SPDX-License-Identifier: BUSL-1.1
//! API handlers for OAuth Application Registration.
//!
//! These handlers return JSON responses for programmatic access to
//! application management.

use crate::AppState;
use crate::db::{
    self, AccessScope, FapiProfile, OAuthClientType, OAuthEventType, UpdateOAuthClientParams,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::CookieJar;
use headers::authorization::{Authorization, Bearer};
use std::sync::Arc;
use vouch_common::ApiError;

use super::types::{
    ApplicationResponse, CreateApplicationRequest, CreateApplicationResponse,
    ListApplicationsResponse, RotateSecretResponse, UpdateApplicationRequest,
};
use super::{generate_client_secret, validate_redirect_uris};
use crate::handlers::{extract_session, hash_token, json_error};
use crate::services::oidc::ResourceUri;

/// List user's applications (API).
/// GET /api/v1/applications
pub async fn list_applications_api(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
) -> Result<Json<ListApplicationsResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header, &jar).await?;
    let claims = session.claims;

    let applications = db::get_oauth_clients_for_user(&state.db, &claims.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list applications: {e}");
            json_error(
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
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Json(req): Json<CreateApplicationRequest>,
) -> Result<Json<CreateApplicationResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header, &jar).await?;
    let claims = session.claims;

    // Validate inputs
    let name = req.name.trim();
    if name.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "Application name is required",
        ));
    }

    let app_type = OAuthClientType::from_str(&req.application_type).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_type",
            "Invalid application type. Must be: web, native, spa, or service",
        )
    })?;

    // Parse access scope (default to personal if not provided)
    let access_scope = req
        .access_scope
        .as_ref()
        .and_then(|s| AccessScope::from_str(s))
        .unwrap_or_default();

    // Get user to check org membership
    let user = db::get_user_by_id(&state.db, &claims.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "not_found", "User not found"))?;

    // Validate: Organization scope requires user to have an org
    if access_scope == AccessScope::Organization && user.org_id.is_none() {
        return Err(json_error(
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

    // For non-service apps, at least one redirect URI is required
    if !matches!(app_type, OAuthClientType::Service) && req.redirect_uris.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uris",
            "At least one redirect URI is required",
        ));
    }

    // Validate redirect URIs are valid URLs
    if let Err(invalid) = validate_redirect_uris(&req.redirect_uris) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uris",
            &format!(
                "Invalid redirect URI(s): {}. Each URI must be a valid http:// or https:// URL.",
                invalid.join(", ")
            ),
        ));
    }

    // RFC 8707: Resource URIs default to empty if not provided.
    let resource_uris = req.resource_uris.as_deref().unwrap_or(&[]);

    // Validate resource URIs per RFC 8707 (absolute URI, no fragment).
    for uri in resource_uris {
        if let Err(e) = ResourceUri::parse(uri) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "invalid_resource_uri",
                &format!("Invalid resource URI '{uri}': {e}"),
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
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_fapi_profile",
            "FAPI 2.0 Security Profile requires a confidential client type (web or service)",
        ));
    }

    // FAPI validation: require JWKS or JWKS URI
    let jwks_trimmed = req.jwks.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let jwks_uri_trimmed = req
        .jwks_uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if is_fapi && jwks_trimmed.is_none() && jwks_uri_trimmed.is_none() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "missing_jwks",
            "FAPI 2.0 requires jwks or jwks_uri for private_key_jwt authentication",
        ));
    }

    // Validate JWKS JSON if provided
    if let Some(jwks_json) = jwks_trimmed {
        match serde_json::from_str::<serde_json::Value>(jwks_json) {
            Ok(val) => {
                if !val
                    .get("keys")
                    .is_some_and(|k| k.is_array() && !k.as_array().is_some_and(|a| a.is_empty()))
                {
                    return Err(json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_jwks",
                        "JWKS must be a JSON object with a non-empty \"keys\" array",
                    ));
                }
            }
            Err(_) => {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_jwks",
                    "JWKS must be valid JSON",
                ));
            }
        }
    }

    // Validate JWKS URI if provided
    if let Some(uri) = jwks_uri_trimmed {
        match url::Url::parse(uri) {
            Ok(parsed) if parsed.scheme() == "https" => {}
            _ => {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_jwks_uri",
                    "JWKS URI must be a valid https:// URL",
                ));
            }
        }
    }

    // Create the application
    let (client, client_id) = db::create_oauth_client(
        &state.db,
        &claims.sub,
        name,
        req.description.as_deref(),
        app_type,
        &req.redirect_uris,
        access_scope,
        org_id,
        resource_uris,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create OAuth client: {e}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Internal database error",
        )
    })?;

    // If FAPI is enabled, update the client with FAPI settings
    if is_fapi {
        db::update_oauth_client(
            &state.db,
            &UpdateOAuthClientParams {
                id: &client.id,
                name,
                description: req.description.as_deref(),
                redirect_uris: &req.redirect_uris,
                access_scope: Some(access_scope),
                org_id,
                resource_uris,
                token_endpoint_auth_method: "private_key_jwt",
                jwks: jwks_trimmed,
                jwks_uri: jwks_uri_trimmed,
                fapi_profile: FapiProfile::Fapi2Security,
                dpop_bound_access_tokens: true,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to apply FAPI settings: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;
    }

    // Generate client secret for confidential clients (skip for FAPI — they use private_key_jwt)
    let client_secret = if app_type.requires_secret() && !is_fapi {
        let secret = generate_client_secret();
        let secret_hash = hash_token(&secret);

        db::create_oauth_client_secret(
            &state.db,
            &client.id,
            &secret_hash,
            Some("Initial secret"),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create client secret: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

        Some(secret)
    } else {
        None
    };

    // Re-fetch to get final state (with FAPI settings applied)
    let final_client = if is_fapi {
        db::get_oauth_client_by_id(&state.db, &client.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to refetch client: {e}");
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    "Internal database error",
                )
            })?
            .ok_or_else(|| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    "Internal database error",
                )
            })?
    } else {
        client
    };

    tracing::info!("Created OAuth application: {} ({})", name, client_id);

    let jwks_configured = final_client.jwks.is_some() || final_client.jwks_uri.is_some();
    let response_jwks_uri = final_client.jwks_uri.clone();

    Ok(Json(CreateApplicationResponse {
        id: final_client.id,
        client_id,
        client_secret,
        name: name.to_string(),
        application_type: req.application_type,
        access_scope: access_scope.as_str().to_string(),
        resource_uris: resource_uris.to_vec(),
        token_endpoint_auth_method: final_client.token_endpoint_auth_method,
        fapi_profile: final_client.fapi_profile,
        jwks_configured,
        jwks_uri: response_jwks_uri,
    }))
}

/// Get application details (API).
/// GET /api/v1/applications/:id
pub async fn get_application_api(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Result<Json<ApplicationResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header, &jar).await?;
    let claims = session.claims;

    let client = db::get_oauth_client_by_id(&state.db, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "not_found", "Application not found"))?;

    // Verify ownership
    if client.user_id != claims.sub {
        return Err(json_error(
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
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
    Json(req): Json<UpdateApplicationRequest>,
) -> Result<Json<ApplicationResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header, &jar).await?;
    let claims = session.claims;

    // Get existing application
    let client = db::get_oauth_client_by_id(&state.db, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application for update: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "not_found", "Application not found"))?;

    // Verify ownership
    if client.user_id != claims.sub {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    // Parse access scope if provided
    let access_scope = req
        .access_scope
        .as_ref()
        .and_then(|s| AccessScope::from_str(s));

    // Get user to check org membership if changing to organization scope
    let user = if access_scope == Some(AccessScope::Organization) {
        Some(
            db::get_user_by_id(&state.db, &claims.sub)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to get user for scope validation: {e}");
                    json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "db_error",
                        "Internal database error",
                    )
                })?
                .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "not_found", "User not found"))?,
        )
    } else {
        None
    };

    // Validate: Organization scope requires user to have an org
    if access_scope == Some(AccessScope::Organization)
        && user.as_ref().is_some_and(|u| u.org_id.is_none())
    {
        return Err(json_error(
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

    // Apply updates
    let name = req.name.as_deref().unwrap_or(&client.name);
    let description = req.description.as_deref().or(client.description.as_deref());
    let redirect_uris = req
        .redirect_uris
        .clone()
        .unwrap_or_else(|| client.get_redirect_uris());

    // Validate redirect URIs are valid URLs
    if let Err(invalid) = validate_redirect_uris(&redirect_uris) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uris",
            &format!(
                "Invalid redirect URI(s): {}. Each URI must be a valid http:// or https:// URL.",
                invalid.join(", ")
            ),
        ));
    }

    // RFC 8707: Resource URIs default to existing if not provided.
    let resource_uris = req
        .resource_uris
        .as_deref()
        .map(|u| u.to_vec())
        .unwrap_or_else(|| client.get_resource_uris());

    // Validate resource URIs per RFC 8707 (absolute URI, no fragment).
    for uri in &resource_uris {
        if let Err(e) = ResourceUri::parse(uri) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "invalid_resource_uri",
                &format!("Invalid resource URI '{uri}': {e}"),
            ));
        }
    }

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
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_fapi_profile",
            "FAPI 2.0 Security Profile requires a confidential client type (web or service)",
        ));
    }

    // FAPI validation: require JWKS or JWKS URI
    let jwks_trimmed = req.jwks.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let jwks_uri_trimmed = req
        .jwks_uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if is_fapi
        && jwks_trimmed.is_none()
        && jwks_uri_trimmed.is_none()
        && client.jwks.is_none()
        && client.jwks_uri.is_none()
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "missing_jwks",
            "FAPI 2.0 requires jwks or jwks_uri for private_key_jwt authentication",
        ));
    }

    // Validate JWKS JSON if provided
    if let Some(jwks_json) = jwks_trimmed {
        match serde_json::from_str::<serde_json::Value>(jwks_json) {
            Ok(val) => {
                if !val
                    .get("keys")
                    .is_some_and(|k| k.is_array() && !k.as_array().is_some_and(|a| a.is_empty()))
                {
                    return Err(json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_jwks",
                        "JWKS must be a JSON object with a non-empty \"keys\" array",
                    ));
                }
            }
            Err(_) => {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_jwks",
                    "JWKS must be valid JSON",
                ));
            }
        }
    }

    // Validate JWKS URI if provided
    if let Some(uri) = jwks_uri_trimmed {
        match url::Url::parse(uri) {
            Ok(parsed) if parsed.scheme() == "https" => {}
            _ => {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_jwks_uri",
                    "JWKS URI must be a valid https:// URL",
                ));
            }
        }
    }

    // Compute FAPI-related values
    let fapi_profile = if is_fapi {
        FapiProfile::Fapi2Security
    } else if req.fapi_profile.is_some() {
        // Explicitly set to non-FAPI
        FapiProfile::None
    } else {
        client.fapi_profile()
    };

    let token_endpoint_auth_method = if is_fapi {
        "private_key_jwt"
    } else if !is_fapi && req.fapi_profile.is_some() && client.is_fapi() {
        // Transitioning from FAPI to Standard
        "client_secret_basic"
    } else {
        client.token_endpoint_auth_method.as_str()
    };

    let effective_jwks = if jwks_trimmed.is_some() {
        jwks_trimmed
    } else if fapi_profile == FapiProfile::Fapi2Security {
        client.jwks.as_deref()
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
        &state.db,
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
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Internal database error",
        )
    })?;

    // Fetch updated client
    let updated = db::get_oauth_client_by_id(&state.db, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch updated application: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "not_found", "Application not found"))?;

    tracing::info!("Updated OAuth application: {} ({})", name, client.client_id);

    Ok(Json(ApplicationResponse::from(updated)))
}

/// Delete an application (API).
/// DELETE /api/v1/applications/:id
pub async fn delete_application_api(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header, &jar).await?;
    let claims = session.claims;

    // Verify ownership
    let client = db::get_oauth_client_by_id(&state.db, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application for deletion: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "not_found", "Application not found"))?;

    if client.user_id != claims.sub {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    db::delete_oauth_client(&state.db, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete OAuth client: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    tracing::info!("Deleted OAuth application: {}", client.client_id);

    Ok(StatusCode::NO_CONTENT)
}

/// Rotate client secret (API).
/// POST /api/v1/applications/:id/rotate
pub async fn rotate_secret_api(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Result<Json<RotateSecretResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header, &jar).await?;
    let claims = session.claims;

    // Verify ownership
    let client = db::get_oauth_client_by_id(&state.db, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application for secret rotation: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "not_found", "Application not found"))?;

    if client.user_id != claims.sub {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    // Check if this client type supports secrets
    if !client.application_type.requires_secret() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "no_secret",
            "This application type does not use client secrets",
        ));
    }

    // Generate new secret
    let secret = generate_client_secret();
    let secret_hash = hash_token(&secret);

    // Revoke old secrets
    db::revoke_all_oauth_client_secrets(&state.db, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke old secrets: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    // Create new secret
    let secret_record = db::create_oauth_client_secret(
        &state.db,
        &app_id,
        &secret_hash,
        Some("Rotated secret"),
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create rotated secret: {e}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Internal database error",
        )
    })?;

    tracing::info!("Rotated secret for OAuth application: {}", client.client_id);

    Ok(Json(RotateSecretResponse {
        client_secret: secret,
        created_at: secret_record.created_at.to_jiff().to_string(),
        expires_at: secret_record.expires_at.map(|ts| ts.to_jiff().to_string()),
    }))
}

/// Revoke all tokens for an application (API).
/// POST /api/v1/applications/:id/revoke
pub async fn revoke_tokens_api(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header, &jar).await?;
    let claims = session.claims;

    // Verify ownership
    let client = db::get_oauth_client_by_id(&state.db, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application for token revocation: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "not_found", "Application not found"))?;

    if client.user_id != claims.sub {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    // Revoke all secrets (effectively revoking all tokens)
    db::revoke_all_oauth_client_secrets(&state.db, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke all secrets: {e}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    // Log the event
    if let Err(e) = db::record_oauth_event(
        &state.db,
        &app_id,
        OAuthEventType::TokenRevoked,
        Some(&claims.sub),
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
