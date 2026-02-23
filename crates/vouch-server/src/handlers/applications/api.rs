// SPDX-License-Identifier: BUSL-1.1
//! API handlers for OAuth Application Registration.
//!
//! These handlers return JSON responses for programmatic access to
//! application management.

use crate::AppState;
use crate::db::{self, AccessScope, OAuthClientType, OAuthEventType};
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
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
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
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
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
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    // Generate client secret for confidential clients
    let client_secret = if app_type.requires_secret() {
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
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

        Some(secret)
    } else {
        None
    };

    tracing::info!("Created OAuth application: {} ({})", name, client_id);

    Ok(Json(CreateApplicationResponse {
        id: client.id,
        client_id,
        client_secret,
        name: name.to_string(),
        application_type: req.application_type,
        access_scope: access_scope.as_str().to_string(),
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
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
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
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
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
                    json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "db_error",
                        &e.to_string(),
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

    db::update_oauth_client(
        &state.db,
        &app_id,
        name,
        description,
        &redirect_uris,
        access_scope,
        org_id,
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    // Fetch updated client
    let updated = db::get_oauth_client_by_id(&state.db, &app_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
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
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
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
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
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
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
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
    let app_type = client.client_type().ok_or_else(|| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_type",
            "Invalid application type",
        )
    })?;

    if !app_type.requires_secret() {
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
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
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
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
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
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
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
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
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
