// SPDX-License-Identifier: BUSL-1.1
//! OAuth Application Registration handlers.
//!
//! This module implements the self-service portal for developers to register
//! OAuth applications that can integrate with Vouch.

use crate::AppState;
use crate::db::{self, OAuthClient, OAuthClientType, OAuthEventType};
use crate::impl_template_response;
use askama::Template;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use axum::{
    Form, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use headers::authorization::{Authorization, Bearer};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vouch_common::ApiError;

use super::common::AuthContext;
use super::{extract_session, extract_session_from_cookie, json_error};

// ============================================================================
// Constants
// ============================================================================

/// Length of generated client secrets in bytes.
const SECRET_LENGTH: usize = 32;

// ============================================================================
// Templates
// ============================================================================

/// Applications list page template.
#[derive(Template)]
#[template(path = "applications/list.html")]
pub struct ApplicationsListTemplate {
    pub applications: Vec<ApplicationInfo>,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Application info for display.
pub struct ApplicationInfo {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: Vec<String>,
    pub active: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

impl From<OAuthClient> for ApplicationInfo {
    fn from(client: OAuthClient) -> Self {
        let redirect_uris = client.get_redirect_uris();
        let active = client.is_active();
        Self {
            id: client.id,
            client_id: client.client_id,
            name: client.name,
            description: client.description,
            application_type: client.application_type,
            redirect_uris,
            active,
            created_at: client.created_at,
            last_used_at: client.last_used_at,
        }
    }
}

/// Application create page template.
#[derive(Template)]
#[template(path = "applications/create.html")]
#[allow(dead_code)]
pub struct ApplicationCreateTemplate {
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Application created success page (shows credentials once).
#[derive(Template)]
#[template(path = "applications/created.html")]
#[allow(dead_code)]
pub struct ApplicationCreatedTemplate {
    pub name: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub application_type: String,
    pub requires_secret: bool,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Application detail page template.
#[derive(Template)]
#[template(path = "applications/detail.html")]
#[allow(dead_code)]
pub struct ApplicationDetailTemplate {
    pub app: ApplicationInfo,
    pub secrets_count: usize,
    pub usage_stats: Vec<UsageStat>,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Usage stat for display.
pub struct UsageStat {
    pub event_type: String,
    pub count: i64,
}

/// Secret rotated success page (shows new secret once).
#[derive(Template)]
#[template(path = "applications/rotated.html")]
#[allow(dead_code)]
pub struct SecretRotatedTemplate {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Error page template.
#[derive(Template)]
#[template(path = "applications/error.html")]
pub struct ApplicationErrorTemplate {
    pub title: String,
    pub message: String,
    pub back_url: String,
}

/// Unauthorized template.
#[derive(Template)]
#[template(path = "applications/unauthorized.html")]
pub struct ApplicationUnauthorizedTemplate;

impl_template_response!(
    ApplicationsListTemplate,
    ApplicationCreateTemplate,
    ApplicationCreatedTemplate,
    ApplicationDetailTemplate,
    SecretRotatedTemplate,
    ApplicationErrorTemplate,
);

// Note: ApplicationUnauthorizedTemplate needs a custom implementation
// because it returns a different status code
impl IntoResponse for ApplicationUnauthorizedTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => (StatusCode::UNAUTHORIZED, Html(html)).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Form data for creating an application.
#[derive(Debug, Deserialize)]
pub struct CreateApplicationForm {
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: String,
}

/// Form data for updating an application.
#[derive(Debug, Deserialize)]
pub struct UpdateApplicationForm {
    pub name: String,
    pub description: Option<String>,
    pub redirect_uris: String,
}

/// API request for creating an application.
#[derive(Debug, Deserialize)]
pub struct CreateApplicationRequest {
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: Vec<String>,
}

/// API request for updating an application.
#[derive(Debug, Deserialize)]
pub struct UpdateApplicationRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
}

/// API response for a created application.
#[derive(Debug, Serialize)]
pub struct CreateApplicationResponse {
    pub id: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub name: String,
    pub application_type: String,
}

/// API response for application details.
#[derive(Debug, Serialize)]
pub struct ApplicationResponse {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: Vec<String>,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
}

impl From<OAuthClient> for ApplicationResponse {
    fn from(client: OAuthClient) -> Self {
        let redirect_uris = client.get_redirect_uris();
        let active = client.is_active();
        Self {
            id: client.id,
            client_id: client.client_id,
            name: client.name,
            description: client.description,
            application_type: client.application_type,
            redirect_uris,
            active,
            created_at: client.created_at,
            updated_at: client.updated_at,
            last_used_at: client.last_used_at,
        }
    }
}

/// API response for listing applications.
#[derive(Debug, Serialize)]
pub struct ListApplicationsResponse {
    pub applications: Vec<ApplicationResponse>,
}

/// API response for secret rotation.
#[derive(Debug, Serialize)]
pub struct RotateSecretResponse {
    pub client_secret: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Hash a secret for storage.
fn hash_secret(secret: &str) -> String {
    hex::encode(digest::digest(&SHA256, secret.as_bytes()))
}

/// Generate a secure random client secret.
///
/// # Panics
/// Panics if the system RNG fails.
#[allow(clippy::expect_used)]
fn generate_client_secret() -> String {
    let mut bytes = [0u8; SECRET_LENGTH];
    aws_rand::fill(&mut bytes).expect("RNG failure");
    format!("vouch_{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Extract auth context from cookie for web UI.
///
/// Returns `Some(AuthContext)` if a valid session exists, `None` otherwise.
async fn extract_auth_from_cookie(state: &AppState, jar: &CookieJar) -> Option<AuthContext> {
    // Use shared cookie extraction
    let session = extract_session_from_cookie(state, jar).await.ok()?;

    // Get user info
    let user = db::get_user_by_id(&state.db, &session.claims.sub)
        .await
        .ok()??;

    Some(AuthContext {
        authenticated: true,
        user_id: Some(session.claims.sub),
        user_email: Some(user.email),
        has_org: user.org_id.is_some(),
        is_org_admin: user.is_org_admin,
    })
}

/// Parse redirect URIs from form input (newline or comma separated).
fn parse_redirect_uris(input: &str) -> Vec<String> {
    input
        .lines()
        .flat_map(|line| line.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ============================================================================
// Web UI Handlers
// ============================================================================

/// List user's applications.
/// GET /applications
pub async fn list_applications_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();
    let applications = match db::get_oauth_clients_for_user(&state.db, user_id).await {
        Ok(apps) => apps.into_iter().map(ApplicationInfo::from).collect(),
        Err(e) => {
            tracing::error!("Failed to list applications: {}", e);
            return ApplicationErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to load applications.".to_string(),
                back_url: "/".to_string(),
            }
            .into_response();
        }
    };

    ApplicationsListTemplate { applications, auth }.into_response()
}

/// Show create application form.
/// GET /applications/new
pub async fn create_application_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    ApplicationCreateTemplate { auth }.into_response()
}

/// Create a new application.
/// POST /applications/new
pub async fn create_application_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<CreateApplicationForm>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Validate inputs
    let name = form.name.trim();
    if name.is_empty() {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "Application name is required.".to_string(),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    }

    let Some(app_type) = OAuthClientType::from_str(&form.application_type) else {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "Invalid application type.".to_string(),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    };

    let redirect_uris = parse_redirect_uris(&form.redirect_uris);

    // For non-service apps, at least one redirect URI is required
    if !matches!(app_type, OAuthClientType::Service) && redirect_uris.is_empty() {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "At least one redirect URI is required.".to_string(),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    }

    // Create the application
    let (client, client_id) = match db::create_oauth_client(
        &state.db,
        user_id,
        name,
        form.description.as_deref(),
        app_type,
        &redirect_uris,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create application: {}", e);
            return ApplicationErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create application.".to_string(),
                back_url: "/applications/new".to_string(),
            }
            .into_response();
        }
    };

    // Generate client secret for confidential clients
    let client_secret = if app_type.requires_secret() {
        let secret = generate_client_secret();
        let secret_hash = hash_secret(&secret);

        if let Err(e) = db::create_oauth_client_secret(
            &state.db,
            &client.id,
            &secret_hash,
            Some("Initial secret"),
            None,
        )
        .await
        {
            tracing::error!("Failed to create client secret: {}", e);
            // Clean up the client
            if let Err(cleanup_err) = db::delete_oauth_client(&state.db, &client.id).await {
                tracing::warn!(
                    "Failed to clean up OAuth client after secret creation failure: {cleanup_err}"
                );
            }
            return ApplicationErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create application.".to_string(),
                back_url: "/applications/new".to_string(),
            }
            .into_response();
        }

        Some(secret)
    } else {
        None
    };

    tracing::info!("Created OAuth application: {} ({})", name, client_id);

    ApplicationCreatedTemplate {
        name: name.to_string(),
        client_id,
        client_secret,
        application_type: form.application_type,
        requires_secret: app_type.requires_secret(),
        auth,
    }
    .into_response()
}

/// Show application details.
/// GET /applications/:id
pub async fn detail_application_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Get the application
    let client = match db::get_oauth_client_by_id(&state.db, &app_id).await {
        Ok(Some(c)) if c.user_id == user_id => c,
        Ok(Some(_)) => {
            return ApplicationErrorTemplate {
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
        Ok(None) => {
            return ApplicationErrorTemplate {
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get application: {}", e);
            return ApplicationErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to load application.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
    };

    // Get secrets count
    let secrets_count = match db::get_oauth_client_secrets(&state.db, &app_id).await {
        Ok(s) => s.iter().filter(|s| s.revoked_at.is_none()).count(),
        Err(_) => 0,
    };

    // Get usage stats
    let usage_stats = match db::get_oauth_usage_stats(&state.db, &app_id, None).await {
        Ok(stats) => stats
            .into_iter()
            .map(|s| UsageStat {
                event_type: s.event_type,
                count: s.count,
            })
            .collect(),
        Err(_) => vec![],
    };

    ApplicationDetailTemplate {
        app: ApplicationInfo::from(client),
        secrets_count,
        usage_stats,
        auth,
    }
    .into_response()
}

/// Update an application.
/// POST /applications/:id
pub async fn update_application_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
    Form(form): Form<UpdateApplicationForm>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Verify ownership
    let client = match db::get_oauth_client_by_id(&state.db, &app_id).await {
        Ok(Some(c)) if c.user_id == user_id => c,
        _ => {
            return ApplicationErrorTemplate {
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
    };

    // Validate inputs
    let name = form.name.trim();
    if name.is_empty() {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "Application name is required.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    let redirect_uris = parse_redirect_uris(&form.redirect_uris);

    // Update the application
    if let Err(e) = db::update_oauth_client(
        &state.db,
        &app_id,
        name,
        form.description.as_deref(),
        &redirect_uris,
    )
    .await
    {
        tracing::error!("Failed to update application: {}", e);
        return ApplicationErrorTemplate {
            title: "Error".to_string(),
            message: "Failed to update application.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    tracing::info!("Updated OAuth application: {} ({})", name, client.client_id);

    Redirect::to(&format!("/applications/{}", app_id)).into_response()
}

/// Delete an application.
/// POST /applications/:id/delete
pub async fn delete_application_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Verify ownership
    let client = match db::get_oauth_client_by_id(&state.db, &app_id).await {
        Ok(Some(c)) if c.user_id == user_id => c,
        _ => {
            return ApplicationErrorTemplate {
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
    };

    // Delete the application
    if let Err(e) = db::delete_oauth_client(&state.db, &app_id).await {
        tracing::error!("Failed to delete application: {}", e);
        return ApplicationErrorTemplate {
            title: "Error".to_string(),
            message: "Failed to delete application.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    tracing::info!("Deleted OAuth application: {}", client.client_id);

    Redirect::to("/applications").into_response()
}

/// Rotate client secret.
/// POST /applications/:id/rotate
pub async fn rotate_secret_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Verify ownership
    let client = match db::get_oauth_client_by_id(&state.db, &app_id).await {
        Ok(Some(c)) if c.user_id == user_id => c,
        _ => {
            return ApplicationErrorTemplate {
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
    };

    // Check if this client type supports secrets
    let Some(app_type) = client.client_type() else {
        return ApplicationErrorTemplate {
            title: "Error".to_string(),
            message: "Invalid application type.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    };

    if !app_type.requires_secret() {
        return ApplicationErrorTemplate {
            title: "Error".to_string(),
            message: "This application type does not use client secrets.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    // Generate new secret
    let secret = generate_client_secret();
    let secret_hash = hash_secret(&secret);

    // Revoke old secrets
    if let Err(e) = db::revoke_all_oauth_client_secrets(&state.db, &app_id).await {
        tracing::error!("Failed to revoke old secrets: {}", e);
    }

    // Create new secret
    if let Err(e) = db::create_oauth_client_secret(
        &state.db,
        &app_id,
        &secret_hash,
        Some("Rotated secret"),
        None,
    )
    .await
    {
        tracing::error!("Failed to create new secret: {}", e);
        return ApplicationErrorTemplate {
            title: "Error".to_string(),
            message: "Failed to rotate secret.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    tracing::info!("Rotated secret for OAuth application: {}", client.client_id);

    SecretRotatedTemplate {
        name: client.name,
        client_id: client.client_id,
        client_secret: secret,
        auth,
    }
    .into_response()
}

// ============================================================================
// API Handlers
// ============================================================================

/// List user's applications (API).
/// GET /api/v1/applications
pub async fn list_applications_api(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<Json<ListApplicationsResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header).await?;
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
    Json(req): Json<CreateApplicationRequest>,
) -> Result<Json<CreateApplicationResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header).await?;
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

    // For non-service apps, at least one redirect URI is required
    if !matches!(app_type, OAuthClientType::Service) && req.redirect_uris.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uris",
            "At least one redirect URI is required",
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
        let secret_hash = hash_secret(&secret);

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
    }))
}

/// Get application details (API).
/// GET /api/v1/applications/:id
pub async fn get_application_api(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    Path(app_id): Path<String>,
) -> Result<Json<ApplicationResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header).await?;
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
    Path(app_id): Path<String>,
    Json(req): Json<UpdateApplicationRequest>,
) -> Result<Json<ApplicationResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header).await?;
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

    // Apply updates
    let name = req.name.as_deref().unwrap_or(&client.name);
    let description = req.description.as_deref().or(client.description.as_deref());
    let redirect_uris = req
        .redirect_uris
        .clone()
        .unwrap_or_else(|| client.get_redirect_uris());

    db::update_oauth_client(&state.db, &app_id, name, description, &redirect_uris)
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
    Path(app_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header).await?;
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
    Path(app_id): Path<String>,
) -> Result<Json<RotateSecretResponse>, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header).await?;
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
    let secret_hash = hash_secret(&secret);

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
        created_at: secret_record.created_at,
        expires_at: secret_record.expires_at,
    }))
}

/// Revoke all tokens for an application (API).
/// POST /api/v1/applications/:id/revoke
pub async fn revoke_tokens_api(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    Path(app_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let session = extract_session(&state, auth_header).await?;
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
