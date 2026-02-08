// SPDX-License-Identifier: BUSL-1.1
//! Integrations page handler and cloud integration APIs.
//!
//! Shows available integrations and their connection status:
//! - GitHub (org-wide, requires org membership)
//! - GCP (org-wide config, per-user setup)
//! - AWS (org-wide config, per-user setup)
//! - SSH (per-user, CLI setup)
//! - Kubernetes (coming soon)
//!
//! Also provides API endpoints for managing cloud integration configs:
//! - GET/PUT/DELETE /v1/integrations/gcp
//! - GET/PUT/DELETE /v1/integrations/aws
//!
//! Browser-based configuration:
//! - GET/POST /gcp/configure - Configure GCP via browser form
//! - POST /gcp/configure/delete - Delete GCP configuration

use crate::db;
use crate::handlers::common::{AuthContext, extract_session, get_auth_context};
use crate::{AppState, impl_template_response};
use askama::Template;
use axum::Form;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::CookieJar;
use headers::authorization::{Authorization, Bearer};
use serde::Deserialize;
use std::sync::Arc;
use vouch_common::{
    ApiError, AwsIntegrationConfig, GcpIntegrationConfig, IntegrationConfigResponse,
};

use super::json_error;

// ============================================================================
// Templates
// ============================================================================

/// Integrations page template.
#[derive(Template)]
#[template(path = "integrations.html")]
pub struct IntegrationsTemplate {
    /// Authentication context for header display.
    pub auth: AuthContext,
    /// Whether the server has GitHub App configured.
    pub github_configured: bool,
    /// Connected GitHub accounts (for org members).
    pub github_accounts: Vec<String>,
    /// Whether GCP integration is configured for the org.
    pub gcp_configured: bool,
    /// GCP configuration details (for display).
    pub gcp_config: Option<GcpIntegrationConfig>,
    /// Whether the SSH CA is configured on the server.
    pub ssh_ca_configured: bool,
    /// SSH CA public key in OpenSSH format (when configured).
    pub ssh_ca_public_key: Option<String>,
}

impl_template_response!(IntegrationsTemplate);

/// GCP configuration page template.
#[derive(Template)]
#[template(path = "gcp/configure.html")]
pub struct GcpConfigureTemplate {
    /// Authentication context for header display.
    pub auth: AuthContext,
    /// Current configuration (empty for new config).
    pub config: GcpIntegrationConfig,
    /// Whether we're editing existing config.
    pub editing: bool,
    /// Error message to display.
    pub error: Option<String>,
    /// Success message to display.
    pub success: Option<String>,
}

impl_template_response!(GcpConfigureTemplate);

/// Form data for GCP configuration.
#[derive(Debug, Deserialize)]
pub struct GcpConfigureForm {
    pub project_number: String,
    pub pool_id: String,
    pub provider_id: String,
    #[serde(default)]
    pub service_account: Option<String>,
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /integrations - Show integrations page.
pub async fn integrations_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    let auth = get_auth_context(&state, &jar).await;

    // Redirect unauthenticated users to enrollment
    if !auth.authenticated {
        return Redirect::to("/enroll/start").into_response();
    }

    // Check if GitHub App is configured on the server
    let github_configured = state.github_app.is_some();

    // Check if SSH CA is configured on the server and get its public key
    let ssh_ca_configured = state.ssh_ca.is_some();
    let ssh_ca_public_key = state
        .ssh_ca
        .as_ref()
        .and_then(|ca| ca.public_key().ok());

    // Get connected GitHub accounts and GCP config status if user has an org
    let (github_accounts, gcp_configured, gcp_config) = if auth.has_org {
        // We need to get the user's org_id to fetch installations
        if let Ok(session) =
            crate::handlers::common::extract_session_from_cookie(&state, &jar).await
        {
            if let Ok(Some(user)) = db::get_user_by_id(&state.db, &session.claims.sub).await {
                if let Some(org_id) = &user.org_id {
                    let github_accounts = db::get_github_installations_by_org(&state.db, org_id)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .map(|i| i.github_account_login)
                        .collect();
                    let gcp_integration = db::get_cloud_integration(&state.db, org_id, "gcp")
                        .await
                        .unwrap_or(None);
                    let gcp_configured = gcp_integration.is_some();
                    let gcp_config = gcp_integration
                        .and_then(|i| serde_json::from_str::<GcpIntegrationConfig>(&i.config).ok());
                    (github_accounts, gcp_configured, gcp_config)
                } else {
                    (Vec::new(), false, None)
                }
            } else {
                (Vec::new(), false, None)
            }
        } else {
            (Vec::new(), false, None)
        }
    } else {
        (Vec::new(), false, None)
    };

    IntegrationsTemplate {
        auth,
        github_configured,
        github_accounts,
        gcp_configured,
        gcp_config,
        ssh_ca_configured,
        ssh_ca_public_key,
    }
    .into_response()
}

// ============================================================================
// Cloud Integration API Helpers
// ============================================================================

/// Extract authenticated user and their org_id.
/// Returns (user, org_id) or an error if not authenticated or no org.
async fn extract_user_with_org(
    state: &AppState,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: &CookieJar,
) -> Result<(db::User, String), (StatusCode, Json<ApiError>)> {
    let session = extract_session(state, auth_header, jar).await?;

    let user = db::get_user_by_id(&state.db, &session.claims.sub)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::UNAUTHORIZED, "unauthorized", "User not found"))?;

    let org_id = user.org_id.clone().ok_or_else(|| {
        json_error(
            StatusCode::FORBIDDEN,
            "no_organization",
            "Cloud integrations require organization membership",
        )
    })?;

    Ok((user, org_id))
}

/// Extract and validate an org admin from the JWT Bearer token.
/// Returns the user and their org_id if they are an org admin.
async fn extract_org_admin(
    state: &AppState,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: &CookieJar,
) -> Result<(db::User, String), (StatusCode, Json<ApiError>)> {
    let (user, org_id) = extract_user_with_org(state, auth_header, jar).await?;

    if !user.is_org_admin {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Organization admin access required",
        ));
    }

    Ok((user, org_id))
}

// ============================================================================
// GCP Integration API
// ============================================================================

/// GET /v1/integrations/gcp
/// Returns GCP config for authenticated user's organization.
pub async fn get_gcp_integration(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
) -> Result<Json<IntegrationConfigResponse<GcpIntegrationConfig>>, (StatusCode, Json<ApiError>)> {
    let (_user, org_id) = extract_user_with_org(&state, auth_header, &jar).await?;

    let integration = db::get_cloud_integration(&state.db, &org_id, "gcp")
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    match integration {
        Some(i) => {
            let config: GcpIntegrationConfig = serde_json::from_str(&i.config).map_err(|e| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "config_parse_error",
                    &format!("Failed to parse GCP config: {e}"),
                )
            })?;
            Ok(Json(IntegrationConfigResponse {
                configured: true,
                config: Some(config),
            }))
        }
        None => Ok(Json(IntegrationConfigResponse {
            configured: false,
            config: None,
        })),
    }
}

/// PUT /v1/integrations/gcp (org admin only)
/// Set or update GCP config for the organization.
pub async fn set_gcp_integration(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Json(config): Json<GcpIntegrationConfig>,
) -> Result<Json<GcpIntegrationConfig>, (StatusCode, Json<ApiError>)> {
    let (user, org_id) = extract_org_admin(&state, auth_header, &jar).await?;

    // Validate config
    if config.project_number.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_config",
            "project_number is required",
        ));
    }
    if config.pool_id.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_config",
            "pool_id is required",
        ));
    }
    if config.provider_id.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_config",
            "provider_id is required",
        ));
    }

    let config_json = serde_json::to_string(&config).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialize_error",
            &e.to_string(),
        )
    })?;

    db::upsert_cloud_integration(&state.db, &org_id, "gcp", &config_json, &user.id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    tracing::info!(
        user_id = %user.id,
        org_id = %org_id,
        "GCP integration configured"
    );

    Ok(Json(config))
}

/// DELETE /v1/integrations/gcp (org admin only)
/// Remove GCP config for the organization.
pub async fn delete_gcp_integration(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let (user, org_id) = extract_org_admin(&state, auth_header, &jar).await?;

    let deleted = db::delete_cloud_integration(&state.db, &org_id, "gcp")
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    if deleted {
        tracing::info!(
            user_id = %user.id,
            org_id = %org_id,
            "GCP integration removed"
        );
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "GCP integration not configured",
        ))
    }
}

// ============================================================================
// AWS Integration API
// ============================================================================

/// GET /v1/integrations/aws
/// Returns AWS config for authenticated user's organization.
pub async fn get_aws_integration(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
) -> Result<Json<IntegrationConfigResponse<AwsIntegrationConfig>>, (StatusCode, Json<ApiError>)> {
    let (_user, org_id) = extract_user_with_org(&state, auth_header, &jar).await?;

    let integration = db::get_cloud_integration(&state.db, &org_id, "aws")
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    match integration {
        Some(i) => {
            let config: AwsIntegrationConfig = serde_json::from_str(&i.config).map_err(|e| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "config_parse_error",
                    &format!("Failed to parse AWS config: {e}"),
                )
            })?;
            Ok(Json(IntegrationConfigResponse {
                configured: true,
                config: Some(config),
            }))
        }
        None => Ok(Json(IntegrationConfigResponse {
            configured: false,
            config: None,
        })),
    }
}

/// PUT /v1/integrations/aws (org admin only)
/// Set or update AWS config for the organization.
pub async fn set_aws_integration(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Json(config): Json<AwsIntegrationConfig>,
) -> Result<Json<AwsIntegrationConfig>, (StatusCode, Json<ApiError>)> {
    let (user, org_id) = extract_org_admin(&state, auth_header, &jar).await?;

    let config_json = serde_json::to_string(&config).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialize_error",
            &e.to_string(),
        )
    })?;

    db::upsert_cloud_integration(&state.db, &org_id, "aws", &config_json, &user.id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    tracing::info!(
        user_id = %user.id,
        org_id = %org_id,
        "AWS integration configured"
    );

    Ok(Json(config))
}

/// DELETE /v1/integrations/aws (org admin only)
/// Remove AWS config for the organization.
pub async fn delete_aws_integration(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let (user, org_id) = extract_org_admin(&state, auth_header, &jar).await?;

    let deleted = db::delete_cloud_integration(&state.db, &org_id, "aws")
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    if deleted {
        tracing::info!(
            user_id = %user.id,
            org_id = %org_id,
            "AWS integration removed"
        );
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "AWS integration not configured",
        ))
    }
}

// ============================================================================
// GCP Browser-Based Configuration
// ============================================================================

/// Error template for GCP configuration errors.
#[derive(Template)]
#[template(path = "github/error.html")]
struct GcpErrorTemplate {
    title: String,
    message: String,
}

impl_template_response!(GcpErrorTemplate);

/// GET /gcp/configure - Show GCP configuration form (org admin only).
pub async fn gcp_configure_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    // Extract session from cookie (browser UI)
    let session = match crate::handlers::common::extract_session_from_cookie(&state, &jar).await {
        Ok(s) => s,
        Err(_) => {
            // No valid session - redirect to enrollment
            return Redirect::to("/enroll/start").into_response();
        }
    };

    // Get user
    let user = match db::get_user_by_id(&state.db, &session.claims.sub).await {
        Ok(Some(u)) => u,
        _ => {
            return GcpErrorTemplate {
                title: "Error".to_string(),
                message: "User not found.".to_string(),
            }
            .into_response();
        }
    };

    // Verify user has an organization
    let org_id = match &user.org_id {
        Some(id) => id.clone(),
        None => {
            return GcpErrorTemplate {
                title: "Organization Required".to_string(),
                message: "GCP integration requires organization membership.".to_string(),
            }
            .into_response();
        }
    };

    // Verify user is org admin
    if !user.is_org_admin {
        return GcpErrorTemplate {
            title: "Admin Required".to_string(),
            message: "Only organization administrators can configure GCP.".to_string(),
        }
        .into_response();
    }

    // Check for existing configuration
    let (config, editing) = match db::get_cloud_integration(&state.db, &org_id, "gcp").await {
        Ok(Some(i)) => match serde_json::from_str::<GcpIntegrationConfig>(&i.config) {
            Ok(c) => (c, true),
            Err(_) => (
                GcpIntegrationConfig {
                    project_number: String::new(),
                    pool_id: String::new(),
                    provider_id: String::new(),
                    service_account: None,
                },
                false,
            ),
        },
        _ => (
            GcpIntegrationConfig {
                project_number: String::new(),
                pool_id: String::new(),
                provider_id: String::new(),
                service_account: None,
            },
            false,
        ),
    };

    let auth = AuthContext {
        authenticated: true,
        user_id: Some(user.id),
        user_email: Some(user.email),
        has_org: true,
        is_org_admin: true,
    };

    GcpConfigureTemplate {
        auth,
        config,
        editing,
        error: None,
        success: None,
    }
    .into_response()
}

/// POST /gcp/configure - Handle GCP configuration form submission.
pub async fn gcp_configure_submit(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<GcpConfigureForm>,
) -> Response {
    // Extract session from cookie (browser UI)
    let session = match crate::handlers::common::extract_session_from_cookie(&state, &jar).await {
        Ok(s) => s,
        Err(_) => {
            return Redirect::to("/enroll/start").into_response();
        }
    };

    // Get user
    let user = match db::get_user_by_id(&state.db, &session.claims.sub).await {
        Ok(Some(u)) => u,
        _ => {
            return GcpErrorTemplate {
                title: "Error".to_string(),
                message: "User not found.".to_string(),
            }
            .into_response();
        }
    };

    // Verify user has an organization
    let org_id = match &user.org_id {
        Some(id) => id.clone(),
        None => {
            return GcpErrorTemplate {
                title: "Organization Required".to_string(),
                message: "GCP integration requires organization membership.".to_string(),
            }
            .into_response();
        }
    };

    // Verify user is org admin
    if !user.is_org_admin {
        return GcpErrorTemplate {
            title: "Admin Required".to_string(),
            message: "Only organization administrators can configure GCP.".to_string(),
        }
        .into_response();
    }

    let auth = AuthContext {
        authenticated: true,
        user_id: Some(user.id.clone()),
        user_email: Some(user.email),
        has_org: true,
        is_org_admin: true,
    };

    // Check if we're editing
    let editing = db::get_cloud_integration(&state.db, &org_id, "gcp")
        .await
        .ok()
        .flatten()
        .is_some();

    // Validate form
    let project_number = form.project_number.trim().to_string();
    let pool_id = form.pool_id.trim().to_string();
    let provider_id = form.provider_id.trim().to_string();
    let service_account: Option<String> = form
        .service_account
        .as_ref()
        .map(|s: &String| s.trim().to_string())
        .filter(|s: &String| !s.is_empty());

    if project_number.is_empty() {
        return GcpConfigureTemplate {
            auth,
            config: GcpIntegrationConfig {
                project_number,
                pool_id,
                provider_id,
                service_account,
            },
            editing,
            error: Some("Project number is required.".to_string()),
            success: None,
        }
        .into_response();
    }

    if pool_id.is_empty() {
        return GcpConfigureTemplate {
            auth,
            config: GcpIntegrationConfig {
                project_number,
                pool_id,
                provider_id,
                service_account,
            },
            editing,
            error: Some("Pool ID is required.".to_string()),
            success: None,
        }
        .into_response();
    }

    if provider_id.is_empty() {
        return GcpConfigureTemplate {
            auth,
            config: GcpIntegrationConfig {
                project_number,
                pool_id,
                provider_id,
                service_account,
            },
            editing,
            error: Some("Provider ID is required.".to_string()),
            success: None,
        }
        .into_response();
    }

    // Build config
    let config = GcpIntegrationConfig {
        project_number,
        pool_id,
        provider_id,
        service_account,
    };

    // Save to database
    let config_json = match serde_json::to_string(&config) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("Failed to serialize GCP config: {}", e);
            return GcpConfigureTemplate {
                auth,
                config,
                editing,
                error: Some("Failed to save configuration.".to_string()),
                success: None,
            }
            .into_response();
        }
    };

    if let Err(e) =
        db::upsert_cloud_integration(&state.db, &org_id, "gcp", &config_json, &user.id).await
    {
        tracing::error!("Failed to save GCP config: {}", e);
        return GcpConfigureTemplate {
            auth,
            config,
            editing,
            error: Some("Failed to save configuration.".to_string()),
            success: None,
        }
        .into_response();
    }

    tracing::info!(
        user_id = %user.id,
        org_id = %org_id,
        "GCP integration configured via browser"
    );

    // Redirect to integrations page on success
    Redirect::to("/integrations").into_response()
}

/// POST /gcp/configure/delete - Delete GCP configuration.
pub async fn gcp_configure_delete(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    // Extract session from cookie (browser UI)
    let session = match crate::handlers::common::extract_session_from_cookie(&state, &jar).await {
        Ok(s) => s,
        Err(_) => {
            return Redirect::to("/enroll/start").into_response();
        }
    };

    // Get user
    let user = match db::get_user_by_id(&state.db, &session.claims.sub).await {
        Ok(Some(u)) => u,
        _ => {
            return GcpErrorTemplate {
                title: "Error".to_string(),
                message: "User not found.".to_string(),
            }
            .into_response();
        }
    };

    // Verify user has an organization
    let org_id = match &user.org_id {
        Some(id) => id.clone(),
        None => {
            return GcpErrorTemplate {
                title: "Organization Required".to_string(),
                message: "GCP integration requires organization membership.".to_string(),
            }
            .into_response();
        }
    };

    // Verify user is org admin
    if !user.is_org_admin {
        return GcpErrorTemplate {
            title: "Admin Required".to_string(),
            message: "Only organization administrators can configure GCP.".to_string(),
        }
        .into_response();
    }

    // Delete configuration
    match db::delete_cloud_integration(&state.db, &org_id, "gcp").await {
        Ok(true) => {
            tracing::info!(
                user_id = %user.id,
                org_id = %org_id,
                "GCP integration removed via browser"
            );
        }
        Ok(false) => {
            tracing::debug!("GCP integration was not configured");
        }
        Err(e) => {
            tracing::error!("Failed to delete GCP config: {}", e);
            return GcpErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to remove configuration.".to_string(),
            }
            .into_response();
        }
    }

    Redirect::to("/integrations").into_response()
}
