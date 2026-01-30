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

use crate::db;
use crate::handlers::common::{AuthContext, extract_session, get_auth_context};
use crate::{AppState, impl_template_response};
use askama::Template;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::CookieJar;
use headers::authorization::{Authorization, Bearer};
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
}

impl_template_response!(IntegrationsTemplate);

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

    // Get connected GitHub accounts and GCP config status if user has an org
    let (github_accounts, gcp_configured) = if auth.has_org {
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
                    let gcp_configured = db::get_cloud_integration(&state.db, org_id, "gcp")
                        .await
                        .unwrap_or(None)
                        .is_some();
                    (github_accounts, gcp_configured)
                } else {
                    (Vec::new(), false)
                }
            } else {
                (Vec::new(), false)
            }
        } else {
            (Vec::new(), false)
        }
    } else {
        (Vec::new(), false)
    };

    IntegrationsTemplate {
        auth,
        github_configured,
        github_accounts,
        gcp_configured,
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
) -> Result<(db::User, String), (StatusCode, Json<ApiError>)> {
    let session = extract_session(state, auth_header).await?;

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
) -> Result<(db::User, String), (StatusCode, Json<ApiError>)> {
    let (user, org_id) = extract_user_with_org(state, auth_header).await?;

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
) -> Result<Json<IntegrationConfigResponse<GcpIntegrationConfig>>, (StatusCode, Json<ApiError>)> {
    let (_user, org_id) = extract_user_with_org(&state, auth_header).await?;

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
    Json(config): Json<GcpIntegrationConfig>,
) -> Result<Json<GcpIntegrationConfig>, (StatusCode, Json<ApiError>)> {
    let (user, org_id) = extract_org_admin(&state, auth_header).await?;

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
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let (user, org_id) = extract_org_admin(&state, auth_header).await?;

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
) -> Result<Json<IntegrationConfigResponse<AwsIntegrationConfig>>, (StatusCode, Json<ApiError>)> {
    let (_user, org_id) = extract_user_with_org(&state, auth_header).await?;

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
    Json(config): Json<AwsIntegrationConfig>,
) -> Result<Json<AwsIntegrationConfig>, (StatusCode, Json<ApiError>)> {
    let (user, org_id) = extract_org_admin(&state, auth_header).await?;

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
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let (user, org_id) = extract_org_admin(&state, auth_header).await?;

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
