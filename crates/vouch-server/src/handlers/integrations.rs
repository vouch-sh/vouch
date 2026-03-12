// SPDX-License-Identifier: BUSL-1.1
//! Integrations page handler and cloud integration APIs.
//!
//! Shows available integrations and their connection status:
//! - GitHub (org-wide, requires org membership)
//! - AWS (org-wide config, per-user setup)
//! - SSH (per-user, CLI setup)
//! - EKS (via AWS IAM and EKS Access Entries)
//!
//! Also provides API endpoints for managing cloud integration configs:
//! - GET/PUT/DELETE /v1/integrations/aws

use crate::db;
use crate::handlers::session::{
    AuthContext, extract_org_admin, extract_user_with_org, get_resource_auth_context,
};
use crate::services::error::ServiceError;
use crate::{AppState, impl_template_response};
use askama::Template;
use axum::Json;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;
use vouch_common::{AwsIntegrationConfig, IntegrationConfigResponse};

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
    /// SSH CA public key in OpenSSH format (None if SSH CA not configured).
    pub ssh_ca_public_key: Option<String>,
    /// AWS IAM Identity Center config (None if not configured).
    pub idc_config: Option<AwsIntegrationConfig>,
}

impl_template_response!(IntegrationsTemplate);

// ============================================================================
// Handlers
// ============================================================================

/// GET /integrations - Show integrations page.
pub async fn integrations_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    let auth = get_resource_auth_context(&state, &jar).await;

    // Redirect unauthenticated users to enrollment
    if !auth.authenticated {
        return Redirect::to("/enroll/start").into_response();
    }

    // Check if GitHub App is configured on the server
    let github_configured = state.github_app.is_some();

    // Get SSH CA public key (None means SSH CA is not configured)
    let ssh_ca_public_key = state.ssh_ca.as_ref().and_then(|ca| ca.public_key().ok());

    // Get connected GitHub accounts if user has an org
    let github_accounts = if auth.has_org {
        // We need to get the user's org_id to fetch installations
        if let Ok(session) =
            crate::handlers::session::extract_session_from_cookie(&state, &jar).await
        {
            if let Ok(Some(user)) = db::get_user_by_id(&state.store, &session.sub).await {
                if let Some(org_id) = &user.org_id {
                    db::get_github_installations_by_org(&state.store, org_id)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .map(|i| i.github_account_login)
                        .collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Load AWS IdC config if the user belongs to an org
    let idc_config = if auth.has_org {
        if let Ok(session) =
            crate::handlers::session::extract_session_from_cookie(&state, &jar).await
        {
            if let Ok(Some(user)) = db::get_user_by_id(&state.store, &session.sub).await {
                if let Some(org_id) = &user.org_id {
                    db::get_cloud_integration(&state.store, org_id, "aws")
                        .await
                        .ok()
                        .flatten()
                        .and_then(|i| serde_json::from_value::<AwsIntegrationConfig>(i.config).ok())
                        .filter(|c| c.idc_configured())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    IntegrationsTemplate {
        auth,
        github_configured,
        github_accounts,
        ssh_ca_public_key,
        idc_config,
    }
    .into_response()
}

// ============================================================================
// AWS Integration API
// ============================================================================

/// GET /v1/integrations/aws
/// Returns AWS config for authenticated user's organization.
pub async fn get_aws_integration(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> Result<Json<IntegrationConfigResponse<AwsIntegrationConfig>>, ServiceError> {
    let (_user, org_id) =
        extract_user_with_org(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let integration = db::get_cloud_integration(&state.store, &org_id, "aws")
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    match integration {
        Some(i) => {
            let config: AwsIntegrationConfig = serde_json::from_value(i.config).map_err(|e| {
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "config_parse_error",
                    format!("Failed to parse AWS config: {e}"),
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
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Json(config): Json<AwsIntegrationConfig>,
) -> Result<Json<AwsIntegrationConfig>, ServiceError> {
    let (user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let config_value = serde_json::to_value(&config).map_err(|e| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialize_error",
            e.to_string(),
        )
    })?;

    db::upsert_cloud_integration(&state.store, &org_id, "aws", &config_value, &user.id)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
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
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, ServiceError> {
    let (user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let deleted = db::delete_cloud_integration(&state.store, &org_id, "aws")
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    if deleted {
        tracing::info!(
            user_id = %user.id,
            org_id = %org_id,
            "AWS integration removed"
        );
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "AWS integration not configured",
        ))
    }
}
