//! Admin handlers for server setup and user management.

use crate::AppState;
use crate::config::config_keys;
use crate::db;
use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use std::sync::Arc;

// ============================================================================
// Templates
// ============================================================================

/// Admin setup page template.
#[derive(Template)]
#[template(path = "admin/setup.html")]
pub struct AdminSetupTemplate {
    pub token: String,
    pub redirect_uri: String,
    pub oidc_configured: bool,
    pub current_client_id: String,
    pub current_domains: String,
    pub current_org: String,
}

impl IntoResponse for AdminSetupTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Admin user list template.
#[derive(Template)]
#[template(path = "admin/users.html")]
pub struct AdminUsersTemplate {
    pub token: String,
    pub users: Vec<db::UserWithAuthCount>,
}

impl IntoResponse for AdminUsersTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Admin unauthorized template.
#[derive(Template)]
#[template(path = "admin/unauthorized.html")]
pub struct AdminUnauthorizedTemplate;

impl IntoResponse for AdminUnauthorizedTemplate {
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

/// Admin message template (success/error).
#[derive(Template)]
#[template(path = "admin/message.html")]
pub struct AdminMessageTemplate {
    pub page_title: String,
    pub title: String,
    pub message: String,
    pub back_url: String,
    pub is_error: bool,
}

impl IntoResponse for AdminMessageTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

// ============================================================================
// Request Types
// ============================================================================

/// Query params for admin pages.
#[derive(Debug, Deserialize)]
pub struct AdminQuery {
    token: Option<String>,
}

/// Form data for OIDC configuration.
#[derive(Debug, Deserialize)]
pub struct OidcConfigForm {
    client_id: String,
    client_secret: String,
    allowed_domains: Option<String>,
    org_name: Option<String>,
}

/// Form data for testing OIDC configuration (empty, uses saved config).
#[derive(Debug, Deserialize)]
pub struct OidcTestForm {
    #[serde(default)]
    #[allow(dead_code)]
    _unused: Option<String>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if the request is authorized for admin access.
fn is_admin_authorized(state: &AppState, query: &AdminQuery) -> bool {
    // Check bootstrap token
    if let Some(token) = &query.token
        && state.config.verify_bootstrap_token(token)
    {
        return true;
    }

    // For now, bootstrap token is the only way to access admin.
    // In a full implementation, you'd check OIDC session cookies here.
    false
}

// ============================================================================
// Handlers
// ============================================================================

/// Admin setup wizard page.
/// GET /admin/setup
pub async fn setup_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
) -> Response {
    if !is_admin_authorized(&state, &query) {
        return AdminUnauthorizedTemplate.into_response();
    }

    let token = query.token.as_deref().unwrap_or("").to_string();
    let redirect_uri = format!("{}/oauth/callback", state.config.verification_base_url);
    let oidc_configured = state.config.oidc_configured();
    let current_client_id = state
        .config
        .oidc_client_id
        .as_deref()
        .unwrap_or("")
        .to_string();
    let current_domains = state
        .config
        .allowed_domains
        .as_ref()
        .map(|d| d.join(", "))
        .unwrap_or_default();
    let current_org = state.config.org_name.as_deref().unwrap_or("").to_string();

    AdminSetupTemplate {
        token,
        redirect_uri,
        oidc_configured,
        current_client_id,
        current_domains,
        current_org,
    }
    .into_response()
}

/// Save OIDC configuration.
/// POST /admin/setup/oidc
pub async fn setup_save_oidc(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
    Form(form): Form<OidcConfigForm>,
) -> Response {
    if !is_admin_authorized(&state, &query) {
        return AdminUnauthorizedTemplate.into_response();
    }

    let token = query.token.as_deref().unwrap_or("").to_string();

    // Validate inputs
    if form.client_id.trim().is_empty() || form.client_secret.trim().is_empty() {
        return AdminMessageTemplate {
            page_title: "Error".to_string(),
            title: "Invalid Input".to_string(),
            message: "Client ID and Client Secret are required.".to_string(),
            back_url: format!("/admin/setup?token={token}"),
            is_error: true,
        }
        .into_response();
    }

    // Save to database
    let db = &state.db;

    if let Err(e) =
        db::set_config(db, config_keys::OIDC_ISSUER, "https://accounts.google.com").await
    {
        tracing::error!("Failed to save OIDC issuer: {}", e);
        return AdminMessageTemplate {
            page_title: "Error".to_string(),
            title: "Database Error".to_string(),
            message: "Failed to save configuration.".to_string(),
            back_url: format!("/admin/setup?token={token}"),
            is_error: true,
        }
        .into_response();
    }

    if let Err(e) = db::set_config(db, config_keys::OIDC_CLIENT_ID, form.client_id.trim()).await {
        tracing::error!("Failed to save OIDC client ID: {}", e);
        return AdminMessageTemplate {
            page_title: "Error".to_string(),
            title: "Database Error".to_string(),
            message: "Failed to save configuration.".to_string(),
            back_url: format!("/admin/setup?token={token}"),
            is_error: true,
        }
        .into_response();
    }

    if let Err(e) = db::set_config(
        db,
        config_keys::OIDC_CLIENT_SECRET,
        form.client_secret.trim(),
    )
    .await
    {
        tracing::error!("Failed to save OIDC client secret: {}", e);
        return AdminMessageTemplate {
            page_title: "Error".to_string(),
            title: "Database Error".to_string(),
            message: "Failed to save configuration.".to_string(),
            back_url: format!("/admin/setup?token={token}"),
            is_error: true,
        }
        .into_response();
    }

    // Save optional fields
    if let Some(domains) = &form.allowed_domains {
        let domains = domains.trim();
        if !domains.is_empty()
            && let Err(e) = db::set_config(db, config_keys::ALLOWED_DOMAINS, domains).await
        {
            tracing::error!("Failed to save allowed domains: {}", e);
        }
    }

    if let Some(org_name) = &form.org_name {
        let org_name = org_name.trim();
        if !org_name.is_empty()
            && let Err(e) = db::set_config(db, config_keys::ORG_NAME, org_name).await
        {
            tracing::error!("Failed to save org name: {}", e);
        }
    }

    tracing::info!("OIDC configuration saved");

    AdminMessageTemplate {
        page_title: "Success".to_string(),
        title: "Configuration Saved".to_string(),
        message: "OIDC configuration has been saved successfully. The server will use the new configuration for subsequent requests. Note: You may need to restart the server for changes to take effect immediately.".to_string(),
        back_url: format!("/admin/setup?token={token}"),
        is_error: false,
    }
    .into_response()
}

/// Test OIDC configuration.
/// POST /admin/setup/test
pub async fn setup_test_oidc(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
    Form(_form): Form<OidcTestForm>,
) -> Response {
    if !is_admin_authorized(&state, &query) {
        return AdminUnauthorizedTemplate.into_response();
    }

    let token = query.token.as_deref().unwrap_or("").to_string();

    // Get current config
    let client_id = match &state.config.oidc_client_id {
        Some(id) => id.clone(),
        None => {
            return AdminMessageTemplate {
                page_title: "Error".to_string(),
                title: "Not Configured".to_string(),
                message: "OIDC is not configured. Please save your credentials first.".to_string(),
                back_url: format!("/admin/setup?token={token}"),
                is_error: true,
            }
            .into_response();
        }
    };

    // Test by fetching Google's OIDC discovery document
    let client = reqwest::Client::new();
    let discovery_url = "https://accounts.google.com/.well-known/openid-configuration";

    match client.get(discovery_url).send().await {
        Ok(resp) if resp.status().is_success() => AdminMessageTemplate {
            page_title: "Success".to_string(),
            title: "Connection Successful".to_string(),
            message: format!(
                "Successfully connected to Google's OIDC endpoint. Client ID: {}...{}",
                client_id.chars().take(8).collect::<String>(),
                client_id
                    .chars()
                    .rev()
                    .take(4)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>()
            ),
            back_url: format!("/admin/setup?token={token}"),
            is_error: false,
        }
        .into_response(),
        Ok(resp) => AdminMessageTemplate {
            page_title: "Error".to_string(),
            title: "Connection Failed".to_string(),
            message: format!("Google OIDC endpoint returned status: {}", resp.status()),
            back_url: format!("/admin/setup?token={token}"),
            is_error: true,
        }
        .into_response(),
        Err(e) => AdminMessageTemplate {
            page_title: "Error".to_string(),
            title: "Connection Failed".to_string(),
            message: format!("Failed to connect to Google: {e}"),
            back_url: format!("/admin/setup?token={token}"),
            is_error: true,
        }
        .into_response(),
    }
}

/// List enrolled users.
/// GET /admin/users
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
) -> Response {
    if !is_admin_authorized(&state, &query) {
        return AdminUnauthorizedTemplate.into_response();
    }

    let token = query.token.as_deref().unwrap_or("").to_string();

    let users = match db::list_users_with_auth_count(&state.db).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Failed to list users: {}", e);
            return AdminMessageTemplate {
                page_title: "Error".to_string(),
                title: "Database Error".to_string(),
                message: "Failed to load users.".to_string(),
                back_url: format!("/admin/setup?token={token}"),
                is_error: true,
            }
            .into_response();
        }
    };

    AdminUsersTemplate { token, users }.into_response()
}

/// Delete a user.
/// POST /admin/users/:id/delete
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
    Path(user_id): Path<String>,
) -> Response {
    if !is_admin_authorized(&state, &query) {
        return AdminUnauthorizedTemplate.into_response();
    }

    let token = query.token.as_deref().unwrap_or("").to_string();

    if let Err(e) = db::delete_user(&state.db, &user_id).await {
        tracing::error!("Failed to delete user: {}", e);
        return AdminMessageTemplate {
            page_title: "Error".to_string(),
            title: "Database Error".to_string(),
            message: "Failed to delete user.".to_string(),
            back_url: format!("/admin/users?token={token}"),
            is_error: true,
        }
        .into_response();
    }

    tracing::info!("Deleted user: {}", user_id);

    Redirect::to(&format!("/admin/users?token={token}")).into_response()
}
