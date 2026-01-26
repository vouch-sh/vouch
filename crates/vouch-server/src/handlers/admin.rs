//! Admin handlers for server setup and user management.

use crate::AppState;
use crate::config::config_keys;
use crate::db;
use crate::impl_template_response;
use askama::Template;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use axum::{
    Form, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::sync::Arc;
use vouch_common::{ApiError, AuthEventInfo, ListAuthEventsResponse};

use super::json_error;

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
    pub current_idp: String,
    pub current_issuer: String,
    pub current_client_id: String,
    pub current_domains: String,
    pub current_org: String,
}

/// Admin user list template.
#[derive(Template)]
#[template(path = "admin/users.html")]
pub struct AdminUsersTemplate {
    pub token: String,
    pub users: Vec<db::UserWithAuthCount>,
}

/// Admin unauthorized template.
#[derive(Template)]
#[template(path = "admin/unauthorized.html")]
pub struct AdminUnauthorizedTemplate;

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

impl_template_response!(AdminSetupTemplate, AdminUsersTemplate, AdminMessageTemplate,);

// Note: AdminUnauthorizedTemplate needs a custom implementation
// because it returns a different status code
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
    /// IdP provider type (google, microsoft, okta, custom).
    idp_provider: String,
    /// Custom issuer URL (only used if idp_provider is "custom").
    custom_issuer: Option<String>,
    client_id: String,
    client_secret: String,
    allowed_domains: Option<String>,
    org_name: Option<String>,
}

/// Get the OIDC issuer URL for a provider.
fn get_issuer_for_provider(provider: &str, custom_issuer: Option<&str>) -> Option<String> {
    match provider {
        "google" => Some("https://accounts.google.com".to_string()),
        "microsoft" => Some("https://login.microsoftonline.com/common/v2.0".to_string()),
        "okta" => None, // Requires custom issuer
        "custom" => custom_issuer.map(|s| s.to_string()),
        _ => None,
    }
}

/// Get the provider name from an issuer URL.
fn get_provider_for_issuer(issuer: &str) -> String {
    if issuer.contains("accounts.google.com") {
        "google".to_string()
    } else if issuer.contains("login.microsoftonline.com") {
        "microsoft".to_string()
    } else if issuer.contains("okta.com") {
        "okta".to_string()
    } else {
        "custom".to_string()
    }
}

/// Form data for testing OIDC configuration (empty, uses saved config).
#[derive(Debug, Deserialize)]
pub struct OidcTestForm {
    #[serde(default)]
    #[allow(dead_code)]
    _unused: Option<String>,
}

/// Query params for auth events API.
#[derive(Debug, Deserialize)]
pub struct AuthEventsQuery {
    /// Admin token for authorization.
    token: Option<String>,
    /// Filter by user ID.
    user_id: Option<String>,
    /// Filter by event type (login_success, login_failed, enrollment, logout).
    event_type: Option<String>,
    /// Filter by client IP.
    client_ip: Option<String>,
    /// Filter by events since this ISO 8601 timestamp.
    since: Option<String>,
    /// Maximum number of events to return (default 100).
    limit: Option<i64>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Admin session cookie name.
const ADMIN_COOKIE_NAME: &str = "vouch_admin";

/// Admin session duration (24 hours).
const ADMIN_SESSION_HOURS: i64 = 24;

/// Check if the request is authorized for admin access.
fn is_admin_authorized(state: &AppState, query: &AdminQuery) -> bool {
    // Check bootstrap token
    if let Some(token) = &query.token
        && state.config.verify_bootstrap_token(token)
    {
        return true;
    }

    false
}

/// Admin authorization result with context.
pub struct AdminAuthResult {
    /// Whether the admin is authorized.
    pub authorized: bool,
    /// Bootstrap token if used (None for cookie auth).
    pub token: Option<String>,
    /// Admin email if authenticated via cookie.
    #[allow(dead_code)]
    pub admin_email: Option<String>,
    /// Organization ID if admin is scoped to an org (None for global admin).
    pub org_id: Option<String>,
    /// Whether this is a global admin (bootstrap token or config-listed email).
    pub is_global_admin: bool,
}

/// Check if the request is authorized for admin access (async version with cookie support).
async fn is_admin_authorized_async(
    state: &AppState,
    query: &AdminQuery,
    headers: &HeaderMap,
) -> AdminAuthResult {
    // Check bootstrap token first (global admin)
    if let Some(token) = &query.token
        && state.config.verify_bootstrap_token(token)
    {
        return AdminAuthResult {
            authorized: true,
            token: query.token.clone(),
            admin_email: None,
            org_id: None,
            is_global_admin: true,
        };
    }

    // Check admin session cookie
    if let Some(email) = get_admin_session_from_cookie(state, headers).await {
        // Check if email is in global admin list
        let is_global = state
            .config
            .admin_emails
            .iter()
            .any(|e| e.eq_ignore_ascii_case(&email));

        if is_global {
            return AdminAuthResult {
                authorized: true,
                token: None,
                admin_email: Some(email),
                org_id: None,
                is_global_admin: true,
            };
        }

        // Check if user is an org admin
        if let Ok(Some(user)) = db::get_user_by_email(&state.db, &email).await
            && user.is_org_admin
        {
            return AdminAuthResult {
                authorized: true,
                token: None,
                admin_email: Some(email),
                org_id: user.org_id,
                is_global_admin: false,
            };
        }
    }

    AdminAuthResult {
        authorized: false,
        token: None,
        admin_email: None,
        org_id: None,
        is_global_admin: false,
    }
}

/// Extract admin email from session cookie if valid.
#[allow(dead_code)]
async fn get_admin_session_from_cookie(state: &AppState, headers: &HeaderMap) -> Option<String> {
    // Get Cookie header
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    // Parse cookies to find vouch_admin
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix("vouch_admin=") {
            // Hash the token to look up session
            let token_hash = hex::encode(digest::digest(&SHA256, value.as_bytes()));

            // Look up session and check if valid
            if let Ok(Some(session)) =
                db::get_admin_session_by_token_hash(&state.db, &token_hash).await
                && let Ok(expires) = Timestamp::strptime("%Y-%m-%d %H:%M:%S", &session.expires_at)
                && expires > Timestamp::now()
            {
                // Update last used timestamp
                let _ = db::touch_admin_session(&state.db, &session.id).await;
                return Some(session.admin_email);
            }
        }
    }

    None
}

/// Create an admin session and return the Set-Cookie header value.
async fn create_admin_session_cookie(
    state: &AppState,
    admin_email: &str,
    oidc_provider: Option<&str>,
    oidc_subject: Option<&str>,
) -> Option<String> {
    // Generate random token
    let mut token_bytes = [0u8; 32];
    aws_rand::fill(&mut token_bytes).ok()?;
    let token = URL_SAFE_NO_PAD.encode(token_bytes);

    // Hash for storage
    let token_hash = hex::encode(digest::digest(&SHA256, token.as_bytes()));

    // Calculate expiration
    let expires = Timestamp::now()
        .checked_add(Span::new().hours(ADMIN_SESSION_HOURS))
        .ok()?;
    let expires_str = expires.strftime("%Y-%m-%d %H:%M:%S").to_string();

    // Store session
    db::create_admin_session(
        &state.db,
        admin_email,
        &token_hash,
        &expires_str,
        oidc_provider,
        oidc_subject,
    )
    .await
    .ok()?;

    // Build cookie with security attributes
    Some(format!(
        "{}={}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        ADMIN_COOKIE_NAME,
        token,
        ADMIN_SESSION_HOURS * 3600
    ))
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
    let current_issuer = state
        .config
        .oidc_issuer_url
        .as_deref()
        .unwrap_or("")
        .to_string();
    let current_idp = get_provider_for_issuer(&current_issuer);
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
        current_idp,
        current_issuer,
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

    // Determine issuer based on provider
    let issuer = match get_issuer_for_provider(&form.idp_provider, form.custom_issuer.as_deref()) {
        Some(i) => i,
        None => {
            return AdminMessageTemplate {
                page_title: "Error".to_string(),
                title: "Invalid IdP".to_string(),
                message: "Please provide a valid IdP issuer URL.".to_string(),
                back_url: format!("/admin/setup?token={token}"),
                is_error: true,
            }
            .into_response();
        }
    };

    // Save to database
    let db = &state.db;

    if let Err(e) = db::set_config(db, config_keys::OIDC_ISSUER, &issuer).await {
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
    let issuer = match &state.config.oidc_issuer_url {
        Some(iss) => iss.clone(),
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

    let client_id = state
        .config
        .oidc_client_id
        .as_deref()
        .unwrap_or("unknown")
        .to_string();

    // Test by fetching the IdP's OIDC discovery document
    let client = reqwest::Client::new();
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let provider_name = get_provider_for_issuer(&issuer);

    match client.get(&discovery_url).send().await {
        Ok(resp) if resp.status().is_success() => AdminMessageTemplate {
            page_title: "Success".to_string(),
            title: "Connection Successful".to_string(),
            message: format!(
                "Successfully connected to {} OIDC endpoint. Client ID: {}...{}",
                provider_name,
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
            message: format!(
                "{} OIDC endpoint returned status: {}",
                provider_name,
                resp.status()
            ),
            back_url: format!("/admin/setup?token={token}"),
            is_error: true,
        }
        .into_response(),
        Err(e) => AdminMessageTemplate {
            page_title: "Error".to_string(),
            title: "Connection Failed".to_string(),
            message: format!("Failed to connect to {}: {e}", provider_name),
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
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
) -> Response {
    let auth = is_admin_authorized_async(&state, &query, &headers).await;

    if !auth.authorized {
        return AdminUnauthorizedTemplate.into_response();
    }

    let token = auth.token.as_deref().unwrap_or("").to_string();

    // Scope users by organization for non-global admins
    let users = if auth.is_global_admin {
        // Global admin sees all users
        db::list_users_with_auth_count(&state.db).await
    } else if let Some(org_id) = &auth.org_id {
        // Org admin sees only their org's users
        db::list_users_with_auth_count_by_org(&state.db, org_id).await
    } else {
        // Personal account admin (shouldn't happen, but handle gracefully)
        Ok(vec![])
    };

    let users = match users {
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
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    Path(user_id): Path<String>,
) -> Response {
    let auth = is_admin_authorized_async(&state, &query, &headers).await;

    if !auth.authorized {
        return AdminUnauthorizedTemplate.into_response();
    }

    let token = auth.token.as_deref().unwrap_or("").to_string();

    // For non-global admins, verify the user belongs to their org
    if !auth.is_global_admin
        && let Ok(Some(target_user)) = db::get_user_by_id(&state.db, &user_id).await
        && target_user.org_id != auth.org_id
    {
        return AdminMessageTemplate {
            page_title: "Error".to_string(),
            title: "Unauthorized".to_string(),
            message: "You can only delete users from your organization.".to_string(),
            back_url: format!("/admin/users?token={token}"),
            is_error: true,
        }
        .into_response();
    }

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

// ============================================================================
// Auth Events API
// ============================================================================

/// List authentication events.
/// GET /api/v1/admin/auth-events
pub async fn list_auth_events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthEventsQuery>,
) -> Result<Json<ListAuthEventsResponse>, (StatusCode, Json<ApiError>)> {
    // Check authorization using token
    let admin_query = AdminQuery {
        token: query.token.clone(),
    };
    if !is_admin_authorized(&state, &admin_query) {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Invalid or missing admin token",
        ));
    }

    // Build query params
    let db_query = db::AuthEventQuery {
        user_id: query.user_id.clone(),
        event_type: query.event_type.clone(),
        client_ip: query.client_ip.clone(),
        since: query.since.clone(),
        limit: query.limit,
    };

    // Fetch events
    let events = db::get_auth_events(&state.db, &db_query)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    // Get user emails for the events (for display)
    // Build a map of user_id -> email
    let mut user_emails: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for event in &events {
        if !user_emails.contains_key(&event.user_id)
            && let Ok(Some(user)) = db::get_user_by_id(&state.db, &event.user_id).await
        {
            user_emails.insert(event.user_id.clone(), user.email);
        }
    }

    // Convert to API response type
    let events: Vec<AuthEventInfo> = events
        .into_iter()
        .map(|e| AuthEventInfo {
            id: e.id,
            user_id: e.user_id.clone(),
            user_email: user_emails.get(&e.user_id).cloned(),
            event_type: e.event_type,
            authenticator_id: e.authenticator_id,
            client_ip: e.client_ip,
            user_agent: e.user_agent,
            client_hostname: e.client_hostname,
            client_os: e.client_os,
            client_arch: e.client_arch,
            client_version: e.client_version,
            success: e.success != 0,
            failure_reason: e.failure_reason,
            created_at: e.created_at,
        })
        .collect();

    Ok(Json(ListAuthEventsResponse { events }))
}

// ============================================================================
// SCIM Token Management API
// ============================================================================

/// Request to create a SCIM token.
#[derive(Debug, Deserialize)]
pub struct CreateScimTokenRequest {
    pub description: Option<String>,
    /// Token expiration in days (optional, None = never expires).
    pub expires_in_days: Option<i64>,
}

/// Response for created SCIM token.
#[derive(Debug, serde::Serialize)]
pub struct CreateScimTokenResponse {
    pub id: String,
    pub token: String,
    pub description: Option<String>,
    pub expires_at: Option<String>,
}

/// SCIM token info for listing.
#[derive(Debug, serde::Serialize)]
pub struct ScimTokenInfo {
    pub id: String,
    pub description: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
}

/// Response for listing SCIM tokens.
#[derive(Debug, serde::Serialize)]
pub struct ListScimTokensResponse {
    pub tokens: Vec<ScimTokenInfo>,
}

/// Create a new SCIM token.
/// POST /api/v1/admin/scim-tokens
pub async fn create_scim_token(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
    Json(req): Json<CreateScimTokenRequest>,
) -> Result<Json<CreateScimTokenResponse>, (StatusCode, Json<ApiError>)> {
    if !is_admin_authorized(&state, &query) {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Invalid or missing admin token",
        ));
    }

    // Generate a secure random token
    let mut token_bytes = [0u8; 32];
    aws_rand::fill(&mut token_bytes).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "RNG failure",
        )
    })?;
    let token = format!("vouch_scim_{}", URL_SAFE_NO_PAD.encode(token_bytes));

    // Hash the token for storage
    let token_hash = hex::encode(digest::digest(&SHA256, token.as_bytes()));

    // Calculate expiration if specified
    let expires_at = req.expires_in_days.map(|days| {
        let duration = jiff::Span::new().days(days);
        jiff::Timestamp::now()
            .checked_add(duration)
            .map(|t| t.to_string())
            .unwrap_or_default()
    });

    // Store the token
    let token_id = db::create_scim_token(
        &state.db,
        &token_hash,
        req.description.as_deref(),
        expires_at.as_deref(),
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    tracing::info!("Created SCIM token: {}", token_id);

    Ok(Json(CreateScimTokenResponse {
        id: token_id,
        token,
        description: req.description,
        expires_at,
    }))
}

/// List all SCIM tokens.
/// GET /api/v1/admin/scim-tokens
pub async fn list_scim_tokens(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
) -> Result<Json<ListScimTokensResponse>, (StatusCode, Json<ApiError>)> {
    if !is_admin_authorized(&state, &query) {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Invalid or missing admin token",
        ));
    }

    let tokens = db::list_scim_tokens(&state.db).await.map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    let tokens: Vec<ScimTokenInfo> = tokens
        .into_iter()
        .map(|t| ScimTokenInfo {
            id: t.id,
            description: t.description,
            created_at: t.created_at,
            last_used_at: t.last_used_at,
            expires_at: t.expires_at,
        })
        .collect();

    Ok(Json(ListScimTokensResponse { tokens }))
}

/// Delete a SCIM token.
/// DELETE /api/v1/admin/scim-tokens/:id
pub async fn delete_scim_token(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
    Path(token_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    if !is_admin_authorized(&state, &query) {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Invalid or missing admin token",
        ));
    }

    db::delete_scim_token(&state.db, &token_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    tracing::info!("Deleted SCIM token: {}", token_id);

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Admin Login/Logout
// ============================================================================

/// Admin login page template.
#[derive(Template)]
#[template(path = "admin/login.html")]
pub struct AdminLoginTemplate {
    pub error: Option<String>,
    pub oidc_configured: bool,
    pub org_name: String,
}

impl IntoResponse for AdminLoginTemplate {
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

/// Admin login page.
/// GET /admin/login
pub async fn admin_login_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminLoginQuery>,
) -> Response {
    let oidc_configured = state.config.oidc_configured();
    let org_name = state
        .config
        .org_name
        .clone()
        .unwrap_or_else(|| "Vouch".to_string());

    AdminLoginTemplate {
        error: query.error,
        oidc_configured,
        org_name,
    }
    .into_response()
}

/// Query params for admin login.
#[derive(Debug, Deserialize)]
pub struct AdminLoginQuery {
    error: Option<String>,
}

/// Admin OIDC state claims (encoded in the state parameter).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct AdminOidcState {
    /// Random nonce for CSRF protection.
    nonce: String,
    /// Redirect URI for token exchange.
    redirect_uri: String,
    /// Expiration timestamp.
    exp: i64,
}

/// Initiate admin OIDC login.
/// POST /admin/login
pub async fn admin_login_start(State(state): State<Arc<AppState>>) -> Response {
    if !state.config.oidc_configured() {
        return Redirect::to("/admin/login?error=OIDC+not+configured").into_response();
    }

    let redirect_uri = format!("{}/admin/callback", state.config.verification_base_url);
    let nonce = uuid::Uuid::now_v7().to_string();

    // Create signed state token with expiration
    let exp = Timestamp::now()
        .checked_add(Span::new().minutes(10))
        .map(|t| t.as_second())
        .unwrap_or(0);

    let state_claims = AdminOidcState {
        nonce: nonce.clone(),
        redirect_uri: redirect_uri.clone(),
        exp,
    };

    let state_token = match jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &state_claims,
        &jsonwebtoken::EncodingKey::from_secret(state.config.jwt_secret_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to encode state: {}", e);
            return Redirect::to("/admin/login?error=Internal+error").into_response();
        }
    };

    let issuer = state.config.oidc_issuer_url.as_deref().unwrap_or("");
    let client_id = state.config.oidc_client_id.as_deref().unwrap_or("");

    // Build authorization URL
    let auth_url = format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid+email+profile&state={}&nonce={}",
        issuer.trim_end_matches('/'),
        urlencoding::encode(client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&state_token),
        urlencoding::encode(&nonce),
    );

    Redirect::to(&auth_url).into_response()
}

/// Admin OIDC callback.
/// GET /admin/callback
pub async fn admin_oidc_callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OidcCallbackQuery>,
) -> Response {
    // Verify and decode state token
    let oidc_state: AdminOidcState = match jsonwebtoken::decode(
        &query.state,
        &jsonwebtoken::DecodingKey::from_secret(state.config.jwt_secret_bytes()),
        &jsonwebtoken::Validation::default(),
    ) {
        Ok(data) => data.claims,
        Err(_) => {
            return Redirect::to("/admin/login?error=Invalid+state").into_response();
        }
    };

    // Check for error from IdP
    if let Some(error) = &query.error {
        return Redirect::to(&format!(
            "/admin/login?error={}",
            urlencoding::encode(error)
        ))
        .into_response();
    }

    let code = match &query.code {
        Some(c) => c,
        None => {
            return Redirect::to("/admin/login?error=No+authorization+code").into_response();
        }
    };

    // Exchange code for tokens
    let issuer = state.config.oidc_issuer_url.as_deref().unwrap_or("");
    let client_id = state.config.oidc_client_id.as_deref().unwrap_or("");
    let client_secret = state
        .config
        .oidc_client_secret
        .as_ref()
        .map(|s| s.expose_secret())
        .unwrap_or("");

    let token_url = format!("{}/token", issuer.trim_end_matches('/'));

    let client = reqwest::Client::new();
    let token_response = match client
        .post(&token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &oidc_state.redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Token exchange failed: {}", e);
            return Redirect::to("/admin/login?error=Token+exchange+failed").into_response();
        }
    };

    if !token_response.status().is_success() {
        let error = token_response.text().await.unwrap_or_default();
        tracing::error!("Token exchange error: {}", error);
        return Redirect::to("/admin/login?error=Token+exchange+failed").into_response();
    }

    let tokens: TokenResponse = match token_response.json().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to parse token response: {}", e);
            return Redirect::to("/admin/login?error=Invalid+token+response").into_response();
        }
    };

    // Decode ID token to get email (without full verification for now)
    let id_token = &tokens.id_token;
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Redirect::to("/admin/login?error=Invalid+ID+token").into_response();
    }

    let claims_json = match URL_SAFE_NO_PAD.decode(parts.get(1).copied().unwrap_or("")) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => {
            return Redirect::to("/admin/login?error=Invalid+ID+token").into_response();
        }
    };

    let claims: IdTokenClaims = match serde_json::from_str(&claims_json) {
        Ok(c) => c,
        Err(_) => {
            return Redirect::to("/admin/login?error=Invalid+ID+token+claims").into_response();
        }
    };

    let email = claims.email.unwrap_or_default();
    if email.is_empty() {
        return Redirect::to("/admin/login?error=No+email+in+token").into_response();
    }

    // Check if email is in admin list
    if !state
        .config
        .admin_emails
        .iter()
        .any(|e| e.eq_ignore_ascii_case(&email))
    {
        tracing::warn!("Non-admin login attempt: {}", email);
        return Redirect::to("/admin/login?error=Not+an+admin").into_response();
    }

    // Create admin session
    let cookie = match create_admin_session_cookie(
        &state,
        &email,
        Some(issuer),
        claims.sub.as_deref(),
    )
    .await
    {
        Some(c) => c,
        None => {
            return Redirect::to("/admin/login?error=Session+creation+failed").into_response();
        }
    };

    tracing::info!("Admin login successful: {}", email);

    // Redirect to admin setup with session cookie
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/admin/setup")
        .header(header::SET_COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// OIDC callback query params.
#[derive(Debug, Deserialize)]
pub struct OidcCallbackQuery {
    code: Option<String>,
    state: String,
    error: Option<String>,
}

/// Token response from OIDC provider.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    access_token: Option<String>,
}

/// ID token claims.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: Option<String>,
    email: Option<String>,
}

/// Admin logout.
/// POST /admin/logout
pub async fn admin_logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // Get session from cookie and revoke it
    if let Some(cookie_header) = headers.get(header::COOKIE)
        && let Ok(cookie_str) = cookie_header.to_str()
    {
        for cookie in cookie_str.split(';') {
            let cookie = cookie.trim();
            if let Some(value) = cookie.strip_prefix("vouch_admin=") {
                let token_hash = hex::encode(digest::digest(&SHA256, value.as_bytes()));
                if let Ok(Some(session)) =
                    db::get_admin_session_by_token_hash(&state.db, &token_hash).await
                {
                    let _ = db::revoke_admin_session(&state.db, &session.id).await;
                    tracing::info!("Admin logout: {}", session.admin_email);
                }
            }
        }
    }

    // Clear cookie and redirect to login
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/admin/login")
        .header(
            header::SET_COOKIE,
            "vouch_admin=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
        )
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
