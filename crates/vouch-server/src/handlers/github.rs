// SPDX-License-Identifier: BUSL-1.1
//! GitHub App installation handlers.
//!
//! Handles:
//! - POST /api/webhooks/github - GitHub webhook events
//! - GET /github/callback - Post-installation redirect
//! - GET /github/connect - Connect GitHub page
//! - GET /github/success - Success page after connection

use crate::db::{self, GitHubCredentialEventParams};
use crate::github_app::GitHubInstallationId;
use crate::handlers::common::{AuthContext, json_error};
use crate::{AppState, impl_template_response};
use askama::Template;
use aws_lc_rs::hmac;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use vouch_common::ApiError;

// ============================================================================
// Templates
// ============================================================================

/// Unlinked GitHub installation (exists on GitHub but not in our database).
pub struct UnlinkedInstallation {
    pub id: u64,
    pub account_login: String,
    pub account_type: String,
}

/// GitHub connect page template.
#[derive(Template)]
#[template(path = "github/connect.html")]
pub struct GitHubConnectTemplate {
    pub org_name: String,
    pub github_app_url: String,
    pub error: Option<String>,
    /// Already connected GitHub accounts.
    pub connected_accounts: Vec<String>,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(GitHubConnectTemplate);

/// GitHub success page template.
#[derive(Template)]
#[template(path = "github/success.html")]
pub struct GitHubSuccessTemplate {
    pub org_name: String,
    pub github_account: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(GitHubSuccessTemplate);

/// Error page template.
#[derive(Template)]
#[template(path = "github/error.html")]
pub struct GitHubErrorTemplate {
    pub title: String,
    pub message: String,
}

impl_template_response!(GitHubErrorTemplate);

// ============================================================================
// State Token (for CSRF protection)
// ============================================================================

/// State token for GitHub installation callback.
#[derive(Debug, Serialize, Deserialize)]
struct GitHubStateToken {
    /// Organization ID being connected.
    org_id: String,
    /// User ID initiating the connection.
    user_id: String,
    /// Issued at timestamp (Unix seconds).
    iat: i64,
    /// Expiration timestamp (Unix seconds).
    exp: i64,
    /// Random nonce for replay protection.
    nonce: String,
}

impl GitHubStateToken {
    /// Create a new state token (10-minute validity).
    fn new(org_id: &str, user_id: &str) -> Self {
        let now = Timestamp::now().as_second();
        let nonce = URL_SAFE_NO_PAD.encode(crate::handlers::common::generate_random_bytes(16));
        Self {
            org_id: org_id.to_string(),
            user_id: user_id.to_string(),
            iat: now,
            exp: now + 600, // 10 minutes
            nonce,
        }
    }

    /// Encode as JWT.
    fn encode(&self, secret: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
        encode(&Header::default(), self, &EncodingKey::from_secret(secret))
    }

    /// Decode from JWT.
    fn decode(token: &str, secret: &[u8]) -> Result<Self, jsonwebtoken::errors::Error> {
        let data = decode::<Self>(
            token,
            &DecodingKey::from_secret(secret),
            &Validation::default(),
        )?;
        Ok(data.claims)
    }
}

// ============================================================================
// Webhook Types
// ============================================================================

/// Installation webhook events with typed actions.
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum InstallationEvent {
    Created {
        installation: WebhookInstallation,
        #[serde(default)]
        repositories: Vec<WebhookRepository>,
        #[allow(dead_code)]
        sender: Option<WebhookSender>,
    },
    Deleted {
        installation: WebhookInstallation,
        #[serde(default)]
        #[allow(dead_code)]
        repositories: Vec<WebhookRepository>,
    },
    Suspend {
        installation: WebhookInstallation,
    },
    Unsuspend {
        installation: WebhookInstallation,
    },
    /// Catch-all for unhandled actions (e.g., new_permissions_accepted).
    #[serde(other)]
    Unknown,
}

/// Installation repositories webhook events.
/// Note: Both arrays are always present in GitHub payloads (one may be empty).
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum InstallationRepositoriesEvent {
    Added {
        installation: WebhookInstallation,
        #[serde(default)]
        repositories_added: Vec<WebhookRepository>,
        #[serde(default)]
        repositories_removed: Vec<WebhookRepository>,
    },
    Removed {
        installation: WebhookInstallation,
        #[serde(default)]
        repositories_added: Vec<WebhookRepository>,
        #[serde(default)]
        repositories_removed: Vec<WebhookRepository>,
    },
    /// Catch-all for unhandled actions.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
struct WebhookInstallation {
    id: u64,
    account: WebhookAccount,
}

#[derive(Debug, Deserialize)]
struct WebhookAccount {
    login: String,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    account_type: String,
}

#[derive(Debug, Deserialize)]
struct WebhookRepository {
    name: String,
    #[allow(dead_code)]
    full_name: String,
    #[allow(dead_code)]
    private: bool,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct WebhookSender {
    login: String,
}

// ============================================================================
// Callback Parameters
// ============================================================================

/// Query parameters for GitHub callback.
#[derive(Debug, Deserialize)]
pub struct GitHubCallbackParams {
    /// Installation ID from GitHub.
    installation_id: Option<u64>,
    /// State token for CSRF protection.
    state: Option<String>,
    /// Setup action (only present during installation).
    #[allow(dead_code)]
    setup_action: Option<String>,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /api/webhooks/github - Handle GitHub webhook events.
pub async fn github_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    // Verify webhook secret is configured
    let webhook_secret = state
        .config
        .github_webhook_secret_exposed()
        .ok_or_else(|| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "not_configured",
                "GitHub webhook secret not configured",
            )
        })?;

    // Verify signature
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("sha256="))
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "invalid_signature",
                "Missing or invalid X-Hub-Signature-256 header",
            )
        })?;

    // Compute expected signature
    let key = hmac::Key::new(hmac::HMAC_SHA256, webhook_secret.as_bytes());
    let computed = hmac::sign(&key, &body);
    let computed_hex = hex::encode(computed.as_ref());

    // Constant-time comparison
    if computed_hex.as_bytes().ct_eq(signature.as_bytes()).into() {
        // Signatures match
    } else {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "invalid_signature",
            "Invalid webhook signature",
        ));
    }

    // Get event type
    let event_type = headers
        .get("x-github-event")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    match event_type {
        "installation" => handle_installation_event(&state, &body).await,
        "installation_repositories" => handle_installation_repositories_event(&state, &body).await,
        _ => {
            tracing::debug!("Ignoring GitHub webhook event: {}", event_type);
            Ok(StatusCode::OK)
        }
    }
}

/// Parse webhook payload with standardized error handling.
fn parse_webhook<T: serde::de::DeserializeOwned>(
    body: &[u8],
    event_type: &str,
) -> Result<T, (StatusCode, Json<ApiError>)> {
    serde_json::from_slice(body).map_err(|e| {
        tracing::warn!("Failed to parse {} payload: {}", event_type, e);
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_payload",
            "Invalid webhook payload",
        )
    })
}

/// Handle installation webhook events (created, deleted, suspend, unsuspend).
async fn handle_installation_event(
    state: &Arc<AppState>,
    body: &[u8],
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let event: InstallationEvent = parse_webhook(body, "installation")?;

    match event {
        InstallationEvent::Created {
            installation,
            repositories,
            ..
        } => {
            let installation_id = installation.id as i64;
            let repo_names: Vec<String> = repositories.iter().map(|r| r.name.clone()).collect();
            if repo_names.is_empty() {
                tracing::info!(
                    "GitHub installation created: {} ({}) with all repositories",
                    installation_id,
                    installation.account.login
                );
            } else {
                tracing::info!(
                    "GitHub installation created: {} ({}) with {} repositories",
                    installation_id,
                    installation.account.login,
                    repo_names.len()
                );
                if let Err(e) =
                    db::update_github_installation_repos(&state.db, installation_id, &repo_names)
                        .await
                {
                    tracing::error!(
                        "Failed to update repos for installation {}: {}",
                        installation_id,
                        e
                    );
                }
            }
        }
        InstallationEvent::Deleted { installation, .. } => {
            let installation_id = installation.id as i64;
            tracing::info!(
                "GitHub installation deleted: {} ({})",
                installation_id,
                installation.account.login
            );
            if let Err(e) =
                db::delete_github_installation_by_installation_id(&state.db, installation_id).await
            {
                tracing::error!("Failed to delete installation {}: {}", installation_id, e);
            }
        }
        InstallationEvent::Suspend { installation } => {
            let installation_id = installation.id as i64;
            tracing::info!(
                "GitHub installation suspended: {} ({})",
                installation_id,
                installation.account.login
            );
            if let Err(e) = db::suspend_github_installation(&state.db, installation_id).await {
                tracing::error!("Failed to suspend installation {}: {}", installation_id, e);
            }
        }
        InstallationEvent::Unsuspend { installation } => {
            let installation_id = installation.id as i64;
            tracing::info!(
                "GitHub installation unsuspended: {} ({})",
                installation_id,
                installation.account.login
            );
            if let Err(e) = db::unsuspend_github_installation(&state.db, installation_id).await {
                tracing::error!(
                    "Failed to unsuspend installation {}: {}",
                    installation_id,
                    e
                );
            }
        }
        InstallationEvent::Unknown => {
            tracing::debug!("Ignoring unknown installation action");
        }
    }

    Ok(StatusCode::OK)
}

/// Handle installation_repositories webhook events (added/removed repos).
async fn handle_installation_repositories_event(
    state: &Arc<AppState>,
    body: &[u8],
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let event: InstallationRepositoriesEvent = parse_webhook(body, "installation_repositories")?;

    let (installation, added, removed, action) = match event {
        InstallationRepositoriesEvent::Added {
            installation,
            repositories_added,
            repositories_removed,
        } => (
            installation,
            repositories_added,
            repositories_removed,
            "added",
        ),
        InstallationRepositoriesEvent::Removed {
            installation,
            repositories_added,
            repositories_removed,
        } => (
            installation,
            repositories_added,
            repositories_removed,
            "removed",
        ),
        InstallationRepositoriesEvent::Unknown => {
            tracing::debug!("Ignoring unknown installation_repositories action");
            return Ok(StatusCode::OK);
        }
    };

    let installation_id = installation.id as i64;
    let added_names: Vec<String> = added.iter().map(|r| r.name.clone()).collect();
    let removed_names: Vec<String> = removed.iter().map(|r| r.name.clone()).collect();

    tracing::info!(
        "GitHub installation {} repositories updated: +{} -{} ({})",
        installation_id,
        added_names.len(),
        removed_names.len(),
        action
    );

    if let Err(e) = db::update_github_installation_repos_delta(
        &state.db,
        installation_id,
        &added_names,
        &removed_names,
    )
    .await
    {
        tracing::error!(
            "Failed to update repos delta for installation {}: {}",
            installation_id,
            e
        );
    }

    Ok(StatusCode::OK)
}

/// Query parameters for connect page (may include callback params).
#[derive(Debug, Deserialize, Default)]
pub struct GitHubConnectParams {
    /// Installation ID from GitHub (present when redirected after install).
    installation_id: Option<u64>,
    /// State token for CSRF protection.
    state: Option<String>,
    /// Setup action (only present during installation).
    #[allow(dead_code)]
    setup_action: Option<String>,
}

/// GET /github/connect - Show GitHub connection page.
///
/// Also handles redirects from GitHub after app installation if the GitHub App's
/// "Setup URL" points here instead of `/github/callback`.
pub async fn github_connect_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<GitHubConnectParams>,
) -> Response {
    // If we have installation_id and state, redirect to the callback handler
    if let (Some(installation_id), Some(state_token)) = (params.installation_id, &params.state) {
        let callback_url = format!(
            "/github/callback?installation_id={}&state={}",
            installation_id,
            urlencoding::encode(state_token)
        );
        return Redirect::to(&callback_url).into_response();
    }

    // Verify GitHub App is configured
    if state.github_app.is_none() {
        return GitHubErrorTemplate {
            title: "Not Available".to_string(),
            message: "GitHub integration is not configured on this server.".to_string(),
        }
        .into_response();
    }

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
            return GitHubErrorTemplate {
                title: "Error".to_string(),
                message: "User not found.".to_string(),
            }
            .into_response();
        }
    };

    // Verify user has an organization
    let org_id = match &user.org_id {
        Some(id) => id,
        None => {
            return GitHubErrorTemplate {
                title: "Organization Required".to_string(),
                message: "GitHub integration requires a Google Workspace account. Personal Gmail accounts are not supported.".to_string(),
            }
            .into_response();
        }
    };

    // Verify user is org admin
    if !user.is_org_admin {
        return GitHubErrorTemplate {
            title: "Admin Required".to_string(),
            message: "Only organization administrators can connect GitHub.".to_string(),
        }
        .into_response();
    }

    // Get existing installations (for display, but allow adding more)
    let existing_installations = db::get_github_installations_by_org(&state.db, org_id)
        .await
        .unwrap_or_default();
    let connected_accounts: Vec<String> = existing_installations
        .iter()
        .map(|i| i.github_account_login.clone())
        .collect();

    // Generate state token
    let state_token = GitHubStateToken::new(org_id, &user.id);
    let encoded_state = match state_token.encode(state.config.jwt_secret_bytes()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to encode state token: {}", e);
            return GitHubErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to generate state token.".to_string(),
            }
            .into_response();
        }
    };

    // Build GitHub App installation URL
    let app_name = match &state.config.github_app_name {
        Some(name) => name,
        None => {
            return GitHubErrorTemplate {
                title: "Configuration Error".to_string(),
                message: "GitHub App name not configured. Set VOUCH_GITHUB_APP_NAME.".to_string(),
            }
            .into_response();
        }
    };
    let github_app_url = format!(
        "https://github.com/apps/{}/installations/new?state={}",
        urlencoding::encode(app_name),
        urlencoding::encode(&encoded_state)
    );

    let auth = AuthContext {
        authenticated: true,
        user_id: Some(user.id.clone()),
        user_email: Some(user.email),
        has_org: user.org_id.is_some(),
        is_org_admin: user.is_org_admin,
    };

    GitHubConnectTemplate {
        org_name: state.config.get_org_display_name().to_string(),
        github_app_url,
        error: None,
        connected_accounts,
        auth,
    }
    .into_response()
}

/// GET /github/callback - Handle post-installation redirect from GitHub.
pub async fn github_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GitHubCallbackParams>,
) -> Response {
    // Verify required parameters
    let installation_id = match params.installation_id {
        Some(id) => id,
        None => {
            return GitHubErrorTemplate {
                title: "Error".to_string(),
                message: "Missing installation ID.".to_string(),
            }
            .into_response();
        }
    };

    let state_token = match &params.state {
        Some(s) => s,
        None => {
            return GitHubErrorTemplate {
                title: "Error".to_string(),
                message: "Missing state parameter.".to_string(),
            }
            .into_response();
        }
    };

    // Decode and validate state token
    let token = match GitHubStateToken::decode(state_token, state.config.jwt_secret_bytes()) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Invalid state token: {}", e);
            return GitHubErrorTemplate {
                title: "Invalid State".to_string(),
                message: "The state token is invalid or expired. Please try again.".to_string(),
            }
            .into_response();
        }
    };

    // Verify GitHub App is configured
    let github_app = match &state.github_app {
        Some(app) => app,
        None => {
            return GitHubErrorTemplate {
                title: "Not Available".to_string(),
                message: "GitHub integration is not configured on this server.".to_string(),
            }
            .into_response();
        }
    };

    // Fetch installation details from GitHub
    let details = match github_app
        .get_installation_details(GitHubInstallationId(installation_id))
        .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Failed to fetch installation details: {}", e);
            return GitHubErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to fetch installation details from GitHub.".to_string(),
            }
            .into_response();
        }
    };

    // Serialize permissions to JSON
    let permissions_json = serde_json::to_string(&details.permissions).unwrap_or_default();

    // Get user for audit log
    let user = match db::get_user_by_id(&state.db, &token.user_id).await {
        Ok(Some(u)) => u,
        _ => {
            return GitHubErrorTemplate {
                title: "Error".to_string(),
                message: "User not found.".to_string(),
            }
            .into_response();
        }
    };

    // Store installation in database
    match db::create_github_installation(
        &state.db,
        &token.org_id,
        installation_id as i64,
        &details.account.login,
        &details.account.account_type,
        &permissions_json,
        &details.repository_selection,
        Some(&token.user_id),
    )
    .await
    {
        Ok(_) => {
            tracing::info!(
                "GitHub installation connected: {} -> org {}",
                details.account.login,
                token.org_id
            );
        }
        Err(e) => {
            tracing::error!("Failed to store installation: {}", e);
            return GitHubErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to store installation. The organization may already have a GitHub connection.".to_string(),
            }
            .into_response();
        }
    }

    // Log audit event
    if let Err(e) = db::log_github_credential_event(
        &state.db,
        GitHubCredentialEventParams {
            event_type: "installation_connected",
            user_id: &user.id,
            user_email: &user.email,
            org_id: Some(&token.org_id),
            installation_id: Some(installation_id as i64),
            session_id: None,
            authenticator_id: None,
            repositories: None,
            permissions: Some(&permissions_json),
            token_expires_at: None,
            success: true,
            error_code: None,
            ip_address: None,
            user_agent: None,
        },
    )
    .await
    {
        tracing::warn!("Failed to log GitHub credential event: {e}");
    }

    Redirect::to(&format!(
        "/github/success?account={}",
        urlencoding::encode(&details.account.login)
    ))
    .into_response()
}

/// GET /github/success - Show success page after GitHub connection.
pub async fn github_success_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<GitHubSuccessParams>,
) -> impl IntoResponse {
    let auth = crate::handlers::common::get_auth_context(&state, &jar).await;

    GitHubSuccessTemplate {
        org_name: state.config.get_org_display_name().to_string(),
        github_account: params.account.unwrap_or_else(|| "GitHub".to_string()),
        auth,
    }
}

/// Query parameters for success page.
#[derive(Debug, Deserialize)]
pub struct GitHubSuccessParams {
    account: Option<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_installation_created() {
        let payload = r#"{
            "action": "created",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } },
            "repositories": [{ "name": "Hello-World", "full_name": "Codertocat/Hello-World", "private": false }],
            "sender": { "login": "Codertocat" }
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        match event {
            InstallationEvent::Created {
                installation,
                repositories,
                ..
            } => {
                assert_eq!(installation.id, 957387);
                assert_eq!(installation.account.login, "Codertocat");
                assert_eq!(repositories.len(), 1);
                assert_eq!(repositories[0].name, "Hello-World");
            }
            _ => panic!("Expected Created event"),
        }
    }

    #[test]
    fn test_parse_installation_created_without_repos() {
        let payload = r#"{
            "action": "created",
            "installation": { "id": 123, "account": { "login": "test-org", "type": "Organization" } },
            "sender": { "login": "admin" }
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        match event {
            InstallationEvent::Created { repositories, .. } => {
                assert!(repositories.is_empty());
            }
            _ => panic!("Expected Created event"),
        }
    }

    #[test]
    fn test_parse_installation_deleted() {
        let payload = r#"{
            "action": "deleted",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } },
            "repositories": []
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        assert!(matches!(event, InstallationEvent::Deleted { .. }));
    }

    #[test]
    fn test_parse_installation_suspend() {
        let payload = r#"{
            "action": "suspend",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } }
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        assert!(matches!(event, InstallationEvent::Suspend { .. }));
    }

    #[test]
    fn test_parse_installation_unsuspend() {
        let payload = r#"{
            "action": "unsuspend",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } }
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        assert!(matches!(event, InstallationEvent::Unsuspend { .. }));
    }

    #[test]
    fn test_parse_installation_unknown_action() {
        let payload = r#"{
            "action": "new_permissions_accepted",
            "installation": { "id": 1, "account": { "login": "x", "type": "User" } }
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        assert!(matches!(event, InstallationEvent::Unknown));
    }

    #[test]
    fn test_parse_installation_repositories_added() {
        let payload = r#"{
            "action": "added",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } },
            "repositories_added": [{ "name": "Space", "full_name": "Codertocat/Space", "private": false }],
            "repositories_removed": []
        }"#;
        let event: InstallationRepositoriesEvent = serde_json::from_str(payload).unwrap();
        match event {
            InstallationRepositoriesEvent::Added {
                installation,
                repositories_added,
                repositories_removed,
            } => {
                assert_eq!(installation.id, 957387);
                assert_eq!(repositories_added.len(), 1);
                assert_eq!(repositories_added[0].name, "Space");
                assert!(repositories_removed.is_empty());
            }
            _ => panic!("Expected Added event"),
        }
    }

    #[test]
    fn test_parse_installation_repositories_removed() {
        let payload = r#"{
            "action": "removed",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } },
            "repositories_added": [],
            "repositories_removed": [{ "name": "OldRepo", "full_name": "Codertocat/OldRepo", "private": true }]
        }"#;
        let event: InstallationRepositoriesEvent = serde_json::from_str(payload).unwrap();
        match event {
            InstallationRepositoriesEvent::Removed {
                repositories_added,
                repositories_removed,
                ..
            } => {
                assert!(repositories_added.is_empty());
                assert_eq!(repositories_removed.len(), 1);
                assert_eq!(repositories_removed[0].name, "OldRepo");
            }
            _ => panic!("Expected Removed event"),
        }
    }

    #[test]
    fn test_parse_installation_repositories_unknown_action() {
        let payload = r#"{
            "action": "future_action",
            "installation": { "id": 1, "account": { "login": "x", "type": "User" } }
        }"#;
        let event: InstallationRepositoriesEvent = serde_json::from_str(payload).unwrap();
        assert!(matches!(event, InstallationRepositoriesEvent::Unknown));
    }
}
