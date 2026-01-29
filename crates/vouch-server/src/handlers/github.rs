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

/// GitHub webhook payload for installation events.
#[derive(Debug, Deserialize)]
struct InstallationWebhookPayload {
    action: String,
    installation: WebhookInstallation,
    #[allow(dead_code)]
    sender: Option<WebhookSender>,
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

    // Only handle installation events
    if event_type != "installation" {
        tracing::debug!("Ignoring GitHub webhook event: {}", event_type);
        return Ok(StatusCode::OK);
    }

    // Parse payload
    let payload: InstallationWebhookPayload = serde_json::from_slice(&body).map_err(|e| {
        tracing::warn!("Failed to parse webhook payload: {}", e);
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_payload",
            "Invalid webhook payload",
        )
    })?;

    let installation_id = payload.installation.id as i64;

    match payload.action.as_str() {
        "deleted" => {
            tracing::info!(
                "GitHub installation deleted: {} ({})",
                installation_id,
                payload.installation.account.login
            );
            let _ =
                db::delete_github_installation_by_installation_id(&state.db, installation_id).await;
        }
        "suspend" => {
            tracing::info!(
                "GitHub installation suspended: {} ({})",
                installation_id,
                payload.installation.account.login
            );
            let _ = db::suspend_github_installation(&state.db, installation_id).await;
        }
        "unsuspend" => {
            tracing::info!(
                "GitHub installation unsuspended: {} ({})",
                installation_id,
                payload.installation.account.login
            );
            let _ = db::unsuspend_github_installation(&state.db, installation_id).await;
        }
        _ => {
            tracing::debug!(
                "Ignoring installation action: {} for {}",
                payload.action,
                installation_id
            );
        }
    }

    Ok(StatusCode::OK)
}

/// GET /github/connect - Show GitHub connection page.
pub async fn github_connect_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
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
    let _ = db::log_github_credential_event(
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
    .await;

    Redirect::to(&format!(
        "/github/success?account={}",
        urlencoding::encode(&details.account.login)
    ))
    .into_response()
}

/// GET /github/success - Show success page after GitHub connection.
#[allow(clippy::unused_async)]
pub async fn github_success_page(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GitHubSuccessParams>,
) -> impl IntoResponse {
    GitHubSuccessTemplate {
        org_name: state.config.get_org_display_name().to_string(),
        github_account: params.account.unwrap_or_else(|| "GitHub".to_string()),
    }
}

/// Query parameters for success page.
#[derive(Debug, Deserialize)]
pub struct GitHubSuccessParams {
    account: Option<String>,
}
