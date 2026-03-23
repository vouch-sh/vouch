// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub App installation handlers.
//!
//! Handles:
//! - POST /api/webhooks/github - GitHub webhook events
//! - GET /github/callback - Post-installation redirect and OAuth callback
//! - GET /github/connect - Connect GitHub page
//! - GET /github/link - Start GitHub OAuth flow to link account
//! - POST /github/reconnect - Reconnect an existing GitHub installation
//! - GET /github/success - Success page after connection

use crate::db;
use crate::handlers::HasVersion;
use crate::handlers::session::AuthContext;
use crate::services::error::ServiceError;
use crate::services::integrations::github::{
    ConnectInstallationParams, GitHubError, GitHubService, LinkAccountParams,
    ReconnectInstallationParams, installations::validate_org_admin, webhooks::WebhookEvent,
};
use crate::{AppState, impl_template_response};
use askama::Template;
use axum::Form;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    /// Whether the user has linked their GitHub account.
    pub github_linked: bool,
    /// GitHub username if linked.
    pub github_login: Option<String>,
    /// Unlinked installations the user can reconnect.
    pub unlinked_installations: Vec<UnlinkedInstallation>,
    /// Whether GitHub OAuth is configured (client_id + client_secret).
    pub oauth_configured: bool,
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

/// Type of GitHub state token flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GitHubStateFlowType {
    /// Installation flow - user is installing the GitHub App.
    Install,
    /// Link flow - user is linking their GitHub account via OAuth.
    Link,
}

/// State token for GitHub installation and OAuth callbacks.
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
    /// Flow type (install or link).
    #[serde(default = "default_flow_type")]
    flow_type: GitHubStateFlowType,
}

fn default_flow_type() -> GitHubStateFlowType {
    GitHubStateFlowType::Install
}

impl GitHubStateToken {
    /// Create a new state token for installation flow (10-minute validity).
    fn new_for_install(org_id: &str, user_id: &str) -> Result<Self, aws_lc_rs::error::Unspecified> {
        Self::new(org_id, user_id, GitHubStateFlowType::Install)
    }

    /// Create a new state token for OAuth link flow (10-minute validity).
    fn new_for_link(org_id: &str, user_id: &str) -> Result<Self, aws_lc_rs::error::Unspecified> {
        Self::new(org_id, user_id, GitHubStateFlowType::Link)
    }

    fn new(
        org_id: &str,
        user_id: &str,
        flow_type: GitHubStateFlowType,
    ) -> Result<Self, aws_lc_rs::error::Unspecified> {
        let now = Timestamp::now().as_second();
        let nonce = URL_SAFE_NO_PAD.encode(crate::crypto::generate_random_bytes(16)?);
        Ok(Self {
            org_id: org_id.to_string(),
            user_id: user_id.to_string(),
            iat: now,
            exp: now + 600, // 10 minutes
            nonce,
            flow_type,
        })
    }

    /// Encode as JWT (RFC 8725 §3.11: explicit typ).
    async fn encode(
        &self,
        signer: &crate::crypto::jwt::StateTokenSigner,
    ) -> Result<String, crate::crypto::jwt::StateTokenError> {
        signer
            .encode_state_token(self, crate::crypto::jwt::JwtType::GitHubState)
            .await
    }

    /// Decode from JWT.
    async fn decode(
        token: &str,
        signer: &crate::crypto::jwt::StateTokenSigner,
    ) -> Result<Self, crate::crypto::jwt::StateTokenError> {
        signer
            .decode_state_token(token, crate::crypto::jwt::JwtType::GitHubState)
            .await
    }
}

// ============================================================================
// Callback Parameters
// ============================================================================

/// Query parameters for GitHub callback.
#[derive(Debug, Deserialize)]
pub struct GitHubCallbackParams {
    /// Installation ID from GitHub (present for installation callbacks).
    installation_id: Option<u64>,
    /// State token for CSRF protection.
    state: Option<String>,
    /// Setup action (only present during installation).
    #[allow(dead_code)]
    setup_action: Option<String>,
    /// OAuth authorization code (present for OAuth callbacks).
    code: Option<String>,
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

/// Query parameters for success page.
#[derive(Debug, Deserialize)]
pub struct GitHubSuccessParams {
    account: Option<String>,
}

/// Form data for reconnecting a GitHub installation.
#[derive(Debug, Deserialize)]
pub struct GitHubReconnectForm {
    /// Installation ID to reconnect.
    installation_id: u64,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert a GitHubError to an error template response.
fn error_response(error: GitHubError) -> Response {
    GitHubErrorTemplate {
        title: error.title().to_string(),
        message: error.to_string(),
    }
    .into_response()
}

/// Create a GitHubService from AppState components.
fn github_service<'a>(
    state: &'a AppState,
    config: &'a crate::config::ServerConfig,
) -> GitHubService<'a> {
    GitHubService::new(
        &state.store,
        &state.audit,
        config,
        state.github_app.as_ref(),
    )
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /api/webhooks/github - Handle GitHub webhook events.
pub async fn github_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ServiceError> {
    let config = state.config();
    let service = github_service(&state, &config);

    // Extract and verify signature
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("sha256="))
        .ok_or_else(|| {
            ServiceError::api(
                StatusCode::UNAUTHORIZED,
                "invalid_signature",
                "Missing or invalid X-Hub-Signature-256 header",
            )
        })?;

    service
        .verify_webhook_signature(signature, &body)
        .map_err(|e| {
            ServiceError::api(StatusCode::UNAUTHORIZED, "invalid_signature", e.to_string())
        })?;

    // Get event type and handle
    let event_type = headers
        .get("x-github-event")
        .and_then(|h| h.to_str().ok())
        .map(WebhookEvent::from)
        .unwrap_or(WebhookEvent::Unknown);

    service
        .handle_webhook_event(event_type, &body)
        .await
        .map_err(|e| {
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "webhook_error",
                e.to_string(),
            )
        })?;

    Ok(StatusCode::OK)
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

    let config = state.config();
    let service = github_service(&state, &config);

    // Verify GitHub App is configured
    if !service.is_configured() {
        return error_response(GitHubError::NotConfigured);
    }

    // Extract session from cookie (browser UI)
    let session = match crate::handlers::session::extract_session_from_cookie(&state, &jar).await {
        Ok(s) => s,
        Err(_) => {
            return Redirect::to("/enroll/start").into_response();
        }
    };

    // Get user
    let user = match db::get_user_by_id(&state.store, &session.sub).await {
        Ok(Some(u)) => u,
        _ => return error_response(GitHubError::UserNotFound),
    };

    // Verify user has an organization and is admin
    let org_id = match validate_org_admin(&user) {
        Ok(org_id) => org_id,
        Err(e) => return error_response(e),
    };

    // Get existing connected accounts
    let connected_accounts = service
        .get_org_installations(org_id)
        .await
        .unwrap_or_default();

    // Get unlinked installations the user can reconnect
    let unlinked_installations = service
        .get_unlinked_installations(&user)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|i| UnlinkedInstallation {
            id: i.id,
            account_login: i.account_login,
            account_type: i.account_type,
        })
        .collect();

    // Generate state token for installation flow
    let state_token = match GitHubStateToken::new_for_install(org_id, &user.id) {
        Ok(t) => t,
        Err(_) => {
            return error_response(GitHubError::Internal(
                "Failed to generate secure state token".to_string(),
            ));
        }
    };
    let encoded_state = match state_token.encode(&state.state_signer).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to encode state token: {}", e);
            return error_response(GitHubError::Internal(
                "Failed to generate state token".to_string(),
            ));
        }
    };

    // Build GitHub App installation URL
    let github_app_url = match service.build_installation_url(&encoded_state) {
        Ok(url) => url,
        Err(e) => return error_response(e),
    };

    let auth = AuthContext {
        authenticated: true,
        user_id: Some(user.id.clone()),
        user_email: Some(user.email),
        has_org: user.org_id.is_some(),
        is_org_admin: user.is_org_admin,
    };

    GitHubConnectTemplate {
        org_name: state.config().get_org_display_name().to_string(),
        github_app_url,
        error: None,
        connected_accounts,
        auth,
        github_linked: user.github_login.is_some(),
        github_login: user.github_login.clone(),
        unlinked_installations,
        oauth_configured: service.is_oauth_configured(),
    }
    .into_response()
}

/// GET /github/callback - Handle both OAuth and installation callbacks from GitHub.
///
/// Distinguishes between:
/// - OAuth callbacks: Have `code` parameter (user linking their GitHub account)
/// - Installation callbacks: Have `installation_id` parameter (app installation)
pub async fn github_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GitHubCallbackParams>,
) -> Response {
    // Detect callback type by presence of `code` parameter
    if let Some(code) = &params.code {
        return handle_oauth_callback(&state, code, params.state.as_deref()).await;
    }

    // Otherwise, handle as installation callback
    handle_installation_callback(&state, &params).await
}

/// Handle OAuth callback - user linking their GitHub account.
async fn handle_oauth_callback(
    state: &Arc<AppState>,
    code: &str,
    state_param: Option<&str>,
) -> Response {
    // Verify state parameter
    let state_token = match state_param {
        Some(s) => s,
        None => return error_response(GitHubError::InvalidStateToken),
    };

    // Decode and validate state token
    let token = match GitHubStateToken::decode(state_token, &state.state_signer).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Invalid state token: {}", e);
            return error_response(GitHubError::InvalidStateToken);
        }
    };

    // Verify this is a link flow
    if token.flow_type != GitHubStateFlowType::Link {
        return error_response(GitHubError::WrongFlowType);
    }

    let config = state.config();
    let service = github_service(state, &config);

    // Link the account
    match service
        .link_user_account(LinkAccountParams {
            code,
            user_id: &token.user_id,
        })
        .await
    {
        Ok(_) => Redirect::to("/github/connect").into_response(),
        Err(e) => {
            tracing::error!(user_id = %token.user_id, "GitHub OAuth account linking failed: {e}");
            error_response(e)
        }
    }
}

/// Handle installation callback - app installation flow.
async fn handle_installation_callback(
    state: &Arc<AppState>,
    params: &GitHubCallbackParams,
) -> Response {
    // Verify required parameters
    let installation_id = match params.installation_id {
        Some(id) => id,
        None => {
            return error_response(GitHubError::Internal("Missing installation ID".to_string()));
        }
    };

    let state_token = match &params.state {
        Some(s) => s,
        None => return error_response(GitHubError::InvalidStateToken),
    };

    // Decode and validate state token
    let token = match GitHubStateToken::decode(state_token, &state.state_signer).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Invalid state token: {}", e);
            return error_response(GitHubError::InvalidStateToken);
        }
    };

    // Get user for audit log
    let user = match db::get_user_by_id(&state.store, &token.user_id).await {
        Ok(Some(u)) => u,
        _ => return error_response(GitHubError::UserNotFound),
    };

    let config = state.config();
    let service = github_service(state, &config);

    // Connect the installation
    match service
        .connect_installation(ConnectInstallationParams {
            installation_id,
            org_id: &token.org_id,
            user: &user,
        })
        .await
    {
        Ok(result) => Redirect::to(&format!(
            "/github/success?account={}",
            urlencoding::encode(&result.account_login)
        ))
        .into_response(),
        Err(e) => {
            tracing::error!(
                user_id = %token.user_id,
                installation_id,
                "GitHub installation connection failed: {e}"
            );
            error_response(e)
        }
    }
}

/// GET /github/link - Redirect user to GitHub OAuth to link their GitHub account.
pub async fn github_link_start(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    let config = state.config();
    let service = github_service(&state, &config);

    // Verify OAuth is configured
    if !service.is_oauth_configured() {
        return error_response(GitHubError::OAuthNotConfigured);
    }

    // Extract session from cookie
    let session = match crate::handlers::session::extract_session_from_cookie(&state, &jar).await {
        Ok(s) => s,
        Err(_) => {
            return Redirect::to("/enroll/start").into_response();
        }
    };

    // Get user
    let user = match db::get_user_by_id(&state.store, &session.sub).await {
        Ok(Some(u)) => u,
        _ => return error_response(GitHubError::UserNotFound),
    };

    // Verify user has an organization
    let org_id = match &user.org_id {
        Some(id) => id,
        None => return error_response(GitHubError::OrganizationRequired),
    };

    // Generate state token for link flow
    let state_token = match GitHubStateToken::new_for_link(org_id, &user.id) {
        Ok(t) => t,
        Err(_) => {
            return error_response(GitHubError::Internal(
                "Failed to generate secure state token".to_string(),
            ));
        }
    };
    let encoded_state = match state_token.encode(&state.state_signer).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to encode state token: {}", e);
            return error_response(GitHubError::Internal(
                "Failed to generate state token".to_string(),
            ));
        }
    };

    // Build OAuth URL
    match service.build_oauth_url(&encoded_state) {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(e) => error_response(e),
    }
}

/// POST /github/reconnect - Reconnect an existing GitHub installation.
///
/// This allows an org admin to link an existing GitHub installation (that they
/// have access to via `/user/installations`) to their Vouch organization.
pub async fn github_reconnect(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<GitHubReconnectForm>,
) -> Response {
    let config = state.config();
    let service = github_service(&state, &config);

    // Verify GitHub App is configured
    if !service.is_configured() {
        return error_response(GitHubError::NotConfigured);
    }

    // Extract session from cookie
    let session = match crate::handlers::session::extract_session_from_cookie(&state, &jar).await {
        Ok(s) => s,
        Err(_) => {
            return Redirect::to("/enroll/start").into_response();
        }
    };

    // Get user
    let user = match db::get_user_by_id(&state.store, &session.sub).await {
        Ok(Some(u)) => u,
        _ => return error_response(GitHubError::UserNotFound),
    };

    // Verify user has an organization and is admin
    let org_id = match validate_org_admin(&user) {
        Ok(org_id) => org_id.to_string(),
        Err(e) => return error_response(e),
    };

    // Reconnect the installation
    match service
        .reconnect_installation(ReconnectInstallationParams {
            installation_id: form.installation_id,
            org_id: &org_id,
            user: &user,
        })
        .await
    {
        Ok(result) => Redirect::to(&format!(
            "/github/success?account={}",
            urlencoding::encode(&result.account_login)
        ))
        .into_response(),
        Err(e) => {
            tracing::error!(
                user_id = %user.id,
                installation_id = form.installation_id,
                "GitHub installation reconnect failed: {e}"
            );
            error_response(e)
        }
    }
}

/// GET /github/success - Show success page after GitHub connection.
pub async fn github_success_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<GitHubSuccessParams>,
) -> impl IntoResponse {
    let auth = crate::handlers::session::get_auth_context(&state, &jar).await;

    GitHubSuccessTemplate {
        org_name: state.config().get_org_display_name().to_string(),
        github_account: params.account.unwrap_or_else(|| "GitHub".to_string()),
        auth,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::jwt::{JwtType, StateTokenSigner};
    use crate::test_utils::TEST_JWT_SECRET;

    #[tokio::test]
    async fn test_github_state_token_roundtrip() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let token = GitHubStateToken::new_for_install("org-1", "user-1").expect("create token");

        let encoded = token.encode(&signer).await.expect("encode");
        let decoded = GitHubStateToken::decode(&encoded, &signer)
            .await
            .expect("decode");

        assert_eq!(decoded.org_id, "org-1");
        assert_eq!(decoded.user_id, "user-1");
        assert_eq!(decoded.flow_type, GitHubStateFlowType::Install);
    }

    #[tokio::test]
    async fn test_github_state_token_link_flow() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let token = GitHubStateToken::new_for_link("org-2", "user-2").expect("create token");

        let encoded = token.encode(&signer).await.expect("encode");
        let decoded = GitHubStateToken::decode(&encoded, &signer)
            .await
            .expect("decode");

        assert_eq!(decoded.org_id, "org-2");
        assert_eq!(decoded.user_id, "user-2");
        assert_eq!(decoded.flow_type, GitHubStateFlowType::Link);
    }

    #[tokio::test]
    async fn test_github_state_token_wrong_secret_rejected() {
        let signer_a = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let signer_b =
            StateTokenSigner::local(b"different_secret_at_least_32chars_long!!".to_vec());
        let token = GitHubStateToken::new_for_install("org-1", "user-1").expect("create token");

        let encoded = token.encode(&signer_a).await.expect("encode");
        let result = GitHubStateToken::decode(&encoded, &signer_b).await;
        assert!(result.is_err(), "Wrong secret should be rejected");
    }

    #[tokio::test]
    async fn test_github_state_token_wrong_type_rejected() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let token = GitHubStateToken::new_for_install("org-1", "user-1").expect("create token");

        let encoded = token.encode(&signer).await.expect("encode");

        // Try decoding with wrong JwtType via the raw signer
        let result: Result<GitHubStateToken, _> = signer
            .decode_state_token(&encoded, JwtType::RegistrationState)
            .await;
        assert!(result.is_err(), "Wrong JWT type should be rejected");
    }
}
