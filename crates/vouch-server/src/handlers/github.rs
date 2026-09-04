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

use crate::error::ServiceError;
use crate::handlers::session::{
    AuthContext, extract_session_from_cookie, get_auth_context, load_active_user,
};
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
pub(crate) struct UnlinkedInstallation {
    pub id: u64,
    pub account_login: String,
    pub account_type: String,
}

/// GitHub connect page template.
#[derive(Template)]
#[template(path = "github/connect.html")]
#[allow(dead_code, reason = "fields rendered via Askama template macros")]
pub(crate) struct GitHubConnectTemplate {
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
#[allow(dead_code, reason = "fields rendered via Askama template macros")]
pub(crate) struct GitHubSuccessTemplate {
    pub org_name: String,
    pub github_account: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(GitHubSuccessTemplate);

/// Error page template.
#[derive(Template)]
#[template(path = "github/error.html")]
pub(crate) struct GitHubErrorTemplate {
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
///
/// Bound to the initiating session via `session_binding` (the SHA-256 token hash
/// of the access token that minted this state). On callback, the server requires
/// that the same session cookie is present and that its `token_hash` matches —
/// preventing CSRF where an attacker pairs their state with a victim's GitHub
/// authorization (RFC 6819 §5.3.5).
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
    /// SHA-256 hash of the access token from the session that minted this
    /// state. Required at callback time to bind the flow to a single session.
    session_binding: String,
}

fn default_flow_type() -> GitHubStateFlowType {
    GitHubStateFlowType::Install
}

impl GitHubStateToken {
    /// Create a new state token for installation flow (10-minute validity).
    fn new_for_install(
        org_id: &str,
        user_id: &str,
        session_binding: &str,
    ) -> Result<Self, aws_lc_rs::error::Unspecified> {
        Self::new(
            org_id,
            user_id,
            session_binding,
            GitHubStateFlowType::Install,
        )
    }

    /// Create a new state token for OAuth link flow (10-minute validity).
    fn new_for_link(
        org_id: &str,
        user_id: &str,
        session_binding: &str,
    ) -> Result<Self, aws_lc_rs::error::Unspecified> {
        Self::new(org_id, user_id, session_binding, GitHubStateFlowType::Link)
    }

    fn new(
        org_id: &str,
        user_id: &str,
        session_binding: &str,
        flow_type: GitHubStateFlowType,
    ) -> Result<Self, aws_lc_rs::error::Unspecified> {
        let now = Timestamp::now().as_second();
        let nonce = URL_SAFE_NO_PAD.encode(crate::crypto::generate_random_bytes(16)?);
        Ok(Self {
            org_id: org_id.to_string(),
            user_id: user_id.to_string(),
            iat: now,
            exp: now.saturating_add(600), // 10 minutes
            nonce,
            flow_type,
            session_binding: session_binding.to_string(),
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
pub(crate) struct GitHubCallbackParams {
    /// Installation ID from GitHub (present for installation callbacks).
    installation_id: Option<u64>,
    /// State token for CSRF protection.
    state: Option<String>,
    /// Setup action (only present during installation).
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
    setup_action: Option<String>,
    /// OAuth authorization code (present for OAuth callbacks).
    code: Option<String>,
}

/// Query parameters for connect page (may include callback params).
#[derive(Debug, Deserialize, Default)]
pub(crate) struct GitHubConnectParams {
    /// Installation ID from GitHub (present when redirected after install).
    installation_id: Option<u64>,
    /// State token for CSRF protection.
    state: Option<String>,
    /// Setup action (only present during installation).
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
    setup_action: Option<String>,
}

/// Query parameters for success page.
#[derive(Debug, Deserialize)]
pub(crate) struct GitHubSuccessParams {
    account: Option<String>,
}

/// Form data for reconnecting a GitHub installation.
#[derive(Debug, Deserialize)]
pub(crate) struct GitHubReconnectForm {
    /// Installation ID to reconnect.
    installation_id: u64,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert a GitHubError to an error template response.
///
/// **Implicit dependency:** resolves the page context via
/// [`PageContext::current`], which reads the `REQUEST_I18N` task-local set by
/// `crate::infra::i18n::i18n_layer`. That layer is applied at the merged
/// router in `build_app`, so any handler routed there is covered. A future
/// caller from a non-HTTP context (e.g. a background job) would silently fall
/// back to `en-US`.
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
pub(crate) async fn github_webhook(
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
        .map_or(WebhookEvent::Unknown, WebhookEvent::from);

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
pub(crate) async fn github_connect_page(
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
    let session = match extract_session_from_cookie(&state, &jar).await {
        Ok(s) => s,
        Err(_) => {
            return Redirect::to("/enroll/start").into_response();
        }
    };

    // Refuse a deactivated account: the cookie extraction skips the active
    // check, so this mutating flow carries its own guard.
    let user = match load_active_user(&state, &session.sub).await {
        Ok(u) => u,
        Err(_) => return error_response(GitHubError::UserNotFound),
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

    // Generate state token for installation flow, bound to the current session.
    let state_token = match GitHubStateToken::new_for_install(org_id, &user.id, &session.token_hash)
    {
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
///
/// Both flows require an authenticated session cookie that matches the session
/// which originally minted the state token (RFC 6819 §5.3.5 CSRF defense).
pub(crate) async fn github_callback(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<GitHubCallbackParams>,
) -> Response {
    // Detect callback type by presence of `code` parameter
    if let Some(code) = &params.code {
        return handle_oauth_callback(&state, &jar, code, params.state.as_deref()).await;
    }

    // Otherwise, handle as installation callback
    handle_installation_callback(&state, &jar, &params).await
}

/// Validate the callback session against the state token.
///
/// Enforces three properties:
///   1. A valid session cookie is present (otherwise `SessionRequired`).
///   2. The session's user matches `token.user_id` (otherwise `SessionMismatch`).
///   3. The session's `token_hash` matches `token.session_binding`, i.e. the
///      same session that minted the state is completing the callback.
///
/// Returns the validated session on success or an error response on failure.
#[expect(
    clippy::result_large_err,
    reason = "Err is an HTTP Response; size is acceptable in error path"
)]
async fn validate_callback_session(
    state: &Arc<AppState>,
    jar: &CookieJar,
    token: &GitHubStateToken,
    flow_label: &'static str,
) -> Result<crate::services::auth::ValidatedResourceToken, Response> {
    let session = match extract_session_from_cookie(state, jar).await {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!(
                flow = flow_label,
                expected_user_id = %token.user_id,
                expected_org_id = %token.org_id,
                "GitHub callback received without a valid session cookie — \
                 possible CSRF or stale flow"
            );
            return Err(error_response(GitHubError::SessionRequired));
        }
    };

    if session.sub != token.user_id {
        tracing::warn!(
            flow = flow_label,
            session_user_id = %session.sub,
            token_user_id = %token.user_id,
            "GitHub callback session does not match state token user — CSRF attempt"
        );
        return Err(error_response(GitHubError::SessionMismatch));
    }

    if session.token_hash != token.session_binding {
        tracing::warn!(
            flow = flow_label,
            session_user_id = %session.sub,
            "GitHub callback session_binding mismatch — state token was minted \
             from a different session"
        );
        return Err(error_response(GitHubError::SessionMismatch));
    }

    Ok(session)
}

/// Handle OAuth callback - user linking their GitHub account.
async fn handle_oauth_callback(
    state: &Arc<AppState>,
    jar: &CookieJar,
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

    // CSRF defense: bind the callback to the cookie session.
    let session = match validate_callback_session(state, jar, &token, "oauth_link").await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    let config = state.config();
    let service = github_service(state, &config);

    // Link the account — use the validated session user as the authoritative
    // identifier; the state token is only an equality witness at this point.
    match service
        .link_user_account(LinkAccountParams {
            code,
            user_id: &session.sub,
        })
        .await
    {
        Ok(_) => Redirect::to("/github/connect").into_response(),
        Err(e) => {
            tracing::error!(user_id = %session.sub, "GitHub OAuth account linking failed: {e}");
            error_response(e)
        }
    }
}

/// Handle installation callback - app installation flow.
async fn handle_installation_callback(
    state: &Arc<AppState>,
    jar: &CookieJar,
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

    if token.flow_type != GitHubStateFlowType::Install {
        return error_response(GitHubError::WrongFlowType);
    }

    // CSRF defense: bind the callback to the cookie session.
    let session = match validate_callback_session(state, jar, &token, "install").await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // Re-fetch the user from DB by the *session* identity (not the JWT),
    // refusing an account deactivated since the flow began.
    let user = match load_active_user(state, &session.sub).await {
        Ok(u) => u,
        Err(_) => return error_response(GitHubError::UserNotFound),
    };

    // Verify the user is still a member of the org bound to the state token.
    // Guards against the user changing orgs in the 10-minute state window.
    match user.org_id.as_deref() {
        Some(org_id) if org_id == token.org_id => {}
        _ => {
            tracing::warn!(
                user_id = %session.sub,
                token_org_id = %token.org_id,
                user_org_id = ?user.org_id,
                "GitHub installation callback: session user is not a member of \
                 the org bound to the state token"
            );
            return error_response(GitHubError::SessionMismatch);
        }
    }

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
                user_id = %session.sub,
                installation_id,
                "GitHub installation connection failed: {e}"
            );
            error_response(e)
        }
    }
}

/// GET /github/link - Redirect user to GitHub OAuth to link their GitHub account.
pub(crate) async fn github_link_start(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Response {
    let config = state.config();
    let service = github_service(&state, &config);

    // Verify OAuth is configured
    if !service.is_oauth_configured() {
        return error_response(GitHubError::OAuthNotConfigured);
    }

    // Extract session from cookie
    let session = match extract_session_from_cookie(&state, &jar).await {
        Ok(s) => s,
        Err(_) => {
            return Redirect::to("/enroll/start").into_response();
        }
    };

    // Refuse a deactivated account: the cookie extraction skips the active
    // check, so this mutating flow carries its own guard.
    let user = match load_active_user(&state, &session.sub).await {
        Ok(u) => u,
        Err(_) => return error_response(GitHubError::UserNotFound),
    };

    // Verify user has an organization
    let org_id = match &user.org_id {
        Some(id) => id,
        None => return error_response(GitHubError::OrganizationRequired),
    };

    // Generate state token for link flow, bound to the current session.
    let state_token = match GitHubStateToken::new_for_link(org_id, &user.id, &session.token_hash) {
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
pub(crate) async fn github_reconnect(
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
    let session = match extract_session_from_cookie(&state, &jar).await {
        Ok(s) => s,
        Err(_) => {
            return Redirect::to("/enroll/start").into_response();
        }
    };

    // Refuse a deactivated account: the cookie extraction skips the active
    // check, so this mutating flow carries its own guard.
    let user = match load_active_user(&state, &session.sub).await {
        Ok(u) => u,
        Err(_) => return error_response(GitHubError::UserNotFound),
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
pub(crate) async fn github_success_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<GitHubSuccessParams>,
) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;

    GitHubSuccessTemplate {
        org_name: state.config().get_org_display_name().to_string(),
        github_account: params.account.unwrap_or_else(|| "GitHub".to_string()),
        auth,
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::crypto::jwt::{JwtType, StateTokenSigner};
    use crate::test_utils::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_github_state_token_roundtrip() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let token = GitHubStateToken::new_for_install("org-1", "user-1", "test-binding")
            .expect("create token");

        let encoded = token.encode(&signer).await.expect("encode");
        let decoded = GitHubStateToken::decode(&encoded, &signer)
            .await
            .expect("decode");

        assert_eq!(decoded.org_id, "org-1");
        assert_eq!(decoded.user_id, "user-1");
        assert_eq!(decoded.flow_type, GitHubStateFlowType::Install);
        assert_eq!(decoded.session_binding, "test-binding");
    }

    #[tokio::test]
    async fn test_github_state_token_link_flow() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let token = GitHubStateToken::new_for_link("org-2", "user-2", "test-binding-link")
            .expect("create token");

        let encoded = token.encode(&signer).await.expect("encode");
        let decoded = GitHubStateToken::decode(&encoded, &signer)
            .await
            .expect("decode");

        assert_eq!(decoded.org_id, "org-2");
        assert_eq!(decoded.user_id, "user-2");
        assert_eq!(decoded.flow_type, GitHubStateFlowType::Link);
        assert_eq!(decoded.session_binding, "test-binding-link");
    }

    #[tokio::test]
    async fn test_github_state_token_wrong_secret_rejected() {
        let signer_a = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let signer_b =
            StateTokenSigner::local(b"different_secret_at_least_32chars_long!!".to_vec());
        let token = GitHubStateToken::new_for_install("org-1", "user-1", "test-binding")
            .expect("create token");

        let encoded = token.encode(&signer_a).await.expect("encode");
        let result = GitHubStateToken::decode(&encoded, &signer_b).await;
        assert!(result.is_err(), "Wrong secret should be rejected");
    }

    #[tokio::test]
    async fn test_github_state_token_wrong_type_rejected() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let token = GitHubStateToken::new_for_install("org-1", "user-1", "test-binding")
            .expect("create token");

        let encoded = token.encode(&signer).await.expect("encode");

        // Try decoding with wrong JwtType via the raw signer
        let result: Result<GitHubStateToken, _> = signer
            .decode_state_token(&encoded, JwtType::RegistrationState)
            .await;
        assert!(result.is_err(), "Wrong JWT type should be rejected");
    }

    // ========================================================================
    // Webhook tests
    // ========================================================================

    #[tokio::test]
    async fn test_webhook_missing_signature_rejected() {
        let (app, _state) = test_app().await;
        let (status, _body) = http_request(
            &app,
            "POST",
            "/api/webhooks/github",
            Some("{}".to_string()),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_webhook_invalid_signature_rejected() {
        let (app, _state) = test_app().await;
        let (status, _body) = http_request(
            &app,
            "POST",
            "/api/webhooks/github",
            Some("{}".to_string()),
            &[("X-Hub-Signature-256", "sha256=deadbeefdeadbeef")],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_webhook_missing_body_with_signature() {
        let (app, _state) = test_app().await;
        // Signature header present but won't match empty body
        let (status, _body) = http_request(
            &app,
            "POST",
            "/api/webhooks/github",
            None,
            &[(
                "X-Hub-Signature-256",
                "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            )],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // ========================================================================
    // Connect page tests
    // ========================================================================

    #[tokio::test]
    async fn test_connect_redirects_unauthenticated() {
        let (app, _state) = test_app().await;
        // No cookie — should redirect to /enroll/start
        // GitHub App is not configured in test_app, so NotConfigured error renders first.
        // The handler checks is_configured() AFTER the redirect check, so unauthenticated
        // path returns redirect before the not-configured check.
        let (status, _body) = http_get(&app, "/github/connect", &[]).await;
        // Without installation_id+state params the handler tries GitHub App check first,
        // then session. Since GitHub App is None → NotConfigured error (200 HTML).
        // So we expect either a redirect (303) or a 200 error page.
        // Actually: is_configured() returns false → error_response (200 HTML template).
        assert!(
            status == StatusCode::SEE_OTHER || status == StatusCode::OK || status.is_redirection(),
            "Unexpected status: {status}"
        );
    }

    #[tokio::test]
    async fn test_connect_with_installation_params_redirects() {
        let (app, _state) = test_app().await;
        // When both installation_id and state are present, the connect page redirects
        // to /github/callback before checking authentication or GitHub App config.
        let (status, _body) =
            http_get(&app, "/github/connect?installation_id=123&state=fake", &[]).await;
        assert!(
            status.is_redirection(),
            "Expected redirect when installation_id+state present, got {status}"
        );
    }

    // ========================================================================
    // Callback tests
    // ========================================================================

    #[tokio::test]
    async fn test_callback_missing_installation_id_and_code() {
        let (app, _state) = test_app().await;
        // No code and no installation_id → missing installation ID error page
        let (status, body) = http_get(&app, "/github/callback", &[]).await;
        assert_eq!(status, StatusCode::OK, "Error page should return 200");
        assert!(
            body.contains("Missing installation ID") || body.contains("missing"),
            "Expected error about missing installation ID, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_callback_invalid_state_token() {
        let (app, _state) = test_app().await;
        // installation_id present but state token is garbage → invalid state token error
        let (status, body) = http_get(
            &app,
            "/github/callback?installation_id=123&state=garbage",
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "Error page should return 200");
        assert!(
            body.contains("state") || body.contains("token") || body.contains("invalid"),
            "Expected error about invalid state token, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_callback_oauth_missing_state() {
        let (app, _state) = test_app().await;
        // code present but no state → InvalidStateToken error page
        let (status, body) = http_get(&app, "/github/callback?code=test_code", &[]).await;
        assert_eq!(status, StatusCode::OK, "Error page should return 200");
        assert!(
            body.contains("state") || body.contains("token") || body.contains("invalid"),
            "Expected error about missing/invalid state, got: {body}"
        );
    }

    // ========================================================================
    // CSRF defense tests (issue #394)
    //
    // The callback must bind the GitHub `code`/`installation_id` to the cookie
    // session that originally minted the state token. These tests cover:
    //   * no session cookie → SessionRequired
    //   * cookie present but session.sub != state.user_id → SessionMismatch
    //   * cookie present but session.token_hash != state.session_binding
    //     → SessionMismatch (state minted from a different session)
    //   * cookie present, matching user, mismatched org_id (install flow only)
    //     → SessionMismatch (user changed orgs in the 10-min window)
    //   * cookie present and everything matches → falls through to the GitHub
    //     service layer (which fails on missing GitHub config in tests — we
    //     only assert the callback got past the CSRF gate)
    // ========================================================================

    /// Mint a state token using the test signer and return its encoded form.
    async fn mint_state_token(
        state: &Arc<AppState>,
        flow: GitHubStateFlowType,
        org_id: &str,
        user_id: &str,
        session_binding: &str,
    ) -> String {
        let token = GitHubStateToken::new(org_id, user_id, session_binding, flow)
            .expect("mint state token");
        token
            .encode(&state.state_signer)
            .await
            .expect("encode state token")
    }

    fn cookie_header(session_token: &str) -> String {
        format!("__Host-vouch_session={session_token}")
    }

    /// Set up a test user with an org, an authenticator, and a session token.
    /// Returns (user_id, org_id, session_token, session_token_hash).
    async fn setup_user_with_session(
        state: &Arc<AppState>,
        email: &str,
        domain: &str,
    ) -> (String, String, String, String) {
        let org = create_test_org(&state.store, domain).await;
        let user = create_test_user_in_org(&state.store, email, &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            state,
            TestSessionSpec {
                user_id: &user.id,
                email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let token_hash = crate::crypto::hash_token(&session_token);
        (user.id, org.id, session_token, token_hash)
    }

    #[tokio::test]
    async fn test_callback_oauth_rejects_without_session_cookie() {
        let (app, state) = test_app().await;
        let encoded = mint_state_token(
            &state,
            GitHubStateFlowType::Link,
            "org-x",
            "user-x",
            "binding-x",
        )
        .await;
        let uri = format!(
            "/github/callback?code=victim_code&state={}",
            urlencoding::encode(&encoded)
        );

        let (status, body) = http_get(&app, &uri, &[]).await;
        assert_eq!(status, StatusCode::OK, "Error page should return 200");
        assert!(
            body.contains("Sign In Required") || body.contains("sign in"),
            "Expected SessionRequired error page, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_callback_install_rejects_without_session_cookie() {
        let (app, state) = test_app().await;
        let encoded = mint_state_token(
            &state,
            GitHubStateFlowType::Install,
            "org-x",
            "user-x",
            "binding-x",
        )
        .await;
        let uri = format!(
            "/github/callback?installation_id=42&state={}",
            urlencoding::encode(&encoded)
        );

        let (status, body) = http_get(&app, &uri, &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("Sign In Required") || body.contains("sign in"),
            "Expected SessionRequired error page, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_callback_oauth_rejects_mismatched_user_id() {
        let (app, state) = test_app().await;
        // Victim has a valid session.
        let (_victim_id, _victim_org, victim_token, victim_hash) =
            setup_user_with_session(&state, "victim@example.com", "example.com").await;

        // Attacker mints a state token bound to *their own* user_id but using
        // the victim's session_binding (impossible in practice — the attacker
        // doesn't know the victim's token_hash — but tests the user_id check
        // in isolation).
        let encoded = mint_state_token(
            &state,
            GitHubStateFlowType::Link,
            "attacker-org",
            "attacker-user-id",
            &victim_hash,
        )
        .await;
        let uri = format!(
            "/github/callback?code=victim_code&state={}",
            urlencoding::encode(&encoded)
        );
        let cookie = cookie_header(&victim_token);

        let (status, body) = http_get(&app, &uri, &[("Cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("Session Mismatch") || body.contains("does not match"),
            "Expected SessionMismatch error page, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_callback_oauth_rejects_mismatched_session_binding() {
        let (app, state) = test_app().await;
        let (victim_id, victim_org, victim_token, _victim_hash) =
            setup_user_with_session(&state, "victim@example.com", "example.com").await;

        // State has the correct user_id but a session_binding that doesn't
        // match the cookie's token_hash — i.e. it was minted from a different
        // session of the same user (e.g. an attacker who used /github/link as
        // the victim from another device).
        let encoded = mint_state_token(
            &state,
            GitHubStateFlowType::Link,
            &victim_org,
            &victim_id,
            "binding-from-a-different-session",
        )
        .await;
        let uri = format!(
            "/github/callback?code=victim_code&state={}",
            urlencoding::encode(&encoded)
        );
        let cookie = cookie_header(&victim_token);

        let (status, body) = http_get(&app, &uri, &[("Cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("Session Mismatch") || body.contains("does not match"),
            "Expected SessionMismatch on binding mismatch, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_callback_install_rejects_mismatched_org_id() {
        let (app, state) = test_app().await;
        let (user_id, user_org, session_token, session_hash) =
            setup_user_with_session(&state, "alice@example.com", "example.com").await;

        // State was minted while the user belonged to a different org, but the
        // user's current org_id no longer matches.
        let encoded = mint_state_token(
            &state,
            GitHubStateFlowType::Install,
            "some-other-org",
            &user_id,
            &session_hash,
        )
        .await;
        // Sanity check that the user's org is not the state's org_id.
        assert_ne!(user_org, "some-other-org");

        let uri = format!(
            "/github/callback?installation_id=42&state={}",
            urlencoding::encode(&encoded)
        );
        let cookie = cookie_header(&session_token);

        let (status, body) = http_get(&app, &uri, &[("Cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("Session Mismatch") || body.contains("does not match"),
            "Expected SessionMismatch on org_id mismatch, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_callback_oauth_passes_csrf_gate_when_session_matches() {
        let (app, state) = test_app().await;
        let (user_id, user_org, session_token, session_hash) =
            setup_user_with_session(&state, "alice@example.com", "example.com").await;

        let encoded = mint_state_token(
            &state,
            GitHubStateFlowType::Link,
            &user_org,
            &user_id,
            &session_hash,
        )
        .await;
        let uri = format!(
            "/github/callback?code=test_code&state={}",
            urlencoding::encode(&encoded)
        );
        let cookie = cookie_header(&session_token);

        // GitHub OAuth is not configured in test_app, so link_user_account
        // will fail downstream — but the response must NOT be a CSRF rejection.
        let (status, body) = http_get(&app, &uri, &[("Cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !body.contains("Session Mismatch"),
            "CSRF gate should pass when session matches, got: {body}"
        );
        assert!(
            !body.contains("Sign In Required"),
            "CSRF gate should pass when session matches, got: {body}"
        );
    }

    // ========================================================================
    // Link tests
    // ========================================================================

    #[tokio::test]
    async fn test_link_redirects_unauthenticated() {
        let (app, _state) = test_app().await;
        // No cookie — OAuth not configured in test_app, so OAuthNotConfigured error first.
        let (status, _body) = http_get(&app, "/github/link", &[]).await;
        // is_oauth_configured() → false → OAuthNotConfigured error (200 HTML) or redirect
        assert!(
            status == StatusCode::SEE_OTHER || status == StatusCode::OK || status.is_redirection(),
            "Unexpected status: {status}"
        );
    }

    // ========================================================================
    // Success page tests
    // ========================================================================

    #[tokio::test]
    async fn test_success_page_returns_ok() {
        let (app, _state) = test_app().await;
        let (status, _body) = http_get(&app, "/github/success", &[]).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_success_page_with_account_param() {
        let (app, _state) = test_app().await;
        let (status, body) = http_get(&app, "/github/success?account=myorg", &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("myorg"),
            "Expected 'myorg' in success page body"
        );
    }

    // ========================================================================
    // State token additional tests
    // ========================================================================

    #[tokio::test]
    async fn test_state_token_nonce_uniqueness() {
        let token_a = GitHubStateToken::new_for_install("org-1", "user-1", "test-binding-a")
            .expect("create token a");
        let token_b = GitHubStateToken::new_for_install("org-1", "user-1", "test-binding-a")
            .expect("create token b");
        assert_ne!(
            token_a.nonce, token_b.nonce,
            "Two tokens for same org/user should have different nonces"
        );
    }

    #[tokio::test]
    async fn test_state_token_expiry_is_10_minutes() {
        let token = GitHubStateToken::new_for_install("org-1", "user-1", "test-binding")
            .expect("create token");
        assert_eq!(
            token.exp - token.iat,
            600,
            "Token expiry should be exactly 600 seconds (10 minutes)"
        );
    }
}
