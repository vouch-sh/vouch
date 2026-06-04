// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub App integration service.
//!
//! This module provides business logic for GitHub App integration:
//!
//! - [`app`] - Low-level GitHub API client (JWT auth, token exchange)
//! - [`webhooks`] - Webhook event handling (installation lifecycle)
//! - [`oauth`] - User OAuth account linking
//! - [`installations`] - Installation management (connect, reconnect)
//!
//! # Architecture
//!
//! The [`GitHubService`] orchestrates all GitHub operations, providing a clean
//! interface for HTTP handlers. Handlers remain thin, focusing on HTTP concerns
//! (extraction, cookies, templates), while this service handles business logic.
//!
//! ```text
//! HTTP Handler (handlers/github.rs)
//!     │
//!     ▼
//! ┌─────────────────────────────────┐
//! │        GitHubService            │  ← Business logic orchestration
//! │  - verify_webhook_signature()   │
//! │  - handle_webhook_event()       │
//! │  - link_user_account()          │
//! │  - connect_installation()       │
//! │  - reconnect_installation()     │
//! └─────────────────────────────────┘
//!     │
//!     ├─► app.rs (GitHub API calls)
//!     ├─► db::github (persistence)
//!     └─► db::users (user updates)
//! ```

pub(crate) mod app;
pub(crate) mod installations;
pub(crate) mod oauth;
pub(crate) mod webhooks;

use std::sync::Arc;

use crate::config::ServerConfig;
use crate::db::audit::AuditStore;
use crate::db::store::DocumentStore;

// Re-export commonly used types
pub(crate) use app::{
    GitHubApp, GitHubInstallationId, GitHubUser, exchange_oauth_code, get_github_user,
    list_user_accessible_installations, minimal_git_permissions, refresh_oauth_token,
};
pub(crate) use installations::{ConnectInstallationParams, ReconnectInstallationParams};
pub(crate) use oauth::LinkAccountParams;

/// Error types for GitHub service operations.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GitHubError {
    /// GitHub App not configured on this server.
    #[error("GitHub integration is not configured on this server")]
    NotConfigured,

    /// GitHub OAuth not configured (missing client_id or client_secret).
    #[error("GitHub OAuth is not configured on this server")]
    OAuthNotConfigured,

    /// Webhook secret not configured.
    #[error("GitHub webhook secret not configured")]
    WebhookSecretNotConfigured,

    /// Invalid webhook signature.
    #[error("Invalid webhook signature")]
    InvalidSignature,

    /// Invalid or expired state token.
    #[error("Invalid or expired state token")]
    InvalidStateToken,

    /// State token flow type mismatch.
    #[error("State token is for a different flow type")]
    WrongFlowType,

    /// Callback received without an authenticated session cookie.
    #[error("Please sign in before completing the GitHub connection")]
    SessionRequired,

    /// Authenticated session does not match the user/org bound to the state token.
    #[error("This GitHub callback does not match your current session")]
    SessionMismatch,

    /// User not found.
    #[error("User not found")]
    UserNotFound,

    /// Organization required (personal account not supported).
    #[error("GitHub integration requires an organization account")]
    OrganizationRequired,

    /// User is not an organization administrator.
    #[error("Only organization administrators can perform this action")]
    NotOrgAdmin,

    /// User has not linked their GitHub account.
    #[error("Please link your GitHub account first")]
    GitHubAccountNotLinked,

    /// User does not have access to the requested installation.
    #[error("You do not have access to this GitHub installation")]
    InstallationAccessDenied,

    /// Installation already connected to an organization.
    #[error("This GitHub installation is already connected to an organization")]
    InstallationAlreadyConnected,

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),

    /// GitHub API error.
    #[error("GitHub API error: {0}")]
    GitHubApi(String),

    /// Internal error (encoding, etc.).
    #[error("Internal error: {0}")]
    Internal(String),
}

impl GitHubError {
    /// Get a user-friendly error title for display.
    #[must_use]
    pub(crate) fn title(&self) -> &'static str {
        match self {
            Self::NotConfigured => "Not Available",
            Self::OAuthNotConfigured => "Not Available",
            Self::WebhookSecretNotConfigured => "Configuration Error",
            Self::InvalidSignature => "Unauthorized",
            Self::InvalidStateToken => "Invalid State",
            Self::WrongFlowType => "Invalid Flow",
            Self::SessionRequired => "Sign In Required",
            Self::SessionMismatch => "Session Mismatch",
            Self::UserNotFound => "Error",
            Self::OrganizationRequired => "Organization Required",
            Self::NotOrgAdmin => "Admin Required",
            Self::GitHubAccountNotLinked => "GitHub Account Required",
            Self::InstallationAccessDenied => "Access Denied",
            Self::InstallationAlreadyConnected => "Already Connected",
            Self::Database(_) => "Error",
            Self::GitHubApi(_) => "GitHub Error",
            Self::Internal(_) => "Error",
        }
    }
}

/// Result type for GitHub service operations.
pub(crate) type GitHubResult<T> = Result<T, GitHubError>;

/// GitHub integration service.
///
/// Provides business logic for all GitHub operations. This is the main entry
/// point for handlers to interact with GitHub functionality.
pub(crate) struct GitHubService<'a> {
    /// Document store for CRUD operations.
    pub store: &'a DocumentStore,
    /// Audit store for audit event operations.
    pub audit: &'a AuditStore,
    /// Server configuration.
    pub config: &'a ServerConfig,
    /// GitHub App client (if configured).
    pub github_app: Option<&'a Arc<GitHubApp>>,
}

impl<'a> GitHubService<'a> {
    /// Create a new GitHub service instance.
    #[must_use]
    pub(crate) fn new(
        store: &'a DocumentStore,
        audit: &'a AuditStore,
        config: &'a ServerConfig,
        github_app: Option<&'a Arc<GitHubApp>>,
    ) -> Self {
        Self {
            store,
            audit,
            config,
            github_app,
        }
    }

    /// Check if GitHub App is configured.
    #[must_use]
    pub(crate) fn is_configured(&self) -> bool {
        self.github_app.is_some()
    }

    /// Check if GitHub OAuth is configured.
    #[must_use]
    pub(crate) fn is_oauth_configured(&self) -> bool {
        self.config.github_oauth_configured()
    }

    /// Get the GitHub App, returning an error if not configured.
    pub(crate) fn require_app(&self) -> GitHubResult<&Arc<GitHubApp>> {
        self.github_app.ok_or(GitHubError::NotConfigured)
    }

    /// Get the GitHub App name for building installation URLs.
    pub(crate) fn app_name(&self) -> GitHubResult<&str> {
        self.config
            .github_app_name
            .as_deref()
            .ok_or_else(|| GitHubError::Internal("GitHub App name not configured".to_string()))
    }

    /// Get OAuth client ID.
    pub(crate) fn oauth_client_id(&self) -> GitHubResult<&str> {
        self.config
            .github_app_client_id
            .as_deref()
            .ok_or(GitHubError::OAuthNotConfigured)
    }

    /// Get OAuth client secret.
    pub(crate) fn oauth_client_secret(&self) -> GitHubResult<&str> {
        self.config
            .github_app_client_secret_exposed()
            .ok_or(GitHubError::OAuthNotConfigured)
    }

    /// Get webhook secret.
    pub(crate) fn webhook_secret(&self) -> GitHubResult<&str> {
        self.config
            .github_webhook_secret_exposed()
            .ok_or(GitHubError::WebhookSecretNotConfigured)
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::test_utils;
    use secrecy::SecretString;

    #[tokio::test]
    async fn is_configured_reflects_app_presence() {
        let state = test_utils::test_app_state().await;
        let config = (**state.config()).clone();
        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );
        assert!(!service.is_configured());
        assert!(matches!(
            service.require_app(),
            Err(GitHubError::NotConfigured)
        ));
    }

    #[tokio::test]
    async fn is_oauth_configured_requires_both_id_and_secret() {
        let state = test_utils::test_app_state().await;
        let config = (**state.config()).clone();
        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );
        assert!(!service.is_oauth_configured());
        assert!(matches!(
            service.oauth_client_id(),
            Err(GitHubError::OAuthNotConfigured)
        ));
        assert!(matches!(
            service.oauth_client_secret(),
            Err(GitHubError::OAuthNotConfigured)
        ));
    }

    #[tokio::test]
    async fn oauth_helpers_return_configured_values() {
        let state = test_utils::test_app_state().await;
        let mut config = (**state.config()).clone();
        config.github_app_client_id = Some("client-xyz".to_string());
        config.github_app_client_secret = Some(SecretString::from("secret-xyz".to_string()));

        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );
        assert!(service.is_oauth_configured());
        assert_eq!(service.oauth_client_id().expect("client_id"), "client-xyz");
        assert_eq!(
            service.oauth_client_secret().expect("client_secret"),
            "secret-xyz"
        );
    }

    #[tokio::test]
    async fn webhook_secret_helper_paths() {
        let state = test_utils::test_app_state().await;
        let config = (**state.config()).clone();
        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );
        assert!(matches!(
            service.webhook_secret(),
            Err(GitHubError::WebhookSecretNotConfigured)
        ));

        let mut config_with_secret = (**state.config()).clone();
        config_with_secret.github_webhook_secret =
            Some(SecretString::from("wh-secret".to_string()));
        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config_with_secret,
            state.github_app.as_ref(),
        );
        assert_eq!(service.webhook_secret().expect("secret"), "wh-secret");
    }

    #[tokio::test]
    async fn app_name_helper_paths() {
        let state = test_utils::test_app_state().await;
        let config = (**state.config()).clone();
        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );
        assert!(matches!(service.app_name(), Err(GitHubError::Internal(_))));

        let mut config_with_name = (**state.config()).clone();
        config_with_name.github_app_name = Some("acme".to_string());
        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config_with_name,
            state.github_app.as_ref(),
        );
        assert_eq!(service.app_name().expect("app name"), "acme");
    }

    #[test]
    fn github_error_titles_are_stable() {
        // Smoke-test a couple of branches so the title() match arms get exercised.
        assert_eq!(GitHubError::NotConfigured.title(), "Not Available");
        assert_eq!(GitHubError::NotOrgAdmin.title(), "Admin Required");
        assert_eq!(
            GitHubError::InstallationAccessDenied.title(),
            "Access Denied"
        );
        assert_eq!(
            GitHubError::InstallationAlreadyConnected.title(),
            "Already Connected"
        );
    }
}
