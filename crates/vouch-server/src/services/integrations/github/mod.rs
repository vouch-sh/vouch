// SPDX-License-Identifier: BUSL-1.1
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

pub mod app;
pub mod installations;
pub mod oauth;
pub mod webhooks;

use std::sync::Arc;

use crate::config::ServerConfig;
use crate::db::Pool;

// Re-export commonly used types
pub use app::{
    GitHubApp, GitHubAppId, GitHubInstallationId, GitHubInstallationToken,
    GitHubOAuthTokenResponse, GitHubRepository, GitHubUser, InstallationAccount,
    InstallationDetails, RsaPrivateKeyDer, exchange_oauth_code, get_github_user,
    list_user_accessible_installations, minimal_git_permissions, refresh_oauth_token,
};
pub use installations::{ConnectInstallationParams, ReconnectInstallationParams};
pub use oauth::{LinkAccountParams, LinkAccountResult};
pub use webhooks::{WebhookEvent, WebhookResult};

/// Error types for GitHub service operations.
#[derive(Debug, thiserror::Error)]
pub enum GitHubError {
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
    pub fn title(&self) -> &'static str {
        match self {
            Self::NotConfigured => "Not Available",
            Self::OAuthNotConfigured => "Not Available",
            Self::WebhookSecretNotConfigured => "Configuration Error",
            Self::InvalidSignature => "Unauthorized",
            Self::InvalidStateToken => "Invalid State",
            Self::WrongFlowType => "Invalid Flow",
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
pub type GitHubResult<T> = Result<T, GitHubError>;

/// GitHub integration service.
///
/// Provides business logic for all GitHub operations. This is the main entry
/// point for handlers to interact with GitHub functionality.
pub struct GitHubService<'a> {
    /// Database pool.
    pub db: &'a Pool,
    /// Server configuration.
    pub config: &'a ServerConfig,
    /// GitHub App client (if configured).
    pub github_app: Option<&'a Arc<GitHubApp>>,
}

impl<'a> GitHubService<'a> {
    /// Create a new GitHub service instance.
    #[must_use]
    pub fn new(
        db: &'a Pool,
        config: &'a ServerConfig,
        github_app: Option<&'a Arc<GitHubApp>>,
    ) -> Self {
        Self {
            db,
            config,
            github_app,
        }
    }

    /// Check if GitHub App is configured.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.github_app.is_some()
    }

    /// Check if GitHub OAuth is configured.
    #[must_use]
    pub fn is_oauth_configured(&self) -> bool {
        self.config.github_oauth_configured()
    }

    /// Get the GitHub App, returning an error if not configured.
    pub fn require_app(&self) -> GitHubResult<&Arc<GitHubApp>> {
        self.github_app.ok_or(GitHubError::NotConfigured)
    }

    /// Get the GitHub App name for building installation URLs.
    pub fn app_name(&self) -> GitHubResult<&str> {
        self.config
            .github_app_name
            .as_deref()
            .ok_or_else(|| GitHubError::Internal("GitHub App name not configured".to_string()))
    }

    /// Get OAuth client ID.
    pub fn oauth_client_id(&self) -> GitHubResult<&str> {
        self.config
            .github_app_client_id
            .as_deref()
            .ok_or(GitHubError::OAuthNotConfigured)
    }

    /// Get OAuth client secret.
    pub fn oauth_client_secret(&self) -> GitHubResult<&str> {
        self.config
            .github_app_client_secret_exposed()
            .ok_or(GitHubError::OAuthNotConfigured)
    }

    /// Get webhook secret.
    pub fn webhook_secret(&self) -> GitHubResult<&str> {
        self.config
            .github_webhook_secret_exposed()
            .ok_or(GitHubError::WebhookSecretNotConfigured)
    }
}
