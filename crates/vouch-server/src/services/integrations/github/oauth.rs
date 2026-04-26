// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub OAuth user account linking.
//!
//! This module handles linking a Vouch user's account to their GitHub identity:
//! - Exchange OAuth authorization code for tokens
//! - Fetch GitHub user info
//! - Store GitHub identity and refresh token
//! - Refresh access tokens using stored refresh tokens

use super::{
    GitHubError, GitHubResult, GitHubService, GitHubUser, exchange_oauth_code, get_github_user,
    refresh_oauth_token,
};
use crate::db;

// ============================================================================
// Account Linking Types
// ============================================================================

/// Parameters for linking a GitHub account.
pub struct LinkAccountParams<'a> {
    /// The OAuth authorization code from GitHub.
    pub code: &'a str,
    /// The user ID to link the GitHub account to.
    pub user_id: &'a str,
}

/// Result of successfully linking a GitHub account.
pub struct LinkAccountResult {
    /// The linked GitHub user info.
    pub github_user: GitHubUser,
}

// ============================================================================
// OAuth Implementation
// ============================================================================

impl GitHubService<'_> {
    /// Link a user's Vouch account to their GitHub identity.
    ///
    /// This exchanges the OAuth authorization code for tokens, fetches the
    /// GitHub user info, and stores the identity and refresh token.
    pub async fn link_user_account(
        &self,
        params: LinkAccountParams<'_>,
    ) -> GitHubResult<LinkAccountResult> {
        let app = self.require_app()?;
        let client_id = self.oauth_client_id()?;
        let client_secret = self.oauth_client_secret()?;

        // Exchange code for tokens (RFC 6749 §4.1.3: redirect_uri MUST match authorization request)
        let redirect_uri = format!("{}/github/callback", self.config.base_url);
        let token_response = exchange_oauth_code(
            app.http_client(),
            client_id,
            client_secret,
            params.code,
            &redirect_uri,
        )
        .await
        .map_err(|e| GitHubError::GitHubApi(format!("{e:#}")))?;

        // Get GitHub user info
        let github_user = get_github_user(app.http_client(), &token_response.access_token)
            .await
            .map_err(|e| GitHubError::GitHubApi(format!("{e:#}")))?;

        // Update user's GitHub identity
        db::update_user_github_identity(
            self.store,
            params.user_id,
            github_user.id.cast_signed(),
            &github_user.login,
            token_response.refresh_token.as_deref(),
        )
        .await
        .map_err(GitHubError::Database)?;

        tracing::info!(
            "User {} linked GitHub account: {}",
            params.user_id,
            github_user.login
        );

        Ok(LinkAccountResult { github_user })
    }

    /// Get a fresh GitHub access token for a user using their stored refresh token.
    ///
    /// Returns `Ok(None)` if the user doesn't have a stored refresh token.
    /// Returns an error if the refresh fails.
    pub async fn get_user_access_token(&self, user_id: &str) -> GitHubResult<Option<String>> {
        // Get the user's refresh token
        let refresh_token = match db::get_user_github_refresh_token(self.store, user_id)
            .await
            .map_err(GitHubError::Database)?
        {
            Some(token) => token,
            None => return Ok(None),
        };

        let app = self.require_app()?;
        let client_id = self.oauth_client_id()?;
        let client_secret = self.oauth_client_secret()?;

        // Refresh the token
        let token_response =
            refresh_oauth_token(app.http_client(), client_id, client_secret, &refresh_token)
                .await
                .map_err(|e| GitHubError::GitHubApi(format!("{e:#}")))?;

        // Update the refresh token if a new one was issued
        if let Some(new_refresh_token) = &token_response.refresh_token
            && let Ok(Some(user)) = db::get_user_by_id(self.store, user_id).await
            && let (Some(github_id), Some(github_login)) = (user.github_id, &user.github_login)
        {
            // Best-effort refresh-token rotation; user session stays valid even if
            // this DB write fails — the next refresh will retry.
            let _updated = db::update_user_github_identity(
                self.store,
                user_id,
                github_id,
                github_login,
                Some(new_refresh_token),
            )
            .await;
        }

        Ok(Some(token_response.access_token))
    }

    /// Build the GitHub OAuth authorization URL for account linking.
    ///
    /// # Arguments
    /// * `state` - The encoded state token for CSRF protection
    pub fn build_oauth_url(&self, state: &str) -> GitHubResult<String> {
        let client_id = self.oauth_client_id()?;
        let redirect_uri = format!("{}/github/callback", self.config.base_url);

        Ok(format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}",
            urlencoding::encode(client_id),
            urlencoding::encode(&redirect_uri),
            urlencoding::encode(state)
        ))
    }
}
