// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub OAuth user account linking.
//!
//! This module handles linking a Vouch user's account to their GitHub identity:
//! - Exchange OAuth authorization code for tokens
//! - Fetch GitHub user info
//! - Store GitHub identity and refresh token
//! - Refresh access tokens using stored refresh tokens

use secrecy::{ExposeSecret, SecretString};

use super::{
    GitHubError, GitHubResult, GitHubService, exchange_oauth_code, get_github_user,
    refresh_oauth_token,
};
use crate::db;

// ============================================================================
// Account Linking Types
// ============================================================================

/// Parameters for linking a GitHub account.
pub(crate) struct LinkAccountParams<'a> {
    /// The OAuth authorization code from GitHub.
    pub code: &'a str,
    /// The user ID to link the GitHub account to.
    pub user_id: &'a str,
}

// ============================================================================
// OAuth Implementation
// ============================================================================

impl GitHubService<'_> {
    /// Link a user's Vouch account to their GitHub identity.
    ///
    /// This exchanges the OAuth authorization code for tokens, fetches the
    /// GitHub user info, and stores the identity and refresh token.
    pub(crate) async fn link_user_account(
        &self,
        params: LinkAccountParams<'_>,
    ) -> GitHubResult<()> {
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
        let github_user = get_github_user(
            app.http_client(),
            token_response.access_token.expose_secret(),
        )
        .await
        .map_err(|e| GitHubError::GitHubApi(format!("{e:#}")))?;

        // Update user's GitHub identity
        db::update_user_github_identity(
            self.store,
            params.user_id,
            github_user.id.cast_signed(),
            &github_user.login,
            token_response
                .refresh_token
                .as_ref()
                .map(|s| s.expose_secret()),
        )
        .await
        .map_err(GitHubError::Database)?;

        tracing::info!(
            "User {} linked GitHub account: {}",
            params.user_id,
            github_user.login
        );

        Ok(())
    }

    /// Get a fresh GitHub access token for a user using their stored refresh token.
    ///
    /// Returns `Ok(None)` if the user doesn't have a stored refresh token, the
    /// user document is gone, or a concurrent re-link to a different GitHub
    /// account committed during the refresh round-trip (in which case the
    /// rotated token would belong to the pre-relink account and is
    /// discarded to avoid overwriting the re-link's refresh token — the
    /// caller then signals the same recovery the missing-token branch
    /// already routes to).
    /// Returns an error if the refresh fails.
    pub(crate) async fn get_user_access_token(
        &self,
        user_id: &str,
    ) -> GitHubResult<Option<SecretString>> {
        // Read the GitHub identity (id + refresh token) from a single doc
        // snapshot. The conditional write below compares the stored link
        // against this snapshot, so both fields must describe one moment.
        let Some(linked) = db::get_user_github_link(self.store, user_id)
            .await
            .map_err(GitHubError::Database)?
        else {
            return Ok(None);
        };
        let Some(refresh_token) = linked.github_refresh_token.as_ref() else {
            return Ok(None);
        };

        let app = self.require_app()?;
        let client_id = self.oauth_client_id()?;
        let client_secret = self.oauth_client_secret()?;

        // Refresh the token. RACE WINDOW: a re-link, a revocation, or
        // another refresh can commit during this round-trip.
        let token_response = refresh_oauth_token(
            app.http_client(),
            client_id,
            client_secret,
            refresh_token.expose_secret(),
        )
        .await
        .map_err(|e| GitHubError::GitHubApi(format!("{e:#}")))?;

        // Persist the rotated refresh token. GitHub rotates refresh tokens:
        // the old token is invalidated by the refresh above, so losing the
        // new one here would permanently break the integration (the "next
        // refresh" would present the already-invalidated token). Propagate
        // failures so they surface instead of silently discarding the only
        // copy of the new token.
        if let Some(new_refresh_token) = &token_response.refresh_token {
            // Write only the refresh token, and only when the stored link is
            // still the one refreshed above — see
            // `update_user_github_refresh_token`.
            let outcome = db::update_user_github_refresh_token(
                self.store,
                user_id,
                new_refresh_token.expose_secret(),
                &linked,
            )
            .await
            .map_err(GitHubError::Database)?;
            if outcome == db::RefreshOutcome::SkippedLinkChanged {
                // The link changed during the round-trip: re-linked, revoked,
                // or rotated by another refresh. There is no usable access
                // token for the doc's current state; route recovery the same
                // way the missing-refresh-token branch does.
                return Ok(None);
            }
        }

        Ok(Some(token_response.access_token))
    }

    /// Build the GitHub OAuth authorization URL for account linking.
    ///
    /// # Arguments
    /// * `state` - The encoded state token for CSRF protection
    pub(crate) fn build_oauth_url(&self, state: &str) -> GitHubResult<String> {
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

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::test_utils;
    use secrecy::SecretString;

    #[tokio::test]
    async fn build_oauth_url_includes_client_id_redirect_and_state() {
        let state = test_utils::test_app_state().await;
        let mut config = (**state.config()).clone();
        config.github_app_client_id = Some("github-client-id".to_string());
        config.github_app_client_secret =
            crate::config::NonEmptySecret::new(SecretString::from("shh"));

        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );
        let url = service
            .build_oauth_url("opaque-csrf-state")
            .expect("build url");

        // The URL starts with the authorize endpoint and contains the encoded
        // client_id, redirect_uri (with port-less https origin), and state.
        assert!(
            url.starts_with("https://github.com/login/oauth/authorize?"),
            "unexpected prefix: {url}"
        );
        assert!(url.contains("client_id=github-client-id"), "url: {url}");
        // The configured base_url is https://test.example.com (no special chars in
        // path), so the only encoded characters come from `://`.
        assert!(
            url.contains("redirect_uri=https%3A%2F%2Ftest.example.com%2Fgithub%2Fcallback"),
            "redirect uri encoding wrong: {url}"
        );
        assert!(url.contains("state=opaque-csrf-state"), "url: {url}");
    }

    #[tokio::test]
    async fn build_oauth_url_urlencodes_state_special_characters() {
        let state = test_utils::test_app_state().await;
        let mut config = (**state.config()).clone();
        config.github_app_client_id = Some("github-client-id".to_string());
        config.github_app_client_secret =
            crate::config::NonEmptySecret::new(SecretString::from("shh"));

        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );
        let url = service
            .build_oauth_url("state with =& special / chars")
            .expect("build url");
        assert!(
            !url.contains("state with =& special / chars"),
            "raw state must not appear unencoded: {url}"
        );
        assert!(
            url.contains("state%20with%20%3D%26%20special%20%2F%20chars"),
            "state must be url-encoded: {url}"
        );
    }

    #[tokio::test]
    async fn build_oauth_url_errors_when_client_id_missing() {
        let state = test_utils::test_app_state().await;
        let config = (**state.config()).clone(); // client_id is None
        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );

        match service.build_oauth_url("state") {
            Err(GitHubError::OAuthNotConfigured) => {}
            other => panic!("expected OAuthNotConfigured, got {other:?}"),
        }
    }
}
