// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub App installation management.
//!
//! This module handles:
//! - Connecting new GitHub App installations to organizations
//! - Reconnecting existing installations
//! - Fetching user-accessible installations
//! - Installation access verification

use std::collections::{HashMap, HashSet};

use super::{
    GitHubError, GitHubInstallationId, GitHubResult, GitHubService,
    list_user_accessible_installations,
};
use crate::db::{self, GitHubCredentialAuditData, User};

// ============================================================================
// Installation Connection Types
// ============================================================================

/// Parameters for connecting a new GitHub installation.
pub(crate) struct ConnectInstallationParams<'a> {
    /// The GitHub installation ID.
    pub installation_id: u64,
    /// The organization ID to connect to.
    pub org_id: &'a str,
    /// The user performing the connection.
    pub user: &'a User,
}

/// Parameters for reconnecting an existing GitHub installation.
pub(crate) struct ReconnectInstallationParams<'a> {
    /// The GitHub installation ID to reconnect.
    pub installation_id: u64,
    /// The organization ID to connect to.
    pub org_id: &'a str,
    /// The user performing the reconnection.
    pub user: &'a User,
}

/// Result of a successful installation connection.
pub(crate) struct InstallationConnectResult {
    /// The GitHub account login (org/user name).
    pub account_login: String,
}

/// An unlinked installation that can be reconnected.
pub(crate) struct UnlinkedInstallation {
    /// Installation ID.
    pub id: u64,
    /// GitHub account login.
    pub account_login: String,
    /// Account type (Organization or User).
    pub account_type: String,
}

// ============================================================================
// Installation Management Implementation
// ============================================================================

impl GitHubService<'_> {
    /// Connect a new GitHub App installation to an organization.
    ///
    /// This is called after the user installs the GitHub App and is redirected
    /// back with an installation ID.
    pub(crate) async fn connect_installation(
        &self,
        params: ConnectInstallationParams<'_>,
    ) -> GitHubResult<InstallationConnectResult> {
        let app = self.require_app()?;

        // Fetch installation details from GitHub
        let details = app
            .get_installation_details(GitHubInstallationId(params.installation_id))
            .await
            .map_err(|e| GitHubError::GitHubApi(e.to_string()))?;

        // Store installation in database
        db::create_github_installation(
            self.store,
            params.org_id,
            params.installation_id.cast_signed(),
            &details.account.login,
            &details.account.account_type,
            &details.permissions,
            &details.repository_selection,
            Some(&params.user.id),
        )
        .await
        .map_err(GitHubError::Database)?;

        tracing::info!(
            "GitHub installation connected: {} -> org {}",
            details.account.login,
            params.org_id
        );

        // Log audit event
        self.log_installation_event(
            "installation_connected",
            params.user,
            params.org_id,
            params.installation_id,
            Some(&details.permissions),
        )
        .await;

        Ok(InstallationConnectResult {
            account_login: details.account.login,
        })
    }

    /// Reconnect an existing GitHub installation to an organization.
    ///
    /// This allows an org admin to link an existing GitHub installation (that they
    /// have access to via their OAuth token) to their Vouch organization.
    pub(crate) async fn reconnect_installation(
        &self,
        params: ReconnectInstallationParams<'_>,
    ) -> GitHubResult<InstallationConnectResult> {
        let app = self.require_app()?;

        // Verify user has linked their GitHub account
        if params.user.github_login.is_none() {
            return Err(GitHubError::GitHubAccountNotLinked);
        }

        // Get fresh access token
        let access_token = self
            .get_user_access_token(&params.user.id)
            .await?
            .ok_or_else(|| {
                GitHubError::Internal(
                    "Failed to get access token - please re-link your GitHub account".to_string(),
                )
            })?;

        // Verify user actually has access to this installation
        let user_installations =
            list_user_accessible_installations(app.http_client(), &access_token)
                .await
                .map_err(|e| GitHubError::GitHubApi(e.to_string()))?;

        let user_installation = user_installations
            .iter()
            .find(|i| i.id == params.installation_id)
            .ok_or(GitHubError::InstallationAccessDenied)?;

        // Verify installation is not already linked
        if db::get_github_installation_by_installation_id(
            self.store,
            params.installation_id.cast_signed(),
        )
        .await
        .map_err(GitHubError::Database)?
        .is_some()
        {
            return Err(GitHubError::InstallationAlreadyConnected);
        }

        // Fetch full installation details from GitHub App API
        let details = app
            .get_installation_details(GitHubInstallationId(params.installation_id))
            .await
            .map_err(|e| GitHubError::GitHubApi(e.to_string()))?;

        // Store installation in database
        db::create_github_installation(
            self.store,
            params.org_id,
            params.installation_id.cast_signed(),
            &user_installation.account.login,
            &user_installation.account.account_type,
            &details.permissions,
            &details.repository_selection,
            Some(&params.user.id),
        )
        .await
        .map_err(GitHubError::Database)?;

        tracing::info!(
            "GitHub installation reconnected: {} -> org {} by user {}",
            user_installation.account.login,
            params.org_id,
            params.user.id
        );

        // Log audit event
        self.log_installation_event(
            "installation_reconnected",
            params.user,
            params.org_id,
            params.installation_id,
            Some(&details.permissions),
        )
        .await;

        Ok(InstallationConnectResult {
            account_login: user_installation.account.login.clone(),
        })
    }

    /// Get installations that the user can access but are not yet linked to any org.
    ///
    /// Returns an empty list if the user hasn't linked their GitHub account or
    /// if OAuth is not configured.
    pub(crate) async fn get_unlinked_installations(
        &self,
        user: &User,
    ) -> GitHubResult<Vec<UnlinkedInstallation>> {
        // Check if user has linked GitHub account and OAuth is configured
        if user.github_login.is_none() || !self.is_oauth_configured() {
            return Ok(vec![]);
        }

        // Try to get fresh access token
        let access_token = match self.get_user_access_token(&user.id).await {
            Ok(Some(token)) => token,
            Ok(None) => {
                tracing::debug!("No refresh token available for user");
                return Ok(vec![]);
            }
            Err(e) => {
                tracing::warn!("Failed to get access token: {}", e);
                return Ok(vec![]);
            }
        };

        let app = self.require_app()?;

        // Get all linked installation IDs
        let linked_ids: HashSet<i64> = db::get_all_linked_installation_ids(self.store)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();

        // Fetch installations the user can access
        let installations =
            match list_user_accessible_installations(app.http_client(), &access_token).await {
                Ok(installations) => installations,
                Err(e) => {
                    tracing::warn!("Failed to fetch user installations: {}", e);
                    return Ok(vec![]);
                }
            };

        // Filter to unlinked installations only
        let unlinked = installations
            .into_iter()
            .filter(|i| !linked_ids.contains(&i.id.cast_signed()))
            .map(|i| UnlinkedInstallation {
                id: i.id,
                account_login: i.account.login,
                account_type: i.account.account_type,
            })
            .collect();

        Ok(unlinked)
    }

    /// Get connected installations for an organization.
    pub(crate) async fn get_org_installations(&self, org_id: &str) -> GitHubResult<Vec<String>> {
        let installations = db::get_github_installations_by_org(self.store, org_id)
            .await
            .map_err(GitHubError::Database)?;

        Ok(installations
            .into_iter()
            .map(|i| i.github_account_login)
            .collect())
    }

    /// Build the GitHub App installation URL.
    ///
    /// # Arguments
    /// * `state` - The encoded state token for CSRF protection
    pub(crate) fn build_installation_url(&self, state: &str) -> GitHubResult<String> {
        let app_name = self.app_name()?;

        Ok(format!(
            "https://github.com/apps/{}/installations/new?state={}",
            urlencoding::encode(app_name),
            urlencoding::encode(state)
        ))
    }

    /// Log an installation audit event.
    async fn log_installation_event(
        &self,
        event_type: &str,
        user: &User,
        org_id: &str,
        installation_id: u64,
        permissions: Option<&HashMap<String, String>>,
    ) {
        if let Err(e) = db::log_github_credential_event(
            self.audit,
            &user.id,
            &user.email,
            GitHubCredentialAuditData {
                event_type: event_type.to_string(),
                org_id: Some(org_id.to_string()),
                installation_id: Some(installation_id.cast_signed()),
                permissions: permissions.cloned(),
                success: true,
                ..Default::default()
            },
            None,
        )
        .await
        {
            tracing::warn!("Failed to log GitHub credential event: {e}");
        }
    }
}

/// Validate that a user can manage GitHub installations for an organization.
///
/// Returns the organization ID if valid, or an error if not.
pub(crate) fn validate_org_admin(user: &User) -> GitHubResult<&str> {
    match &user.org_id {
        Some(org_id) if user.is_org_admin => Ok(org_id),
        Some(_) => Err(GitHubError::NotOrgAdmin),
        None => Err(GitHubError::OrganizationRequired),
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

    fn user_with(org_id: Option<&str>, is_admin: bool) -> User {
        User {
            id: "user-1".to_string(),
            email: "u@example.com".to_string(),
            name: None,
            org_id: org_id.map(String::from),
            is_org_admin: is_admin,
            active: true,
            external_id: None,
            github_id: None,
            github_login: None,
            github_refresh_token: None,
        }
    }

    // -----------------------------------------------------------------
    // validate_org_admin
    // -----------------------------------------------------------------

    #[test]
    fn validate_org_admin_accepts_admin_with_org() {
        let user = user_with(Some("org-123"), true);
        let id = validate_org_admin(&user).expect("admin must be allowed");
        assert_eq!(id, "org-123");
    }

    #[test]
    fn validate_org_admin_rejects_non_admin() {
        let user = user_with(Some("org-123"), false);
        match validate_org_admin(&user) {
            Err(GitHubError::NotOrgAdmin) => {}
            other => panic!("expected NotOrgAdmin, got {other:?}"),
        }
    }

    #[test]
    fn validate_org_admin_rejects_no_org() {
        let user = user_with(None, true);
        match validate_org_admin(&user) {
            Err(GitHubError::OrganizationRequired) => {}
            other => panic!("expected OrganizationRequired, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // GitHubService::build_installation_url
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn build_installation_url_renders_app_name_and_state() {
        let state = test_utils::test_app_state().await;
        let mut config = (**state.config()).clone();
        config.github_app_name = Some("acme-vouch".to_string());

        let service =
            GitHubService::new(&state.store, &state.audit, &config, state.github_app.as_ref());
        let url = service
            .build_installation_url("opaque-state-token")
            .expect("build url");
        assert_eq!(
            url,
            "https://github.com/apps/acme-vouch/installations/new?state=opaque-state-token"
        );
    }

    #[tokio::test]
    async fn build_installation_url_urlencodes_special_characters() {
        let state = test_utils::test_app_state().await;
        let mut config = (**state.config()).clone();
        // App slug with a space (unusual but worth covering — `urlencoding::encode`
        // turns it into `%20`).
        config.github_app_name = Some("acme vouch".to_string());

        let service =
            GitHubService::new(&state.store, &state.audit, &config, state.github_app.as_ref());
        let url = service
            .build_installation_url("state with spaces & symbols")
            .expect("build url");
        assert!(url.contains("acme%20vouch"), "app name must be url-encoded: {url}");
        assert!(
            url.contains("state%20with%20spaces%20%26%20symbols"),
            "state must be url-encoded: {url}"
        );
    }

    #[tokio::test]
    async fn build_installation_url_errors_when_app_name_missing() {
        let state = test_utils::test_app_state().await;
        let config = (**state.config()).clone(); // github_app_name is None by default
        let service =
            GitHubService::new(&state.store, &state.audit, &config, state.github_app.as_ref());

        match service.build_installation_url("state") {
            Err(GitHubError::Internal(msg)) => {
                assert!(msg.contains("App name"), "unexpected message: {msg}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // GitHubService::get_org_installations
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn get_org_installations_returns_empty_when_none_linked() {
        let state = test_utils::test_app_state().await;
        let org = crate::db::create_organization(&state.store, "empty.example", Some("Empty"), None)
            .await
            .expect("create org");
        let config = (**state.config()).clone();

        let service =
            GitHubService::new(&state.store, &state.audit, &config, state.github_app.as_ref());
        let logins = service
            .get_org_installations(&org.id)
            .await
            .expect("get installations");
        assert!(logins.is_empty());
    }

    #[tokio::test]
    async fn get_org_installations_returns_linked_logins() {
        let state = test_utils::test_app_state().await;
        let org = crate::db::create_organization(&state.store, "linked.example", Some("Linked"), None)
            .await
            .expect("create org");
        let perms = HashMap::from([("contents".to_string(), "read".to_string())]);
        crate::db::create_github_installation(
            &state.store,
            &org.id,
            42,
            "the-org",
            "Organization",
            &perms,
            "all",
            None,
        )
        .await
        .expect("create installation");
        let config = (**state.config()).clone();

        let service =
            GitHubService::new(&state.store, &state.audit, &config, state.github_app.as_ref());
        let logins = service
            .get_org_installations(&org.id)
            .await
            .expect("get installations");
        assert_eq!(logins, vec!["the-org".to_string()]);
    }
}
