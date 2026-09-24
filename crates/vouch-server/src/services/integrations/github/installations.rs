// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub App installation management.
//!
//! This module handles:
//! - Connecting new GitHub App installations to organizations
//! - Reconnecting existing installations
//! - Fetching user-accessible installations
//! - Installation access verification

use std::collections::{HashMap, HashSet};

use secrecy::ExposeSecret;

use super::{
    GitHubError, GitHubInstallationId, GitHubResult, GitHubService,
    list_user_accessible_installations,
};
use crate::db::{self, User};

// ============================================================================
// Installation Connection Types
// ============================================================================

/// How an installation reached the link step, recorded as the audit event.
#[derive(Clone, Copy, Debug)]
pub(crate) enum InstallationLinkFlow {
    /// GitHub redirected the admin back after they installed the App.
    Install,
    /// The admin picked an installation their GitHub account can already see.
    Reconnect,
}

impl InstallationLinkFlow {
    fn event_type(self) -> &'static str {
        match self {
            Self::Install => "installation_connected",
            Self::Reconnect => "installation_reconnected",
        }
    }
}

/// Parameters for linking a GitHub installation to an organization.
pub(crate) struct LinkInstallationParams<'a> {
    /// The GitHub installation ID, as supplied by the browser.
    pub installation_id: u64,
    /// The organization ID to link to.
    pub org_id: &'a str,
    /// The org admin performing the link.
    pub user: &'a User,
    /// Which flow the request came from.
    pub flow: InstallationLinkFlow,
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
    /// Fetch and store the installation's repository list.
    ///
    /// The `installation.created` webhook carries this list, but it races the
    /// OAuth callback that creates the installation row: when the webhook wins,
    /// `update_github_installation_repos` finds no row, returns `Ok(false)`, and
    /// the list is lost — later webhooks only carry deltas, so nothing restores
    /// it. Fetching here makes the stored list independent of which arrives
    /// first.
    ///
    /// Only meaningful for `repository_selection == "selected"`; an all-repos
    /// installation is represented by a stored `None`.
    ///
    /// Failures are logged, not propagated: the installation itself is already
    /// connected, and a later `installation_repositories` webhook can still fill
    /// the list in.
    async fn store_installation_repositories(
        &self,
        app: &crate::services::integrations::github::GitHubApp,
        installation_id: u64,
        repository_selection: &str,
    ) {
        if repository_selection != "selected" {
            return;
        }

        // Network call, deliberately outside any DB retry closure.
        let repos = match app
            .list_installation_repositories(GitHubInstallationId(installation_id))
            .await
        {
            Ok(repos) => repos,
            Err(e) => {
                tracing::warn!(
                    installation_id,
                    error = %e,
                    "Failed to list installation repositories; repo list left unset"
                );
                return;
            }
        };

        match db::update_github_installation_repos(
            self.store,
            installation_id.cast_signed(),
            &repos,
        )
        .await
        {
            Ok(true) => {
                tracing::info!(
                    installation_id,
                    count = repos.len(),
                    "Stored selected repositories for installation"
                );
            }
            Ok(false) => {
                tracing::warn!(
                    installation_id,
                    "Installation row missing when storing repositories"
                );
            }
            Err(e) => {
                tracing::warn!(
                    installation_id,
                    error = %e,
                    "Failed to store installation repositories"
                );
            }
        }
    }

    /// Link a GitHub App installation to an organization.
    ///
    /// The installation ID comes from the browser, and the App JWT can read
    /// every installation of the App, so the App's view proves nothing about
    /// the caller. The link requires the caller's own GitHub account to see
    /// the installation in `GET /user/installations`.
    pub(crate) async fn link_installation(
        &self,
        params: LinkInstallationParams<'_>,
    ) -> GitHubResult<InstallationConnectResult> {
        let app = self.require_app()?;

        if params.user.github_login.is_none() {
            return Err(GitHubError::GitHubAccountNotLinked);
        }

        let access_token = self
            .get_user_access_token(&params.user.id)
            .await?
            .ok_or_else(|| {
                GitHubError::Internal(
                    "Failed to get access token - please re-link your GitHub account".to_string(),
                )
            })?;

        let user_installations =
            list_user_accessible_installations(app.http_client(), access_token.expose_secret())
                .await
                .map_err(|e| GitHubError::GitHubApi(e.to_string()))?;
        if !user_installations
            .iter()
            .any(|i| i.id == params.installation_id)
        {
            return Err(GitHubError::InstallationAccessDenied);
        }

        // Already-linked guard. Rows written before installation IDs became
        // deterministic carry random document IDs, so a replayed callback for
        // one of them would not collide on insert; the index lookup catches
        // those, and skips the details round trip for every replay.
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

        let details = app
            .get_installation_details(GitHubInstallationId(params.installation_id))
            .await
            .map_err(|e| GitHubError::GitHubApi(e.to_string()))?;

        // The guard above is a fast path; a replayed callback or two
        // concurrent links that pass it collide on the deterministic document
        // ID and surface as `Duplicate`, which maps to
        // `InstallationAlreadyConnected` — race-safe, no duplicate row.
        db::create_github_installation(
            self.store,
            &db::CreateGitHubInstallationParams {
                org_id: params.org_id,
                installation_id: params.installation_id.cast_signed(),
                github_account_login: &details.account.login,
                github_account_type: &details.account.account_type,
                permissions: &details.permissions,
                repository_selection: &details.repository_selection,
                installed_by_user_id: Some(&params.user.id),
            },
        )
        .await
        .map_err(|e| match e {
            db::CreateGitHubInstallationError::Duplicate => {
                GitHubError::InstallationAlreadyConnected
            }
            db::CreateGitHubInstallationError::Other(err) => GitHubError::Database(err),
        })?;

        self.store_installation_repositories(
            app,
            params.installation_id,
            &details.repository_selection,
        )
        .await;

        tracing::info!(
            flow = ?params.flow,
            "GitHub installation linked: {} -> org {} by user {}",
            details.account.login,
            params.org_id,
            params.user.id
        );

        self.log_installation_event(
            params.flow.event_type(),
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
        let installations = match list_user_accessible_installations(
            app.http_client(),
            access_token.expose_secret(),
        )
        .await
        {
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
        self.audit
            .log_credential_event(
                &user.id,
                &user.email,
                db::CredentialAuditEnvelope {
                    event_type: event_type.to_string(),
                    org_id: Some(org_id.to_string()),
                    success: true,
                    ..Default::default()
                },
                &db::GitHubCredentialDetails {
                    installation_id: Some(installation_id.cast_signed()),
                    permissions: permissions.cloned(),
                    ..Default::default()
                },
            )
            .await;
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
            org_domain: None,
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

        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );
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

        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );
        let url = service
            .build_installation_url("state with spaces & symbols")
            .expect("build url");
        assert!(
            url.contains("acme%20vouch"),
            "app name must be url-encoded: {url}"
        );
        assert!(
            url.contains("state%20with%20spaces%20%26%20symbols"),
            "state must be url-encoded: {url}"
        );
    }

    #[tokio::test]
    async fn build_installation_url_errors_when_app_name_missing() {
        let state = test_utils::test_app_state().await;
        let config = (**state.config()).clone(); // github_app_name is None by default
        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );

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
        let org =
            crate::db::create_organization(&state.store, "empty.example", Some("Empty"), None)
                .await
                .expect("create org");
        let config = (**state.config()).clone();

        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );
        let logins = service
            .get_org_installations(&org.id)
            .await
            .expect("get installations");
        assert!(logins.is_empty());
    }

    #[tokio::test]
    async fn get_org_installations_returns_linked_logins() {
        let state = test_utils::test_app_state().await;
        let org =
            crate::db::create_organization(&state.store, "linked.example", Some("Linked"), None)
                .await
                .expect("create org");
        let perms = HashMap::from([("contents".to_string(), "read".to_string())]);
        crate::db::create_github_installation(
            &state.store,
            &crate::db::CreateGitHubInstallationParams {
                org_id: &org.id,
                installation_id: 42,
                github_account_login: "the-org",
                github_account_type: "Organization",
                permissions: &perms,
                repository_selection: "all",
                installed_by_user_id: None,
            },
        )
        .await
        .expect("create installation");
        let config = (**state.config()).clone();

        let service = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );
        let logins = service
            .get_org_installations(&org.id)
            .await
            .expect("get installations");
        assert_eq!(logins, vec!["the-org".to_string()]);
    }

    /// Installation details as `GET /app/installations/{id}` and
    /// `GET /user/installations` report them.
    fn installation_json(id: u64, login: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "account": { "login": login, "id": 1234, "type": "Organization" },
            "repository_selection": "all",
            "permissions": { "contents": "read", "metadata": "read" },
            "created_at": "2025-01-01T00:00:00Z",
            "suspended_at": null,
        })
    }

    /// Answer the three calls a link makes: the user-token refresh, the
    /// user's installation list (`visible`), and App-JWT installation details
    /// (any ID, owned by `login`).
    fn github_route(line: &str, visible: &[u64], login: &str) -> (u16, serde_json::Value) {
        if line.starts_with("POST /login/oauth/access_token ") {
            return (
                200,
                serde_json::json!({
                    "access_token": "ghu_test",
                    "token_type": "bearer",
                    "refresh_token": "ghr_rotated",
                }),
            );
        }
        if line.starts_with("GET /user/installations?") {
            let installations: Vec<_> = visible
                .iter()
                .map(|id| installation_json(*id, login))
                .collect();
            return (
                200,
                serde_json::json!({
                    "total_count": installations.len(),
                    "installations": installations,
                }),
            );
        }
        let details_id = line
            .strip_prefix("GET /app/installations/")
            .and_then(|rest| rest.split(' ').next())
            .and_then(|id| id.parse::<u64>().ok());
        match details_id {
            Some(id) => (200, installation_json(id, login)),
            None => (404, serde_json::json!({ "message": "Not Found" })),
        }
    }

    /// An org admin whose linked GitHub account holds a refresh token.
    async fn linked_admin(store: &db::store::DocumentStore, domain: &str) -> (String, User) {
        let org = test_utils::create_test_org(store, domain).await;
        let user =
            test_utils::create_test_user_in_org(store, &format!("admin@{domain}"), &org.id, true)
                .await;
        db::update_user_github_identity(store, &user.id, 77, "octo-admin", Some("ghr_initial"))
            .await
            .expect("link GitHub account");
        let user = db::get_user_by_id(store, &user.id)
            .await
            .expect("read user")
            .expect("user exists");
        (org.id, user)
    }

    fn link_params<'a>(
        installation_id: u64,
        org_id: &'a str,
        user: &'a User,
    ) -> LinkInstallationParams<'a> {
        LinkInstallationParams {
            installation_id,
            org_id,
            user,
            flow: InstallationLinkFlow::Install,
        }
    }

    #[tokio::test]
    async fn link_installation_refuses_installation_user_cannot_see() {
        // The installation ID comes from the browser and the App JWT reads
        // every installation of the App, so only the user's own installation
        // list shows they may link it.
        let mock =
            test_utils::GitHubMock::spawn(
                |line| async move { github_route(&line, &[1], "victim-org") },
            )
            .await;
        let state = test_utils::test_app_state_with_github_app(mock.client()).await;
        let config = state.config();
        let (org_id, admin) = linked_admin(&state.store, "attacker.example").await;
        let svc = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );

        let result = svc
            .link_installation(link_params(999, &org_id, &admin))
            .await;

        assert!(
            matches!(result, Err(GitHubError::InstallationAccessDenied)),
            "expected InstallationAccessDenied, got {:?}",
            result.map(|r| r.account_login)
        );
        assert!(
            db::get_github_installation_by_installation_id(&state.store, 999)
                .await
                .expect("lookup")
                .is_none(),
            "no row may be written"
        );
        assert!(
            mock.requests()
                .iter()
                .any(|l| l.starts_with("GET /user/installations?")),
            "the user's installation list must be consulted: {:?}",
            mock.requests()
        );
    }

    #[tokio::test]
    async fn link_installation_links_installation_user_can_see() {
        let mock =
            test_utils::GitHubMock::spawn(
                |line| async move { github_route(&line, &[999], "own-org") },
            )
            .await;
        let state = test_utils::test_app_state_with_github_app(mock.client()).await;
        let config = state.config();
        let (org_id, admin) = linked_admin(&state.store, "owner.example").await;
        let svc = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );

        let result = svc
            .link_installation(link_params(999, &org_id, &admin))
            .await
            .expect("link succeeds");

        assert_eq!(result.account_login, "own-org");
        let row = db::get_github_installation_by_installation_id(&state.store, 999)
            .await
            .expect("lookup")
            .expect("row written");
        assert_eq!(row.org_id, org_id);
        assert_eq!(row.github_account_login, "own-org");
    }

    #[tokio::test]
    async fn link_installation_requires_linked_github_account() {
        let mock =
            test_utils::GitHubMock::spawn(
                |line| async move { github_route(&line, &[999], "own-org") },
            )
            .await;
        let state = test_utils::test_app_state_with_github_app(mock.client()).await;
        let config = state.config();
        let org = test_utils::create_test_org(&state.store, "unlinked.example").await;
        let admin = test_utils::create_test_user_in_org(
            &state.store,
            "admin@unlinked.example",
            &org.id,
            true,
        )
        .await;
        let svc = GitHubService::new(
            &state.store,
            &state.audit,
            &config,
            state.github_app.as_ref(),
        );

        let result = svc
            .link_installation(link_params(999, &org.id, &admin))
            .await;

        assert!(
            matches!(result, Err(GitHubError::GitHubAccountNotLinked)),
            "expected GitHubAccountNotLinked, got {:?}",
            result.map(|r| r.account_login)
        );
        assert!(mock.requests().is_empty(), "no GitHub call without a link");
    }

    #[tokio::test]
    async fn link_installation_records_flow_as_audit_event() {
        for (flow, event_type) in [
            (InstallationLinkFlow::Install, "installation_connected"),
            (InstallationLinkFlow::Reconnect, "installation_reconnected"),
        ] {
            let mock = test_utils::GitHubMock::spawn(|line| async move {
                github_route(&line, &[5], "own-org")
            })
            .await;
            let state = test_utils::test_app_state_with_github_app(mock.client()).await;
            let config = state.config();
            let (org_id, admin) = linked_admin(&state.store, "audit.example").await;
            let svc = GitHubService::new(
                &state.store,
                &state.audit,
                &config,
                state.github_app.as_ref(),
            );

            svc.link_installation(LinkInstallationParams {
                installation_id: 5,
                org_id: &org_id,
                user: &admin,
                flow,
            })
            .await
            .expect("link succeeds");

            let events = state
                .audit
                .query_events(&db::AuditEventFilter {
                    user_id: Some(admin.id.clone()),
                    ..Default::default()
                })
                .await
                .expect("audit events");
            let subtypes: Vec<String> = events
                .iter()
                .filter_map(|e| serde_json::from_str::<serde_json::Value>(&e.data).ok())
                .filter_map(|d| d.get("event_type")?.as_str().map(str::to_string))
                .collect();
            assert_eq!(subtypes, vec![event_type.to_string()], "{flow:?}");
        }
    }

    #[tokio::test]
    async fn cross_org_concurrent_link_installation_produces_single_owner() {
        // Two orgs race `link_installation` for installation_id=42. The mock
        // holds both `get_installation_details` calls at a `Barrier(2)`, so
        // both callers pass the already-linked guard before either inserts.
        // The `installation_id`-only document ID collides: one `Ok`, one
        // `InstallationAlreadyConnected`, exactly one row globally.
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mock = test_utils::GitHubMock::spawn(move |line| {
            let barrier = barrier.clone();
            async move {
                if line.starts_with("GET /app/installations/") {
                    barrier.wait().await;
                }
                github_route(&line, &[42], "shared-acct")
            }
        })
        .await;

        let state = test_utils::test_app_state_with_github_app(mock.client()).await;
        let config = state.config();

        let (org_a_id, user_a) = linked_admin(&state.store, "gh-xorg-a.example").await;
        let (org_b_id, user_b) = linked_admin(&state.store, "gh-xorg-b.example").await;

        let store_a = state.store.clone();
        let store_b = state.store.clone();
        let audit_a = state.audit.clone();
        let audit_b = state.audit.clone();
        let config_a = (**config).clone();
        let config_b = (**config).clone();
        let app_a = state.github_app.clone();
        let app_b = state.github_app.clone();
        let org_a = org_a_id.clone();
        let org_b = org_b_id.clone();

        let h_a = tokio::spawn(async move {
            let svc = GitHubService::new(&store_a, &audit_a, &config_a, app_a.as_ref());
            svc.link_installation(link_params(42, &org_a, &user_a))
                .await
        });
        let h_b = tokio::spawn(async move {
            let svc = GitHubService::new(&store_b, &audit_b, &config_b, app_b.as_ref());
            svc.link_installation(link_params(42, &org_b, &user_b))
                .await
        });

        let r_a = h_a.await.expect("join a");
        let r_b = h_b.await.expect("join b");

        // Exactly one wins; the other is `InstallationAlreadyConnected`.
        let (ok_count, already_count, other_err) = match (&r_a, &r_b) {
            (Ok(_), Err(GitHubError::InstallationAlreadyConnected)) => (1, 1, None),
            (Err(GitHubError::InstallationAlreadyConnected), Ok(_)) => (1, 1, None),
            (Ok(_), Ok(_)) => (2, 0, None),
            (Err(e1), Err(e2)) => (0, 0, Some(format!("both failed: {e1} | {e2}"))),
            (Ok(_), Err(e)) => (
                1,
                0,
                Some(format!(
                    "unexpected non-InstallationAlreadyConnected err: {e}"
                )),
            ),
            (Err(e), Ok(_)) => (
                0,
                1,
                Some(format!(
                    "unexpected non-InstallationAlreadyConnected err: {e}"
                )),
            ),
        };
        assert!(
            other_err.is_none(),
            "unexpected error(s) from link_installation: {other_err:?}"
        );
        assert_eq!(ok_count, 1, "exactly one link must win, got {ok_count} ok");
        assert_eq!(
            already_count, 1,
            "exactly one must be InstallationAlreadyConnected, got {already_count}"
        );

        // Exactly one row exists globally for installation_id 42.
        let by_id = db::get_github_installation_by_installation_id(&state.store, 42)
            .await
            .expect("global lookup")
            .expect("single row present");
        assert_eq!(by_id.installation_id, 42);

        let listed_a = db::get_github_installations_by_org(&state.store, &org_a_id)
            .await
            .expect("get by org a");
        let listed_b = db::get_github_installations_by_org(&state.store, &org_b_id)
            .await
            .expect("get by org b");
        let total = listed_a.len() + listed_b.len();
        assert_eq!(total, 1, "exactly one row globally, got {total}");
        assert!(
            (listed_a.len() == 1) ^ (listed_b.len() == 1),
            "exactly one org owns the row"
        );

        // `get_all_linked_installation_ids` sees the single installation_id once.
        let mut all_ids = db::get_all_linked_installation_ids(&state.store)
            .await
            .expect("list linked");
        all_ids.retain(|id| *id == 42);
        assert_eq!(
            all_ids,
            vec![42],
            "the dead ID must not be hidden/duplicated"
        );
    }
}
