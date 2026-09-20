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

    /// Connect a new GitHub App installation to an organization.
    ///
    /// This is called after the user installs the GitHub App and is redirected
    /// back with an installation ID.
    pub(crate) async fn connect_installation(
        &self,
        params: ConnectInstallationParams<'_>,
    ) -> GitHubResult<InstallationConnectResult> {
        let app = self.require_app()?;

        // Already-linked guard. Rows written before installation IDs became
        // deterministic carry random document IDs, so a replayed callback for
        // one of them would not collide on insert; the index lookup catches
        // those, and skips the GitHub API round trip for every replay.
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

        // Fetch installation details from GitHub
        let details = app
            .get_installation_details(GitHubInstallationId(params.installation_id))
            .await
            .map_err(|e| GitHubError::GitHubApi(e.to_string()))?;

        // Store installation in database. The guard above is a fast path; a
        // replayed callback or two concurrent connects that pass it collide on
        // the deterministic document ID and surface as `Duplicate`, which maps
        // to `InstallationAlreadyConnected` — race-safe, no duplicate row.
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
            list_user_accessible_installations(app.http_client(), access_token.expose_secret())
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

        // Store installation in database. The already-linked guard above is a
        // fast path; a concurrent reconnect that passes the guard and our own
        // insert collide on the deterministic document ID and surface as
        // `Duplicate`, which we map to `InstallationAlreadyConnected` — closing
        // the guard's TOCTOU window race-free.
        db::create_github_installation(
            self.store,
            &db::CreateGitHubInstallationParams {
                org_id: params.org_id,
                installation_id: params.installation_id.cast_signed(),
                github_account_login: &user_installation.account.login,
                github_account_type: &user_installation.account.account_type,
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
    clippy::indexing_slicing,
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

    // -----------------------------------------------------------------
    // End-to-end service-path cross-org concurrent connect_installation.
    //
    // Reproduces the bug's exact shape: two orgs race `connect_installation`
    // for the same `installation_id`. The in-process TLS mock holds both
    // `get_installation_details` calls at a `Barrier(2)` so both callers are
    // past the global guard and concurrently between guard and insert. Before
    // the fix, the `(org_id, installation_id)`-scoped deterministic ID let both
    // inserts win; after the fix the `installation_id`-only ID collides and
    // the losing call surfaces `InstallationAlreadyConnected`.
    // -----------------------------------------------------------------

    /// Self-signed P-256 cert (SAN: localhost) + PKCS#8 key for the in-process
    /// TLS mock. Throwaway, mirrors `handlers::credentials::tests`.
    const CROSS_ORG_MOCK_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBoDCCAUagAwIBAgIUPOBIDoD8Akv9FXfEjb8GEV6GYLowCgYIKoZIzj0EAwIw\n\
HDEaMBgGA1UEAwwRdm91Y2gtcHEtdGxzLXRlc3QwHhcNMjYwNzA5MTEzMDE1WhcN\n\
MzYwNzA2MTEzMDE1WjAcMRowGAYDVQQDDBF2b3VjaC1wcS10bHMtdGVzdDBZMBMG\n\
ByqGSM49AgEGCCqGSM49AwEHA0IABO7wN7GBAX4FydRe2AvENBb6WZ9XHh4NKbkO\n\
G9ulpEIAVoZaGHMAlK7ZGTLf/tBukQxhXDwQKLLot23POsF8nP+jZjBkMB0GA1Ud\n\
DgQWBBQ3svXuWL2wS8xcHilgxDuYURTVwDAfBgNVHSMEGDAWgBQ3svXuWL2wS8xc\n\
HilgxDuYURTVwDAUBgNVHREEDTALgglsb2NhbGhvc3QwDAYDVR0TAQH/BAIwADAK\n\
BggqhkjOPQQDAgNIADBFAiEAqVgc77k203H6G5gEaAcHuna5DKJmQPCQjQLQAtry\n\
KnMCICKcoY9vNlshsz2y7RVcfGqowba3/xXj3aYFegT/BdAW\n\
-----END CERTIFICATE-----\n";
    const CROSS_ORG_MOCK_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTljx1Qv2H2TQMKaX\n\
+palx1XsuLkORqDCzFBkRDcz3tihRANCAATu8DexgQF+BcnUXtgLxDQW+lmfVx4e\n\
DSm5DhvbpaRCAFaGWhhzAJSu2Rky3/7QbpEMYVw8ECiy6LdtzzrBfJz/\n\
-----END PRIVATE KEY-----\n";

    /// `Content-Length` of an HTTP/1.1 request header block, or 0 if absent.
    fn cross_org_content_length_of(headers: &[u8]) -> usize {
        let Ok(s) = std::str::from_utf8(headers) else {
            return 0;
        };
        for line in s.split("\r\n") {
            if let Some((k, v)) = line.split_once(':')
                && k.eq_ignore_ascii_case("content-length")
            {
                return v.trim().parse().unwrap_or(0);
            }
        }
        0
    }

    /// Accept `n` TLS connections, then spawn `n` handlers that each read the
    /// request and wait at a shared `Barrier(n)` before writing the canned
    /// `GET /app/installations/{id}` response. This forces all
    /// `get_installation_details` callers to be pending concurrently — i.e.
    /// past the global guard, between guard and insert — deterministically
    /// opening the TOCTOU window without timers.
    async fn serve_installation_details_barrier(
        listener: tokio::net::TcpListener,
        barrier: std::sync::Arc<tokio::sync::Barrier>,
        n: usize,
    ) {
        use rustls::pki_types::pem::PemObject;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(CROSS_ORG_MOCK_CERT_PEM.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("parse mock cert");
        let key =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(CROSS_ORG_MOCK_KEY_PEM.as_bytes())
                .expect("parse mock key");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("mock server config");
        let acceptor = std::sync::Arc::new(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
            server_config,
        )));

        let body = serde_json::json!({
            "id": 42,
            "account": { "login": "shared-acct", "id": 1234, "type": "Organization" },
            "repository_selection": "all",
            "permissions": { "contents": "read", "metadata": "read" },
            "created_at": "2025-01-01T00:00:00Z",
            "suspended_at": null,
        });
        let body_bytes =
            std::sync::Arc::new(serde_json::to_vec(&body).expect("serialize mock body"));

        // Accept all connections first, then spawn per-connection handlers so
        // all of them can wait at the barrier concurrently.
        let mut streams = Vec::with_capacity(n);
        for _ in 0..n {
            let (stream, _) = listener.accept().await.expect("mock accept");
            let tls = acceptor.accept(stream).await.expect("mock tls accept");
            streams.push(tls);
        }

        let mut tasks = Vec::with_capacity(n);
        for mut tls in streams {
            let barrier = barrier.clone();
            let body_bytes = body_bytes.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::with_capacity(8192);
                let mut tmp = [0u8; 4096];
                loop {
                    let nread = tls.read(&mut tmp).await.expect("mock read");
                    if nread == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..nread]);
                    if let Some(hend) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let body_start = hend.saturating_add(4);
                        let content_length = cross_org_content_length_of(&buf[..hend]);
                        if buf.len() >= body_start.saturating_add(content_length) {
                            break;
                        }
                    }
                    if buf.len() > 64 * 1024 {
                        break;
                    }
                }

                // Hold all callers here until every connection has drained its
                // request — both `get_installation_details` futures are pending
                // concurrently, meaning both `connect_installation` callers have
                // passed the global guard.
                barrier.wait().await;

                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body_bytes.len()
                );
                tls.write_all(head.as_bytes())
                    .await
                    .expect("mock write head");
                tls.write_all(&body_bytes).await.expect("mock write body");
                drop(tls.shutdown().await);
            }));
        }
        for t in tasks {
            t.await.expect("mock task join");
        }
    }

    #[tokio::test]
    async fn cross_org_concurrent_connect_installation_produces_single_owner() {
        // Two orgs race `connect_installation` for installation_id=42 through
        // the production service path. The TLS mock barriers both
        // `get_installation_details` calls so both callers pass the global
        // guard before either inserts. Before the deterministic-ID fix, the
        // `(org_id, installation_id)` scoping let both inserts win (two rows,
        // one orphaned from webhook cleanup). After the fix, the
        // `installation_id`-only ID collides: one `Ok`, one
        // `InstallationAlreadyConnected`, exactly one row globally.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock listener");
        let mock_addr = listener.local_addr().expect("mock addr");
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let barrier_clone = barrier.clone();
        tokio::spawn(serve_installation_details_barrier(
            listener,
            barrier_clone,
            2,
        ));

        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .resolve("api.github.com", mock_addr)
            .build()
            .expect("build mock http client");

        let state = test_utils::test_app_state_with_github_app(http_client).await;
        let config = state.config();

        let org_a = test_utils::create_test_org(&state.store, "gh-xorg-a.example").await;
        let org_b = test_utils::create_test_org(&state.store, "gh-xorg-b.example").await;
        let user_a = test_utils::create_test_user_in_org(
            &state.store,
            "admin-a@gh-xorg-a.example",
            &org_a.id,
            true,
        )
        .await;
        let user_b = test_utils::create_test_user_in_org(
            &state.store,
            "admin-b@gh-xorg-b.example",
            &org_b.id,
            true,
        )
        .await;

        // Save the IDs before moving the org/user values into the spawns.
        let org_a_id = org_a.id.clone();
        let org_b_id = org_b.id.clone();

        let store_a = state.store.clone();
        let store_b = state.store.clone();
        let audit_a = state.audit.clone();
        let audit_b = state.audit.clone();
        let config_a = (**config).clone();
        let config_b = (**config).clone();
        let app_a = state.github_app.clone();
        let app_b = state.github_app.clone();

        let h_a = tokio::spawn(async move {
            let svc = GitHubService::new(&store_a, &audit_a, &config_a, app_a.as_ref());
            svc.connect_installation(ConnectInstallationParams {
                installation_id: 42,
                org_id: &org_a.id,
                user: &user_a,
            })
            .await
        });
        let h_b = tokio::spawn(async move {
            let svc = GitHubService::new(&store_b, &audit_b, &config_b, app_b.as_ref());
            svc.connect_installation(ConnectInstallationParams {
                installation_id: 42,
                org_id: &org_b.id,
                user: &user_b,
            })
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
            "unexpected error(s) from connect_installation: {other_err:?}"
        );
        assert_eq!(
            ok_count, 1,
            "exactly one connect must win, got {ok_count} ok"
        );
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
