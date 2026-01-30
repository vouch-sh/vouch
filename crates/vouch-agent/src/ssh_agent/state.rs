// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH Agent state management.

use super::MIN_REFRESH_INTERVAL_SECONDS;
use super::credentials::SshCredentials;
use jiff::Timestamp;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// SSH Agent state with session linkage.
pub struct SshAgentState {
    /// Current SSH credentials (if loaded).
    credentials: RwLock<Option<SshCredentials>>,
    /// Session expiration timestamp (linked to Vouch session).
    session_expires_at: RwLock<Option<Timestamp>>,
    /// Server URL for credential refresh.
    server_url: RwLock<Option<String>>,
    /// Last refresh attempt timestamp (for rate limiting).
    last_refresh_at: RwLock<Option<Timestamp>>,
}

impl Default for SshAgentState {
    fn default() -> Self {
        Self {
            credentials: RwLock::new(None),
            session_expires_at: RwLock::new(None),
            server_url: RwLock::new(None),
            last_refresh_at: RwLock::new(None),
        }
    }
}

impl SshAgentState {
    /// Create a new SSH agent state.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Store SSH credentials with session linkage.
    pub async fn store_credentials(
        &self,
        creds: SshCredentials,
        session_expires_at: Option<Timestamp>,
        server_url: Option<String>,
    ) {
        let mut cred_guard = self.credentials.write().await;
        *cred_guard = Some(creds);

        if let Some(expires) = session_expires_at {
            let mut session_guard = self.session_expires_at.write().await;
            *session_guard = Some(expires);
        }

        if let Some(url) = server_url {
            let mut url_guard = self.server_url.write().await;
            *url_guard = Some(url);
        }
    }

    /// Store SSH credentials without session info (backwards compatibility).
    pub async fn store_credentials_simple(&self, creds: SshCredentials) {
        let mut guard = self.credentials.write().await;
        *guard = Some(creds);
    }

    /// Clear SSH credentials and session linkage.
    pub async fn clear_credentials(&self) {
        let mut cred_guard = self.credentials.write().await;
        *cred_guard = None;

        let mut session_guard = self.session_expires_at.write().await;
        *session_guard = None;

        let mut url_guard = self.server_url.write().await;
        *url_guard = None;

        let mut refresh_guard = self.last_refresh_at.write().await;
        *refresh_guard = None;
    }

    /// Get current credentials (if any).
    pub async fn get_credentials(&self) -> Option<SshCredentials> {
        let guard = self.credentials.read().await;
        guard.clone()
    }

    /// Get valid credentials (not expired, session not expired).
    pub async fn get_valid_credentials(&self) -> Option<SshCredentials> {
        let creds = self.get_credentials().await?;

        // Check if certificate is expired
        if creds.is_expired() {
            debug!("Certificate has expired");
            return None;
        }

        // Check if session is expired
        let session_expires = self.session_expires_at.read().await;
        if let Some(expires) = *session_expires
            && Timestamp::now() >= expires
        {
            debug!("Session has expired");
            return None;
        }

        Some(creds)
    }

    /// Check if credentials are loaded.
    pub async fn has_credentials(&self) -> bool {
        let guard = self.credentials.read().await;
        guard.is_some()
    }

    /// Check if certificate needs refresh.
    pub async fn needs_refresh(&self) -> bool {
        let guard = self.credentials.read().await;
        guard.as_ref().is_some_and(|c| c.is_expiring_soon())
    }

    /// Check if we can attempt refresh (rate limiting).
    pub async fn can_attempt_refresh(&self) -> bool {
        let guard = self.last_refresh_at.read().await;
        match *guard {
            Some(last) => {
                let now = Timestamp::now();
                let elapsed = now.as_second() - last.as_second();
                elapsed >= MIN_REFRESH_INTERVAL_SECONDS
            }
            None => true,
        }
    }

    /// Record refresh attempt time.
    pub async fn record_refresh_attempt(&self) {
        let mut guard = self.last_refresh_at.write().await;
        *guard = Some(Timestamp::now());
    }

    /// Set the server URL for credential refresh/lazy provisioning.
    pub async fn set_server_url(&self, url: String) {
        let mut guard = self.server_url.write().await;
        *guard = Some(url);
    }

    /// Get the server URL for refresh.
    pub async fn get_server_url(&self) -> Option<String> {
        let guard = self.server_url.read().await;
        guard.clone()
    }

    /// Clean up expired credentials.
    pub async fn cleanup_expired(&self) {
        let should_clear = {
            let guard = self.credentials.read().await;
            guard.as_ref().is_some_and(|c| c.is_expired())
        };

        if should_clear {
            info!("Cleaning up expired SSH credentials");
            self.clear_credentials().await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_mock_state() -> Arc<SshAgentState> {
        SshAgentState::new()
    }

    #[tokio::test]
    async fn test_state_default_empty() {
        let state = make_mock_state();
        assert!(!state.has_credentials().await);
        assert!(state.get_credentials().await.is_none());
        assert!(state.get_server_url().await.is_none());
    }

    #[tokio::test]
    async fn test_set_and_get_server_url() {
        let state = make_mock_state();

        state
            .set_server_url("https://example.com".to_string())
            .await;
        assert_eq!(
            state.get_server_url().await,
            Some("https://example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_clear_credentials_clears_all() {
        let state = make_mock_state();

        state
            .set_server_url("https://example.com".to_string())
            .await;
        state.record_refresh_attempt().await;

        state.clear_credentials().await;

        assert!(state.get_server_url().await.is_none());
        assert!(state.can_attempt_refresh().await);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let state = make_mock_state();

        // Initially can attempt refresh
        assert!(state.can_attempt_refresh().await);

        // After recording attempt, should be rate limited
        state.record_refresh_attempt().await;
        assert!(!state.can_attempt_refresh().await);
    }
}
