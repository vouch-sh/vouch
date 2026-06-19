// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH Agent state management.
//!
//! Uses a single `RwLock<SshAgentInner>` to ensure atomic reads and writes
//! across all state fields (credentials, session expiry, server URL, refresh timing).

use super::MIN_REFRESH_INTERVAL_SECONDS;
use super::credentials::SshCredentials;
use jiff::Timestamp;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

/// Internal state protected by a single lock.
#[derive(Default)]
struct SshAgentInner {
    /// Current SSH credentials (if loaded).
    credentials: Option<SshCredentials>,
    /// Session expiration timestamp (linked to Vouch session).
    session_expires_at: Option<Timestamp>,
    /// Server URL for credential refresh.
    server_url: Option<String>,
    /// Last refresh attempt timestamp (for rate limiting).
    last_refresh_at: Option<Timestamp>,
}

/// SSH Agent state with session linkage.
///
/// All fields are protected by a single `RwLock` to ensure consistency
/// when reading or updating multiple fields in a single operation.
pub struct SshAgentState {
    inner: RwLock<SshAgentInner>,
}

impl Default for SshAgentState {
    fn default() -> Self {
        Self {
            inner: RwLock::new(SshAgentInner::default()),
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
        let mut guard = self.inner.write().await;
        guard.credentials = Some(creds);

        if let Some(expires) = session_expires_at {
            guard.session_expires_at = Some(expires);
        }

        if let Some(url) = server_url {
            guard.server_url = Some(url);
        }
    }

    /// Clear SSH credentials and session linkage.
    pub async fn clear_credentials(&self) {
        let mut guard = self.inner.write().await;
        guard.credentials = None;
        guard.session_expires_at = None;
        guard.server_url = None;
        guard.last_refresh_at = None;
    }

    /// Get current credentials (if any).
    pub async fn get_credentials(&self) -> Option<SshCredentials> {
        let guard = self.inner.read().await;
        guard.credentials.clone()
    }

    /// Get valid credentials (not expired, session not expired).
    ///
    /// Reads certificate and session expiry atomically under a single lock.
    pub async fn get_valid_credentials(&self) -> Option<SshCredentials> {
        let guard = self.inner.read().await;
        let creds = guard.credentials.as_ref()?;

        // Check if certificate is expired
        if creds.is_expired() {
            debug!("Certificate has expired");
            return None;
        }

        // Check if session is expired (atomic read under the same lock)
        if let Some(expires) = guard.session_expires_at
            && Timestamp::now() >= expires
        {
            debug!("Session has expired");
            return None;
        }

        Some(creds.clone())
    }

    /// Check if credentials are loaded.
    pub async fn has_credentials(&self) -> bool {
        let guard = self.inner.read().await;
        guard.credentials.is_some()
    }

    /// Check if certificate needs refresh.
    pub async fn needs_refresh(&self) -> bool {
        let guard = self.inner.read().await;
        guard
            .credentials
            .as_ref()
            .is_some_and(|c| c.is_expiring_soon())
    }

    /// Check if we can attempt refresh (rate limiting).
    pub async fn can_attempt_refresh(&self) -> bool {
        let guard = self.inner.read().await;
        match guard.last_refresh_at {
            Some(last) => {
                let now = Timestamp::now();
                let elapsed = now.as_second().saturating_sub(last.as_second());
                elapsed >= MIN_REFRESH_INTERVAL_SECONDS
            }
            None => true,
        }
    }

    /// Record refresh attempt time.
    pub async fn record_refresh_attempt(&self) {
        let mut guard = self.inner.write().await;
        guard.last_refresh_at = Some(Timestamp::now());
    }

    /// Set the server URL for credential refresh/lazy provisioning.
    pub async fn set_server_url(&self, url: String) {
        let mut guard = self.inner.write().await;
        guard.server_url = Some(url);
    }

    /// Get the server URL for refresh.
    pub async fn get_server_url(&self) -> Option<String> {
        let guard = self.inner.read().await;
        guard.server_url.clone()
    }

}

#[cfg(test)]
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
