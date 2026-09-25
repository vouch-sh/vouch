// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent state and session management.

use crate::ssh_agent::SshCredentials;
use jiff::Timestamp;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Maximum number of entries in the credential cache.
const MAX_CACHE_ENTRIES: usize = 128;

/// Maximum length of a credential type key.
const MAX_CREDENTIAL_TYPE_LEN: usize = 256;

/// Session information stored by the agent.
#[derive(Debug, Clone)]
pub struct Session {
    /// JWT token from the server.
    token: SecretString,
    /// User's email address.
    user_email: String,
    /// When the session expires.
    pub expires_at: Timestamp,
    /// When the user authenticated.
    authenticated_at: Timestamp,
}

impl Session {
    /// Create a new session.
    pub fn new(token: SecretString, user_email: String, expires_at: Timestamp) -> Self {
        Self {
            token,
            user_email,
            expires_at,
            authenticated_at: Timestamp::now(),
        }
    }

    /// Get the JWT token.
    pub fn token(&self) -> &SecretString {
        &self.token
    }

    /// Get the user's email.
    pub fn user_email(&self) -> &str {
        &self.user_email
    }

    /// Get the expiration timestamp.
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        Timestamp::now() >= self.expires_at
    }

    /// Get seconds until expiration (0 if already expired).
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "duration since now is non-negative and bounded by session lifetime (< 24h, fits u64)"
    )]
    pub fn expires_in_seconds(&self) -> u64 {
        let now = Timestamp::now();
        if now >= self.expires_at {
            return 0;
        }
        let duration = self.expires_at.since(now);
        match duration {
            Ok(span) => {
                // Get total seconds from the span
                match span.total(jiff::Unit::Second) {
                    Ok(secs) => {
                        if secs < 0.0 {
                            0
                        } else {
                            secs as u64
                        }
                    }
                    Err(_) => 0,
                }
            }
            Err(_) => 0,
        }
    }
}

/// Serializable session info for IPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// User's email address.
    pub user_email: String,
    /// ISO 8601 expiration timestamp.
    pub expires_at: String,
    /// ISO 8601 authentication timestamp.
    pub authenticated_at: String,
    /// Seconds until expiration.
    pub expires_in_seconds: u64,
    /// Server URL the session is connected to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

impl From<&Session> for SessionInfo {
    fn from(session: &Session) -> Self {
        Self {
            user_email: session.user_email.clone(),
            expires_at: session.expires_at.to_string(),
            authenticated_at: session.authenticated_at.to_string(),
            expires_in_seconds: session.expires_in_seconds(),
            server_url: None,
        }
    }
}

/// Cached credential for non-SSH services (AWS, GitHub, etc.).
///
/// Credential data is stored as a [`SecretString`] containing JSON, which is
/// automatically zeroized when dropped. This prevents sensitive material
/// (e.g. AWS secret keys, GitHub tokens) from lingering in process memory
/// after the credential expires or is evicted.
#[derive(Clone, Serialize, Deserialize)]
#[serde(from = "CachedCredentialWire", into = "CachedCredentialWire")]
pub struct CachedCredential {
    /// Credential data as JSON string, zeroized on drop.
    data: SecretString,
    /// When the credential expires.
    expires_at: Timestamp,
    /// When the credential was cached.
    cached_at: Timestamp,
}

/// Wire format for [`CachedCredential`] used in JSON-RPC serialization.
#[derive(Serialize, Deserialize)]
struct CachedCredentialWire {
    data: serde_json::Value,
    expires_at: String,
    cached_at: String,
}

impl From<CachedCredentialWire> for CachedCredential {
    fn from(wire: CachedCredentialWire) -> Self {
        let expires_at = wire.expires_at.parse().unwrap_or_else(|e| {
            warn!(
                "invalid expires_at timestamp '{}': {e}; treating as expired",
                wire.expires_at
            );
            Timestamp::UNIX_EPOCH
        });
        let cached_at = wire.cached_at.parse().unwrap_or_else(|e| {
            warn!(
                "invalid cached_at timestamp '{}': {e}; defaulting to epoch",
                wire.cached_at
            );
            Timestamp::UNIX_EPOCH
        });
        Self {
            data: SecretString::from(wire.data.to_string()),
            expires_at,
            cached_at,
        }
    }
}

impl From<CachedCredential> for CachedCredentialWire {
    fn from(cred: CachedCredential) -> Self {
        let data =
            serde_json::from_str(cred.data.expose_secret()).unwrap_or(serde_json::Value::Null);
        Self {
            data,
            expires_at: cred.expires_at.to_string(),
            cached_at: cred.cached_at.to_string(),
        }
    }
}

impl std::fmt::Debug for CachedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedCredential")
            .field("data", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("cached_at", &self.cached_at)
            .finish()
    }
}

impl CachedCredential {
    /// Create a new cached credential from a JSON value.
    pub fn new(data: serde_json::Value, expires_at: Timestamp) -> Self {
        Self {
            data: SecretString::from(data.to_string()),
            expires_at,
            cached_at: Timestamp::now(),
        }
    }

    /// Access the credential data as a JSON Value.
    ///
    /// Returns `Value::Null` if the stored JSON is somehow invalid (should not
    /// happen under normal operation since we always store valid JSON).
    pub fn data(&self) -> serde_json::Value {
        serde_json::from_str(self.data.expose_secret()).unwrap_or(serde_json::Value::Null)
    }

    /// Get the expiration timestamp.
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Check if this cached credential is still valid (not expired).
    pub fn is_valid(&self) -> bool {
        Timestamp::now() < self.expires_at
    }
}

/// Everything the agent holds on behalf of one login.
///
/// The session, the server that issued it, and every credential obtained under
/// it live in one value. [`AgentState::store_session`] replaces the whole slot
/// and [`AgentState::clear_session`] drops it, so a credential cannot outlive
/// the session that authorized it or be paired with a later session's
/// identity or server: there is no field to leave behind.
struct SessionSlot {
    /// The session.
    session: Session,
    /// Server URL the session was issued by.
    server_url: Option<String>,
    /// Credential cache keyed by type (e.g., "aws", "github").
    ///
    /// Keys are built from role and provider parameters, never the user, so
    /// the cache is only safe because it dies with the slot.
    credential_cache: HashMap<String, CachedCredential>,
    /// Current SSH credentials (if loaded).
    ///
    /// Validity is derived from `session` rather than a copied expiry
    /// timestamp; a duplicate could drift from the session it mirrors.
    ssh_credentials: Option<SshCredentials>,
}

impl SessionSlot {
    fn new(session: Session, server_url: Option<String>) -> Self {
        Self {
            session,
            server_url,
            credential_cache: HashMap::new(),
            ssh_credentials: None,
        }
    }

    /// The session, if it has not expired.
    fn live_session(&self) -> Option<&Session> {
        Some(&self.session).filter(|s| !s.is_expired())
    }
}

/// Hand-written so SSH credentials are reported as present or absent only.
/// `SshCredentials` wraps a `PrivateKey` and deliberately has no `Debug`.
impl std::fmt::Debug for SessionSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSlot")
            .field("session", &self.session)
            .field("server_url", &self.server_url)
            .field("credential_cache", &self.credential_cache)
            .field("ssh_credentials", &self.ssh_credentials.is_some())
            .finish()
    }
}

/// Why [`AgentState::store_ssh_credentials`] refused a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshStoreRefusal {
    /// No live session to attach the certificate to.
    NoSession,
    /// The certificate's key ID names a different user or server than the
    /// current session.
    NotIssuedToSession,
}

/// Why [`AgentState::cache_credential`] refused an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheRefusal {
    /// The credential type exceeds the 256-byte key limit.
    KeyTooLong,
    /// No session is stored, so there is no identity to bind the entry to.
    NoSession,
}

/// Agent state (shared across connections).
///
/// A single lock guards the one `SessionSlot`, so a request never observes
/// a credential from one login beside the session of another.
#[derive(Debug, Default)]
pub struct AgentState {
    inner: RwLock<Option<SessionSlot>>,
}

impl AgentState {
    /// Create a new agent state.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Get the current session (if valid).
    pub async fn get_session(&self) -> Option<Session> {
        let guard = self.inner.read().await;
        guard.as_ref()?.live_session().cloned()
    }

    /// Store a new session with the server URL it was issued by.
    ///
    /// The previous slot is replaced whole: its server URL, cached
    /// credentials, and SSH certificate are dropped with it, whoever the new
    /// session belongs to. Cache keys are not user-specific, so a kept entry
    /// would be served under the new session; and a same-email login may be
    /// to a different server, whose credentials are not the old server's.
    /// There are no refresh tokens, so this only runs on login, enroll, and
    /// agent-restart recovery, and the cost is one re-fetch per credential.
    pub async fn store_session(&self, session: Session, server_url: Option<String>) {
        let mut guard = self.inner.write().await;
        *guard = Some(SessionSlot::new(session, server_url));
    }

    /// Clear the current session and every credential it authorized.
    ///
    /// Session, cached credentials, and SSH credentials are dropped in one
    /// critical section, so no concurrent request can observe a credential
    /// that outlived the logout.
    pub async fn clear_session(&self) {
        let mut guard = self.inner.write().await;
        *guard = None;
    }

    /// Store SSH credentials, but only for the live session that owns them.
    ///
    /// Refused when there is no live session, or when the certificate's key
    /// ID (`{email}@{rp_id}`) does not name the session's user and server; a
    /// certificate left on disk by a previous login must not be served under
    /// the next one. The checks and the write share one critical section
    /// because callers do slow work (loading a key and certificate off disk)
    /// before storing, and a logout or re-login landing in that gap would
    /// otherwise be undone by the store.
    pub async fn store_ssh_credentials(
        &self,
        creds: SshCredentials,
    ) -> Result<(), SshStoreRefusal> {
        let mut guard = self.inner.write().await;
        let Some(slot) = guard.as_mut() else {
            debug!("No live session; refusing to store SSH credentials");
            return Err(SshStoreRefusal::NoSession);
        };
        let Some(session) = slot.live_session() else {
            debug!("No live session; refusing to store SSH credentials");
            return Err(SshStoreRefusal::NoSession);
        };
        if !vouch_common::ssh_cert_issued_to(
            &creds.metadata.key_id,
            session.user_email(),
            slot.server_url.as_deref(),
        ) {
            warn!("Refusing SSH certificate not issued to the current session");
            return Err(SshStoreRefusal::NotIssuedToSession);
        }
        slot.ssh_credentials = Some(creds);
        Ok(())
    }

    /// Clear SSH credentials. The session and its server URL are kept.
    pub async fn clear_ssh_credentials(&self) {
        let mut guard = self.inner.write().await;
        if let Some(slot) = guard.as_mut() {
            slot.ssh_credentials = None;
        }
    }

    /// Get SSH credentials, if both the certificate and the session are live.
    ///
    /// Both checks happen under one lock against the authoritative session, so
    /// a certificate cannot be served after the session backing it is gone.
    pub async fn get_valid_ssh_credentials(&self) -> Option<SshCredentials> {
        let guard = self.inner.read().await;
        let slot = guard.as_ref()?;
        let creds = slot.ssh_credentials.as_ref()?;

        if creds.is_expired() {
            debug!("SSH certificate has expired");
            return None;
        }

        if slot.live_session().is_none() {
            debug!("No live session; refusing to serve SSH credentials");
            return None;
        }
        Some(creds.clone())
    }

    /// Check whether SSH credentials are loaded, regardless of validity.
    pub async fn has_ssh_credentials(&self) -> bool {
        let guard = self.inner.read().await;
        guard.as_ref().is_some_and(|s| s.ssh_credentials.is_some())
    }

    /// Get the server URL the current session was issued by.
    pub async fn get_server_url(&self) -> Option<String> {
        let guard = self.inner.read().await;
        guard.as_ref()?.server_url.clone()
    }

    /// Store a credential in the current session's cache.
    ///
    /// Rejects keys longer than 256 bytes and caps the cache at 128 entries,
    /// evicting the oldest expired entry (or the oldest entry) when full.
    ///
    /// Refused when no session is stored: an entry with no session to belong
    /// to would otherwise be served to whichever identity logs in next. When
    /// refused, nothing is cached, so the caller must not log or audit a
    /// cache hit.
    pub async fn cache_credential(
        &self,
        credential_type: String,
        credential: CachedCredential,
    ) -> Result<(), CacheRefusal> {
        if credential_type.len() > MAX_CREDENTIAL_TYPE_LEN {
            warn!(
                "Rejecting credential cache key: length {} exceeds maximum {MAX_CREDENTIAL_TYPE_LEN}",
                credential_type.len()
            );
            return Err(CacheRefusal::KeyTooLong);
        }

        let mut guard = self.inner.write().await;
        let Some(slot) = guard.as_mut() else {
            debug!("No session; refusing to cache credential");
            return Err(CacheRefusal::NoSession);
        };
        let cache = &mut slot.credential_cache;

        // Evict if at capacity and this is a new key
        let is_new_key = !cache.contains_key(&credential_type);
        if is_new_key && cache.len() >= MAX_CACHE_ENTRIES {
            // Try to evict an expired entry first, then fall back to oldest
            let evict_key = cache
                .iter()
                .find(|(_, v)| !v.is_valid())
                .map(|(k, _)| k.clone());
            let evict_key = evict_key.or_else(|| {
                cache
                    .iter()
                    .min_by_key(|(_, v)| v.expires_at())
                    .map(|(k, _)| k.clone())
            });

            if let Some(key) = evict_key {
                cache.remove(&key);
            }
        }

        cache.insert(credential_type, credential);
        Ok(())
    }

    /// Get a cached credential if it is still valid.
    pub async fn get_cached_credential(&self, credential_type: &str) -> Option<CachedCredential> {
        let guard = self.inner.read().await;
        guard
            .as_ref()?
            .credential_cache
            .get(credential_type)
            .filter(|c| c.is_valid())
            .cloned()
    }

    /// Clear all cached credentials.
    pub async fn clear_credential_cache(&self) {
        let mut guard = self.inner.write().await;
        if let Some(slot) = guard.as_mut() {
            slot.credential_cache.clear();
        }
    }

    /// Get seconds until session expiry (`None` if no session, `Some(0)` if expired).
    pub async fn expires_in_seconds(&self) -> Option<u64> {
        let guard = self.inner.read().await;
        guard.as_ref().map(|s| s.session.expires_in_seconds())
    }

    /// Get the raw token (if session is valid).
    pub async fn get_token(&self) -> Option<SecretString> {
        let guard = self.inner.read().await;
        guard.as_ref()?.live_session().map(|s| s.token.clone())
    }

    /// Get the current session's email, if a session is stored.
    ///
    /// Returns the email even when the session has expired so that the expiry
    /// monitor can attribute an `AuditEvent::SessionExpired` to the user.
    pub async fn current_user_email(&self) -> Option<String> {
        let guard = self.inner.read().await;
        guard.as_ref().map(|s| s.session.user_email().to_string())
    }

    /// Get the current session's expiry timestamp and remaining seconds under a
    /// single read lock.
    ///
    /// Both values are read atomically so the expiry monitor never observes a
    /// torn pair where the timestamp comes from one session and the remaining
    /// seconds from a session that replaced it between two separate reads.
    /// Values are returned even for an expired-but-not-yet-cleared session so the
    /// monitor can detect when a new login replaces it and re-arm its warnings.
    pub async fn session_expiry_info(&self) -> (Option<Timestamp>, Option<u64>) {
        let guard = self.inner.read().await;
        match guard.as_ref() {
            Some(slot) => (
                Some(slot.session.expires_at()),
                Some(slot.session.expires_in_seconds()),
            ),
            None => (None, None),
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    fn future_timestamp(seconds: i64) -> Timestamp {
        let now = Timestamp::now();
        Timestamp::from_second(now.as_second() + seconds).unwrap()
    }

    fn past_timestamp(seconds: i64) -> Timestamp {
        let now = Timestamp::now();
        Timestamp::from_second(now.as_second() - seconds).unwrap()
    }

    /// A real Ed25519 key and self-signed certificate, valid for an hour,
    /// issued to `user@example.com` by the RP `example.com`.
    fn test_ssh_credentials() -> SshCredentials {
        test_ssh_credentials_with_key_id("user@example.com@example.com")
    }

    /// As [`test_ssh_credentials`], with the certificate key ID `key_id`.
    fn test_ssh_credentials_with_key_id(key_id: &str) -> SshCredentials {
        use ssh_key::rand_core::OsRng;
        use ssh_key::{Algorithm, PrivateKey, certificate};

        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let now = u64::try_from(Timestamp::now().as_second()).unwrap();
        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut OsRng,
            key.public_key(),
            now - 60,
            now + 3600,
        )
        .unwrap();
        builder.key_id(key_id).unwrap();
        builder.valid_principal("tester").unwrap();
        let cert = builder.sign(&key).unwrap();

        SshCredentials::new(key, &cert, "tester".to_string()).unwrap()
    }

    /// A live session, so credential stores are accepted.
    async fn with_live_session(state: &Arc<AgentState>) {
        state
            .store_session(
                Session::new(
                    SecretString::from("token"),
                    "user@example.com".to_string(),
                    future_timestamp(3600),
                ),
                None,
            )
            .await;
    }

    /// Logout must drop SSH credentials in the same critical section as the
    /// session. When these lived behind separate locks, a signing request
    /// landing between the two clears was served after logout.
    #[tokio::test]
    async fn clear_session_also_clears_ssh_credentials() {
        let state = AgentState::new();
        with_live_session(&state).await;
        assert!(
            state
                .store_ssh_credentials(test_ssh_credentials())
                .await
                .is_ok()
        );
        assert!(state.get_valid_ssh_credentials().await.is_some());

        state.clear_session().await;

        assert!(!state.has_ssh_credentials().await);
        assert!(state.get_valid_ssh_credentials().await.is_none());
        assert!(state.get_server_url().await.is_none());
    }

    /// A certificate is only served while a session backs it, so an expired
    /// session revokes it without any separate bookkeeping.
    #[tokio::test]
    async fn ssh_credentials_require_a_live_session() {
        let state = AgentState::new();
        with_live_session(&state).await;
        assert!(
            state
                .store_ssh_credentials(test_ssh_credentials())
                .await
                .is_ok()
        );
        assert!(state.get_valid_ssh_credentials().await.is_some());

        // Let the session expire in place; the certificate is untouched and
        // still within its own validity window.
        state
            .inner
            .write()
            .await
            .as_mut()
            .unwrap()
            .session
            .expires_at = past_timestamp(1);

        assert!(
            state.has_ssh_credentials().await,
            "credentials are still held"
        );
        assert!(
            state.get_valid_ssh_credentials().await.is_none(),
            "but must not be served without a live session"
        );
    }

    /// Storing is refused outright with no session, so slow callers (lazy disk
    /// load) cannot resurrect credentials a concurrent logout just cleared.
    #[tokio::test]
    async fn storing_ssh_credentials_without_a_session_is_refused() {
        let state = AgentState::new();
        assert_eq!(
            state.store_ssh_credentials(test_ssh_credentials()).await,
            Err(SshStoreRefusal::NoSession)
        );
        assert!(!state.has_ssh_credentials().await);
    }

    /// A certificate whose key ID names another user, or another server, is
    /// refused even with a live session. This is the check the lazy disk load
    /// relies on: `vouch logout` and a different user's `vouch login` both
    /// leave the previous user's certificate in `~/.ssh`.
    #[tokio::test]
    async fn ssh_credentials_must_be_issued_to_the_session() {
        let state = AgentState::new();
        state
            .store_session(
                Session::new(
                    SecretString::from("token"),
                    "bob@example.com".to_string(),
                    future_timestamp(3600),
                ),
                Some("https://vouch.example.com".to_string()),
            )
            .await;

        for key_id in [
            "alice@example.com@vouch.example.com",
            "bob@example.com@vouch.other.example",
            "bob@example.com",
            "",
        ] {
            assert_eq!(
                state
                    .store_ssh_credentials(test_ssh_credentials_with_key_id(key_id))
                    .await,
                Err(SshStoreRefusal::NotIssuedToSession),
                "key ID {key_id:?} must be refused"
            );
            assert!(!state.has_ssh_credentials().await);
        }

        assert!(
            state
                .store_ssh_credentials(test_ssh_credentials_with_key_id(
                    "bob@example.com@vouch.example.com"
                ))
                .await
                .is_ok(),
            "the session's own certificate is accepted"
        );
        assert!(state.get_valid_ssh_credentials().await.is_some());
    }

    /// The server URL belongs to the session: clearing SSH credentials keeps
    /// it, and only clearing the session drops it.
    #[tokio::test]
    async fn server_url_lives_and_dies_with_the_session() {
        let state = AgentState::new();
        assert!(state.get_server_url().await.is_none());

        state
            .store_session(
                Session::new(
                    SecretString::from("token"),
                    "user@example.com".to_string(),
                    future_timestamp(3600),
                ),
                Some("https://example.com".to_string()),
            )
            .await;
        assert_eq!(
            state.get_server_url().await,
            Some("https://example.com".to_string())
        );

        state.clear_ssh_credentials().await;
        assert_eq!(
            state.get_server_url().await,
            Some("https://example.com".to_string())
        );

        state.clear_session().await;
        assert!(state.get_server_url().await.is_none());
    }

    #[test]
    fn test_session_new() {
        let token = SecretString::from("test_token");
        let expires = future_timestamp(3600);
        let session = Session::new(token, "user@example.com".to_string(), expires);

        assert_eq!(session.user_email(), "user@example.com");
        assert_eq!(session.expires_at(), expires);
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_is_expired() {
        let token = SecretString::from("test_token");

        // Not expired (1 hour from now)
        let future_session = Session::new(
            token.clone(),
            "user@example.com".to_string(),
            future_timestamp(3600),
        );
        assert!(!future_session.is_expired());

        // Expired (1 hour ago)
        let past_session =
            Session::new(token, "user@example.com".to_string(), past_timestamp(3600));
        assert!(past_session.is_expired());
    }

    #[test]
    fn test_session_expires_in_seconds() {
        let token = SecretString::from("test_token");

        // Future session (1 hour from now)
        let future_session = Session::new(
            token.clone(),
            "user@example.com".to_string(),
            future_timestamp(3600),
        );
        let remaining = future_session.expires_in_seconds();
        // Allow some tolerance for test execution time
        assert!((3590..=3600).contains(&remaining));

        // Expired session
        let past_session = Session::new(token, "user@example.com".to_string(), past_timestamp(100));
        assert_eq!(past_session.expires_in_seconds(), 0);
    }

    #[test]
    fn test_session_info_from_session() {
        let token = SecretString::from("test_token");
        let expires = future_timestamp(3600);
        let session = Session::new(token, "user@example.com".to_string(), expires);

        let info = SessionInfo::from(&session);
        assert_eq!(info.user_email, "user@example.com");
        assert!(!info.expires_at.is_empty());
        assert!(!info.authenticated_at.is_empty());
        assert!(info.expires_in_seconds > 0);
    }

    #[tokio::test]
    async fn test_agent_state_store_get_session() {
        let state = AgentState::new();
        let token = SecretString::from("test_token");
        let session = Session::new(
            token,
            "user@example.com".to_string(),
            future_timestamp(3600),
        );

        // Initially no session
        assert!(state.get_session().await.is_none());

        // Store session
        state.store_session(session, None).await;

        // Retrieve session
        let retrieved = state.get_session().await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_email(), "user@example.com");
    }

    #[tokio::test]
    async fn test_agent_state_clear_session() {
        let state = AgentState::new();
        let token = SecretString::from("test_token");
        let session = Session::new(
            token,
            "user@example.com".to_string(),
            future_timestamp(3600),
        );

        state.store_session(session, None).await;
        assert!(state.get_session().await.is_some());

        state.clear_session().await;
        assert!(state.get_session().await.is_none());
    }

    #[tokio::test]
    async fn test_agent_state_get_token() {
        let state = AgentState::new();
        let token = SecretString::from("secret_jwt_token");
        let session = Session::new(
            token,
            "user@example.com".to_string(),
            future_timestamp(3600),
        );

        // No token when no session
        assert!(state.get_token().await.is_none());

        state.store_session(session, None).await;

        // Get token
        let retrieved_token = state.get_token().await;
        assert!(retrieved_token.is_some());
        assert_eq!(retrieved_token.unwrap().expose_secret(), "secret_jwt_token");
    }

    #[tokio::test]
    async fn test_agent_state_expired_session_not_returned() {
        let state = AgentState::new();
        let token = SecretString::from("test_token");
        let session = Session::new(
            token,
            "user@example.com".to_string(),
            past_timestamp(100), // Already expired
        );

        state.store_session(session, None).await;

        // Expired session should not be returned
        assert!(state.get_session().await.is_none());
        assert!(state.get_token().await.is_none());
    }

    #[tokio::test]
    async fn test_current_user_email_available_for_expired_session() {
        let state = AgentState::new();

        // No session yet.
        assert!(state.current_user_email().await.is_none());

        // An expired session still yields the email so the expiry monitor can
        // attribute the SessionExpired audit event to the user.
        let session = Session::new(
            SecretString::from("test_token"),
            "user@example.com".to_string(),
            past_timestamp(100),
        );
        state.store_session(session, None).await;

        assert!(
            state.get_session().await.is_none(),
            "expired session hidden"
        );
        assert_eq!(
            state.current_user_email().await.as_deref(),
            Some("user@example.com")
        );
    }

    // --- CachedCredential tests ---

    #[test]
    fn test_cached_credential_new_and_data_roundtrip() {
        let data = serde_json::json!({
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "FwoGZXIvYXdzEP///wEaDH...",
            "Expiration": "2099-12-31T23:59:59Z"
        });

        let cred = CachedCredential::new(data.clone(), future_timestamp(3600));

        // Data should round-trip through SecretString
        let retrieved = cred.data();
        assert_eq!(
            retrieved.get("AccessKeyId").unwrap().as_str().unwrap(),
            "AKIAIOSFODNN7EXAMPLE"
        );
        assert_eq!(
            retrieved.get("SecretAccessKey").unwrap().as_str().unwrap(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
    }

    #[test]
    fn test_cached_credential_is_valid() {
        // Valid: expires in the future
        let valid = CachedCredential::new(serde_json::json!({}), future_timestamp(3600));
        assert!(valid.is_valid());

        // Expired: in the past
        let expired = CachedCredential::new(serde_json::json!({}), past_timestamp(100));
        assert!(!expired.is_valid());
    }

    #[test]
    fn test_cached_credential_debug_redacts_data() {
        let cred = CachedCredential::new(
            serde_json::json!({"secret": "very-secret-value"}),
            future_timestamp(3600),
        );
        let debug = format!("{cred:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("very-secret-value"));
    }

    #[test]
    fn test_cached_credential_serialization_roundtrip() {
        let original_data = serde_json::json!({
            "token": "ghs_xxxxxxxxxxxxxxxxxxxx",
            "expires_at": "2099-12-31T23:59:59Z"
        });
        let cred = CachedCredential::new(original_data.clone(), future_timestamp(3600));

        // Serialize to JSON (simulates IPC send)
        let json = serde_json::to_string(&cred).unwrap();

        // The JSON should contain the data as an object, not a string
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("data").unwrap().is_object());
        assert_eq!(
            parsed
                .get("data")
                .unwrap()
                .get("token")
                .unwrap()
                .as_str()
                .unwrap(),
            "ghs_xxxxxxxxxxxxxxxxxxxx"
        );

        // Deserialize back (simulates IPC receive)
        let deserialized: CachedCredential = serde_json::from_str(&json).unwrap();
        let roundtripped = deserialized.data();
        assert_eq!(
            roundtripped.get("token").unwrap().as_str().unwrap(),
            "ghs_xxxxxxxxxxxxxxxxxxxx"
        );
    }

    #[tokio::test]
    async fn test_agent_state_credential_cache() {
        let state = AgentState::new();
        with_live_session(&state).await;

        // Initially empty
        assert!(state.get_cached_credential("aws:role1").await.is_none());

        // Cache a credential
        let cred = CachedCredential::new(
            serde_json::json!({"AccessKeyId": "AKIA..."}),
            future_timestamp(3600),
        );
        assert!(
            state
                .cache_credential("aws:role1".to_string(), cred)
                .await
                .is_ok()
        );

        // Retrieve it
        let cached = state.get_cached_credential("aws:role1").await;
        assert!(cached.is_some());
        let data = cached.unwrap().data();
        assert_eq!(
            data.get("AccessKeyId").unwrap().as_str().unwrap(),
            "AKIA..."
        );

        // Different key returns None
        assert!(state.get_cached_credential("aws:role2").await.is_none());
    }

    #[tokio::test]
    async fn test_agent_state_expired_credential_not_returned() {
        let state = AgentState::new();
        with_live_session(&state).await;
        let cred =
            CachedCredential::new(serde_json::json!({"token": "expired"}), past_timestamp(100));
        assert!(
            state
                .cache_credential("github".to_string(), cred)
                .await
                .is_ok()
        );

        // Expired credential should not be returned
        assert!(state.get_cached_credential("github").await.is_none());
    }

    #[tokio::test]
    async fn test_clear_session_also_clears_credential_cache() {
        let state = AgentState::new();

        // Store session and credential
        let session = Session::new(
            SecretString::from("token"),
            "user@example.com".to_string(),
            future_timestamp(3600),
        );
        state.store_session(session, None).await;
        state
            .cache_credential(
                "aws:role".to_string(),
                CachedCredential::new(serde_json::json!({}), future_timestamp(3600)),
            )
            .await
            .unwrap();

        assert!(state.get_session().await.is_some());
        assert!(state.get_cached_credential("aws:role").await.is_some());

        // Clear session should also clear credential cache
        state.clear_session().await;
        assert!(state.get_session().await.is_none());
        assert!(state.get_cached_credential("aws:role").await.is_none());
    }

    /// A session for `email`, expiring in an hour.
    fn session_for(email: &str) -> Session {
        Session::new(
            SecretString::from(format!("token-{email}")),
            email.to_string(),
            future_timestamp(3600),
        )
    }

    /// Cache an AWS-shaped credential and a matching SSH certificate under
    /// the current session, asserting both were accepted.
    async fn hold_credentials(state: &Arc<AgentState>, key_id: &str) {
        assert!(
            state
                .cache_credential(
                    "aws:role".to_string(),
                    CachedCredential::new(
                        serde_json::json!({"AccessKeyId": "AKIA_PREVIOUS"}),
                        future_timestamp(3600),
                    ),
                )
                .await
                .is_ok()
        );
        assert!(
            state
                .store_ssh_credentials(test_ssh_credentials_with_key_id(key_id))
                .await
                .is_ok()
        );
    }

    /// Every `store_session` starts an empty slot, whoever logs in. The
    /// cache key is not user-specific, so a kept entry would be served under
    /// the new session; and the same email on a different server is a
    /// different principal whose credentials are not the old server's. There
    /// are no refresh tokens, so no replacement is a refresh of the same
    /// session.
    #[tokio::test]
    async fn store_session_drops_every_credential_of_the_session_it_replaces() {
        let replacements = [
            ("different user", "bob@example.com", "https://a.example.com"),
            (
                "same user, other server",
                "alice@example.com",
                "https://b.example.com",
            ),
            (
                "same user, same server",
                "alice@example.com",
                "https://a.example.com",
            ),
        ];
        for (case, email, server) in replacements {
            let state = AgentState::new();
            state
                .store_session(
                    session_for("alice@example.com"),
                    Some("https://a.example.com".to_string()),
                )
                .await;
            hold_credentials(&state, "alice@example.com@a.example.com").await;

            state
                .store_session(session_for(email), Some(server.to_string()))
                .await;

            assert_eq!(state.current_user_email().await.as_deref(), Some(email));
            assert_eq!(state.get_server_url().await.as_deref(), Some(server));
            assert!(
                state.get_cached_credential("aws:role").await.is_none(),
                "{case}: the previous session's cached credential must not survive"
            );
            assert!(
                !state.has_ssh_credentials().await,
                "{case}: the previous session's SSH certificate must not survive"
            );
        }
    }

    /// A `None` server URL on the replacing session clears the old URL rather
    /// than keeping it beside the new session.
    #[tokio::test]
    async fn store_session_without_a_server_url_does_not_keep_the_old_one() {
        let state = AgentState::new();
        state
            .store_session(
                session_for("alice@example.com"),
                Some("https://a.example.com".to_string()),
            )
            .await;
        state
            .store_session(session_for("alice@example.com"), None)
            .await;
        assert!(state.get_server_url().await.is_none());
    }

    /// With no session there is no identity to bind a cache entry to, so it
    /// is refused rather than kept for whoever logs in next.
    #[tokio::test]
    async fn cache_credential_without_a_session_is_refused() {
        let state = AgentState::new();
        let cred = CachedCredential::new(serde_json::json!({"k": "v"}), future_timestamp(3600));
        assert_eq!(
            state.cache_credential("aws:role".to_string(), cred).await,
            Err(CacheRefusal::NoSession)
        );

        state
            .store_session(session_for("bob@example.com"), None)
            .await;
        assert!(state.get_cached_credential("aws:role").await.is_none());
    }

    /// Oversized cache keys are rejected at the state layer: `cache_credential`
    /// returns `KeyTooLong` and stores nothing, while a key at exactly the limit is
    /// accepted. This is the state-layer half of the fix for the IPC handler
    /// that previously reported success and audited a cache hit on rejection.
    #[tokio::test]
    async fn test_cache_credential_rejects_oversized_key() {
        let state = AgentState::new();
        with_live_session(&state).await;

        // A key at exactly the maximum length is accepted.
        let at_limit = "a".repeat(MAX_CREDENTIAL_TYPE_LEN);
        let cred = CachedCredential::new(serde_json::json!({"k": "v"}), future_timestamp(3600));
        assert!(
            state.cache_credential(at_limit.clone(), cred).await.is_ok(),
            "key at the limit should be stored"
        );
        assert!(state.get_cached_credential(&at_limit).await.is_some());

        // One byte over the limit is rejected and must not be cached.
        let over_limit = "b".repeat(MAX_CREDENTIAL_TYPE_LEN + 1);
        let cred = CachedCredential::new(serde_json::json!({"k": "v2"}), future_timestamp(3600));
        assert_eq!(
            state.cache_credential(over_limit.clone(), cred).await,
            Err(CacheRefusal::KeyTooLong),
            "oversized key should be rejected"
        );
        assert!(
            state.get_cached_credential(&over_limit).await.is_none(),
            "rejected key must not be cached"
        );
    }
}
