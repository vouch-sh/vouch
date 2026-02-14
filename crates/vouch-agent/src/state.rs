// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent state and session management.

use jiff::Timestamp;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

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

    /// Get when the user authenticated.
    pub fn authenticated_at(&self) -> Timestamp {
        self.authenticated_at
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        Timestamp::now() >= self.expires_at
    }

    /// Get seconds until expiration (0 if already expired).
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
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
}

impl From<&Session> for SessionInfo {
    fn from(session: &Session) -> Self {
        Self {
            user_email: session.user_email.clone(),
            expires_at: session.expires_at.to_string(),
            authenticated_at: session.authenticated_at.to_string(),
            expires_in_seconds: session.expires_in_seconds(),
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

    /// Get the cache timestamp.
    pub fn cached_at(&self) -> Timestamp {
        self.cached_at
    }

    /// Check if this cached credential is still valid (not expired).
    pub fn is_valid(&self) -> bool {
        Timestamp::now() < self.expires_at
    }
}

/// Agent state (shared across connections).
#[derive(Debug, Default)]
pub struct AgentState {
    /// Current session (if authenticated).
    session: RwLock<Option<Session>>,
    /// Credential cache keyed by type (e.g., "aws", "github").
    credential_cache: RwLock<HashMap<String, CachedCredential>>,
}

impl AgentState {
    /// Create a new agent state.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            session: RwLock::new(None),
            credential_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Get the current session (if valid).
    pub async fn get_session(&self) -> Option<Session> {
        let guard = self.session.read().await;
        match guard.as_ref() {
            Some(session) if !session.is_expired() => Some(session.clone()),
            _ => None,
        }
    }

    /// Store a new session.
    pub async fn store_session(&self, session: Session) {
        let mut guard = self.session.write().await;
        *guard = Some(session);
    }

    /// Clear the current session and credential cache.
    pub async fn clear_session(&self) {
        let mut guard = self.session.write().await;
        *guard = None;
        drop(guard);

        self.clear_credential_cache().await;
    }

    /// Store a credential in the cache.
    pub async fn cache_credential(&self, credential_type: String, credential: CachedCredential) {
        let mut guard = self.credential_cache.write().await;
        guard.insert(credential_type, credential);
    }

    /// Get a cached credential if it is still valid.
    pub async fn get_cached_credential(&self, credential_type: &str) -> Option<CachedCredential> {
        let guard = self.credential_cache.read().await;
        guard
            .get(credential_type)
            .and_then(|c| if c.is_valid() { Some(c.clone()) } else { None })
    }

    /// Clear all cached credentials.
    pub async fn clear_credential_cache(&self) {
        let mut guard = self.credential_cache.write().await;
        guard.clear();
    }

    /// Get seconds until session expiry (`None` if no session, `Some(0)` if expired).
    pub async fn expires_in_seconds(&self) -> Option<u64> {
        let guard = self.session.read().await;
        guard.as_ref().map(Session::expires_in_seconds)
    }

    /// Get the raw token (if session is valid).
    pub async fn get_token(&self) -> Option<String> {
        let guard = self.session.read().await;
        match guard.as_ref() {
            Some(session) if !session.is_expired() => {
                Some(session.token.expose_secret().to_string())
            }
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
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
        state.store_session(session).await;

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

        state.store_session(session).await;
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

        state.store_session(session).await;

        // Get token
        let retrieved_token = state.get_token().await;
        assert!(retrieved_token.is_some());
        assert_eq!(retrieved_token.unwrap(), "secret_jwt_token");
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

        state.store_session(session).await;

        // Expired session should not be returned
        assert!(state.get_session().await.is_none());
        assert!(state.get_token().await.is_none());
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

        // Initially empty
        assert!(state.get_cached_credential("aws:role1").await.is_none());

        // Cache a credential
        let cred = CachedCredential::new(
            serde_json::json!({"AccessKeyId": "AKIA..."}),
            future_timestamp(3600),
        );
        state.cache_credential("aws:role1".to_string(), cred).await;

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
        let cred =
            CachedCredential::new(serde_json::json!({"token": "expired"}), past_timestamp(100));
        state.cache_credential("github".to_string(), cred).await;

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
        state.store_session(session).await;
        state
            .cache_credential(
                "aws:role".to_string(),
                CachedCredential::new(serde_json::json!({}), future_timestamp(3600)),
            )
            .await;

        assert!(state.get_session().await.is_some());
        assert!(state.get_cached_credential("aws:role").await.is_some());

        // Clear session should also clear credential cache
        state.clear_session().await;
        assert!(state.get_session().await.is_none());
        assert!(state.get_cached_credential("aws:role").await.is_none());
    }
}
