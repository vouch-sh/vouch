// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent state and session management.

use jiff::Timestamp;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

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

/// Agent state (shared across connections).
#[derive(Debug, Default)]
pub struct AgentState {
    /// Current session (if authenticated).
    session: RwLock<Option<Session>>,
}

impl AgentState {
    /// Create a new agent state.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            session: RwLock::new(None),
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

    /// Clear the current session.
    pub async fn clear_session(&self) {
        let mut guard = self.session.write().await;
        *guard = None;
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
