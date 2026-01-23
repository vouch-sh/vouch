//! Session management types
//!
//! A session represents an authenticated user with a verified device.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A user session after successful FIDO2 authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID
    pub id: Uuid,
    /// User who owns this session
    pub user_id: Uuid,
    /// Device (authenticator) used
    pub device_id: Uuid,
    /// When the session was created
    pub created_at: Timestamp,
    /// When the session expires (default 8 hours)
    pub expires_at: Timestamp,
    /// Last activity timestamp
    pub last_used_at: Timestamp,
    /// IP address of session creation
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
}

/// Session status for CLI display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    /// Is there an active session?
    pub authenticated: bool,
    /// User email if authenticated
    pub user_email: Option<String>,
    /// Time remaining in session
    pub expires_in_seconds: Option<i64>,
    /// Device name used for auth
    pub device_name: Option<String>,
    /// Active delegations count
    pub active_delegations: u32,
}

/// Request to start a new session (after FIDO2 auth)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    /// FIDO2 assertion response (base64 encoded)
    pub assertion: String,
    /// Challenge that was signed
    pub challenge: String,
    /// Client data JSON (base64 encoded)
    pub client_data: String,
}

/// Response with session token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    /// JWT session token
    pub token: String,
    /// Session details
    pub session: Session,
}
