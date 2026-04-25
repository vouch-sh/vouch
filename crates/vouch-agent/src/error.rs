// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent error types.

use std::io;
use thiserror::Error;

/// Errors that can occur when communicating with the agent.
#[derive(Debug, Error)]
pub enum AgentError {
    /// Agent daemon is not running.
    #[error("agent is not running")]
    NotRunning,

    /// Connection error (socket I/O).
    #[error("connection error: {0}")]
    Connection(#[from] io::Error),

    /// Session has expired.
    #[error("session has expired")]
    SessionExpired,

    /// No active session (not authenticated).
    #[error("not authenticated")]
    NotAuthenticated,

    /// Protocol error (invalid JSON-RPC message).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Socket path error.
    #[error("socket path error: {0}")]
    SocketPath(String),

    /// Configuration or daemon lifecycle error.
    #[error("daemon error: {0}")]
    Config(String),
}

/// Result type for agent operations.
pub type Result<T> = std::result::Result<T, AgentError>;

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_not_running() {
        let err = AgentError::NotRunning;
        assert_eq!(err.to_string(), "agent is not running");
    }

    #[test]
    fn test_error_display_session_expired() {
        let err = AgentError::SessionExpired;
        assert_eq!(err.to_string(), "session has expired");
    }

    #[test]
    fn test_error_display_not_authenticated() {
        let err = AgentError::NotAuthenticated;
        assert_eq!(err.to_string(), "not authenticated");
    }

    #[test]
    fn test_error_display_protocol() {
        let err = AgentError::Protocol("invalid message".to_string());
        assert_eq!(err.to_string(), "protocol error: invalid message");
    }

    #[test]
    fn test_error_display_socket_path() {
        let err = AgentError::SocketPath("path not found".to_string());
        assert_eq!(err.to_string(), "socket path error: path not found");
    }

    #[test]
    fn test_error_display_config() {
        let err = AgentError::Config("missing value".to_string());
        assert_eq!(err.to_string(), "daemon error: missing value");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let agent_err = AgentError::from(io_err);
        assert!(matches!(agent_err, AgentError::Connection(_)));
    }

    #[test]
    fn test_error_from_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let agent_err = AgentError::from(json_err);
        assert!(matches!(agent_err, AgentError::Serialization(_)));
    }
}
