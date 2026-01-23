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
}

/// Result type for agent operations.
pub type Result<T> = std::result::Result<T, AgentError>;
