//! vouch local credential agent
//!
//! The agent runs as a daemon and handles credential requests from:
//! - Git credential helper
//! - AWS credential_process
//! - Direct CLI requests
//! - AI agent SDKs

use serde::{Deserialize, Serialize};
use vouch_common::{CredentialTarget, IssuedCredential, PresenceType};

/// Request from a client to the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentRequest {
    /// Get a credential
    GetCredential {
        target: CredentialTarget,
        /// Optional delegation token (for agents)
        delegation_token: Option<String>,
    },
    /// Check if agent is running and authenticated
    Ping,
    /// Get current status
    Status,
}

/// Response from agent to client
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentResponse {
    /// Credential issued
    Credential {
        credential: IssuedCredential,
        presence: PresenceType,
        expires_at: String,
    },
    /// Pong response to ping
    Pong {
        version: String,
        authenticated: bool,
    },
    /// Status response
    Status {
        authenticated: bool,
        user_email: Option<String>,
        session_expires_at: Option<String>,
        cached_credentials: u32,
    },
    /// Error response
    Error {
        code: String,
        message: String,
    },
}

/// Git credential helper protocol
pub mod git {
    use std::collections::HashMap;

    /// Parse git credential helper input
    pub fn parse_input(input: &str) -> HashMap<String, String> {
        input
            .lines()
            .filter_map(|line| {
                let mut parts = line.splitn(2, '=');
                Some((parts.next()?.to_string(), parts.next()?.to_string()))
            })
            .collect()
    }

    /// Format git credential helper output
    pub fn format_output(username: &str, password: &str) -> String {
        format!("username={}\npassword={}\n", username, password)
    }
}

/// AWS credential_process protocol
pub mod aws {
    use serde::Serialize;

    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CredentialProcessOutput {
        pub version: u32,
        pub access_key_id: String,
        pub secret_access_key: String,
        pub session_token: String,
        pub expiration: String,
    }

    impl CredentialProcessOutput {
        pub fn new(
            access_key_id: String,
            secret_access_key: String,
            session_token: String,
            expiration: String,
        ) -> Self {
            Self {
                version: 1,
                access_key_id,
                secret_access_key,
                session_token,
                expiration,
            }
        }
    }
}
