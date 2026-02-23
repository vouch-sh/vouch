// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP client configuration with appropriate timeouts.
//!
//! Provides pre-configured HTTP clients for different contexts, ensuring
//! consistent timeout behavior across the codebase.

use std::time::Duration;

/// Timeout values for different contexts.
pub mod timeouts {
    use super::Duration;

    /// Total timeout for credential helper operations.
    pub const CREDENTIAL_TOTAL: Duration = Duration::from_secs(10);
    /// Connection timeout for credential helper operations.
    pub const CREDENTIAL_CONNECT: Duration = Duration::from_secs(5);

    /// Total timeout for interactive CLI operations.
    pub const INTERACTIVE_TOTAL: Duration = Duration::from_secs(30);
    /// Connection timeout for interactive CLI operations.
    pub const INTERACTIVE_CONNECT: Duration = Duration::from_secs(10);

    /// Total timeout for agent background operations.
    pub const AGENT_TOTAL: Duration = Duration::from_secs(5);
    /// Connection timeout for agent background operations.
    pub const AGENT_CONNECT: Duration = Duration::from_secs(3);

    /// Total timeout for server-side API calls.
    pub const SERVER_TOTAL: Duration = Duration::from_secs(15);
    /// Connection timeout for server-side API calls.
    pub const SERVER_CONNECT: Duration = Duration::from_secs(5);
}

/// Create an HTTP client for credential helper operations.
///
/// Uses short timeouts (10s total, 5s connect) for fast failure.
/// Credential helpers are called by tools (aws, docker, gcloud) that have
/// their own retry logic.
///
/// # Arguments
///
/// * `user_agent` - The User-Agent header value for outgoing requests.
///
/// # Errors
///
/// Returns an error if the client cannot be built.
pub fn credential_client(user_agent: &str) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(timeouts::CREDENTIAL_TOTAL)
        .connect_timeout(timeouts::CREDENTIAL_CONNECT)
        .build()
}

/// Create an HTTP client for interactive CLI operations.
///
/// Uses longer timeouts (30s total, 10s connect) since users expect
/// some latency for interactive commands.
///
/// # Arguments
///
/// * `user_agent` - The User-Agent header value for outgoing requests.
///
/// # Errors
///
/// Returns an error if the client cannot be built.
pub fn interactive_client(user_agent: &str) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(timeouts::INTERACTIVE_TOTAL)
        .connect_timeout(timeouts::INTERACTIVE_CONNECT)
        .build()
}

/// Create an HTTP client for agent background operations.
///
/// Uses short timeouts (5s total, 3s connect) for best-effort,
/// non-blocking background work.
///
/// # Arguments
///
/// * `user_agent` - The User-Agent header value for outgoing requests.
///
/// # Errors
///
/// Returns an error if the client cannot be built.
pub fn agent_client(user_agent: &str) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(timeouts::AGENT_TOTAL)
        .connect_timeout(timeouts::AGENT_CONNECT)
        .build()
}

/// Create an HTTP client for server-side API calls.
///
/// Uses moderate timeouts (15s total, 5s connect) since external
/// APIs may be slower but we still want to fail reasonably fast.
///
/// # Arguments
///
/// * `user_agent` - The User-Agent header value for outgoing requests.
///
/// # Errors
///
/// Returns an error if the client cannot be built.
pub fn server_client(user_agent: &str) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(timeouts::SERVER_TOTAL)
        .connect_timeout(timeouts::SERVER_CONNECT)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_client_builds() {
        let client = credential_client("test-credential/1.0.0");
        assert!(client.is_ok());
    }

    #[test]
    fn test_interactive_client_builds() {
        let client = interactive_client("test-cli/1.0.0");
        assert!(client.is_ok());
    }

    #[test]
    fn test_agent_client_builds() {
        let client = agent_client("test-agent/1.0.0");
        assert!(client.is_ok());
    }

    #[test]
    fn test_server_client_builds() {
        let client = server_client("test-agent");
        assert!(client.is_ok());
    }

    #[test]
    fn test_timeout_values() {
        // Verify timeout relationships make sense
        assert!(timeouts::CREDENTIAL_CONNECT < timeouts::CREDENTIAL_TOTAL);
        assert!(timeouts::INTERACTIVE_CONNECT < timeouts::INTERACTIVE_TOTAL);
        assert!(timeouts::AGENT_CONNECT < timeouts::AGENT_TOTAL);
        assert!(timeouts::SERVER_CONNECT < timeouts::SERVER_TOTAL);

        // Agent should be fastest, interactive slowest
        assert!(timeouts::AGENT_TOTAL < timeouts::CREDENTIAL_TOTAL);
        assert!(timeouts::CREDENTIAL_TOTAL < timeouts::SERVER_TOTAL);
        assert!(timeouts::SERVER_TOTAL < timeouts::INTERACTIVE_TOTAL);
    }
}
