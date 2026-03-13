// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH Agent Protocol implementation.
//!
//! This module implements the SSH agent protocol
//! ([draft-miller-ssh-agent](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent))
//! to provide seamless SSH authentication using Vouch-issued certificates.
//!
//! The agent listens on `~/.vouch/ssh-agent.sock` and handles:
//! - `SSH_AGENTC_REQUEST_IDENTITIES` - Returns available SSH certificates
//! - `SSH_AGENTC_SIGN_REQUEST` - Signs data with the user's private key

mod credentials;
mod protocol;
mod provisioning;
mod server;
mod state;

use crate::error::Result;
use crate::socket::vouch_dir;
use std::path::PathBuf;

// Re-export public types
pub use credentials::{CertificateMetadata, SshCredentials};
pub use server::SshAgentServer;
pub use state::SshAgentState;

// SSH Agent Protocol Constants
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
pub(crate) const SSH_AGENT_FAILURE: u8 = 5;
pub(crate) const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub(crate) const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub(crate) const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub(crate) const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Refresh threshold in seconds (30 minutes before expiration).
pub(crate) const REFRESH_THRESHOLD_SECONDS: i64 = 30 * 60;

/// Minimum interval between refresh attempts (5 minutes).
pub(crate) const MIN_REFRESH_INTERVAL_SECONDS: i64 = 5 * 60;

/// Default SSH key path for lazy disk loading.
pub(crate) const DEFAULT_KEY_NAME: &str = "id_ed25519_vouch";

/// Get the SSH agent socket path (~/.vouch/ssh-agent.sock).
pub fn ssh_agent_socket_path() -> Result<PathBuf> {
    Ok(vouch_dir()?.join("ssh-agent.sock"))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_agent_socket_path() {
        let path = ssh_agent_socket_path();
        assert!(path.is_ok());
        let path = path.unwrap();
        assert!(path.ends_with("ssh-agent.sock"));
    }
}
