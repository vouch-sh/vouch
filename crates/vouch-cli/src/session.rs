// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session utilities for credential commands.

use crate::client::VouchClient;
use crate::config::Config;

/// Get user email for AWS session name default.
///
/// Tries multiple sources in order:
/// 1. Agent (Unix only) - most reliable, always up-to-date
/// 2. Config file - saved during login/enroll
/// 3. Server status endpoint - fallback for edge cases
pub async fn get_user_email(server: &str) -> Option<String> {
    // 1. Try agent first (Unix only)
    #[cfg(unix)]
    if let Ok(mut agent) = vouch_agent::AgentClient::connect().await
        && let Ok(session) = agent.get_session().await
    {
        return Some(session.user_email);
    }

    // 2. Try config
    if let Ok(config) = Config::load()
        && let Some(email) = config.email()
    {
        return Some(email.to_string());
    }

    // 3. Try server status endpoint (fallback)
    if let Ok(client) = VouchClient::new(server)
        && let Ok(status) = client
            .get_authenticated::<vouch_common::SessionStatus>("/v1/auth/status")
            .await
    {
        return status.email;
    }

    None
}
