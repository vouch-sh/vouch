// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session utilities for credential commands.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};

use crate::client::VouchClient;
use crate::config::Config;

/// A resolved session: server URL and authentication token.
pub struct ResolvedSession {
    /// The server URL.
    pub server_url: String,
    /// The session token.
    pub token: SecretString,
}

/// Try to get a full session (server_url + token) from the agent.
///
/// Returns `None` if the agent is not running, has no session, or the
/// session lacks a server URL.
#[cfg(unix)]
async fn try_agent_session() -> Option<ResolvedSession> {
    let mut agent = vouch_agent::AgentClient::connect().await.ok()?;
    let session_info = agent.get_session().await.ok()?;
    let server_url = session_info.server_url?;
    let token = agent.get_token().await.ok()?;
    Some(ResolvedSession {
        server_url,
        token: SecretString::from(token),
    })
}

/// Try to get the authentication token from the agent.
#[cfg(unix)]
async fn try_agent_token() -> Option<SecretString> {
    let mut agent = vouch_agent::AgentClient::connect().await.ok()?;
    let token = agent.get_token().await.ok()?;
    Some(SecretString::from(token))
}

/// Resolve the current session (server URL + token).
///
/// Tries multiple sources in order:
/// 1. Agent (Unix only) - most reliable, always up-to-date
/// 2. Config file - saved during login/enroll
///
/// Returns an error if no session is available.
pub async fn resolve_session() -> Result<ResolvedSession> {
    // 1. Try agent first (Unix only)
    #[cfg(unix)]
    if let Some(session) = try_agent_session().await {
        return Ok(session);
    }

    // 2. Fall back to config file
    let config = Config::load().context("failed to load config")?;
    let server = config
        .server_url()
        .context("not configured - run 'vouch enroll' first")?
        .to_string();
    let token = config
        .token()
        .context("not authenticated - run 'vouch login' first")?;
    // Clone the secret string value before config is dropped
    let token = SecretString::from(token.expose_secret().to_string());

    Ok(ResolvedSession {
        server_url: server,
        token,
    })
}

/// Resolve the current authentication token.
///
/// Tries multiple sources in order:
/// 1. Agent (Unix only) - most reliable, always up-to-date
/// 2. Config file - saved during login/enroll
///
/// Returns an error if no token is available.
pub async fn resolve_token() -> Result<SecretString> {
    // 1. Try agent first (Unix only)
    #[cfg(unix)]
    if let Some(token) = try_agent_token().await {
        return Ok(token);
    }

    // 2. Fall back to config file
    let config = Config::load().context("failed to load config")?;
    let token = config
        .token()
        .context("not authenticated - run 'vouch login' first")?;
    Ok(SecretString::from(token.expose_secret().to_string()))
}

/// Get user email for AWS session name default.
///
/// Tries multiple sources in order:
/// 1. Agent (Unix only) - most reliable, always up-to-date
/// 2. Server status endpoint - fallback for edge cases
pub async fn get_user_email(server: &str) -> Option<String> {
    // 1. Try agent first (Unix only)
    #[cfg(unix)]
    if let Ok(mut agent) = vouch_agent::AgentClient::connect().await
        && let Ok(session) = agent.get_session().await
    {
        return Some(session.user_email);
    }

    // 2. Try server status endpoint (fallback)
    if let Ok(client) = VouchClient::new(server).await
        && let Ok(status) = client
            .get_authenticated::<vouch_common::SessionStatus>("/v1/auth/status")
            .await
    {
        return status.email;
    }

    None
}
