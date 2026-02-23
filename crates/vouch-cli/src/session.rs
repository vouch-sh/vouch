// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session utilities for credential commands.

use anyhow::{Context, Result};
use secrecy::SecretString;
#[cfg(unix)]
use vouch_agent::{AgentClient, AgentError};
use vouch_common::{SessionCookie, write_cookie};

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
    Some(ResolvedSession { server_url, token })
}

/// Try to get the authentication token from the agent.
#[cfg(unix)]
async fn try_agent_token() -> Option<SecretString> {
    let mut agent = vouch_agent::AgentClient::connect().await.ok()?;
    agent.get_token().await.ok()
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
        .ok_or(crate::exit_code::CliError::ConfigError(
            "not configured — run 'vouch enroll' first".to_string(),
        ))?
        .to_string();
    let token = config
        .token()
        .ok_or(crate::exit_code::CliError::NotAuthenticated)?;
    // Clone the secret string before config is dropped
    let token = token.clone();

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
        .ok_or(crate::exit_code::CliError::NotAuthenticated)?;
    Ok(token.clone())
}

/// Store session in the agent (if running).
///
/// Returns `true` if the session was successfully stored, `false` otherwise.
/// This is a best-effort operation — agent not running is not an error.
#[cfg(unix)]
pub async fn store_session_in_agent(
    token: &str,
    email: &str,
    expires_at: &str,
    server: &str,
) -> bool {
    match AgentClient::connect().await {
        Ok(mut agent) => {
            match agent
                .store_session(token, email, expires_at, Some(server))
                .await
            {
                Ok(()) => true,
                Err(e) => {
                    tracing::debug!("Failed to store session in agent: {e}");
                    false
                }
            }
        }
        Err(AgentError::NotRunning) => {
            tracing::debug!("Agent not running, session stored in config only");
            false
        }
        Err(e) => {
            tracing::debug!("Failed to connect to agent: {e}");
            false
        }
    }
}

/// Write the session cookie file for CLI tools.
pub fn write_session_cookie_file(
    server: &str,
    token: &str,
    expires_at: jiff::Timestamp,
) -> Result<()> {
    let url = url::Url::parse(server).context("failed to parse server URL")?;
    let domain = url
        .host_str()
        .context("server URL has no host")?
        .to_string();

    let cookie = SessionCookie::new(&domain, token, expires_at.as_second());
    write_cookie(&cookie)?;

    tracing::debug!("Cookie written to ~/.vouch/cookie.txt");
    Ok(())
}

/// Store session credentials and finalize the post-authentication ceremony.
///
/// This is the shared logic between `login` and `enroll` commands. It:
/// 1. Saves the server URL and token to the config file
/// 2. Stores the session in the agent (if running, Unix only)
/// 3. Writes the session cookie file
/// 4. Auto-provisions an SSH certificate
///
/// Returns whether the agent stored the session successfully.
pub async fn store_and_finalize(
    server: &str,
    token: &str,
    email: &str,
    expires_at_str: &str,
    expires_at_ts: Option<jiff::Timestamp>,
) -> Result<bool> {
    // 1. Config save — fast local I/O, do first
    let mut config = Config::load()?;
    config.set_server_url(server);
    config.set_token(token);
    config.save()?;

    // 2. Parse timestamp (use provided or parse from string)
    let ts = match expires_at_ts {
        Some(ts) => Some(ts),
        None => expires_at_str.parse::<jiff::Timestamp>().ok(),
    };

    // 3. Agent IPC and cookie write are independent — run concurrently
    let (agent_stored, _) = tokio::join!(
        async {
            #[cfg(unix)]
            {
                store_session_in_agent(token, email, expires_at_str, server).await
            }
            #[cfg(not(unix))]
            {
                false
            }
        },
        async {
            if let Some(expires_at) = ts {
                if let Err(e) = write_session_cookie_file(server, token, expires_at) {
                    tracing::debug!("Failed to write cookie file: {e}");
                }
            } else {
                tracing::debug!("Failed to parse expiration time: {expires_at_str}");
            }
        },
    );

    // 4. Auto-provision SSH certificate
    crate::commands::credential::ssh::auto_provision(server, expires_at_str).await;

    Ok(agent_stored)
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_write_session_cookie_file_invalid_url() {
        let result = write_session_cookie_file("not-a-url", "token", jiff::Timestamp::UNIX_EPOCH);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_session_cookie_file_url_without_host() {
        let result =
            write_session_cookie_file("file:///etc/passwd", "token", jiff::Timestamp::UNIX_EPOCH);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_session_cookie_file_valid_url() {
        // This will attempt to write to ~/.vouch/cookie.txt
        // We just verify it doesn't error on URL parsing
        let ts = jiff::Timestamp::now();
        let result = write_session_cookie_file("https://vouch.example.com", "test-token", ts);
        // This may succeed or fail depending on whether ~/.vouch/ exists,
        // but it should not fail on URL parsing
        if let Err(e) = &result {
            let msg = format!("{e}");
            // Should not fail on URL parsing
            assert!(!msg.contains("failed to parse server URL"));
            assert!(!msg.contains("server URL has no host"));
        }
    }
}
