// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Logout command - end current session.

use anyhow::Result;
use secrecy::ExposeSecret;
#[cfg(unix)]
use vouch_agent::{AgentClient, AgentError};

use crate::config::Config;
use vouch_common::clear_cookie;

/// Run the logout command.
pub async fn run(server: &str) -> Result<()> {
    let mut config = Config::load()?;
    config.set_server_url(server);

    // Check if we have a token in config
    let had_token = config.token().is_some();

    // Best-effort server-side revocation before clearing local state.
    if had_token {
        revoke_on_server(&config).await;
    }

    // Clear session from agent (if running)
    #[cfg(unix)]
    let agent_cleared = clear_session_in_agent().await;
    #[cfg(not(unix))]
    let agent_cleared = false;

    // Clear token from config
    if had_token {
        config.clear_token();
        config.save()?;
    }

    // Clear cookie file
    let cookie_cleared = match clear_cookie() {
        Ok(()) => true,
        Err(e) => {
            tracing::debug!("Failed to clear cookie: {e}");
            false
        }
    };

    if had_token || agent_cleared || cookie_cleared {
        println!("Logged out successfully.");
    } else {
        println!("Not currently logged in.");
    }

    Ok(())
}

/// Revoke the token server-side via POST /oauth/revoke (RFC 7009).
///
/// Uses `private_key_jwt` (RFC 7523) client authentication when a FAPI
/// key and client_id are available. Best-effort: failures are logged at
/// debug level and do not block local cleanup.
async fn revoke_on_server(config: &Config) {
    let (Some(token), Some(client_id), Some(server_url)) =
        (config.token(), config.client_id(), config.server_url())
    else {
        tracing::debug!("Skipping server revocation: missing token, client_id, or server_url");
        return;
    };

    let fapi_key = match crate::client::load_fapi_key() {
        Some(key) => key,
        None => {
            tracing::debug!("Skipping server revocation: no FAPI key available");
            return;
        }
    };

    let revoke_url = format!("{server_url}/oauth/revoke");

    let assertion = match vouch_cli::fapi::ClientAssertionBuilder::new(client_id, &revoke_url)
        .build(&fapi_key)
    {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!("Failed to build client assertion for revocation: {e}");
            return;
        }
    };

    let client = match vouch_cli::http::ReqwestClient::new() {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("Failed to create HTTP client for revocation: {e}");
            return;
        }
    };

    let form = serde_urlencoded::to_string([
        ("token", token.expose_secret()),
        ("client_id", client_id),
        ("client_assertion", assertion.assertion.as_str()),
        ("client_assertion_type", assertion.assertion_type),
    ]);

    let form_body = match form {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!("Failed to encode revocation form: {e}");
            return;
        }
    };

    use vouch_cli::http::HttpClient;
    match client
        .request(
            "POST",
            &revoke_url,
            Some(form_body.as_bytes()),
            Some("application/x-www-form-urlencoded"),
            None,
            None,
        )
        .await
    {
        Ok(resp) if resp.is_success() => {
            tracing::debug!("Server-side token revocation succeeded");
        }
        Ok(resp) => {
            tracing::debug!(
                "Server-side token revocation returned status {}",
                resp.status
            );
        }
        Err(e) => {
            tracing::debug!("Server-side token revocation failed: {e}");
        }
    }
}

/// Clear session in the agent (if running).
#[cfg(unix)]
async fn clear_session_in_agent() -> bool {
    match AgentClient::connect().await {
        Ok(mut agent) => match agent.clear_session().await {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!("Failed to clear session in agent: {e}");
                false
            }
        },
        Err(AgentError::NotRunning) => {
            tracing::debug!("Agent not running");
            false
        }
        Err(e) => {
            tracing::debug!("Failed to connect to agent: {e}");
            false
        }
    }
}
