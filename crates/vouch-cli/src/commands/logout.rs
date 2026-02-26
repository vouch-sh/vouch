// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Logout command - end current session.

use anyhow::Result;
#[cfg(unix)]
use vouch_agent::{AgentClient, AgentError};

use crate::config::Config;
use vouch_common::clear_cookie;

/// Run the logout command.
pub async fn run() -> Result<()> {
    let mut config = Config::load()?;

    // Check if we have a token in config
    let had_token = config.token().is_some();

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
