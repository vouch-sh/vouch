//! Logout command - end current session.

use anyhow::Result;
use vouch_agent::{AgentClient, AgentError};

use crate::config::Config;

/// Run the logout command.
pub async fn run() -> Result<()> {
    let mut config = Config::load()?;

    // Check if we have a token in config
    let had_token = config.token().is_some();

    // Clear session from agent (if running)
    let agent_cleared = clear_session_in_agent().await;

    // Clear token from config
    if had_token {
        config.clear_token()?;
    }

    if had_token || agent_cleared {
        println!("Logged out successfully.");
    } else {
        println!("Not currently logged in.");
    }

    Ok(())
}

/// Clear session in the agent (if running).
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
