//! Status command - show current session status.

use anyhow::Result;
use vouch_agent::{AgentClient, AgentError, SessionInfo};
use vouch_common::SessionStatus;

use crate::client::VouchClient;
use crate::config::Config;

/// Run the status command.
pub async fn run(server: &str) -> Result<()> {
    // First, try to get session from agent
    match get_session_from_agent().await {
        Ok(session) => {
            print_agent_session(&session);
            return Ok(());
        }
        Err(AgentError::NotRunning) => {
            // Agent not running, fall back to server check
            tracing::debug!("Agent not running, checking server");
        }
        Err(AgentError::NotAuthenticated) => {
            println!("Not authenticated.");
            println!("\nRun 'vouch login' to authenticate.");
            return Ok(());
        }
        Err(AgentError::SessionExpired) => {
            println!("Session expired.");
            println!("\nRun 'vouch login' to re-authenticate.");
            return Ok(());
        }
        Err(e) => {
            tracing::debug!("Agent error: {e}, falling back to server check");
        }
    }

    // Fall back to config/server check
    let config = Config::load()?;

    if config.token().is_none() {
        println!("Not authenticated.");
        println!("\nRun 'vouch login' to authenticate.");
        return Ok(());
    }

    let client = VouchClient::new(server)?;

    match client
        .get_authenticated::<SessionStatus>("/v1/auth/status")
        .await
    {
        Ok(status) => {
            if status.authenticated {
                println!("Authenticated");
                if let Some(email) = &status.email {
                    println!("  Email: {email}");
                }
                if let Some(device) = &status.device_name {
                    println!("  Device: {device}");
                }
                if let Some(expires_in) = status.expires_in_seconds {
                    print_expiry(expires_in);
                }
                println!(
                    "\nNote: Start the agent for faster status checks: vouch-agent --foreground"
                );
            } else {
                println!("Session expired.");
                println!("\nRun 'vouch login' to re-authenticate.");
            }
        }
        Err(e) => {
            // Token might be invalid/expired
            println!("Session invalid: {e}");
            println!("\nRun 'vouch login' to re-authenticate.");
        }
    }

    Ok(())
}

/// Get session from the agent.
async fn get_session_from_agent() -> vouch_agent::Result<SessionInfo> {
    let mut agent = AgentClient::connect().await?;
    agent.get_session().await
}

/// Print session info from agent.
fn print_agent_session(session: &SessionInfo) {
    println!("Authenticated (via agent)");
    println!("  Email: {}", session.user_email);
    print_expiry(session.expires_in_seconds);
}

/// Print expiry time.
fn print_expiry(expires_in: u64) {
    let hours = expires_in / 3600;
    let minutes = (expires_in % 3600) / 60;
    if hours > 0 {
        println!("  Expires in: {hours}h {minutes}m");
    } else {
        println!("  Expires in: {minutes}m");
    }
}
