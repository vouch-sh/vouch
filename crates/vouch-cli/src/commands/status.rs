// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Status command - show current session status.

use anyhow::Result;
#[cfg(unix)]
use vouch_agent::{AgentClient, AgentError, SessionInfo};
use vouch_common::SessionStatus;

use crate::client::VouchClient;
use crate::config::Config;
use crate::integrations::{
    AwsIntegration, CargoIntegration, DockerIntegration, GcpIntegration, GitHubIntegration,
    K8sIntegration, SshIntegration, print_integration_status,
};

/// Run the status command.
pub async fn run(server: &str) -> Result<()> {
    // First, try to get session from agent (Unix only)
    #[cfg(unix)]
    match get_session_from_agent().await {
        Ok(session) => {
            print_agent_session(server, &session);
            print_all_integrations(server).await;
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
                println!("Authenticated ({server})");
                if let Some(email) = &status.email {
                    println!("  Email: {email}");
                }
                if let Some(device) = &status.device_name {
                    println!("  Device: {device}");
                }
                if let Some(expires_in) = status.expires_in_seconds {
                    print_expiry(expires_in);
                }
                println!("  Agent: not running");
                print_all_integrations(server).await;
                println!(
                    "\nHint: Start the agent for faster status checks: vouch-agent --foreground"
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
#[cfg(unix)]
async fn get_session_from_agent() -> vouch_agent::Result<SessionInfo> {
    let mut agent = AgentClient::connect().await?;
    agent.get_session().await
}

/// Print session info from agent.
#[cfg(unix)]
fn print_agent_session(server: &str, session: &SessionInfo) {
    println!("Authenticated ({server})");
    println!("  Email: {}", session.user_email);
    print_expiry(session.expires_in_seconds);
    println!("  Agent: running");
}

/// Print expiry time.
fn print_expiry(expires_in: u64) {
    let remaining = jiff::SignedDuration::from_mins((expires_in / 60) as i64);
    println!("  Expires in: {remaining:#}");
}

/// Print all integration statuses.
async fn print_all_integrations(server: &str) {
    print_integration_status(&SshIntegration::new());
    print_integration_status(&AwsIntegration::new());
    print_integration_status(&GcpIntegration::new());
    print_integration_status(&K8sIntegration::new());
    print_integration_status(&DockerIntegration::new());
    print_integration_status(&CargoIntegration::new());
    GitHubIntegration::new(server).check_and_print().await;
}
