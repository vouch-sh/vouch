// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Status command - show current session status.

use anyhow::Result;
use serde::Serialize;
#[cfg(unix)]
use vouch_agent::{AgentClient, AgentError, SessionInfo};
use vouch_common::SessionStatus;

use crate::client::VouchClient;
use crate::config::Config;
use crate::integrations::{
    AwsIntegration, CargoIntegration, DockerIntegration, EksIntegration, GitHubIntegration,
    SshIntegration, SsmIntegration, print_integration_status,
};

/// JSON output for `vouch status --json`.
#[derive(Serialize)]
struct StatusJson {
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in_seconds: Option<u64>,
    agent_running: bool,
}

/// Print a serializable value as JSON to stdout.
fn print_json<T: Serialize>(value: &T) {
    if let Ok(s) = serde_json::to_string_pretty(value) {
        println!("{s}");
    }
}

/// Run the status command.
pub async fn run(server: &str, json: bool) -> Result<()> {
    // First, try to get session from agent (Unix only)
    #[cfg(unix)]
    match get_session_from_agent().await {
        Ok(session) => {
            // Prefer the server URL from the agent (it knows the real server),
            // falling back to the CLI-resolved server URL.
            let effective_server = session.server_url.as_deref().unwrap_or(server);
            if json {
                print_json(&StatusJson {
                    authenticated: true,
                    email: Some(session.user_email.clone()),
                    expires_in_seconds: Some(session.expires_in_seconds),
                    agent_running: true,
                });
            } else {
                print_agent_session(effective_server, &session);
                print_all_integrations(effective_server).await;
            }
            return Ok(());
        }
        Err(AgentError::NotRunning) => {
            tracing::debug!("Agent not running, checking server");
        }
        Err(AgentError::NotAuthenticated) => {
            if json {
                print_json(&StatusJson {
                    authenticated: false,
                    email: None,
                    expires_in_seconds: None,
                    agent_running: true,
                });
            } else {
                println!("Not authenticated.");
                println!("\nRun 'vouch login' to authenticate.");
            }
            return Ok(());
        }
        Err(AgentError::SessionExpired) => {
            if json {
                print_json(&StatusJson {
                    authenticated: false,
                    email: None,
                    expires_in_seconds: Some(0),
                    agent_running: true,
                });
            } else {
                println!("Session expired.");
                println!("\nRun 'vouch login' to re-authenticate.");
            }
            return Ok(());
        }
        Err(e) => {
            tracing::debug!("Agent error: {e}, falling back to server check");
        }
    }

    // Fall back to config/server check
    let config = Config::load()?;

    if config.token().is_none() {
        if json {
            print_json(&StatusJson {
                authenticated: false,
                email: None,
                expires_in_seconds: None,
                agent_running: false,
            });
        } else {
            println!("Not authenticated.");
            println!("\nRun 'vouch login' to authenticate.");
        }
        return Ok(());
    }

    let client = VouchClient::new(server)?;

    match client
        .get_authenticated::<SessionStatus>("/v1/auth/status")
        .await
    {
        Ok(status) => {
            if json {
                print_json(&StatusJson {
                    authenticated: status.authenticated,
                    email: status.email.clone(),
                    expires_in_seconds: status.expires_in_seconds,
                    agent_running: false,
                });
            } else if status.authenticated {
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
            if json {
                print_json(&StatusJson {
                    authenticated: false,
                    email: None,
                    expires_in_seconds: None,
                    agent_running: false,
                });
            } else {
                println!("Session invalid: {e}");
                println!("\nRun 'vouch login' to re-authenticate.");
            }
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
///
/// Starts the GitHub HTTP request early so network latency overlaps with
/// local integration checks.
async fn print_all_integrations(server: &str) {
    // Start GitHub check early (network call)
    let github = GitHubIntegration::new(server);
    let github_future = github.check_and_print();

    // Print local integrations while GitHub check runs
    print_integration_status(&SshIntegration::new());
    print_integration_status(&AwsIntegration::new());
    print_integration_status(&EksIntegration::new());
    print_integration_status(&SsmIntegration::new());
    print_integration_status(&DockerIntegration::new());
    print_integration_status(&CargoIntegration::new());

    // Now await the GitHub result
    github_future.await;
}
