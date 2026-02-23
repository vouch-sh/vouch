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
    LABEL_WIDTH, SshIntegration, SsmIntegration, print_integration_status,
};
use crate::style;

/// Output format for the status command.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable output (default).
    #[default]
    Human,
    /// JSON output.
    Json,
    /// Shell-evaluable key=value pairs for use in shell hooks.
    Shell,
}

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

/// Print shell-evaluable key=value pairs to stdout.
///
/// Output format:
/// ```text
/// VOUCH_AUTHENTICATED=1
/// VOUCH_EMAIL=user@example.com
/// VOUCH_EXPIRES_IN=28800
/// ```
///
/// Or when not authenticated:
/// ```text
/// VOUCH_AUTHENTICATED=0
/// ```
pub(crate) fn print_shell(
    authenticated: bool,
    email: Option<&str>,
    expires_in_seconds: Option<u64>,
) {
    if authenticated {
        println!("VOUCH_AUTHENTICATED=1");
        if let Some(email) = email {
            println!("VOUCH_EMAIL={email}");
        }
        if let Some(expires_in) = expires_in_seconds {
            println!("VOUCH_EXPIRES_IN={expires_in}");
        }
    } else {
        println!("VOUCH_AUTHENTICATED=0");
    }
}

/// Run the status command.
pub async fn run(server: &str, mode: OutputFormat) -> Result<()> {
    // First, try to get session from agent (Unix only)
    #[cfg(unix)]
    match get_session_from_agent().await {
        Ok(session) => {
            // Prefer the server URL from the agent (it knows the real server),
            // falling back to the CLI-resolved server URL.
            let effective_server = session.server_url.as_deref().unwrap_or(server);
            match mode {
                OutputFormat::Json => {
                    print_json(&StatusJson {
                        authenticated: true,
                        email: Some(session.user_email.clone()),
                        expires_in_seconds: Some(session.expires_in_seconds),
                        agent_running: true,
                    });
                }
                OutputFormat::Shell => {
                    print_shell(
                        true,
                        Some(&session.user_email),
                        Some(session.expires_in_seconds),
                    );
                }
                OutputFormat::Human => {
                    print_agent_session(effective_server, &session);
                    println!();
                    print_all_integrations(effective_server).await;
                }
            }
            return Ok(());
        }
        Err(AgentError::NotRunning) => {
            tracing::debug!("Agent not running, checking server");
        }
        Err(AgentError::NotAuthenticated) => {
            match mode {
                OutputFormat::Json => {
                    print_json(&StatusJson {
                        authenticated: false,
                        email: None,
                        expires_in_seconds: None,
                        agent_running: true,
                    });
                }
                OutputFormat::Shell => {
                    print_shell(false, None, None);
                }
                OutputFormat::Human => {
                    println!("{}", style::bold_red("Not authenticated."));
                    println!("\n{}", style::dim("Run 'vouch login' to authenticate."));
                }
            }
            return Ok(());
        }
        Err(AgentError::SessionExpired) => {
            match mode {
                OutputFormat::Json => {
                    print_json(&StatusJson {
                        authenticated: false,
                        email: None,
                        expires_in_seconds: Some(0),
                        agent_running: true,
                    });
                }
                OutputFormat::Shell => {
                    print_shell(false, None, None);
                }
                OutputFormat::Human => {
                    println!("{}", style::bold_red("Session expired."));
                    println!("\n{}", style::dim("Run 'vouch login' to re-authenticate."));
                }
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
        match mode {
            OutputFormat::Json => {
                print_json(&StatusJson {
                    authenticated: false,
                    email: None,
                    expires_in_seconds: None,
                    agent_running: false,
                });
            }
            OutputFormat::Shell => {
                print_shell(false, None, None);
            }
            OutputFormat::Human => {
                println!("{}", style::bold_red("Not authenticated."));
                println!("\n{}", style::dim("Run 'vouch login' to authenticate."));
            }
        }
        return Ok(());
    }

    let client = VouchClient::new(server).await?;

    match client
        .get_authenticated::<SessionStatus>("/v1/auth/status")
        .await
    {
        Ok(status) => match mode {
            OutputFormat::Json => {
                print_json(&StatusJson {
                    authenticated: status.authenticated,
                    email: status.email.clone(),
                    expires_in_seconds: status.expires_in_seconds,
                    agent_running: false,
                });
            }
            OutputFormat::Shell => {
                print_shell(
                    status.authenticated,
                    status.email.as_deref(),
                    status.expires_in_seconds,
                );
            }
            OutputFormat::Human => {
                if status.authenticated {
                    println!("{} ({server})", style::bold_green("Authenticated"));
                    if let Some(email) = &status.email {
                        println!("  {:LABEL_WIDTH$} {email}", "Email:");
                    }
                    if let Some(device) = &status.device_name {
                        println!("  {:LABEL_WIDTH$} {device}", "Device:");
                    }
                    if let Some(expires_in) = status.expires_in_seconds {
                        print_expiry(expires_in);
                    }
                    println!(
                        "  {:LABEL_WIDTH$} {}",
                        "Agent:",
                        style::yellow("not running")
                    );
                    println!();
                    print_all_integrations(server).await;
                    println!(
                        "\n{}",
                        style::dim(
                            "Hint: Start the agent for faster status checks: vouch-agent --foreground"
                        )
                    );
                } else {
                    println!("{}", style::bold_red("Session expired."));
                    println!("\n{}", style::dim("Run 'vouch login' to re-authenticate."));
                }
            }
        },
        Err(e) => match mode {
            OutputFormat::Json => {
                print_json(&StatusJson {
                    authenticated: false,
                    email: None,
                    expires_in_seconds: None,
                    agent_running: false,
                });
            }
            OutputFormat::Shell => {
                print_shell(false, None, None);
            }
            OutputFormat::Human => {
                println!("{}: {e}", style::bold_red("Session invalid"));
                println!("\n{}", style::dim("Run 'vouch login' to re-authenticate."));
            }
        },
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
    println!("{} ({server})", style::bold_green("Authenticated"));
    println!("  {:LABEL_WIDTH$} {}", "Email:", session.user_email);
    print_expiry(session.expires_in_seconds);
    println!("  {:LABEL_WIDTH$} {}", "Agent:", style::green("running"));
}

/// Format the remaining time as a human-readable string.
///
/// Returns `"in Xh Ym"` or `"in Ym"` depending on whether hours > 0.
pub(crate) fn format_remaining_time(expires_in: u64) -> String {
    let remaining_mins = expires_in / 60;
    let hours = remaining_mins / 60;
    let mins = remaining_mins % 60;

    if hours > 0 {
        format!("in {hours}h {mins}m")
    } else {
        format!("in {mins}m")
    }
}

/// Print expiry time with wall-clock time and remaining duration.
///
/// Color: green (>1 h), yellow (<=1 h), red (<=15 min).
fn print_expiry(expires_in: u64) {
    let label = "Expires:";

    // Color based on remaining time
    let color_fn: fn(&str) -> String = if expires_in > 3600 {
        style::green
    } else if expires_in > 900 {
        style::yellow
    } else {
        style::red
    };

    let remaining = format_remaining_time(expires_in);

    let duration = jiff::SignedDuration::from_secs(expires_in as i64);
    let now = jiff::Zoned::now();
    if let Ok(expiry_ts) = now.timestamp().checked_add(duration) {
        let expiry = expiry_ts.to_zoned(now.time_zone().clone());
        let value = format!("{} ({remaining})", expiry.strftime("%H:%M %Z"));
        println!("  {label:<LABEL_WIDTH$} {}", color_fn(&value));
    } else {
        println!("  {label:<LABEL_WIDTH$} {}", color_fn(&remaining));
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_format_remaining_time_hours_and_minutes() {
        assert_eq!(format_remaining_time(7200), "in 2h 0m");
        assert_eq!(format_remaining_time(3661), "in 1h 1m");
        assert_eq!(format_remaining_time(28800), "in 8h 0m");
    }

    #[test]
    fn test_format_remaining_time_minutes_only() {
        assert_eq!(format_remaining_time(300), "in 5m");
        assert_eq!(format_remaining_time(59), "in 0m");
        assert_eq!(format_remaining_time(0), "in 0m");
    }
}
