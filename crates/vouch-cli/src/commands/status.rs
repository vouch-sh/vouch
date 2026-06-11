// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Status command - show current session status.

use anyhow::{Context, Result, bail};
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
pub(crate) enum OutputFormat {
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
pub(crate) async fn run(server: &str, mode: OutputFormat) -> Result<()> {
    // First, try to get status from the agent (Unix only)
    #[cfg(unix)]
    if agent_status(server, mode).await? {
        return Ok(());
    }

    server_status(server, mode).await
}

/// Report an unauthenticated/expired session in the requested format.
///
/// `headline` is printed as-is in human mode, so callers style it.
fn report_unauthenticated(
    mode: OutputFormat,
    agent_running: bool,
    expires_in_seconds: Option<u64>,
    headline: &str,
    hint: &str,
) {
    match mode {
        OutputFormat::Json => {
            print_json(&StatusJson {
                authenticated: false,
                email: None,
                expires_in_seconds,
                agent_running,
            });
        }
        OutputFormat::Shell => {
            print_shell(false, None, None);
        }
        OutputFormat::Human => {
            println!("{headline}");
            println!("\n{}", style::dim(hint));
        }
    }
}

/// Report status from the agent session, if the agent answers.
///
/// Returns `true` when the agent gave a definitive answer (authenticated,
/// not authenticated, or expired) and `false` when the caller should fall
/// back to the config/server check.
#[cfg(unix)]
async fn agent_status(server: &str, mode: OutputFormat) -> Result<bool> {
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
                    print_agent_session(effective_server, &session)?;
                    println!();
                    print_all_integrations(effective_server).await;
                }
            }
            Ok(true)
        }
        Err(AgentError::NotRunning) => {
            tracing::debug!("Agent not running, checking server");
            Ok(false)
        }
        Err(AgentError::NotAuthenticated) => {
            report_unauthenticated(
                mode,
                true,
                None,
                &style::bold_red("Not authenticated."),
                "Run 'vouch login' to authenticate.",
            );
            Ok(true)
        }
        Err(AgentError::SessionExpired) => {
            report_unauthenticated(
                mode,
                true,
                Some(0),
                &style::bold_red("Session expired."),
                "Run 'vouch login' to re-authenticate.",
            );
            Ok(true)
        }
        Err(e) => {
            tracing::debug!("Agent error: {e}, falling back to server check");
            Ok(false)
        }
    }
}

/// Report status from the stored token and the server's /v1/auth/status.
async fn server_status(server: &str, mode: OutputFormat) -> Result<()> {
    let mut config = Config::load()?;
    config.set_server_url(server);

    if config.token().is_none() {
        report_unauthenticated(
            mode,
            false,
            None,
            &style::bold_red("Not authenticated."),
            "Run 'vouch login' to authenticate.",
        );
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
                    print_server_session(server, &status).await?;
                } else {
                    println!("{}", style::bold_red("Session expired."));
                    println!("\n{}", style::dim("Run 'vouch login' to re-authenticate."));
                }
            }
        },
        Err(e) => {
            report_unauthenticated(
                mode,
                false,
                None,
                &format!("{}: {e}", style::bold_red("Session invalid")),
                "Run 'vouch login' to re-authenticate.",
            );
        }
    }

    Ok(())
}

/// Print a human-readable report for a server-verified session (no agent).
async fn print_server_session(server: &str, status: &SessionStatus) -> Result<()> {
    println!("{} ({server})", style::bold_green("Authenticated"));
    if let Some(email) = &status.email {
        println!("  {:LABEL_WIDTH$} {email}", "Email:");
    }
    if let Some(device) = &status.device_name {
        println!("  {:LABEL_WIDTH$} {device}", "Device:");
    }
    if let Some(expires_in) = status.expires_in_seconds {
        print_expiry(expires_in)?;
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
        style::dim("Hint: Start the agent for faster status checks: vouch-agent --foreground")
    );
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
fn print_agent_session(server: &str, session: &SessionInfo) -> Result<()> {
    println!("{} ({server})", style::bold_green("Authenticated"));
    println!("  {:LABEL_WIDTH$} {}", "Email:", session.user_email);
    print_expiry(session.expires_in_seconds)?;
    println!("  {:LABEL_WIDTH$} {}", "Agent:", style::green("running"));
    Ok(())
}

/// Format the remaining time as a human-readable string.
///
/// Returns `"in Xh Ym"` or `"in Ym"` depending on whether hours > 0.
pub(crate) fn format_remaining_time(expires_in: u64) -> String {
    // 60 is non-zero; unwrap_or arms are unreachable.
    let remaining_mins = expires_in.checked_div(60).unwrap_or(0);
    let hours = remaining_mins.checked_div(60).unwrap_or(0);
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
///
/// # Errors
///
/// Returns an error if `expires_in` is outside the sane session lifetime
/// (one year). Such values indicate a server bug, clock skew, or corrupt
/// session state and should not be silently displayed.
fn print_expiry(expires_in: u64) -> Result<()> {
    // Real sessions are at most a few hours. Anything past one year means
    // something is wrong upstream — fail loudly rather than render gibberish.
    const MAX_SANE_SECS: u64 = 60 * 60 * 24 * 365;
    if expires_in > MAX_SANE_SECS {
        bail!(
            "session expires_in_seconds={expires_in} exceeds sane upper bound \
             ({MAX_SANE_SECS}s); refusing to render"
        );
    }

    let label = "Expires:";

    let color_fn: fn(&str) -> String = if expires_in > 3600 {
        style::green
    } else if expires_in > 900 {
        style::yellow
    } else {
        style::red
    };

    let remaining = format_remaining_time(expires_in);

    let secs = i64::try_from(expires_in).context("expires_in does not fit in i64")?;
    let duration = jiff::SignedDuration::from_secs(secs);
    let now = jiff::Zoned::now();
    if let Ok(expiry_ts) = now.timestamp().checked_add(duration) {
        let expiry = expiry_ts.to_zoned(now.time_zone().clone());
        let value = format!("{} ({remaining})", expiry.strftime("%H:%M %Z"));
        println!("  {label:<LABEL_WIDTH$} {}", color_fn(&value));
    } else {
        println!("  {label:<LABEL_WIDTH$} {}", color_fn(&remaining));
    }
    Ok(())
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
