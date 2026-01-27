//! Status command - show current session status.

use anyhow::Result;
use ssh_key::certificate::Certificate;
use vouch_agent::{AgentClient, AgentError, SessionInfo};
use vouch_common::SessionStatus;

use crate::client::VouchClient;
use crate::commands::credential::ssh::default_key_path;
use crate::config::Config;

/// Run the status command.
pub async fn run(server: &str) -> Result<()> {
    // First, try to get session from agent
    match get_session_from_agent().await {
        Ok(session) => {
            print_agent_session(server, &session);
            print_ssh_certificate_status();
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
                print_ssh_certificate_status();
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
async fn get_session_from_agent() -> vouch_agent::Result<SessionInfo> {
    let mut agent = AgentClient::connect().await?;
    agent.get_session().await
}

/// Print session info from agent.
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

/// Print SSH certificate status by checking disk.
fn print_ssh_certificate_status() {
    let key_path = match default_key_path() {
        Ok(p) => p,
        Err(_) => return,
    };

    let cert_path_str = format!("{}-cert.pub", key_path.display());
    let cert_path = std::path::Path::new(&cert_path_str);

    if !key_path.exists() {
        println!("  SSH: no keypair");
        return;
    }

    if !cert_path.exists() {
        println!("  SSH: keypair exists, no certificate");
        println!("       Key: {}", key_path.display());
        return;
    }

    // Parse the certificate for details
    let cert_data = match std::fs::read_to_string(cert_path) {
        Ok(d) => d,
        Err(_) => {
            println!("  SSH: certificate unreadable");
            return;
        }
    };

    let cert = match Certificate::from_openssh(&cert_data) {
        Ok(c) => c,
        Err(_) => {
            println!("  SSH: certificate invalid");
            return;
        }
    };

    let valid_before = cert.valid_before();
    let now_unix = jiff::Timestamp::now().as_second();
    let valid_before_i64 = i64::try_from(valid_before).unwrap_or(i64::MAX);

    if valid_before_i64 <= now_unix {
        println!("  SSH: certificate expired");
        println!("       Certificate: {cert_path_str}");
        return;
    }

    let remaining_secs = valid_before_i64 - now_unix;
    let remaining = jiff::SignedDuration::from_mins(remaining_secs / 60);

    let principals: Vec<String> = cert
        .valid_principals()
        .iter()
        .map(|s| s.to_string())
        .collect();

    println!("  SSH: certificate valid ({remaining:#} remaining)");
    println!("       Certificate: {cert_path_str}");
    if !principals.is_empty() {
        println!("       Principals: {}", principals.join(", "));
    }
    println!("       Serial: {}", cert.serial());

    // Show SSH agent socket if configured
    if let Ok(socket_path) = vouch_agent::ssh_agent_socket_path()
        && socket_path.exists()
    {
        println!("       Agent socket: {}", socket_path.display());
    }
}
