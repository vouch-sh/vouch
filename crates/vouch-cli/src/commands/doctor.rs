//! Doctor command - diagnostic checks for the Vouch environment.

use anyhow::Result;
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
use vouch_agent::AgentClient;

use crate::client::VouchClient;
use crate::config::Config;

/// Check result with status and optional message.
struct CheckResult {
    passed: bool,
    message: String,
}

impl CheckResult {
    fn pass(msg: impl Into<String>) -> Self {
        Self {
            passed: true,
            message: msg.into(),
        }
    }

    fn fail(msg: impl Into<String>) -> Self {
        Self {
            passed: false,
            message: msg.into(),
        }
    }
}

/// Run the doctor command.
pub async fn run(server: &str) -> Result<()> {
    println!("Vouch Doctor - Environment Diagnostics\n");

    let mut all_passed = true;

    // Check 1: YubiKey connectivity
    print!("YubiKey connectivity ... ");
    let yubikey_result = check_yubikey();
    print_result(&yubikey_result);
    if !yubikey_result.passed {
        all_passed = false;
    }

    // Check 2: Agent running
    print!("Agent running ... ");
    let agent_result = check_agent().await;
    print_result(&agent_result);
    if !agent_result.passed {
        all_passed = false;
    }

    // Check 3: Server reachable
    print!("Server reachable ... ");
    let server_result = check_server(server).await;
    print_result(&server_result);
    if !server_result.passed {
        all_passed = false;
    }

    // Check 4: Session valid
    print!("Session valid ... ");
    let session_result = check_session().await;
    print_result(&session_result);
    if !session_result.passed {
        all_passed = false;
    }

    // Check 5: SSH config
    print!("SSH configuration ... ");
    let ssh_result = check_ssh_config();
    print_result(&ssh_result);
    if !ssh_result.passed {
        all_passed = false;
    }

    // Summary
    println!();
    if all_passed {
        println!("All checks passed!");
    } else {
        println!("Some checks failed. Review the issues above.");
    }

    Ok(())
}

/// Print check result with color indicators.
fn print_result(result: &CheckResult) {
    if result.passed {
        println!("[OK] {}", result.message);
    } else {
        println!("[FAIL] {}", result.message);
    }
}

/// Check if a YubiKey is connected and accessible.
fn check_yubikey() -> CheckResult {
    let cfg = Cfg::init();
    match FidoKeyHidFactory::create(&cfg) {
        Ok(_device) => CheckResult::pass("FIDO2 device found"),
        Err(e) => CheckResult::fail(format!("No FIDO2 device found: {e}")),
    }
}

/// Check if the agent is running.
async fn check_agent() -> CheckResult {
    match AgentClient::connect().await {
        Ok(mut client) => {
            // Try to ping the agent
            match client.ping().await {
                Ok(_) => {
                    // Try to read PID from pid file for extra diagnostic info
                    let pid_info = vouch_agent::daemon::pid_file_path()
                        .ok()
                        .and_then(|p| std::fs::read_to_string(p).ok())
                        .and_then(|s| s.trim().parse::<u32>().ok());
                    match pid_info {
                        Some(pid) => CheckResult::pass(format!("Agent is running (PID {pid})")),
                        None => CheckResult::pass("Agent is running"),
                    }
                }
                Err(e) => CheckResult::fail(format!("Agent connection failed: {e}")),
            }
        }
        Err(e) => {
            // Check if socket exists
            if let Ok(socket_path) = vouch_agent::socket::socket_path()
                && socket_path.exists()
            {
                return CheckResult::fail(format!("Socket exists but connection failed: {e}"));
            }
            CheckResult::fail("Agent not running. Start with: vouch-agent --foreground")
        }
    }
}

/// Check if the server is reachable.
async fn check_server(server: &str) -> CheckResult {
    let client = match VouchClient::new(server) {
        Ok(c) => c,
        Err(e) => return CheckResult::fail(format!("Invalid server URL: {e}")),
    };

    let url = format!("{}/health", client.base_url());
    match client.raw_client().get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            CheckResult::pass(format!("Server at {server} is reachable"))
        }
        Ok(resp) => CheckResult::fail(format!("Server returned status: {}", resp.status())),
        Err(e) => CheckResult::fail(format!("Server unreachable: {e}")),
    }
}

/// Check if there's a valid session.
async fn check_session() -> CheckResult {
    // Try agent first
    match AgentClient::connect().await {
        Ok(mut client) => match client.get_session().await {
            Ok(session) => {
                if session.expires_in_seconds > 0 {
                    let hours = session.expires_in_seconds / 3600;
                    let mins = (session.expires_in_seconds % 3600) / 60;
                    CheckResult::pass(format!(
                        "Session valid for {}h {}m ({})",
                        hours, mins, session.user_email
                    ))
                } else {
                    CheckResult::fail("Session expired. Run: vouch login")
                }
            }
            Err(_) => CheckResult::fail("No active session. Run: vouch login"),
        },
        Err(_) => {
            // Fall back to config
            let config = match Config::load() {
                Ok(c) => c,
                Err(_) => return CheckResult::fail("No config found. Run: vouch login"),
            };

            if config.token().is_some() {
                CheckResult::pass("Session token found (agent not running for full validation)")
            } else {
                CheckResult::fail("No session token. Run: vouch login")
            }
        }
    }
}

/// Check SSH configuration for Vouch integration.
fn check_ssh_config() -> CheckResult {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return CheckResult::fail("Could not determine home directory"),
    };

    let ssh_config_path = home.join(".ssh").join("config");
    let vouch_key_path = home.join(".ssh").join("id_ed25519_vouch");

    let mut issues = Vec::new();

    // Check for Vouch SSH key
    if !vouch_key_path.exists() {
        issues.push("Vouch SSH key not found. Run: vouch setup ssh");
    }

    // Check for SSH config entry
    if ssh_config_path.exists() {
        match std::fs::read_to_string(&ssh_config_path) {
            Ok(content) => {
                if !content.contains("id_ed25519_vouch") && !content.contains("vouch") {
                    issues.push("No Vouch entry in SSH config. Run: vouch setup ssh");
                }
            }
            Err(_) => {
                issues.push("Could not read SSH config");
            }
        }
    } else {
        issues.push("SSH config not found");
    }

    if issues.is_empty() {
        CheckResult::pass("SSH configured for Vouch")
    } else {
        CheckResult::fail(issues.join("; "))
    }
}
