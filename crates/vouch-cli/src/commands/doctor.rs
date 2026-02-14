// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Doctor command - diagnostic checks for the Vouch environment.

use anyhow::{Result, bail};
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
#[cfg(unix)]
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
///
/// Returns an error if any checks fail, so the CLI exits with a non-zero code.
/// When `quiet` is true, all output is suppressed (exit code only).
pub async fn run(server: &str, quiet: bool) -> Result<()> {
    if !quiet {
        println!("Vouch Doctor - Environment Diagnostics\n");
    }

    let mut all_passed = true;

    // Check 1: YubiKey connectivity
    if !quiet {
        print!("YubiKey connectivity ... ");
    }
    let yubikey_result = check_yubikey();
    if !quiet {
        print_result(&yubikey_result);
    }
    if !yubikey_result.passed {
        all_passed = false;
    }

    // Check 2: Agent running (Unix only — agent requires Unix sockets)
    #[cfg(unix)]
    {
        if !quiet {
            print!("Agent running ... ");
        }
        let agent_result = check_agent().await;
        if !quiet {
            print_result(&agent_result);
        }
        if !agent_result.passed {
            all_passed = false;
        }
    }

    // Check 3: Server reachable
    if !quiet {
        print!("Server reachable ... ");
    }
    let server_result = check_server(server).await;
    if !quiet {
        print_result(&server_result);
    }
    if !server_result.passed {
        all_passed = false;
    }

    // Check 4: Session valid
    if !quiet {
        print!("Session valid ... ");
    }
    let session_result = check_session().await;
    if !quiet {
        print_result(&session_result);
    }
    if !session_result.passed {
        all_passed = false;
    }

    // Check 5: SSH config
    if !quiet {
        print!("SSH configuration ... ");
    }
    let ssh_result = check_ssh_config();
    if !quiet {
        print_result(&ssh_result);
    }
    if !ssh_result.passed {
        all_passed = false;
    }

    // Check 6: EKS config
    if !quiet {
        print!("EKS configuration ... ");
    }
    let eks_result = check_eks_config();
    if !quiet {
        print_result(&eks_result);
    }
    if !eks_result.passed {
        all_passed = false;
    }

    // Check 7: Server URL security
    if !quiet {
        print!("Server URL security ... ");
    }
    let security_result = check_server_url_security(server);
    if !quiet {
        print_result(&security_result);
    }
    if !security_result.passed {
        all_passed = false;
    }

    // Summary
    if !quiet {
        println!();
    }
    if all_passed {
        if !quiet {
            println!("All checks passed!");
        }
        Ok(())
    } else {
        if !quiet {
            println!("Some checks failed. Review the issues above.");
        }
        bail!("doctor: one or more checks failed")
    }
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
#[cfg(unix)]
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
    // Try agent first (Unix only — agent requires Unix sockets)
    #[cfg(unix)]
    if let Ok(mut client) = AgentClient::connect().await {
        return match client.get_session().await {
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
        };
    }

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

/// Check EKS configuration for Vouch integration.
fn check_eks_config() -> CheckResult {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return CheckResult::fail("Could not determine home directory"),
    };

    // Check KUBECONFIG env var first, then default path
    let kubeconfig_path = std::env::var("KUBECONFIG")
        .ok()
        .and_then(|k| k.split(':').next().map(std::path::PathBuf::from))
        .unwrap_or_else(|| home.join(".kube").join("config"));

    if !kubeconfig_path.exists() {
        return CheckResult::pass("No kubeconfig found (EKS not configured)");
    }

    match std::fs::read_to_string(&kubeconfig_path) {
        Ok(content) => {
            // Check if there's a Vouch EKS user configured
            if content.contains("vouch-eks-") {
                CheckResult::pass("EKS configured for Vouch")
            } else {
                CheckResult::pass(
                    "Kubeconfig exists (no Vouch EKS integration). Run: vouch setup eks --cluster <name>",
                )
            }
        }
        Err(_) => CheckResult::fail("Could not read kubeconfig"),
    }
}

/// Check if the server URL uses secure transport.
fn check_server_url_security(server: &str) -> CheckResult {
    if vouch_common::check_url_security(server).is_insecure() {
        CheckResult::fail(format!(
            "Server uses plain HTTP ({server}). Use HTTPS or set VOUCH_ALLOW_INSECURE=1."
        ))
    } else {
        CheckResult::pass("Server URL is secure (HTTPS or localhost)")
    }
}
