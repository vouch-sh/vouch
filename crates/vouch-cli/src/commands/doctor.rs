// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Doctor command - diagnostic checks for the Vouch environment.

use anyhow::{Result, bail};
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
use serde::Serialize;
#[cfg(unix)]
use vouch_agent::AgentClient;

use crate::client::VouchClient;
use crate::config::Config;

/// Check result with status and optional message.
struct CheckResult {
    name: &'static str,
    passed: bool,
    message: String,
}

/// JSON representation of a single doctor check.
#[derive(Serialize)]
struct DoctorCheckJson {
    name: &'static str,
    passed: bool,
    message: String,
}

/// JSON representation of all doctor check results.
#[derive(Serialize)]
struct DoctorJson {
    checks: Vec<DoctorCheckJson>,
    all_passed: bool,
}

impl CheckResult {
    fn pass(name: &'static str, msg: impl Into<String>) -> Self {
        Self {
            name,
            passed: true,
            message: msg.into(),
        }
    }

    fn fail(name: &'static str, msg: impl Into<String>) -> Self {
        Self {
            name,
            passed: false,
            message: msg.into(),
        }
    }
}

/// Run the doctor command.
///
/// Returns an error if any checks fail, so the CLI exits with a non-zero code.
/// When `quiet` is true, all output is suppressed (exit code only).
/// When `json` is true, results are printed as JSON to stdout.
pub async fn run(server: &str, quiet: bool, json: bool) -> Result<()> {
    let suppress = quiet || json;

    if !suppress {
        println!("Vouch Doctor - Environment Diagnostics\n");
    }

    let mut checks: Vec<CheckResult> = Vec::new();

    // Check 1: YubiKey connectivity
    if !suppress {
        print!("YubiKey connectivity ... ");
    }
    let yubikey_result = check_yubikey();
    if !suppress {
        print_result(&yubikey_result);
    }
    checks.push(yubikey_result);

    // Check 2: Agent running (Unix only — agent requires Unix sockets)
    #[cfg(unix)]
    {
        if !suppress {
            print!("Agent running ... ");
        }
        let agent_result = check_agent().await;
        if !suppress {
            print_result(&agent_result);
        }
        checks.push(agent_result);
    }

    // Check 3: Server reachable
    if !suppress {
        print!("Server reachable ... ");
    }
    let server_result = check_server(server).await;
    if !suppress {
        print_result(&server_result);
    }
    checks.push(server_result);

    // Check 4: Session valid
    if !suppress {
        print!("Session valid ... ");
    }
    let session_result = check_session().await;
    if !suppress {
        print_result(&session_result);
    }
    checks.push(session_result);

    // Check 5: SSH config
    if !suppress {
        print!("SSH configuration ... ");
    }
    let ssh_result = check_ssh_config();
    if !suppress {
        print_result(&ssh_result);
    }
    checks.push(ssh_result);

    // Check 6: EKS config
    if !suppress {
        print!("EKS configuration ... ");
    }
    let eks_result = check_eks_config();
    if !suppress {
        print_result(&eks_result);
    }
    checks.push(eks_result);

    // Check 7: SSM config
    if !suppress {
        print!("SSM configuration ... ");
    }
    let ssm_result = check_ssm_config();
    if !suppress {
        print_result(&ssm_result);
    }
    checks.push(ssm_result);

    // Check 8: Server URL security
    if !suppress {
        print!("Server URL security ... ");
    }
    let security_result = check_server_url_security(server);
    if !suppress {
        print_result(&security_result);
    }
    checks.push(security_result);

    let all_passed = checks.iter().all(|c| c.passed);

    // JSON output
    if json {
        let json_output = DoctorJson {
            checks: checks
                .into_iter()
                .map(|c| DoctorCheckJson {
                    name: c.name,
                    passed: c.passed,
                    message: c.message,
                })
                .collect(),
            all_passed,
        };
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    }

    // Summary
    if !suppress {
        println!();
    }
    if all_passed {
        if !suppress {
            println!("All checks passed!");
        }
        Ok(())
    } else {
        if !suppress {
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
        Ok(_device) => CheckResult::pass("yubikey", "FIDO2 device found"),
        Err(e) => CheckResult::fail("yubikey", format!("No FIDO2 device found: {e}")),
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
                        Some(pid) => {
                            CheckResult::pass("agent", format!("Agent is running (PID {pid})"))
                        }
                        None => CheckResult::pass("agent", "Agent is running"),
                    }
                }
                Err(e) => CheckResult::fail("agent", format!("Agent connection failed: {e}")),
            }
        }
        Err(e) => {
            // Check if socket exists
            if let Ok(socket_path) = vouch_agent::socket::socket_path()
                && socket_path.exists()
            {
                return CheckResult::fail(
                    "agent",
                    format!("Socket exists but connection failed: {e}"),
                );
            }
            CheckResult::fail(
                "agent",
                "Agent not running. Start with: vouch-agent --foreground",
            )
        }
    }
}

/// Check if the server is reachable.
async fn check_server(server: &str) -> CheckResult {
    let client = match VouchClient::new(server) {
        Ok(c) => c,
        Err(e) => return CheckResult::fail("server", format!("Invalid server URL: {e}")),
    };

    let url = format!("{}/health", client.base_url());
    match client.raw_client().get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            CheckResult::pass("server", format!("Server at {server} is reachable"))
        }
        Ok(resp) => CheckResult::fail(
            "server",
            format!("Server returned status: {}", resp.status()),
        ),
        Err(e) => CheckResult::fail("server", format!("Server unreachable: {e}")),
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
                    CheckResult::pass(
                        "session",
                        format!(
                            "Session valid for {}h {}m ({})",
                            hours, mins, session.user_email
                        ),
                    )
                } else {
                    CheckResult::fail("session", "Session expired. Run: vouch login")
                }
            }
            Err(_) => CheckResult::fail("session", "No active session. Run: vouch login"),
        };
    }

    // Fall back to config
    let config = match Config::load() {
        Ok(c) => c,
        Err(_) => return CheckResult::fail("session", "No config found. Run: vouch login"),
    };

    if config.token().is_some() {
        CheckResult::pass(
            "session",
            "Session token found (agent not running for full validation)",
        )
    } else {
        CheckResult::fail("session", "No session token. Run: vouch login")
    }
}

/// Check SSH configuration for Vouch integration.
fn check_ssh_config() -> CheckResult {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return CheckResult::fail("ssh", "Could not determine home directory"),
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
        CheckResult::pass("ssh", "SSH configured for Vouch")
    } else {
        CheckResult::fail("ssh", issues.join("; "))
    }
}

/// Check EKS configuration for Vouch integration.
fn check_eks_config() -> CheckResult {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return CheckResult::fail("eks", "Could not determine home directory"),
    };

    // Check KUBECONFIG env var first, then default path
    let kubeconfig_path = std::env::var("KUBECONFIG")
        .ok()
        .and_then(|k| k.split(':').next().map(std::path::PathBuf::from))
        .unwrap_or_else(|| home.join(".kube").join("config"));

    if !kubeconfig_path.exists() {
        return CheckResult::pass("eks", "No kubeconfig found (EKS not configured)");
    }

    match std::fs::read_to_string(&kubeconfig_path) {
        Ok(content) => {
            // Check if there's a Vouch EKS user configured
            if content.contains("vouch-eks-") {
                CheckResult::pass("eks", "EKS configured for Vouch")
            } else {
                CheckResult::pass(
                    "eks",
                    "Kubeconfig exists (no Vouch EKS integration). Run: vouch setup eks --cluster <name>",
                )
            }
        }
        Err(_) => CheckResult::fail("eks", "Could not read kubeconfig"),
    }
}

/// Check SSM configuration.
///
/// Checks for `session-manager-plugin` on PATH and the Vouch SSM marker in SSH config.
fn check_ssm_config() -> CheckResult {
    use crate::commands::setup::ssm::SSM_MARKER;
    use crate::integrations::ssm::is_plugin_available;

    let plugin_found = is_plugin_available();

    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return CheckResult::fail("ssm", "Could not determine home directory"),
    };

    let ssh_config_path = home.join(".ssh").join("config");
    let marker_found = ssh_config_path
        .exists()
        .then(|| std::fs::read_to_string(&ssh_config_path).ok())
        .flatten()
        .is_some_and(|content| content.contains(SSM_MARKER));

    match (plugin_found, marker_found) {
        (true, true) => CheckResult::pass("ssm", "SSM configured for Vouch"),
        (true, false) => CheckResult::pass(
            "ssm",
            "session-manager-plugin found (not configured). Run: vouch setup ssm",
        ),
        (false, true) => CheckResult::fail(
            "ssm",
            "SSH config references SSM but session-manager-plugin not found on PATH",
        ),
        (false, false) => CheckResult::pass(
            "ssm",
            "SSM not configured (session-manager-plugin not found)",
        ),
    }
}

/// Check if the server URL uses secure transport.
fn check_server_url_security(server: &str) -> CheckResult {
    if vouch_common::check_url_security(server).is_insecure() {
        CheckResult::fail(
            "server_url_security",
            format!("Server uses plain HTTP ({server}). Use HTTPS or set VOUCH_ALLOW_INSECURE=1."),
        )
    } else {
        CheckResult::pass(
            "server_url_security",
            "Server URL is secure (HTTPS or localhost)",
        )
    }
}
