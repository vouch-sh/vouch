// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Doctor command - diagnostic checks for the Vouch environment.

use anyhow::{Result, bail};
#[cfg(not(target_os = "windows"))]
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
use serde::Serialize;
#[cfg(unix)]
use vouch_agent::AgentClient;

use crate::client::VouchClient;
use crate::config::Config;
use crate::style;
use vouch_cli::{tr, tr_args};

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
pub(crate) async fn run(server: &str, quiet: bool, json: bool) -> Result<()> {
    let suppress = quiet || json;

    if !suppress {
        println!("{}", tr!("doctor-title"));
        println!();
    }

    let checks = run_checks(server, suppress).await;

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
            println!("{}", tr!("doctor-all-passed"));
        }
        Ok(())
    } else {
        if !suppress {
            println!("{}", tr!("doctor-some-failed"));
        }
        bail!("doctor: one or more checks failed")
    }
}

/// Run every diagnostic check in order, printing progress as each one
/// completes (unless `suppress` is set), and collect the results.
async fn run_checks(server: &str, suppress: bool) -> Vec<CheckResult> {
    let mut checks: Vec<CheckResult> = Vec::new();

    // Check 1: YubiKey connectivity
    if !suppress {
        print!("{} ", tr!("doctor-check-yubikey-label"));
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
            print!("{} ", tr!("doctor-check-agent-label"));
        }
        let agent_result = check_agent().await;
        if !suppress {
            print_result(&agent_result);
        }
        checks.push(agent_result);
    }

    // Check 3: Server reachable (and clock skew, derived from same response)
    if !suppress {
        print!("{} ", tr!("doctor-check-server-label"));
    }
    let (server_result, clock_result) = check_server(server).await;
    if !suppress {
        print_result(&server_result);
    }
    checks.push(server_result);
    if let Some(clock) = clock_result {
        if !suppress {
            print!("{} ", tr!("doctor-check-clock-label"));
            print_result(&clock);
        }
        checks.push(clock);
    }

    // Check 3a: DNS-over-HTTPS resolution status.
    if let Some(resolver) = vouch_common::dns::process_resolver() {
        if !suppress {
            print!("{} ", tr!("doctor-check-doh-label"));
        }
        let doh_result = check_doh(&resolver, server).await;
        if !suppress {
            print_result(&doh_result);
        }
        checks.push(doh_result);
    } else if !suppress {
        println!(
            "{} {} {}",
            tr!("doctor-check-doh-label"),
            style::yellow("[INFO]"),
            tr!("doctor-doh-disabled"),
        );
    }

    // Check 4: Session valid
    if !suppress {
        print!("{} ", tr!("doctor-check-session-label"));
    }
    let session_result = check_session().await;
    if !suppress {
        print_result(&session_result);
    }
    checks.push(session_result);

    // Check 5: SSH config
    if !suppress {
        print!("{} ", tr!("doctor-check-ssh-label"));
    }
    let ssh_result = check_ssh_config();
    if !suppress {
        print_result(&ssh_result);
    }
    checks.push(ssh_result);

    // Check 6: EKS config
    if !suppress {
        print!("{} ", tr!("doctor-check-eks-label"));
    }
    let eks_result = check_eks_config();
    if !suppress {
        print_result(&eks_result);
    }
    checks.push(eks_result);

    // Check 7: SSM config
    if !suppress {
        print!("{} ", tr!("doctor-check-ssm-label"));
    }
    let ssm_result = check_ssm_config();
    if !suppress {
        print_result(&ssm_result);
    }
    checks.push(ssm_result);

    // Check 8: Server URL security
    if !suppress {
        print!("{} ", tr!("doctor-check-server-url-label"));
    }
    let security_result = check_server_url_security(server);
    if !suppress {
        print_result(&security_result);
    }
    checks.push(security_result);

    checks
}

/// Print check result with color indicators.
fn print_result(result: &CheckResult) {
    if result.passed {
        println!("{} {}", style::green("[OK]"), result.message);
    } else {
        println!("{} {}", style::red("[FAIL]"), result.message);
    }
}

/// Check if a YubiKey is connected and accessible.
#[cfg(not(target_os = "windows"))]
fn check_yubikey() -> CheckResult {
    let cfg = Cfg::init();
    match FidoKeyHidFactory::create(&cfg) {
        Ok(_device) => CheckResult::pass("yubikey", tr!("doctor-yubikey-found")),
        Err(e) => CheckResult::fail("yubikey", tr_args!("doctor-yubikey-not-found", reason = e)),
    }
}

/// Check that the Windows WebAuthn API is available.
///
/// Unlike the Unix backend, we cannot probe the YubiKey directly — Windows
/// blocks non-elevated processes from opening FIDO2 HID devices, and the
/// WebAuthn API only opens a device interactively (when the user clicks
/// through the Windows Security modal). The best we can do is confirm the
/// API itself is present and report its version.
#[cfg(target_os = "windows")]
fn check_yubikey() -> CheckResult {
    use windows::Win32::Networking::WindowsWebServices::WebAuthNGetApiVersionNumber;

    // SAFETY: WebAuthNGetApiVersionNumber takes no parameters, has no
    // preconditions, and is available since Windows 10 1903.
    #[expect(
        unsafe_code,
        reason = "WebAuthNGetApiVersionNumber is a no-arg FFI call; safety documented inline"
    )]
    let version = unsafe { WebAuthNGetApiVersionNumber() };
    if version == 0 {
        CheckResult::fail("yubikey", tr!("doctor-yubikey-win-api-missing"))
    } else {
        CheckResult::pass(
            "yubikey",
            tr_args!("doctor-yubikey-win-api-available", version = version),
        )
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
                        Some(pid) => CheckResult::pass(
                            "agent",
                            tr_args!("doctor-agent-running-pid", pid = pid),
                        ),
                        None => CheckResult::pass("agent", tr!("doctor-agent-running")),
                    }
                }
                Err(e) => CheckResult::fail(
                    "agent",
                    tr_args!("doctor-agent-connection-failed", reason = e),
                ),
            }
        }
        Err(e) => {
            // Check if socket exists
            if let Ok(socket_path) = vouch_agent::socket::socket_path()
                && socket_path.exists()
            {
                return CheckResult::fail(
                    "agent",
                    tr_args!("doctor-agent-socket-exists", reason = e),
                );
            }
            CheckResult::fail("agent", tr!("doctor-agent-not-running"))
        }
    }
}

/// Check if the server is reachable, and use the response's `Date` header
/// to also report clock skew between the local system and the server.
///
/// Returns `(reachability_result, Some(clock_skew_result))` when the request
/// completes (skew can be computed from the `Date` header), or
/// `(reachability_result, None)` when the request never produced a response.
async fn check_server(server: &str) -> (CheckResult, Option<CheckResult>) {
    let client = match VouchClient::unauthenticated(server) {
        Ok(c) => c,
        Err(e) => {
            return (
                CheckResult::fail("server", tr_args!("doctor-server-invalid-url", reason = e)),
                None,
            );
        }
    };

    let url = format!("{}/health", client.base_url());
    let response = match client.raw_client().get(&url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            return (
                CheckResult::fail("server", tr_args!("doctor-server-unreachable", reason = e)),
                None,
            );
        }
    };

    let clock_result = build_clock_skew_result(response.headers());

    let server_result = if response.status().is_success() {
        CheckResult::pass(
            "server",
            tr_args!("doctor-server-reachable", server = server),
        )
    } else {
        CheckResult::fail(
            "server",
            tr_args!("doctor-server-status", status = response.status()),
        )
    };

    (server_result, clock_result)
}

/// Build a `CheckResult` describing the clock skew between this client and
/// the server, derived from the response's `Date` header. Returns `None` if
/// the server response lacks a parseable `Date` header (rare — RFC 7231
/// requires it on every response).
fn build_clock_skew_result(headers: &reqwest::header::HeaderMap) -> Option<CheckResult> {
    let (skew_secs, local_behind) = vouch_cli::http::compute_clock_skew(headers)?;
    if skew_secs < vouch_cli::http::CLOCK_SKEW_THRESHOLD_SECS {
        return Some(CheckResult::pass(
            "clock_skew",
            tr_args!("doctor-clock-ok", secs = skew_secs),
        ));
    }
    let direction = if local_behind {
        tr!("doctor-clock-direction-behind")
    } else {
        tr!("doctor-clock-direction-ahead")
    };
    Some(CheckResult::fail(
        "clock_skew",
        tr_args!("doctor-clock-skew", secs = skew_secs, direction = direction),
    ))
}

/// Verify that the configured DNS-over-HTTPS provider can resolve the
/// server hostname. Caller is responsible for gating on DoH-enabled state
/// (typically `process_resolver().is_some()`).
///
/// DNSSEC validation rides with DoH (always on), so a `[FAIL]` here may
/// indicate either a network problem reaching the DoH provider or a
/// DNSSEC-signed zone in the user's path that has broken signatures.
async fn check_doh(resolver: &vouch_common::dns::DohResolver, server: &str) -> CheckResult {
    let label = format!(
        "DNS-over-HTTPS via {} ({}, DNSSEC)",
        resolver.label(),
        resolver.endpoint_url(),
    );
    // Parse the URL directly so IPv6 hosts (which contain colons) survive
    // intact — `hostname_from_url`/colon-splitting would mangle `[::1]`.
    let host = match url::Url::parse(server)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
    {
        Some(h) => h,
        None => {
            return CheckResult::fail(
                "doh",
                format!("{label}: cannot extract host from server URL"),
            );
        }
    };
    match resolver.lookup_ip(&host).await {
        Ok(addrs) if addrs.is_empty() => CheckResult::fail(
            "doh",
            tr_args!("doctor-doh-zero-addresses", label = label, host = host),
        ),
        Ok(addrs) => CheckResult::pass(
            "doh",
            tr_args!(
                "doctor-doh-resolved",
                label = label,
                host = host,
                count = addrs.len(),
            ),
        ),
        Err(e) => CheckResult::fail(
            "doh",
            tr_args!("doctor-doh-error", label = label, reason = format!("{e:#}")),
        ),
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
                    // 3600 and 60 are non-zero; unwrap_or arms are unreachable.
                    let hours = session.expires_in_seconds.checked_div(3600).unwrap_or(0);
                    let mins = (session.expires_in_seconds % 3600)
                        .checked_div(60)
                        .unwrap_or(0);
                    CheckResult::pass(
                        "session",
                        tr_args!(
                            "doctor-session-valid",
                            hours = hours,
                            mins = mins,
                            email = &session.user_email,
                        ),
                    )
                } else {
                    CheckResult::fail("session", tr!("doctor-session-expired"))
                }
            }
            Err(_) => CheckResult::fail("session", tr!("doctor-session-none")),
        };
    }

    // Fall back to config
    let config = match Config::load() {
        Ok(c) => c,
        Err(_) => return CheckResult::fail("session", tr!("doctor-session-no-config")),
    };

    if config.token().is_some() {
        CheckResult::pass("session", tr!("doctor-session-token-only"))
    } else {
        CheckResult::fail("session", tr!("doctor-session-no-token"))
    }
}

/// Check SSH configuration for Vouch integration.
fn check_ssh_config() -> CheckResult {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return CheckResult::fail("ssh", tr!("doctor-ssh-no-home")),
    };

    let ssh_config_path = home.join(".ssh").join("config");
    let vouch_key_path = home.join(".ssh").join("id_ed25519_vouch");

    let mut issues: Vec<String> = Vec::new();

    if !vouch_key_path.exists() {
        issues.push(tr!("doctor-ssh-key-missing"));
    }

    if ssh_config_path.exists() {
        match std::fs::read_to_string(&ssh_config_path) {
            Ok(content) => {
                if !content.contains("id_ed25519_vouch") && !content.contains("vouch") {
                    issues.push(tr!("doctor-ssh-config-missing-entry"));
                }
            }
            Err(_) => {
                issues.push(tr!("doctor-ssh-config-unreadable"));
            }
        }
    } else {
        issues.push(tr!("doctor-ssh-config-not-found"));
    }

    if issues.is_empty() {
        CheckResult::pass("ssh", tr!("doctor-ssh-configured"))
    } else {
        CheckResult::fail("ssh", issues.join("; "))
    }
}

/// Check EKS configuration for Vouch integration.
fn check_eks_config() -> CheckResult {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return CheckResult::fail("eks", tr!("doctor-eks-no-home")),
    };

    let kubeconfig_path = std::env::var("KUBECONFIG")
        .ok()
        .and_then(|k| k.split(':').next().map(std::path::PathBuf::from))
        .unwrap_or_else(|| home.join(".kube").join("config"));

    if !kubeconfig_path.exists() {
        return CheckResult::pass("eks", tr!("doctor-eks-no-kubeconfig"));
    }

    match std::fs::read_to_string(&kubeconfig_path) {
        Ok(content) => {
            if content.contains("vouch-eks-") {
                CheckResult::pass("eks", tr!("doctor-eks-configured"))
            } else {
                CheckResult::pass("eks", tr!("doctor-eks-no-vouch-entry"))
            }
        }
        Err(_) => CheckResult::fail("eks", tr!("doctor-eks-unreadable")),
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
        None => return CheckResult::fail("ssm", tr!("doctor-ssm-no-home")),
    };

    let ssh_config_path = home.join(".ssh").join("config");
    let marker_found = ssh_config_path
        .exists()
        .then(|| std::fs::read_to_string(&ssh_config_path).ok())
        .flatten()
        .is_some_and(|content| content.contains(SSM_MARKER));

    match (plugin_found, marker_found) {
        (true, true) => CheckResult::pass("ssm", tr!("doctor-ssm-configured")),
        (true, false) => CheckResult::pass("ssm", tr!("doctor-ssm-plugin-found")),
        (false, true) => CheckResult::fail("ssm", tr!("doctor-ssm-plugin-missing-but-configured")),
        (false, false) => CheckResult::pass("ssm", tr!("doctor-ssm-not-configured")),
    }
}

/// Check if the server URL uses secure transport.
fn check_server_url_security(server: &str) -> CheckResult {
    if vouch_common::check_url_security(server).is_insecure() {
        CheckResult::fail(
            "server_url_security",
            tr_args!("doctor-server-url-insecure", server = server),
        )
    } else {
        CheckResult::pass("server_url_security", tr!("doctor-server-url-secure"))
    }
}
