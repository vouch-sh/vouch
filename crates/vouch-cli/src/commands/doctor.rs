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

    // Check 3: Server reachable (and clock skew, derived from same response)
    if !suppress {
        print!("Server reachable ... ");
    }
    let (server_result, clock_result) = check_server(server).await;
    if !suppress {
        print_result(&server_result);
    }
    checks.push(server_result);
    if let Some(clock) = clock_result {
        if !suppress {
            print!("Clock in sync with server ... ");
            print_result(&clock);
        }
        checks.push(clock);
    }

    // Check 3a: DNS-over-HTTPS resolution status.
    //
    // Always emit something so users discover the option. When DoH is enabled
    // we run a real lookup through the configured provider. When disabled we
    // print a one-line nudge — not added to `checks` so it doesn't count
    // toward pass/fail or appear in --json output (DoH being off is a user
    // choice, not a misconfiguration).
    if let Some(resolver) = vouch_common::dns::process_resolver() {
        if !suppress {
            print!("DNS-over-HTTPS resolution ... ");
        }
        let doh_result = check_doh(&resolver, server).await;
        if !suppress {
            print_result(&doh_result);
        }
        checks.push(doh_result);
    } else if !suppress {
        println!(
            "DNS-over-HTTPS resolution ... {} disabled — DNS queries are visible to your \
             local network. Set VOUCH_DOH=cloudflare (or google/quad9) to encrypt them.",
            style::yellow("[INFO]"),
        );
    }

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

    // Check 8: Claude federation
    if !suppress {
        print!("Claude federation ... ");
    }
    let anthropic_result = check_anthropic_config();
    if !suppress {
        print_result(&anthropic_result);
    }
    checks.push(anthropic_result);

    // Check 9: OpenAI federation
    if !suppress {
        print!("OpenAI federation ... ");
    }
    let openai_result = check_openai_config();
    if !suppress {
        print_result(&openai_result);
    }
    checks.push(openai_result);

    // Check 10: Server URL security
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
        Ok(_device) => CheckResult::pass("yubikey", "FIDO2 device found"),
        Err(e) => CheckResult::fail("yubikey", format!("No FIDO2 device found: {e}")),
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
        CheckResult::fail(
            "yubikey",
            "Windows WebAuthn API not available. Update to Windows 10 1903 or later.",
        )
    } else {
        CheckResult::pass(
            "yubikey",
            format!(
                "Windows WebAuthn API available (version {version}); \
                 vouch login uses the system Security dialog to authenticate \
                 your YubiKey — no admin privileges required."
            ),
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
                CheckResult::fail("server", format!("Invalid server URL: {e}")),
                None,
            );
        }
    };

    let url = format!("{}/health", client.base_url());
    let response = match client.raw_client().get(&url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            return (
                CheckResult::fail("server", format!("Server unreachable: {e}")),
                None,
            );
        }
    };

    let clock_result = build_clock_skew_result(response.headers());

    let server_result = if response.status().is_success() {
        CheckResult::pass("server", format!("Server at {server} is reachable"))
    } else {
        CheckResult::fail(
            "server",
            format!("Server returned status: {}", response.status()),
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
            format!("System clock within {skew_secs}s of server"),
        ));
    }
    let direction = if local_behind { "behind" } else { "ahead of" };
    Some(CheckResult::fail(
        "clock_skew",
        format!(
            "System clock is {skew_secs}s {direction} the server. \
             Signed requests will fail once skew exceeds 300s. \
             Sync your clock (Windows: Settings → Time & Language → Date & Time → \
             \"Sync now\"; macOS: `sudo sntp -sS time.apple.com`)."
        ),
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
        Ok(addrs) if addrs.is_empty() => {
            CheckResult::fail("doh", format!("{label}: {host} resolved to zero addresses"))
        }
        Ok(addrs) => CheckResult::pass(
            "doh",
            format!("{label}: {host} resolved to {} address(es)", addrs.len()),
        ),
        Err(e) => CheckResult::fail("doh", format!("{label}: {e:#}")),
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

/// Check Anthropic (Claude) federation configuration.
///
/// Federation that's persisted in `~/.vouch/config.json` but not wired
/// into Claude Code's `apiKeyHelper` is a real misconfiguration —
/// `vouch credential anthropic` works in isolation but Claude Code
/// would never invoke it. That asymmetry warrants a fail, not just a
/// hint. The "neither configured" case is a normal pass: not every
/// install uses Claude federation.
fn check_anthropic_config() -> CheckResult {
    use crate::integrations::anthropic::{ClaudeCodeHelperState, claude_code_helper_state};

    let config = match Config::load() {
        Ok(c) => c,
        Err(_) => {
            return CheckResult::pass("anthropic", "Claude federation not configured");
        }
    };
    let vouch_configured = config.ai().and_then(|ai| ai.anthropic.as_ref()).is_some();
    let helper = claude_code_helper_state();

    match (vouch_configured, helper) {
        (false, ClaudeCodeHelperState::Missing | ClaudeCodeHelperState::Other(_)) => {
            CheckResult::pass(
                "anthropic",
                "Claude federation not configured. Run: vouch setup anthropic",
            )
        }
        (true, ClaudeCodeHelperState::Vouch) => {
            CheckResult::pass("anthropic", "Claude federation configured")
        }
        (true, ClaudeCodeHelperState::Missing) => CheckResult::fail(
            "anthropic",
            "Vouch federation configured but Claude Code apiKeyHelper is missing. \
             Run: vouch setup anthropic",
        ),
        (true, ClaudeCodeHelperState::Other(cmd)) => CheckResult::fail(
            "anthropic",
            format!(
                "Vouch federation configured but Claude Code apiKeyHelper points elsewhere: \
                 {cmd}. Run: vouch setup anthropic --force"
            ),
        ),
        (false, ClaudeCodeHelperState::Vouch) => CheckResult::fail(
            "anthropic",
            "Claude Code apiKeyHelper points at vouch but no Anthropic federation is \
             configured. Run: vouch setup anthropic",
        ),
    }
}

/// Check OpenAI federation configuration.
///
/// Same fail-on-asymmetry rationale as Claude. Cross-check Vouch
/// federation params against Codex's top-level `model_provider`.
fn check_openai_config() -> CheckResult {
    use crate::integrations::openai::{CodexProviderState, codex_provider_state};

    let config = match Config::load() {
        Ok(c) => c,
        Err(_) => {
            return CheckResult::pass("openai", "OpenAI federation not configured");
        }
    };
    let vouch_configured = config.ai().and_then(|ai| ai.openai.as_ref()).is_some();
    let provider = codex_provider_state();

    match (vouch_configured, provider) {
        (false, CodexProviderState::Missing | CodexProviderState::Other(_)) => CheckResult::pass(
            "openai",
            "OpenAI federation not configured. Run: vouch setup openai",
        ),
        (true, CodexProviderState::Vouch) => {
            CheckResult::pass("openai", "OpenAI federation configured")
        }
        (true, CodexProviderState::Missing) => CheckResult::fail(
            "openai",
            "Vouch federation configured but Codex model_provider is not set. \
             Run: vouch setup openai",
        ),
        (true, CodexProviderState::Other(name)) => CheckResult::fail(
            "openai",
            format!(
                "Vouch federation configured but Codex model_provider = {name:?}. \
                 Run: vouch setup openai --force"
            ),
        ),
        (false, CodexProviderState::Vouch) => CheckResult::fail(
            "openai",
            "Codex model_provider = \"vouch\" but no OpenAI federation is configured. \
             Run: vouch setup openai",
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
