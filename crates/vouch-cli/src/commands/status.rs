// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Status command - show current session status.

use anyhow::Result;
use ssh_key::certificate::Certificate;
use std::path::PathBuf;
#[cfg(unix)]
use vouch_agent::{AgentClient, AgentError, SessionInfo};
use vouch_common::{GitHubStatusResponse, SessionStatus};

use crate::client::VouchClient;
use crate::commands::credential::ssh::default_key_path;
use crate::config::Config;

/// Run the status command.
pub async fn run(server: &str) -> Result<()> {
    // First, try to get session from agent (Unix only)
    #[cfg(unix)]
    match get_session_from_agent().await {
        Ok(session) => {
            print_agent_session(server, &session);
            print_ssh_certificate_status();
            print_aws_status(&check_aws_integration_status());
            print_github_status(&check_github_integration_status(server).await, server);
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
                print_aws_status(&check_aws_integration_status());
                print_github_status(&check_github_integration_status(server).await, server);
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

    // Show SSH agent socket if configured (Unix only)
    #[cfg(unix)]
    if let Ok(socket_path) = vouch_agent::ssh_agent_socket_path()
        && socket_path.exists()
    {
        println!("       Agent socket: {}", socket_path.display());
    }
}

// ============================================================================
// AWS Integration Status
// ============================================================================

/// AWS integration status.
struct AwsIntegrationStatus {
    configured: bool,
    profile_name: Option<String>,
    role_arn: Option<String>,
}

/// Check AWS integration status by reading ~/.aws/config.
fn check_aws_integration_status() -> AwsIntegrationStatus {
    let config_path = match aws_config_path() {
        Some(p) => p,
        None => {
            return AwsIntegrationStatus {
                configured: false,
                profile_name: None,
                role_arn: None,
            };
        }
    };

    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => {
            return AwsIntegrationStatus {
                configured: false,
                profile_name: None,
                role_arn: None,
            };
        }
    };

    // Look for profiles with credential_process containing "vouch"
    let mut current_profile: Option<String> = None;
    let mut found_profile: Option<String> = None;
    let mut found_role: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();

        // Check for profile header
        if let Some(header) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if header == "default" {
                current_profile = Some("default".to_string());
            } else if let Some(name) = header.strip_prefix("profile ") {
                current_profile = Some(name.to_string());
            } else {
                current_profile = None;
            }
            continue;
        }

        // Check for credential_process with vouch
        if let Some(profile) = &current_profile
            && line.starts_with("credential_process")
            && line.contains("vouch")
        {
            found_profile = Some(profile.clone());

            // Extract role ARN from --role argument
            if let Some(after_role) = line.split("--role").nth(1) {
                let role_arn = after_role.split_whitespace().next().map(|s| s.to_string());
                found_role = role_arn;
            }
            break;
        }
    }

    AwsIntegrationStatus {
        configured: found_profile.is_some(),
        profile_name: found_profile,
        role_arn: found_role,
    }
}

/// Get the AWS config file path.
fn aws_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".aws").join("config"))
}

/// Print AWS integration status.
fn print_aws_status(status: &AwsIntegrationStatus) {
    if status.configured {
        let profile_display = status
            .profile_name
            .as_ref()
            .map(|p| {
                if p == "default" {
                    "default profile".to_string()
                } else {
                    format!("profile: {p}")
                }
            })
            .unwrap_or_else(|| "configured".to_string());

        println!("  AWS: configured ({profile_display})");
        if let Some(role) = &status.role_arn {
            println!("       Role: {role}");
        }
    } else {
        println!("  AWS: not configured");
        println!("       Run: vouch setup aws --role <role-arn>");
    }
}

// ============================================================================
// GitHub Integration Status
// ============================================================================

/// GitHub integration status.
struct GitHubIntegrationStatus {
    local_configured: bool,
    host: Option<String>,
    server_status: Option<GitHubStatusResponse>,
    server_error: Option<String>,
    /// Current git repo info (if in a git repo with GitHub remotes).
    current_repo: Option<CurrentRepoStatus>,
}

/// Status of the current git repository's GitHub remotes.
struct CurrentRepoStatus {
    /// Remotes that can be pushed to.
    accessible: Vec<GitRemote>,
    /// Remotes that cannot be pushed to (not in configured repos).
    inaccessible: Vec<GitRemote>,
}

/// A parsed git remote.
#[derive(Clone)]
struct GitRemote {
    name: String,
    owner: String,
    repo: String,
}

/// Check GitHub integration status.
async fn check_github_integration_status(server: &str) -> GitHubIntegrationStatus {
    let (local_configured, host) = check_git_credential_helper();

    // Try to get server status
    let (server_status, server_error) = match get_github_server_status(server).await {
        Ok(status) => (Some(status), None),
        Err(e) => (None, Some(e.to_string())),
    };

    // Check current repo if we have server status
    let current_repo = server_status.as_ref().and_then(check_current_repo_access);

    GitHubIntegrationStatus {
        local_configured,
        host,
        server_status,
        server_error,
        current_repo,
    }
}

/// Check if git credential helper is configured for GitHub.
fn check_git_credential_helper() -> (bool, Option<String>) {
    // Check common GitHub hosts
    for host in &["github.com", "ghe.com"] {
        let config_key = format!("credential.https://{}.helper", host);
        let output = std::process::Command::new("git")
            .args(["config", "--global", "--get", &config_key])
            .output();

        if let Ok(output) = output
            && output.status.success()
        {
            let helper = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if helper.contains("vouch") {
                return (true, Some((*host).to_string()));
            }
        }
    }

    (false, None)
}

/// Get GitHub status from server.
async fn get_github_server_status(server: &str) -> Result<GitHubStatusResponse> {
    let client = VouchClient::new(server)?;
    client
        .get_authenticated("/v1/credentials/github/status")
        .await
}

/// Check if the current directory is a git repo and analyze GitHub remote access.
fn check_current_repo_access(server_status: &GitHubStatusResponse) -> Option<CurrentRepoStatus> {
    // Check if we're in a git repo
    if !is_git_repo() {
        return None;
    }

    // Get GitHub remotes
    let remotes = get_github_remotes();
    if remotes.is_empty() {
        return None;
    }

    // Categorize remotes by accessibility
    let mut accessible = Vec::new();
    let mut inaccessible = Vec::new();

    for remote in remotes {
        if is_repo_accessible(&remote, server_status) {
            accessible.push(remote);
        } else {
            inaccessible.push(remote);
        }
    }

    Some(CurrentRepoStatus {
        accessible,
        inaccessible,
    })
}

/// Check if current directory is inside a git repository.
fn is_git_repo() -> bool {
    std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Get all GitHub remotes from the current git repo.
fn get_github_remotes() -> Vec<GitRemote> {
    let output = std::process::Command::new("git")
        .args(["remote", "-v"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut remotes = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in stdout.lines() {
        // Format: "origin	git@github.com:owner/repo.git (fetch)"
        // or:     "origin	https://github.com/owner/repo.git (push)"
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(url) = parts.next() else {
            continue;
        };

        // Skip if we've already processed this remote (fetch/push appear twice)
        let key = format!("{name}:{url}");
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);

        // Parse the URL to extract owner/repo
        if let Some((owner, repo)) = parse_github_remote_url(url) {
            remotes.push(GitRemote {
                name: name.to_string(),
                owner,
                repo,
            });
        }
    }

    remotes
}

/// Parse a GitHub remote URL to extract owner and repo.
/// Handles both SSH and HTTPS formats:
/// - git@github.com:owner/repo.git
/// - https://github.com/owner/repo.git
/// - https://github.com/owner/repo
fn parse_github_remote_url(url: &str) -> Option<(String, String)> {
    // SSH format: git@github.com:owner/repo.git
    if let Some(path) = url.strip_prefix("git@github.com:") {
        return parse_owner_repo_path(path);
    }

    // HTTPS format: https://github.com/owner/repo.git
    if let Some(path) = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))
    {
        return parse_owner_repo_path(path);
    }

    // GitHub Enterprise: git@ghe.com:owner/repo.git or similar
    if url.contains("github") || url.contains("ghe.com") {
        // Try to extract path after the host (SSH format: git@host:path)
        if let Some(colon_pos) = url.rfind(':')
            && let Some(path) = url.get(colon_pos + 1..)
            && !path.starts_with("//")
        {
            return parse_owner_repo_path(path);
        }
        // Try URL path format (https://host/owner/repo)
        let path_str: String = url.split('/').skip(3).collect::<Vec<_>>().join("/");
        if !path_str.is_empty() {
            return parse_owner_repo_path(&path_str);
        }
    }

    None
}

/// Parse "owner/repo.git" or "owner/repo" into (owner, repo).
fn parse_owner_repo_path(path: &str) -> Option<(String, String)> {
    let path = path.trim_end_matches(".git");
    let mut parts = path.split('/');

    let owner = parts.next()?;
    let repo = parts.next()?;

    Some((owner.to_string(), repo.to_string()))
}

/// Check if a repository is accessible based on the server's GitHub status.
fn is_repo_accessible(remote: &GitRemote, status: &GitHubStatusResponse) -> bool {
    // Must be configured and connected
    if !status.configured || !status.connected {
        return false;
    }

    // Find matching account (case-insensitive owner match)
    for account in &status.github_accounts {
        if account.login.eq_ignore_ascii_case(&remote.owner) {
            // Account is suspended
            if account.suspended {
                return false;
            }

            // "all" repos means full access
            if account.repository_selection == "all" {
                return true;
            }

            // Check if repo is in the selected list
            if let Some(repos) = &account.repositories {
                return repos.iter().any(|r| r.eq_ignore_ascii_case(&remote.repo));
            }

            // Selected but no repo list (shouldn't happen, but treat as inaccessible)
            return false;
        }
    }

    // No matching account found
    false
}

/// Print GitHub integration status.
fn print_github_status(status: &GitHubIntegrationStatus, server: &str) {
    match &status.server_status {
        Some(server_status) if server_status.configured && server_status.connected => {
            // Fully working - show connected accounts
            let host = status.host.as_deref().unwrap_or("github.com");
            println!("  GitHub: connected ({host})");
            if !server_status.github_accounts.is_empty() {
                print_github_accounts(server_status, &status.current_repo);
            }
        }
        Some(server_status) if !server_status.configured => {
            // Server doesn't have GitHub App configured at all
            println!("  GitHub: not available");
            println!("       Server does not have GitHub App configured");
        }
        Some(_) => {
            // GitHub App configured on server, but not installed for this org
            println!("  GitHub: not installed");
            println!("       Admin action: visit {server}/github/connect");
            if status.local_configured {
                let host = status.host.as_deref().unwrap_or("github.com");
                println!("       (git credential helper ready for {host})");
            }
        }
        None => {
            // Couldn't reach server or get status
            if let Some(err) = &status.server_error {
                tracing::debug!("GitHub status error: {err}");
            }
            if status.local_configured {
                let host = status.host.as_deref().unwrap_or("github.com");
                println!("  GitHub: unknown (git helper configured for {host})");
                println!("       Could not check server status");
            } else {
                println!("  GitHub: not configured");
                println!("       Run: vouch setup github");
            }
        }
    }
}

/// Print connected GitHub accounts with their accessible repos.
fn print_github_accounts(status: &GitHubStatusResponse, current_repo: &Option<CurrentRepoStatus>) {
    // Track which current repo remotes we've printed
    let mut printed_remotes: std::collections::HashSet<String> = std::collections::HashSet::new();

    for account in &status.github_accounts {
        if account.suspended {
            let current_tag = format_current_tag_for_owner(&account.login, current_repo);
            println!(
                "       \u{2718} {}/*{} (suspended)",
                account.login, current_tag
            );
            mark_owner_remotes_printed(&account.login, current_repo, &mut printed_remotes);
        } else if account.repository_selection == "all" {
            let current_tag = format_current_tag_for_owner(&account.login, current_repo);
            println!("       \u{2714} {}/*{}", account.login, current_tag);
            mark_owner_remotes_printed(&account.login, current_repo, &mut printed_remotes);
        } else if let Some(repos) = &account.repositories {
            if repos.is_empty() {
                let current_tag = format_current_tag_for_owner(&account.login, current_repo);
                println!(
                    "       \u{2718} {}/*{} (no repos)",
                    account.login, current_tag
                );
            } else {
                for repo in repos {
                    let current_tag =
                        format_current_tag_for_repo(&account.login, repo, current_repo);
                    if !current_tag.is_empty() {
                        printed_remotes
                            .insert(format!("{}/{}", account.login, repo).to_lowercase());
                    }
                    println!("       \u{2714} {}/{}{}", account.login, repo, current_tag);
                }
            }
        } else {
            println!("       ? {}/* (repos unknown)", account.login);
        }
    }

    // Print any inaccessible remotes from current repo that weren't already shown
    if let Some(repo_status) = current_repo {
        for r in &repo_status.inaccessible {
            let key = format!("{}/{}", r.owner, r.repo).to_lowercase();
            if !printed_remotes.contains(&key) {
                println!(
                    "       \u{2718} {}/{} ({}) [current]",
                    r.owner, r.repo, r.name
                );
                printed_remotes.insert(key);
            }
        }
    }
}

/// Format a "(current, remote_name)" tag if the owner matches any current repo remote.
fn format_current_tag_for_owner(owner: &str, current_repo: &Option<CurrentRepoStatus>) -> String {
    let Some(repo_status) = current_repo else {
        return String::new();
    };

    let matching_remotes: Vec<&str> = repo_status
        .accessible
        .iter()
        .chain(repo_status.inaccessible.iter())
        .filter(|r| r.owner.eq_ignore_ascii_case(owner))
        .map(|r| r.name.as_str())
        .collect();

    format_current_tag(&matching_remotes)
}

/// Format a "(current, remote_name)" tag if owner/repo matches any current repo remote.
fn format_current_tag_for_repo(
    owner: &str,
    repo: &str,
    current_repo: &Option<CurrentRepoStatus>,
) -> String {
    let Some(repo_status) = current_repo else {
        return String::new();
    };

    let matching_remotes: Vec<&str> = repo_status
        .accessible
        .iter()
        .chain(repo_status.inaccessible.iter())
        .filter(|r| r.owner.eq_ignore_ascii_case(owner) && r.repo.eq_ignore_ascii_case(repo))
        .map(|r| r.name.as_str())
        .collect();

    format_current_tag(&matching_remotes)
}

/// Format the current tag from a list of matching remote names.
fn format_current_tag(remotes: &[&str]) -> String {
    match remotes {
        [] => String::new(),
        [single] => format!(" ({single}) [current]"),
        multiple => format!(" ({}) [current]", multiple.join(", ")),
    }
}

/// Mark all remotes for a given owner as printed.
fn mark_owner_remotes_printed(
    owner: &str,
    current_repo: &Option<CurrentRepoStatus>,
    printed: &mut std::collections::HashSet<String>,
) {
    let Some(repo_status) = current_repo else {
        return;
    };

    for r in repo_status
        .accessible
        .iter()
        .chain(repo_status.inaccessible.iter())
    {
        if r.owner.eq_ignore_ascii_case(owner) {
            printed.insert(format!("{}/{}", r.owner, r.repo).to_lowercase());
        }
    }
}
