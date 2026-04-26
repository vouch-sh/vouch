// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub integration status checking.

use anyhow::Result;
use vouch_common::GitHubStatusResponse;

use super::{LABEL_WIDTH, VALUE_INDENT};
use crate::client::VouchClient;
use crate::style;

/// GitHub integration checker.
pub(crate) struct GitHubIntegration {
    server: String,
}

impl GitHubIntegration {
    /// Create a new GitHub integration checker.
    #[must_use]
    pub(crate) fn new(server: &str) -> Self {
        Self {
            server: server.to_string(),
        }
    }
}

/// GitHub integration status.
struct GitHubStatus {
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

impl GitHubIntegration {
    /// Check and print GitHub integration status.
    ///
    /// GitHub needs custom printing due to its complex account list format.
    pub(crate) async fn check_and_print(&self) {
        let status = check_github_status(&self.server).await;
        print_github_status(&status, &self.server);
    }
}

/// Check GitHub integration status.
async fn check_github_status(server: &str) -> GitHubStatus {
    let (local_configured, host) = check_git_credential_helper();

    // Try to get server status
    let (server_status, server_error) = match get_github_server_status(server).await {
        Ok(status) => (Some(status), None),
        Err(e) => (None, Some(e.to_string())),
    };

    // Check current repo if we have server status
    let current_repo = server_status.as_ref().and_then(check_current_repo_access);

    GitHubStatus {
        local_configured,
        host,
        server_status,
        server_error,
        current_repo,
    }
}

/// Print GitHub integration status.
fn print_github_status(status: &GitHubStatus, server: &str) {
    match &status.server_status {
        Some(server_status) if server_status.configured && server_status.connected => {
            // Fully working - show connected accounts
            let host = status.host.as_deref().unwrap_or("github.com");
            println!(
                "  {:LABEL_WIDTH$} {} ({host})",
                "GitHub:",
                style::green("connected")
            );
            if !server_status.github_accounts.is_empty() {
                print_github_accounts(server_status, &status.current_repo);
            }
        }
        Some(server_status) if !server_status.configured => {
            // Server doesn't have GitHub App configured at all
            println!(
                "  {:LABEL_WIDTH$} {}",
                "GitHub:",
                style::dim("not available")
            );
            println!(
                "{VALUE_INDENT}{}",
                style::dim("Server does not have GitHub App configured")
            );
        }
        Some(_) => {
            // GitHub App configured on server, but not installed for this org
            println!(
                "  {:LABEL_WIDTH$} {}",
                "GitHub:",
                style::yellow("not installed")
            );
            println!("{VALUE_INDENT}Admin action: visit {server}/github/connect");
            if status.local_configured {
                let host = status.host.as_deref().unwrap_or("github.com");
                println!("{VALUE_INDENT}(git credential helper ready for {host})");
            }
        }
        None => {
            // Couldn't reach server or get status
            if let Some(err) = &status.server_error {
                tracing::debug!("GitHub status error: {err}");
            }
            if status.local_configured {
                let host = status.host.as_deref().unwrap_or("github.com");
                println!(
                    "  {:LABEL_WIDTH$} {} (git helper configured for {host})",
                    "GitHub:",
                    style::yellow("unknown")
                );
                println!("{VALUE_INDENT}Could not check server status");
            } else {
                println!(
                    "  {:LABEL_WIDTH$} {}",
                    "GitHub:",
                    style::dim("not configured")
                );
                println!("{VALUE_INDENT}{}", style::dim("Run: vouch setup github"));
            }
        }
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
    let client = VouchClient::new(server).await?;
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
        .is_ok_and(|s| s.success())
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
            && let Some(path) = url.get(colon_pos.saturating_add(1)..)
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

/// Print connected GitHub accounts with their accessible repos.
fn print_github_accounts(status: &GitHubStatusResponse, current_repo: &Option<CurrentRepoStatus>) {
    // Track which current repo remotes we've printed
    let mut printed_remotes: std::collections::HashSet<String> = std::collections::HashSet::new();

    for account in &status.github_accounts {
        if account.suspended {
            let current_tag = format_current_tag_for_owner(&account.login, current_repo);
            println!(
                "{VALUE_INDENT}{} {}/*{} (suspended)",
                style::red("\u{2718}"),
                account.login,
                current_tag
            );
            mark_owner_remotes_printed(&account.login, current_repo, &mut printed_remotes);
        } else if account.repository_selection == "all" {
            let current_tag = format_current_tag_for_owner(&account.login, current_repo);
            println!(
                "{VALUE_INDENT}{} {}/*{}",
                style::green("\u{2714}"),
                account.login,
                current_tag
            );
            mark_owner_remotes_printed(&account.login, current_repo, &mut printed_remotes);
        } else if let Some(repos) = &account.repositories {
            if repos.is_empty() {
                let current_tag = format_current_tag_for_owner(&account.login, current_repo);
                println!(
                    "{VALUE_INDENT}{} {}/*{} (no repos)",
                    style::red("\u{2718}"),
                    account.login,
                    current_tag
                );
            } else {
                for repo in repos {
                    let current_tag =
                        format_current_tag_for_repo(&account.login, repo, current_repo);
                    if !current_tag.is_empty() {
                        printed_remotes
                            .insert(format!("{}/{}", account.login, repo).to_lowercase());
                    }
                    println!(
                        "{VALUE_INDENT}{} {}/{}{}",
                        style::green("\u{2714}"),
                        account.login,
                        repo,
                        current_tag
                    );
                }
            }
        } else {
            println!("{VALUE_INDENT}? {}/* (repos unknown)", account.login);
        }
    }

    // Print any inaccessible remotes from current repo that weren't already shown
    if let Some(repo_status) = current_repo {
        for r in &repo_status.inaccessible {
            let key = format!("{}/{}", r.owner, r.repo).to_lowercase();
            if !printed_remotes.contains(&key) {
                println!(
                    "{VALUE_INDENT}{} {}/{} ({}) [current]",
                    style::red("\u{2718}"),
                    r.owner,
                    r.repo,
                    r.name
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

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // URL Parsing Tests
    // ==========================================================================

    #[test]
    fn test_parse_github_ssh_url() {
        let result = parse_github_remote_url("git@github.com:owner/repo.git");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_parse_github_ssh_url_no_git_suffix() {
        let result = parse_github_remote_url("git@github.com:owner/repo");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_parse_github_https_url() {
        let result = parse_github_remote_url("https://github.com/owner/repo.git");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_parse_github_https_url_no_git_suffix() {
        let result = parse_github_remote_url("https://github.com/owner/repo");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_parse_github_http_url() {
        let result = parse_github_remote_url("http://github.com/owner/repo.git");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_parse_github_enterprise_ssh() {
        let result = parse_github_remote_url("git@ghe.com:myorg/myrepo.git");
        assert_eq!(result, Some(("myorg".to_string(), "myrepo".to_string())));
    }

    #[test]
    fn test_parse_github_enterprise_https() {
        let result = parse_github_remote_url("https://github.mycompany.com/team/project.git");
        assert_eq!(result, Some(("team".to_string(), "project".to_string())));
    }

    #[test]
    fn test_parse_non_github_url_returns_none() {
        let result = parse_github_remote_url("https://gitlab.com/owner/repo.git");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_owner_repo_path_with_git_suffix() {
        let result = parse_owner_repo_path("owner/repo.git");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_parse_owner_repo_path_without_git_suffix() {
        let result = parse_owner_repo_path("owner/repo");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_parse_owner_repo_path_only_owner() {
        let result = parse_owner_repo_path("owner");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_owner_repo_path_empty() {
        let result = parse_owner_repo_path("");
        assert_eq!(result, None);
    }

    // ==========================================================================
    // Current Tag Formatting Tests
    // ==========================================================================

    #[test]
    fn test_format_current_tag_empty() {
        let result = format_current_tag(&[]);
        assert_eq!(result, "");
    }

    #[test]
    fn test_format_current_tag_single() {
        let result = format_current_tag(&["origin"]);
        assert_eq!(result, " (origin) [current]");
    }

    #[test]
    fn test_format_current_tag_multiple() {
        let result = format_current_tag(&["origin", "upstream"]);
        assert_eq!(result, " (origin, upstream) [current]");
    }

    // ==========================================================================
    // Repository Accessibility Tests
    // ==========================================================================

    #[test]
    fn test_is_repo_accessible_not_configured() {
        let remote = GitRemote {
            name: "origin".to_string(),
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };
        let status = GitHubStatusResponse {
            configured: false,
            connected: false,
            github_accounts: vec![],
        };

        assert!(!is_repo_accessible(&remote, &status));
    }

    #[test]
    fn test_is_repo_accessible_not_connected() {
        let remote = GitRemote {
            name: "origin".to_string(),
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };
        let status = GitHubStatusResponse {
            configured: true,
            connected: false,
            github_accounts: vec![],
        };

        assert!(!is_repo_accessible(&remote, &status));
    }

    #[test]
    fn test_is_repo_accessible_all_repos() {
        use vouch_common::GitHubAccountStatus;

        let remote = GitRemote {
            name: "origin".to_string(),
            owner: "myorg".to_string(),
            repo: "anyrepo".to_string(),
        };
        let status = GitHubStatusResponse {
            configured: true,
            connected: true,
            github_accounts: vec![GitHubAccountStatus {
                login: "myorg".to_string(),
                account_type: "Organization".to_string(),
                suspended: false,
                repository_selection: "all".to_string(),
                repositories: None,
            }],
        };

        assert!(is_repo_accessible(&remote, &status));
    }

    #[test]
    fn test_is_repo_accessible_selected_repos_match() {
        use vouch_common::GitHubAccountStatus;

        let remote = GitRemote {
            name: "origin".to_string(),
            owner: "myorg".to_string(),
            repo: "allowed-repo".to_string(),
        };
        let status = GitHubStatusResponse {
            configured: true,
            connected: true,
            github_accounts: vec![GitHubAccountStatus {
                login: "myorg".to_string(),
                account_type: "Organization".to_string(),
                suspended: false,
                repository_selection: "selected".to_string(),
                repositories: Some(vec!["allowed-repo".to_string(), "other-repo".to_string()]),
            }],
        };

        assert!(is_repo_accessible(&remote, &status));
    }

    #[test]
    fn test_is_repo_accessible_selected_repos_no_match() {
        use vouch_common::GitHubAccountStatus;

        let remote = GitRemote {
            name: "origin".to_string(),
            owner: "myorg".to_string(),
            repo: "not-allowed".to_string(),
        };
        let status = GitHubStatusResponse {
            configured: true,
            connected: true,
            github_accounts: vec![GitHubAccountStatus {
                login: "myorg".to_string(),
                account_type: "Organization".to_string(),
                suspended: false,
                repository_selection: "selected".to_string(),
                repositories: Some(vec!["allowed-repo".to_string()]),
            }],
        };

        assert!(!is_repo_accessible(&remote, &status));
    }

    #[test]
    fn test_is_repo_accessible_suspended_account() {
        use vouch_common::GitHubAccountStatus;

        let remote = GitRemote {
            name: "origin".to_string(),
            owner: "myorg".to_string(),
            repo: "repo".to_string(),
        };
        let status = GitHubStatusResponse {
            configured: true,
            connected: true,
            github_accounts: vec![GitHubAccountStatus {
                login: "myorg".to_string(),
                account_type: "Organization".to_string(),
                suspended: true,
                repository_selection: "all".to_string(),
                repositories: None,
            }],
        };

        assert!(!is_repo_accessible(&remote, &status));
    }

    #[test]
    fn test_is_repo_accessible_case_insensitive_owner() {
        use vouch_common::GitHubAccountStatus;

        let remote = GitRemote {
            name: "origin".to_string(),
            owner: "MyOrg".to_string(),
            repo: "repo".to_string(),
        };
        let status = GitHubStatusResponse {
            configured: true,
            connected: true,
            github_accounts: vec![GitHubAccountStatus {
                login: "myorg".to_string(),
                account_type: "Organization".to_string(),
                suspended: false,
                repository_selection: "all".to_string(),
                repositories: None,
            }],
        };

        assert!(is_repo_accessible(&remote, &status));
    }

    #[test]
    fn test_is_repo_accessible_case_insensitive_repo() {
        use vouch_common::GitHubAccountStatus;

        let remote = GitRemote {
            name: "origin".to_string(),
            owner: "myorg".to_string(),
            repo: "MyRepo".to_string(),
        };
        let status = GitHubStatusResponse {
            configured: true,
            connected: true,
            github_accounts: vec![GitHubAccountStatus {
                login: "myorg".to_string(),
                account_type: "Organization".to_string(),
                suspended: false,
                repository_selection: "selected".to_string(),
                repositories: Some(vec!["myrepo".to_string()]),
            }],
        };

        assert!(is_repo_accessible(&remote, &status));
    }

    #[test]
    fn test_is_repo_accessible_no_matching_account() {
        use vouch_common::GitHubAccountStatus;

        let remote = GitRemote {
            name: "origin".to_string(),
            owner: "unknown-org".to_string(),
            repo: "repo".to_string(),
        };
        let status = GitHubStatusResponse {
            configured: true,
            connected: true,
            github_accounts: vec![GitHubAccountStatus {
                login: "myorg".to_string(),
                account_type: "Organization".to_string(),
                suspended: false,
                repository_selection: "all".to_string(),
                repositories: None,
            }],
        };

        assert!(!is_repo_accessible(&remote, &status));
    }
}
