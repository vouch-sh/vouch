// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub setup command.
//!
//! Configures Git to use Vouch for GitHub credentials.

use anyhow::{Context, Result};
use vouch_cli::{tr, tr_println};
use vouch_common::GitHubStatusResponse;

use crate::commands::credential::github::check_status;
use crate::config::Config;
use crate::install_path::resolve_install_path;

/// Run the GitHub setup command.
///
/// This command:
/// 1. Checks if the user is logged in and has GitHub access
/// 2. Shows/configures git credential helper settings
///
/// # Arguments
/// * `host` - The GitHub host to configure (default: "github.com")
/// * `configure` - If true, automatically configure git; if false, just show instructions
pub(crate) async fn run(host: &str, configure: bool) -> Result<()> {
    // Load config to get server URL
    let config = Config::load().with_context(|| tr!("setup-err-load-config"))?;
    let server = config
        .server_url()
        .with_context(|| tr!("setup-err-not-configured"))?;

    tr_println!("setup-github-header");
    println!();

    // Check login status and GitHub connectivity
    match check_status(server).await {
        Ok(status) => {
            print_status(&status);

            if !status.configured {
                println!();
                tr_println!("setup-github-not-configured-block");
                return Ok(());
            }

            if !status.connected {
                println!();
                tr_println!("setup-github-org-not-connected-block", server = server);
                return Ok(());
            }

            // Check if all installations are suspended
            let all_suspended = !status.github_accounts.is_empty()
                && status.github_accounts.iter().all(|a| a.suspended);
            if all_suspended {
                println!();
                tr_println!("setup-github-all-suspended-block");
                return Ok(());
            }
        }
        Err(e) => {
            if e.to_string().contains("not authenticated") {
                tr_println!("setup-github-not-logged-in-block");
                return Ok(());
            }
            // Server might not have the endpoint yet, continue with setup
            tr_println!("setup-github-could-not-check", reason = format!("{e:#}"));
            println!();
        }
    }

    // Get vouch binary path
    let vouch_path = resolve_install_path();

    // Build the helper command.
    //
    // The leading `!` is required: git only runs a helper value through a shell
    // when it starts with `!` or is literally an absolute path. A value starting
    // with `"` matches neither, so git would build `git credential-"<path>"` and
    // fail with "is not a git command". The path is single-quoted so it survives
    // intact when it contains spaces (or any other shell metacharacter).
    let helper_command = credential_helper_command(&vouch_path);

    // Git config key for this host
    let config_key = format!("credential.https://{}.helper", host);

    if configure {
        // Check for existing helpers that might conflict
        if let Some(existing) = detect_existing_helper(host) {
            tr_println!(
                "setup-github-existing-warning-block",
                existing = existing.as_str()
            );
            println!();
        }

        // Configure git
        if !crate::git_config::set_global(&config_key, &helper_command)
            .with_context(|| tr!("setup-github-err-run-config"))?
        {
            return Err(
                crate::exit_code::CliError::ConfigError(tr!("setup-github-err-helper")).into(),
            );
        }

        tr_println!(
            "setup-github-configured-block",
            host = host,
            key = config_key.as_str(),
            value = helper_command.as_str(),
        );
    } else {
        tr_println!(
            "setup-github-add-to-gitconfig",
            host = host,
            helper_command = helper_command.as_str(),
        );
    }

    println!();
    tr_println!("setup-github-to-verify", host = host);

    Ok(())
}

/// Build the `credential.https://<host>.helper` value git will execute.
///
/// The leading `!` is required: git only runs a helper value through a shell
/// when it starts with `!` or is literally an absolute path. The install path
/// is single-quoted because it routinely contains spaces
/// (`/Users/John Smith/.cargo/bin/vouch`), and single quotes make every other
/// character literal to the shell.
fn credential_helper_command(vouch_path: &std::path::Path) -> String {
    let quoted_path = crate::utils::shell_single_quote(&vouch_path.display().to_string());
    format!("!{quoted_path} credential github")
}

/// Print GitHub status information.
fn print_status(status: &GitHubStatusResponse) {
    tr_println!(
        "setup-github-app-configured",
        configured = status.configured.to_string(),
    );
    tr_println!(
        "setup-github-org-connected",
        connected = status.connected.to_string(),
    );

    if !status.github_accounts.is_empty() {
        tr_println!("setup-github-accounts-header");
        for account in &status.github_accounts {
            tr_println!(
                "setup-github-account-line",
                indent = "  ",
                login = account.login.as_str(),
                kind = account.account_type.as_str(),
                suspended = account.suspended.to_string(),
            );
        }
    }

    println!();
}

/// Detect existing credential helpers for the given host.
///
/// Returns a non-vouch helper if one is already configured, so the caller can
/// warn before overwriting it.
fn detect_existing_helper(host: &str) -> Option<String> {
    let config_key = format!("credential.https://{}.helper", host);
    crate::git_config::get_global(&config_key).filter(|helper| !helper.contains("vouch"))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::credential_helper_command;

    /// Git runs credential helpers through a shell, so a vouch binary path
    /// containing spaces must stay quoted as a single token (same defect as
    /// the codecommit helper, fixed the same way).
    #[test]
    fn helper_command_quotes_path_with_spaces() {
        let vouch_path = std::path::Path::new("/Users/John Smith/.cargo/bin/vouch");
        assert_eq!(
            credential_helper_command(vouch_path),
            "!'/Users/John Smith/.cargo/bin/vouch' credential github"
        );
    }

    /// Git only executes a credential helper value that starts with `!` or is
    /// literally an absolute path; a value starting with `"` takes neither
    /// branch and git builds `git credential-"<path>"` instead.
    #[test]
    fn helper_command_is_shell_prefixed() {
        let value = credential_helper_command(std::path::Path::new("/opt/homebrew/bin/vouch"));
        assert!(
            value.starts_with('!'),
            "git will not execute a helper value that lacks the '!' prefix: {value}"
        );
    }

    /// Drive a real `git credential fill` against a stub helper installed at a
    /// path containing a space, and return git's stdout.
    ///
    /// Uses `example.com` rather than `github.com`: macOS ships a
    /// distribution-level `credential.helper = osxkeychain` (in
    /// `git-core/gitconfig` under the Xcode/CLT prefix) that neither
    /// `GIT_CONFIG_GLOBAL` nor `GIT_CONFIG_SYSTEM` suppresses, so a real
    /// `github.com` request also runs the developer's actual keychain-cached
    /// helper (e.g. `gh`'s) alongside the stub and returns real credentials
    /// instead of the stub's. `example.com` has nothing cached there.
    #[cfg(unix)]
    fn run_helper_via_git() -> String {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("create temp dir");
        let bin_dir = dir.path().join("bin with space");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");
        let stub = bin_dir.join("vouch");
        std::fs::write(
            &stub,
            "#!/bin/sh\necho \"username=$1|$2\"\necho password=stub-pass\n",
        )
        .expect("write stub helper");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stub helper");

        let gitconfig = dir.path().join("gitconfig");
        let status = std::process::Command::new("git")
            .args(["config", "--file"])
            .arg(&gitconfig)
            .arg("credential.https://example.com.helper")
            .arg(credential_helper_command(&stub))
            .status()
            .expect("write helper into a git config file");
        assert!(status.success(), "git config write failed");

        let mut child = std::process::Command::new("git")
            // Isolate from the developer's real git configuration.
            .env("GIT_CONFIG_GLOBAL", &gitconfig)
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(["credential", "fill"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn git credential fill");

        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"protocol=https\nhost=example.com\n\n")
            .expect("write credential request");

        let output = child.wait_with_output().expect("wait for git");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "git credential fill failed: {stderr}"
        );

        stdout
            .lines()
            .filter(|l| l.starts_with("username=") || l.starts_with("password="))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// End-to-end proof that git runs the helper and reads its output — the
    /// same class of bug (missing `!`, dropped quoting) that broke the
    /// CodeCommit helper would break this one identically.
    #[cfg(unix)]
    #[test]
    fn git_executes_the_helper_command() {
        let output = run_helper_via_git();
        assert!(
            output.contains("username=credential|github"),
            "git did not run the helper with its arguments intact: {output}"
        );
        assert!(
            output.contains("password=stub-pass"),
            "git did not read the helper output: {output}"
        );
    }
}
