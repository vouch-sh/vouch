// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub setup command.
//!
//! Configures Git to use Vouch for GitHub credentials.

use anyhow::{Context, Result};
use std::process::Command;
use vouch_common::GitHubStatusResponse;

use crate::commands::credential::github::check_status;
use crate::config::Config;

/// Run the GitHub setup command.
///
/// This command:
/// 1. Checks if the user is logged in and has GitHub access
/// 2. Shows/configures git credential helper settings
///
/// # Arguments
/// * `host` - The GitHub host to configure (default: "github.com")
/// * `configure` - If true, automatically configure git; if false, just show instructions
pub async fn run(host: &str, configure: bool) -> Result<()> {
    // Load config to get server URL
    let config = Config::load().context("failed to load config - run 'vouch enroll' first")?;
    let server = config
        .server_url()
        .context("not configured - run 'vouch enroll' first")?;

    println!("GitHub Credential Setup");
    println!("=======================\n");

    // Check login status and GitHub connectivity
    match check_status(server).await {
        Ok(status) => {
            print_status(&status);

            if !status.configured {
                println!("\nGitHub App is not configured on the server.");
                println!("Contact your administrator to enable GitHub integration.");
                return Ok(());
            }

            if !status.connected {
                println!("\nYour organization has not connected GitHub.");
                println!(
                    "An organization admin needs to visit: {}/github/connect",
                    server
                );
                return Ok(());
            }

            // Check if all installations are suspended
            let all_suspended = !status.github_accounts.is_empty()
                && status.github_accounts.iter().all(|a| a.suspended);
            if all_suspended {
                println!("\nAll GitHub installations are currently suspended.");
                println!("Contact your administrator to resolve this.");
                return Ok(());
            }
        }
        Err(e) => {
            if e.to_string().contains("not authenticated") {
                println!("Login status: Not logged in");
                println!("\nRun 'vouch login' first to authenticate.");
                return Ok(());
            }
            // Server might not have the endpoint yet, continue with setup
            println!("Note: Could not check GitHub status: {e}");
            println!();
        }
    }

    // Get vouch binary path
    let vouch_path = std::env::current_exe().context("could not determine vouch binary path")?;
    let vouch_path_str = vouch_path.display().to_string();

    // Build the helper command
    let helper_command = format!("\"{}\" credential github", vouch_path_str);

    // Git config key for this host
    let config_key = format!("credential.https://{}.helper", host);

    if configure {
        // Check for existing helpers that might conflict
        if let Some(existing) = detect_existing_helper(host)? {
            println!("Warning: Existing credential helper detected: {}", existing);
            println!("This may conflict with Vouch.\n");
        }

        // Configure git
        let status = Command::new("git")
            .args(["config", "--global", &config_key, &helper_command])
            .status()
            .context("failed to run git config")?;

        if !status.success() {
            anyhow::bail!("failed to configure git credential helper");
        }

        println!("Git configured for {}", host);
        println!();
        println!("Configuration added:");
        println!("  {} = {}", config_key, helper_command);
    } else {
        println!("Add to ~/.gitconfig:\n");
        println!("[credential \"https://{}\"]", host);
        println!("    helper = {}", helper_command);
        println!();
        println!("Or run: vouch setup github --configure");
    }

    println!();
    println!("To verify, run:");
    println!("  git ls-remote https://{}/YOUR-ORG/YOUR-REPO.git", host);

    Ok(())
}

/// Print GitHub status information.
fn print_status(status: &GitHubStatusResponse) {
    println!(
        "GitHub App configured: {}",
        if status.configured { "Yes" } else { "No" }
    );
    println!(
        "Organization connected: {}",
        if status.connected { "Yes" } else { "No" }
    );

    if !status.github_accounts.is_empty() {
        println!("Connected GitHub accounts:");
        for account in &status.github_accounts {
            let suspended_indicator = if account.suspended {
                " (SUSPENDED)"
            } else {
                ""
            };
            println!(
                "  - {} ({}){}",
                account.login, account.account_type, suspended_indicator
            );
        }
    }

    println!();
}

/// Detect existing credential helpers for the given host.
fn detect_existing_helper(host: &str) -> Result<Option<String>> {
    let config_key = format!("credential.https://{}.helper", host);

    let output = Command::new("git")
        .args(["config", "--global", "--get", &config_key])
        .output()
        .context("failed to run git config")?;

    if output.status.success() {
        let helper = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !helper.is_empty() && !helper.contains("vouch") {
            return Ok(Some(helper));
        }
    }

    Ok(None)
}
