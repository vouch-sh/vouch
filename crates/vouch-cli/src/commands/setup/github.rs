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
    let vouch_path_str = vouch_path.display().to_string();

    // Build the helper command.
    //
    // The leading `!` is required: git only runs a helper value through a shell
    // when it starts with `!` or is literally an absolute path. A value starting
    // with `"` matches neither, so git would build `git credential-"<path>"` and
    // fail with "is not a git command". The `!` also preserves the quoting that
    // keeps a vouch binary under a path containing spaces working.
    let helper_command = format!("!\"{vouch_path_str}\" credential github");

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
