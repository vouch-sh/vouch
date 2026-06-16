// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CodeCommit setup command.
//!
//! Configures Git to use Vouch's native CodeCommit support:
//!
//! 1. **Credential helper** — for `https://git-codecommit.*.amazonaws.com` URLs:
//!    git asks for credentials → `vouch credential codecommit` signs with SigV4
//!
//! 2. **Remote helper** — for `codecommit://` URLs:
//!    `git-remote-codecommit` symlink → `vouch` binary → signs and delegates to `git remote-http`
//!
//! No AWS CLI dependency required. Vouch handles the full chain:
//! OIDC token → STS AssumeRoleWithWebIdentity → SigV4 signing for CodeCommit.

use anyhow::{Context, Result};
use std::process::Command;

use crate::config::Config;
use crate::install_path::resolve_install_path;
use crate::integrations::aws::{AwsConfig, extract_role_from_credential_process};

/// Git config patterns for CodeCommit credential helper by partition.
///
/// All partition patterns are always configured — non-matching entries are
/// harmless and it avoids needing partition-specific flags.
const PARTITION_PATTERNS: &[&str] = &[
    "https://git-codecommit.*.amazonaws.com", // Commercial + GovCloud
    "https://git-codecommit.*.amazonaws.com.cn", // China
    "https://git-codecommit.*.amazonaws.eu",  // European Sovereign Cloud (future)
];

/// Run the CodeCommit setup command.
///
/// This command:
/// 1. Verifies the user is enrolled
/// 2. Checks AWS is configured and shows profile/role
/// 3. Creates the `git-remote-codecommit` symlink for `codecommit://` URLs
/// 4. Configures git to use `vouch credential codecommit` for HTTPS URLs
///
/// # Arguments
/// * `region` - Optional specific region (default: wildcard `*` matching all regions)
/// * `profile` - Optional AWS profile name (default: auto-detect vouch profile)
/// * `configure` - If true, automatically configure; if false, just show instructions
pub(crate) async fn run(
    region: Option<&str>,
    profile: Option<&str>,
    configure: bool,
) -> Result<()> {
    use vouch_cli::{tr, tr_args, tr_println};

    // Load config to verify enrollment
    let config = Config::load().with_context(|| tr!("setup-err-load-config"))?;
    let _server = config
        .server_url()
        .with_context(|| tr!("setup-err-not-configured"))?;

    tr_println!("setup-codecommit-header");
    println!();

    // Check AWS configuration
    let (profile_name, role_arn) = check_aws_config(profile)?;
    tr_println!("setup-codecommit-aws-profile", profile = &profile_name);
    if let Some(ref role) = role_arn {
        tr_println!("setup-codecommit-aws-role", role = role);
    }
    println!();

    // Get vouch binary path for the credential helper command and symlink
    let vouch_path = resolve_install_path();

    // Build the native credential helper command
    let helper_command = format!("{} credential codecommit", vouch_path.display());

    // Determine the credential pattern(s)
    let patterns: Vec<String> = if let Some(r) = region {
        // Region-specific: replace wildcard with actual region in each partition pattern
        PARTITION_PATTERNS
            .iter()
            .map(|p| p.replace('*', r))
            .collect()
    } else {
        PARTITION_PATTERNS
            .iter()
            .map(|p| (*p).to_string())
            .collect()
    };

    // Symlink path for git-remote-codecommit
    let symlink_path = crate::utils::vouch_helper_path("git-remote-codecommit")?;

    if configure {
        // Check for conflicting credential helpers
        detect_conflicting_helpers()?;

        // 1. Create git-remote-codecommit symlink for codecommit:// URLs
        create_remote_helper_symlink(&vouch_path, &symlink_path)?;

        // 2. Configure git credential helper for HTTPS URLs
        for pattern in &patterns {
            let config_key = format!("credential.{pattern}.helper");
            let use_http_path_key = format!("credential.{pattern}.useHttpPath");

            let status = Command::new("git")
                .args(["config", "--global", &config_key, &helper_command])
                .status()
                .with_context(|| tr!("setup-codecommit-err-run-config"))?;

            if !status.success() {
                return Err(crate::exit_code::CliError::ConfigError(tr_args!(
                    "setup-codecommit-err-helper-pattern",
                    pattern = pattern,
                ))
                .into());
            }

            // useHttpPath is critical — git must pass the full path (region + repo)
            let status = Command::new("git")
                .args(["config", "--global", &use_http_path_key, "true"])
                .status()
                .with_context(|| tr!("setup-codecommit-err-run-config"))?;

            if !status.success() {
                return Err(crate::exit_code::CliError::ConfigError(tr_args!(
                    "setup-codecommit-err-http-path",
                    pattern = pattern,
                ))
                .into());
            }
        }

        println!();
        tr_println!("setup-codecommit-success-block");
        for pattern in &patterns {
            tr_println!(
                "setup-codecommit-helper-line",
                indent = "  ",
                pattern = pattern,
                helper = &helper_command,
            );
            tr_println!(
                "setup-codecommit-http-path-line",
                indent = "  ",
                pattern = pattern,
            );
        }
        println!();
        tr_println!("setup-codecommit-remote-helper-header");
        tr_println!(
            "setup-codecommit-remote-line",
            indent = "  ",
            symlink = symlink_path.display(),
            vouch = vouch_path.display(),
        );
    } else {
        tr_println!("setup-codecommit-step1");
        println!();
        println!(
            "  ln -sf \"{}\" \"{}\"",
            vouch_path.display(),
            symlink_path.display()
        );

        println!();
        tr_println!("setup-codecommit-step2");
        println!();
        for pattern in &patterns {
            println!("[credential \"{pattern}\"]");
            println!("    helper = {helper_command}");
            println!("    useHttpPath = true");
            println!();
        }
        tr_println!("setup-codecommit-or-run");
    }

    let example_region = region.unwrap_or("us-east-1");
    println!();
    tr_println!("setup-codecommit-tail-block", region = example_region);
    tr_println!(
        "setup-codecommit-undo-rm",
        indent = "  ",
        path = symlink_path.display(),
    );
    for pattern in &patterns {
        tr_println!(
            "setup-codecommit-undo-config",
            indent = "  ",
            pattern = pattern,
        );
    }

    Ok(())
}

/// Check AWS configuration and return (profile_name, optional_role_arn).
fn check_aws_config(profile: Option<&str>) -> Result<(String, Option<String>)> {
    use vouch_cli::{tr, tr_args};

    let aws_config = AwsConfig::load()
        .map_err(|_| anyhow::anyhow!(tr!("setup-codecommit-err-aws-not-configured")))?;

    if let Some(profile_name) = profile {
        // User specified a profile — look it up
        let profile_data = aws_config.get_profile(profile_name).ok_or_else(|| {
            anyhow::anyhow!(tr_args!(
                "setup-codecommit-err-profile-not-found",
                profile = profile_name,
            ))
        })?;
        let role_arn = profile_data
            .credential_process
            .as_deref()
            .and_then(extract_role_from_credential_process);
        Ok((profile_name.to_string(), role_arn))
    } else {
        // Auto-detect the vouch profile
        let profile = aws_config
            .find_vouch_profile()
            .ok_or_else(|| anyhow::anyhow!(tr!("setup-codecommit-err-no-vouch-profile")))?;
        let role_arn = profile
            .credential_process
            .as_deref()
            .and_then(extract_role_from_credential_process);
        Ok((profile.name, role_arn))
    }
}

/// Create the `git-remote-codecommit` symlink pointing to the vouch binary.
fn create_remote_helper_symlink(
    vouch_path: &std::path::Path,
    symlink_path: &std::path::Path,
) -> Result<()> {
    // The batch file sets VOUCH_GIT_REMOTE_CODECOMMIT=1 so vouch can detect
    // it was invoked as a remote helper (argv[0] detection doesn't work through .bat)
    let batch_content = format!(
        "@echo off\r\nset VOUCH_GIT_REMOTE_CODECOMMIT=1\r\n\"{}\" %*\r\n",
        vouch_path.display()
    );
    crate::utils::create_symlink_with_fallback(vouch_path, symlink_path, &batch_content)
}

/// Detect credential helpers that may conflict with Vouch.
fn detect_conflicting_helpers() -> Result<()> {
    use vouch_cli::{tr, tr_println};

    let output = Command::new("git")
        .args([
            "config",
            "--global",
            "--get-regexp",
            r"credential.*codecommit.*helper",
        ])
        .output()
        .with_context(|| tr!("setup-codecommit-err-run-config"))?;

    if output.status.success() {
        let existing = String::from_utf8_lossy(&output.stdout);
        for line in existing.lines() {
            // Skip entries that already use vouch
            if line.contains("vouch credential codecommit") {
                continue;
            }
            if line.contains("aws codecommit credential-helper")
                || line.contains("git-remote-codecommit")
            {
                tr_println!("setup-codecommit-warn-existing-block", line = line);
            }
        }
    }

    Ok(())
}
