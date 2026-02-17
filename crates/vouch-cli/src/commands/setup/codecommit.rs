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
use std::path::PathBuf;
use std::process::Command;

use crate::config::Config;
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
pub async fn run(region: Option<&str>, profile: Option<&str>, configure: bool) -> Result<()> {
    // Load config to verify enrollment
    let config = Config::load().context("failed to load config - run 'vouch enroll' first")?;
    let _server = config
        .server_url()
        .context("not configured - run 'vouch enroll' first")?;

    println!("CodeCommit Credential Setup");
    println!("===========================\n");

    // Check AWS configuration
    let (profile_name, role_arn) = check_aws_config(profile)?;
    println!("AWS profile: {profile_name}");
    if let Some(ref role) = role_arn {
        println!("AWS role:    {role}");
    }
    println!();

    // Get vouch binary path for the credential helper command and symlink
    let vouch_path = std::env::current_exe().context("could not determine vouch binary path")?;

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
    let symlink_path = get_remote_helper_symlink_path()?;

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
                .context("failed to run git config")?;

            if !status.success() {
                anyhow::bail!("failed to configure git credential helper for {pattern}");
            }

            // useHttpPath is critical — git must pass the full path (region + repo)
            let status = Command::new("git")
                .args(["config", "--global", &use_http_path_key, "true"])
                .status()
                .context("failed to run git config")?;

            if !status.success() {
                anyhow::bail!("failed to set useHttpPath for {pattern}");
            }
        }

        println!("\nGit configured for CodeCommit.\n");
        println!("Credential helper (HTTPS URLs):");
        for pattern in &patterns {
            println!("  credential.{pattern}.helper = {helper_command}");
            println!("  credential.{pattern}.useHttpPath = true");
        }
        println!();
        println!("Remote helper (codecommit:// URLs):");
        println!("  {} -> {}", symlink_path.display(), vouch_path.display());
    } else {
        println!("Step 1: Create symlink for codecommit:// URL support\n");
        println!(
            "  ln -sf \"{}\" \"{}\"",
            vouch_path.display(),
            symlink_path.display()
        );

        println!("\nStep 2: Configure git credential helper for HTTPS URLs\n");
        println!("  Add to ~/.gitconfig:\n");
        for pattern in &patterns {
            println!("[credential \"{pattern}\"]");
            println!("    helper = {helper_command}");
            println!("    useHttpPath = true");
            println!();
        }
        println!("Or run: vouch setup codecommit --configure");
    }

    let example_region = region.unwrap_or("us-east-1");
    println!();
    println!("To verify, run:");
    println!(
        "  git ls-remote https://git-codecommit.{example_region}.amazonaws.com/v1/repos/YOUR-REPO"
    );
    println!("  git ls-remote codecommit::{example_region}://YOUR-REPO");

    println!();
    println!("To undo:");
    println!("  rm \"{}\"", symlink_path.display());
    for pattern in &patterns {
        println!(
            "  git config --global --remove-section credential.\"{}\"",
            pattern
        );
    }

    Ok(())
}

/// Check AWS configuration and return (profile_name, optional_role_arn).
fn check_aws_config(profile: Option<&str>) -> Result<(String, Option<String>)> {
    let aws_config = AwsConfig::load().map_err(|_| {
        anyhow::anyhow!("AWS not configured. Run 'vouch setup aws --role <role-arn>' first.")
    })?;

    if let Some(profile_name) = profile {
        // User specified a profile — look it up
        let profile_data = aws_config.get_profile(profile_name).ok_or_else(|| {
            anyhow::anyhow!(
                "AWS profile '{profile_name}' not found in ~/.aws/config.\n\
                 Run 'vouch setup aws --role <role-arn>' first."
            )
        })?;
        let role_arn = profile_data
            .credential_process
            .as_deref()
            .and_then(extract_role_from_credential_process);
        Ok((profile_name.to_string(), role_arn))
    } else {
        // Auto-detect the vouch profile
        let profile = aws_config.find_vouch_profile().ok_or_else(|| {
            anyhow::anyhow!(
                "No Vouch AWS profile found in ~/.aws/config.\n\
                 Run 'vouch setup aws --role <role-arn>' first."
            )
        })?;
        let role_arn = profile
            .credential_process
            .as_deref()
            .and_then(extract_role_from_credential_process);
        Ok((profile.name, role_arn))
    }
}

/// Get the path for the `git-remote-codecommit` symlink.
fn get_remote_helper_symlink_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;

    #[cfg(unix)]
    {
        Ok(home.join(".local/bin/git-remote-codecommit"))
    }

    #[cfg(windows)]
    {
        Ok(home
            .join(".local")
            .join("bin")
            .join("git-remote-codecommit"))
    }
}

/// Create the `git-remote-codecommit` symlink pointing to the vouch binary.
fn create_remote_helper_symlink(
    vouch_path: &std::path::Path,
    symlink_path: &std::path::Path,
) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = symlink_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
        println!("Created directory: {}", parent.display());
    }

    #[cfg(unix)]
    {
        // Remove existing symlink if present
        if symlink_path.exists() || symlink_path.is_symlink() {
            std::fs::remove_file(symlink_path)
                .with_context(|| format!("failed to remove existing {}", symlink_path.display()))?;
        }

        std::os::unix::fs::symlink(vouch_path, symlink_path)
            .with_context(|| format!("failed to create symlink at {}", symlink_path.display()))?;

        println!(
            "Created symlink: {} -> {}",
            symlink_path.display(),
            vouch_path.display()
        );

        // Check if the symlink directory is in PATH
        if let Some(parent) = symlink_path.parent()
            && let Ok(path_var) = std::env::var("PATH")
            && !std::env::split_paths(&path_var).any(|p| p == parent)
        {
            println!();
            println!("Note: {} is not in your PATH.", parent.display());
            println!("Add it to your shell profile:");
            println!("  export PATH=\"$PATH:{}\"", parent.display());
        }
    }

    #[cfg(windows)]
    {
        // On Windows, create a batch file wrapper
        let bat_path = symlink_path.with_extension("bat");

        if bat_path.exists() {
            std::fs::remove_file(&bat_path)
                .with_context(|| format!("failed to remove existing {}", bat_path.display()))?;
        }

        // The batch file sets VOUCH_GIT_REMOTE_CODECOMMIT=1 so vouch can detect
        // it was invoked as a remote helper (argv[0] detection doesn't work through .bat)
        let batch_content = format!(
            "@echo off\r\nset VOUCH_GIT_REMOTE_CODECOMMIT=1\r\n\"{}\" %*\r\n",
            vouch_path.display()
        );
        std::fs::write(&bat_path, &batch_content)
            .with_context(|| format!("failed to create {}", bat_path.display()))?;

        println!("Created: {}", bat_path.display());

        if let Some(parent) = bat_path.parent() {
            if let Ok(path_var) = std::env::var("PATH")
                && !std::env::split_paths(&path_var).any(|p| p == parent)
            {
                println!();
                println!("Note: {} is not in your PATH.", parent.display());
                println!("Add it to your system PATH environment variable.");
            }
        }
    }

    Ok(())
}

/// Detect credential helpers that may conflict with Vouch.
fn detect_conflicting_helpers() -> Result<()> {
    let output = Command::new("git")
        .args([
            "config",
            "--global",
            "--get-regexp",
            r"credential.*codecommit.*helper",
        ])
        .output()
        .context("failed to run git config")?;

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
                println!("Warning: Existing CodeCommit credential helper detected:\n  {line}");
                println!("This may conflict. Consider removing it.\n");
            }
        }
    }

    Ok(())
}
