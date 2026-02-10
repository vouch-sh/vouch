// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CodeCommit setup command.
//!
//! Configures Git to use the AWS CLI's built-in CodeCommit credential helper
//! with the Vouch AWS profile. This chains through Vouch automatically:
//!
//! 1. git asks for CodeCommit credentials
//! 2. `aws codecommit credential-helper` is invoked (with `--profile vouch`)
//! 3. AWS CLI needs credentials → reads `credential_process = vouch credential aws --role ...`
//! 4. Vouch gets OIDC token → STS AssumeRoleWithWebIdentity → returns temp AWS creds
//! 5. AWS CLI uses those creds to generate SigV4-signed CodeCommit credentials

use anyhow::{Context, Result};
use std::process::Command;

use crate::config::Config;
use crate::integrations::aws::{AwsConfig, extract_role_from_credential_process};

/// Git config patterns for CodeCommit credential helper.
///
/// Both commercial and China domain patterns are always configured —
/// non-matching entries are harmless and it avoids needing a `--china` flag.
const COMMERCIAL_PATTERN: &str = "https://git-codecommit.*.amazonaws.com";
const CHINA_PATTERN: &str = "https://git-codecommit.*.amazonaws.com.cn";

/// Run the CodeCommit setup command.
///
/// This command:
/// 1. Verifies the user is enrolled
/// 2. Checks AWS is configured and shows profile/role
/// 3. Verifies the AWS CLI is installed
/// 4. Configures git to use `aws codecommit credential-helper` with the vouch profile
///
/// # Arguments
/// * `region` - Optional specific region (default: wildcard `*` matching all regions)
/// * `profile` - Optional AWS profile name (default: auto-detect vouch profile)
/// * `configure` - If true, automatically configure git; if false, just show instructions
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

    // Verify AWS CLI is installed
    check_aws_cli_installed()?;

    // Build the helper command using the AWS CLI's built-in credential helper.
    // The `!` prefix tells git this is a shell command, not an executable name.
    // `$@` passes through the git credential operation (get/store/erase).
    let helper_command = format!(
        "!aws --profile {profile_name} codecommit credential-helper $@"
    );

    // Determine the credential pattern(s)
    let patterns = if let Some(r) = region {
        vec![
            format!("https://git-codecommit.{r}.amazonaws.com"),
            format!("https://git-codecommit.{r}.amazonaws.com.cn"),
        ]
    } else {
        vec![COMMERCIAL_PATTERN.to_string(), CHINA_PATTERN.to_string()]
    };

    if configure {
        // Check for conflicting credential helpers
        detect_conflicting_helpers()?;

        for pattern in &patterns {
            let config_key = format!("credential.{pattern}.helper");
            let use_http_path_key = format!("credential.{pattern}.useHttpPath");

            // Configure the credential helper
            let status = Command::new("git")
                .args(["config", "--global", &config_key, &helper_command])
                .status()
                .context("failed to run git config")?;

            if !status.success() {
                anyhow::bail!("failed to configure git credential helper for {pattern}");
            }

            // Set useHttpPath = true (critical for CodeCommit — git must pass the
            // full path including region and repo name)
            let status = Command::new("git")
                .args(["config", "--global", &use_http_path_key, "true"])
                .status()
                .context("failed to run git config")?;

            if !status.success() {
                anyhow::bail!("failed to set useHttpPath for {pattern}");
            }
        }

        println!("Git configured for CodeCommit.");
        println!();
        println!("Configuration added:");
        for pattern in &patterns {
            println!("  credential.{pattern}.helper = {helper_command}");
            println!("  credential.{pattern}.useHttpPath = true");
        }
    } else {
        println!("Add to ~/.gitconfig:\n");
        for pattern in &patterns {
            println!("[credential \"{pattern}\"]");
            println!("    helper = {helper_command}");
            println!("    useHttpPath = true");
            println!();
        }
        println!("Or run: vouch setup codecommit --configure");
    }

    println!();
    println!("To verify, run:");
    println!("  git ls-remote https://git-codecommit.us-east-1.amazonaws.com/v1/repos/YOUR-REPO");

    println!();
    println!("To undo:");
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

/// Verify the AWS CLI is installed and accessible.
fn check_aws_cli_installed() -> Result<()> {
    let output = Command::new("aws")
        .arg("--version")
        .output()
        .context(
            "AWS CLI not found. Install it from https://aws.amazon.com/cli/\n\
             The AWS CLI is required for CodeCommit credential generation.",
        )?;

    if !output.status.success() {
        anyhow::bail!(
            "AWS CLI check failed. Install it from https://aws.amazon.com/cli/\n\
             The AWS CLI is required for CodeCommit credential generation."
        );
    }

    let version = String::from_utf8_lossy(&output.stdout);
    let version_str = version.trim();
    if !version_str.is_empty() {
        println!("AWS CLI:     {version_str}");
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
            // Skip entries that are already using the AWS CLI with a vouch profile
            if line.contains("--profile vouch") || line.contains("--profile=vouch") {
                continue;
            }
            if line.contains("aws codecommit credential-helper")
                || line.contains("git-remote-codecommit")
                || line.contains("vouch credential codecommit")
            {
                println!("Warning: Existing CodeCommit credential helper detected:\n  {line}");
                println!("This may conflict. Consider removing it.\n");
            }
        }
    }

    Ok(())
}
