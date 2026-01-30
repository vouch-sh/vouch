// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS setup command.
//!
//! Configures AWS CLI/SDK to use Vouch for credential federation.

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use crate::utils::ensure_secure_dir;

/// Get the AWS config directory (~/.aws).
fn aws_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".aws"))
}

/// Get the AWS config file path (~/.aws/config).
fn aws_config_path() -> Result<PathBuf> {
    Ok(aws_config_dir()?.join("config"))
}

/// Run the AWS setup command.
///
/// This command:
/// 1. Shows how to configure AWS CLI/SDK to use Vouch
/// 2. Optionally adds a profile to ~/.aws/config
pub async fn run(profile: &str, role_arn: &str, add_profile: bool) -> Result<()> {
    // Get the path to the vouch binary
    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));

    println!("AWS Credential Federation Setup");
    println!("================================");
    println!();

    if add_profile {
        // Add profile to AWS config
        add_aws_profile(profile, role_arn, &vouch_path)?;
        println!("Added profile [{profile}] to ~/.aws/config");
        println!();
    }

    println!("To use Vouch for AWS credentials, add this to ~/.aws/config:");
    println!();
    println!("[profile {profile}]");
    println!(
        "credential_process = {} credential aws --role {role_arn}",
        vouch_path.display()
    );
    println!();
    println!("Then use AWS CLI with the profile:");
    println!();
    println!("  aws --profile {profile} sts get-caller-identity");
    println!();
    println!("Or set the environment variable:");
    println!();
    println!("  export AWS_PROFILE={profile}");
    println!("  aws sts get-caller-identity");
    println!();
    println!("Prerequisites:");
    println!("  1. You must be logged in to Vouch: vouch login");
    println!("  2. The AWS role must trust the Vouch OIDC provider");
    println!();
    println!("To configure AWS role trust policy, see:");
    println!(
        "  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html"
    );

    Ok(())
}

/// Add a profile to the AWS config file.
fn add_aws_profile(profile: &str, role_arn: &str, vouch_path: &std::path::Path) -> Result<()> {
    let config_path = aws_config_path()?;
    let aws_dir = aws_config_dir()?;

    // Ensure .aws directory exists with secure permissions
    ensure_secure_dir(&aws_dir)?;

    // Read existing config or create empty
    let existing = if config_path.exists() {
        fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?
    } else {
        String::new()
    };

    // Check if profile already exists
    let profile_header = format!("[profile {profile}]");
    if existing.contains(&profile_header) {
        println!("Profile [{profile}] already exists in AWS config");
        println!("Please update it manually if needed.");
        return Ok(());
    }

    // Append new profile
    let profile_config = format!(
        "\n{profile_header}\ncredential_process = {} credential aws --role {role_arn}\n",
        vouch_path.display()
    );
    let new_config = format!("{existing}{profile_config}");

    fs::write(&config_path, new_config)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    Ok(())
}
