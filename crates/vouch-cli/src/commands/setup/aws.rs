// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS setup command.
//!
//! Configures AWS CLI/SDK to use Vouch for credential federation.

use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::aws_config::{AwsConfig, AwsProfile};
use crate::utils::ensure_secure_dir;

/// Get the AWS config directory (~/.aws).
fn aws_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".aws"))
}

/// Check if a profile already exists in AWS config.
fn profile_exists(profile: &str) -> bool {
    AwsConfig::load()
        .map(|c| c.profile_exists(profile))
        .unwrap_or(false)
}

/// Run the AWS setup command.
///
/// This command:
/// 1. Shows how to configure AWS CLI/SDK to use Vouch
/// 2. Optionally adds a profile to ~/.aws/config
pub async fn run(profile: Option<&str>, role_arn: &str, add_profile: bool) -> Result<()> {
    // Determine profile name
    let profile = match profile {
        Some(p) => p.to_string(),
        None => {
            // Default to "vouch" if it doesn't exist yet
            if profile_exists("vouch") {
                println!("Profile [vouch] already exists in ~/.aws/config.");
                println!();
                println!("To add another profile with a different role, run:");
                println!();
                println!("  vouch setup aws --profile <name> --role {role_arn}");
                println!();
                println!("To update the existing [vouch] profile, edit ~/.aws/config directly.");
                return Ok(());
            }
            "vouch".to_string()
        }
    };

    // Get the path to the vouch binary
    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));

    println!("AWS Credential Federation Setup");
    println!("================================");
    println!();

    if add_profile {
        // Add profile to AWS config
        add_aws_profile(&profile, role_arn, &vouch_path)?;
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
    let config_path = AwsConfig::default_path()?;
    let aws_dir = aws_config_dir()?;

    // Ensure .aws directory exists with secure permissions
    ensure_secure_dir(&aws_dir)?;

    // Load existing config or create empty
    let mut config =
        AwsConfig::load_from(config_path.clone()).unwrap_or_else(|_| AwsConfig::empty(config_path));

    // Check if profile already exists
    if config.profile_exists(profile) {
        println!("Profile [{profile}] already exists in AWS config");
        println!("Please update it manually if needed.");
        return Ok(());
    }

    // Add new profile and save (preserves all existing sections/keys)
    config.set_profile(&AwsProfile {
        name: profile.to_string(),
        credential_process: Some(format!(
            "{} credential aws --role {role_arn}",
            vouch_path.display()
        )),
        region: None,
    });
    config.save()
}
