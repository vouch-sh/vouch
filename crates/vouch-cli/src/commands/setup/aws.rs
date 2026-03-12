// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS setup command.
//!
//! Configures AWS CLI/SDK to use Vouch for credential federation.

use anyhow::Result;
use std::path::PathBuf;

use crate::integrations::aws::{AwsConfig, AwsProfile, aws_config_dir};
use crate::utils::ensure_secure_dir;

/// Run the AWS setup command.
///
/// Automatically adds a vouch profile to ~/.aws/config with smart naming:
/// - If `--profile` is given, uses that name (exits early if it already exists).
/// - Otherwise, checks existing vouch profiles for a role match (exits early if found),
///   then picks the next available name: "vouch", "vouch-2", "vouch-3", etc.
pub async fn run(profile: Option<&str>, role_arn: &str, region: Option<&str>) -> Result<()> {
    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));

    let config_path = AwsConfig::default_path()?;
    let aws_dir = aws_config_dir()?;

    // Ensure .aws directory exists with secure permissions
    ensure_secure_dir(&aws_dir)?;

    // Load existing config or create empty
    let mut config =
        AwsConfig::load_from(config_path.clone()).unwrap_or_else(|_| AwsConfig::empty(config_path));

    let profile_name = match profile {
        Some(p) => {
            // Explicit profile name: exit early if it already exists
            if config.profile_exists(p) {
                println!("Profile [{p}] already exists in ~/.aws/config.");
                println!("To update it, edit ~/.aws/config directly.");
                return Ok(());
            }
            p.to_string()
        }
        None => {
            // Auto-naming: check if a vouch profile already targets this role
            if let Some(existing) = config.find_vouch_profile_for_role(role_arn) {
                println!(
                    "Already configured: profile [{}] uses role {role_arn}",
                    existing.name
                );
                println!();
                println!("Use it with:");
                println!("  aws --profile {} sts get-caller-identity", existing.name);
                return Ok(());
            }
            config.next_vouch_profile_name()
        }
    };

    // Write the profile
    config.set_profile(&AwsProfile {
        name: profile_name.clone(),
        credential_process: Some(format!(
            "{} credential aws --role {role_arn}",
            vouch_path.display()
        )),
        region: region.map(str::to_string),
        output: Some("json".to_string()),
        ..Default::default()
    });
    config.save()?;

    println!("Added profile [{profile_name}] to ~/.aws/config");
    println!();
    println!("Use AWS CLI with the profile:");
    println!();
    println!("  aws --profile {profile_name} sts get-caller-identity");
    println!();
    println!("Or set the environment variable:");
    println!();
    println!("  export AWS_PROFILE={profile_name}");
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
