// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center setup command.
//!
//! Configures AWS CLI/SDK profiles to use Vouch for Identity Center credential
//! federation. The IdC configuration (bootstrap role, application ARN, region)
//! is fetched from the Vouch server.

use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::integrations::aws::{AwsConfig, AwsProfile};
use crate::utils::ensure_secure_dir;

/// Get the AWS config directory (~/.aws).
fn aws_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".aws"))
}

/// Run the AWS Identity Center setup command.
///
/// Fetches the IdC config from the Vouch server (to validate it's configured),
/// then writes an AWS CLI profile to `~/.aws/config`.
pub async fn run(
    server: &str,
    profile: Option<&str>,
    account_id: &str,
    role_name: &str,
    region: Option<&str>,
) -> Result<()> {
    // Fetch and validate IdC config from server
    let idc_region = fetch_idc_region(server).await?;
    let effective_region = region.unwrap_or(&idc_region);

    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));

    let config_path = AwsConfig::default_path()?;
    let aws_dir = aws_config_dir()?;

    // Ensure .aws directory exists with secure permissions
    ensure_secure_dir(&aws_dir)?;

    // Load existing config or create empty
    let mut config =
        AwsConfig::load_from(config_path.clone()).unwrap_or_else(|_| AwsConfig::empty(config_path));

    let credential_process = format!(
        "{} credential aws-idc --account-id {account_id} --role-name {role_name}",
        vouch_path.display()
    );

    let profile_name = match profile {
        Some(p) => {
            if config.profile_exists(p) {
                println!("Profile [{p}] already exists in ~/.aws/config.");
                println!("To update it, edit ~/.aws/config directly.");
                return Ok(());
            }
            p.to_string()
        }
        None => {
            // Check if an IdC profile already targets this account/role
            if let Some(existing) = find_idc_profile(&config, account_id, role_name) {
                println!(
                    "Already configured: profile [{existing}] targets \
                     account {account_id} / role {role_name}"
                );
                println!();
                println!("Use it with:");
                println!("  aws --profile {existing} sts get-caller-identity");
                return Ok(());
            }
            next_idc_profile_name(&config)
        }
    };

    config.set_profile(&AwsProfile {
        name: profile_name.clone(),
        credential_process: Some(credential_process),
        region: Some(effective_region.to_string()),
        output: Some("json".to_string()),
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
    println!("  2. Your Identity Center user must have the '{role_name}' permission set");
    println!("     assigned for account {account_id}");

    Ok(())
}

/// Fetch the IdC region from the Vouch server config.
async fn fetch_idc_region(server: &str) -> Result<String> {
    let client = crate::client::VouchClient::new(server).await?;
    let resp: vouch_common::IntegrationConfigResponse<vouch_common::AwsIntegrationConfig> = client
        .get_authenticated("/v1/integrations/aws")
        .await
        .context("failed to fetch AWS integration config from server")?;

    let config = resp
        .config
        .filter(|c| c.idc_configured())
        .context(
            "AWS Identity Center is not configured on the Vouch server.\n\
             Ask your org admin to configure it at the Vouch admin portal.",
        )?;

    config.idc_region.context("missing idc_region in server config")
}

/// Find an existing IdC profile that targets the given account/role.
fn find_idc_profile(config: &AwsConfig, account_id: &str, role_name: &str) -> Option<String> {
    let needle_account = format!("--account-id {account_id}");
    let needle_role = format!("--role-name {role_name}");

    for profile in config.find_all_vouch_profiles() {
        if let Some(ref cp) = profile.credential_process
            && cp.contains("credential aws-idc")
            && cp.contains(&needle_account)
            && cp.contains(&needle_role)
        {
            return Some(profile.name.clone());
        }
    }
    None
}

/// Generate the next available IdC profile name.
fn next_idc_profile_name(config: &AwsConfig) -> String {
    let base = "vouch-idc";
    if !config.profile_exists(base) {
        return base.to_string();
    }
    let mut n = 2u32;
    loop {
        let name = format!("{base}-{n}");
        if !config.profile_exists(&name) {
            return name;
        }
        n = n.saturating_add(1);
    }
}
