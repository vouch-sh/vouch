// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center setup command.
//!
//! Configures AWS CLI/SDK profiles to use Vouch for Identity Center credential
//! federation. The IdC configuration (bootstrap role, application ARN, region)
//! is fetched from the Vouch server.
//!
//! Two modes:
//! - **Discovery** (`vouch setup aws-idc`): Enumerate all available
//!   accounts/roles and create profiles for each.
//! - **Manual** (`vouch setup aws-idc --account-id X --role-name Y`):
//!   Create a single profile.

use anyhow::{Context, Result};
use secrecy::SecretString;
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
/// When `account_id` and `role_name` are provided, creates a single profile.
/// When omitted, discovers all available accounts/roles and creates profiles.
pub async fn run(
    server: &str,
    profile: Option<&str>,
    account_id: Option<&str>,
    role_name: Option<&str>,
    region: Option<&str>,
) -> Result<()> {
    match (account_id, role_name) {
        (Some(aid), Some(rn)) => run_single(server, profile, aid, rn, region).await,
        _ => run_discovery(server, region).await,
    }
}

/// Create a single profile for a specific account/role.
async fn run_single(
    server: &str,
    profile: Option<&str>,
    account_id: &str,
    role_name: &str,
    region: Option<&str>,
) -> Result<()> {
    let idc_token = fetch_idc_token(server).await?;
    let effective_region = region.unwrap_or(&idc_token.region);

    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));

    let config_path = AwsConfig::default_path()?;
    let aws_dir = aws_config_dir()?;
    ensure_secure_dir(&aws_dir)?;

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
            sanitize_profile_name("", role_name, account_id)
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

    Ok(())
}

/// Discover all available accounts/roles and create profiles.
async fn run_discovery(server: &str, region_override: Option<&str>) -> Result<()> {
    use crate::integrations::aws::sso;

    println!("Discovering accounts and roles from Identity Center...");
    println!();

    let idc_token = fetch_idc_token(server).await?;
    let effective_region = region_override.unwrap_or(&idc_token.region);

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    let access_token = SecretString::from(idc_token.access_token);

    // Enumerate accounts
    let accounts = sso::list_accounts(
        &http_client,
        &access_token,
        &idc_token.region,
        &idc_token.domain_suffix,
    )
    .await
    .context("failed to list accounts from Identity Center")?;

    if accounts.is_empty() {
        println!("No accounts available from Identity Center.");
        println!("Check your Identity Center permission set assignments.");
        return Ok(());
    }

    // Enumerate roles for each account
    let mut pairs: Vec<(String, String, String)> = Vec::new();
    for account in &accounts {
        let roles = sso::list_account_roles(
            &http_client,
            &access_token,
            &account.account_id,
            &idc_token.region,
            &idc_token.domain_suffix,
        )
        .await
        .context("failed to list roles for account")?;

        for role in roles {
            pairs.push((
                account.account_name.clone(),
                account.account_id.clone(),
                role.role_name,
            ));
        }
    }

    if pairs.is_empty() {
        println!("No roles available from Identity Center.");
        return Ok(());
    }

    // Load AWS config
    let config_path = AwsConfig::default_path()?;
    let aws_dir = aws_config_dir()?;
    ensure_secure_dir(&aws_dir)?;
    let mut config =
        AwsConfig::load_from(config_path.clone()).unwrap_or_else(|_| AwsConfig::empty(config_path));

    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));

    let mut added = 0u32;
    let mut existed = 0u32;

    // Print header
    println!(
        "  {:<20} {:<24} {:<36} Status",
        "Account", "Role", "Profile"
    );

    // Create profiles
    for (account_name, account_id, role_name) in &pairs {
        let profile_name = sanitize_profile_name(account_name, role_name, account_id);

        let account_display = if account_name.is_empty() {
            account_id.clone()
        } else {
            let id_short = account_id.get(..6).unwrap_or(account_id);
            format!("{account_name} ({id_short}...)")
        };

        // Check if already configured
        if find_idc_profile(&config, account_id, role_name).is_some() {
            println!(
                "  {:<20} {:<24} {:<36} Exists",
                truncate(&account_display, 20),
                truncate(role_name, 24),
                truncate(&profile_name, 36),
            );
            existed = existed.saturating_add(1);
            continue;
        }

        let credential_process = format!(
            "{} credential aws-idc --account-id {account_id} --role-name {role_name}",
            vouch_path.display()
        );

        config.set_profile(&AwsProfile {
            name: profile_name.clone(),
            credential_process: Some(credential_process),
            region: Some(effective_region.to_string()),
            output: Some("json".to_string()),
        });

        println!(
            "  {:<20} {:<24} {:<36} Added",
            truncate(&account_display, 20),
            truncate(role_name, 24),
            truncate(&profile_name, 36),
        );
        added = added.saturating_add(1);
    }

    // Detect stale profiles
    let stale = find_stale_profiles(&config, &pairs);
    for (profile_name, account_id, role_name) in &stale {
        println!();
        println!("  Warning: profile [{profile_name}] targets account {account_id}/{role_name}");
        println!("           which is no longer available from Identity Center");
    }

    if added > 0 {
        config.save()?;
    }

    println!();
    if added > 0 {
        println!(
            "Added {added} profile{} to ~/.aws/config ({existed} already existed)",
            if added == 1 { "" } else { "s" }
        );
    } else {
        println!("All {existed} profiles already exist in ~/.aws/config");
    }

    if let Some(first_profile) = pairs.first() {
        let name = sanitize_profile_name(&first_profile.0, &first_profile.2, &first_profile.1);
        println!();
        println!("Use: aws --profile {name} sts get-caller-identity");
    }

    Ok(())
}

/// Fetch an SSO access token from the Vouch server.
async fn fetch_idc_token(server: &str) -> Result<vouch_common::IdcTokenResponse> {
    let client = crate::client::VouchClient::new(server).await?;
    client
        .get_authenticated("/v1/credentials/aws-idc/token")
        .await
        .context(
            "failed to get IdC token from Vouch server.\n\
             Ensure AWS Identity Center is configured by your org admin.",
        )
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

/// Generate a sanitized profile name from account name and role name.
///
/// Pattern: `vouch-idc-{account_name}-{role_name}`
/// Falls back to account ID if account name is empty.
pub(crate) fn sanitize_profile_name(
    account_name: &str,
    role_name: &str,
    account_id: &str,
) -> String {
    let account_part = if account_name.is_empty() {
        account_id.to_string()
    } else {
        account_name.to_string()
    };

    let raw = format!("vouch-idc-{account_part}-{role_name}");

    let sanitized: String = raw
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();

    // Collapse consecutive dashes and trim
    let mut result = String::with_capacity(sanitized.len());
    let mut prev_dash = false;
    for c in sanitized.chars() {
        if c == '-' {
            if !prev_dash {
                result.push(c);
            }
            prev_dash = true;
        } else {
            result.push(c);
            prev_dash = false;
        }
    }

    let trimmed = result.trim_matches('-');
    if trimmed.is_empty() {
        "vouch-idc".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Find stale vouch-idc profiles that no longer match any discovered pair.
fn find_stale_profiles(
    config: &AwsConfig,
    discovered: &[(String, String, String)],
) -> Vec<(String, String, String)> {
    let mut stale = Vec::new();

    for profile in config.find_all_vouch_profiles() {
        let Some(ref cp) = profile.credential_process else {
            continue;
        };
        if !cp.contains("credential aws-idc") {
            continue;
        }

        // Extract account-id and role-name from credential_process
        let account_id = extract_flag(cp, "--account-id");
        let role_name = extract_flag(cp, "--role-name");

        if let (Some(aid), Some(rn)) = (account_id, role_name) {
            let found = discovered
                .iter()
                .any(|(_, disc_aid, disc_rn)| disc_aid == &aid && disc_rn == &rn);
            if !found {
                stale.push((profile.name.clone(), aid, rn));
            }
        }
    }

    stale
}

/// Extract a flag value from a credential_process command string.
fn extract_flag(command: &str, flag: &str) -> Option<String> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == flag {
            return parts.get(i.saturating_add(1)).map(|s| s.to_string());
        }
    }
    None
}

/// Truncate a string to a maximum length, adding "..." if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let end = max.saturating_sub(3);
        let truncated = s.get(..end).unwrap_or(s);
        format!("{truncated}...")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_profile_name_basic() {
        assert_eq!(
            sanitize_profile_name("Production", "AdministratorAccess", "123456789012"),
            "vouch-idc-production-administratoraccess"
        );
    }

    #[test]
    fn test_sanitize_profile_name_empty_account() {
        assert_eq!(
            sanitize_profile_name("", "ReadOnlyAccess", "123456789012"),
            "vouch-idc-123456789012-readonlyaccess"
        );
    }

    #[test]
    fn test_sanitize_profile_name_special_chars() {
        assert_eq!(
            sanitize_profile_name("My Account (Test)", "Admin Access", "123"),
            "vouch-idc-my-account-test-admin-access"
        );
    }

    #[test]
    fn test_sanitize_profile_name_consecutive_dashes() {
        assert_eq!(
            sanitize_profile_name("a--b", "c--d", "123"),
            "vouch-idc-a-b-c-d"
        );
    }

    #[test]
    fn test_extract_flag() {
        let cmd = "vouch credential aws-idc --account-id 123 --role-name Admin";
        assert_eq!(extract_flag(cmd, "--account-id"), Some("123".to_string()));
        assert_eq!(extract_flag(cmd, "--role-name"), Some("Admin".to_string()));
        assert_eq!(extract_flag(cmd, "--nonexistent"), None);
    }

    #[test]
    fn test_find_stale_profiles() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let content = r#"
[profile vouch-idc-prod-admin]
credential_process = vouch credential aws-idc --account-id 111 --role-name Admin

[profile vouch-idc-staging-readonly]
credential_process = vouch credential aws-idc --account-id 222 --role-name ReadOnly
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        // Only 111/Admin is still discovered
        let discovered = vec![("Prod".to_string(), "111".to_string(), "Admin".to_string())];

        let stale = find_stale_profiles(&config, &discovered);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].0, "vouch-idc-staging-readonly");
        assert_eq!(stale[0].1, "222");
        assert_eq!(stale[0].2, "ReadOnly");
    }
}
