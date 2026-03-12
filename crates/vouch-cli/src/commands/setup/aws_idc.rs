// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center setup command.
//!
//! Configures AWS CLI/SDK profiles to use Vouch for Identity Center credential
//! federation. Account and role discovery is performed server-side — the SSO
//! access token never leaves the server.
//!
//! Two modes:
//! - **Discovery** (`vouch setup aws-idc`): Enumerate all available
//!   accounts/roles and create profiles for each.
//! - **Manual** (`vouch setup aws-idc --account-id X --role-name Y`):
//!   Create a single profile.

use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::client::VouchClient;
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
    // Fetch IdC region from the server (accounts endpoint gives us the region)
    let client = VouchClient::new(server).await?;
    let accounts_resp: vouch_common::IdcAccountsResponse = client
        .get_authenticated("/v1/credentials/aws-idc")
        .await
        .context(
            "failed to get IdC accounts from Vouch server.\n\
             Ensure AWS Identity Center is configured by your org admin.",
        )?;
    let effective_region = region.unwrap_or(&accounts_resp.region);

    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));

    let config_path = AwsConfig::default_path()?;
    let aws_dir = aws_config_dir()?;
    ensure_secure_dir(&aws_dir)?;

    let mut config =
        AwsConfig::load_from(config_path.clone()).unwrap_or_else(|_| AwsConfig::empty(config_path));

    validate_account_id(account_id)?;
    validate_role_name(role_name)?;

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
    println!("Discovering accounts and roles from Identity Center...");
    println!();

    let client = VouchClient::new(server).await?;

    // Fetch accounts (server-side: token exchange + SSO ListAccounts)
    let accounts_resp: vouch_common::IdcAccountsResponse = client
        .get_authenticated("/v1/credentials/aws-idc")
        .await
        .context(
            "failed to list IdC accounts from Vouch server.\n\
             Ensure AWS Identity Center is configured by your org admin.",
        )?;
    let effective_region = region_override.unwrap_or(&accounts_resp.region);

    if accounts_resp.accounts.is_empty() {
        println!("No accounts available from Identity Center.");
        println!("Check your Identity Center permission set assignments.");
        return Ok(());
    }

    // Fetch roles for each account (server-side: token exchange + SSO ListAccountRoles)
    let mut pairs: Vec<(String, String, String)> = Vec::new();
    for account in &accounts_resp.accounts {
        let url = format!(
            "/v1/credentials/aws-idc/{}/roles",
            urlencoding::encode(&account.account_id),
        );
        let roles_resp: vouch_common::IdcRolesResponse = client
            .get_authenticated(&url)
            .await
            .context("failed to list roles for account")?;

        for role in roles_resp.roles {
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

    // Pre-compute profile names and detect collisions
    let mut profile_name_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for (account_name, account_id, role_name) in &pairs {
        let name = sanitize_profile_name(account_name, role_name, account_id);
        *profile_name_counts.entry(name).or_insert(0) += 1;
    }

    // Create profiles
    for (account_name, account_id, role_name) in &pairs {
        // Validate server-provided values before writing to ~/.aws/config
        if let Err(e) = validate_account_id(account_id) {
            tracing::warn!("Skipping invalid account from server: {e}");
            continue;
        }
        if let Err(e) = validate_role_name(role_name) {
            tracing::warn!("Skipping invalid role from server: {e}");
            continue;
        }
        let mut profile_name = sanitize_profile_name(account_name, role_name, account_id);

        // Disambiguate collisions by appending last 4 digits of account_id
        if profile_name_counts.get(&profile_name).copied().unwrap_or(0) > 1 {
            let suffix = account_id.get(8..).unwrap_or(account_id);
            profile_name = format!("{profile_name}-{suffix}");
        }

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

/// Find an existing IdC profile that targets the given account/role.
fn find_idc_profile(config: &AwsConfig, account_id: &str, role_name: &str) -> Option<String> {
    for profile in config.find_all_vouch_profiles() {
        if let Some(ref cp) = profile.credential_process
            && cp.contains("credential aws-idc")
            && extract_flag(cp, "--account-id").as_deref() == Some(account_id)
            && extract_flag(cp, "--role-name").as_deref() == Some(role_name)
        {
            return Some(profile.name.clone());
        }
    }
    None
}

/// Validate that `account_id` is exactly 12 ASCII digits.
fn validate_account_id(account_id: &str) -> Result<()> {
    anyhow::ensure!(
        account_id.len() == 12 && account_id.chars().all(|c| c.is_ascii_digit()),
        "Account ID must be exactly 12 digits, got: {account_id}"
    );
    Ok(())
}

/// Validate that `role_name` matches IAM role name constraints:
/// `[a-zA-Z0-9+=,.@_-]{1,64}`.
fn validate_role_name(role_name: &str) -> Result<()> {
    anyhow::ensure!(
        !role_name.is_empty()
            && role_name.len() <= 64
            && role_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c)),
        "Role name must be 1-64 characters matching [a-zA-Z0-9+=,.@_-], got: {role_name}"
    );
    Ok(())
}

/// Generate a sanitized profile name from account name and role name.
///
/// Pattern: `vouch-idc-{account_name}-{role_name}`
/// Falls back to account ID if account name is empty.
fn sanitize_profile_name(account_name: &str, role_name: &str, account_id: &str) -> String {
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

/// Truncate a string to a maximum display width, adding "..." if truncated.
///
/// Uses char count rather than byte length to handle non-ASCII safely.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let end = max.saturating_sub(3);
        let truncated: String = s.chars().take(end).collect();
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

    #[test]
    fn test_find_idc_profile_exact_match_not_prefix() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let content = r#"
[profile vouch-idc-prod-admin]
credential_process = vouch credential aws-idc --account-id 123456789012 --role-name Admin
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        // Exact match
        assert!(find_idc_profile(&config, "123456789012", "Admin").is_some());
        // Prefix should NOT match
        assert!(find_idc_profile(&config, "123", "Admin").is_none());
        // Different role should NOT match
        assert!(find_idc_profile(&config, "123456789012", "ReadOnly").is_none());
    }
}
