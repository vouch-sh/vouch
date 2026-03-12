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
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::client::VouchClient;
use crate::config::hostname_from_url;
use crate::integrations::aws::{AwsConfig, AwsProfile};
use crate::utils::ensure_secure_dir;

/// Cache TTL for IdC discovery data (4 hours — matches session duration).
const DISCOVERY_CACHE_TTL_HOURS: i64 = 4;

/// Get the AWS config directory (~/.aws).
fn aws_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".aws"))
}

/// Run the AWS Identity Center setup command.
///
/// When `account_id` and `role_name` are provided, creates a single profile.
/// When omitted, discovers all available accounts/roles and creates profiles.
///
/// Discovery results are cached in `~/.vouch/cache/` for 4 hours.
/// Pass `refresh = true` to bypass the cache.
pub async fn run(
    server: &str,
    profile: Option<&str>,
    account_id: Option<&str>,
    role_name: Option<&str>,
    region: Option<&str>,
    refresh: bool,
) -> Result<()> {
    match (account_id, role_name) {
        (Some(aid), Some(rn)) => run_single(server, profile, aid, rn, region, refresh).await,
        _ => run_discovery(server, region, refresh).await,
    }
}

/// Create a single profile for a specific account/role.
async fn run_single(
    server: &str,
    profile: Option<&str>,
    account_id: &str,
    role_name: &str,
    region: Option<&str>,
    refresh: bool,
) -> Result<()> {
    let discovery = fetch_discovery(server, refresh).await?;
    let effective_region = region.unwrap_or(&discovery.region);

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

/// Discover all available accounts/roles and let the user select which to configure.
async fn run_discovery(server: &str, region_override: Option<&str>, refresh: bool) -> Result<()> {
    println!("Discovering accounts and roles from Identity Center...");
    println!();

    let discovery = fetch_discovery(server, refresh).await?;
    let effective_region = region_override.unwrap_or(&discovery.region);

    // Show warnings for partial failures
    for err in &discovery.errors {
        println!(
            "  Warning: failed to list roles for account {}: {}",
            err.account_id, err.message
        );
    }

    // Flatten accounts+roles into (account_name, account_id, role_name) triples
    let mut pairs: Vec<(String, String, String)> = Vec::new();
    for account in &discovery.accounts {
        for role in &account.roles {
            pairs.push((
                account.account_name.clone(),
                account.account_id.clone(),
                role.clone(),
            ));
        }
    }

    if pairs.is_empty() {
        println!("No accounts or roles available from Identity Center.");
        println!("Check your Identity Center permission set assignments.");
        return Ok(());
    }

    // Load AWS config to check for existing profiles
    let config_path = AwsConfig::default_path()?;
    let aws_dir = aws_config_dir()?;
    ensure_secure_dir(&aws_dir)?;
    let mut config =
        AwsConfig::load_from(config_path.clone()).unwrap_or_else(|_| AwsConfig::empty(config_path));

    // Build display labels and track which are already configured
    let mut options: Vec<String> = Vec::with_capacity(pairs.len());
    let mut already_configured: Vec<bool> = Vec::with_capacity(pairs.len());
    for (account_name, account_id, role_name) in &pairs {
        let exists = find_idc_profile(&config, account_id, role_name).is_some();
        already_configured.push(exists);

        let label = if account_name.is_empty() {
            format!("{account_id} / {role_name}")
        } else {
            format!("{account_name} ({account_id}) / {role_name}")
        };
        let label = if exists {
            format!("{label} (exists)")
        } else {
            label
        };
        options.push(label);
    }

    // Pre-select items that are NOT already configured
    let defaults: Vec<usize> = already_configured
        .iter()
        .enumerate()
        .filter(|(_, exists)| !*exists)
        .map(|(i, _)| i)
        .collect();

    // If everything is already configured, show summary and exit
    if defaults.is_empty() {
        println!(
            "All {} account/role pairs are already configured in ~/.aws/config",
            pairs.len()
        );
        return Ok(());
    }

    let selected =
        match inquire::MultiSelect::new("Select accounts and roles to configure:", options)
            .with_default(&defaults)
            .prompt()
        {
            Ok(sel) => sel,
            Err(
                inquire::InquireError::OperationCanceled
                | inquire::InquireError::OperationInterrupted,
            ) => {
                println!("Setup cancelled.");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

    if selected.is_empty() {
        println!("No profiles selected.");
        return Ok(());
    }

    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));

    // Pre-compute profile names and detect collisions
    let mut profile_name_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for (account_name, account_id, role_name) in &pairs {
        let name = sanitize_profile_name(account_name, role_name, account_id);
        *profile_name_counts.entry(name).or_insert(0) += 1;
    }

    let mut added = 0u32;
    let mut skipped = 0u32;

    for (account_name, account_id, role_name) in &pairs {
        // Build label to check if this pair was selected
        let exists = find_idc_profile(&config, account_id, role_name).is_some();
        let label = if account_name.is_empty() {
            format!("{account_id} / {role_name}")
        } else {
            format!("{account_name} ({account_id}) / {role_name}")
        };
        let label = if exists {
            format!("{label} (exists)")
        } else {
            label
        };

        if !selected.contains(&label) {
            skipped = skipped.saturating_add(1);
            continue;
        }

        // Skip already-configured pairs
        if exists {
            skipped = skipped.saturating_add(1);
            continue;
        }

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

        added = added.saturating_add(1);
    }

    // Detect stale profiles
    let stale = find_stale_profiles(&config, &pairs);
    for (profile_name, account_id, role_name) in &stale {
        println!(
            "  Warning: profile [{profile_name}] targets {account_id}/{role_name} \
             which is no longer available"
        );
    }

    if added > 0 {
        config.save()?;
    }

    println!();
    println!(
        "Added {added} profile{} to ~/.aws/config ({skipped} skipped)",
        if added == 1 { "" } else { "s" }
    );

    if let Some(first_profile) = pairs.first() {
        let name = sanitize_profile_name(&first_profile.0, &first_profile.2, &first_profile.1);
        println!();
        println!("Use: aws --profile {name} sts get-caller-identity");
    }

    Ok(())
}

// ============================================================================
// Discovery cache
// ============================================================================

/// On-disk representation of a cached IdC discovery response.
#[derive(Serialize, Deserialize)]
struct CachedDiscovery {
    cached_at: String,
    #[serde(flatten)]
    data: vouch_common::IdcDiscoveryResponse,
}

/// Path to the discovery cache file for a given server.
fn discovery_cache_path(server: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let host = hostname_from_url(server)?;
    // Sanitize hostname for use as a filename
    let safe_host: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Ok(home
        .join(".vouch")
        .join("cache")
        .join(format!("idc-discovery-{safe_host}.json")))
}

/// Load a cached discovery response if it exists and is not stale.
fn load_cached_discovery(server: &str) -> Option<vouch_common::IdcDiscoveryResponse> {
    let path = discovery_cache_path(server).ok()?;
    let content = std::fs::read_to_string(&path).ok()?;
    let cached: CachedDiscovery = serde_json::from_str(&content).ok()?;

    let cached_at: jiff::Timestamp = cached.cached_at.parse().ok()?;
    let expires_at = cached_at
        .checked_add(jiff::SignedDuration::from_hours(DISCOVERY_CACHE_TTL_HOURS))
        .ok()?;
    if jiff::Timestamp::now() > expires_at {
        return None;
    }

    Some(cached.data)
}

/// Save a discovery response to the cache (best-effort).
fn save_discovery_cache(server: &str, data: &vouch_common::IdcDiscoveryResponse) {
    let cached = CachedDiscovery {
        cached_at: jiff::Timestamp::now().to_string(),
        data: data.clone(),
    };
    let Ok(path) = discovery_cache_path(server) else {
        return;
    };
    let Ok(json) = serde_json::to_string_pretty(&cached) else {
        return;
    };
    // Best-effort: don't fail the command if caching fails
    if let Err(e) = crate::utils::atomic_write(&path, json.as_bytes()) {
        tracing::debug!("failed to write IdC discovery cache: {e}");
    }
}

/// Fetch IdC discovery data, using cache when available.
async fn fetch_discovery(
    server: &str,
    refresh: bool,
) -> Result<vouch_common::IdcDiscoveryResponse> {
    if !refresh && let Some(cached) = load_cached_discovery(server) {
        tracing::debug!("using cached IdC discovery data");
        return Ok(cached);
    }

    let client = VouchClient::new(server).await?;
    let discovery: vouch_common::IdcDiscoveryResponse = client
        .get_authenticated("/v1/credentials/aws-idc/discover")
        .await
        .context(
            "failed to discover IdC accounts from Vouch server.\n\
             Ensure AWS Identity Center is configured by your org admin.",
        )?;

    save_discovery_cache(server, &discovery);
    Ok(discovery)
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

    #[test]
    fn test_discovery_cache_path_sanitizes_hostname() {
        let path = discovery_cache_path("https://us.vouch.sh").unwrap();
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(filename, "idc-discovery-us.vouch.sh.json");
    }

    #[test]
    fn test_discovery_cache_path_with_port() {
        let path = discovery_cache_path("https://localhost:3000").unwrap();
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(filename, "idc-discovery-localhost_3000.json");
    }

    #[test]
    fn test_discovery_cache_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("test-cache.json");

        let discovery = vouch_common::IdcDiscoveryResponse {
            accounts: vec![vouch_common::IdcAccountWithRoles {
                account_id: "123456789012".to_string(),
                account_name: "Production".to_string(),
                roles: vec!["AdminAccess".to_string()],
            }],
            region: "us-east-1".to_string(),
            errors: vec![],
        };

        let cached = CachedDiscovery {
            cached_at: jiff::Timestamp::now().to_string(),
            data: discovery,
        };
        let json = serde_json::to_string_pretty(&cached).unwrap();
        std::fs::write(&cache_path, &json).unwrap();

        let content = std::fs::read_to_string(&cache_path).unwrap();
        let loaded: CachedDiscovery = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded.data.accounts.len(), 1);
        assert_eq!(loaded.data.accounts[0].account_id, "123456789012");
        assert_eq!(loaded.data.region, "us-east-1");
    }

    #[test]
    fn test_discovery_cache_expired() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("test-cache.json");

        let expired_at = jiff::Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_hours(
                DISCOVERY_CACHE_TTL_HOURS + 1,
            ))
            .unwrap();

        let cached = CachedDiscovery {
            cached_at: expired_at.to_string(),
            data: vouch_common::IdcDiscoveryResponse {
                accounts: vec![],
                region: "us-east-1".to_string(),
                errors: vec![],
            },
        };
        let json = serde_json::to_string_pretty(&cached).unwrap();
        std::fs::write(&cache_path, &json).unwrap();

        // Read and check expiry manually (load_cached_discovery needs a server URL)
        let content = std::fs::read_to_string(&cache_path).unwrap();
        let loaded: CachedDiscovery = serde_json::from_str(&content).unwrap();
        let cached_at: jiff::Timestamp = loaded.cached_at.parse().unwrap();
        let expires_at = cached_at
            .checked_add(jiff::SignedDuration::from_hours(DISCOVERY_CACHE_TTL_HOURS))
            .unwrap();
        assert!(
            jiff::Timestamp::now() > expires_at,
            "cache should be expired"
        );
    }
}
