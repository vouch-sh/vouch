// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS setup command.
//!
//! Configures AWS CLI/SDK to use Vouch for credential federation.

use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::integrations::aws::{AwsConfig, AwsProfile};
use crate::utils::ensure_secure_dir;

/// Sanitize an account name into a valid AWS CLI profile name segment.
///
/// Converts to lowercase, replaces non-alphanumeric-non-hyphen chars with `-`,
/// and deduplicates consecutive hyphens.
fn sanitize_profile_name(name: &str) -> String {
    let lower = name.to_lowercase();
    let replaced: String = lower
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();

    // Collapse consecutive hyphens
    let mut result = String::with_capacity(replaced.len());
    let mut prev_hyphen = false;
    for c in replaced.chars() {
        if c == '-' {
            if !prev_hyphen {
                result.push(c);
            }
            prev_hyphen = true;
        } else {
            result.push(c);
            prev_hyphen = false;
        }
    }
    result.trim_matches('-').to_string()
}

/// Run the AWS setup command with an explicit role ARN.
///
/// Automatically adds a vouch profile to ~/.aws/config with smart naming:
/// - If `--profile` is given, uses that name (exits early if it already exists).
/// - Otherwise, checks existing vouch profiles for a role match (exits early if found),
///   then picks the next available name: "vouch", "vouch-2", "vouch-3", etc.
pub(crate) async fn run(
    profile: Option<&str>,
    role_arn: Option<&str>,
    region: Option<&str>,
    discover: bool,
) -> Result<()> {
    if discover {
        return run_discover(profile, region).await;
    }

    let role_arn = role_arn.ok_or_else(|| {
        crate::exit_code::CliError::ConfigError(
            "Either --role or --discover is required".to_string(),
        )
    })?;

    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));

    let config_path = AwsConfig::default_path()?;
    let aws_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".aws");

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

/// Discover AWS accounts/roles via SSO and create profiles automatically.
async fn run_discover(profile_prefix: Option<&str>, region: Option<&str>) -> Result<()> {
    use crate::integrations::aws::config::AwsConfig as AwsCliConfig;
    use crate::integrations::aws::sso::{SsoConfig, load_cached_token};
    use crate::integrations::aws::sso_portal::{list_account_roles, list_accounts};
    use vouch_common::aws::Partition;

    let vouch_config = crate::config::Config::load()?;
    let aws_cli_config = AwsCliConfig::load()?;

    let session = aws_cli_config.find_sso_session(None).ok_or_else(|| {
        crate::exit_code::CliError::ConfigError(
            "No SSO session found in ~/.aws/config. Run 'aws configure sso' first.".to_string(),
        )
    })?;
    let member_role_name = vouch_config
        .aws()
        .and_then(|a| a.sso_sessions.get(&session.name))
        .map_or_else(|| "VouchAccess".to_string(), |s| s.member_role_name.clone());

    let sso_region = session.region.clone();
    let sso_config = SsoConfig::from_session(&session);

    let token = load_cached_token(&sso_config).ok_or_else(|| {
        crate::exit_code::CliError::NotAuthenticated {
            reason: "SSO session expired or missing. Run 'vouch aws login' first.".to_string(),
        }
    })?;
    let bearer = token.token();

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    let accounts = list_accounts(&http_client, &sso_region, &bearer)
        .await
        .context("failed to list SSO accounts")?;

    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));

    let config_path = AwsConfig::default_path()?;
    let aws_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".aws");
    ensure_secure_dir(&aws_dir)?;

    let mut config =
        AwsConfig::load_from(config_path.clone()).unwrap_or_else(|_| AwsConfig::empty(config_path));

    let mut created_count: u32 = 0;
    let mut skipped_count: u32 = 0;

    for account in &accounts {
        let roles = list_account_roles(&http_client, &sso_region, &bearer, &account.account_id)
            .await
            .with_context(|| format!("failed to list roles for account {}", account.account_id))?;

        let has_vouch_role = roles.iter().any(|r| r.role_name == member_role_name);
        if !has_vouch_role {
            continue;
        }

        let partition = Partition::from_region(&sso_region);
        let role_arn = format!(
            "arn:{}:iam::{}:role/{}",
            partition.as_str(),
            account.account_id,
            member_role_name
        );

        let safe_name = sanitize_profile_name(&account.account_name);
        let name_part = if safe_name.is_empty() {
            account.account_id.clone()
        } else {
            safe_name
        };
        let profile_name = match profile_prefix {
            Some(prefix) => format!("{prefix}-{name_part}"),
            None => format!("vouch-{name_part}"),
        };

        if config.profile_exists(&profile_name) {
            println!("Skipped [{profile_name}] — already exists");
            skipped_count += 1;
            continue;
        }

        config.set_profile(&AwsProfile {
            name: profile_name.clone(),
            credential_process: Some(format!(
                "{} credential aws --role {role_arn}",
                vouch_path.display()
            )),
            region: region.map(str::to_string),
            output: Some("json".to_string()),
        });

        println!("Added profile [{profile_name}] → {role_arn}");
        created_count += 1;
    }

    if created_count > 0 {
        config.save()?;
    }

    println!();
    println!("{created_count} profile(s) created, {skipped_count} skipped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_profile_name_basic() {
        assert_eq!(sanitize_profile_name("Production"), "production");
    }

    #[test]
    fn test_sanitize_profile_name_spaces() {
        assert_eq!(sanitize_profile_name("My Account"), "my-account");
    }

    #[test]
    fn test_sanitize_profile_name_special_chars() {
        assert_eq!(sanitize_profile_name("Prod (US-East)"), "prod-us-east");
        assert_eq!(sanitize_profile_name("Dev/Staging"), "dev-staging");
    }

    #[test]
    fn test_sanitize_profile_name_dedup_hyphens() {
        assert_eq!(sanitize_profile_name("prod--staging"), "prod-staging");
        assert_eq!(sanitize_profile_name("a   b"), "a-b");
    }

    #[test]
    fn test_sanitize_profile_name_leading_trailing_hyphen() {
        assert_eq!(sanitize_profile_name("-my-account-"), "my-account");
    }

    #[test]
    fn test_sanitize_profile_name_empty() {
        assert_eq!(sanitize_profile_name(""), "");
    }

    #[test]
    fn test_sanitize_profile_name_all_special_chars() {
        assert_eq!(sanitize_profile_name("!!!@@@###"), "");
    }
}
