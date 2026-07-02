// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS setup command.
//!
//! Configures AWS CLI/SDK to use Vouch for credential federation.

use anyhow::{Context, Result};
use vouch_cli::{tr, tr_println};

use crate::install_path::resolve_install_path;
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

/// Run the AWS setup command. Writes AWS profiles to `~/.aws/config` whose
/// `credential_process` invokes `vouch credential aws`.
///
/// - `--discover` → discover accounts/roles via SSO and write a profile each.
///   Uses the IAM Identity Center portal (writing `--account/--role` process
///   lines) when the session has Identity Center configured, otherwise STS
///   role-chaining (writing `--role <arn>` lines).
/// - `--role <arn>` → write a single STS profile for that role ARN.
/// - neither → interactive single-account Identity Center setup (pick account +
///   permission-set), when the session has Identity Center configured.
pub(crate) async fn run(
    server: &str,
    profile: Option<&str>,
    role_arn: Option<&str>,
    region: Option<&str>,
    discover: bool,
) -> Result<()> {
    if discover {
        return run_discover(server, profile, region).await;
    }
    match role_arn {
        Some(role_arn) => run_explicit_role(profile, role_arn, region),
        None => run_interactive_identity_center(server, profile, region).await,
    }
}

/// Write a single STS profile for an explicit role ARN (patterns 1 & 2).
fn run_explicit_role(profile: Option<&str>, role_arn: &str, region: Option<&str>) -> Result<()> {
    let vouch_path = resolve_install_path();

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
                tr_println!("setup-aws-profile-already-exists", profile = p);
                return Ok(());
            }
            p.to_string()
        }
        None => {
            // Auto-naming: check if a vouch profile already targets this role
            if let Some(existing) = config.find_vouch_profile_for_role(role_arn) {
                tr_println!(
                    "setup-aws-already-configured-block",
                    profile = existing.name.as_str(),
                    role_arn = role_arn,
                );
                return Ok(());
            }
            config.next_vouch_profile_name()
        }
    };

    // Write the profile
    config.set_profile(&AwsProfile {
        name: profile_name.clone(),
        credential_process: Some(format!(
            "\"{}\" credential aws --role {role_arn}",
            vouch_path.display()
        )),
        region: region.map(str::to_string),
        output: Some("json".to_string()),
    });
    config.save()?;

    tr_println!(
        "setup-aws-added-profile-block",
        profile = profile_name.as_str(),
    );

    Ok(())
}

/// Discover AWS accounts/roles via SSO and create profiles automatically.
///
/// Uses the IAM Identity Center portal (permission-set profiles) when the
/// session has Identity Center configured, otherwise STS role-chaining.
async fn run_discover(
    server: &str,
    profile_prefix: Option<&str>,
    region: Option<&str>,
) -> Result<()> {
    use crate::integrations::aws::config::AwsConfig as AwsCliConfig;
    use crate::integrations::aws::sso::{SsoConfig, load_cached_token};
    use crate::integrations::aws::sso_portal::{list_account_roles, list_accounts};
    use vouch_common::aws::Partition;

    let vouch_config = crate::config::Config::load()?;
    let aws_cli_config = AwsCliConfig::load()?;

    // Mirror `vouch credential aws`: honor a single session silently, but emit a
    // stderr hint naming the auto-selected session when several are configured.
    let session = crate::commands::aws::resolve_sso_session(&aws_cli_config, None)?;
    let session_cfg = vouch_config
        .aws()
        .and_then(|a| a.sso_sessions.get(&session.name))
        .cloned()
        .unwrap_or_default();

    // Identity Center configured → portal discovery (permission-set profiles).
    if session_cfg.identity_center_application_arn.is_some() {
        return discover_identity_center(server, &session, profile_prefix, region).await;
    }

    let sso_region = session.region.clone();
    let sso_config = SsoConfig::from_session(&session);

    let token = load_cached_token(&sso_config).ok_or_else(|| {
        crate::exit_code::CliError::NotAuthenticated {
            reason: tr!("setup-aws-err-sso-expired"),
        }
    })?;
    let bearer = token.token();

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    let accounts = list_accounts(&http_client, &sso_region, &bearer)
        .await
        .context("failed to list SSO accounts")?;

    let vouch_path = resolve_install_path();

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

        let has_vouch_role = roles
            .iter()
            .any(|r| r.role_name == session_cfg.member_role_name);
        if !has_vouch_role {
            continue;
        }

        let partition = Partition::from_region(&sso_region);
        let role_arn = session_cfg.role_arn_in(partition.as_str(), &account.account_id);

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
            tr_println!(
                "setup-aws-discover-skipped",
                profile = profile_name.as_str()
            );
            skipped_count = skipped_count.saturating_add(1);
            continue;
        }

        config.set_profile(&AwsProfile {
            name: profile_name.clone(),
            credential_process: Some(format!(
                "\"{}\" credential aws --role {role_arn}",
                vouch_path.display()
            )),
            region: region.map(str::to_string),
            output: Some("json".to_string()),
        });

        tr_println!(
            "setup-aws-discover-added",
            profile = profile_name.as_str(),
            role_arn = role_arn.as_str()
        );
        created_count = created_count.saturating_add(1);
    }

    if created_count > 0 {
        config.save()?;
    }

    println!();
    tr_println!(
        "setup-aws-discover-summary",
        created = created_count,
        skipped = skipped_count
    );
    Ok(())
}

/// An account choice shown in the interactive picker.
struct AccountChoice {
    id: String,
    name: String,
}

impl std::fmt::Display for AccountChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.id)
    }
}

/// Build the `credential_process` line for an Identity Center permission-set
/// profile: `vouch credential aws --sso-session <name> --account <id> --role <ps>`.
///
/// The binary path, session name, and permission-set name are double-quoted so
/// values containing spaces are passed as single argv tokens (AWS parses
/// `credential_process` with shell-like tokenization that respects quotes).
fn idc_credential_process(
    vouch_path: &std::path::Path,
    session_name: &str,
    account_id: &str,
    role_name: &str,
) -> String {
    format!(
        "\"{}\" credential aws --sso-session \"{session_name}\" --account {account_id} --role \"{role_name}\"",
        vouch_path.display()
    )
}

/// Discover accounts/permission-sets via the Identity Center portal and write a
/// profile per account+role (`vouch setup aws --discover` with IdC configured).
async fn discover_identity_center(
    server: &str,
    session: &crate::integrations::aws::config::SsoSession,
    profile_prefix: Option<&str>,
    region: Option<&str>,
) -> Result<()> {
    use crate::integrations::aws::sso_portal::{list_account_roles, list_accounts};

    let sso_region = session.region.clone();
    let bearer =
        crate::commands::credential::aws::resolve_bearer_token(server, session, &sso_region)
            .await?;

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    let accounts = list_accounts(&http_client, &sso_region, &bearer)
        .await
        .context("failed to list SSO accounts")?;

    let vouch_path = resolve_install_path();
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

        let safe_account = sanitize_profile_name(&account.account_name);
        let account_part = if safe_account.is_empty() {
            account.account_id.clone()
        } else {
            safe_account
        };

        for role in &roles {
            let role_part = sanitize_profile_name(&role.role_name);
            let base = format!("{account_part}-{role_part}");
            let profile_name = match profile_prefix {
                Some(prefix) => format!("{prefix}-{base}"),
                None => format!("vouch-sso-{base}"),
            };

            if config.profile_exists(&profile_name) {
                tr_println!(
                    "setup-aws-discover-skipped",
                    profile = profile_name.as_str()
                );
                skipped_count = skipped_count.saturating_add(1);
                continue;
            }

            config.set_profile(&AwsProfile {
                name: profile_name.clone(),
                credential_process: Some(idc_credential_process(
                    &vouch_path,
                    &session.name,
                    &account.account_id,
                    &role.role_name,
                )),
                region: region
                    .map(str::to_string)
                    .or_else(|| Some(sso_region.clone())),
                output: Some("json".to_string()),
            });

            tr_println!(
                "setup-aws-discover-added",
                profile = profile_name.as_str(),
                role_arn = role.role_name.as_str()
            );
            created_count = created_count.saturating_add(1);
        }
    }

    if created_count > 0 {
        config.save()?;
    }

    println!();
    tr_println!(
        "setup-aws-discover-summary",
        created = created_count,
        skipped = skipped_count
    );
    Ok(())
}

/// Interactive single-account Identity Center setup: pick an account and
/// permission-set role, then write one profile (`vouch setup aws` with no
/// `--role`/`--discover`). Requires the session to have Identity Center
/// configured.
async fn run_interactive_identity_center(
    server: &str,
    profile: Option<&str>,
    region: Option<&str>,
) -> Result<()> {
    use crate::integrations::aws::sso_portal::{list_account_roles, list_accounts};

    let aws_cli_config = AwsConfig::load()?;
    // Mirror `vouch credential aws`: honor a single session silently, but emit a
    // stderr hint naming the auto-selected session when several are configured.
    let session = crate::commands::aws::resolve_sso_session(&aws_cli_config, None)?;

    // Interactive setup only applies to the Identity Center route; without it,
    // an explicit `--role <arn>` (or `--discover`) is required.
    let vouch_config = crate::config::Config::load()?;
    let has_idc = vouch_config
        .aws()
        .and_then(|a| a.sso_sessions.get(&session.name))
        .is_some_and(|c| c.identity_center_application_arn.is_some());
    if !has_idc {
        return Err(
            crate::exit_code::CliError::ConfigError(tr!("setup-aws-err-role-required")).into(),
        );
    }

    require_terminal()?;

    let sso_region = session.region.clone();
    let bearer =
        crate::commands::credential::aws::resolve_bearer_token(server, &session, &sso_region)
            .await?;
    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    // Pick account.
    let accounts = list_accounts(&http_client, &sso_region, &bearer)
        .await
        .context("failed to list SSO accounts")?;
    if accounts.is_empty() {
        anyhow::bail!("no AWS accounts are assigned to you via Identity Center");
    }
    let account_choices: Vec<AccountChoice> = accounts
        .into_iter()
        .map(|a| AccountChoice {
            id: a.account_id,
            name: a.account_name,
        })
        .collect();
    let account = prompt_select("Select an AWS account", account_choices)?;

    // Pick permission-set role.
    let roles = list_account_roles(&http_client, &sso_region, &bearer, &account.id)
        .await
        .with_context(|| format!("failed to list roles for account {}", account.id))?;
    if roles.is_empty() {
        anyhow::bail!("no roles are assigned to you in account {}", account.id);
    }
    let role_names: Vec<String> = roles.into_iter().map(|r| r.role_name).collect();
    let role_name = prompt_select("Select a role", role_names)?;

    // Write the profile.
    let profile_name = match profile {
        Some(p) => p.to_string(),
        None => {
            let safe_account = sanitize_profile_name(&account.name);
            let account_part = if safe_account.is_empty() {
                account.id.clone()
            } else {
                safe_account
            };
            format!(
                "vouch-sso-{account_part}-{}",
                sanitize_profile_name(&role_name)
            )
        }
    };

    let config_path = AwsConfig::default_path()?;
    let aws_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".aws");
    ensure_secure_dir(&aws_dir)?;
    let mut config =
        AwsConfig::load_from(config_path.clone()).unwrap_or_else(|_| AwsConfig::empty(config_path));

    if config.profile_exists(&profile_name) {
        tr_println!(
            "setup-aws-profile-already-exists",
            profile = profile_name.as_str()
        );
        return Ok(());
    }

    let vouch_path = resolve_install_path();
    config.set_profile(&AwsProfile {
        name: profile_name.clone(),
        credential_process: Some(idc_credential_process(
            &vouch_path,
            &session.name,
            &account.id,
            &role_name,
        )),
        region: region.map(str::to_string).or(Some(sso_region)),
        output: Some("json".to_string()),
    });
    config.save()?;

    tr_println!(
        "setup-aws-added-profile-block",
        profile = profile_name.as_str(),
    );
    Ok(())
}

/// Error out when stdin is not a terminal (interactive selection impossible).
fn require_terminal() -> Result<()> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return Ok(());
    }
    Err(crate::exit_code::CliError::ConfigError(
        "run interactively, or pass --role <arn> / --discover".to_string(),
    )
    .into())
}

/// Show an interactive single-select prompt, mapping cancellation to a clean error.
fn prompt_select<T: std::fmt::Display>(prompt: &str, options: Vec<T>) -> Result<T> {
    inquire::Select::new(prompt, options)
        .prompt()
        .map_err(|e| match e {
            inquire::InquireError::OperationCanceled
            | inquire::InquireError::OperationInterrupted => {
                crate::exit_code::CliError::ConfigError("selection cancelled".to_string()).into()
            }
            other => anyhow::anyhow!("selection failed: {other}"),
        })
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
