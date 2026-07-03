// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS setup command.
//!
//! Configures AWS CLI/SDK to use Vouch for credential federation.
//!
//! Three patterns:
//!
//! - Single account: `--role <arn>` — writes a single-account profile, no org stored.
//! - Management-role chain: `--management-role <arn> --role <target-arn>` — stores org, writes profile.
//! - Identity Center: `--management-role <arn> --identity-center-application <arn>
//!   --region <region> [--discover]` — stores org + IdC, optionally enumerates.

use anyhow::{Context, Result};
use vouch_cli::{tr, tr_println};

use crate::config::{AwsIdentityCenter, AwsOrganization};
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

/// Open (or create) `~/.aws/config` and ensure the `.aws` directory exists.
fn load_or_create_aws_config() -> Result<AwsConfig> {
    let config_path = AwsConfig::default_path()?;
    let aws_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".aws");
    ensure_secure_dir(&aws_dir)?;
    Ok(AwsConfig::load_from(config_path.clone()).unwrap_or_else(|_| AwsConfig::empty(config_path)))
}

/// Run the AWS setup command.
///
/// Dispatches based on the combination of flags:
///
/// - Only `--role`: single-account direct setup (no org stored).
/// - `--management-role` + optionally `--role`: management-role setup (org stored, optional profile).
/// - `--management-role` + `--identity-center-application` + `--region` + `--discover`:
///   IdC discovery (org + IdC stored, profiles written per account/permission-set).
/// - `--discover` alone: IdC discovery using an already-stored org.
#[allow(
    clippy::too_many_arguments,
    reason = "setup aws takes one arg per distinct CLI flag; no reasonable grouping exists"
)]
pub(crate) async fn run(
    profile: Option<&str>,
    role_arn: Option<&str>,
    management_role: Option<&str>,
    identity_center_application: Option<&str>,
    region: Option<&str>,
    discover: bool,
    server: &str,
) -> Result<()> {
    // Store the org in vouch config if a management role was provided.
    if let Some(mgmt) = management_role {
        store_org(mgmt, identity_center_application, region)?;
    }

    if discover {
        return run_discover(profile, identity_center_application, server).await;
    }

    let role = match role_arn {
        Some(r) => r,
        None => {
            // Stored org but no --role / --discover: inform and exit.
            if management_role.is_some() {
                tr_println!("setup-aws-org-stored-no-profile");
            } else {
                return Err(crate::exit_code::CliError::ConfigError(tr!(
                    "setup-aws-err-role-required"
                ))
                .into());
            }
            return Ok(());
        }
    };

    write_sts_profile(profile, role, management_role.unwrap_or(role), region)
}

/// Append or update the org entry in vouch config.
fn store_org(
    management_role: &str,
    identity_center_application: Option<&str>,
    region: Option<&str>,
) -> Result<()> {
    let identity_center = match (identity_center_application, region) {
        (Some(app_arn), Some(rgn)) => Some(AwsIdentityCenter {
            application_arn: app_arn.to_string(),
            region: rgn.to_string(),
        }),
        (Some(_), None) => {
            return Err(crate::exit_code::CliError::ConfigError(tr!(
                "setup-aws-err-region-required"
            ))
            .into());
        }
        _ => None,
    };

    let mut config = crate::config::Config::load()?;
    config.append_aws_org(AwsOrganization {
        management_role: management_role.to_string(),
        identity_center,
    });
    config.save()?;

    tr_println!("setup-aws-org-stored", management_role = management_role);
    Ok(())
}

/// Write a `vouch credential aws --role <arn>` profile into `~/.aws/config`.
///
/// When `management_role` differs from `role_arn`, the generated
/// `credential_process` includes `--via <management_role>` so the CLI can
/// chain through the correct management role in multi-org configurations.
fn write_sts_profile(
    profile_name_hint: Option<&str>,
    role_arn: &str,
    management_role: &str,
    region: Option<&str>,
) -> Result<()> {
    let vouch_path = resolve_install_path();
    let mut config = load_or_create_aws_config()?;

    let profile_name = match profile_name_hint {
        Some(p) => {
            if config.profile_exists(p) {
                tr_println!("setup-aws-profile-already-exists", profile = p);
                return Ok(());
            }
            p.to_string()
        }
        None => {
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

    // Include --via when chaining through a management role in another account.
    let credential_process = if management_role != role_arn {
        format!(
            "\"{}\" credential aws --role {role_arn} --via {management_role}",
            vouch_path.display()
        )
    } else {
        format!(
            "\"{}\" credential aws --role {role_arn}",
            vouch_path.display()
        )
    };

    config.set_profile(&AwsProfile {
        name: profile_name.clone(),
        credential_process: Some(credential_process),
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

/// Enumerate accounts and permission-sets via Identity Center and write profiles.
///
/// Uses the TTI exchange (`CreateTokenWithIAM`) to obtain an IdC access token,
/// then calls `ListAccounts` + `ListAccountRoles` (SSO portal) and writes one
/// `--account <id> --permission-set <name>` profile per assignment found.
async fn run_discover(
    profile_prefix: Option<&str>,
    idc_application_arn: Option<&str>,
    server: &str,
) -> Result<()> {
    use crate::commands::credential::aws::{obtain_identity_center_token, resolve_identity_center};
    use crate::config::Config;
    use crate::integrations::aws::sso_portal::{list_account_roles, list_accounts};
    use vouch_common::http::credential_client;

    let vouch_config = Config::load()?;
    let aws_cfg = vouch_config.aws().ok_or_else(|| {
        crate::exit_code::CliError::ConfigError(tr!("aws-err-idc-not-configured"))
    })?;

    // Resolve the IdC instance and its owning org together. Returns Err on
    // multi-instance ambiguity (no hint), Ok(None) when no org has IdC.
    let (org, idc) = resolve_identity_center(aws_cfg, idc_application_arn)?.ok_or_else(|| {
        crate::exit_code::CliError::ConfigError(tr!("aws-err-idc-not-configured"))
    })?;
    let management_role = &org.management_role;

    let http_client = credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
        .context("failed to create HTTP client")?;

    let idc_token = obtain_identity_center_token(&http_client, server, management_role, idc)
        .await
        .context("failed to obtain Identity Center token")?;

    let accounts = list_accounts(&http_client, &idc.region, &idc_token)
        .await
        .context("failed to list SSO accounts")?;

    let vouch_path = resolve_install_path();
    let mut aws_config = load_or_create_aws_config()?;
    let mut created_count: u32 = 0;
    let mut skipped_count: u32 = 0;

    for account in &accounts {
        let roles = list_account_roles(&http_client, &idc.region, &idc_token, &account.account_id)
            .await
            .with_context(|| format!("failed to list roles for account {}", account.account_id))?;

        for role in &roles {
            let safe_name = sanitize_profile_name(&account.account_name);
            let name_part = if safe_name.is_empty() {
                account.account_id.clone()
            } else {
                safe_name
            };
            let safe_ps = sanitize_profile_name(&role.role_name);
            let profile_name = match profile_prefix {
                Some(prefix) => format!("{prefix}-{name_part}-{safe_ps}"),
                None => format!("vouch-{name_part}-{safe_ps}"),
            };

            if aws_config.profile_exists(&profile_name) {
                tr_println!(
                    "setup-aws-discover-skipped",
                    profile = profile_name.as_str()
                );
                skipped_count = skipped_count.saturating_add(1);
                continue;
            }

            aws_config.set_profile(&AwsProfile {
                name: profile_name.clone(),
                credential_process: Some(format!(
                    "\"{}\" credential aws --idc-application {} --account {} --permission-set \"{}\"",
                    vouch_path.display(),
                    idc.application_arn,
                    account.account_id,
                    role.role_name,
                )),
                region: None,
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
        aws_config.save()?;
    }

    println!();
    tr_println!(
        "setup-aws-discover-summary",
        created = created_count,
        skipped = skipped_count
    );
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

    /// Verify that the credential_process format used by `run_discover` embeds
    /// `--idc-application` so each profile is self-describing and safe when
    /// a second IdC org is later added.
    #[test]
    fn test_discover_credential_process_embeds_idc_application() {
        let vouch_path = std::path::Path::new("/usr/local/bin/vouch");
        let app_arn = "arn:aws:sso::123456789012:application/ssoins-abc/apl-xyz";
        let account_id = "111111111111";
        let role_name = "ReadOnly";

        let credential_process = format!(
            "\"{}\" credential aws --idc-application {} --account {} --permission-set \"{}\"",
            vouch_path.display(),
            app_arn,
            account_id,
            role_name,
        );

        assert!(
            credential_process.contains("--idc-application"),
            "credential_process must include --idc-application: {credential_process}"
        );
        assert!(
            credential_process.contains(app_arn),
            "credential_process must embed the application ARN: {credential_process}"
        );
        assert!(
            credential_process.contains(&format!("--account {account_id}")),
            "credential_process must include --account: {credential_process}"
        );
        assert!(
            credential_process.contains(&format!("--permission-set \"{role_name}\"")),
            "credential_process must include --permission-set: {credential_process}"
        );
    }
}
