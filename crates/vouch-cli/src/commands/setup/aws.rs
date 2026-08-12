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
use inquire::{Confirm, InquireError, Select, Text};
use vouch_cli::{tr, tr_args, tr_println};

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
        .context(tr!("err-could-not-determine-home-directory"))?
        .join(".aws");
    ensure_secure_dir(&aws_dir)?;
    Ok(AwsConfig::load_from(config_path.clone()).unwrap_or_else(|_| AwsConfig::empty(config_path)))
}

/// Arguments for `setup aws`, one field per CLI flag. Grouped into a borrow
/// struct to stay within the positional-parameter limit.
pub(crate) struct SetupAwsArgs<'a> {
    pub profile: Option<&'a str>,
    pub role_arn: Option<&'a str>,
    pub management_role: Option<&'a str>,
    pub identity_center_application: Option<&'a str>,
    pub region: Option<&'a str>,
    pub discover: bool,
    pub server: &'a str,
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
pub(crate) async fn run(args: SetupAwsArgs<'_>) -> Result<()> {
    let SetupAwsArgs {
        profile,
        role_arn,
        management_role,
        identity_center_application,
        region,
        discover,
        server,
    } = args;
    // No flags supplied → launch the interactive first-run wizard.
    if profile.is_none()
        && role_arn.is_none()
        && management_role.is_none()
        && identity_center_application.is_none()
        && region.is_none()
        && !discover
    {
        return run_wizard(server).await;
    }

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

/// Interactive first-run wizard, launched when `setup aws` is run with no flags.
///
/// Establishes one organization per run, reusing the same helpers as the
/// flag-based paths (`store_org` / `write_sts_profile` / `run_discover`).
async fn run_wizard(server: &str) -> Result<()> {
    tr_println!("setup-aws-wizard-intro");

    let single = tr!("setup-aws-wizard-mode-single");
    let chain = tr!("setup-aws-wizard-mode-chain");
    let idc = tr!("setup-aws-wizard-mode-idc");
    let options = vec![single.clone(), chain.clone(), idc.clone()];

    let choice = match Select::new(&tr!("setup-aws-wizard-mode-prompt"), options).prompt() {
        Ok(c) => c,
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
            tr_println!("setup-aws-wizard-cancelled");
            return Ok(());
        }
        Err(e) => return Err(wizard_input_error(&e)),
    };

    if choice == single {
        wizard_single_account()
    } else if choice == chain {
        wizard_management_chain()
    } else {
        wizard_identity_center(server).await
    }
}

/// Single account: prompt for a role ARN and write one profile.
fn wizard_single_account() -> Result<()> {
    let Some(role) = prompt_role_arn(&tr!("setup-aws-wizard-role-prompt"), None)? else {
        tr_println!("setup-aws-wizard-cancelled");
        return Ok(());
    };
    let region = prompt_optional(&tr!("setup-aws-wizard-region-prompt"))?;
    write_sts_profile(None, &role, &role, region.as_deref())
}

/// Management-role chain: store the org, then optionally add target-role profiles.
fn wizard_management_chain() -> Result<()> {
    let orgs = configured_orgs();
    let mgmt_default = orgs.first().map(|o| o.management_role.as_str());
    let Some(mgmt) = prompt_role_arn(&tr!("setup-aws-wizard-mgmt-role-prompt"), mgmt_default)?
    else {
        tr_println!("setup-aws-wizard-cancelled");
        return Ok(());
    };
    store_org(&mgmt, None, None)?;

    if prompt_confirm(&tr!("setup-aws-wizard-add-target"), true)? {
        loop {
            let Some(role) = prompt_role_arn(&tr!("setup-aws-wizard-target-role-prompt"), None)?
            else {
                break;
            };
            let region = prompt_optional(&tr!("setup-aws-wizard-region-prompt"))?;
            write_sts_profile(None, &role, &mgmt, region.as_deref())?;
            if !prompt_confirm(&tr!("setup-aws-wizard-add-another"), false)? {
                break;
            }
        }
    }
    Ok(())
}

/// Identity Center: store the org + IdC anchor, show the audience reminder for
/// the current issuer, and optionally run discovery.
async fn wizard_identity_center(server: &str) -> Result<()> {
    let orgs = configured_orgs();
    let mgmt_default = orgs.first().map(|o| o.management_role.as_str());
    let Some(mgmt) = prompt_role_arn(&tr!("setup-aws-wizard-mgmt-role-prompt"), mgmt_default)?
    else {
        tr_println!("setup-aws-wizard-cancelled");
        return Ok(());
    };

    // The customer's Identity Center application must set its audience claim to
    // this Vouch issuer, or CreateTokenWithIAM rejects the assertion.
    tr_println!("setup-aws-wizard-idc-aud-reminder", issuer = server);

    // If the org for this management role already has Identity Center configured,
    // offer its application ARN and region as defaults.
    let existing_idc = orgs
        .iter()
        .find(|o| o.management_role == mgmt)
        .and_then(|o| o.identity_center.as_ref());

    let Some(app) = prompt_idc_application(
        &tr!("setup-aws-wizard-idc-app-prompt"),
        existing_idc.map(|i| i.application_arn.as_str()),
    )?
    else {
        tr_println!("setup-aws-wizard-cancelled");
        return Ok(());
    };

    // Region is required for Identity Center; prompt until provided or cancelled.
    let region_default = existing_idc.map(|i| i.region.as_str());
    let region_prompt = tr!("setup-aws-wizard-idc-region-prompt");
    let region = loop {
        let text = match region_default {
            Some(d) => Text::new(&region_prompt).with_default(d),
            None => Text::new(&region_prompt),
        };
        match text.prompt() {
            Ok(input) if !input.trim().is_empty() => break input.trim().to_string(),
            Ok(_) => continue,
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
                tr_println!("setup-aws-wizard-cancelled");
                return Ok(());
            }
            Err(e) => return Err(wizard_input_error(&e)),
        }
    };

    store_org(&mgmt, Some(app.as_str()), Some(region.as_str()))?;

    if prompt_confirm(&tr!("setup-aws-wizard-discover"), true)? {
        run_discover(None, Some(app.as_str()), server).await?;
    }
    Ok(())
}

/// Prompt for a required IAM role ARN, re-prompting until it parses or the user
/// cancels. Returns `Ok(None)` on cancel (Esc / Ctrl-C).
fn prompt_role_arn(prompt: &str, default: Option<&str>) -> Result<Option<String>> {
    loop {
        let text = match default {
            Some(d) => Text::new(prompt).with_default(d),
            None => Text::new(prompt),
        };
        match text.prompt() {
            Ok(input) => {
                let trimmed = input.trim();
                if crate::integrations::aws::sts::parse_role_arn(trimmed).is_ok() {
                    return Ok(Some(trimmed.to_string()));
                }
                tr_println!("setup-aws-wizard-invalid-role-arn");
            }
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
                return Ok(None);
            }
            Err(e) => return Err(wizard_input_error(&e)),
        }
    }
}

/// Prompt for a required Identity Center application ARN (service `sso`),
/// re-prompting until valid or cancelled.
fn prompt_idc_application(prompt: &str, default: Option<&str>) -> Result<Option<String>> {
    loop {
        let text = match default {
            Some(d) => Text::new(prompt).with_default(d),
            None => Text::new(prompt),
        };
        match text.prompt() {
            Ok(input) => {
                let trimmed = input.trim();
                let is_sso =
                    vouch_common::aws::Arn::parse(trimmed).is_ok_and(|a| a.service == "sso");
                if is_sso {
                    return Ok(Some(trimmed.to_string()));
                }
                tr_println!("setup-aws-wizard-invalid-idc-arn");
            }
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
                return Ok(None);
            }
            Err(e) => return Err(wizard_input_error(&e)),
        }
    }
}

/// Prompt for an optional value; empty input or cancel → `None`.
fn prompt_optional(prompt: &str) -> Result<Option<String>> {
    match Text::new(prompt).prompt() {
        Ok(input) if input.trim().is_empty() => Ok(None),
        Ok(input) => Ok(Some(input.trim().to_string())),
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => Ok(None),
        Err(e) => Err(wizard_input_error(&e)),
    }
}

/// Yes/no confirmation with a default; cancel is treated as "no".
fn prompt_confirm(prompt: &str, default: bool) -> Result<bool> {
    match Confirm::new(prompt).with_default(default).prompt() {
        Ok(b) => Ok(b),
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => Ok(false),
        Err(e) => Err(wizard_input_error(&e)),
    }
}

/// Map an unexpected inquire error into a user-facing error.
fn wizard_input_error(e: &InquireError) -> anyhow::Error {
    anyhow::anyhow!(tr_args!(
        "setup-aws-wizard-err-input",
        reason = e.to_string()
    ))
}

/// The organizations currently in vouch config, used to pre-fill wizard defaults.
/// Returns an empty list on any load error (the wizard still works, just without
/// pre-filled values).
fn configured_orgs() -> Vec<AwsOrganization> {
    crate::config::Config::load()
        .ok()
        .and_then(|c| c.aws().map(|a| a.organizations.clone()))
        .unwrap_or_default()
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
/// The `credential_process` line for an STS role profile.
///
/// Includes `--via` when chaining through a management role that differs
/// from the target role.
fn sts_credential_process(
    vouch_path: &std::path::Path,
    role_arn: &str,
    management_role: &str,
) -> String {
    if management_role != role_arn {
        format!(
            "\"{}\" credential aws --role {role_arn} --via {management_role}",
            vouch_path.display()
        )
    } else {
        format!(
            "\"{}\" credential aws --role {role_arn}",
            vouch_path.display()
        )
    }
}

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

    let credential_process = sts_credential_process(&vouch_path, role_arn, management_role);

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

/// Enumerate Identity Center access and write profiles.
///
/// Uses the TTI exchange (`CreateTokenWithIAM`) to obtain an IdC access token,
/// then calls `ListAccounts` + `ListAccountRoles` (SSO portal) and writes one
/// `--account <id> --permission-set <name>` profile per assignment found.
/// A second pass surfaces account access manager entitlements (existing IAM
/// roles assigned to the user or their groups) as `--role`/`--via` profiles;
/// that pass is best-effort — anything it cannot do (missing IAM grants on
/// the management role, no email claim, org without account access manager)
/// is debug-logged and skipped, never aborting permission-set discovery.
async fn run_discover(
    profile_prefix: Option<&str>,
    idc_application_arn: Option<&str>,
    server: &str,
) -> Result<()> {
    use crate::commands::credential::aws::{
        assume_management_role, exchange_idc_access_token, resolve_identity_center,
    };
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
        .context(tr!("err-failed-create-http-client"))?;

    let mgmt_session = assume_management_role(&http_client, server, management_role).await?;
    let idc_token = exchange_idc_access_token(&http_client, idc, &mgmt_session)
        .await
        .context(tr!("err-failed-obtain-identity-center-token"))?;

    let accounts = list_accounts(&http_client, &idc.region, &idc_token)
        .await
        .context(tr!("err-failed-list-sso-accounts"))?;

    let vouch_path = resolve_install_path();
    let mut aws_config = load_or_create_aws_config()?;
    let mut created_count: u32 = 0;
    let mut skipped_count: u32 = 0;

    for account in &accounts {
        let roles = list_account_roles(&http_client, &idc.region, &idc_token, &account.account_id)
            .await
            .with_context(|| {
                tr_args!(
                    "err-failed-list-roles-account",
                    value = account.account_id.to_string()
                )
            })?;

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

    // Entitlement pass — best-effort: failures are debug-logged only and
    // the permission-set results above still land.
    let user_email = mgmt_session.user_email;
    let creds = std::sync::Arc::new(mgmt_session.credentials);
    if let Err(err) = discover_entitlements(
        EntitlementDiscovery {
            http_client: &http_client,
            idc,
            management_role,
            user_email: user_email.as_deref(),
            creds,
            vouch_path: &vouch_path,
            profile_prefix,
        },
        &mut aws_config,
        &mut created_count,
        &mut skipped_count,
    )
    .await
    {
        tracing::debug!("entitlement discovery skipped: {err:#}");
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

/// Inputs to the account access manager entitlement pass.
struct EntitlementDiscovery<'a> {
    http_client: &'a reqwest::Client,
    idc: &'a AwsIdentityCenter,
    management_role: &'a str,
    user_email: Option<&'a str>,
    creds: std::sync::Arc<crate::integrations::aws::sts::StsCredentials>,
    vouch_path: &'a std::path::Path,
    profile_prefix: Option<&'a str>,
}

/// Discover account access manager entitlements and append one
/// `--role`/`--via` profile per entitled role.
///
/// Runs whenever the org has IdC configured. Conditions that make the pass
/// inapplicable (non-commercial partition, no email claim, user not in the
/// identity store) are debug-logged and return `Ok`; real failures propagate
/// for the caller's debug log. Only findings are user-visible: added/skipped
/// profile lines, dropped invalid entitlements, and partial-failure warnings.
async fn discover_entitlements(
    input: EntitlementDiscovery<'_>,
    aws_config: &mut AwsConfig,
    created: &mut u32,
    skipped: &mut u32,
) -> Result<()> {
    use crate::integrations::aws::account_access::{self, AamPrincipal};
    use crate::integrations::aws::{identitystore, sso_admin};
    use vouch_common::aws::Partition;

    let region = &input.idc.region;
    if Partition::from_region(region) != Partition::Aws {
        tracing::debug!(
            "entitlement discovery skipped: account access manager is not available \
             in the {region} region's partition"
        );
        return Ok(());
    }

    let Some(email) = input.user_email else {
        tracing::debug!("entitlement discovery skipped: server token has no email claim");
        return Ok(());
    };

    let instances = sso_admin::list_instances(input.http_client, region, &input.creds).await?;
    let Some(identity_store_id) = resolve_identity_store(&instances, &input.idc.application_arn)
    else {
        tracing::debug!("entitlement discovery skipped: could not resolve the identity store");
        return Ok(());
    };

    let user_id = match identitystore::get_user_id(
        input.http_client,
        region,
        &input.creds,
        &identity_store_id,
        email,
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(err) if crate::exit_code::aws_error_code_matches(&err, "ResourceNotFoundException") => {
            tracing::debug!("entitlement discovery skipped: no Identity Center user for {email}");
            return Ok(());
        }
        Err(err) => return Err(err),
    };

    let group_ids = identitystore::list_group_ids_for_member(
        input.http_client,
        region,
        &input.creds,
        &identity_store_id,
        &user_id,
    )
    .await?;

    let applications =
        account_access::list_applications(input.http_client, region, &input.creds).await?;
    if applications.is_empty() {
        tracing::debug!("entitlement discovery: no account access manager application");
        return Ok(());
    }

    let mut principals = vec![AamPrincipal::User(user_id)];
    for group_id in group_ids {
        principals.push(AamPrincipal::Group(group_id));
    }

    // Bounded fan-out over application × principal queries; per-query
    // failures are collected, not fatal.
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let mut join_set = tokio::task::JoinSet::new();
    let mut total_queries: u32 = 0;
    for application_arn in &applications {
        for principal in &principals {
            total_queries = total_queries.saturating_add(1);
            let semaphore = std::sync::Arc::clone(&semaphore);
            let http_client = input.http_client.clone();
            let region = region.clone();
            let creds = std::sync::Arc::clone(&input.creds);
            let application_arn = application_arn.clone();
            let principal = principal.clone();
            join_set.spawn(async move {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .context(tr!("err-failed-list-aam-entitlements"))?;
                account_access::list_entitlements(
                    &http_client,
                    &region,
                    &creds,
                    &application_arn,
                    &principal,
                )
                .await
            });
        }
    }

    let mut entitled = std::collections::BTreeMap::new();
    let mut failed: u32 = 0;
    let mut first_error: Option<anyhow::Error> = None;
    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok(Ok(roles)) => {
                for role in roles {
                    entitled.entry(role.role_arn.clone()).or_insert(role);
                }
            }
            Ok(Err(err)) => {
                failed = failed.saturating_add(1);
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
            Err(join_err) => {
                failed = failed.saturating_add(1);
                if first_error.is_none() {
                    first_error = Some(join_err.into());
                }
            }
        }
    }

    if failed > 0 {
        if failed == total_queries
            && let Some(err) = first_error
        {
            // Every query failed — surface as a pass-level failure for the
            // caller's debug log.
            return Err(err);
        }
        tr_println!(
            "setup-aws-entitlements-partial",
            failed = failed,
            total = total_queries
        );
    }

    if entitled.is_empty() {
        if failed == 0 {
            tracing::debug!("entitlement discovery: no entitlements for {email}");
        }
        return Ok(());
    }

    write_entitled_profiles(entitled.values(), &input, aws_config, created, skipped);
    Ok(())
}

/// Validate each entitled role and append its `--role`/`--via` profile,
/// updating the shared discovery counters.
fn write_entitled_profiles<'a>(
    roles: impl Iterator<Item = &'a crate::integrations::aws::account_access::EntitledRole>,
    input: &EntitlementDiscovery<'_>,
    aws_config: &mut AwsConfig,
    created: &mut u32,
    skipped: &mut u32,
) {
    for role in roles {
        let Some(profile_name) = entitled_role_profile_name(role, input.profile_prefix) else {
            tr_println!(
                "setup-aws-entitlements-invalid-skipped",
                role_arn = role.role_arn.as_str()
            );
            *skipped = skipped.saturating_add(1);
            continue;
        };
        if aws_config.profile_exists(&profile_name) {
            // Unlike a permission-set re-run, this is a cross-mechanism
            // collision: the existing profile may vend different
            // credentials, and the entitlement was NOT configured.
            tr_println!(
                "setup-aws-entitlements-name-taken",
                profile = profile_name.as_str(),
                role_arn = role.role_arn.as_str()
            );
            *skipped = skipped.saturating_add(1);
            continue;
        }
        aws_config.set_profile(&AwsProfile {
            name: profile_name.clone(),
            credential_process: Some(sts_credential_process(
                input.vouch_path,
                &role.role_arn,
                input.management_role,
            )),
            region: None,
            output: Some("json".to_string()),
        });
        tr_println!(
            "setup-aws-discover-added",
            profile = profile_name.as_str(),
            role_arn = role.role_arn.as_str()
        );
        *created = created.saturating_add(1);
    }
}

/// Extract the `ssoins-…` instance ID embedded in an IdC application ARN
/// (`arn:…:sso::…:application/<ssoins-id>/<apl-id>`).
fn instance_id_from_application_arn(application_arn: &str) -> Option<&str> {
    let resource = application_arn.rsplit(':').next()?;
    let mut segments = resource.split('/');
    if segments.next() != Some("application") {
        return None;
    }
    let candidate = segments.next()?;
    candidate.starts_with("ssoins-").then_some(candidate)
}

/// Pick the identity store backing the configured IdC application.
///
/// A single visible instance is used directly; with several, the one whose
/// ID is embedded in the application ARN must match — anything else returns
/// `None` (never guess).
fn resolve_identity_store(
    instances: &[crate::integrations::aws::sso_admin::SsoInstance],
    application_arn: &str,
) -> Option<String> {
    if let [only] = instances {
        return Some(only.identity_store_id.clone());
    }
    let embedded = instance_id_from_application_arn(application_arn)?;
    let mut matched = None;
    for instance in instances {
        if instance.instance_arn.ends_with(embedded) {
            if matched.is_some() {
                return None;
            }
            matched = Some(instance);
        }
    }
    matched.map(|instance| instance.identity_store_id.clone())
}

/// Validate an entitled role and derive its profile name.
///
/// AWS-returned values are interpolated into `credential_process` lines, so
/// the role ARN must parse as an IAM role, the account must be 12 ASCII
/// digits, and the two must agree; anything else is rejected. Naming
/// follows the permission-set scheme: `{prefix|vouch}-{account}-{role}`,
/// falling back to the account ID when the account name sanitizes away.
fn entitled_role_profile_name(
    role: &crate::integrations::aws::account_access::EntitledRole,
    profile_prefix: Option<&str>,
) -> Option<String> {
    let arn = crate::integrations::aws::sts::parse_role_arn(&role.role_arn).ok()?;
    if role.account.len() != 12 || !role.account.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if arn.account.as_deref() != Some(role.account.as_str()) {
        return None;
    }
    // Role names cannot contain `/`, so the last segment is the bare name
    // even for pathed roles (`role/vouch/Name` → `Name`).
    let role_name = role.role_arn.rsplit('/').next()?;
    let safe_role = sanitize_profile_name(role_name);
    if safe_role.is_empty() {
        return None;
    }
    let account_label = role
        .account_name
        .as_deref()
        .map(sanitize_profile_name)
        .filter(|label| !label.is_empty())
        .unwrap_or_else(|| role.account.clone());
    Some(match profile_prefix {
        Some(prefix) => format!("{prefix}-{account_label}-{safe_role}"),
        None => format!("vouch-{account_label}-{safe_role}"),
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

    #[test]
    fn test_sts_credential_process_chains_via_when_roles_differ() {
        let vouch_path = std::path::Path::new("/usr/local/bin/vouch");
        let target = "arn:aws:iam::111111111111:role/vouch/VouchReadOnly";
        let mgmt = "arn:aws:iam::999999999999:role/vouch/VouchAccess";

        assert_eq!(
            sts_credential_process(vouch_path, target, mgmt),
            format!("\"/usr/local/bin/vouch\" credential aws --role {target} --via {mgmt}")
        );
        assert_eq!(
            sts_credential_process(vouch_path, mgmt, mgmt),
            format!("\"/usr/local/bin/vouch\" credential aws --role {mgmt}")
        );
    }

    #[test]
    fn test_instance_id_from_application_arn() {
        assert_eq!(
            instance_id_from_application_arn(
                "arn:aws:sso::860114833029:application/ssoins-722325820ad4410d/apl-abc123"
            ),
            Some("ssoins-722325820ad4410d")
        );
        assert_eq!(
            instance_id_from_application_arn("arn:aws:sso:::instance/ssoins-1"),
            None
        );
        assert_eq!(instance_id_from_application_arn("not-an-arn"), None);
        assert_eq!(
            instance_id_from_application_arn("arn:aws:sso::1:application/apl-only"),
            None
        );
    }

    fn instance(arn: &str, store: &str) -> crate::integrations::aws::sso_admin::SsoInstance {
        crate::integrations::aws::sso_admin::SsoInstance {
            instance_arn: arn.to_string(),
            identity_store_id: store.to_string(),
        }
    }

    #[test]
    fn test_resolve_identity_store_single_instance() {
        let instances = vec![instance("arn:aws:sso:::instance/ssoins-1", "d-1")];
        assert_eq!(
            resolve_identity_store(&instances, "arn:aws:sso::1:application/ssoins-other/apl-1"),
            Some("d-1".to_string())
        );
    }

    #[test]
    fn test_resolve_identity_store_matches_embedded_id() {
        let instances = vec![
            instance("arn:aws:sso:::instance/ssoins-1", "d-1"),
            instance("arn:aws:sso:::instance/ssoins-2", "d-2"),
        ];
        assert_eq!(
            resolve_identity_store(&instances, "arn:aws:sso::1:application/ssoins-2/apl-1"),
            Some("d-2".to_string())
        );
    }

    #[test]
    fn test_resolve_identity_store_no_match_never_guesses() {
        let instances = vec![
            instance("arn:aws:sso:::instance/ssoins-1", "d-1"),
            instance("arn:aws:sso:::instance/ssoins-2", "d-2"),
        ];
        assert_eq!(
            resolve_identity_store(&instances, "arn:aws:sso::1:application/ssoins-3/apl-1"),
            None
        );
        assert_eq!(
            resolve_identity_store(&[], "arn:aws:sso::1:application/ssoins-1/apl-1"),
            None
        );
    }

    fn entitled(
        role_arn: &str,
        account: &str,
        account_name: Option<&str>,
    ) -> crate::integrations::aws::account_access::EntitledRole {
        crate::integrations::aws::account_access::EntitledRole {
            role_arn: role_arn.to_string(),
            account: account.to_string(),
            account_name: account_name.map(str::to_string),
        }
    }

    #[test]
    fn test_entitled_role_profile_name_uses_account_name_and_role() {
        let role = entitled(
            "arn:aws:iam::444455556666:role/vouch/VouchReadOnly",
            "444455556666",
            Some("Prod Payments"),
        );
        assert_eq!(
            entitled_role_profile_name(&role, None),
            Some("vouch-prod-payments-vouchreadonly".to_string())
        );
        assert_eq!(
            entitled_role_profile_name(&role, Some("work")),
            Some("work-prod-payments-vouchreadonly".to_string())
        );
    }

    #[test]
    fn test_entitled_role_profile_name_falls_back_to_account_id() {
        let role = entitled(
            "arn:aws:iam::444455556666:role/ReadOnly",
            "444455556666",
            None,
        );
        assert_eq!(
            entitled_role_profile_name(&role, None),
            Some("vouch-444455556666-readonly".to_string())
        );

        // An account name that sanitizes to nothing also falls back.
        let role = entitled(
            "arn:aws:iam::444455556666:role/ReadOnly",
            "444455556666",
            Some("!!!"),
        );
        assert_eq!(
            entitled_role_profile_name(&role, None),
            Some("vouch-444455556666-readonly".to_string())
        );
    }

    #[test]
    fn test_entitled_role_profile_name_rejects_invalid_input() {
        // Not an IAM role ARN.
        assert_eq!(
            entitled_role_profile_name(
                &entitled("arn:aws:sso:::instance/ssoins-1", "444455556666", None),
                None
            ),
            None
        );
        // Account is not 12 ASCII digits.
        assert_eq!(
            entitled_role_profile_name(
                &entitled("arn:aws:iam::444455556666:role/R", "44445555666", None),
                None
            ),
            None
        );
        assert_eq!(
            entitled_role_profile_name(
                &entitled("arn:aws:iam::444455556666:role/R", "44445555666x", None),
                None
            ),
            None
        );
        // ARN account and entitlement account disagree.
        assert_eq!(
            entitled_role_profile_name(
                &entitled("arn:aws:iam::444455556666:role/R", "111111111111", None),
                None
            ),
            None
        );
    }
}
