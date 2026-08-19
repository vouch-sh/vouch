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
/// The `credential_process` line for an STS role profile.
///
/// Includes `--via` when chaining through a management role that differs
/// from the target role, so the CLI chains through the correct management
/// role in multi-org configurations.
fn sts_credential_process(
    vouch_path: &std::path::Path,
    role_arn: &str,
    management_role: &str,
) -> String {
    crate::integrations::aws::CredentialProcessLine::Role {
        role_arn: role_arn.to_string(),
        via: (management_role != role_arn).then(|| management_role.to_string()),
    }
    .render(vouch_path)
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
    let mut assignments: std::collections::BTreeSet<(String, String)> =
        std::collections::BTreeSet::new();

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
            assignments.insert((account.account_id.clone(), role.role_name.clone()));
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
                credential_process: Some(
                    crate::integrations::aws::CredentialProcessLine::IdentityCenter {
                        application_arn: Some(idc.application_arn.clone()),
                        account: account.account_id.clone(),
                        permission_set: role.role_name.clone(),
                    }
                    .render(&vouch_path),
                ),
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
    let role_session_name = mgmt_session.role_session_name;
    let ctx = DiscoveryContext {
        http_client: &http_client,
        idc,
        management_role,
        role_session_name: &role_session_name,
        user_email: user_email.as_deref(),
        creds: std::sync::Arc::new(mgmt_session.credentials),
        vouch_path: &vouch_path,
        profile_prefix,
    };
    let probed = match discover_entitlements(
        &ctx,
        &mut aws_config,
        &mut created_count,
        &mut skipped_count,
    )
    .await
    {
        Ok(probed) => probed,
        Err(err) => {
            tracing::debug!("entitlement discovery skipped: {err:#}");
            std::collections::BTreeSet::new()
        }
    };
    validate_existing_profiles(&ctx, &aws_config, &assignments, &probed).await;

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

/// Shared inputs for the entitlement pass and the existing-profile sweep.
struct DiscoveryContext<'a> {
    http_client: &'a reqwest::Client,
    idc: &'a AwsIdentityCenter,
    management_role: &'a str,
    /// The management session's `RoleSessionName` (the JWT `sub`), reused
    /// for probe hops so CloudTrail shows one session identity per human.
    role_session_name: &'a str,
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
///
/// Returns the role ARNs whose assumability was probed, so the
/// existing-profile sweep does not probe them again.
async fn discover_entitlements(
    input: &DiscoveryContext<'_>,
    aws_config: &mut AwsConfig,
    created: &mut u32,
    skipped: &mut u32,
) -> Result<std::collections::BTreeSet<String>> {
    use crate::integrations::aws::account_access::{self, AamPrincipal};
    use crate::integrations::aws::{identitystore, sso_admin};
    use vouch_common::aws::Partition;

    let region = &input.idc.region;
    if Partition::from_region(region) != Partition::Aws {
        tracing::debug!(
            "entitlement discovery skipped: account access manager is not available \
             in the {region} region's partition"
        );
        return Ok(std::collections::BTreeSet::new());
    }

    let Some(email) = input.user_email else {
        tracing::debug!("entitlement discovery skipped: server token has no email claim");
        return Ok(std::collections::BTreeSet::new());
    };

    let instances = sso_admin::list_instances(input.http_client, region, &input.creds).await?;
    let Some(identity_store_id) = resolve_identity_store(&instances, &input.idc.application_arn)
    else {
        tracing::debug!("entitlement discovery skipped: could not resolve the identity store");
        return Ok(std::collections::BTreeSet::new());
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
            return Ok(std::collections::BTreeSet::new());
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
        return Ok(std::collections::BTreeSet::new());
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
        return Ok(std::collections::BTreeSet::new());
    }

    Ok(write_entitled_profiles(entitled.values(), input, aws_config, created, skipped).await)
}

/// Validate each entitled role and append its `--role`/`--via` profile,
/// updating the shared discovery counters.
///
/// Every entitled role — candidate or already configured — is probed for
/// assumability on every pass (the entitlement map does not imply the role
/// trusts the management role, and a trust statement can be added or
/// removed at any time). A new profile is written only when the probe does
/// not confirm a denial, so `~/.aws/config` never gains a dead entry; an
/// existing profile that fails the probe is reported but kept — removing
/// operator config is not discovery's call.
///
/// Returns the role ARNs that were probed.
async fn write_entitled_profiles<'a>(
    roles: impl Iterator<Item = &'a crate::integrations::aws::account_access::EntitledRole>,
    input: &DiscoveryContext<'_>,
    aws_config: &mut AwsConfig,
    created: &mut u32,
    skipped: &mut u32,
) -> std::collections::BTreeSet<String> {
    // Validate names and collisions first, collecting the roles to probe.
    let mut targets = Vec::new();
    for role in roles {
        let Some(profile_name) = entitled_role_profile_name(role, input.profile_prefix) else {
            tr_println!(
                "setup-aws-entitlements-invalid-skipped",
                role_arn = role.role_arn.as_str()
            );
            *skipped = skipped.saturating_add(1);
            continue;
        };
        if let Some(existing) = aws_config.get_profile(&profile_name) {
            match classify_name_collision(&existing, &role.role_arn) {
                // A prior discovery run already configured this role —
                // re-validate that the assumption still works.
                NameCollision::SameRole => targets.push(ProbeTarget {
                    role_arn: role.role_arn.clone(),
                    profile_name,
                    disposition: Disposition::Existing,
                }),
                // Cross-mechanism collision: the existing profile vends
                // something else, and the entitlement was NOT configured.
                NameCollision::Foreign => {
                    tr_println!(
                        "setup-aws-entitlements-name-taken",
                        profile = profile_name.as_str(),
                        role_arn = role.role_arn.as_str()
                    );
                    *skipped = skipped.saturating_add(1);
                }
            }
            continue;
        }
        targets.push(ProbeTarget {
            role_arn: role.role_arn.clone(),
            profile_name,
            disposition: Disposition::Added,
        });
    }

    // Probe concurrently, then report and write in input order. A confirmed
    // denial gates the write of a new profile.
    let mut probed = std::collections::BTreeSet::new();
    for (target, probe) in probe_targets(input, targets).await {
        let usable = report_probe_outcome(input, &target, &probe);
        match target.disposition {
            Disposition::Added if usable => {
                aws_config.set_profile(&AwsProfile {
                    name: target.profile_name.clone(),
                    credential_process: Some(sts_credential_process(
                        input.vouch_path,
                        &target.role_arn,
                        input.management_role,
                    )),
                    region: None,
                    output: Some("json".to_string()),
                });
                *created = created.saturating_add(1);
            }
            Disposition::Added | Disposition::Existing => {
                *skipped = skipped.saturating_add(1);
            }
        }
        probed.insert(target.role_arn);
    }
    probed
}

/// Whether the profile being reported was written this pass or already
/// existed from a prior run — selects the status-line wording only.
#[derive(Clone, Copy)]
enum Disposition {
    Added,
    Existing,
}

/// A role profile awaiting an assumability probe.
struct ProbeTarget {
    role_arn: String,
    profile_name: String,
    disposition: Disposition,
}

/// Probe each target's chained `AssumeRole` hop — the same call vending
/// performs, with the region resolved the same way vending resolves it —
/// with bounded concurrency (the same fan-out shape as the entitlement
/// queries above). Results return in input order so the printed report
/// stays deterministic. One CloudTrail `AssumeRole` event per target; the
/// 900-second minimum duration keeps the unused probe session as short as
/// AWS allows.
async fn probe_targets(
    input: &DiscoveryContext<'_>,
    targets: Vec<ProbeTarget>,
) -> Vec<(
    ProbeTarget,
    Result<crate::integrations::aws::sts::StsCredentials>,
)> {
    use crate::integrations::aws::sts::{AssumeRoleRequest, assume_role};

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let mut join_set = tokio::task::JoinSet::new();
    for (index, target) in targets.iter().enumerate() {
        let semaphore = std::sync::Arc::clone(&semaphore);
        let http_client = input.http_client.clone();
        let creds = std::sync::Arc::clone(&input.creds);
        let role_session_name = input.role_session_name.to_string();
        let role_arn = target.role_arn.clone();
        join_set.spawn(async move {
            let probe = async {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .context("probe semaphore closed")?;
                let region = crate::integrations::aws::resolve_region_with_fallback(&role_arn)?;
                assume_role(AssumeRoleRequest {
                    http_client: &http_client,
                    role_arn: &role_arn,
                    role_session_name: &role_session_name,
                    region: &region,
                    source_creds: &creds,
                    session_policy_names: &[],
                    session_policy: None,
                    identity_context: None,
                    duration_seconds: 900,
                })
                .await
            };
            (index, probe.await)
        });
    }

    let mut results = std::collections::BTreeMap::new();
    while let Some(joined) = join_set.join_next().await {
        // A panicked task leaves its slot empty and reports as inconclusive.
        if let Ok((index, result)) = joined {
            results.insert(index, result);
        }
    }
    targets
        .into_iter()
        .enumerate()
        .map(|(index, target)| {
            let result = results
                .remove(&index)
                .unwrap_or_else(|| Err(anyhow::anyhow!("probe task failed")));
            (target, result)
        })
        .collect()
}

/// Print the probe outcome for one profile.
///
/// Returns whether the profile should exist: `false` only on a confirmed
/// AWS access denial. Inconclusive probes (throttling, network, region
/// resolution) claim nothing and return `true` — a transient fault must
/// not drop profiles.
fn report_probe_outcome(
    input: &DiscoveryContext<'_>,
    target: &ProbeTarget,
    probe: &Result<crate::integrations::aws::sts::StsCredentials>,
) -> bool {
    let profile_name = target.profile_name.as_str();
    let role_arn = target.role_arn.as_str();
    // Denial detection: signature/clock-skew 403s classify as network
    // errors, not denials — see `CliError::is_aws_access_denied`.
    match (target.disposition, probe) {
        (Disposition::Added, Ok(_)) => {
            tr_println!(
                "setup-aws-entitlements-added-verified",
                profile = profile_name,
                role_arn = role_arn
            );
            true
        }
        (Disposition::Existing, Ok(_)) => {
            tr_println!(
                "setup-aws-entitlements-existing-verified",
                profile = profile_name,
                role_arn = role_arn
            );
            true
        }
        (Disposition::Added, Err(err)) if crate::exit_code::aws_access_denied(err) => {
            tr_println!(
                "setup-aws-entitlements-not-assumable-skipped",
                profile = profile_name,
                role_arn = role_arn
            );
            print_trust_remediation(input);
            tr_println!("setup-aws-entitlements-rerun-hint");
            false
        }
        (Disposition::Existing, Err(err)) if crate::exit_code::aws_access_denied(err) => {
            tr_println!(
                "setup-aws-entitlements-existing-trust-missing",
                profile = profile_name,
                role_arn = role_arn
            );
            print_trust_remediation(input);
            false
        }
        // Throttling or network says nothing about trust — claim nothing.
        (Disposition::Added, Err(err)) => {
            tracing::debug!("entitlement probe inconclusive for {role_arn}: {err:#}");
            tr_println!(
                "setup-aws-discover-added",
                profile = profile_name,
                role_arn = role_arn
            );
            true
        }
        (Disposition::Existing, Err(err)) => {
            tracing::debug!("entitlement probe inconclusive for {role_arn}: {err:#}");
            tr_println!("setup-aws-discover-skipped", profile = profile_name);
            true
        }
    }
}

/// Print the trust-statement remediation for a denied probe.
fn print_trust_remediation(input: &DiscoveryContext<'_>) {
    use crate::commands::credential::aws::{chained_role_trust_statement, source_identity_pattern};

    let statement = chained_role_trust_statement(
        input.management_role,
        &source_identity_pattern(input.role_session_name),
    );
    tr_println!(
        "setup-aws-entitlements-trust-remediation",
        management_role = input.management_role,
        statement = statement.as_str()
    );
}

/// Health-check every Vouch-managed profile that discovery did not already
/// touch this run: role-carrying profiles are probed through the management
/// session (the same hop vending uses); Identity Center profiles are
/// checked against the assignments the portal returned. Report-only —
/// nothing is written or removed.
async fn validate_existing_profiles(
    ctx: &DiscoveryContext<'_>,
    aws_config: &AwsConfig,
    assignments: &std::collections::BTreeSet<(String, String)>,
    probed: &std::collections::BTreeSet<String>,
) {
    use crate::integrations::aws::CredentialProcessLine;

    let mut checked: u32 = 0;
    let mut issues: u32 = 0;
    let mut seen = probed.clone();
    let mut targets = Vec::new();
    for profile in aws_config.find_all_vouch_profiles() {
        let Some(line) = profile
            .credential_process
            .as_deref()
            .and_then(CredentialProcessLine::parse)
        else {
            continue;
        };
        match line {
            CredentialProcessLine::Role { role_arn, via } => {
                if !seen.insert(role_arn.clone()) {
                    continue;
                }
                // A profile pinned to a different org's management role
                // cannot be probed with this run's session.
                if via.is_some_and(|via| via != ctx.management_role) {
                    tracing::debug!(
                        "sweep skipped {}: chained via a different management role",
                        profile.name
                    );
                    continue;
                }
                checked = checked.saturating_add(1);
                if role_arn == ctx.management_role {
                    // The session in hand is this role — trivially assumable.
                    tr_println!(
                        "setup-aws-entitlements-existing-verified",
                        profile = profile.name.as_str(),
                        role_arn = role_arn.as_str()
                    );
                    continue;
                }
                targets.push(ProbeTarget {
                    role_arn,
                    profile_name: profile.name,
                    disposition: Disposition::Existing,
                });
            }
            CredentialProcessLine::IdentityCenter {
                application_arn,
                account,
                permission_set,
            } => {
                // An absent `--idc-application` resolves to the configured
                // org at vend time — treat it as this org's profile.
                if application_arn.is_some_and(|app| app != ctx.idc.application_arn) {
                    continue;
                }
                checked = checked.saturating_add(1);
                if !assignments.contains(&(account.clone(), permission_set.clone())) {
                    issues = issues.saturating_add(1);
                    tr_println!(
                        "setup-aws-sweep-assignment-stale",
                        profile = profile.name.as_str(),
                        account = account.as_str(),
                        permission_set = permission_set.as_str()
                    );
                }
            }
        }
    }
    for (target, probe) in probe_targets(ctx, targets).await {
        if !report_probe_outcome(ctx, &target, &probe) {
            issues = issues.saturating_add(1);
        }
    }
    if checked > 0 {
        tr_println!(
            "setup-aws-sweep-summary",
            checked = checked,
            issues = issues
        );
    }
}

/// How an entitled role relates to an existing profile occupying its name.
#[derive(Debug, PartialEq, Eq)]
enum NameCollision {
    /// The existing profile's `credential_process` targets the same role
    /// ARN — a previous discovery run already configured this entitlement.
    SameRole,
    /// The existing profile targets something else (a permission set, a
    /// different role, or a hand-written profile).
    Foreign,
}

fn classify_name_collision(existing: &AwsProfile, role_arn: &str) -> NameCollision {
    use crate::integrations::aws::CredentialProcessLine;

    let same_role = match existing
        .credential_process
        .as_deref()
        .and_then(CredentialProcessLine::parse)
    {
        Some(CredentialProcessLine::Role {
            role_arn: existing_role,
            via: _,
        }) => existing_role == role_arn,
        Some(CredentialProcessLine::IdentityCenter {
            application_arn: _,
            account: _,
            permission_set: _,
        })
        | None => false,
    };
    if same_role {
        NameCollision::SameRole
    } else {
        NameCollision::Foreign
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
/// The instance whose ID is embedded in the application ARN must be
/// visible — never guess, even when only one instance is listed, so a
/// stale `--idc-application` cannot resolve against the wrong org's store.
fn resolve_identity_store(
    instances: &[crate::integrations::aws::sso_admin::SsoInstance],
    application_arn: &str,
) -> Option<String> {
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
    fn test_resolve_identity_store_single_instance_must_match() {
        let instances = vec![instance("arn:aws:sso:::instance/ssoins-1", "d-1")];
        assert_eq!(
            resolve_identity_store(&instances, "arn:aws:sso::1:application/ssoins-1/apl-1"),
            Some("d-1".to_string())
        );
        // A single visible instance is NOT trusted blindly: a stale
        // application ARN pointing at another instance must not resolve.
        assert_eq!(
            resolve_identity_store(&instances, "arn:aws:sso::1:application/ssoins-other/apl-1"),
            None
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

    fn profile_with_cp(credential_process: Option<&str>) -> AwsProfile {
        AwsProfile {
            name: "vouch-prod-readonly".to_string(),
            credential_process: credential_process.map(str::to_string),
            region: None,
            output: None,
        }
    }

    #[test]
    fn test_classify_name_collision_same_role_is_rerun() {
        let role = "arn:aws:iam::444455556666:role/vouch/VouchReadOnly";
        let existing = profile_with_cp(Some(
            "\"/usr/local/bin/vouch\" credential aws --role \
             arn:aws:iam::444455556666:role/vouch/VouchReadOnly --via \
             arn:aws:iam::999999999999:role/vouch/VouchAccess",
        ));
        assert_eq!(
            classify_name_collision(&existing, role),
            NameCollision::SameRole
        );
    }

    #[test]
    fn test_classify_name_collision_foreign_targets() {
        let role = "arn:aws:iam::444455556666:role/vouch/VouchReadOnly";
        // Different role ARN.
        let other_role = profile_with_cp(Some(
            "\"/usr/local/bin/vouch\" credential aws --role arn:aws:iam::1:role/Other",
        ));
        assert_eq!(
            classify_name_collision(&other_role, role),
            NameCollision::Foreign
        );
        // Permission-set profile (no --role in the credential_process).
        let permission_set = profile_with_cp(Some(
            "\"/usr/local/bin/vouch\" credential aws --idc-application arn:aws:sso::1:application/x/y \
             --account 444455556666 --permission-set \"ReadOnly\"",
        ));
        assert_eq!(
            classify_name_collision(&permission_set, role),
            NameCollision::Foreign
        );
        // Hand-written profile without a credential_process.
        assert_eq!(
            classify_name_collision(&profile_with_cp(None), role),
            NameCollision::Foreign
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
