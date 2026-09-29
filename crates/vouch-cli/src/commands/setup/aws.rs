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

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use inquire::{Confirm, InquireError, Select, Text};
use vouch_cli::{tr, tr_args, tr_println};

use crate::config::{AwsIdentityCenter, AwsOrganization, Config};
use crate::exit_code::{self, CliError};
use crate::install_path::resolve_install_path;
use crate::integrations::aws::account_access::EntitledRole;
use crate::integrations::aws::sso_admin::SsoInstance;
use crate::integrations::aws::sts::StsCredentials;
use crate::integrations::aws::{self, AwsConfig, AwsProfile, CredentialProcessLine, sts};
use crate::server_url::ServerUrl;
use crate::utils::ensure_secure_dir;
use vouch_common::aws::Arn;

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

/// Derive the directory to create/secure for an AWS config file path.
///
/// Returns the parent directory of `config_path`, or `None` when the path
/// is a bare filename (`parent()` yields an empty string) — in that case
/// the file lands in the CWD, which already exists, so no directory needs
/// creating.
///
/// Factored out of [`load_or_create_aws_config`] so the directory-derivation
/// logic is testable without mutating process environment variables
/// (`std::env::set_var` is `unsafe` under edition 2024 and the workspace
/// denies `unsafe_code`).
fn config_parent_dir(config_path: &std::path::Path) -> Option<&std::path::Path> {
    config_path.parent().filter(|p| !p.as_os_str().is_empty())
}

/// Open (or create) the AWS config file and ensure its parent directory exists.
///
/// The config path is resolved by [`AwsConfig::default_path`], which honors
/// `AWS_CONFIG_FILE` — so the directory secured here is the parent of the
/// *resolved* path, whether that is `~/.aws` or the override location.
fn load_or_create_aws_config() -> Result<AwsConfig> {
    let config_path = AwsConfig::default_path()?;
    if let Some(parent) = config_parent_dir(&config_path) {
        ensure_secure_dir(parent)?;
    }
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
    pub server: &'a ServerUrl,
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
                return Err(CliError::ConfigError(tr!("setup-aws-err-role-required")).into());
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
async fn run_wizard(server: &ServerUrl) -> Result<()> {
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
async fn wizard_identity_center(server: &ServerUrl) -> Result<()> {
    let orgs = configured_orgs();
    let mgmt_default = orgs.first().map(|o| o.management_role.as_str());
    let Some(mgmt) = prompt_role_arn(&tr!("setup-aws-wizard-mgmt-role-prompt"), mgmt_default)?
    else {
        tr_println!("setup-aws-wizard-cancelled");
        return Ok(());
    };

    // The customer's Identity Center application must set its audience claim to
    // this Vouch issuer, or CreateTokenWithIAM rejects the assertion.
    tr_println!(
        "setup-aws-wizard-idc-aud-reminder",
        issuer = server.as_str()
    );

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
                if sts::parse_role_arn(trimmed).is_ok() {
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
                let is_sso = Arn::parse(trimmed).is_ok_and(|a| a.service == "sso");
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
    Config::load()
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
            return Err(CliError::ConfigError(tr!("setup-aws-err-region-required")).into());
        }
        _ => None,
    };

    let mut config = Config::load()?;
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
    CredentialProcessLine::Role {
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
                tr_println!(
                    "setup-aws-profile-already-exists",
                    profile = p,
                    config_path = config.path().display().to_string(),
                );
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
        config_path = config.path().display().to_string(),
    );
    Ok(())
}

/// Where discovery puts the profile for one assignment: an Identity Center
/// account and permission set, or an entitled IAM role.
///
/// Pure over `aws_config`; the caller does the printing and the
/// `set_profile` for the variant returned.
#[derive(Debug, PartialEq, Eq)]
enum ProfilePlan {
    /// No candidate name holds a profile for this assignment. Write one at
    /// `profile_name`, the first free candidate.
    Write { profile_name: String },
    /// A profile at `profile_name` already vends this assignment: a re-run.
    /// It is left where it is, never renamed.
    Existing { profile_name: String },
    /// Every candidate name is held by a profile vending something else, so
    /// writing would overwrite a working profile. `profile_name` is the last
    /// candidate, for the message.
    NameTaken { profile_name: String },
}

/// The names discovery tries for one assignment, most preferred first.
///
/// The preferred `base` (`{prefix|vouch}-{account-label}-{slug}`) is short
/// but not unique: AWS does not enforce unique account display names, and
/// [`sanitize_profile_name`] collapses distinct names (`Admin.Access`,
/// `Admin_Access`, `Admin+Access`) to one slug. `{base}-{account_id}`
/// separates accounts. `{base}-{account_id}-{hash}` separates assignments,
/// where `hash` is the first 8 hex digits of SHA-256 over `unit`, the raw
/// value the slug came from (the permission-set name, or the role ARN), so
/// two assignments get the same third name only if their raw values are
/// equal. Every name is stable across runs; the longer ones are only used
/// when the shorter ones are taken.
fn profile_name_candidates(base: &str, account_id: &str, unit: &str) -> [String; 3] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, unit.as_bytes());
    let hash: String = digest
        .as_ref()
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();
    [
        base.to_string(),
        format!("{base}-{account_id}"),
        format!("{base}-{account_id}-{hash}"),
    ]
}

/// Decide where the profile for one assignment goes.
///
/// A profile that already vends the assignment (`vends`) at any candidate
/// name wins, so a re-run neither duplicates nor renames it. Otherwise the
/// first candidate that is neither in `aws_config` nor in `claimed` (names
/// this pass has already decided to write, for callers that write after
/// deciding) is chosen. Only when all three are held by other profiles is
/// the assignment reported instead of written.
fn plan_profile(
    aws_config: &AwsConfig,
    claimed: &BTreeSet<String>,
    base: &str,
    account_id: &str,
    unit: &str,
    vends: impl Fn(&AwsProfile) -> bool,
) -> ProfilePlan {
    let candidates = profile_name_candidates(base, account_id, unit);
    for candidate in &candidates {
        if aws_config
            .get_profile(candidate)
            .is_some_and(|existing| vends(&existing))
        {
            return ProfilePlan::Existing {
                profile_name: candidate.clone(),
            };
        }
    }
    for candidate in &candidates {
        if !claimed.contains(candidate) && aws_config.get_profile(candidate).is_none() {
            return ProfilePlan::Write {
                profile_name: candidate.clone(),
            };
        }
    }
    let [.., last] = candidates;
    ProfilePlan::NameTaken { profile_name: last }
}

/// [`plan_profile`] for one Identity Center assignment written by
/// [`run_discover`], which writes each profile as soon as it decides, so no
/// names are claimed ahead of the config.
///
/// An existing profile vends the assignment when its `credential_process`
/// names the same account and permission set under this run's IdC
/// application (see [`existing_vends_same_idc_assignment`]). Anything else
/// at a candidate name, including an STS `--role` profile, a profile pinned
/// to another application, or a hand-written one, is someone else's.
fn plan_idc_write(
    aws_config: &AwsConfig,
    base_name: &str,
    account_id: &str,
    permission_set: &str,
    idc_application_arn: &str,
) -> ProfilePlan {
    plan_profile(
        aws_config,
        &BTreeSet::new(),
        base_name,
        account_id,
        permission_set,
        |existing| {
            existing_vends_same_idc_assignment(
                existing,
                idc_application_arn,
                account_id,
                permission_set,
            )
        },
    )
}

/// Whether an existing profile's `credential_process` vends the given
/// Identity Center assignment under this discovery run's IdC application.
///
/// An absent `--idc-application` resolves to the configured org at vend time
/// (the same policy the existing-profile sweep applies), so a legacy profile
/// with no pinned application counts as this org's. A profile pinned to a
/// *different* application does not — it vends a different IAM role, so the
/// assignment is not covered by it and must get its own profile.
fn existing_vends_same_idc_assignment(
    existing: &AwsProfile,
    idc_application_arn: &str,
    account_id: &str,
    permission_set_name: &str,
) -> bool {
    use crate::integrations::aws::CredentialProcessLine;

    existing
        .credential_process
        .as_deref()
        .and_then(CredentialProcessLine::parse)
        .is_some_and(|line| {
            matches!(
                line,
                CredentialProcessLine::IdentityCenter {
                    application_arn,
                    account,
                    permission_set,
                } if account.as_str() == account_id
                    && permission_set.as_str() == permission_set_name
                    && application_arn.as_deref().is_none_or(|p| p == idc_application_arn)
            )
        })
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
    server: &ServerUrl,
) -> Result<()> {
    use crate::commands::credential::aws::{
        assume_management_role, exchange_idc_access_token, resolve_identity_center,
    };
    use crate::integrations::aws::sso_portal::{list_account_roles, list_accounts};
    use vouch_common::http::credential_client;

    let vouch_config = Config::load()?;
    let aws_cfg = vouch_config
        .aws()
        .ok_or_else(|| CliError::ConfigError(tr!("aws-err-idc-not-configured")))?;

    // Resolve the IdC instance and its owning org together. Returns Err on
    // multi-instance ambiguity (no hint), Ok(None) when no org has IdC.
    let (org, idc) = resolve_identity_center(aws_cfg, idc_application_arn)?
        .ok_or_else(|| CliError::ConfigError(tr!("aws-err-idc-not-configured")))?;
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
    let mut assignments: BTreeSet<(String, String)> = BTreeSet::new();

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
            let base_name = match profile_prefix {
                Some(prefix) => format!("{prefix}-{name_part}-{safe_ps}"),
                None => format!("vouch-{name_part}-{safe_ps}"),
            };

            // The profile name is built from the sanitized account *display
            // name*, which is not unique per assignment (AWS does not enforce
            // unique display names, and sanitization collapses distinct
            // names to one slug). A name-only existence check would silently
            // drop the second colliding assignment while reporting it
            // `setup-aws-idc-existing-verified`. `plan_idc_write` parses the
            // existing profile's `credential_process` and distinguishes a
            // genuine re-run (same account + permission set) from a foreign
            // collision, falling back to the account ID and then a hash of the
            // permission-set name so every assignment the portal returned
            // gets a vendable profile.
            match plan_idc_write(
                &aws_config,
                &base_name,
                &account.account_id,
                &role.role_name,
                &idc.application_arn,
            ) {
                ProfilePlan::Existing { profile_name } => {
                    tr_println!(
                        "setup-aws-idc-existing-verified",
                        profile = profile_name.as_str(),
                        account = account.account_id.as_str(),
                        permission_set = role.role_name.as_str()
                    );
                    skipped_count = skipped_count.saturating_add(1);
                }
                ProfilePlan::NameTaken { profile_name } => {
                    tr_println!(
                        "setup-aws-idc-name-taken",
                        profile = profile_name.as_str(),
                        account = account.account_id.as_str(),
                        permission_set = role.role_name.as_str()
                    );
                    skipped_count = skipped_count.saturating_add(1);
                }
                ProfilePlan::Write { profile_name } => {
                    aws_config.set_profile(&AwsProfile {
                        name: profile_name.clone(),
                        credential_process: Some(
                            CredentialProcessLine::IdentityCenter {
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
            BTreeSet::new()
        }
    };
    validate_existing_profiles(&ctx, &vouch_config, &aws_config, &assignments, &probed).await;

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
    creds: std::sync::Arc<StsCredentials>,
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
) -> Result<BTreeSet<String>> {
    use crate::integrations::aws::account_access::{self, AamPrincipal};
    use crate::integrations::aws::{identitystore, sso_admin};
    use vouch_common::aws::Partition;

    let region = &input.idc.region;
    if Partition::from_region(region) != Partition::Aws {
        tracing::debug!(
            "entitlement discovery skipped: account access manager is not available \
             in the {region} region's partition"
        );
        return Ok(BTreeSet::new());
    }

    let Some(email) = input.user_email else {
        tracing::debug!("entitlement discovery skipped: server token has no email claim");
        return Ok(BTreeSet::new());
    };

    let instances = sso_admin::list_instances(input.http_client, region, &input.creds).await?;
    let Some(identity_store_id) = resolve_identity_store(&instances, &input.idc.application_arn)
    else {
        tracing::debug!("entitlement discovery skipped: could not resolve the identity store");
        return Ok(BTreeSet::new());
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
        Err(err) if exit_code::aws_error_code_matches(&err, "ResourceNotFoundException") => {
            tracing::debug!("entitlement discovery skipped: no Identity Center user for {email}");
            return Ok(BTreeSet::new());
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
        return Ok(BTreeSet::new());
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

    let mut entitled = BTreeMap::new();
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
        return Ok(BTreeSet::new());
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
    roles: impl Iterator<Item = &'a EntitledRole>,
    input: &DiscoveryContext<'_>,
    aws_config: &mut AwsConfig,
    created: &mut u32,
    skipped: &mut u32,
) -> BTreeSet<String> {
    let targets = plan_entitled_profiles(roles, input.profile_prefix, aws_config, skipped);

    // Probe concurrently, then report and write in input order. A confirmed
    // denial gates the write of a new profile.
    let mut probed = BTreeSet::new();
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

/// Choose the profile name for each entitled role, reporting and counting
/// in `skipped` the roles that cannot be configured.
///
/// Returns the roles to probe: each one already configured at one of its
/// candidate names ([`Disposition::Existing`]), or planned for a free one
/// ([`Disposition::Added`]). Profiles are written only after probing, so a
/// name chosen for an earlier role in this pass is claimed to keep a later
/// role whose name slugifies the same off it.
fn plan_entitled_profiles<'a>(
    roles: impl Iterator<Item = &'a EntitledRole>,
    profile_prefix: Option<&str>,
    aws_config: &AwsConfig,
    skipped: &mut u32,
) -> Vec<ProbeTarget> {
    let mut targets = Vec::new();
    let mut claimed = BTreeSet::new();
    for role in roles {
        let Some(base_name) = entitled_role_profile_name(role, profile_prefix) else {
            tr_println!(
                "setup-aws-entitlements-invalid-skipped",
                role_arn = role.role_arn.as_str()
            );
            *skipped = skipped.saturating_add(1);
            continue;
        };
        let plan = plan_profile(
            aws_config,
            &claimed,
            &base_name,
            &role.account,
            &role.role_arn,
            |existing| classify_name_collision(existing, &role.role_arn) == NameCollision::SameRole,
        );
        match plan {
            // A prior discovery run already configured this role —
            // re-validate that the assumption still works.
            ProfilePlan::Existing { profile_name } => targets.push(ProbeTarget {
                role_arn: role.role_arn.clone(),
                profile_name,
                disposition: Disposition::Existing,
            }),
            ProfilePlan::Write { profile_name } => {
                claimed.insert(profile_name.clone());
                targets.push(ProbeTarget {
                    role_arn: role.role_arn.clone(),
                    profile_name,
                    disposition: Disposition::Added,
                });
            }
            // Every candidate name vends something else; the entitlement
            // was NOT configured.
            ProfilePlan::NameTaken { profile_name } => {
                tr_println!(
                    "setup-aws-entitlements-name-taken",
                    profile = profile_name.as_str(),
                    role_arn = role.role_arn.as_str()
                );
                *skipped = skipped.saturating_add(1);
            }
        }
    }

    targets
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
) -> Vec<(ProbeTarget, Result<StsCredentials>)> {
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
                let region = aws::resolve_region_with_fallback(&role_arn)?;
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

    let mut results = BTreeMap::new();
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
    probe: &Result<StsCredentials>,
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
        (Disposition::Added, Err(err)) if exit_code::aws_access_denied(err) => {
            tr_println!(
                "setup-aws-entitlements-not-assumable-skipped",
                profile = profile_name,
                role_arn = role_arn
            );
            print_trust_remediation(input, role_arn);
            tr_println!("setup-aws-entitlements-rerun-hint");
            false
        }
        (Disposition::Existing, Err(err)) if exit_code::aws_access_denied(err) => {
            tr_println!(
                "setup-aws-entitlements-existing-trust-missing",
                profile = profile_name,
                role_arn = role_arn
            );
            print_trust_remediation(input, role_arn);
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
fn print_trust_remediation(input: &DiscoveryContext<'_>, target_role_arn: &str) {
    use crate::commands::credential::aws::{
        chained_role_trust_statement, management_role_policy_statement, source_identity_pattern,
    };

    let statement = chained_role_trust_statement(
        input.management_role,
        &source_identity_pattern(input.role_session_name),
    );
    let policy = management_role_policy_statement(target_role_arn);
    tr_println!(
        "setup-aws-entitlements-trust-remediation",
        management_role = input.management_role,
        statement = statement.as_str(),
        policy = policy.as_str()
    );
}

/// How the existing-profile sweep should handle one `--role` (optionally
/// `--via`) profile, given the management role the current discover run holds
/// a session for (`management_role`) and the org config (`vouch_config`) that
/// vending resolves against.
///
/// This replaces the older `via.is_some_and(|via| via != ctx.management_role)`
/// skip filter, which was vacuous for `via == None`: in a multi-org config a
/// `via == None` profile's vend-time hop is decided by account disambiguation
/// inside [`crate::commands::credential::aws::resolve_management_role_for`],
/// which may resolve to a *different* org's management role (or to a direct
/// `AssumeRoleWithWebIdentity`). Probing such a profile through the discover
/// run's session is a *different* hop than vending performs, so a target that
/// trusts its own org's management role (or the IdP directly) but not the
/// discover run's management role is mis-reported as trust-missing, and an
/// unresolvable target may be mis-reported as verified.
///
/// The decision mirrors the hop vending selects — the same call the vend path
/// makes — so the sweep only probes when its session is the same principal
/// vending chains through.
#[derive(Debug, PartialEq, Eq)]
enum SweepDecision {
    /// The target *is* `management_role` and vending assumes it directly
    /// (`AssumeRoleWithWebIdentity`), which is exactly the hop the discover
    /// run used to obtain the session in hand. Report verified without a
    /// probe — a true positive regardless of org count.
    TriviallyAssumable,
    /// Vending chains `AssumeRole(management_role → target)`, and the sweep
    /// holds `management_role`'s session. The probe matches vending's hop.
    Probe,
    /// Vending resolves the target through a different hop than the sweep's
    /// session — a *different* org's management role, or a direct
    /// `AssumeRoleWithWebIdentity` into a role the sweep cannot reach with its
    /// SigV4 session. The sweep has no matching session; skip without claiming
    /// anything. Identical to the pre-existing skip for `via == Some(other)`
    /// pinned profiles.
    Skip,
    /// Vending cannot resolve the target under the current config at all (no
    /// org covers the account, or it is ambiguous across orgs). The profile is
    /// genuinely broken — surface a distinct diagnostic instead of probing
    /// (which would report a false trust-missing with a useless remediation,
    /// or a false verified) or silently dropping it.
    Unresolved,
}

/// Decide whether the existing-profile sweep should probe one role-carrying
/// profile through the discover run's management session. Pure wrapper over
/// [`crate::commands::credential::aws::resolve_management_role_for`]; see
/// [`SweepDecision`] for the decision semantics.
///
/// `management_role` is the ARN the current discover run assumed (and holds a
/// session for), i.e. [`DiscoveryContext::management_role`]. Resolution is
/// performed against `vouch_config` exactly as vending performs it, so the
/// sweep's hop and vending's hop agree whenever [`SweepDecision::Probe`] is
/// returned.
fn sweep_decision_for_role(
    vouch_config: &Config,
    role_arn: &str,
    via: Option<&str>,
    management_role: &str,
) -> SweepDecision {
    use crate::commands::credential::aws::resolve_management_role_for;
    match resolve_management_role_for(vouch_config, role_arn, via) {
        // Vending chains through management_role — the sweep holds that
        // session, so the probe matches vending's hop.
        Ok(Some(m)) if m == management_role => SweepDecision::Probe,
        // Vending assumes the target directly via AssumeRoleWithWebIdentity.
        // This only happens when the target IS some org's management role and
        // equals it. When that role is the discover run's management role, the
        // session in hand already proves it is assumable (the discover run
        // assumed it via that same direct hop) — trivially assumable. When it
        // is a *different* org's management role, the sweep holds no session
        // for it, so the sweep cannot replicate the hop → falls through to
        // Skip below (the `role_arn == management_role` guard selects only the
        // this-run case here).
        Ok(None) if role_arn == management_role => SweepDecision::TriviallyAssumable,
        // Different org's chain, or a direct AssumeRoleWithWebIdentity into a
        // role the sweep holds no session for — the sweep cannot replicate
        // vending's hop. Skip without claiming anything.
        Ok(_) => SweepDecision::Skip,
        // No org covers the account, or it is ambiguous across orgs — vending
        // itself fails here, so the profile is genuinely broken.
        Err(_) => SweepDecision::Unresolved,
    }
}

/// The existing-profile sweep's action for one `--role` (optionally `--via`)
/// profile: which (if any) diagnostic to emit, whether to count it, and
/// whether to probe it. Produced by [`plan_role_sweep`] from the profile's
/// `role_arn`/`via`, the live org config, the discover run's management
/// role, and the probe-dedup set.
///
/// Distinct from [`SweepDecision`] (the pure classification) because this
/// folds in the probe-dedup gate, which suppresses ONLY re-probing. The
/// [`RoleSweepAction::Verified`] and [`RoleSweepAction::Unresolved`]
/// diagnostics are emitted for *every* existing profile, including one whose
/// `role_arn` the entitlement pass probed this run, so a manually-created
/// `--role` profile (via = `None`) is reported on its own `via` rather than
/// silently dropped when AAM listed the same role ARN.
#[derive(Debug, PartialEq, Eq)]
enum RoleSweepAction {
    /// The discover run already holds a session for this role (it assumed the
    /// role directly). Report `setup-aws-entitlements-existing-verified` and
    /// count it checked — no probe needed.
    Verified,
    /// Vending chains through the run's management role and the role was not
    /// already probed this run. Count it checked and probe it through the
    /// run's session — the probe matches vending's hop.
    Probe,
    /// The role was already probed this run (by the entitlement pass, or an
    /// earlier profile in this sweep). Do not re-probe, do not count, do not
    /// print — the earlier probe's report already covered this `role_arn`.
    /// The non-diagnostic counterpart of [`RoleSweepAction::Skip`], which is
    /// silent where `Skip` emits a `tracing::debug`.
    AlreadyProbed,
    /// Vending resolves the target through a different hop than the sweep's
    /// session. Skip silently to the user; `tracing::debug` only.
    Skip,
    /// Vending cannot resolve the target under the current config. Print
    /// `setup-aws-existing-unresolved`, count it checked, and count an issue.
    Unresolved,
}

/// Plan the existing-profile sweep's action for one role-carrying profile,
/// applying the probe-dedup gate ONLY to the probe path.
///
/// `seen` is the probe-dedup set, seeded with the entitlement pass's `probed`
/// role ARNs before the sweep loop; [`plan_role_sweep`] inserts each probed
/// `role_arn` into it. The dedup suppresses ONLY [`RoleSweepAction::Probe`]
/// — re-probing a role the entitlement pass just probed is redundant (it
/// already produced a CloudTrail `AssumeRole` event and a verified/denial
/// line). The non-probe arms ([`RoleSweepAction::Verified`] and
/// [`RoleSweepAction::Unresolved`]) run for *every* existing profile, so a
/// manual `--role` profile (via = `None`) is still classified and reported
/// even when the entitlement pass probed the same `role_arn` (under a
/// different `--via`) this run. Gating them too would suppress the
/// `setup-aws-existing-unresolved` diagnostic for a genuinely broken manual
/// profile whose `role_arn` AAM also listed.
fn plan_role_sweep(
    vouch_config: &Config,
    role_arn: &str,
    via: Option<&str>,
    management_role: &str,
    seen: &mut BTreeSet<String>,
) -> RoleSweepAction {
    match sweep_decision_for_role(vouch_config, role_arn, via, management_role) {
        SweepDecision::TriviallyAssumable => RoleSweepAction::Verified,
        SweepDecision::Probe => {
            if seen.insert(role_arn.to_string()) {
                RoleSweepAction::Probe
            } else {
                RoleSweepAction::AlreadyProbed
            }
        }
        SweepDecision::Skip => RoleSweepAction::Skip,
        SweepDecision::Unresolved => RoleSweepAction::Unresolved,
    }
}

/// Health-check every Vouch-managed profile that discovery did not already
/// touch this run: role-carrying profiles are probed through the management
/// session *only when that session is the same principal vending chains
/// through* (decided by [`sweep_decision_for_role`], which mirrors
/// [`crate::commands::credential::aws::resolve_management_role_for`]);
/// otherwise they are skipped (different chain) or surfaced as unresolved.
/// Identity Center profiles are checked against the assignments the portal
/// returned. Report-only — nothing is written or removed.
async fn validate_existing_profiles(
    ctx: &DiscoveryContext<'_>,
    vouch_config: &Config,
    aws_config: &AwsConfig,
    assignments: &BTreeSet<(String, String)>,
    probed: &BTreeSet<String>,
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
                // Classify first, then let `plan_role_sweep` apply the
                // probe-dedup gate (`seen`, seeded with the entitlement pass's
                // `probed` role ARNs) ONLY to the probe path. Non-probe
                // diagnostics (Verified/Unresolved) run for every existing
                // profile, so a manual `--role` profile whose `role_arn` AAM
                // also probed is still reported on its own `via` — the gate
                // never suppresses a `setup-aws-existing-unresolved` line.
                match plan_role_sweep(
                    vouch_config,
                    &role_arn,
                    via.as_deref(),
                    ctx.management_role,
                    &mut seen,
                ) {
                    RoleSweepAction::Verified => {
                        // The session in hand IS this role — the discover run
                        // assumed it via the same direct
                        // AssumeRoleWithWebIdentity hop vending uses for a
                        // target that is its own management role.
                        checked = checked.saturating_add(1);
                        tr_println!(
                            "setup-aws-entitlements-existing-verified",
                            profile = profile.name.as_str(),
                            role_arn = role_arn.as_str()
                        );
                    }
                    RoleSweepAction::Probe => {
                        // Vending chains through ctx.management_role, which
                        // is the session the sweep holds — probe matches
                        // vending's hop. The dedup gate already confirmed this
                        // role was not probed this run.
                        checked = checked.saturating_add(1);
                        targets.push(ProbeTarget {
                            role_arn,
                            profile_name: profile.name,
                            disposition: Disposition::Existing,
                        });
                    }
                    RoleSweepAction::AlreadyProbed => {
                        // The entitlement pass (or an earlier profile in this
                        // sweep) already probed this `role_arn` and reported
                        // its outcome; re-probing is redundant.
                    }
                    RoleSweepAction::Skip => {
                        // Vending resolves the target through a different hop
                        // than the sweep's session. The sweep has no matching
                        // session; claim nothing and skip.
                        tracing::debug!(
                            "sweep skipped {}: vending resolves it through \
                             a different hop than this run's management role",
                            profile.name,
                        );
                    }
                    RoleSweepAction::Unresolved => {
                        // Vending cannot resolve this target under the current
                        // config either — the profile is genuinely broken.
                        // Surface a distinct diagnostic; do not probe (the
                        // wrong session would report a false trust-missing
                        // with a useless remediation, or a false verified)
                        // and do not silently drop it.
                        checked = checked.saturating_add(1);
                        issues = issues.saturating_add(1);
                        tr_println!(
                            "setup-aws-existing-unresolved",
                            profile = profile.name.as_str(),
                            role_arn = role_arn.as_str(),
                        );
                    }
                }
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
fn resolve_identity_store(instances: &[SsoInstance], application_arn: &str) -> Option<String> {
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

/// Validate an entitled role and derive its preferred profile name, the
/// first of the candidates [`plan_profile`] tries.
///
/// AWS-returned values are interpolated into `credential_process` lines, so
/// the role ARN must parse as an IAM role, the account must be 12 ASCII
/// digits, and the two must agree; anything else is rejected. Naming
/// follows the permission-set scheme: `{prefix|vouch}-{account}-{role}`,
/// falling back to the account ID when the account name sanitizes away.
fn entitled_role_profile_name(role: &EntitledRole, profile_prefix: Option<&str>) -> Option<String> {
    let arn = sts::parse_role_arn(&role.role_arn).ok()?;
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "test code: panic on assertion failure is acceptable"
)]
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

        let credential_process = CredentialProcessLine::IdentityCenter {
            application_arn: Some(
                "arn:aws:sso::123456789012:application/ssoins-abc/apl-xyz".to_string(),
            ),
            account: "111111111111".to_string(),
            permission_set: "ReadOnly".to_string(),
        }
        .render(vouch_path);

        assert_eq!(
            credential_process,
            "\"/usr/local/bin/vouch\" credential aws \
             --idc-application arn:aws:sso::123456789012:application/ssoins-abc/apl-xyz \
             --account 111111111111 --permission-set ReadOnly"
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

    // -- sweep_decision_for_role ------------------------------------------------
    //
    // The existing-profile sweep's per-profile gate. It must mirror the hop
    // `credential::aws::resolve_management_role_for` selects at vend time, so
    // the sweep only probes when its discover-run session is the same principal
    // vending chains through. Regression coverage for the bug where a
    // `via == None` profile in a multi-org config resolves (via account
    // disambiguation) to a *different* org's management role than the discover
    // run's, so probing through the discover-run session is a different hop
    // than vending performs.

    /// Fixture matching the one in `credential::aws` tests: a `Config` with the
    /// given management-role ARNs as organizations (no IdC).
    fn make_sweep_config(management_roles: &[&str]) -> Config {
        let mut cfg = Config::default();
        for mgmt in management_roles {
            cfg.append_aws_org(AwsOrganization {
                management_role: (*mgmt).to_string(),
                identity_center: None,
            });
        }
        cfg
    }

    /// Single org, `via == None`, target IS the management role -> direct
    /// `AssumeRoleWithWebIdentity`, which is the hop the discover run used; the
    /// session in hand already proves assumability. Must be TriviallyAssumable
    /// (the resolver's `Ok(None)` for the same-ARN case), not Skip.
    #[test]
    fn sweep_trivially_assumable_single_org_target_is_management_role() {
        let mgmt = "arn:aws:iam::111:role/Mgmt";
        let cfg = make_sweep_config(&[mgmt]);
        assert_eq!(
            sweep_decision_for_role(&cfg, mgmt, None, mgmt),
            SweepDecision::TriviallyAssumable,
        );
    }

    /// Multi-org, `via == None`, target IS the discover run's management role
    /// (account disambiguation picks the run's org -> direct assume). Still
    /// TriviallyAssumable, not Skip.
    #[test]
    fn sweep_trivially_assumable_multi_org_target_is_run_management_role() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::222:role/MgmtB";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        assert_eq!(
            sweep_decision_for_role(&cfg, mgmt_a, None, mgmt_a),
            SweepDecision::TriviallyAssumable,
        );
    }

    /// Multi-org, target IS the run's management role, but pinned `--via` a
    /// *different* org's management role -> vending chains `AssumeRole(other ->
    /// run-mgmt)`, a hop the sweep's session cannot represent. Must Skip — NOT
    /// TriviallyAssumable (the `role_arn == management_role` trivially-assumable
    /// branch is gated on vending going direct, i.e. `Ok(None)`). This pins the
    /// regression guard: a naive "short-circuit when role_arn == mgmt before
    /// resolving" would falsely report verified here.
    #[test]
    fn sweep_skips_when_target_is_run_mgmt_but_via_pinned_to_other_org() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::222:role/MgmtB";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        assert_eq!(
            sweep_decision_for_role(&cfg, mgmt_a, Some(mgmt_b), mgmt_a),
            SweepDecision::Skip,
        );
    }

    /// Single org, `via == None`, target differs from the management role ->
    /// standard cross-account chain `AssumeRole(mgmt -> target)`, the same hop
    /// the sweep probes. Preserve the original probe behavior (true positive).
    #[test]
    fn sweep_probe_single_org_cross_account() {
        let mgmt = "arn:aws:iam::111:role/Mgmt";
        let target = "arn:aws:iam::222:role/Target";
        let cfg = make_sweep_config(&[mgmt]);
        assert_eq!(
            sweep_decision_for_role(&cfg, target, None, mgmt),
            SweepDecision::Probe,
        );
    }

    /// Single org, `via == Some(run_mgmt)`, target differs -> probe (matches
    /// the original `via == Some(ctx.mgmt)` fall-through).
    #[test]
    fn sweep_probe_single_org_via_pinned_to_run_mgmt() {
        let mgmt = "arn:aws:iam::111:role/Mgmt";
        let target = "arn:aws:iam::222:role/Target";
        let cfg = make_sweep_config(&[mgmt]);
        assert_eq!(
            sweep_decision_for_role(&cfg, target, Some(mgmt), mgmt),
            SweepDecision::Probe,
        );
    }

    /// Multi-org, `via == None`, target is a member role in the discover run's
    /// *own* account -> account disambiguation picks the run's org, chain
    /// through run-mgmt. Probe (true positive preserved — same-account
    /// cross-role is a true negative the fix must not mask).
    #[test]
    fn sweep_probe_multi_org_target_in_run_org_account() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::222:role/MgmtB";
        // Target in account 111 (the run's account) but a different role.
        let target = "arn:aws:iam::111:role/Member";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        assert_eq!(
            sweep_decision_for_role(&cfg, target, None, mgmt_a),
            SweepDecision::Probe,
        );
    }

    /// Multi-org, `via == Some(run_mgmt)`, target IS the run's management role
    /// -> vending goes direct (`AssumeRoleWithWebIdentity`), the hop the
    /// discover run used. TriviallyAssumable.
    #[test]
    fn sweep_trivially_assumable_multi_org_via_run_mgmt_target_is_run_mgmt() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::222:role/MgmtB";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        assert_eq!(
            sweep_decision_for_role(&cfg, mgmt_a, Some(mgmt_a), mgmt_a),
            SweepDecision::TriviallyAssumable,
        );
    }

    /// BUG Class A (working profile misreported): multi-org, `via == None`,
    /// target account matches a *different* org's management account (but
    /// target != that org's management role). Vending chains through the other
    /// org's management role, but the sweep holds the run's session. Before the
    /// fix this probed through the wrong session and reported a false
    /// `existing-trust-missing`. Must Skip.
    #[test]
    fn sweep_skip_multi_org_target_resolves_to_other_org_chain() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::999:role/MgmtB";
        // Target in account 999 -> disambiguation picks org B; MgmtB != target
        // -> chain through MgmtB, which is not the discover run's management
        // role.
        let target = "arn:aws:iam::999:role/ProdRole";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        assert_eq!(
            sweep_decision_for_role(&cfg, target, None, mgmt_a),
            SweepDecision::Skip,
        );
    }

    /// Multi-org, `via == None`, target IS a *different* org's management role
    /// -> vending assumes it directly via `AssumeRoleWithWebIdentity`, a hop
    /// the sweep cannot replicate with a SigV4 session for the run's role. Must
    /// Skip (was misreported before the fix).
    #[test]
    fn sweep_skip_multi_org_target_is_other_org_management_role() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::999:role/MgmtB";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        assert_eq!(
            sweep_decision_for_role(&cfg, mgmt_b, None, mgmt_a),
            SweepDecision::Skip,
        );
    }

    /// Multi-org, `via == Some(other_mgmt)`, target != other_mgmt -> pinned to
    /// a different org's chain. The original `via.is_some_and` skip handled
    /// this; the fix must preserve it.
    #[test]
    fn sweep_skip_multi_org_via_pinned_to_other_org() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::222:role/MgmtB";
        let target = "arn:aws:iam::222:role/Member";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        assert_eq!(
            sweep_decision_for_role(&cfg, target, Some(mgmt_b), mgmt_a),
            SweepDecision::Skip,
        );
    }

    /// Multi-org, `via == Some(other_mgmt)`, target IS other_mgmt -> vending
    /// assumes that management role directly; the sweep cannot reach it. Skip
    /// (preserves the original `via` skip for this sub-case too).
    #[test]
    fn sweep_skip_multi_org_via_pinned_to_other_org_target_is_that_mgmt() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::222:role/MgmtB";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        assert_eq!(
            sweep_decision_for_role(&cfg, mgmt_b, Some(mgmt_b), mgmt_a),
            SweepDecision::Skip,
        );
    }

    /// BUG Class B (broken profile misreported): multi-org, `via == None`,
    /// target account covered by NO configured org. Vending fails at
    /// `resolve_management_role_for` (`aws-err-no-org-covers-account`); the
    /// sweep must surface Unresolved, not probe (which would report a false
    /// trust-missing for a target that does not trust the run's mgmt, or a
    /// false verified for one that happens to).
    #[test]
    fn sweep_unresolved_multi_org_no_org_covers_account() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::222:role/MgmtB";
        // Account 888 is covered by neither org.
        let target = "arn:aws:iam::888:role/OrphanRole";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        assert_eq!(
            sweep_decision_for_role(&cfg, target, None, mgmt_a),
            SweepDecision::Unresolved,
        );
    }

    /// BUG Class B (ambiguous): multi-org, two orgs in the SAME account, target
    /// in that account with `via == None` -> true ambiguity. Vending fails
    /// (`aws-err-via-ambiguous`); the sweep must surface Unresolved.
    #[test]
    fn sweep_unresolved_multi_org_account_ambiguous() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::111:role/MgmtB";
        let target = "arn:aws:iam::111:role/Target";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        assert_eq!(
            sweep_decision_for_role(&cfg, target, None, mgmt_a),
            SweepDecision::Unresolved,
        );
    }

    /// `via == Some(unknown_mgmt)` (no org matches) is an unresolved
    /// configuration error too — vending fails at `aws-err-via-not-found`. The
    /// sweep surfaces it rather than probing with a session for the run's mgmt.
    #[test]
    fn sweep_unresolved_via_pinned_to_unknown_management_role() {
        let mgmt = "arn:aws:iam::111:role/Mgmt";
        let target = "arn:aws:iam::222:role/Target";
        let cfg = make_sweep_config(&[mgmt]);
        assert_eq!(
            sweep_decision_for_role(&cfg, target, Some("arn:aws:iam::999:role/Unknown"), mgmt),
            SweepDecision::Unresolved,
        );
    }

    // -- plan_role_sweep -------------------------------------------------------
    //
    // `validate_existing_profiles`'s per-profile gate. The probe-dedup set
    // (`seen`, seeded with the entitlement pass's `probed` role ARNs) must
    // suppress ONLY re-probing; the `Unresolved` (broken manual profile) and
    // `Verified` diagnostics must still run for every existing profile, even
    // one whose `role_arn` the entitlement pass probed this run. Regression
    // coverage for the bug where `seen = probed.clone()` plus a `seen.insert`
    // gate *before* classification silently dropped the
    // `setup-aws-existing-unresolved` line for a manual `--role` profile when
    // AAM listed the same `role_arn` as an entitlement.

    /// The headline bug: a manual `--role` profile (via = None) in a multi-org
    /// config whose account no org covers classifies `Unresolved`. The fix must
    /// surface `Unresolved` even when the entitlement pass already probed the
    /// same `role_arn` (inserted it into `seen`). Before the fix, the
    /// `seen.insert` gate fired before classification and suppressed this.
    #[test]
    fn plan_role_sweep_unresolved_not_suppressed_when_role_probed() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::222:role/MgmtB";
        // Account 888 is covered by neither org.
        let orphan = "arn:aws:iam::888:role/OrphanRole";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        // `seen` seeded as if the entitlement pass probed `orphan` this run.
        let mut seen: BTreeSet<String> = BTreeSet::from([orphan.to_string()]);
        assert_eq!(
            plan_role_sweep(&cfg, orphan, None, mgmt_a, &mut seen),
            RoleSweepAction::Unresolved,
        );
    }

    /// The fix keeps probe suppression: an entitlement profile pinned `--via`
    /// the run's management role classifies `Probe`, but when the entitlement
    /// pass already probed the same `role_arn`, re-probing is redundant —
    /// `AlreadyProbed`, not `Probe`. Preserves `probed`'s stated purpose
    /// ("the existing-profile sweep does not probe them again").
    #[test]
    fn plan_role_sweep_probe_suppressed_when_role_probed() {
        let mgmt = "arn:aws:iam::111:role/Mgmt";
        let target = "arn:aws:iam::222:role/Target";
        let cfg = make_sweep_config(&[mgmt]);
        let mut seen: BTreeSet<String> = BTreeSet::from([target.to_string()]);
        assert_eq!(
            plan_role_sweep(&cfg, target, Some(mgmt), mgmt, &mut seen),
            RoleSweepAction::AlreadyProbed,
        );
    }

    /// A role NOT already probed this run (`seen` empty) classifies `Probe`
    /// normally, and `plan_role_sweep` records it so a later profile with the
    /// same `role_arn` is deduped within the sweep.
    #[test]
    fn plan_role_sweep_probe_when_not_yet_probed_dedups_within_sweep() {
        let mgmt = "arn:aws:iam::111:role/Mgmt";
        let target = "arn:aws:iam::222:role/Target";
        let cfg = make_sweep_config(&[mgmt]);
        let mut seen = BTreeSet::new();
        assert_eq!(
            plan_role_sweep(&cfg, target, Some(mgmt), mgmt, &mut seen),
            RoleSweepAction::Probe,
        );
        // Within-sweep dedup: a second profile for the same role_arn does
        // not re-probe.
        assert_eq!(
            plan_role_sweep(&cfg, target, Some(mgmt), mgmt, &mut seen),
            RoleSweepAction::AlreadyProbed,
        );
    }

    /// `TriviallyAssumable` (the role IS the run's management role; the
    /// discover run already assumed it) is not a probe, so the dedup must not
    /// suppress it — the manual profile is still reported `Verified` even when
    /// the entitlement pass probed the same `role_arn`.
    #[test]
    fn plan_role_sweep_verified_not_suppressed_when_role_probed() {
        let mgmt = "arn:aws:iam::111:role/Mgmt";
        let cfg = make_sweep_config(&[mgmt]);
        let mut seen: BTreeSet<String> = BTreeSet::from([mgmt.to_string()]);
        assert_eq!(
            plan_role_sweep(&cfg, mgmt, None, mgmt, &mut seen),
            RoleSweepAction::Verified,
        );
    }

    /// A profile vending through a *different* hop (another org's chain)
    /// classifies `Skip`, which emits a `tracing::debug` — distinct from
    /// `AlreadyProbed` (silently dropped dedup). The dedup must not conflate
    /// the two, even when `role_arn` was probed this run.
    #[test]
    fn plan_role_sweep_skip_not_conflated_with_already_probed() {
        let mgmt_a = "arn:aws:iam::111:role/MgmtA";
        let mgmt_b = "arn:aws:iam::999:role/MgmtB";
        // Member role in account 999 -> disambiguation picks org B; MgmtB !=
        // target -> chain through MgmtB, which is not the run's mgmt -> Skip.
        let target = "arn:aws:iam::999:role/ProdRole";
        let cfg = make_sweep_config(&[mgmt_a, mgmt_b]);
        let mut seen: BTreeSet<String> = BTreeSet::from([target.to_string()]);
        assert_eq!(
            plan_role_sweep(&cfg, target, None, mgmt_a, &mut seen),
            RoleSweepAction::Skip,
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

    fn instance(arn: &str, store: &str) -> SsoInstance {
        SsoInstance {
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

    fn entitled(role_arn: &str, account: &str, account_name: Option<&str>) -> EntitledRole {
        EntitledRole {
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

    // -- config_parent_dir --
    //
    // `AWS_CONFIG_FILE` names the file itself and may live anywhere. The
    // directory to create/secure must be derived from the *resolved* config
    // path, not hardcoded to `~/.aws`. These tests cover the pure helper in
    // isolation; the env-reading `AwsConfig::default_path` / `config_path_from`
    // pair is covered in `integrations/aws/config.rs` (see
    // `aws_config_env_is_the_file_itself`, `aws_config_env_does_not_need_home`).

    /// Default `~/.aws/config` → parent is `~/.aws` (backward-compatible).
    #[test]
    fn config_parent_dir_resolves_default_home_aws() {
        let path = std::path::Path::new("/home/alice/.aws/config");
        assert_eq!(
            config_parent_dir(path),
            Some(std::path::Path::new("/home/alice/.aws"))
        );
    }

    /// `AWS_CONFIG_FILE` override → parent is the override's directory, not
    /// `~/.aws`.
    #[test]
    fn config_parent_dir_resolves_override_parent() {
        let path = std::path::Path::new("/etc/aws/alt.ini");
        assert_eq!(
            config_parent_dir(path),
            Some(std::path::Path::new("/etc/aws"))
        );
    }

    /// A bare relative filename (`AWS_CONFIG_FILE=config`) yields an empty
    /// parent string, which the guard filters to `None` — no directory
    /// creation is attempted (the CWD already exists).
    #[test]
    fn config_parent_dir_bare_filename_is_none() {
        assert_eq!(config_parent_dir(std::path::Path::new("config")), None);
    }

    /// A relative path with a directory (`AWS_CONFIG_FILE=aws/config`)
    /// yields the relative directory as the parent.
    #[test]
    fn config_parent_dir_relative_directory() {
        assert_eq!(
            config_parent_dir(std::path::Path::new("aws/config")),
            Some(std::path::Path::new("aws"))
        );
    }

    /// A root-level file (`AWS_CONFIG_FILE=/config`) has `/` as its parent.
    #[test]
    fn config_parent_dir_root_level_file() {
        assert_eq!(
            config_parent_dir(std::path::Path::new("/config")),
            Some(std::path::Path::new("/"))
        );
    }

    /// Regression for bug report Repro 1: with `AWS_CONFIG_FILE` set to a
    /// writable location, setup must succeed without needing `~/.aws`. The
    /// override parent is created and secured; `~/.aws` is never touched.
    #[cfg(unix)]
    #[test]
    fn override_parent_created_and_secured_without_home_aws() -> anyhow::Result<()> {
        let home = tempfile::tempdir()?;
        let override_parent = home.path().join("alt-aws");
        let config_path = override_parent.join("config");

        let parent = config_parent_dir(&config_path)
            .ok_or_else(|| anyhow::anyhow!("expected Some(parent) for a nested config path"))?;
        ensure_secure_dir(parent)?;

        assert!(override_parent.is_dir());

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&override_parent)?.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "override parent should be secured to 0700"
        );

        // ~/.aws must NOT have been created — the fix derives the directory
        // from config_path.parent(), not from home_dir().join(".aws").
        let home_aws = home.path().join(".aws");
        assert!(
            !home_aws.exists(),
            "~/.aws must not be created when the config path is overridden"
        );
        Ok(())
    }

    /// Default-path regression: without `AWS_CONFIG_FILE`, `config_parent_dir`
    /// returns `~/.aws` and `ensure_secure_dir` creates it at 0700.
    #[cfg(unix)]
    #[test]
    fn default_path_creates_and_secures_home_aws() -> anyhow::Result<()> {
        let home = tempfile::tempdir()?;
        let aws_dir = home.path().join(".aws");
        let config_path = aws_dir.join("config");

        let parent = config_parent_dir(&config_path)
            .ok_or_else(|| anyhow::anyhow!("expected Some(parent) for ~/.aws/config"))?;
        ensure_secure_dir(parent)?;

        assert!(aws_dir.is_dir());

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&aws_dir)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        Ok(())
    }

    /// Regression for bug report Repro 3: with `AWS_CONFIG_FILE` set, an
    /// existing `~/.aws` at mode 0755 (the typical mode after `aws configure`)
    /// must NOT be tightened to 0700. Before the fix, `ensure_secure_dir` was
    /// unconditionally called on `~/.aws` regardless of the override.
    #[cfg(unix)]
    #[test]
    fn override_does_not_tighten_existing_home_aws_mode() -> anyhow::Result<()> {
        let home = tempfile::tempdir()?;

        // Pre-existing ~/.aws at 0755.
        let aws_dir = home.path().join(".aws");
        std::fs::create_dir_all(&aws_dir)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&aws_dir, std::fs::Permissions::from_mode(0o755))?;

        // Override config lives in a different directory.
        let override_parent = home.path().join("alt-aws");
        let config_path = override_parent.join("config");
        let parent = config_parent_dir(&config_path)
            .ok_or_else(|| anyhow::anyhow!("expected Some(parent) for override path"))?;
        ensure_secure_dir(parent)?;

        // ~/.aws mode must be unchanged — the fix secures the override
        // parent, not ~/.aws.
        let mode = std::fs::metadata(&aws_dir)?.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o755,
            "~/.aws mode must not change when the config path is overridden"
        );
        Ok(())
    }

    /// The `AwsConfig::path()` accessor returns the resolved config file
    /// path so the success message can print it instead of a hardcoded
    /// `~/.aws/config`.
    #[test]
    fn aws_config_path_reflects_override_location() {
        let path = std::path::PathBuf::from("/tmp/aws-alt/config");
        let config = super::AwsConfig::empty(path.clone());
        assert_eq!(config.path(), path);
    }

    // -- plan_profile / plan_idc_write / plan_entitled_profiles --------------------
    //
    // Discovery's name-collision handling. The preferred profile name is
    // built from sanitized display names, which are not unique per
    // assignment, so a name-only existence check silently dropped the second
    // colliding assignment while reporting it "verified". These tests cover
    // the shared planner, its Identity Center and entitlement callers, and the
    // IdC write loop driven against an in-memory config.

    use crate::integrations::aws::CredentialProcessLine;

    const IDC_APP_ARN: &str = "arn:aws:sso::123456789012:application/ssoins-abc/apl-xyz";
    const OTHER_IDC_APP_ARN: &str = "arn:aws:sso::123456789012:application/ssoins-abc/apl-other";
    const VOUCH_BIN: &str = "/usr/local/bin/vouch";

    /// Render an Identity Center `credential_process` line, mirroring what
    /// `run_discover` writes.
    fn idc_credential_process(
        application_arn: Option<&str>,
        account: &str,
        permission_set: &str,
    ) -> String {
        CredentialProcessLine::IdentityCenter {
            application_arn: application_arn.map(str::to_string),
            account: account.to_string(),
            permission_set: permission_set.to_string(),
        }
        .render(std::path::Path::new(VOUCH_BIN))
    }

    /// Pre-populate `config` with a profile named `name` vending the given
    /// Identity Center assignment.
    fn seed_idc_profile(
        config: &mut AwsConfig,
        name: &str,
        application_arn: Option<&str>,
        account: &str,
        permission_set: &str,
    ) {
        config.set_profile(&AwsProfile {
            name: name.to_string(),
            credential_process: Some(idc_credential_process(
                application_arn,
                account,
                permission_set,
            )),
            region: None,
            output: Some("json".to_string()),
        });
    }

    /// Mirror of the IdC write loop in `run_discover`, driven against an
    /// in-memory config — the same `plan_idc_write` → `set_profile` →
    /// counter dance, parameterized by the account/permission-set list, so
    /// the collision scenario is testable without a live Identity Center
    /// portal.
    fn drive_idc_loop(
        config: &mut AwsConfig,
        profile_prefix: Option<&str>,
        accounts: &[(&str, &str, &str)],
    ) -> (u32, u32) {
        let mut created: u32 = 0;
        let mut skipped: u32 = 0;
        for &(account_id, account_name, permission_set) in accounts {
            let safe_name = sanitize_profile_name(account_name);
            let name_part = if safe_name.is_empty() {
                account_id.to_string()
            } else {
                safe_name
            };
            let safe_ps = sanitize_profile_name(permission_set);
            let base_name = match profile_prefix {
                Some(prefix) => format!("{prefix}-{name_part}-{safe_ps}"),
                None => format!("vouch-{name_part}-{safe_ps}"),
            };
            match plan_idc_write(config, &base_name, account_id, permission_set, IDC_APP_ARN) {
                ProfilePlan::Existing { .. } | ProfilePlan::NameTaken { .. } => {
                    skipped = skipped.saturating_add(1);
                }
                ProfilePlan::Write { profile_name } => {
                    config.set_profile(&AwsProfile {
                        name: profile_name.clone(),
                        credential_process: Some(idc_credential_process(
                            Some(IDC_APP_ARN),
                            account_id,
                            permission_set,
                        )),
                        region: None,
                        output: Some("json".to_string()),
                    });
                    created = created.saturating_add(1);
                }
            }
        }
        (created, skipped)
    }

    /// Parse an existing profile's `credential_process` as an IdC line and
    /// return the account it vends. Returns `Err` (not a panic) so callers in
    /// `Result`-returning tests can surface fixture misconfiguration through
    /// the workspace's `?` + `panic_in_result_fn` convention.
    fn vended_idc_account(config: &AwsConfig, profile_name: &str) -> anyhow::Result<String> {
        let profile = config
            .get_profile(profile_name)
            .ok_or_else(|| anyhow::anyhow!("profile {profile_name} should exist"))?;
        let cp = profile.credential_process.as_deref().ok_or_else(|| {
            anyhow::anyhow!("profile {profile_name} should have a credential_process")
        })?;
        match CredentialProcessLine::parse(cp) {
            Some(CredentialProcessLine::IdentityCenter { account, .. }) => Ok(account),
            other => anyhow::bail!("profile {profile_name} should be IdC, got {other:?}"),
        }
    }

    // -- plan_idc_write: pure collision resolution ---------------------------------

    #[test]
    fn plan_idc_write_empty_config_writes_base_name() {
        let config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "111111111111",
                "ReadOnly",
                IDC_APP_ARN
            ),
            ProfilePlan::Write {
                profile_name: "vouch-sandbox-readonly".to_string()
            }
        );
    }

    /// The same assignment at the preferred name is a genuine re-run, not a
    /// collision — the existing profile really vends this account. Pre-fix
    /// this path *also* matched a different account sharing only the name.
    #[test]
    fn plan_idc_write_same_assignment_at_base_is_verified() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-readonly",
            Some(IDC_APP_ARN),
            "111111111111",
            "ReadOnly",
        );
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "111111111111",
                "ReadOnly",
                IDC_APP_ARN
            ),
            ProfilePlan::Existing {
                profile_name: "vouch-sandbox-readonly".to_string()
            }
        );
    }

    /// The headline bug: two accounts whose display names slugify to the
    /// same value. The second assignment must be disambiguated by its
    /// account ID and written, NOT silently dropped as "verified".
    #[test]
    fn plan_idc_write_foreign_collision_writes_disambiguated() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-readonly",
            Some(IDC_APP_ARN),
            "111111111111",
            "ReadOnly",
        );
        // A different account ID sharing the name → foreign → disambiguate.
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "222222222222",
                "ReadOnly",
                IDC_APP_ARN
            ),
            ProfilePlan::Write {
                profile_name: "vouch-sandbox-readonly-222222222222".to_string()
            }
        );
    }

    /// An STS `--role` profile occupying the name is a foreign collision
    /// (different mechanism) → disambiguate, never overwrite the role profile.
    #[test]
    fn plan_idc_write_foreign_collision_with_sts_role_writes_disambiguated() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        config.set_profile(&AwsProfile {
            name: "vouch-sandbox-readonly".to_string(),
            credential_process: Some(format!(
                "\"{VOUCH_BIN}\" credential aws --role arn:aws:iam::111111111111:role/Other"
            )),
            region: None,
            output: None,
        });
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "222222222222",
                "ReadOnly",
                IDC_APP_ARN
            ),
            ProfilePlan::Write {
                profile_name: "vouch-sandbox-readonly-222222222222".to_string()
            }
        );
    }

    /// A hand-written profile with no `credential_process` is a foreign
    /// collision → disambiguate, never overwrite the operator's profile.
    #[test]
    fn plan_idc_write_foreign_collision_with_unmanaged_profile_writes_disambiguated() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        config.set_profile(&AwsProfile {
            name: "vouch-sandbox-readonly".to_string(),
            credential_process: None,
            region: Some("us-east-1".to_string()),
            output: None,
        });
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "222222222222",
                "ReadOnly",
                IDC_APP_ARN
            ),
            ProfilePlan::Write {
                profile_name: "vouch-sandbox-readonly-222222222222".to_string()
            }
        );
    }

    /// A different permission set on the same account is a distinct
    /// assignment → disambiguate, not "verified". (Two permission sets on
    /// one account must each get their own profile.)
    #[test]
    fn plan_idc_write_different_permission_set_is_foreign() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-readonly",
            Some(IDC_APP_ARN),
            "111111111111",
            "ReadOnly",
        );
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "111111111111",
                "AdministratorAccess",
                IDC_APP_ARN
            ),
            ProfilePlan::Write {
                profile_name: "vouch-sandbox-readonly-111111111111".to_string()
            }
        );
    }

    /// Re-running discovery over a config where the colliding account was
    /// *already* disambiguated by a prior run must re-detect it at the
    /// suffixed name as a verified re-run, not a fresh write or a taken name.
    /// This is the idempotent re-run guarantee for the previously-colliding
    /// account: a second `--discover` does not duplicate or drop it.
    #[test]
    fn plan_idc_write_same_assignment_at_disambiguated_is_verified() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        // Base name held by a different account (foreign collision)…
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-readonly",
            Some(IDC_APP_ARN),
            "111111111111",
            "ReadOnly",
        );
        // …and this account's profile already written at the suffixed name.
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-readonly-222222222222",
            Some(IDC_APP_ARN),
            "222222222222",
            "ReadOnly",
        );
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "222222222222",
                "ReadOnly",
                IDC_APP_ARN
            ),
            ProfilePlan::Existing {
                profile_name: "vouch-sandbox-readonly-222222222222".to_string()
            }
        );
    }

    /// A profile pinned to a *different* IdC application vends a different
    /// IAM role even when the account and permission-set name match, so it
    /// is a foreign collision and must not be treated as this run's re-run.
    #[test]
    fn plan_idc_write_foreign_application_arn_is_foreign() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-readonly",
            Some(OTHER_IDC_APP_ARN),
            "111111111111",
            "ReadOnly",
        );
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "111111111111",
                "ReadOnly",
                IDC_APP_ARN
            ),
            ProfilePlan::Write {
                profile_name: "vouch-sandbox-readonly-111111111111".to_string()
            }
        );
    }

    /// A legacy IdC profile with no `--idc-application` resolves to the
    /// configured org at vend time, so a matching account + permission set
    /// is a genuine re-run (Verified), not a foreign collision.
    #[test]
    fn plan_idc_write_legacy_profile_without_app_is_verified_when_assignment_matches() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-readonly",
            None,
            "111111111111",
            "ReadOnly",
        );
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "111111111111",
                "ReadOnly",
                IDC_APP_ARN
            ),
            ProfilePlan::Existing {
                profile_name: "vouch-sandbox-readonly".to_string()
            }
        );
    }

    /// An STS `--role` profile at `name` targeting `role_arn`.
    fn seed_role_profile(config: &mut AwsConfig, name: &str, role_arn: &str) {
        config.set_profile(&AwsProfile {
            name: name.to_string(),
            credential_process: Some(format!("\"{VOUCH_BIN}\" credential aws --role {role_arn}")),
            region: None,
            output: None,
        });
    }

    /// When the preferred and account-suffixed names are both held by
    /// foreign profiles, the permission-set-hash name is used.
    #[test]
    fn plan_idc_write_two_candidates_foreign_writes_third() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        seed_role_profile(
            &mut config,
            "vouch-sandbox-readonly",
            "arn:aws:iam::111111111111:role/Other",
        );
        seed_role_profile(
            &mut config,
            "vouch-sandbox-readonly-222222222222",
            "arn:aws:iam::333333333333:role/YetAnother",
        );
        let [.., third] =
            profile_name_candidates("vouch-sandbox-readonly", "222222222222", "ReadOnly");
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "222222222222",
                "ReadOnly",
                IDC_APP_ARN
            ),
            ProfilePlan::Write {
                profile_name: third
            }
        );
    }

    /// All three candidates held by foreign profiles (possible only in a
    /// hand-edited config): nothing is overwritten, and the assignment is
    /// reported as `NameTaken`.
    #[test]
    fn plan_idc_write_all_candidates_foreign_is_name_taken() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        let candidates =
            profile_name_candidates("vouch-sandbox-readonly", "222222222222", "ReadOnly");
        for name in &candidates {
            seed_role_profile(&mut config, name, "arn:aws:iam::111111111111:role/Other");
        }
        let [.., third] = candidates;
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "222222222222",
                "ReadOnly",
                IDC_APP_ARN
            ),
            ProfilePlan::NameTaken {
                profile_name: third
            }
        );
    }

    /// A profile that already vends the assignment is found at a later
    /// candidate even when an earlier one is free again (the preferred-name
    /// profile was deleted), so a re-run does not write a second copy.
    #[test]
    fn plan_idc_write_existing_at_later_candidate_wins_over_free_earlier_one() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-readonly-222222222222",
            Some(IDC_APP_ARN),
            "222222222222",
            "ReadOnly",
        );
        assert_eq!(
            plan_idc_write(
                &config,
                "vouch-sandbox-readonly",
                "222222222222",
                "ReadOnly",
                IDC_APP_ARN
            ),
            ProfilePlan::Existing {
                profile_name: "vouch-sandbox-readonly-222222222222".to_string()
            }
        );
    }

    /// Candidate names are stable: the hash suffix depends only on the raw
    /// value, so re-runs and other machines pick the same names.
    #[test]
    fn profile_name_candidates_are_stable_and_distinct_per_raw_value() {
        let a =
            profile_name_candidates("vouch-sandbox-admin-access", "111111111111", "Admin.Access");
        let b =
            profile_name_candidates("vouch-sandbox-admin-access", "111111111111", "Admin_Access");
        assert_eq!(
            a,
            profile_name_candidates("vouch-sandbox-admin-access", "111111111111", "Admin.Access")
        );
        assert_eq!(a.get(..2), b.get(..2));
        assert_ne!(a.get(2), b.get(2));
        let [_, _, third] = a;
        let suffix = third
            .strip_prefix("vouch-sandbox-admin-access-111111111111-")
            .unwrap_or_default();
        assert_eq!(suffix.len(), 8);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -- end-to-end write loop -----------------------------------------------------

    /// The bug report's scenario, flipped to assert the FIXED behavior: two
    /// accounts whose display names collapse to the same slug (`Sandbox (Dev)`
    /// and `Sandbox-Dev` both → `sandbox-dev`) sharing `ReadOnly` each get
    /// their own profile; the colliding account is disambiguated by its
    /// account ID. Both `created == 2` and the surviving profiles vend their
    /// own account IDs — no assignment is dropped or misreported as verified.
    #[test]
    fn idc_name_collision_writes_both_accounts() -> anyhow::Result<()> {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        let accounts = [
            ("111111111111", "Sandbox (Dev)", "ReadOnly"),
            ("222222222222", "Sandbox-Dev", "ReadOnly"),
        ];

        let (created, skipped) = drive_idc_loop(&mut config, None, &accounts);

        // Both slugify to `vouch-sandbox-dev-readonly`, so without the fix the
        // second account would be dropped. The fix writes both.
        assert_eq!(created, 2);
        assert_eq!(skipped, 0);

        // First account keeps the preferred name; the second is disambiguated.
        assert_eq!(
            vended_idc_account(&config, "vouch-sandbox-dev-readonly")?,
            "111111111111"
        );
        assert_eq!(
            vended_idc_account(&config, "vouch-sandbox-dev-readonly-222222222222")?,
            "222222222222"
        );
        Ok(())
    }

    /// Idempotent re-run: after the first pass writes both profiles (one
    /// preferred, one disambiguated), a second discovery pass over the same
    /// assignments reports both as `Verified` and writes nothing. This proves
    /// the fix does not duplicate profiles or churn the config on re-runs, and
    /// that the previously-colliding account is correctly re-detected at its
    /// suffixed name.
    #[test]
    fn idc_collision_rerun_marks_both_verified() -> anyhow::Result<()> {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        let accounts = [
            ("111111111111", "Sandbox (Dev)", "ReadOnly"),
            ("222222222222", "Sandbox-Dev", "ReadOnly"),
        ];

        let (created1, skipped1) = drive_idc_loop(&mut config, None, &accounts);
        assert_eq!((created1, skipped1), (2, 0));

        let (created2, skipped2) = drive_idc_loop(&mut config, None, &accounts);
        assert_eq!((created2, skipped2), (0, 2));

        // Profiles are unchanged after the second pass.
        assert_eq!(
            vended_idc_account(&config, "vouch-sandbox-dev-readonly")?,
            "111111111111"
        );
        assert_eq!(
            vended_idc_account(&config, "vouch-sandbox-dev-readonly-222222222222")?,
            "222222222222"
        );
        Ok(())
    }

    /// A custom `--profile-prefix` flows through the same collision fix:
    /// `work-sandbox-readonly` and `work-sandbox-readonly-222222222222`.
    #[test]
    fn idc_collision_with_custom_prefix_writes_both() -> anyhow::Result<()> {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        let accounts = [
            ("111111111111", "Sandbox", "ReadOnly"),
            ("222222222222", "Sandbox", "ReadOnly"),
        ];

        let (created, skipped) = drive_idc_loop(&mut config, Some("work"), &accounts);

        assert_eq!(created, 2);
        assert_eq!(skipped, 0);
        assert_eq!(
            vended_idc_account(&config, "work-sandbox-readonly")?,
            "111111111111"
        );
        assert_eq!(
            vended_idc_account(&config, "work-sandbox-readonly-222222222222")?,
            "222222222222"
        );
        Ok(())
    }

    /// A re-run over an already-populated config where the colliding account
    /// was previously disambiguated is the genuinely-silent case the report
    /// calls out: both assignments report `Verified` and nothing is written,
    /// proving the previously-colliding account is never silently dropped or
    /// misreported on a re-run over an existing config.
    #[test]
    fn idc_rerun_over_populated_config_marks_both_verified() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        // Simulate a prior run's result: the first account at the preferred
        // name, the colliding account already at the suffixed name.
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-dev-readonly",
            Some(IDC_APP_ARN),
            "111111111111",
            "ReadOnly",
        );
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-dev-readonly-222222222222",
            Some(IDC_APP_ARN),
            "222222222222",
            "ReadOnly",
        );
        let accounts = [
            ("111111111111", "Sandbox (Dev)", "ReadOnly"),
            ("222222222222", "Sandbox-Dev", "ReadOnly"),
        ];

        let (created, skipped) = drive_idc_loop(&mut config, None, &accounts);

        assert_eq!(created, 0);
        assert_eq!(skipped, 2);
    }

    /// N assignments whose preferred names collide across accounts AND
    /// across permission sets get N distinct profiles, each vending its own
    /// assignment, and an existing profile at the preferred name is never
    /// renamed. `Admin.Access`, `Admin_Access` and `Admin+Access` all slugify
    /// to `admin-access`, and both accounts are named `Sandbox`.
    #[test]
    fn idc_slug_collisions_across_accounts_and_permission_sets_write_all() -> anyhow::Result<()> {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        // A prior run's profile at the preferred name.
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-admin-access",
            Some(IDC_APP_ARN),
            "111111111111",
            "Admin.Access",
        );
        let accounts = [
            ("111111111111", "Sandbox", "Admin.Access"),
            ("111111111111", "Sandbox", "Admin_Access"),
            ("111111111111", "Sandbox", "Admin+Access"),
            ("222222222222", "Sandbox", "Admin.Access"),
            ("222222222222", "Sandbox", "Admin_Access"),
        ];

        let (created, skipped) = drive_idc_loop(&mut config, None, &accounts);
        assert_eq!((created, skipped), (4, 1), "one existing, four written");

        let mut vended = BTreeSet::new();
        for profile in config.find_all_vouch_profiles() {
            if let Some(CredentialProcessLine::IdentityCenter {
                account,
                permission_set,
                ..
            }) = profile
                .credential_process
                .as_deref()
                .and_then(CredentialProcessLine::parse)
            {
                assert!(
                    vended.insert((account, permission_set)),
                    "each assignment is vended by exactly one profile"
                );
            }
        }
        assert_eq!(vended.len(), accounts.len());
        assert_eq!(
            vended_idc_account(&config, "vouch-sandbox-admin-access")?,
            "111111111111",
            "the existing profile keeps the preferred name"
        );

        // A re-run writes nothing and reports every assignment as existing.
        assert_eq!(drive_idc_loop(&mut config, None, &accounts), (0, 5));
        Ok(())
    }

    // -- plan_entitled_profiles ---------------------------------------------------

    /// Entitled roles whose preferred names collide (same account label and
    /// role slug) each get a distinct planned profile instead of the later
    /// ones being dropped as name-taken; a role already configured at its
    /// preferred name stays there; an IdC profile holding a role's preferred
    /// name is not overwritten.
    #[test]
    fn plan_entitled_profiles_gives_colliding_roles_distinct_names() {
        let mut config = AwsConfig::empty(std::path::PathBuf::from("/tmp/x"));
        seed_role_profile(
            &mut config,
            "vouch-sandbox-deploy-role",
            "arn:aws:iam::111111111111:role/Deploy.Role",
        );
        seed_idc_profile(
            &mut config,
            "vouch-sandbox-audit",
            Some(IDC_APP_ARN),
            "111111111111",
            "Audit",
        );
        let roles = [
            entitled(
                "arn:aws:iam::111111111111:role/Deploy.Role",
                "111111111111",
                Some("Sandbox"),
            ),
            entitled(
                "arn:aws:iam::111111111111:role/Deploy_Role",
                "111111111111",
                Some("Sandbox"),
            ),
            entitled(
                "arn:aws:iam::111111111111:role/Deploy+Role",
                "111111111111",
                Some("Sandbox"),
            ),
            entitled(
                "arn:aws:iam::222222222222:role/Deploy.Role",
                "222222222222",
                Some("Sandbox"),
            ),
            entitled(
                "arn:aws:iam::111111111111:role/Audit",
                "111111111111",
                Some("Sandbox"),
            ),
        ];

        let mut skipped = 0;
        let targets = plan_entitled_profiles(roles.iter(), None, &config, &mut skipped);

        assert_eq!(skipped, 0, "no role is dropped");
        assert_eq!(targets.len(), roles.len());
        let names: BTreeSet<&str> = targets.iter().map(|t| t.profile_name.as_str()).collect();
        assert_eq!(names.len(), roles.len(), "every planned name is distinct");
        let first = targets
            .first()
            .map(|t| (t.profile_name.as_str(), t.disposition));
        assert!(matches!(
            first,
            Some(("vouch-sandbox-deploy-role", Disposition::Existing))
        ));
        assert!(
            targets
                .iter()
                .skip(1)
                .all(|t| matches!(t.disposition, Disposition::Added)),
            "the others are new profiles"
        );
        assert!(
            !names.contains("vouch-sandbox-audit"),
            "the IdC profile's name is not reused"
        );
    }
}
