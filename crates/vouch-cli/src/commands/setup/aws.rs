// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS setup command.
//!
//! Configures AWS CLI/SDK to use Vouch for credential federation. Entry
//! point is `run`; call paths:
//!
//! - `--role <arn>`  → `run_explicit_role` (non-interactive; add `--management-role` to chain)
//! - `--discover`    → `run_discover` (non-interactive, re-enumerates an Identity Center management role)
//! - no flags + TTY  → `run_wizard` (interactive; detects existing setup, else pattern-first)

use anyhow::{Context, Result};
use vouch_cli::{tr, tr_args, tr_println};

use crate::install_path::resolve_install_path;
use crate::integrations::aws::{AwsConfig, AwsProfile};
use crate::utils::ensure_secure_dir;

// =========================================================================
// IAM policy generation
// =========================================================================

/// IAM policy generation helpers. All functions are pure — no I/O.
mod policy {
    use serde_json::{Value, json};

    /// Build the OIDC federation trust policy for the given role.
    ///
    /// Allows the Vouch OIDC provider (`issuer_host`) to assume the role via
    /// `sts:AssumeRoleWithWebIdentity`. `sts:TagSession` and
    /// `sts:SetSourceIdentity` are also allowed because Vouch embeds session
    /// tags in the token (`https://aws.amazon.com/tags`) and sets a source
    /// identity — STS rejects the assume without those permissions.
    ///
    /// Conditions:
    /// - `StringEquals { <host>:aud = <issuer_url> }` — audience must be Vouch.
    /// - `StringLike { sts:RoleSessionName = ${<host>:sub} }` — the session name
    ///   must equal the caller's subject (the CLI sets it to the user's `sub`).
    /// - When `subject_pattern` is `Some` (e.g. `*@example.com`), also
    ///   `StringLike { <host>:sub = <subject_pattern> }` to restrict which
    ///   identities may assume the role.
    pub(super) fn trust(
        partition: &str,
        account_id: &str,
        issuer_host: &str,
        issuer_url: &str,
        subject_pattern: Option<&str>,
    ) -> Value {
        let mut string_like = serde_json::Map::new();
        string_like.insert(
            "sts:RoleSessionName".to_string(),
            json!(format!("${{{issuer_host}:sub}}")),
        );
        if let Some(sub) = subject_pattern {
            string_like.insert(format!("{issuer_host}:sub"), json!(sub));
        }
        json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": format!("arn:{partition}:iam::{account_id}:oidc-provider/{issuer_host}")
                },
                "Action": [
                    "sts:AssumeRoleWithWebIdentity",
                    "sts:TagSession",
                    "sts:SetSourceIdentity"
                ],
                "Condition": {
                    "StringEquals": {
                        format!("{issuer_host}:aud"): issuer_url
                    },
                    "StringLike": Value::Object(string_like)
                }
            }]
        })
    }

    /// Build the permission policy for the role-chaining management role.
    ///
    /// Grants `sts:AssumeRole` (plus `sts:TagSession` / `sts:SetSourceIdentity`,
    /// which Vouch's session tags and source identity require) on the
    /// caller-provided `resource` — a wildcard like `arn:aws:iam::*:role/*` by
    /// default, narrowable to specific member roles.
    pub(super) fn chaining(resource: &str) -> Value {
        json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                "Resource": resource
            }]
        })
    }

    /// Build the permission policy for the IAM Identity Center management role.
    ///
    /// Grants `sso-oauth:CreateTokenWithIAM` on the customer-managed application.
    pub(super) fn idc(app_arn: &str) -> Value {
        json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "sso-oauth:CreateTokenWithIAM",
                "Resource": app_arn
            }]
        })
    }

    #[cfg(test)]
    #[expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code: panic on assertion failure is acceptable"
    )]
    mod tests {
        use super::*;

        #[test]
        fn trust_policy_has_correct_principal_and_actions() {
            let p = trust(
                "aws",
                "123456789012",
                "vouch.example.com",
                "https://vouch.example.com",
                None,
            );
            let stmt = &p["Statement"][0];
            assert_eq!(
                stmt["Principal"]["Federated"].as_str().unwrap(),
                "arn:aws:iam::123456789012:oidc-provider/vouch.example.com"
            );
            // AssumeRoleWithWebIdentity plus TagSession/SetSourceIdentity, which
            // Vouch's session tags / source identity require.
            let actions: Vec<&str> = stmt["Action"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect();
            assert_eq!(
                actions,
                [
                    "sts:AssumeRoleWithWebIdentity",
                    "sts:TagSession",
                    "sts:SetSourceIdentity"
                ]
            );
        }

        #[test]
        fn trust_policy_conditions() {
            let p = trust(
                "aws",
                "123456789012",
                "vouch.example.com",
                "https://vouch.example.com",
                Some("*@vouch.example.com"),
            );
            let cond = &p["Statement"][0]["Condition"];
            assert_eq!(
                cond["StringEquals"]["vouch.example.com:aud"]
                    .as_str()
                    .unwrap(),
                "https://vouch.example.com"
            );
            // RoleSessionName is always bound to the subject.
            assert_eq!(
                cond["StringLike"]["sts:RoleSessionName"].as_str().unwrap(),
                "${vouch.example.com:sub}"
            );
            // The subject pattern restricts which identities may assume.
            assert_eq!(
                cond["StringLike"]["vouch.example.com:sub"]
                    .as_str()
                    .unwrap(),
                "*@vouch.example.com"
            );
        }

        #[test]
        fn trust_policy_without_subject_still_binds_session_name() {
            let p = trust(
                "aws",
                "123456789012",
                "vouch.example.com",
                "https://vouch.example.com",
                None,
            );
            let string_like = &p["Statement"][0]["Condition"]["StringLike"];
            assert_eq!(
                string_like["sts:RoleSessionName"].as_str().unwrap(),
                "${vouch.example.com:sub}"
            );
            // No subject filter when the domain is unknown.
            assert!(string_like.get("vouch.example.com:sub").is_none());
        }

        #[test]
        fn chaining_policy_grants_assume_role_on_resource() {
            let p = chaining("arn:aws:iam::*:role/*");
            let stmts = p["Statement"].as_array().unwrap();
            assert_eq!(stmts.len(), 1);
            let actions: Vec<&str> = stmts[0]["Action"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect();
            assert_eq!(
                actions,
                ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]
            );
            assert_eq!(
                stmts[0]["Resource"].as_str().unwrap(),
                "arn:aws:iam::*:role/*"
            );
        }

        #[test]
        fn idc_policy_targets_app_arn() {
            let arn = "arn:aws:sso::123456789012:application/ssoins-abc/apl-xyz";
            let p = idc(arn);
            let stmt = &p["Statement"][0];
            assert_eq!(
                stmt["Action"].as_str().unwrap(),
                "sso-oauth:CreateTokenWithIAM"
            );
            assert_eq!(stmt["Resource"].as_str().unwrap(), arn);
        }
    }
}

// =========================================================================
// Sanitization helpers
// =========================================================================

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

// =========================================================================
// Public entry point
// =========================================================================

/// Run the AWS setup command.
///
/// - `--role <arn>` → single-profile STS setup (non-interactive).
/// - `--discover`   → re-enumerate accounts/roles for the configured session.
/// - neither + TTY  → interactive wizard (role-first).
pub(crate) async fn run(
    server: &str,
    profile: Option<&str>,
    role_arn: Option<&str>,
    management_role: Option<&str>,
    region: Option<&str>,
    discover: bool,
) -> Result<()> {
    if discover {
        return run_discover(server, profile, management_role).await;
    }
    match role_arn {
        Some(role_arn) => run_explicit_role(profile, role_arn, management_role, region),
        None => run_wizard(server, profile, region).await,
    }
}

// =========================================================================
// Scriptable paths
// =========================================================================

/// Write a single STS profile for an explicit role ARN (scriptable,
/// non-interactive). When `management_role` is set, the profile chains through
/// it (`--management-role`) before assuming `role_arn`.
fn run_explicit_role(
    profile: Option<&str>,
    role_arn: &str,
    management_role: Option<&str>,
    region: Option<&str>,
) -> Result<()> {
    let vouch_path = resolve_install_path();

    let config_path = AwsConfig::default_path()?;
    let aws_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".aws");

    ensure_secure_dir(&aws_dir)?;

    let mut config = AwsConfig::load_from(config_path)?;

    let profile_name = match profile {
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

    let credential_process = match management_role {
        Some(mgmt) => format!(
            "\"{}\" credential aws --role {role_arn} --management-role {mgmt}",
            vouch_path.display()
        ),
        None => format!(
            "\"{}\" credential aws --role {role_arn}",
            vouch_path.display()
        ),
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

/// Discover accounts and write profiles via the configured session.
///
/// Uses the IdC portal path when the session has an Identity Center
/// application ARN configured, otherwise uses Organizations role chaining.
async fn run_discover(
    server: &str,
    profile_prefix: Option<&str>,
    management_role: Option<&str>,
) -> Result<()> {
    // Only Identity Center management roles enumerate accounts/roles from the
    // portal; role chaining uses explicit per-account profiles.
    let vouch_config = crate::config::Config::load()?;
    let idc: Vec<(String, String, String)> = vouch_config
        .aws()
        .map(|a| {
            a.management_roles
                .iter()
                .filter_map(|(mgmt, c)| {
                    Some((
                        mgmt.clone(),
                        c.identity_center_application_arn.clone()?,
                        c.identity_center_region.clone()?,
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    let (mgmt, app_arn, region) = match management_role {
        Some(m) => idc
            .into_iter()
            .find(|(role, _, _)| role == m)
            .ok_or_else(|| {
                crate::exit_code::CliError::ConfigError(tr!("aws-err-idc-not-configured"))
            })?,
        None => {
            let mut roles = idc.into_iter();
            match (roles.next(), roles.next()) {
                (Some(only), None) => only,
                (None, _) => {
                    return Err(crate::exit_code::CliError::ConfigError(tr!(
                        "setup-aws-err-discover-not-idc"
                    ))
                    .into());
                }
                (Some(_), Some(_)) => {
                    return Err(crate::exit_code::CliError::ConfigError(tr!(
                        "setup-aws-err-discover-ambiguous"
                    ))
                    .into());
                }
            }
        }
    };

    discover_identity_center(server, profile_prefix, &mgmt, &app_arn, &region).await
}

// =========================================================================
// Interactive wizard
// =========================================================================

/// Access pattern selected in the wizard.
enum AccessPattern {
    /// STS `AssumeRoleWithWebIdentity` — single account.
    Single,
    /// Role chaining through a management role; chained accounts are added as
    /// explicit per-account profiles.
    Chain,
    /// IAM Identity Center trusted-token-issuer exchange.
    Idc,
}

impl std::fmt::Display for AccessPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single => f.write_str(&tr!("wizard-aws-pattern-single")),
            Self::Chain => f.write_str(&tr!("wizard-aws-pattern-chain")),
            Self::Idc => f.write_str(&tr!("wizard-aws-pattern-idc")),
        }
    }
}

/// Interactive wizard.
///
/// Detects existing AWS setup (in `~/.config/vouch/config.json` and
/// `~/.aws/config`) and offers context-aware actions on a re-run; otherwise
/// runs the first-time, pattern-first setup.
async fn run_wizard(server: &str, profile: Option<&str>, region: Option<&str>) -> Result<()> {
    require_terminal()?;

    let existing = ExistingSetup::detect();
    if existing.chaining_mgmt_roles.is_empty() && existing.idc_mgmt_roles.is_empty() {
        new_setup(server, profile, region).await
    } else {
        reconfigure(server, profile, region, &existing).await
    }
}

/// Existing AWS setup with re-run actions, classified from the two sources of
/// truth: the management role / Identity Center config stored in
/// `~/.config/vouch/config.json`, and the vouch profiles already written to
/// `~/.aws/config`. Single-account profiles carry no distinct re-run action and
/// are not tracked.
struct ExistingSetup {
    /// Management-role ARNs available for chaining (no Identity Center config).
    chaining_mgmt_roles: Vec<String>,
    /// Management-role ARNs configured for Identity Center (application ARN set).
    idc_mgmt_roles: Vec<String>,
}

impl ExistingSetup {
    fn detect() -> Self {
        use crate::integrations::aws::config::{
            AwsConfig, extract_management_role_from_credential_process,
        };
        let mut chaining = std::collections::BTreeSet::new();
        let mut idc = std::collections::BTreeSet::new();

        // Vouch config: a management-role entry with an application ARN is
        // Identity Center; otherwise it is a chaining hop.
        if let Ok(cfg) = crate::config::Config::load()
            && let Some(aws) = cfg.aws()
        {
            for (mgmt, entry) in &aws.management_roles {
                if entry.identity_center_application_arn.is_some() {
                    idc.insert(mgmt.clone());
                } else {
                    chaining.insert(mgmt.clone());
                }
            }
        }

        // Profiles in ~/.aws/config: `--account` is an Identity Center profile
        // (its management role is captured from vouch config above) and
        // `--management-role` on a bare `--role` profile is a chaining hop. A
        // profile with no `--management-role` is single-account and ignored.
        if let Ok(aws_config) = AwsConfig::load() {
            for profile in aws_config.find_all_vouch_profiles() {
                if let Some(cp) = profile.credential_process.as_deref()
                    && !cp.contains("--account")
                    && let Some(mgmt) = extract_management_role_from_credential_process(cp)
                {
                    chaining.insert(mgmt);
                }
            }
        }

        // A role configured for Identity Center is presented as IdC, not chaining.
        chaining.retain(|mgmt| !idc.contains(mgmt));

        Self {
            chaining_mgmt_roles: chaining.into_iter().collect(),
            idc_mgmt_roles: idc.into_iter().collect(),
        }
    }
}

/// A context-aware action offered on a re-run.
enum ReconfigAction {
    /// Add a chained account through the given management role.
    AddChaining(String),
    /// Re-enumerate the accounts/roles of an Identity Center management role.
    RediscoverIdc(String),
    /// Start a fresh access-pattern setup.
    NewPattern,
}

impl std::fmt::Display for ReconfigAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddChaining(mgmt) => f.write_str(&tr_args!(
                "wizard-aws-reconfig-add-chaining",
                mgmt = mgmt.as_str()
            )),
            Self::RediscoverIdc(mgmt) => f.write_str(&tr_args!(
                "wizard-aws-reconfig-rediscover-idc",
                mgmt = mgmt.as_str()
            )),
            Self::NewPattern => f.write_str(&tr!("wizard-aws-reconfig-new-pattern")),
        }
    }
}

/// Re-run: present context-aware actions derived from the existing setup and
/// carry them out.
async fn reconfigure(
    server: &str,
    profile: Option<&str>,
    region: Option<&str>,
    existing: &ExistingSetup,
) -> Result<()> {
    let mut actions: Vec<ReconfigAction> = Vec::new();
    for mgmt in &existing.chaining_mgmt_roles {
        actions.push(ReconfigAction::AddChaining(mgmt.clone()));
    }
    for mgmt in &existing.idc_mgmt_roles {
        actions.push(ReconfigAction::RediscoverIdc(mgmt.clone()));
    }
    actions.push(ReconfigAction::NewPattern);

    println!();
    let choice = prompt_select(&tr!("wizard-aws-reconfig-prompt"), actions)?;
    println!();

    match choice {
        ReconfigAction::AddChaining(mgmt) => {
            let account_role = prompt_text(&tr!("wizard-aws-prompt-account-role"))?;
            crate::integrations::aws::sts::parse_role_arn(&account_role).map_err(|_| {
                crate::exit_code::CliError::ConfigError(tr!("wizard-aws-err-invalid-role-arn"))
            })?;
            run_explicit_role(profile, &account_role, Some(&mgmt), region)
        }
        ReconfigAction::RediscoverIdc(mgmt) => {
            let (application_arn, idc_region) =
                crate::commands::credential::aws::idc_application_for(&mgmt)?;
            discover_identity_center(server, profile, &mgmt, &application_arn, &idc_region).await
        }
        ReconfigAction::NewPattern => new_setup(server, profile, region).await,
    }
}

/// First-time setup: choose an access pattern, then configure it. Each branch
/// prompts for its role, prints the trust policy, and finishes the pattern.
async fn new_setup(server: &str, profile: Option<&str>, region: Option<&str>) -> Result<()> {
    use crate::integrations::aws::sts::parse_role_arn;

    println!();
    let pattern = prompt_select(
        &tr!("wizard-aws-pattern-select"),
        vec![
            AccessPattern::Single,
            AccessPattern::Chain,
            AccessPattern::Idc,
        ],
    )?;
    println!();

    // Single account trusts Vouch directly; chaining and Identity Center prompt
    // for the management-account role that Vouch's OIDC provider trusts.
    let role_prompt = match pattern {
        AccessPattern::Single => tr!("wizard-aws-prompt-role-single"),
        AccessPattern::Chain | AccessPattern::Idc => tr!("wizard-aws-prompt-role-management"),
    };
    let role_arn = prompt_text(&role_prompt)?;
    let arn = parse_role_arn(&role_arn).map_err(|_| {
        crate::exit_code::CliError::ConfigError(tr!("wizard-aws-err-invalid-role-arn"))
    })?;
    let account_id = arn
        .account
        .as_deref()
        .ok_or_else(|| {
            crate::exit_code::CliError::ConfigError(tr!("wizard-aws-err-invalid-role-arn"))
        })?
        .to_string();
    let partition = arn.partition;

    print_trust_policy(server, &account_id, partition).await?;
    prompt_continue()?;

    match pattern {
        AccessPattern::Single => run_explicit_role(profile, &role_arn, None, region),
        AccessPattern::Chain => wizard_chaining(&role_arn, partition),
        AccessPattern::Idc => wizard_idc(server, profile, &role_arn, partition, region).await,
    }
}

/// Print the OIDC federation trust policy for `role`'s account, plus the
/// one-time OIDC-provider registration hint. The subject is restricted to the
/// caller's email domain when it can be read from the session token.
async fn print_trust_policy(
    server: &str,
    account_id: &str,
    partition: vouch_common::aws::Partition,
) -> Result<()> {
    let issuer_host = server_host(server)?;
    let subject_pattern = current_user_subject_pattern().await;
    let trust = policy::trust(
        partition.as_str(),
        account_id,
        &issuer_host,
        server,
        subject_pattern.as_deref(),
    );
    let trust_json =
        serde_json::to_string_pretty(&trust).context("failed to serialize trust policy")?;

    println!("\n{}\n", tr!("wizard-aws-trust-policy-header"));
    println!("{trust_json}\n");
    println!(
        "{}",
        tr_args!(
            "wizard-aws-oidc-provider-hint",
            issuer_url = server,
            audience = server,
        )
    );
    Ok(())
}

/// Wizard branch: role chaining. Prints the management-role permission policy
/// and explains how to add each chained account explicitly.
fn wizard_chaining(
    management_role_arn: &str,
    partition: vouch_common::aws::Partition,
) -> Result<()> {
    let default_resource = format!("arn:{}:iam::*:role/*", partition.as_str());
    let resource = prompt_text_default(
        &tr!("wizard-aws-prompt-chaining-resource"),
        &default_resource,
    )?;

    let perm = policy::chaining(&resource);
    let perm_json =
        serde_json::to_string_pretty(&perm).context("failed to serialize permission policy")?;
    println!(
        "\n{}\n",
        tr_args!(
            "wizard-aws-permission-policy-header",
            role_arn = management_role_arn
        )
    );
    println!("{perm_json}\n");

    println!(
        "{}",
        tr_args!(
            "wizard-aws-chaining-add-accounts",
            management_role = management_role_arn
        )
    );
    Ok(())
}

/// Wizard branch: IAM Identity Center TTI. Stores the management role's
/// application ARN and portal region, then enumerates the caller's real accounts
/// and roles.
async fn wizard_idc(
    server: &str,
    profile: Option<&str>,
    management_role_arn: &str,
    partition: vouch_common::aws::Partition,
    region: Option<&str>,
) -> Result<()> {
    println!(
        "\n{}\n",
        tr_args!(
            "wizard-aws-idc-setup-hint",
            issuer_url = server,
            audience = server,
        )
    );
    prompt_continue()?;

    let app_arn = prompt_text(&tr!("wizard-aws-prompt-idc-app-arn"))?;

    let perm = policy::idc(&app_arn);
    let perm_json =
        serde_json::to_string_pretty(&perm).context("failed to serialize permission policy")?;
    println!(
        "\n{}\n",
        tr_args!(
            "wizard-aws-permission-policy-header",
            role_arn = management_role_arn
        )
    );
    println!("{perm_json}\n");
    prompt_continue()?;

    let default_region = region.map_or_else(
        || partition.default_sts_region().to_string(),
        str::to_string,
    );
    let idc_region = prompt_text_default(&tr!("wizard-aws-prompt-idc-region"), &default_region)?;

    let config = crate::config::ManagementRoleConfig {
        identity_center_application_arn: Some(app_arn.clone()),
        identity_center_region: Some(idc_region.clone()),
    };
    crate::config::Config::modify(|c| {
        c.set_management_role(management_role_arn.to_string(), config);
    })?;
    tr_println!("wizard-aws-saved-vouch-config", name = management_role_arn);

    discover_identity_center(server, profile, management_role_arn, &app_arn, &idc_region).await
}

// =========================================================================
// Shared wizard helpers
// =========================================================================

/// Derive the caller's subject restriction (`*@<domain>`) from the `email`
/// claim of the locally-resolved session token.
///
/// Fully local — no extra server call. Best-effort: returns `None` when no
/// session is available or the token carries no `email` claim, in which case the
/// trust policy omits the subject filter (it still binds `sts:RoleSessionName`).
async fn current_user_subject_pattern() -> Option<String> {
    let session = crate::session::resolve_session().await.ok()?;
    let domain = crate::commands::credential::aws::extract_email_domain_from_jwt(
        secrecy::ExposeSecret::expose_secret(&session.token),
    )?;
    Some(format!("*@{domain}"))
}

/// Extract the hostname from a server URL, stripping the scheme.
fn server_host(server: &str) -> Result<String> {
    let url = url::Url::parse(server).with_context(|| format!("invalid server URL: {server}"))?;
    url.host_str()
        .ok_or_else(|| anyhow::anyhow!("server URL has no host: {server}"))
        .map(str::to_string)
}

// =========================================================================
// IdC discovery (shared with discover path and wizard IdC branch)
// =========================================================================

/// Build the `credential_process` line for an Identity Center profile.
fn idc_credential_process(
    vouch_path: &std::path::Path,
    account_id: &str,
    permission_set: &str,
    management_role: &str,
) -> String {
    format!(
        "\"{}\" credential aws --account {account_id} --role \"{permission_set}\" --management-role {management_role}",
        vouch_path.display()
    )
}

/// Discover accounts/permission-sets via the Identity Center portal for the
/// given management role and write a profile per (account × permission set).
async fn discover_identity_center(
    server: &str,
    profile_prefix: Option<&str>,
    management_role: &str,
    application_arn: &str,
    region: &str,
) -> Result<()> {
    use crate::integrations::aws::sso_portal::{list_account_roles, list_accounts};

    let bearer = crate::commands::credential::aws::obtain_identity_center_token(
        server,
        management_role,
        application_arn,
        region,
    )
    .await?;

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    let accounts = list_accounts(&http_client, region, &bearer)
        .await
        .context("failed to list SSO accounts")?;

    let vouch_path = resolve_install_path();
    let config_path = AwsConfig::default_path()?;
    let aws_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".aws");
    ensure_secure_dir(&aws_dir)?;
    let mut config = AwsConfig::load_from(config_path)?;

    let mut created_count: u32 = 0;
    let mut skipped_count: u32 = 0;

    for account in &accounts {
        let roles = list_account_roles(&http_client, region, &bearer, &account.account_id)
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
                    &account.account_id,
                    &role.role_name,
                    management_role,
                )),
                region: Some(region.to_string()),
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

// =========================================================================
// Terminal / prompt helpers
// =========================================================================

/// Error out when stdin is not a terminal (interactive wizard impossible).
fn require_terminal() -> Result<()> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return Ok(());
    }
    Err(crate::exit_code::CliError::ConfigError(tr!("setup-aws-err-needs-terminal")).into())
}

/// Show an interactive single-select prompt.
fn prompt_select<T: std::fmt::Display>(prompt: &str, options: Vec<T>) -> Result<T> {
    inquire::Select::new(prompt, options)
        .prompt()
        .map_err(|e| match e {
            inquire::InquireError::OperationCanceled
            | inquire::InquireError::OperationInterrupted => {
                crate::exit_code::CliError::ConfigError(tr!("wizard-aws-err-cancelled")).into()
            }
            other => anyhow::anyhow!("selection failed: {other}"),
        })
}

/// Show an interactive text-input prompt.
fn prompt_text(prompt: &str) -> Result<String> {
    inquire::Text::new(prompt).prompt().map_err(|e| match e {
        inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted => {
            crate::exit_code::CliError::ConfigError(tr!("wizard-aws-err-cancelled")).into()
        }
        other => anyhow::anyhow!("prompt failed: {other}"),
    })
}

/// Show an interactive text-input prompt with a default value.
fn prompt_text_default(prompt: &str, default: &str) -> Result<String> {
    inquire::Text::new(prompt)
        .with_default(default)
        .prompt()
        .map_err(|e| match e {
            inquire::InquireError::OperationCanceled
            | inquire::InquireError::OperationInterrupted => {
                crate::exit_code::CliError::ConfigError(tr!("wizard-aws-err-cancelled")).into()
            }
            other => anyhow::anyhow!("prompt failed: {other}"),
        })
}

/// Prompt the user to press Enter before continuing.
fn prompt_continue() -> Result<()> {
    println!("{}", tr!("wizard-aws-press-enter"));
    // We use inquire::Text rather than stdin().read_line so that cancellation
    // (Ctrl-C) is handled consistently with the rest of the wizard.
    inquire::Text::new("")
        .with_default("")
        .prompt()
        .map(|_| ())
        .map_err(|e| match e {
            inquire::InquireError::OperationCanceled
            | inquire::InquireError::OperationInterrupted => {
                crate::exit_code::CliError::ConfigError(tr!("wizard-aws-err-cancelled")).into()
            }
            other => anyhow::anyhow!("prompt failed: {other}"),
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

    #[test]
    fn test_server_host_strips_scheme() {
        #[expect(clippy::unwrap_used, reason = "test code")]
        {
            assert_eq!(
                server_host("https://vouch.example.com").unwrap(),
                "vouch.example.com"
            );
            assert_eq!(
                server_host("https://vouch.example.com:8443").unwrap(),
                "vouch.example.com"
            );
        }
    }
}
