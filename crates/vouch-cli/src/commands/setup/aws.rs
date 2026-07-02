// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS setup command.
//!
//! Configures AWS CLI/SDK to use Vouch for credential federation. Entry
//! point is `run`; call paths:
//!
//! - `--role <arn>`  → `run_explicit_role` (non-interactive, single account)
//! - `--discover`    → `run_discover` (non-interactive, re-enumerates sessions)
//! - no flags + TTY  → `run_wizard` (interactive wizard, role-first)

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
        return run_discover(server, profile, region).await;
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
    region: Option<&str>,
) -> Result<()> {
    use crate::integrations::aws::config::AwsConfig as AwsCliConfig;

    let vouch_config = crate::config::Config::load()?;
    let aws_cli_config = AwsCliConfig::load()?;

    let session = crate::commands::aws::resolve_sso_session(&aws_cli_config, None)?;
    let session_cfg = vouch_config
        .aws()
        .and_then(|a| a.sso_sessions.get(&session.name))
        .cloned()
        .unwrap_or_default();

    if session_cfg.identity_center_application_arn.is_some() {
        return discover_identity_center(server, &session, profile_prefix, region).await;
    }

    // Only Identity Center sessions enumerate accounts/roles from the SSO
    // portal. Role chaining is configured with explicit per-account profiles
    // (`setup aws --role <arn> --management-role <mgmt-arn>`).
    Err(crate::exit_code::CliError::ConfigError(tr!("setup-aws-err-discover-not-idc")).into())
}

// =========================================================================
// Interactive wizard
// =========================================================================

/// Access pattern selected in the wizard.
enum AccessPattern {
    /// STS `AssumeRoleWithWebIdentity` — single account.
    Single,
    /// Role chaining through a management role, accounts via Organizations.
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

/// Role-first interactive wizard.
///
/// Guides the user through configuring AWS federation for one of three
/// access patterns: single account STS, multi-account role chaining, or
/// IAM Identity Center TTI.
async fn run_wizard(server: &str, profile: Option<&str>, region: Option<&str>) -> Result<()> {
    use crate::integrations::aws::sts::parse_role_arn;

    require_terminal()?;

    // Step 1: role ARN.
    let role_arn = prompt_text(&tr!("wizard-aws-prompt-role-arn"))?;
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
    let issuer_host = server_host(server)?;

    // Print trust policy and OIDC provider setup hint. Restrict the subject to
    // the caller's email domain when we can read it from the session token.
    let subject_pattern = current_user_subject_pattern().await;
    let trust = policy::trust(
        partition.as_str(),
        &account_id,
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

    prompt_continue()?;

    // Step 2: access pattern.
    println!();
    let patterns = vec![
        AccessPattern::Single,
        AccessPattern::Chain,
        AccessPattern::Idc,
    ];
    let pattern = prompt_select(&tr!("wizard-aws-pattern-select"), patterns)?;
    println!();

    match pattern {
        AccessPattern::Single => run_explicit_role(profile, &role_arn, None, region),
        AccessPattern::Chain => wizard_chaining(&role_arn, partition),
        AccessPattern::Idc => {
            wizard_idc(server, profile, &role_arn, region, &account_id, partition).await
        }
    }
}

/// Wizard branch: role chaining.
///
/// Prints the management-role permission policy and explains how to add each
/// chained account's profile explicitly (`setup aws --role <account-role-arn>
/// --management-role <this-role>`). No account enumeration and no per-account
/// role templating — each profile carries its exact role ARN.
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

/// Wizard branch: IAM Identity Center TTI.
async fn wizard_idc(
    server: &str,
    profile_prefix: Option<&str>,
    management_role_arn: &str,
    region: Option<&str>,
    _account_id: &str,
    partition: vouch_common::aws::Partition,
) -> Result<()> {
    // Print IdC setup instructions.
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

    // Print permission policy.
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

    let session_name = prompt_text(&tr!("wizard-aws-prompt-session-name"))?;
    ensure_sso_session(&session_name)?;

    let session_cfg = crate::config::SsoSessionConfig {
        management_role: management_role_arn.to_string(),
        identity_center_application_arn: Some(app_arn),
    };
    crate::config::Config::modify(|c| c.set_sso_session(session_name.clone(), session_cfg))?;
    tr_println!(
        "wizard-aws-saved-vouch-config",
        name = session_name.as_str()
    );

    let aws_cli_config = crate::integrations::aws::config::AwsConfig::load()?;
    let session = crate::commands::aws::resolve_sso_session(&aws_cli_config, Some(&session_name))?;

    let effective_region = region.unwrap_or(&session.region).to_string();
    let _ = partition; // partition inferred from session region inside discover_identity_center

    discover_identity_center(server, &session, profile_prefix, Some(&effective_region)).await
}

// =========================================================================
// Shared wizard helpers
// =========================================================================

/// Ensure an `[sso-session <name>]` block exists in `~/.aws/config`.
///
/// If the session is not found, prompts for the start URL and region, then
/// writes the block and saves `~/.aws/config`.
fn ensure_sso_session(name: &str) -> Result<()> {
    let config_path = AwsConfig::default_path()?;
    let aws_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".aws");
    ensure_secure_dir(&aws_dir)?;
    let mut config = AwsConfig::load_from(config_path)?;

    if config.find_sso_session(Some(name)).is_some() {
        return Ok(());
    }

    // Session not found — prompt and create it.
    let start_url = prompt_text(&tr!("wizard-aws-prompt-session-start-url"))?;
    let sso_region = prompt_text(&tr!("wizard-aws-prompt-session-region"))?;

    config.set_sso_session(name, &start_url, &sso_region);
    config.save()?;
    tr_println!("wizard-aws-created-sso-session", name = name);
    Ok(())
}

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
    session_name: &str,
    account_id: &str,
    role_name: &str,
) -> String {
    format!(
        "\"{}\" credential aws --sso-session \"{session_name}\" --account {account_id} --role \"{role_name}\"",
        vouch_path.display()
    )
}

/// Discover accounts/permission-sets via the Identity Center portal.
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
    let mut config = AwsConfig::load_from(config_path)?;

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
