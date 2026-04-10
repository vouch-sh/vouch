// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS Identity Center commands for multi-account management.

use anyhow::Result;
use clap::Subcommand;

use crate::integrations::aws::config::{AwsConfig, SsoSession};

pub(crate) mod accounts;
pub(crate) mod login;
pub(crate) mod roles;

/// AWS Identity Center subcommands.
#[derive(Subcommand)]
pub(crate) enum AwsCommands {
    /// Authenticate to AWS IAM Identity Center for account discovery.
    Login(login::LoginArgs),
    /// List AWS accounts you have access to via Identity Center.
    Accounts(accounts::AccountsArgs),
    /// List available roles across your AWS accounts.
    Roles(roles::RolesArgs),
}

/// Resolve which SSO session to use.
///
/// Resolution order:
/// 1. `--sso-session` CLI flag
/// 2. First `[sso-session]` in `~/.aws/config` (with hint if multiple exist)
///
/// Prints a hint to stderr when multiple sessions are found and none was specified,
/// so the user knows how to switch.
pub(crate) fn resolve_sso_session(
    aws_config: &AwsConfig,
    flag: Option<&str>,
) -> Result<SsoSession> {
    let explicit = flag;

    if let Some(name) = explicit {
        return aws_config.find_sso_session(Some(name)).ok_or_else(|| {
            crate::exit_code::CliError::ConfigError(format!(
                "SSO session '{name}' not found in ~/.aws/config. \
                 Run 'aws configure sso' or check --sso-session."
            ))
            .into()
        });
    }

    // No explicit selection — use first found, with a hint if multiple exist
    let all = aws_config.find_all_sso_sessions();
    match all.len() {
        0 => Err(crate::exit_code::CliError::ConfigError(
            "No SSO session found in ~/.aws/config. Run 'aws configure sso' first.".to_string(),
        )
        .into()),
        1 => all
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("internal: list was empty after length check")),
        _ => {
            let Some(first) = all.into_iter().next() else {
                anyhow::bail!("internal: list was empty after length check");
            };
            eprintln!(
                "Using SSO session '{}'. Specify --sso-session to use a different one.",
                first.name
            );
            Ok(first)
        }
    }
}
