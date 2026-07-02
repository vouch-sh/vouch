// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS Identity Center commands.

use anyhow::Result;
use clap::Subcommand;
use vouch_cli::{tr, tr_args};

use crate::integrations::aws::config::{AwsConfig, SsoSession};

pub(crate) mod console;

/// AWS subcommands.
#[derive(Subcommand)]
pub(crate) enum AwsCommands {
    /// Open the AWS Management Console in your browser.
    #[command(about = tr!("cmd-aws-console-about"))]
    Console(console::ConsoleArgs),
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
            crate::exit_code::CliError::ConfigError(tr_args!(
                "aws-err-sso-session-not-found",
                name = name,
            ))
            .into()
        });
    }

    // No explicit selection — use first found, with a hint if multiple exist
    let mut all = aws_config.find_all_sso_sessions();
    if all.is_empty() {
        return Err(crate::exit_code::CliError::ConfigError(tr!("aws-err-no-sso-session")).into());
    }
    if all.len() > 1 {
        eprintln!(
            "{}",
            tr_args!(
                "aws-using-sso-session",
                name = all.first().map_or("", |s| &s.name),
            ),
        );
    }
    Ok(all.swap_remove(0))
}
