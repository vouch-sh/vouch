// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch aws accounts` — list AWS accounts via Identity Center.

use anyhow::{Context, Result};
use vouch_cli::{tr, tr_args};

use crate::integrations::aws::config::AwsConfig;
use crate::integrations::aws::sso::{SsoConfig, load_cached_token};
use crate::integrations::aws::sso_portal::list_accounts;

/// Arguments for `vouch aws accounts`.
#[derive(clap::Args)]
pub(crate) struct AccountsArgs {
    /// SSO session name from ~/.aws/config (default: first found).
    #[arg(long, help = tr!("arg-aws-sso-session-help"))]
    pub sso_session: Option<String>,
    /// Output as JSON.
    #[arg(long, help = tr!("arg-aws-accounts-json-help"))]
    pub json: bool,
}

/// Run `vouch aws accounts`.
pub(crate) async fn run(args: AccountsArgs) -> Result<()> {
    let aws_config = AwsConfig::load()?;
    let session = super::resolve_sso_session(&aws_config, args.sso_session.as_deref())?;
    let sso_config = SsoConfig::from_session(&session);

    let token = load_cached_token(&sso_config).ok_or_else(|| {
        crate::exit_code::CliError::NotAuthenticated {
            reason: tr!("aws-err-sso-expired"),
        }
    })?;

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .with_context(|| tr!("aws-login-err-http-client"))?;

    let accounts = list_accounts(&http_client, &session.region, &token.token())
        .await
        .with_context(|| tr!("aws-accounts-err-list"))?;

    if args.json {
        let json = serde_json::to_string_pretty(
            &accounts
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "accountId": a.account_id,
                        "accountName": a.account_name,
                        "emailAddress": a.email_address,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .with_context(|| tr!("aws-accounts-err-serialize"))?;
        // Machine-readable JSON output: stays English regardless of locale.
        println!("{json}");
    } else {
        println!(
            "{:<14} {:<40} {}",
            tr!("aws-accounts-table-account-id"),
            tr!("aws-accounts-table-name"),
            tr!("aws-accounts-table-email"),
        );
        println!("{}", "-".repeat(80));
        for account in &accounts {
            println!(
                "{:<14} {:<40} {}",
                account.account_id, account.account_name, account.email_address
            );
        }
        println!();
        println!(
            "{}",
            tr_args!("aws-accounts-summary", count = accounts.len())
        );
    }

    Ok(())
}
