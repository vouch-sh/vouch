// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch aws roles` — list available roles across AWS accounts.

use anyhow::{Context, Result};

use crate::integrations::aws::config::AwsConfig;
use crate::integrations::aws::sso::{SsoConfig, load_cached_token};
use crate::integrations::aws::sso_portal::{SsoAccount, list_account_roles, list_accounts};

/// Arguments for `vouch aws roles`.
#[derive(clap::Args)]
pub(crate) struct RolesArgs {
    /// SSO session name from ~/.aws/config (default: first found).
    #[arg(long)]
    pub sso_session: Option<String>,
    /// Filter by account ID (show roles for a single account only).
    #[arg(long)]
    pub account: Option<String>,
    /// Output as JSON.
    #[arg(long)]
    pub json: bool,
}

/// A role entry for display/output.
struct RoleEntry {
    account_id: String,
    account_name: String,
    role_name: String,
}

/// Run `vouch aws roles`.
pub(crate) async fn run(args: RolesArgs) -> Result<()> {
    let aws_config = AwsConfig::load()?;
    let session = super::resolve_sso_session(&aws_config, args.sso_session.as_deref())?;
    let sso_config = SsoConfig::from_session(&session);

    let token = load_cached_token(&sso_config).ok_or_else(|| {
        crate::exit_code::CliError::NotAuthenticated {
            reason: "SSO session expired or missing. Run 'vouch aws login' first.".to_string(),
        }
    })?;
    let bearer = token.token();
    let region = session.region.clone();

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    // Determine which accounts to query
    let accounts: Vec<SsoAccount> = if let Some(ref account_id) = args.account {
        // User filtered to a single account — build a synthetic entry
        vec![SsoAccount {
            account_id: account_id.clone(),
            account_name: account_id.clone(),
            email_address: String::new(),
        }]
    } else {
        list_accounts(&http_client, &region, &bearer)
            .await
            .context("failed to list SSO accounts")?
    };

    // Collect roles for each account (O(N) sequential — acceptable for v1)
    let mut entries: Vec<RoleEntry> = Vec::new();
    for account in &accounts {
        let roles = list_account_roles(&http_client, &region, &bearer, &account.account_id)
            .await
            .with_context(|| format!("failed to list roles for account {}", account.account_id))?;

        for role in roles {
            entries.push(RoleEntry {
                account_id: account.account_id.clone(),
                account_name: account.account_name.clone(),
                role_name: role.role_name,
            });
        }
    }

    if args.json {
        let json = serde_json::to_string_pretty(
            &entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "accountId": e.account_id,
                        "accountName": e.account_name,
                        "roleName": e.role_name,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .context("failed to serialize roles")?;
        println!("{json}");
    } else {
        println!("{:<14} {:<35} ROLE NAME", "ACCOUNT ID", "ACCOUNT NAME");
        println!("{}", "-".repeat(80));
        for entry in &entries {
            println!(
                "{:<14} {:<35} {}",
                entry.account_id, entry.account_name, entry.role_name
            );
        }
        println!();
        println!("{} role(s)", entries.len());
    }

    Ok(())
}
