// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch setup anthropic` — persist Anthropic Workload Identity Federation
//! parameters for use by `vouch credential anthropic`.
//!
//! This is the **workload** federation path: the minted `sk-ant-oat01-...`
//! token acts as a non-human **service account**, which is the correct
//! identity for CI/headless automation. It is intentionally *not* wired into
//! Claude Code — vouch does not manage `~/.claude/settings.json`.

use anyhow::{Context, Result};

use crate::config::{AnthropicFederation, Config};

/// Arguments captured by the clap `Anthropic` setup variant.
pub(crate) struct SetupArgs<'a> {
    pub federation_rule_id: &'a str,
    pub organization_id: &'a str,
    pub service_account_id: &'a str,
    pub workspace_id: &'a str,
    pub audience: Option<&'a str>,
    pub token_endpoint: Option<&'a str>,
}

/// Run `vouch setup anthropic`.
pub(crate) async fn run(args: SetupArgs<'_>) -> Result<()> {
    // Confirm the user has actually enrolled before persisting anything —
    // Config::load() succeeds on an empty file, so we have to check that a
    // server context exists. Otherwise we'd save federation params for a
    // machine that can't get a Vouch session.
    let config = Config::load().context("failed to load Vouch config")?;
    let _server = config
        .server_url()
        .context("not configured — run 'vouch enroll' first")?;

    let fed = AnthropicFederation {
        federation_rule_id: args.federation_rule_id.to_string(),
        organization_id: args.organization_id.to_string(),
        service_account_id: args.service_account_id.to_string(),
        workspace_id: args.workspace_id.to_string(),
        audience: args.audience.map(str::to_string),
        token_endpoint: args.token_endpoint.map(str::to_string),
    };
    Config::modify(move |c| c.set_ai_anthropic(fed))?;

    print_success();
    Ok(())
}

fn print_success() {
    println!("Anthropic (Claude) Workload Identity Federation configured.\n");
    println!("  Federation params: ~/.vouch/config.json\n");

    println!("This mints a service-account token for CI/headless automation.");
    println!("Get a token:");
    println!("  vouch login                 # YubiKey tap, once per session");
    println!("  vouch credential anthropic  # prints sk-ant-oat01-...\n");

    println!("Smoke test:");
    println!("  curl -sS https://api.anthropic.com/v1/messages \\");
    println!("    -H \"authorization: Bearer $(vouch credential anthropic)\" \\");
    println!("    -H \"anthropic-version: 2023-06-01\" \\");
    println!("    -H \"content-type: application/json\" \\");
    println!(
        "    -d '{{\"model\":\"claude-sonnet-4-6\",\"max_tokens\":64,\"messages\":[{{\"role\":\"user\",\"content\":\"hi\"}}]}}'"
    );
}
