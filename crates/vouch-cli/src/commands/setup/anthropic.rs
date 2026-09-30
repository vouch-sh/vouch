// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch setup anthropic` — persist Anthropic Workload Identity Federation
//! parameters for use by `vouch credential anthropic`.
//!
//! This is the **workload** federation path: the minted `sk-ant-oat01-...`
//! token acts as a non-human **service account**, which is the correct
//! identity for CI/headless automation. It is intentionally *not* wired into
//! Claude Code — vouch does not manage `~/.claude/settings.json`.

use anyhow::{Context, Result};
use vouch_cli::{tr, tr_println};

use crate::config::{AnthropicFederation, Config};
use crate::server_url::ServerUrl;
use vouch_common::paths;

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
    let config = Config::load().with_context(|| tr!("setup-err-load-vouch-config"))?;
    let _server = config
        .server_url()
        .with_context(|| tr!("setup-err-anthropic-not-enrolled"))?;

    // The endpoint receives the Vouch-minted assertion, so it takes TLS
    // (RFC 7521 §4); a plain-HTTP one is refused before anything is saved.
    let token_endpoint = args
        .token_endpoint
        .map(|endpoint| ServerUrl::parse(endpoint, false))
        .transpose()?;

    let fed = AnthropicFederation {
        federation_rule_id: args.federation_rule_id.to_string(),
        organization_id: args.organization_id.to_string(),
        service_account_id: args.service_account_id.to_string(),
        workspace_id: args.workspace_id.to_string(),
        audience: args.audience.map(str::to_string),
        token_endpoint: token_endpoint.map(|endpoint| endpoint.as_str().to_string()),
    };
    Config::modify(move |c| c.set_ai_anthropic(fed))?;

    print_success();
    Ok(())
}

fn print_success() {
    let config_path = paths::config_file().map_or_else(
        || "~/.config/vouch/config.json".to_string(),
        |p| p.display().to_string(),
    );
    tr_println!("setup-anthropic-success-block", config_path = config_path);
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::session::test_support::with_stored_session;

    fn args(token_endpoint: Option<&str>) -> SetupArgs<'_> {
        SetupArgs {
            federation_rule_id: "rule",
            organization_id: "org",
            service_account_id: "sa",
            workspace_id: "ws",
            audience: None,
            token_endpoint,
        }
    }

    // RFC 7521 §4: "all requests to the token endpoint MUST use Transport
    // Layer Security (TLS)". The endpoint receives the Vouch-minted
    // assertion, so a plain-HTTP one is refused before anything is saved.
    #[tokio::test]
    async fn plain_http_token_endpoint_is_refused() {
        let (refused, saved) =
            with_stored_session(Some("https://vouch.example.com"), None, async || {
                let refused = run(args(Some("http://0.0.0.0:8080/token"))).await;
                let saved = Config::load()
                    .unwrap()
                    .ai()
                    .and_then(|ai| ai.anthropic.clone());
                (refused, saved)
            })
            .await;
        assert!(refused.is_err(), "a plain-HTTP endpoint is refused");
        assert!(saved.is_none(), "nothing is saved for a refused endpoint");
    }

    #[tokio::test]
    async fn https_token_endpoint_is_saved() {
        let saved = with_stored_session(Some("https://vouch.example.com"), None, async || {
            run(args(Some("https://federation.example.com/token/")))
                .await
                .unwrap();
            Config::load()
                .unwrap()
                .ai()
                .and_then(|ai| ai.anthropic.clone())
        })
        .await;
        assert_eq!(
            saved.unwrap().token_endpoint.as_deref(),
            Some("https://federation.example.com/token")
        );
    }
}
