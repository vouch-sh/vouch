// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch credential anthropic` — exchange a Vouch session for a short-lived
//! Anthropic (Claude) API token via Workload Identity Federation
//! ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) `jwt-bearer` grant).
//!
//! Prints the bare `sk-ant-oat01-...` token to stdout so it can be consumed
//! directly as a credential helper (for example, Claude Code's `apiKeyHelper`).

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};

use crate::config::Config;

/// Default Anthropic token endpoint.
const DEFAULT_ENDPOINT: &str = "https://api.anthropic.com/v1/oauth/token";

/// Run `vouch credential anthropic`.
pub(crate) async fn run(server: &str) -> Result<()> {
    let token = get_token(server).await?;
    // Bare token, no trailing newline — matches `vouch credential token`
    // and is what apiKeyHelper expects.
    print!("{}", token.expose_secret());
    Ok(())
}

/// Fetch (or return from cache) a short-lived Anthropic access token.
async fn get_token(server: &str) -> Result<SecretString> {
    let config = Config::load().context("failed to load Vouch config")?;
    let fed = config
        .ai()
        .and_then(|ai| ai.anthropic.clone())
        .context("Anthropic federation not configured — run 'vouch setup anthropic' first")?;
    let endpoint = fed
        .token_endpoint
        .clone()
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
    let audience = fed.audience.clone();

    let agent = super::aws::detect_agent_source();
    let cache_key =
        super::wif::build_cache_key("anthropic", &fed.federation_rule_id, agent.as_deref());
    let server = server.to_string();

    let data = super::cache::get_or_fetch(&cache_key, "Anthropic token", || async move {
        let assertion = super::wif::fetch_assertion(&server, audience.as_deref()).await?;
        let body = serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion.expose_secret(),
            "federation_rule_id": fed.federation_rule_id,
            "organization_id": fed.organization_id,
            "service_account_id": fed.service_account_id,
            "workspace_id": fed.workspace_id,
        });
        let (token, expiry) = super::wif::exchange(&endpoint, &body, "Anthropic").await?;
        Ok((
            serde_json::json!({ "access_token": token.expose_secret() }),
            expiry,
        ))
    })
    .await?;

    let token = data
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .context("cached Anthropic token is missing the access_token field")?;
    Ok(SecretString::from(token.to_string()))
}
