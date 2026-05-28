// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch credential openai` — exchange a Vouch session for a short-lived
//! OpenAI API token via Workload Identity Federation
//! ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token-exchange grant).
//!
//! Prints the bare provider token to stdout so it can be consumed directly
//! as a credential helper (for example, an OpenAI Codex CLI
//! `[model_providers.*.auth]` command with `refresh_interval_ms`).

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};

use crate::config::Config;

/// Default OpenAI token endpoint.
const DEFAULT_ENDPOINT: &str = "https://auth.openai.com/oauth/token";

/// Run `vouch credential openai`.
pub(crate) async fn run(server: &str) -> Result<()> {
    let token = get_token(server).await?;
    print!("{}", token.expose_secret());
    Ok(())
}

async fn get_token(server: &str) -> Result<SecretString> {
    let config = Config::load().context("failed to load Vouch config")?;
    let fed = config
        .ai()
        .and_then(|ai| ai.openai.clone())
        .context("OpenAI federation not configured — run 'vouch setup openai' first")?;
    let endpoint = fed
        .token_endpoint
        .clone()
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
    let audience = fed.audience.clone();

    let agent = super::aws::detect_agent_source();
    let cache_key =
        super::wif::build_cache_key("openai", &fed.identity_provider_id, agent.as_deref());
    let server = server.to_string();

    let data = super::cache::get_or_fetch(&cache_key, "OpenAI token", || async move {
        let assertion = super::wif::fetch_assertion(&server, audience.as_deref()).await?;
        let body = serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "subject_token": assertion.expose_secret(),
            "identity_provider_id": fed.identity_provider_id,
            "service_account_id": fed.service_account_id,
        });
        let (token, expiry) = super::wif::exchange(&endpoint, &body, "OpenAI").await?;
        Ok((
            serde_json::json!({ "access_token": token.expose_secret() }),
            expiry,
        ))
    })
    .await?;

    let token = data
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .context("cached OpenAI token is missing the access_token field")?;
    Ok(SecretString::from(token.to_string()))
}
