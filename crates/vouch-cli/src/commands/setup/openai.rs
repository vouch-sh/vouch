// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch setup openai` — persist OpenAI Workload Identity Federation
//! parameters and auto-configure the OpenAI Codex CLI.
//!
//! Writes / merges `~/.codex/config.toml` to add:
//!
//! - `[model_providers.vouch]` with `base_url` + `wire_api`
//! - `[model_providers.vouch.auth]` with a refreshing `command`
//!   that calls `vouch credential openai`
//! - top-level `model_provider = "vouch"`
//!
//! Uses Codex's command-with-refresh auth pattern (rather than
//! `export OPENAI_API_KEY=$(vouch credential openai)`) so the short-lived
//! provider token is refreshed mid-session instead of expiring at the
//! first long generation.
//!
//! If Codex already has a different `model_provider` or a conflicting
//! `[model_providers.vouch]` block, the command errors and asks the
//! user to either remove it or re-run with `--force`. Configuring Vouch for
//! an AI provider is meant to be the workforce default, not silently merge
//! with an unrelated provider.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

use crate::config::{Config, OpenAiFederation};

/// Codex provider id Vouch registers itself under.
const PROVIDER_ID: &str = "vouch";

/// Token-fetch timeout. 5 seconds is comfortably above a normal Vouch
/// round trip and well under Codex's own request timeouts.
const AUTH_TIMEOUT_MS: i64 = 5_000;

/// Re-run the auth command every 5 minutes. Short enough to refresh
/// well before the ~1 hour provider token expires; long enough to avoid
/// hammering the Vouch + OpenAI token endpoints.
const AUTH_REFRESH_INTERVAL_MS: i64 = 300_000;

pub(crate) struct SetupArgs<'a> {
    pub identity_provider_id: &'a str,
    pub service_account_id: &'a str,
    pub audience: Option<&'a str>,
    pub token_endpoint: Option<&'a str>,
    pub force: bool,
}

pub(crate) async fn run(args: SetupArgs<'_>) -> Result<()> {
    // Confirm the user has actually enrolled before mutating anything —
    // Config::load() succeeds on an empty file, so we have to check that a
    // server context exists. Otherwise we'd happily write a Codex provider
    // block for a machine that can't get a Vouch session.
    let config = Config::load().context("failed to load Vouch config")?;
    let _server = config
        .server_url()
        .context("not configured — run 'vouch enroll' first")?;

    let vouch_path = std::env::current_exe()
        .ok()
        .map_or_else(|| "vouch".to_string(), |p| p.display().to_string());

    // Configure Codex FIRST so a conflict error doesn't leave the user
    // with persisted Vouch state pointing at an unwired provider.
    let config_path = configure_codex(&vouch_path, args.force)?;

    let fed = OpenAiFederation {
        identity_provider_id: args.identity_provider_id.to_string(),
        service_account_id: args.service_account_id.to_string(),
        audience: args.audience.map(str::to_string),
        token_endpoint: args.token_endpoint.map(str::to_string),
    };
    Config::modify(move |c| c.set_ai_openai(fed))?;

    print_success(&config_path);
    Ok(())
}

/// Write/merge Codex's `~/.codex/config.toml`. Errors out if Codex already
/// has a different `model_provider` or a conflicting `vouch` provider
/// block, unless `force` is set.
fn configure_codex(vouch_path: &str, force: bool) -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let codex_dir = home.join(".codex");
    let config_path = codex_dir.join("config.toml");

    let mut doc: DocumentMut = if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?;
        content
            .parse()
            .with_context(|| format!("failed to parse {}", config_path.display()))?
    } else {
        DocumentMut::new()
    };

    check_conflicts(&doc, &config_path, force)?;

    write_provider_block(&mut doc, vouch_path);
    doc.insert("model_provider", toml_edit::value(PROVIDER_ID));

    if !codex_dir.exists() {
        std::fs::create_dir_all(&codex_dir)
            .with_context(|| format!("failed to create {}", codex_dir.display()))?;
    }
    crate::utils::atomic_write(&config_path, doc.to_string().as_bytes())
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    Ok(config_path)
}

/// The only Codex setting `vouch setup openai` doesn't own is the top-level
/// `model_provider` selector. The `[model_providers.vouch]` block
/// itself is uniquely ours — if a previous run wrote it, silently updating
/// is correct (probably just a path or refresh-interval change). The
/// top-level selector, however, may legitimately point at the user's other
/// providers, so changing it requires `--force`.
fn check_conflicts(doc: &DocumentMut, config_path: &Path, force: bool) -> Result<()> {
    if force {
        return Ok(());
    }

    if let Some(existing_mp) = doc.get("model_provider").and_then(Item::as_str)
        && existing_mp != PROVIDER_ID
    {
        anyhow::bail!(
            "Codex already has model_provider = {existing_mp:?} in {}.\n\n\
             Remove the `model_provider` entry from config.toml, or re-run \
             `vouch setup openai --force` to switch the default to \
             `{PROVIDER_ID}`.",
            config_path.display(),
        );
    }

    Ok(())
}

/// Insert (or replace) the `[model_providers.vouch]` block, preserving
/// any other provider entries that already live under `model_providers`.
fn write_provider_block(doc: &mut DocumentMut, vouch_path: &str) {
    let mut provider = Table::new();
    provider.insert("name", toml_edit::value(PROVIDER_ID));
    provider.insert("base_url", toml_edit::value("https://api.openai.com/v1"));
    provider.insert("wire_api", toml_edit::value("chat"));

    let mut auth = Table::new();
    auth.insert("command", toml_edit::value(vouch_path));
    let mut args = Array::new();
    args.push("credential");
    args.push("openai");
    auth.insert("args", Item::Value(Value::Array(args)));
    auth.insert("timeout_ms", toml_edit::value(AUTH_TIMEOUT_MS));
    auth.insert(
        "refresh_interval_ms",
        toml_edit::value(AUTH_REFRESH_INTERVAL_MS),
    );
    provider.insert("auth", Item::Table(auth));

    let providers = doc
        .entry("model_providers")
        .or_insert(Item::Table(Table::new()));
    // Without this the parent renders as plain `[model_providers]` instead
    // of letting the child `[model_providers.vouch]` header own the
    // section, which clutters the file.
    if let Some(providers_tbl) = providers.as_table_mut() {
        providers_tbl.set_implicit(true);
        providers_tbl.insert(PROVIDER_ID, Item::Table(provider));
    }
}

fn print_success(config_path: &Path) {
    println!("OpenAI Workload Identity Federation configured.\n");
    println!("  Federation params: ~/.vouch/config.json");
    println!(
        "  Codex provider block: {} ([model_providers.{PROVIDER_ID}])\n",
        config_path.display()
    );

    println!("NOTE: OpenAI must onboard the Vouch issuer as a workload identity provider");
    println!("      before this works — custom OIDC issuers are not self-service. Contact");
    println!("      OpenAI to register your Vouch base URL.\n");

    println!("Get a token:");
    println!("  vouch login              # YubiKey tap, once per session");
    println!("  vouch credential openai  # prints a short-lived OpenAI access token\n");

    println!("Ensure OPENAI_API_KEY is UNSET in every environment Codex runs in —");
    println!("it shadows the configured auth command.\n");

    println!("Note: the [model_providers.vouch] block is owned by `vouch setup openai` —");
    println!("re-running this command overwrites it. Edit the top-level `model_provider`");
    println!("if you want to switch Codex back to a different provider.");
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    fn doc_from(s: &str) -> DocumentMut {
        s.parse().expect("valid toml")
    }

    #[test]
    fn test_write_provider_block_into_empty_doc() {
        let mut doc = DocumentMut::new();
        write_provider_block(&mut doc, "/usr/local/bin/vouch");
        let rendered = doc.to_string();
        assert!(rendered.contains("[model_providers.vouch]"));
        assert!(rendered.contains("[model_providers.vouch.auth]"));
        assert!(rendered.contains("command = \"/usr/local/bin/vouch\""));
        assert!(rendered.contains("args = [\"credential\", \"openai\"]"));
        assert!(rendered.contains("refresh_interval_ms = 300000"));
    }

    /// Existing `[model_providers.openai]` entries must survive — we only
    /// touch our own `vouch` key.
    #[test]
    fn test_write_provider_block_preserves_other_providers() {
        let mut doc = doc_from(
            r#"
[model_providers.openai]
name = "openai"
base_url = "https://api.openai.com/v1"
"#,
        );
        write_provider_block(&mut doc, "/bin/vouch");
        let rendered = doc.to_string();
        assert!(rendered.contains("[model_providers.openai]"));
        assert!(rendered.contains("[model_providers.vouch]"));
    }

    #[test]
    fn test_check_conflicts_passes_on_empty_doc() {
        let doc = DocumentMut::new();
        let path = PathBuf::from("/tmp/codex.toml");
        assert!(check_conflicts(&doc, &path, false).is_ok());
    }

    #[test]
    fn test_check_conflicts_passes_on_matching_top_level_provider() {
        let doc = doc_from(r#"model_provider = "vouch""#);
        let path = PathBuf::from("/tmp/codex.toml");
        assert!(check_conflicts(&doc, &path, false).is_ok());
    }

    #[test]
    fn test_check_conflicts_errors_on_different_top_level_provider() {
        let doc = doc_from(r#"model_provider = "openai""#);
        let path = PathBuf::from("/tmp/codex.toml");
        let err = check_conflicts(&doc, &path, false).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("model_provider"));
        assert!(msg.contains("--force"));
    }

    /// Pre-existing `[model_providers.vouch]` block from an earlier
    /// run is OURS to update — must not require `--force`. Only the
    /// top-level `model_provider` selector is shared with the user.
    #[test]
    fn test_check_conflicts_ignores_existing_vouch_provider_block() {
        let doc = doc_from(
            r#"
[model_providers.vouch.auth]
command = "/old/path/vouch"
"#,
        );
        let path = PathBuf::from("/tmp/codex.toml");
        assert!(check_conflicts(&doc, &path, false).is_ok());
    }

    #[test]
    fn test_check_conflicts_force_overrides_top_level_conflict() {
        let doc = doc_from(r#"model_provider = "openai""#);
        let path = PathBuf::from("/tmp/codex.toml");
        assert!(check_conflicts(&doc, &path, true).is_ok());
    }
}
