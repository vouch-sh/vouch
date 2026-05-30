// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch setup anthropic` — persist Anthropic Workload Identity Federation
//! parameters and auto-configure Claude Code's credential helper.
//!
//! Writes / merges `~/.claude/settings.json` to set:
//!
//! - `apiKeyHelper` → `<vouch> credential anthropic`
//! - `env.CLAUDE_CODE_API_KEY_HELPER_TTL_MS` → `3000000` (~50 min — refreshes
//!   before the ~1 h provider token expires)
//!
//! If Claude Code already has a different `apiKeyHelper`, the command errors
//! and asks the user to either remove it or re-run with `--force`. This is
//! deliberate: configuring Vouch for an AI provider is meant to be the
//! workforce default, not silently merge with another helper.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::{AnthropicFederation, Config};
use crate::install_path::resolve_install_path;

/// Refresh interval injected into Claude Code's environment so the
/// `apiKeyHelper` is actually re-invoked before the short-lived provider
/// token expires. ~50 minutes is comfortably under the ~1 h Anthropic
/// federation token lifetime.
const HELPER_TTL_MS: &str = "3000000";

/// Arguments captured by the clap `Anthropic` setup variant.
pub(crate) struct SetupArgs<'a> {
    pub federation_rule_id: &'a str,
    pub organization_id: &'a str,
    pub service_account_id: &'a str,
    pub workspace_id: &'a str,
    pub audience: Option<&'a str>,
    pub token_endpoint: Option<&'a str>,
    pub force: bool,
}

/// Run `vouch setup anthropic`.
pub(crate) async fn run(args: SetupArgs<'_>) -> Result<()> {
    // Confirm the user has actually enrolled before mutating anything —
    // Config::load() succeeds on an empty file, so we have to check that a
    // server context exists. Otherwise we'd happily write a wired
    // apiKeyHelper for a machine that can't get a Vouch session, and the
    // user would only discover the problem when Claude Code starts erroring.
    let config = Config::load().context("failed to load Vouch config")?;
    let _server = config
        .server_url()
        .context("not configured — run 'vouch enroll' first")?;

    let vouch_path = resolve_install_path().display().to_string();
    // `apiKeyHelper` is a shell command string executed via `/bin/sh`, so any
    // path containing a space (or other shell-special character) must be
    // POSIX-quoted to survive word-splitting.
    let helper_command = format!("{} credential anthropic", posix_shell_quote(&vouch_path));

    // Configure Claude Code FIRST so a conflict error doesn't leave the
    // user with persisted Vouch state pointing at an unwired helper.
    let settings_path = configure_claude_code(&helper_command, args.force)?;

    let fed = AnthropicFederation {
        federation_rule_id: args.federation_rule_id.to_string(),
        organization_id: args.organization_id.to_string(),
        service_account_id: args.service_account_id.to_string(),
        workspace_id: args.workspace_id.to_string(),
        audience: args.audience.map(str::to_string),
        token_endpoint: args.token_endpoint.map(str::to_string),
    };
    Config::modify(move |c| c.set_ai_anthropic(fed))?;

    print_success(&settings_path);
    Ok(())
}

/// Write/merge Claude Code's `~/.claude/settings.json`. Errors out if an
/// existing `apiKeyHelper` differs from ours, unless `force` is set.
fn configure_claude_code(helper_command: &str, force: bool) -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let settings_path = home.join(".claude").join("settings.json");

    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)
            .with_context(|| format!("failed to read {}", settings_path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("failed to parse {}", settings_path.display()))?
    } else {
        serde_json::json!({})
    };

    // Conflict check: only error when an existing helper is configured AND
    // it isn't the one we'd install. An exact match is idempotent.
    if let Some(existing) = settings
        .get("apiKeyHelper")
        .and_then(serde_json::Value::as_str)
        && existing != helper_command
        && !force
    {
        anyhow::bail!(
            "Claude Code already has an apiKeyHelper configured in {}:\n  \
             {existing}\n\n\
             Remove the `apiKeyHelper` entry from settings.json, or re-run \
             `vouch setup anthropic --force` to overwrite it.",
            settings_path.display(),
        );
    }

    let obj = settings
        .as_object_mut()
        .context("~/.claude/settings.json root must be a JSON object")?;
    obj.insert(
        "apiKeyHelper".to_string(),
        serde_json::Value::String(helper_command.to_string()),
    );

    // Inject env.CLAUDE_CODE_API_KEY_HELPER_TTL_MS, preserving any other env
    // vars the user has set. This is paired with apiKeyHelper and is
    // overwritten without warning (the user wouldn't set it independently).
    let env_entry = obj
        .entry("env".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let env_obj = env_entry
        .as_object_mut()
        .context("~/.claude/settings.json `env` must be a JSON object")?;
    env_obj.insert(
        "CLAUDE_CODE_API_KEY_HELPER_TTL_MS".to_string(),
        serde_json::Value::String(HELPER_TTL_MS.to_string()),
    );

    ensure_parent_dir(&settings_path)?;
    let json = serde_json::to_string_pretty(&settings)
        .context("failed to serialize Claude Code settings")?;
    crate::utils::atomic_write(&settings_path, json.as_bytes())
        .with_context(|| format!("failed to write {}", settings_path.display()))?;

    Ok(settings_path)
}

/// POSIX-quote a string for safe embedding in a `/bin/sh` command line.
///
/// Returns the input unchanged when it contains only safe characters
/// (`[A-Za-z0-9_\-./+:@]`). Otherwise wraps it in single quotes using the
/// `'foo'\''bar'` idiom, which preserves every byte literally — there is no
/// metacharacter that can survive single-quoting in POSIX shells, including
/// spaces, `$`, backticks, `\`, and newlines.
fn posix_shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '.' | '+' | ':' | '@')
        });
    if safe {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

fn print_success(settings_path: &Path) {
    println!("Anthropic (Claude) Workload Identity Federation configured.\n");
    println!("  Federation params: ~/.vouch/config.json");
    println!(
        "  Claude Code helper: {} (apiKeyHelper + TTL env)\n",
        settings_path.display()
    );

    println!("Get a token:");
    println!("  vouch login                 # YubiKey tap, once per session");
    println!("  vouch credential anthropic  # prints sk-ant-oat01-...\n");

    println!("Ensure ANTHROPIC_API_KEY is UNSET in every environment Claude Code");
    println!("runs in — it sits above the helper in the credential precedence chain");
    println!("and will silently shadow federation.\n");

    println!("Smoke test:");
    println!("  curl -sS https://api.anthropic.com/v1/messages \\");
    println!("    -H \"authorization: Bearer $(vouch credential anthropic)\" \\");
    println!("    -H \"anthropic-version: 2023-06-01\" \\");
    println!("    -H \"content-type: application/json\" \\");
    println!(
        "    -d '{{\"model\":\"claude-sonnet-4-6\",\"max_tokens\":64,\"messages\":[{{\"role\":\"user\",\"content\":\"hi\"}}]}}'"
    );
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// Verify the JSON merge logic preserves unrelated keys and adds the
    /// expected `apiKeyHelper` + `env.CLAUDE_CODE_API_KEY_HELPER_TTL_MS`
    /// entries. Operates on an in-memory Value to avoid touching disk in
    /// tests.
    fn merge(existing: serde_json::Value, helper: &str) -> serde_json::Value {
        let mut settings = existing;
        let obj = settings.as_object_mut().expect("object");
        obj.insert(
            "apiKeyHelper".to_string(),
            serde_json::Value::String(helper.to_string()),
        );
        let env = obj
            .entry("env".to_string())
            .or_insert_with(|| serde_json::json!({}));
        env.as_object_mut().expect("env object").insert(
            "CLAUDE_CODE_API_KEY_HELPER_TTL_MS".to_string(),
            serde_json::Value::String(HELPER_TTL_MS.to_string()),
        );
        settings
    }

    #[test]
    fn test_posix_shell_quote_plain_path_unchanged() {
        assert_eq!(
            posix_shell_quote("/usr/local/bin/vouch"),
            "/usr/local/bin/vouch"
        );
        assert_eq!(posix_shell_quote("vouch"), "vouch");
        assert_eq!(
            posix_shell_quote("/Users/jane/.cargo/bin/vouch"),
            "/Users/jane/.cargo/bin/vouch"
        );
    }

    /// The bug from review finding #8: a path containing a space must be
    /// wrapped in single quotes so `/bin/sh` doesn't split it into multiple
    /// arguments and report "command not found".
    #[test]
    fn test_posix_shell_quote_path_with_space() {
        let quoted = posix_shell_quote("/Applications/Vouch Tools/vouch");
        assert_eq!(quoted, "'/Applications/Vouch Tools/vouch'");
    }

    /// A literal `'` in the path is escaped using the POSIX
    /// `'foo'\''bar'` idiom so single-quoting stays sound.
    #[test]
    fn test_posix_shell_quote_path_with_single_quote() {
        let quoted = posix_shell_quote("/home/o'brien/vouch");
        assert_eq!(quoted, "'/home/o'\\''brien/vouch'");
    }

    /// Other shell metacharacters that would survive double-quoting (`$`,
    /// backtick, `\`) must also be neutralised. Single-quoting handles them
    /// all.
    #[test]
    fn test_posix_shell_quote_path_with_metacharacters() {
        assert_eq!(
            posix_shell_quote("/tmp/$(rm -rf)/vouch"),
            "'/tmp/$(rm -rf)/vouch'"
        );
        assert_eq!(
            posix_shell_quote("/tmp/`whoami`/vouch"),
            "'/tmp/`whoami`/vouch'"
        );
        assert_eq!(
            posix_shell_quote("/tmp/\\evil/vouch"),
            "'/tmp/\\evil/vouch'"
        );
    }

    #[test]
    fn test_posix_shell_quote_empty_string_is_quoted() {
        assert_eq!(posix_shell_quote(""), "''");
    }

    #[test]
    fn test_merge_preserves_unrelated_keys() {
        let input = serde_json::json!({
            "theme": "dark",
            "permissions": { "allow": ["Read"] },
            "env": { "FOO": "bar" }
        });
        let out = merge(input, "/usr/local/bin/vouch credential anthropic");
        assert_eq!(out["theme"], "dark");
        assert_eq!(out["permissions"]["allow"][0], "Read");
        assert_eq!(out["env"]["FOO"], "bar");
        assert_eq!(
            out["apiKeyHelper"],
            "/usr/local/bin/vouch credential anthropic"
        );
        assert_eq!(out["env"]["CLAUDE_CODE_API_KEY_HELPER_TTL_MS"], "3000000");
    }

    #[test]
    fn test_merge_creates_env_object_when_missing() {
        let input = serde_json::json!({});
        let out = merge(input, "vouch credential anthropic");
        assert!(out["env"].is_object());
        assert_eq!(out["env"]["CLAUDE_CODE_API_KEY_HELPER_TTL_MS"], "3000000");
    }
}
