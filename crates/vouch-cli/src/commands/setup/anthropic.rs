// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch setup anthropic` — persist Anthropic Workload Identity Federation
//! parameters and tell the user how to launch Claude Code against them.
//!
//! Earlier versions of this command wrote an `apiKeyHelper` entry into
//! `~/.claude/settings.json` pointing at `vouch credential anthropic`. That
//! is structurally broken for the `sk-ant-oat01-*` OAuth tokens vouch
//! issues: Claude Code sends `apiKeyHelper` output as **both** the
//! `X-Api-Key` and `Authorization: Bearer` headers, and the Anthropic API
//! rejects OAuth tokens via `X-Api-Key`. The validated path is the
//! `ANTHROPIC_AUTH_TOKEN` env var, which is sent only as the Bearer
//! header.
//!
//! This command now only persists federation params to
//! `~/.vouch/config.json` and, if a previous setup run left the broken
//! `apiKeyHelper` + `CLAUDE_CODE_API_KEY_HELPER_TTL_MS` pair in
//! `~/.claude/settings.json`, removes them. Any other settings the user
//! has configured are left untouched.

use std::path::PathBuf;

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
    // Confirm the user has actually enrolled before persisting federation
    // params. Config::load() succeeds on an empty file, so we have to
    // check that a server context exists.
    let config = Config::load().context("failed to load Vouch config")?;
    let _server = config
        .server_url()
        .context("not configured — run 'vouch enroll' first")?;

    let cleanup = remove_stale_claude_code_helper()?;

    let fed = AnthropicFederation {
        federation_rule_id: args.federation_rule_id.to_string(),
        organization_id: args.organization_id.to_string(),
        service_account_id: args.service_account_id.to_string(),
        workspace_id: args.workspace_id.to_string(),
        audience: args.audience.map(str::to_string),
        token_endpoint: args.token_endpoint.map(str::to_string),
    };
    Config::modify(move |c| c.set_ai_anthropic(fed))?;

    print_success(cleanup);
    Ok(())
}

/// Outcome of inspecting `~/.claude/settings.json` for stale entries left
/// by previous versions of this command.
struct CleanupOutcome {
    /// Path we inspected (returned even when nothing was removed, so the
    /// success message can reference it).
    settings_path: PathBuf,
    /// True iff a stale `apiKeyHelper` or
    /// `env.CLAUDE_CODE_API_KEY_HELPER_TTL_MS` was found and removed.
    removed: bool,
}

/// Remove stale `apiKeyHelper` and `CLAUDE_CODE_API_KEY_HELPER_TTL_MS`
/// entries from `~/.claude/settings.json` if present. Touches nothing else.
fn remove_stale_claude_code_helper() -> Result<CleanupOutcome> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let settings_path = home.join(".claude").join("settings.json");

    if !settings_path.exists() {
        return Ok(CleanupOutcome {
            settings_path,
            removed: false,
        });
    }

    let content = std::fs::read_to_string(&settings_path)
        .with_context(|| format!("failed to read {}", settings_path.display()))?;
    let mut settings: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse {}", settings_path.display()))?;

    let removed = strip_stale_keys(&mut settings);
    if !removed {
        return Ok(CleanupOutcome {
            settings_path,
            removed: false,
        });
    }

    let json = serde_json::to_string_pretty(&settings)
        .context("failed to serialize Claude Code settings")?;
    crate::utils::atomic_write(&settings_path, json.as_bytes())
        .with_context(|| format!("failed to write {}", settings_path.display()))?;

    Ok(CleanupOutcome {
        settings_path,
        removed: true,
    })
}

/// The exact TTL value previous versions of this command wrote alongside
/// `apiKeyHelper`. Used as a fingerprint when deciding whether the TTL
/// env var is ours to remove.
const STALE_HELPER_TTL_MS: &str = "3000000";

/// Suffix that uniquely identifies an `apiKeyHelper` command vouch wrote.
/// The leading path can vary (Homebrew, cargo-installed, etc.) and may be
/// POSIX-quoted, but the trailing subcommand is always the same.
const STALE_HELPER_SUFFIX: &str = " credential anthropic";

/// Remove `apiKeyHelper` and `env.CLAUDE_CODE_API_KEY_HELPER_TTL_MS` from
/// the given JSON value — but only when they look like values a previous
/// `vouch setup anthropic` run wrote. A user-customized `apiKeyHelper`
/// pointing at an unrelated tool is left alone.
///
/// The TTL env var is only removed when we also removed our own
/// `apiKeyHelper` and the TTL value matches what we wrote. The TTL is a
/// generic Claude Code knob; if vouch's helper is gone the user may want
/// to keep it for a different helper they added later.
///
/// Operates on `serde_json::Value` so it can be exercised in unit tests
/// without touching disk.
fn strip_stale_keys(settings: &mut serde_json::Value) -> bool {
    let Some(obj) = settings.as_object_mut() else {
        return false;
    };

    let helper_is_ours = obj
        .get("apiKeyHelper")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| s.ends_with(STALE_HELPER_SUFFIX));

    let mut removed = false;
    if helper_is_ours {
        obj.remove("apiKeyHelper");
        removed = true;

        if let Some(env) = obj
            .get_mut("env")
            .and_then(serde_json::Value::as_object_mut)
            && env
                .get("CLAUDE_CODE_API_KEY_HELPER_TTL_MS")
                .and_then(serde_json::Value::as_str)
                == Some(STALE_HELPER_TTL_MS)
        {
            env.remove("CLAUDE_CODE_API_KEY_HELPER_TTL_MS");
        }
    }

    removed
}

fn print_success(cleanup: CleanupOutcome) {
    println!("Anthropic (Claude) Workload Identity Federation configured.\n");
    println!("  Federation params: ~/.vouch/config.json\n");

    if cleanup.removed {
        println!(
            "Cleaned up a previously-configured Claude Code apiKeyHelper from {}.",
            cleanup.settings_path.display()
        );
        println!("(That config is incompatible with vouch's OAuth tokens — the Anthropic API");
        println!(
            "rejects sk-ant-oat01-* tokens via the X-Api-Key header that apiKeyHelper sets.)\n"
        );
    }

    println!("Get a token:");
    println!("  vouch login                 # YubiKey tap, once per session");
    println!("  vouch credential anthropic  # prints sk-ant-oat01-...\n");

    println!("Launch Claude Code with the token:");
    println!("  ANTHROPIC_AUTH_TOKEN=$(vouch credential anthropic) claude\n");

    println!("The token is fixed for the Claude Code session. When it expires");
    println!("(typically ~1 hour), restart Claude with the same command.\n");

    println!("Ensure ANTHROPIC_API_KEY is UNSET in every environment Claude Code");
    println!("runs in — it takes precedence over ANTHROPIC_AUTH_TOKEN and will");
    println!("silently shadow federation.");
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_vouch_helper_and_matching_ttl() {
        let mut v = serde_json::json!({
            "apiKeyHelper": "/usr/local/bin/vouch credential anthropic",
            "theme": "dark",
            "env": {
                "CLAUDE_CODE_API_KEY_HELPER_TTL_MS": "3000000",
                "DISABLE_TELEMETRY": "1"
            }
        });
        assert!(strip_stale_keys(&mut v));
        assert!(v.get("apiKeyHelper").is_none());
        assert_eq!(v["theme"], "dark");
        let env = v["env"].as_object().expect("env object");
        assert!(env.get("CLAUDE_CODE_API_KEY_HELPER_TTL_MS").is_none());
        assert_eq!(env["DISABLE_TELEMETRY"], "1");
    }

    /// Helper paths can be POSIX-quoted (old code path-quoted any path
    /// containing a space). The `credential anthropic` subcommand is the
    /// stable suffix we match on.
    #[test]
    fn strip_removes_helper_with_quoted_path() {
        let mut v = serde_json::json!({
            "apiKeyHelper": "'/Applications/Vouch Tools/vouch' credential anthropic"
        });
        assert!(strip_stale_keys(&mut v));
        assert!(v.get("apiKeyHelper").is_none());
    }

    /// A user's own `apiKeyHelper` pointing at an unrelated tool must be
    /// preserved. This is the core "don't nuke user config" guarantee.
    #[test]
    fn strip_preserves_unrelated_helper() {
        let mut v = serde_json::json!({
            "apiKeyHelper": "/usr/local/bin/my-corporate-helper.sh"
        });
        let before = v.clone();
        assert!(!strip_stale_keys(&mut v));
        assert_eq!(v, before);
    }

    /// The trailing-subcommand match must be precise. A helper that
    /// happens to *contain* "credential anthropic" mid-string (e.g., a
    /// wrapper that calls it then does something else) is not ours.
    #[test]
    fn strip_preserves_helper_with_substring_only() {
        let mut v = serde_json::json!({
            "apiKeyHelper": "vouch credential anthropic | tee /tmp/log"
        });
        let before = v.clone();
        assert!(!strip_stale_keys(&mut v));
        assert_eq!(v, before);
    }

    /// If our helper is gone but the TTL was tweaked to a non-default
    /// value, leave it — the user likely set it for a different helper.
    #[test]
    fn strip_preserves_ttl_with_custom_value() {
        let mut v = serde_json::json!({
            "apiKeyHelper": "/usr/local/bin/vouch credential anthropic",
            "env": { "CLAUDE_CODE_API_KEY_HELPER_TTL_MS": "60000" }
        });
        assert!(strip_stale_keys(&mut v));
        assert!(v.get("apiKeyHelper").is_none());
        assert_eq!(v["env"]["CLAUDE_CODE_API_KEY_HELPER_TTL_MS"], "60000");
    }

    /// TTL must not be touched when there's no vouch helper present, even
    /// if its value matches what we'd write.
    #[test]
    fn strip_preserves_ttl_when_no_vouch_helper() {
        let mut v = serde_json::json!({
            "env": { "CLAUDE_CODE_API_KEY_HELPER_TTL_MS": "3000000" }
        });
        let before = v.clone();
        assert!(!strip_stale_keys(&mut v));
        assert_eq!(v, before);
    }

    #[test]
    fn strip_is_noop_when_keys_absent() {
        let mut v = serde_json::json!({
            "theme": "dark",
            "env": { "DISABLE_TELEMETRY": "1" }
        });
        let before = v.clone();
        assert!(!strip_stale_keys(&mut v));
        assert_eq!(v, before);
    }

    #[test]
    fn strip_handles_non_object_root() {
        let mut v = serde_json::json!([]);
        assert!(!strip_stale_keys(&mut v));
    }

    /// A non-string `apiKeyHelper` value isn't ours (settings.json schema
    /// has it as a string, but defensive against malformed input).
    #[test]
    fn strip_preserves_non_string_helper() {
        let mut v = serde_json::json!({ "apiKeyHelper": 42 });
        let before = v.clone();
        assert!(!strip_stale_keys(&mut v));
        assert_eq!(v, before);
    }

    /// Our helper removal must not fail when `env` is malformed — leave
    /// the env value as-is in that case.
    #[test]
    fn strip_handles_non_object_env() {
        let mut v = serde_json::json!({
            "apiKeyHelper": "/usr/local/bin/vouch credential anthropic",
            "env": "not-an-object"
        });
        assert!(strip_stale_keys(&mut v));
        assert!(v.get("apiKeyHelper").is_none());
        assert_eq!(v["env"], "not-an-object");
    }
}
