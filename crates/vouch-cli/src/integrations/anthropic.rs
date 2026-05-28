// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Anthropic (Claude) Workload Identity Federation integration status.

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};
use crate::config::Config;

/// Anthropic federation integration checker.
pub(crate) struct AnthropicIntegration;

impl AnthropicIntegration {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Default for AnthropicIntegration {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrationCheck for AnthropicIntegration {
    fn name(&self) -> &'static str {
        "Claude"
    }

    fn check(&self) -> IntegrationState {
        let Ok(config) = Config::load() else {
            return IntegrationState::NotConfigured {
                setup_hint: "vouch setup anthropic".to_string(),
            };
        };
        let Some(fed) = config.ai().and_then(|ai| ai.anthropic.as_ref()) else {
            return IntegrationState::NotConfigured {
                setup_hint: "vouch setup anthropic".to_string(),
            };
        };

        let summary = format!("rule: {}", fed.federation_rule_id);
        let mut details = vec![("workspace".to_string(), fed.workspace_id.clone())];
        if let Some(aud) = fed.audience.as_deref() {
            details.push(("audience".to_string(), aud.to_string()));
        }

        // Cross-check Claude Code's apiKeyHelper. A federation persisted in
        // ~/.vouch/config.json but a Claude Code helper missing or pointing
        // somewhere else is the half-configured state worth surfacing.
        match claude_code_helper_state() {
            ClaudeCodeHelperState::Vouch => {
                IntegrationState::Configured(ConfiguredDetails { summary, details })
            }
            ClaudeCodeHelperState::Missing => IntegrationState::Partial {
                message: "Claude Code apiKeyHelper not set".to_string(),
                setup_hint: Some("vouch setup anthropic".to_string()),
            },
            ClaudeCodeHelperState::Other(cmd) => IntegrationState::Partial {
                message: format!("Claude Code apiKeyHelper points elsewhere: {cmd}"),
                setup_hint: Some("vouch setup anthropic --force".to_string()),
            },
        }
    }
}

/// Observed state of `~/.claude/settings.json`'s `apiKeyHelper` entry.
pub(crate) enum ClaudeCodeHelperState {
    /// `apiKeyHelper` is set and references `vouch credential anthropic`.
    Vouch,
    /// The file or the key is absent.
    Missing,
    /// `apiKeyHelper` is set to a command that doesn't reference vouch.
    Other(String),
}

/// Inspect `~/.claude/settings.json` for the `apiKeyHelper` entry.
///
/// Matches loosely on `vouch credential anthropic` to tolerate the
/// POSIX-shell-quoted form (e.g. `'/path with space/vouch' credential
/// anthropic`) as well as the unquoted form.
pub(crate) fn claude_code_helper_state() -> ClaudeCodeHelperState {
    let Some(home) = dirs::home_dir() else {
        return ClaudeCodeHelperState::Missing;
    };
    let settings_path = home.join(".claude").join("settings.json");
    let Ok(content) = std::fs::read_to_string(&settings_path) else {
        return ClaudeCodeHelperState::Missing;
    };
    let Ok(value): Result<serde_json::Value, _> = serde_json::from_str(&content) else {
        return ClaudeCodeHelperState::Missing;
    };
    let Some(helper) = value
        .get("apiKeyHelper")
        .and_then(serde_json::Value::as_str)
    else {
        return ClaudeCodeHelperState::Missing;
    };
    if helper.contains("vouch credential anthropic")
        || helper.contains("vouch' credential anthropic")
    {
        ClaudeCodeHelperState::Vouch
    } else {
        ClaudeCodeHelperState::Other(helper.to_string())
    }
}
