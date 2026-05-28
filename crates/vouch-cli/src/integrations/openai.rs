// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OpenAI Workload Identity Federation integration status.

use toml_edit::{DocumentMut, Item};

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};
use crate::config::Config;

/// OpenAI federation integration checker.
pub(crate) struct OpenAiIntegration;

impl OpenAiIntegration {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Default for OpenAiIntegration {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrationCheck for OpenAiIntegration {
    fn name(&self) -> &'static str {
        "OpenAI"
    }

    fn check(&self) -> IntegrationState {
        let Ok(config) = Config::load() else {
            return IntegrationState::NotConfigured {
                setup_hint: "vouch setup openai".to_string(),
            };
        };
        let Some(fed) = config.ai().and_then(|ai| ai.openai.as_ref()) else {
            return IntegrationState::NotConfigured {
                setup_hint: "vouch setup openai".to_string(),
            };
        };

        let summary = format!("provider: {}", fed.identity_provider_id);
        let mut details = vec![(
            "service_account".to_string(),
            fed.service_account_id.clone(),
        )];
        if let Some(aud) = fed.audience.as_deref() {
            details.push(("audience".to_string(), aud.to_string()));
        }

        match codex_provider_state() {
            CodexProviderState::Vouch => {
                IntegrationState::Configured(ConfiguredDetails { summary, details })
            }
            CodexProviderState::Missing => IntegrationState::Partial {
                message: "Codex model_provider not set to vouch".to_string(),
                setup_hint: Some("vouch setup openai".to_string()),
            },
            CodexProviderState::Other(name) => IntegrationState::Partial {
                message: format!("Codex model_provider is {name:?}"),
                setup_hint: Some("vouch setup openai --force".to_string()),
            },
        }
    }
}

/// Observed state of `~/.codex/config.toml`'s top-level `model_provider`.
pub(crate) enum CodexProviderState {
    /// `model_provider = "vouch"`.
    Vouch,
    /// The file or the key is absent.
    Missing,
    /// `model_provider` is set to a different provider id.
    Other(String),
}

/// Inspect `~/.codex/config.toml` for the top-level `model_provider`.
pub(crate) fn codex_provider_state() -> CodexProviderState {
    let Some(home) = dirs::home_dir() else {
        return CodexProviderState::Missing;
    };
    let config_path = home.join(".codex").join("config.toml");
    let Ok(content) = std::fs::read_to_string(&config_path) else {
        return CodexProviderState::Missing;
    };
    let Ok(doc) = content.parse::<DocumentMut>() else {
        return CodexProviderState::Missing;
    };
    let Some(provider) = doc.get("model_provider").and_then(Item::as_str) else {
        return CodexProviderState::Missing;
    };
    if provider == "vouch" {
        CodexProviderState::Vouch
    } else {
        CodexProviderState::Other(provider.to_string())
    }
}
