// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo integration utilities and status checking.

mod config;

pub(crate) use config::CargoConfig;

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};
use crate::config::Config;
use crate::integrations::aws::codeartifact;

const SETUP_HINT: &str = "vouch setup cargo --registry <name> --audience <aud> --configure";

/// Cargo integration checker.
pub(crate) struct CargoIntegration;

impl CargoIntegration {
    /// Create a new Cargo integration checker.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self
    }

    /// Classify the Cargo setup from the Cargo config and the Vouch config.
    ///
    /// A registry counts as configured when Vouch can answer for it: it is a
    /// CodeArtifact registry, or its index URL has an audience in the Vouch
    /// config. A legacy global provider only ever answers for CodeArtifact.
    fn state(cargo_config: &CargoConfig, vouch_config: &Config) -> IntegrationState {
        let mut unrecorded = None;
        for registry in cargo_config.vouch_registries() {
            let index_url = cargo_config.get_registry_index(&registry);
            if let Some(ca) = index_url
                .as_deref()
                .and_then(codeartifact::parse_codeartifact_url)
            {
                return IntegrationState::Configured(ConfiguredDetails {
                    summary: format!("CodeArtifact registry: {registry}"),
                    details: vec![(
                        "CodeArtifact".to_string(),
                        format!("{}/{}", ca.domain, ca.region),
                    )],
                });
            }
            if index_url
                .as_deref()
                .and_then(|url| vouch_config.cargo_registry_audience(url))
                .is_some()
            {
                return IntegrationState::Configured(ConfiguredDetails {
                    summary: format!("registry: {registry}"),
                    details: vec![],
                });
            }
            unrecorded.get_or_insert(registry);
        }

        if let Some(registry) = unrecorded {
            return IntegrationState::Partial {
                message: format!("registry {registry} has no audience in the Vouch config"),
                setup_hint: Some(SETUP_HINT.to_string()),
            };
        }

        if cargo_config.has_global_vouch() {
            return IntegrationState::Partial {
                message: "global credential provider (CodeArtifact registries only)".to_string(),
                setup_hint: Some(SETUP_HINT.to_string()),
            };
        }

        IntegrationState::NotConfigured {
            setup_hint: SETUP_HINT.to_string(),
        }
    }
}

impl Default for CargoIntegration {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrationCheck for CargoIntegration {
    fn name(&self) -> &'static str {
        "Cargo"
    }

    fn check(&self) -> IntegrationState {
        let Ok(cargo_config) = CargoConfig::load() else {
            return IntegrationState::NotConfigured {
                setup_hint: SETUP_HINT.to_string(),
            };
        };
        // An unreadable Vouch config behaves as an empty one: no registry has an audience.
        let vouch_config = Config::load().unwrap_or_default();
        Self::state(&cargo_config, &vouch_config)
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const CODEARTIFACT_INDEX: &str = "sparse+https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/my-repo/";

    fn state_from(content: &str, vouch_config: &Config) -> IntegrationState {
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        file.write_all(content.as_bytes())
            .expect("failed to write temp file");
        let cargo_config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();
        CargoIntegration::state(&cargo_config, vouch_config)
    }

    fn registry_config(index: &str) -> String {
        format!(
            "[registries.my-registry]\nindex = \"{index}\"\ncredential-provider = [\"/usr/local/bin/vouch\"]\n"
        )
    }

    #[test]
    fn test_registry_in_vouch_config_is_configured() {
        let mut vouch = Config::default();
        vouch.set_cargo_registry_audience("sparse+https://crates.example.com/", "aud");

        let state = state_from(
            &registry_config("sparse+https://crates.example.com/"),
            &vouch,
        );

        match state {
            IntegrationState::Configured(details) => {
                assert_eq!(details.summary, "registry: my-registry");
            }
            _ => panic!("expected Configured state"),
        }
    }

    #[test]
    fn test_codeartifact_registry_is_configured_without_a_vouch_entry() {
        let state = state_from(&registry_config(CODEARTIFACT_INDEX), &Config::default());

        match state {
            IntegrationState::Configured(details) => {
                assert_eq!(details.summary, "CodeArtifact registry: my-registry");
            }
            _ => panic!("expected Configured state"),
        }
    }

    #[test]
    fn test_registry_missing_from_vouch_config_is_partial() {
        let state = state_from(
            &registry_config("sparse+https://crates.example.com/"),
            &Config::default(),
        );

        match state {
            IntegrationState::Partial {
                message,
                setup_hint,
            } => {
                assert!(message.contains("my-registry"), "{message}");
                assert!(setup_hint.unwrap().contains("--audience"));
            }
            _ => panic!("expected Partial state"),
        }
    }

    #[test]
    fn test_legacy_global_provider_covers_codeartifact_only() {
        let content = r#"
[registry]
global-credential-providers = ["/usr/local/bin/vouch", "credential", "cargo", "--"]
"#;

        match state_from(content, &Config::default()) {
            IntegrationState::Partial {
                message,
                setup_hint,
            } => {
                assert!(message.contains("CodeArtifact"), "{message}");
                assert!(setup_hint.unwrap().contains("--registry"));
            }
            _ => panic!("expected Partial state"),
        }
    }

    #[test]
    fn test_not_configured() {
        let content = r#"
[registry]
global-credential-providers = ["cargo:token"]
"#;

        match state_from(content, &Config::default()) {
            IntegrationState::NotConfigured { setup_hint } => {
                assert!(setup_hint.contains("vouch setup cargo"));
            }
            _ => panic!("expected NotConfigured state"),
        }
    }

    #[test]
    fn test_empty_config() {
        match state_from("", &Config::default()) {
            IntegrationState::NotConfigured { setup_hint } => {
                assert!(setup_hint.contains("vouch setup cargo"));
            }
            _ => panic!("expected NotConfigured state"),
        }
    }
}
