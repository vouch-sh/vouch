// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo integration utilities and status checking.

mod config;

pub(crate) use config::CargoConfig;

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};
use crate::integrations::aws::codeartifact;

/// Cargo integration checker.
pub(crate) struct CargoIntegration;

impl CargoIntegration {
    /// Create a new Cargo integration checker.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self
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
        let config = match CargoConfig::load() {
            Ok(c) => c,
            Err(_) => {
                return IntegrationState::NotConfigured {
                    setup_hint: "vouch setup cargo --configure".to_string(),
                };
            }
        };

        if config.has_global_vouch() {
            return IntegrationState::Configured(ConfiguredDetails {
                summary: "global credential provider".to_string(),
                details: vec![],
            });
        }

        if let Some(registry) = config.find_vouch_registry() {
            let index_url = config.get_registry_index(&registry);
            let ca_parsed = index_url
                .as_deref()
                .and_then(codeartifact::parse_codeartifact_url);

            let details = ca_parsed
                .as_ref()
                .map(|ca| {
                    vec![(
                        "CodeArtifact".to_string(),
                        format!("{}/{}", ca.domain, ca.region),
                    )]
                })
                .unwrap_or_default();

            let summary = if ca_parsed.is_some() {
                format!("CodeArtifact registry: {registry}")
            } else {
                format!("registry: {registry}")
            };

            return IntegrationState::Configured(ConfiguredDetails { summary, details });
        }

        IntegrationState::NotConfigured {
            setup_hint: "vouch setup cargo --configure".to_string(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_config(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        file.write_all(content.as_bytes())
            .expect("failed to write temp file");
        file
    }

    fn check_status_from_content(content: &str) -> IntegrationState {
        let file = create_temp_config(content);
        let config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        if config.has_global_vouch() {
            return IntegrationState::Configured(ConfiguredDetails {
                summary: "global credential provider".to_string(),
                details: vec![],
            });
        }

        if let Some(registry) = config.find_vouch_registry() {
            return IntegrationState::Configured(ConfiguredDetails {
                summary: format!("registry: {registry}"),
                details: vec![],
            });
        }

        IntegrationState::NotConfigured {
            setup_hint: "vouch setup cargo --configure".to_string(),
        }
    }

    #[test]
    fn test_global_vouch_configured() {
        let content = r#"
[registry]
global-credential-providers = ["/usr/local/bin/vouch", "credential", "cargo", "--"]
"#;

        let state = check_status_from_content(content);
        match state {
            IntegrationState::Configured(details) => {
                assert_eq!(details.summary, "global credential provider");
            }
            _ => panic!("expected Configured state"),
        }
    }

    #[test]
    fn test_registry_vouch_configured() {
        let content = r#"
[registries.my-registry]
credential-provider = ["/usr/local/bin/vouch", "credential", "cargo", "--"]
"#;

        let state = check_status_from_content(content);
        match state {
            IntegrationState::Configured(details) => {
                assert_eq!(details.summary, "registry: my-registry");
            }
            _ => panic!("expected Configured state"),
        }
    }

    #[test]
    fn test_not_configured() {
        let content = r#"
[registry]
global-credential-providers = ["cargo:token"]
"#;

        let state = check_status_from_content(content);
        match state {
            IntegrationState::NotConfigured { setup_hint } => {
                assert!(setup_hint.contains("vouch setup cargo"));
            }
            _ => panic!("expected NotConfigured state"),
        }
    }

    #[test]
    fn test_empty_config() {
        let state = check_status_from_content("");
        match state {
            IntegrationState::NotConfigured { setup_hint } => {
                assert!(setup_hint.contains("vouch setup cargo"));
            }
            _ => panic!("expected NotConfigured state"),
        }
    }
}
