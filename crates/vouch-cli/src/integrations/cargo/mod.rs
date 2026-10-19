// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo integration utilities and status checking.

mod config;

pub(crate) use config::CargoConfig;

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};
use crate::integrations::aws::codeartifact;

/// How to configure Cargo; the only way is per CodeArtifact registry.
const SETUP_HINT: &str = "vouch setup codeartifact --tool cargo --repository <name>";

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
        match CargoConfig::load() {
            Ok(config) => state_for(&config),
            Err(_) => not_configured(),
        }
    }
}

fn not_configured() -> IntegrationState {
    IntegrationState::NotConfigured {
        setup_hint: SETUP_HINT.to_string(),
    }
}

/// Status for a loaded Cargo config. Only a registry whose index is a
/// CodeArtifact URL counts as configured: the provider answers
/// `url-not-supported` for every other registry, so one set up with Vouch is
/// reported as not served.
fn state_for(config: &CargoConfig) -> IntegrationState {
    let mut unserved = Vec::new();
    for registry in config.vouch_registries() {
        let Some(ca) = config
            .get_registry_index(&registry)
            .as_deref()
            .and_then(codeartifact::parse_codeartifact_url)
        else {
            unserved.push(registry);
            continue;
        };
        return IntegrationState::Configured(ConfiguredDetails {
            summary: format!("CodeArtifact registry: {registry}"),
            details: vec![(
                "CodeArtifact".to_string(),
                format!("{}/{}", ca.domain, ca.region),
            )],
        });
    }
    match unserved.first() {
        Some(registry) => IntegrationState::Partial {
            message: format!("registry {registry} uses Vouch, which only serves CodeArtifact"),
            setup_hint: Some(SETUP_HINT.to_string()),
        },
        None => not_configured(),
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

    fn create_temp_config(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        file.write_all(content.as_bytes())
            .expect("failed to write temp file");
        file
    }

    fn check_status_from_content(content: &str) -> IntegrationState {
        let file = create_temp_config(content);
        let config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();
        state_for(&config)
    }

    fn assert_not_configured(state: IntegrationState) {
        match state {
            IntegrationState::NotConfigured { setup_hint } => {
                assert!(setup_hint.contains("vouch setup codeartifact --tool cargo"));
            }
            _ => panic!("expected NotConfigured state"),
        }
    }

    fn assert_not_served(state: IntegrationState, registry: &str) {
        match state {
            IntegrationState::Partial {
                message,
                setup_hint,
            } => {
                assert!(message.contains(registry) && message.contains("only serves CodeArtifact"));
                assert!(setup_hint.is_some_and(|h| h.contains("setup codeartifact")));
            }
            _ => panic!("expected Partial state"),
        }
    }

    #[test]
    fn test_codeartifact_registry_configured() {
        let content = r#"
[registries.my-registry]
index = "sparse+https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/r/"
credential-provider = ["/usr/local/bin/vouch"]
"#;

        match check_status_from_content(content) {
            IntegrationState::Configured(details) => {
                assert_eq!(details.summary, "CodeArtifact registry: my-registry");
                assert_eq!(
                    details.details,
                    [(
                        "CodeArtifact".to_string(),
                        "my-domain/us-east-1".to_string()
                    )]
                );
            }
            _ => panic!("expected Configured state"),
        }
    }

    // The provider answers `url-not-supported` for a registry that is not
    // CodeArtifact, so configuring Vouch for one is not a working setup.
    #[test]
    fn test_non_codeartifact_registry_is_not_served() {
        let content = r#"
[registries.other]
index = "sparse+https://registry.example.com/index/"
credential-provider = ["/usr/local/bin/vouch"]
"#;
        assert_not_served(check_status_from_content(content), "other");
    }

    #[test]
    fn test_registry_without_index_is_not_served() {
        let content = r#"
[registries.other]
credential-provider = ["/usr/local/bin/vouch"]
"#;
        assert_not_served(check_status_from_content(content), "other");
    }

    // A later CodeArtifact registry still counts when an earlier Vouch registry
    // is not one.
    #[test]
    fn test_skips_non_codeartifact_registry_before_codeartifact_one() {
        let content = r#"
[registries.a-other]
index = "sparse+https://registry.example.com/index/"
credential-provider = ["/usr/local/bin/vouch"]

[registries.b-ca]
index = "sparse+https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/r/"
credential-provider = ["/usr/local/bin/vouch"]
"#;
        match check_status_from_content(content) {
            IntegrationState::Configured(details) => {
                assert_eq!(details.summary, "CodeArtifact registry: b-ca");
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
        assert_not_configured(check_status_from_content(content));
    }

    #[test]
    fn test_empty_config() {
        assert_not_configured(check_status_from_content(""));
    }
}
