// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Docker integration status checking.

use crate::commands::setup::docker::{DockerSetupStatus, check_docker_config};
use crate::integrations::{ConfiguredDetails, IntegrationCheck, IntegrationState};

/// Docker integration checker.
pub struct DockerIntegration;

impl DockerIntegration {
    /// Create a new Docker integration checker.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for DockerIntegration {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrationCheck for DockerIntegration {
    fn name(&self) -> &'static str {
        "Docker"
    }

    fn check(&self) -> IntegrationState {
        let status = check_docker_config();
        check_docker_status(&status)
    }
}

/// Check Docker integration status.
fn check_docker_status(status: &DockerSetupStatus) -> IntegrationState {
    if !status.symlink_exists && status.configured_registries.is_empty() {
        return IntegrationState::NotConfigured {
            setup_hint: "vouch setup docker --configure".to_string(),
        };
    }

    if !status.symlink_exists {
        return IntegrationState::Partial {
            message: "credential helper not installed".to_string(),
            setup_hint: Some("vouch setup docker --configure".to_string()),
        };
    }

    if status.configured_registries.is_empty() {
        return IntegrationState::Partial {
            message: "no registries configured".to_string(),
            setup_hint: Some("vouch setup docker --configure <registry>".to_string()),
        };
    }

    // Fully configured
    let summary = if let [registry] = status.configured_registries.as_slice() {
        format!("1 registry: {registry}")
    } else {
        format!("{} registries", status.configured_registries.len())
    };

    let details: Vec<(String, String)> = status
        .configured_registries
        .iter()
        .map(|r| ("registry".to_string(), r.clone()))
        .collect();

    IntegrationState::Configured(ConfiguredDetails { summary, details })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_configured() {
        let status = DockerSetupStatus {
            symlink_exists: false,
            configured_registries: vec![],
        };
        let result = check_docker_status(&status);
        assert!(matches!(result, IntegrationState::NotConfigured { .. }));
    }

    #[test]
    fn test_partial_no_symlink() {
        let status = DockerSetupStatus {
            symlink_exists: false,
            configured_registries: vec!["ghcr.io".to_string()],
        };
        let result = check_docker_status(&status);
        assert!(matches!(result, IntegrationState::Partial { .. }));
    }

    #[test]
    fn test_partial_no_registries() {
        let status = DockerSetupStatus {
            symlink_exists: true,
            configured_registries: vec![],
        };
        let result = check_docker_status(&status);
        assert!(matches!(result, IntegrationState::Partial { .. }));
    }

    #[test]
    fn test_configured() {
        let status = DockerSetupStatus {
            symlink_exists: true,
            configured_registries: vec!["ghcr.io".to_string(), "123456789012.dkr.ecr.us-east-1.amazonaws.com".to_string()],
        };
        let result = check_docker_status(&status);
        assert!(matches!(result, IntegrationState::Configured(_)));
    }
}
