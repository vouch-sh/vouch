// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration utilities and status checking for cloud providers and services.
//!
//! This module provides:
//! - Integration-specific utilities (config parsing, API clients)
//! - A trait-based system for checking configuration status
//!
//! Each integration is organized as a submodule containing both utilities
//! and status checking (AWS, Cargo, GitHub, EKS, SSH, Docker).

pub mod aws;
pub mod cargo;
pub mod docker;
pub mod eks;
pub mod github;
pub mod ssh;
pub mod ssm;

pub use aws::AwsIntegration;
pub use cargo::CargoIntegration;
pub use docker::DockerIntegration;
pub use eks::EksIntegration;
pub use github::GitHubIntegration;
pub use ssh::SshIntegration;
pub use ssm::SsmIntegration;

use crate::style;

/// Width for left-aligned integration labels (e.g., "SSH:", "Expires:").
pub(crate) const LABEL_WIDTH: usize = 8;

/// Indentation for continuation/detail lines (2 leading + 8 label + 1 space = 11).
pub(crate) const VALUE_INDENT: &str = "           ";

/// Result of checking an integration's status.
pub enum IntegrationState {
    /// Integration is fully configured and ready.
    Configured(ConfiguredDetails),
    /// Integration is not configured.
    NotConfigured { setup_hint: String },
    /// Integration is partially configured or has issues.
    Partial {
        message: String,
        setup_hint: Option<String>,
    },
}

/// Details about a configured integration.
pub struct ConfiguredDetails {
    /// Summary line (e.g., "profile: vouch").
    pub summary: String,
    /// Additional key-value details to display.
    pub details: Vec<(String, String)>,
}

/// Trait for checking integration status synchronously.
pub trait IntegrationCheck {
    /// Name of the integration (e.g., "SSH", "AWS").
    fn name(&self) -> &'static str;

    /// Check the integration status.
    fn check(&self) -> IntegrationState;
}

/// Print the status of a synchronous integration check.
pub fn print_integration_status<I: IntegrationCheck>(integration: &I) {
    let name = integration.name();
    let label = format!("{name}:");
    match integration.check() {
        IntegrationState::Configured(details) => {
            println!(
                "  {label:<LABEL_WIDTH$} {} ({})",
                style::green("configured"),
                details.summary
            );
            for (key, value) in details.details {
                println!("{VALUE_INDENT}{key}: {value}");
            }
        }
        IntegrationState::NotConfigured { setup_hint } => {
            println!("  {label:<LABEL_WIDTH$} {}", style::dim("not configured"));
            println!(
                "{VALUE_INDENT}{}",
                style::dim(&format!("Run: {setup_hint}"))
            );
        }
        IntegrationState::Partial {
            message,
            setup_hint,
        } => {
            println!("  {label:<LABEL_WIDTH$} {}", style::yellow(&message));
            if let Some(hint) = setup_hint {
                println!("{VALUE_INDENT}{}", style::dim(&format!("Run: {hint}")));
            }
        }
    }
}
