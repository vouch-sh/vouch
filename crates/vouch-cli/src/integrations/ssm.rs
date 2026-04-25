// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS Systems Manager Session Manager integration status checking.

use std::io::ErrorKind;

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};
use crate::commands::setup::ssm::SSM_MARKER;

/// SSM integration checker.
pub(crate) struct SsmIntegration;

impl SsmIntegration {
    /// Create a new SSM integration checker.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Default for SsmIntegration {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether `session-manager-plugin` is installed and on PATH.
pub(crate) fn is_plugin_available() -> bool {
    match std::process::Command::new("session-manager-plugin")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            let _ = child.wait();
            true
        }
        Err(e) if e.kind() == ErrorKind::NotFound => false,
        Err(_) => false,
    }
}

impl IntegrationCheck for SsmIntegration {
    fn name(&self) -> &'static str {
        "SSM"
    }

    fn check(&self) -> IntegrationState {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => {
                return IntegrationState::NotConfigured {
                    setup_hint: "vouch setup ssm".to_string(),
                };
            }
        };

        let ssh_config_path = home.join(".ssh").join("config");
        let content = match std::fs::read_to_string(&ssh_config_path) {
            Ok(c) => c,
            Err(_) => {
                return IntegrationState::NotConfigured {
                    setup_hint: "vouch setup ssm".to_string(),
                };
            }
        };

        if !content.contains(SSM_MARKER) {
            return IntegrationState::NotConfigured {
                setup_hint: "vouch setup ssm".to_string(),
            };
        }

        // Check if session-manager-plugin is available
        let plugin_available = is_plugin_available();

        if !plugin_available {
            return IntegrationState::Partial {
                message: "configured but session-manager-plugin not on PATH".to_string(),
                setup_hint: Some(
                    "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html"
                        .to_string(),
                ),
            };
        }

        // Extract profile and region from the ProxyCommand line
        let mut details = Vec::new();
        if let Some(proxy_line) = content
            .lines()
            .find(|l| l.contains("aws ssm start-session"))
        {
            if let Some(profile) = extract_flag_value(proxy_line, "--profile") {
                details.push(("Profile".to_string(), profile));
            }
            if let Some(region) = extract_flag_value(proxy_line, "--region") {
                details.push(("Region".to_string(), region));
            }
        }

        IntegrationState::Configured(ConfiguredDetails {
            summary: "configured".to_string(),
            details,
        })
    }
}

/// Extract the value following a `--flag` in a command string.
pub(crate) fn extract_flag_value(line: &str, flag: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    while let Some(part) = parts.next() {
        if part == flag {
            return parts.next().map(|v| {
                // Strip trailing quote or backslash if present
                v.trim_end_matches('"').trim_end_matches('\'').to_string()
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_flag_value_profile() {
        let line = r#"    ProxyCommand sh -c "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p' --profile vouch --region us-east-1""#;
        assert_eq!(
            extract_flag_value(line, "--profile"),
            Some("vouch".to_string())
        );
    }

    #[test]
    fn test_extract_flag_value_region() {
        let line = r#"    ProxyCommand sh -c "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p' --profile vouch --region us-east-1""#;
        assert_eq!(
            extract_flag_value(line, "--region"),
            Some("us-east-1".to_string())
        );
    }

    #[test]
    fn test_extract_flag_value_region_with_trailing_quote() {
        let line =
            r#"    ProxyCommand sh -c "aws ssm start-session --target %h --region us-west-2""#;
        assert_eq!(
            extract_flag_value(line, "--region"),
            Some("us-west-2".to_string())
        );
    }

    #[test]
    fn test_extract_flag_value_missing() {
        let line = "aws ssm start-session --target %h";
        assert_eq!(extract_flag_value(line, "--profile"), None);
    }

    #[test]
    fn test_extract_flag_value_at_end() {
        let line = "aws ssm start-session --profile";
        assert_eq!(extract_flag_value(line, "--profile"), None);
    }
}
