// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GCP integration status checking.

use serde::Deserialize;
use std::path::PathBuf;

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};

/// GCP integration checker.
pub struct GcpIntegration;

impl GcpIntegration {
    /// Create a new GCP integration checker.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for GcpIntegration {
    fn default() -> Self {
        Self::new()
    }
}

/// A GCP credential profile.
struct GcpProfile {
    filename: String,
    audience: Option<String>,
}

/// GCP external account credential configuration (for parsing).
#[derive(Debug, Deserialize)]
struct GcpExternalAccountConfig {
    #[serde(rename = "type")]
    config_type: Option<String>,
    audience: Option<String>,
    credential_source: Option<GcpCredentialSource>,
}

#[derive(Debug, Deserialize)]
struct GcpCredentialSource {
    executable: Option<GcpExecutableConfig>,
}

#[derive(Debug, Deserialize)]
struct GcpExecutableConfig {
    command: Option<String>,
}

impl IntegrationCheck for GcpIntegration {
    fn name(&self) -> &'static str {
        "GCP"
    }

    fn check(&self) -> IntegrationState {
        let profiles = find_gcp_profiles();

        if profiles.is_empty() {
            return IntegrationState::NotConfigured {
                setup_hint: "vouch setup gcp".to_string(),
            };
        }

        match profiles.as_slice() {
            [profile] => {
                let mut details = Vec::new();
                if let Some(audience) = &profile.audience {
                    // Truncate audience if too long (safely at char boundary)
                    let display_audience = if audience.chars().count() > 60 {
                        let truncated: String = audience.chars().take(57).collect();
                        format!("{truncated}...")
                    } else {
                        audience.clone()
                    };
                    details.push(("Audience".to_string(), display_audience));
                }

                IntegrationState::Configured(ConfiguredDetails {
                    summary: profile.filename.clone(),
                    details,
                })
            }
            _ => {
                let details: Vec<(String, String)> = profiles
                    .iter()
                    .enumerate()
                    .map(|(i, p)| (format!("Profile {}", i + 1), p.filename.clone()))
                    .collect();

                IntegrationState::Configured(ConfiguredDetails {
                    summary: format!("{} profiles", profiles.len()),
                    details,
                })
            }
        }
    }
}

/// Get the GCP config directory (~/.config/gcloud).
fn gcp_config_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".config").join("gcloud"))
}

/// Find all Vouch GCP credential profiles.
fn find_gcp_profiles() -> Vec<GcpProfile> {
    let config_dir = match gcp_config_dir() {
        Some(d) if d.exists() => d,
        _ => return Vec::new(),
    };

    let mut profiles = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&config_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let filename = match path.file_name().and_then(|n| n.to_str()) {
                Some(f) => f.to_string(),
                None => continue,
            };

            // Check if it's a vouch credentials file
            if !filename.starts_with("vouch-credentials") || !filename.ends_with(".json") {
                continue;
            }

            // Try to parse and verify it's a vouch config
            if let Ok(content) = std::fs::read_to_string(&path)
                && let Ok(profile) = parse_gcp_config(&content, &filename)
            {
                profiles.push(profile);
            }
        }
    }

    profiles
}

/// Parse GCP external account config and verify it's a vouch config.
/// Returns None if the config is not a valid vouch credential.
fn parse_gcp_config(content: &str, filename: &str) -> Result<GcpProfile, ()> {
    let config: GcpExternalAccountConfig = serde_json::from_str(content).map_err(|_| ())?;

    // Verify it's an external_account type with vouch in the command
    let is_external_account = config
        .config_type
        .as_ref()
        .is_some_and(|t| t == "external_account");
    let has_vouch_command = config
        .credential_source
        .as_ref()
        .and_then(|cs| cs.executable.as_ref())
        .and_then(|ex| ex.command.as_ref())
        .is_some_and(|cmd| cmd.contains("vouch"));

    if is_external_account && has_vouch_command {
        Ok(GcpProfile {
            filename: filename.to_string(),
            audience: config.audience,
        })
    } else {
        Err(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gcp_config_valid() {
        let content = r#"{
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/my-pool/providers/my-provider",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": "https://sts.googleapis.com/v1/token",
            "credential_source": {
                "executable": {
                    "command": "/usr/local/bin/vouch credential gcp --audience test",
                    "timeout_millis": 5000,
                    "output_file": "/tmp/gcp-token"
                }
            }
        }"#;

        let result = parse_gcp_config(content, "vouch-credentials.json");

        assert!(result.is_ok());
        let profile = result.unwrap();
        assert_eq!(profile.filename, "vouch-credentials.json");
        assert!(profile.audience.is_some());
        assert!(profile.audience.unwrap().contains("workloadIdentityPools"));
    }

    #[test]
    fn test_parse_gcp_config_not_external_account() {
        let content = r#"{
            "type": "service_account",
            "project_id": "my-project",
            "private_key_id": "key123"
        }"#;

        let result = parse_gcp_config(content, "vouch-credentials.json");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_gcp_config_no_vouch_command() {
        let content = r#"{
            "type": "external_account",
            "audience": "//iam.googleapis.com/test",
            "credential_source": {
                "executable": {
                    "command": "/usr/bin/other-tool get-token"
                }
            }
        }"#;

        let result = parse_gcp_config(content, "vouch-credentials.json");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_gcp_config_no_executable() {
        let content = r#"{
            "type": "external_account",
            "audience": "//iam.googleapis.com/test",
            "credential_source": {
                "file": "/path/to/token"
            }
        }"#;

        let result = parse_gcp_config(content, "vouch-credentials.json");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_gcp_config_invalid_json() {
        let content = "not valid json";

        let result = parse_gcp_config(content, "vouch-credentials.json");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_gcp_config_no_audience() {
        let content = r#"{
            "type": "external_account",
            "credential_source": {
                "executable": {
                    "command": "/usr/local/bin/vouch credential gcp"
                }
            }
        }"#;

        let result = parse_gcp_config(content, "vouch-credentials.json");

        assert!(result.is_ok());
        let profile = result.unwrap();
        assert!(profile.audience.is_none());
    }

    #[test]
    fn test_parse_gcp_config_vouch_anywhere_in_command() {
        let content = r#"{
            "type": "external_account",
            "audience": "test",
            "credential_source": {
                "executable": {
                    "command": "/home/user/.local/bin/vouch credential gcp --audience test"
                }
            }
        }"#;

        let result = parse_gcp_config(content, "vouch-credentials-prod.json");

        assert!(result.is_ok());
        let profile = result.unwrap();
        assert_eq!(profile.filename, "vouch-credentials-prod.json");
    }

    // ==========================================================================
    // Config Struct Parsing Tests
    // ==========================================================================

    #[test]
    fn test_gcp_external_account_config_deserialization() {
        let json = r#"{
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
            "credential_source": {
                "executable": {
                    "command": "vouch credential gcp"
                }
            }
        }"#;

        let config: GcpExternalAccountConfig = serde_json::from_str(json).unwrap();

        assert_eq!(config.config_type, Some("external_account".to_string()));
        assert!(config.audience.is_some());
        assert!(config.credential_source.is_some());

        let source = config.credential_source.unwrap();
        assert!(source.executable.is_some());

        let exec = source.executable.unwrap();
        assert_eq!(exec.command, Some("vouch credential gcp".to_string()));
    }

    #[test]
    fn test_gcp_external_account_config_missing_optional_fields() {
        let json = r#"{
            "type": "external_account"
        }"#;

        let config: GcpExternalAccountConfig = serde_json::from_str(json).unwrap();

        assert_eq!(config.config_type, Some("external_account".to_string()));
        assert!(config.audience.is_none());
        assert!(config.credential_source.is_none());
    }
}
