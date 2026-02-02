// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS integration utilities and status checking.
//!
//! - `config` - AWS config file (~/.aws/config) parsing
//! - `sts` - AWS STS (Security Token Service) utilities

pub mod config;
pub mod sts;

// Re-export commonly used types
pub use config::{AwsConfig, AwsProfile, extract_role_from_credential_process};

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};

/// AWS integration checker.
pub struct AwsIntegration;

impl AwsIntegration {
    /// Create a new AWS integration checker.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for AwsIntegration {
    fn default() -> Self {
        Self::new()
    }
}

/// AWS integration status details.
struct AwsStatus {
    configured: bool,
    profile_name: Option<String>,
    role_arn: Option<String>,
}

impl IntegrationCheck for AwsIntegration {
    fn name(&self) -> &'static str {
        "AWS"
    }

    fn check(&self) -> IntegrationState {
        let status = check_aws_status();

        if !status.configured {
            return IntegrationState::NotConfigured {
                setup_hint: "vouch setup aws --role <role-arn>".to_string(),
            };
        }

        let summary = status
            .profile_name
            .as_ref()
            .map(|p| {
                if p == "default" {
                    "default profile".to_string()
                } else {
                    format!("profile: {p}")
                }
            })
            .unwrap_or_else(|| "configured".to_string());

        let mut details = Vec::new();
        if let Some(role) = &status.role_arn {
            details.push(("Role".to_string(), role.clone()));
        }

        IntegrationState::Configured(ConfiguredDetails { summary, details })
    }
}

/// Check AWS integration status by reading ~/.aws/config.
fn check_aws_status() -> AwsStatus {
    let config = match AwsConfig::load() {
        Ok(c) => c,
        Err(_) => {
            return AwsStatus {
                configured: false,
                profile_name: None,
                role_arn: None,
            };
        }
    };

    match config.find_vouch_profile() {
        Some(profile) => {
            let role_arn = profile
                .credential_process
                .as_ref()
                .and_then(|cp| extract_role_from_credential_process(cp));

            AwsStatus {
                configured: true,
                profile_name: Some(profile.name),
                role_arn,
            }
        }
        None => AwsStatus {
            configured: false,
            profile_name: None,
            role_arn: None,
        },
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
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

    fn check_status_from_content(content: &str) -> AwsStatus {
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        match config.find_vouch_profile() {
            Some(profile) => {
                let role_arn = profile
                    .credential_process
                    .as_ref()
                    .and_then(|cp| extract_role_from_credential_process(cp));

                AwsStatus {
                    configured: true,
                    profile_name: Some(profile.name),
                    role_arn,
                }
            }
            None => AwsStatus {
                configured: false,
                profile_name: None,
                role_arn: None,
            },
        }
    }

    #[test]
    fn test_parse_aws_config_vouch_profile() {
        let content = r#"
[profile vouch]
credential_process = /usr/local/bin/vouch credential aws --role arn:aws:iam::123456789012:role/MyRole
region = us-east-1
"#;

        let status = check_status_from_content(content);

        assert!(status.configured);
        assert_eq!(status.profile_name, Some("vouch".to_string()));
        assert_eq!(
            status.role_arn,
            Some("arn:aws:iam::123456789012:role/MyRole".to_string())
        );
    }

    #[test]
    fn test_parse_aws_config_default_profile() {
        let content = r#"
[default]
credential_process = vouch credential aws --role arn:aws:iam::123456789012:role/DefaultRole
"#;

        let status = check_status_from_content(content);

        assert!(status.configured);
        assert_eq!(status.profile_name, Some("default".to_string()));
        assert_eq!(
            status.role_arn,
            Some("arn:aws:iam::123456789012:role/DefaultRole".to_string())
        );
    }

    #[test]
    fn test_parse_aws_config_no_vouch() {
        let content = r#"
[profile prod]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-west-2
"#;

        let status = check_status_from_content(content);

        assert!(!status.configured);
        assert_eq!(status.profile_name, None);
        assert_eq!(status.role_arn, None);
    }

    #[test]
    fn test_parse_aws_config_vouch_no_role() {
        let content = r#"
[profile vouch]
credential_process = /usr/local/bin/vouch credential aws
"#;

        let status = check_status_from_content(content);

        assert!(status.configured);
        assert_eq!(status.profile_name, Some("vouch".to_string()));
        assert_eq!(status.role_arn, None);
    }

    #[test]
    fn test_parse_aws_config_multiple_profiles_finds_vouch() {
        let content = r#"
[profile regular]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = secret

[profile vouch-prod]
credential_process = vouch credential aws --role arn:aws:iam::111:role/Prod

[profile vouch-staging]
credential_process = vouch credential aws --role arn:aws:iam::222:role/Staging
"#;

        let status = check_status_from_content(content);

        assert!(status.configured);
        // Should find one of the vouch profiles
        assert!(
            status.profile_name == Some("vouch-prod".to_string())
                || status.profile_name == Some("vouch-staging".to_string())
        );
        assert!(status.role_arn.is_some());
    }

    #[test]
    fn test_parse_aws_config_empty() {
        let content = "";

        let status = check_status_from_content(content);

        assert!(!status.configured);
        assert_eq!(status.profile_name, None);
        assert_eq!(status.role_arn, None);
    }

    #[test]
    fn test_parse_aws_config_non_profile_section() {
        // Sections like [sso-session] should not be treated as profiles
        let content = r#"
[sso-session my-sso]
sso_start_url = https://my-sso.awsapps.com/start
credential_process = vouch credential aws --role some-role
"#;

        let status = check_status_from_content(content);

        // Should not find vouch because [sso-session] is not a profile
        assert!(!status.configured);
    }

    #[test]
    fn test_parse_aws_config_whitespace_handling() {
        let content = r#"
  [profile vouch]
  credential_process = vouch credential aws --role arn:aws:iam::123:role/Test
"#;

        let status = check_status_from_content(content);

        assert!(status.configured);
        assert_eq!(status.profile_name, Some("vouch".to_string()));
    }
}
