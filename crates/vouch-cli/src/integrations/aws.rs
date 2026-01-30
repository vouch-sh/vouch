// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS integration status checking.

use std::path::PathBuf;

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
    let config_path = match aws_config_path() {
        Some(p) => p,
        None => {
            return AwsStatus {
                configured: false,
                profile_name: None,
                role_arn: None,
            };
        }
    };

    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => {
            return AwsStatus {
                configured: false,
                profile_name: None,
                role_arn: None,
            };
        }
    };

    parse_aws_config(&content)
}

/// Get the AWS config file path.
fn aws_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".aws").join("config"))
}

/// Parse AWS config content and extract vouch profile info.
/// This is extracted for testing.
fn parse_aws_config(content: &str) -> AwsStatus {
    let mut current_profile: Option<String> = None;
    let mut found_profile: Option<String> = None;
    let mut found_role: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();

        // Check for profile header
        if let Some(header) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if header == "default" {
                current_profile = Some("default".to_string());
            } else if let Some(name) = header.strip_prefix("profile ") {
                current_profile = Some(name.to_string());
            } else {
                current_profile = None;
            }
            continue;
        }

        // Check for credential_process with vouch
        if let Some(profile) = &current_profile
            && line.starts_with("credential_process")
            && line.contains("vouch")
        {
            found_profile = Some(profile.clone());

            // Extract role ARN from --role argument
            if let Some(after_role) = line.split("--role").nth(1) {
                let role_arn = after_role.split_whitespace().next().map(|s| s.to_string());
                found_role = role_arn;
            }
            break;
        }
    }

    AwsStatus {
        configured: found_profile.is_some(),
        profile_name: found_profile,
        role_arn: found_role,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_aws_config_vouch_profile() {
        let content = r#"
[profile vouch]
credential_process = /usr/local/bin/vouch credential aws --role arn:aws:iam::123456789012:role/MyRole
region = us-east-1
"#;

        let status = parse_aws_config(content);

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

        let status = parse_aws_config(content);

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

        let status = parse_aws_config(content);

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

        let status = parse_aws_config(content);

        assert!(status.configured);
        assert_eq!(status.profile_name, Some("vouch".to_string()));
        assert_eq!(status.role_arn, None);
    }

    #[test]
    fn test_parse_aws_config_multiple_profiles_finds_first_vouch() {
        let content = r#"
[profile regular]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = secret

[profile vouch-prod]
credential_process = vouch credential aws --role arn:aws:iam::111:role/Prod

[profile vouch-staging]
credential_process = vouch credential aws --role arn:aws:iam::222:role/Staging
"#;

        let status = parse_aws_config(content);

        assert!(status.configured);
        assert_eq!(status.profile_name, Some("vouch-prod".to_string()));
        assert_eq!(
            status.role_arn,
            Some("arn:aws:iam::111:role/Prod".to_string())
        );
    }

    #[test]
    fn test_parse_aws_config_empty() {
        let content = "";

        let status = parse_aws_config(content);

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

        let status = parse_aws_config(content);

        // Should not find vouch because [sso-session] is not a profile
        assert!(!status.configured);
    }

    #[test]
    fn test_parse_aws_config_whitespace_handling() {
        let content = r#"
  [profile vouch]
  credential_process = vouch credential aws --role arn:aws:iam::123:role/Test
"#;

        let status = parse_aws_config(content);

        assert!(status.configured);
        assert_eq!(status.profile_name, Some("vouch".to_string()));
    }
}
