// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS integration utilities and status checking.
//!
//! - `config` - AWS config file (~/.aws/config) parsing
//! - `sts` - AWS STS (Security Token Service) utilities

pub mod codeartifact;
pub mod codecommit;
pub mod config;
pub mod redshift;
pub mod sigv4;
pub mod sts;

// Re-export commonly used types
pub use config::{
    AwsConfig, AwsProfile, AwsSsoSession, aws_config_dir, extract_role_from_credential_process,
};

/// Derive the SSO session name from a server URL.
///
/// Uses the hostname (with port if non-standard), sanitized to
/// `[a-z0-9-]`. This becomes both the `[sso-session X]` name in
/// `~/.aws/config` and the SHA-1 cache key in `~/.aws/sso/cache/`.
///
/// Examples:
/// - `https://us.vouch.sh`    → `us-vouch-sh`
/// - `http://localhost:3000`   → `localhost-3000`
/// - `https://dev.vouch.sh`   → `dev-vouch-sh`
pub fn sso_session_name(server: &str) -> anyhow::Result<String> {
    let host = crate::config::hostname_from_url(server)?;
    let sanitized: String = host
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();

    // Collapse consecutive dashes and trim
    let mut result = String::with_capacity(sanitized.len());
    let mut prev_dash = false;
    for c in sanitized.chars() {
        if c == '-' {
            if !prev_dash {
                result.push(c);
            }
            prev_dash = true;
        } else {
            result.push(c);
            prev_dash = false;
        }
    }

    let trimmed = result.trim_matches('-');
    if trimmed.is_empty() {
        anyhow::bail!("could not derive SSO session name from server URL: {server}");
    }
    Ok(trimmed.to_string())
}

/// Resolve the AWS profile to use, auto-detecting from ~/.aws/config if not specified.
pub fn resolve_profile(profile: Option<&str>) -> anyhow::Result<String> {
    if let Some(p) = profile {
        return Ok(p.to_string());
    }

    let aws_config = AwsConfig::load()?;
    match aws_config.find_vouch_profile() {
        Some(p) => {
            tracing::debug!("auto-detected vouch AWS profile: {}", p.name);
            Ok(p.name)
        }
        None => anyhow::bail!(
            "No Vouch AWS profile found.\n\
             Run 'vouch setup aws' first, or specify --profile."
        ),
    }
}

/// Resolve the AWS region, checking profile config then environment variables.
pub fn resolve_region(region: Option<&str>, profile_name: &str) -> anyhow::Result<String> {
    if let Some(r) = region {
        return Ok(r.to_string());
    }

    // Check the AWS profile's region setting
    let aws_config = AwsConfig::load()?;
    if let Some(profile) = aws_config.get_profile(profile_name)
        && let Some(r) = profile.region
    {
        tracing::debug!("using region from AWS profile '{}': {}", profile_name, r);
        return Ok(r);
    }

    // Check environment variables
    if let Ok(r) = std::env::var("AWS_DEFAULT_REGION") {
        return Ok(r);
    }
    if let Ok(r) = std::env::var("AWS_REGION") {
        return Ok(r);
    }

    anyhow::bail!(
        "Could not determine AWS region.\n\
         Specify --region, or set a region in your AWS profile or AWS_DEFAULT_REGION."
    );
}

/// Try to read the AWS role ARN from the local `~/.aws/config` file.
///
/// Finds the first vouch profile and extracts the role ARN from its `credential_process`.
pub(crate) fn get_local_aws_role() -> Option<String> {
    let config = AwsConfig::load().ok()?;
    let profile = config.find_vouch_profile()?;
    extract_role_from_credential_process(&profile.credential_process?)
}

/// Resolve AWS role ARN and region from CLI flags or local config.
///
/// This is the standard resolution pattern used by credential commands
/// that need both a role and region (EKS, RDS, Redshift). It:
/// 1. Uses the `--role` flag if provided, otherwise reads from `~/.aws/config`
/// 2. Resolves region from `--region` flag, AWS profile, or env vars
pub fn resolve_role_and_region(
    role: Option<&str>,
    region: Option<&str>,
) -> anyhow::Result<(String, String)> {
    let role_arn = match role {
        Some(r) => r.to_string(),
        None => get_local_aws_role().ok_or_else(|| {
            anyhow::anyhow!(
                "AWS not configured. Run 'vouch setup aws --role <role-arn>' \
                 first, or specify --role."
            )
        })?,
    };

    let profile_name = resolve_profile(None).unwrap_or_default();
    let region_name = resolve_region(region, &profile_name)?;

    Ok((role_arn, region_name))
}

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

    // =========================================================================
    // sso_session_name tests
    // =========================================================================

    #[test]
    fn test_sso_session_name_standard_https() {
        assert_eq!(
            sso_session_name("https://us.vouch.sh").unwrap(),
            "us-vouch-sh"
        );
    }

    #[test]
    fn test_sso_session_name_with_port() {
        assert_eq!(
            sso_session_name("http://localhost:3000").unwrap(),
            "localhost-3000"
        );
    }

    #[test]
    fn test_sso_session_name_dev_subdomain() {
        assert_eq!(
            sso_session_name("https://dev.vouch.sh").unwrap(),
            "dev-vouch-sh"
        );
    }

    #[test]
    fn test_sso_session_name_collapses_consecutive_dashes() {
        // Hostname with multiple non-alphanumeric chars in a row
        assert_eq!(
            sso_session_name("https://my--host.example.com").unwrap(),
            "my-host-example-com"
        );
    }

    #[test]
    fn test_sso_session_name_strips_leading_trailing_dashes() {
        // Hostname starting/ending with dots produces leading/trailing dashes
        assert_eq!(sso_session_name("https://vouch.sh").unwrap(), "vouch-sh");
    }

    #[test]
    fn test_sso_session_name_lowercases() {
        assert_eq!(
            sso_session_name("https://US.Vouch.SH").unwrap(),
            "us-vouch-sh"
        );
    }

    #[test]
    fn test_sso_session_name_standard_port_443_omitted() {
        // Standard port should not appear in session name
        assert_eq!(
            sso_session_name("https://vouch.sh:443").unwrap(),
            "vouch-sh"
        );
    }

    #[test]
    fn test_sso_session_name_invalid_url_errors() {
        assert!(sso_session_name("not-a-url").is_err());
    }

    #[test]
    fn test_sso_session_name_idempotent() {
        // Running through the same URL twice gives the same result
        let a = sso_session_name("https://us.vouch.sh").unwrap();
        let b = sso_session_name("https://us.vouch.sh").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_sso_session_name_ip_address() {
        assert_eq!(
            sso_session_name("https://192.168.1.1").unwrap(),
            "192-168-1-1"
        );
    }
}
