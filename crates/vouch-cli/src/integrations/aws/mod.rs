// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS integration utilities and status checking.
//!
//! - `config` - AWS config file (~/.aws/config) parsing
//! - `sts` - AWS STS (Security Token Service) utilities

pub(crate) mod codeartifact;
pub(crate) mod codecommit;
pub(crate) mod config;
pub(crate) mod identity_center;
pub(crate) mod redshift;
pub(crate) mod sigv4;
pub(crate) mod sso_portal;
pub(crate) mod sts;

// Re-export commonly used types
pub(crate) use config::{AwsConfig, AwsProfile, extract_role_from_credential_process};

/// Resolve the AWS profile to use, auto-detecting from ~/.aws/config if not specified.
pub(crate) fn resolve_profile(profile: Option<&str>) -> anyhow::Result<String> {
    if let Some(p) = profile {
        return Ok(p.to_string());
    }

    let aws_config = AwsConfig::load()?;
    match aws_config.find_vouch_profile() {
        Some(p) => {
            tracing::debug!("auto-detected vouch AWS profile: {}", p.name);
            Ok(p.name)
        }
        None => Err(crate::exit_code::CliError::ConfigError(
            "No Vouch AWS profile found.\n\
             Run 'vouch setup aws' first, or specify --profile."
                .to_string(),
        )
        .into()),
    }
}

/// Resolve the AWS region, checking profile config then environment variables.
pub(crate) fn resolve_region(region: Option<&str>, profile_name: &str) -> anyhow::Result<String> {
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

    Err(crate::exit_code::CliError::ConfigError(
        "Could not determine AWS region.\n\
         Specify --region, or set a region in your AWS profile or AWS_DEFAULT_REGION."
            .to_string(),
    )
    .into())
}

/// Resolve the AWS region, falling back to the partition's default STS region
/// derived from the role ARN when no region is configured.
pub(crate) fn resolve_region_with_fallback(role_arn: &str) -> anyhow::Result<String> {
    let profile_name = resolve_profile(None).unwrap_or_default();
    match resolve_region(None, &profile_name) {
        Ok(r) => Ok(r),
        Err(_) => {
            let arn = sts::parse_role_arn(role_arn)?;
            let default = arn.partition.default_sts_region();
            tracing::debug!("no region configured, defaulting to {default} for STS");
            Ok(default.to_string())
        }
    }
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
pub(crate) fn resolve_role_and_region(
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
use crate::config::{AwsMultiAccountConfig, Config};

/// AWS integration checker.
pub(crate) struct AwsIntegration;

impl AwsIntegration {
    /// Create a new AWS integration checker.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Default for AwsIntegration {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum number of vouch profiles listed in `vouch status` before truncating.
const MAX_LISTED_PROFILES: usize = 3;

/// Setup hint shown when AWS is not configured.
const SETUP_HINT: &str = "vouch setup aws --role <role-arn>";

/// A vouch-managed AWS profile discovered in `~/.aws/config`.
struct VouchProfile {
    name: String,
    role_arn: Option<String>,
}

/// What `vouch status` learned about the AWS integration.
enum AwsStatusKind {
    /// No vouch-managed profiles in `~/.aws/config`.
    NotConfigured,
    /// One or more vouch profiles are present and aligned with vouch config.
    Configured { profiles: Vec<VouchProfile> },
    /// The SSO session named in `~/.aws/config` has no matching Identity Center
    /// entry in `~/.config/vouch/config.json`, so `credential aws --sso-session`
    /// can't resolve its application ARN. Reconcile before Identity Center
    /// credential fetching works.
    Mismatched {
        aws_session_name: String,
        vouch_session_name: String,
    },
}

impl IntegrationCheck for AwsIntegration {
    fn name(&self) -> &'static str {
        "AWS"
    }

    fn check(&self) -> IntegrationState {
        let Ok(aws_config) = AwsConfig::load() else {
            return IntegrationState::NotConfigured {
                setup_hint: SETUP_HINT.to_string(),
            };
        };
        let vouch_cfg = Config::load().ok();
        let kind = check_aws_status(&aws_config, vouch_cfg.as_ref().and_then(Config::aws));
        render(kind)
    }
}

/// Pure logic: classify the AWS integration state from parsed configs.
fn check_aws_status(
    aws_config: &AwsConfig,
    vouch_aws: Option<&AwsMultiAccountConfig>,
) -> AwsStatusKind {
    let profiles: Vec<VouchProfile> = aws_config
        .find_all_vouch_profiles()
        .into_iter()
        .map(|p| {
            let role_arn = p
                .credential_process
                .as_ref()
                .and_then(|cp| extract_role_from_credential_process(cp));
            VouchProfile {
                name: p.name,
                role_arn,
            }
        })
        .collect();

    if profiles.is_empty() {
        return AwsStatusKind::NotConfigured;
    }

    if let Some(vouch_aws) = vouch_aws
        && !vouch_aws.sso_sessions.is_empty()
        && let Some(aws_session) = aws_config.find_sso_session(None)
        && !vouch_aws.sso_sessions.contains_key(&aws_session.name)
    {
        let vouch_session_name = vouch_aws
            .sso_sessions
            .keys()
            .next()
            .cloned()
            .unwrap_or_default();
        return AwsStatusKind::Mismatched {
            aws_session_name: aws_session.name,
            vouch_session_name,
        };
    }

    AwsStatusKind::Configured { profiles }
}

/// Map an `AwsStatusKind` into the shared `IntegrationState` enum.
fn render(kind: AwsStatusKind) -> IntegrationState {
    match kind {
        AwsStatusKind::NotConfigured => IntegrationState::NotConfigured {
            setup_hint: SETUP_HINT.to_string(),
        },
        AwsStatusKind::Mismatched {
            aws_session_name,
            vouch_session_name,
        } => IntegrationState::Partial {
            message: format!(
                "SSO session name mismatch (\"{aws_session_name}\" vs \
                 \"{vouch_session_name}\")"
            ),
            setup_hint: None,
        },
        AwsStatusKind::Configured { profiles } => render_configured(&profiles),
    }
}

fn render_configured(profiles: &[VouchProfile]) -> IntegrationState {
    match profiles {
        [] => IntegrationState::NotConfigured {
            setup_hint: SETUP_HINT.to_string(),
        },
        [single] => render_single(single),
        _ => render_multi(profiles),
    }
}

fn render_single(p: &VouchProfile) -> IntegrationState {
    let summary = if p.name == "default" {
        "default profile".to_string()
    } else {
        format!("profile: {}", p.name)
    };
    let mut details = Vec::new();
    if let Some(role) = &p.role_arn {
        details.push(("Role".to_string(), role.clone()));
    }
    IntegrationState::Configured(ConfiguredDetails { summary, details })
}

fn render_multi(profiles: &[VouchProfile]) -> IntegrationState {
    let count = profiles.len();
    let shown = count.min(MAX_LISTED_PROFILES);
    let summary = if count > shown {
        format!("{count} profiles, showing {shown}")
    } else {
        format!("{count} profiles")
    };
    let name_width = profiles
        .iter()
        .take(shown)
        .map(|p| p.name.len())
        .max()
        .unwrap_or(0);
    // Use empty key + pre-formatted "name = arn" so the renderer emits raw
    // lines. Avoids stacking the kv `:` against the colon-heavy ARN.
    let details = profiles
        .iter()
        .take(shown)
        .map(|p| {
            let name = &p.name;
            let role = p.role_arn.as_deref().unwrap_or("(no --role)");
            let row = format!("{name:name_width$} = {role}");
            (String::new(), row)
        })
        .collect();
    IntegrationState::Configured(ConfiguredDetails { summary, details })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::config::SsoSessionConfig;
    use std::collections::BTreeMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn load_config(content: &str) -> AwsConfig {
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        file.write_all(content.as_bytes())
            .expect("failed to write temp file");
        AwsConfig::load_from(file.path().to_path_buf()).expect("failed to load aws config")
    }

    fn vouch_aws_with_sessions(names: &[&str]) -> AwsMultiAccountConfig {
        let mut sso_sessions = BTreeMap::new();
        for name in names {
            sso_sessions.insert(
                (*name).to_string(),
                SsoSessionConfig {
                    management_role: format!("arn:aws:iam::111:role/Mgmt-{name}"),
                    ..SsoSessionConfig::default()
                },
            );
        }
        AwsMultiAccountConfig { sso_sessions }
    }

    #[test]
    fn classifies_empty_config_as_not_configured() {
        let aws = load_config("");
        assert!(matches!(
            check_aws_status(&aws, None),
            AwsStatusKind::NotConfigured
        ));
    }

    #[test]
    fn classifies_config_without_vouch_profile_as_not_configured() {
        let content = r#"
[profile prod]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-west-2
"#;
        let aws = load_config(content);
        assert!(matches!(
            check_aws_status(&aws, None),
            AwsStatusKind::NotConfigured
        ));
    }

    #[test]
    fn ignores_sso_session_block_as_profile() {
        let content = r#"
[sso-session my-sso]
sso_start_url = https://my-sso.awsapps.com/start
credential_process = vouch credential aws --role some-role
"#;
        let aws = load_config(content);
        assert!(matches!(
            check_aws_status(&aws, None),
            AwsStatusKind::NotConfigured
        ));
    }

    #[test]
    fn classifies_single_vouch_profile() {
        let content = r#"
[profile vouch]
credential_process = vouch credential aws --role arn:aws:iam::123:role/MyRole
region = us-east-1
"#;
        let aws = load_config(content);
        let AwsStatusKind::Configured { profiles } = check_aws_status(&aws, None) else {
            panic!("expected Configured");
        };
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "vouch");
        assert_eq!(
            profiles[0].role_arn.as_deref(),
            Some("arn:aws:iam::123:role/MyRole")
        );
    }

    #[test]
    fn classifies_vouch_profile_missing_role_arn() {
        let content = r#"
[profile vouch]
credential_process = /usr/local/bin/vouch credential aws
"#;
        let aws = load_config(content);
        let AwsStatusKind::Configured { profiles } = check_aws_status(&aws, None) else {
            panic!("expected Configured");
        };
        assert_eq!(profiles.len(), 1);
        assert!(profiles[0].role_arn.is_none());
    }

    #[test]
    fn classifies_three_vouch_profiles() {
        let content = r#"
[profile vouch-prod]
credential_process = vouch credential aws --role arn:aws:iam::111:role/Prod

[profile vouch-staging]
credential_process = vouch credential aws --role arn:aws:iam::222:role/Staging

[profile vouch-dev]
credential_process = vouch credential aws --role arn:aws:iam::333:role/Dev
"#;
        let aws = load_config(content);
        let AwsStatusKind::Configured { profiles } = check_aws_status(&aws, None) else {
            panic!("expected Configured");
        };
        assert_eq!(profiles.len(), 3);
    }

    #[test]
    fn detects_sso_session_name_mismatch() {
        let content = r#"
[sso-session sealodge]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile vouch-x]
credential_process = vouch credential aws --role arn:aws:iam::111:role/X
"#;
        let aws = load_config(content);
        let vouch_aws = vouch_aws_with_sessions(&["sealodge-prod"]);
        let AwsStatusKind::Mismatched {
            aws_session_name,
            vouch_session_name,
        } = check_aws_status(&aws, Some(&vouch_aws))
        else {
            panic!("expected Mismatched");
        };
        assert_eq!(aws_session_name, "sealodge");
        assert_eq!(vouch_session_name, "sealodge-prod");
    }

    #[test]
    fn matching_sso_session_returns_configured() {
        let content = r#"
[sso-session sealodge]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile vouch-x]
credential_process = vouch credential aws --role arn:aws:iam::111:role/X
"#;
        let aws = load_config(content);
        let vouch_aws = vouch_aws_with_sessions(&["sealodge"]);
        assert!(matches!(
            check_aws_status(&aws, Some(&vouch_aws)),
            AwsStatusKind::Configured { .. }
        ));
    }

    #[test]
    fn empty_vouch_sso_sessions_does_not_trigger_mismatch() {
        // sso_sessions empty -> mismatch detection skipped even if ~/.aws/config
        // names an SSO session.
        let content = r#"
[sso-session sealodge]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile vouch-x]
credential_process = vouch credential aws --role arn:aws:iam::111:role/X
"#;
        let aws = load_config(content);
        let vouch_aws = AwsMultiAccountConfig::default();
        assert!(matches!(
            check_aws_status(&aws, Some(&vouch_aws)),
            AwsStatusKind::Configured { .. }
        ));
    }

    #[test]
    fn render_single_profile_preserves_existing_shape() {
        let p = VouchProfile {
            name: "sealodge-admin".to_string(),
            role_arn: Some("arn:aws:iam::861:role/VouchAdmin".to_string()),
        };
        let IntegrationState::Configured(details) = render_single(&p) else {
            panic!("expected Configured");
        };
        assert_eq!(details.summary, "profile: sealodge-admin");
        assert_eq!(
            details.details,
            vec![(
                "Role".to_string(),
                "arn:aws:iam::861:role/VouchAdmin".to_string(),
            )]
        );
    }

    #[test]
    fn render_single_default_profile_uses_default_phrase() {
        let p = VouchProfile {
            name: "default".to_string(),
            role_arn: Some("arn:aws:iam::111:role/Default".to_string()),
        };
        let IntegrationState::Configured(details) = render_single(&p) else {
            panic!("expected Configured");
        };
        assert_eq!(details.summary, "default profile");
    }

    #[test]
    fn render_single_omits_role_line_when_missing() {
        let p = VouchProfile {
            name: "vouch".to_string(),
            role_arn: None,
        };
        let IntegrationState::Configured(details) = render_single(&p) else {
            panic!("expected Configured");
        };
        assert!(details.details.is_empty());
    }

    fn make_profiles(count: usize) -> Vec<VouchProfile> {
        (1..=count)
            .map(|i| VouchProfile {
                name: format!("vouch-{i}"),
                role_arn: Some(format!("arn:aws:iam::{i}11:role/R{i}")),
            })
            .collect()
    }

    #[test]
    fn render_three_profiles_lists_all() {
        let IntegrationState::Configured(details) = render_multi(&make_profiles(3)) else {
            panic!("expected Configured");
        };
        assert_eq!(details.summary, "3 profiles");
        assert_eq!(details.details.len(), 3);
        for (key, _) in &details.details {
            assert!(key.is_empty(), "multi rows should use raw-line format");
        }
    }

    #[test]
    fn render_multi_rows_use_equals_and_pad_names() {
        let profiles = vec![
            VouchProfile {
                name: "short".to_string(),
                role_arn: Some("arn:aws:iam::111:role/A".to_string()),
            },
            VouchProfile {
                name: "much-longer-name".to_string(),
                role_arn: Some("arn:aws:iam::222:role/B".to_string()),
            },
        ];
        let IntegrationState::Configured(details) = render_multi(&profiles) else {
            panic!("expected Configured");
        };
        // Padded to the longest name (16 chars), then " = ", then the ARN.
        assert_eq!(
            details.details[0].1,
            "short            = arn:aws:iam::111:role/A"
        );
        assert_eq!(
            details.details[1].1,
            "much-longer-name = arn:aws:iam::222:role/B"
        );
    }

    #[test]
    fn render_five_profiles_truncates_to_three() {
        let IntegrationState::Configured(details) = render_multi(&make_profiles(5)) else {
            panic!("expected Configured");
        };
        assert_eq!(details.summary, "5 profiles, showing 3");
        assert_eq!(details.details.len(), 3);
    }

    #[test]
    fn render_profile_without_role_shows_placeholder() {
        let profiles = vec![
            VouchProfile {
                name: "vouch-a".to_string(),
                role_arn: None,
            },
            VouchProfile {
                name: "vouch-b".to_string(),
                role_arn: Some("arn:aws:iam::111:role/B".to_string()),
            },
        ];
        let IntegrationState::Configured(details) = render_multi(&profiles) else {
            panic!("expected Configured");
        };
        assert!(details.details[0].1.ends_with("= (no --role)"));
        assert!(details.details[1].1.ends_with("= arn:aws:iam::111:role/B"));
    }

    #[test]
    fn render_mismatched_returns_partial() {
        let state = render(AwsStatusKind::Mismatched {
            aws_session_name: "sealodge".to_string(),
            vouch_session_name: "sealodge-prod".to_string(),
        });
        let IntegrationState::Partial {
            message,
            setup_hint,
        } = state
        else {
            panic!("expected Partial");
        };
        assert!(message.contains("sealodge"));
        assert!(message.contains("sealodge-prod"));
        assert!(setup_hint.is_none());
    }

    #[test]
    fn render_not_configured_returns_setup_hint() {
        let IntegrationState::NotConfigured { setup_hint } = render(AwsStatusKind::NotConfigured)
        else {
            panic!("expected NotConfigured");
        };
        assert_eq!(setup_hint, SETUP_HINT);
    }
}
