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
pub(crate) use config::{
    AwsConfig, AwsProfile, VouchProfile, extract_idc_target_from_credential_process,
    extract_role_from_credential_process,
};

use crate::exit_code::CliError;

/// Resolve which Vouch-managed AWS profile a command should use.
///
/// Resolution order:
/// 1. `explicit` — a `--profile` flag, or the profile in a `codecommit://` URL
/// 2. `$AWS_PROFILE`, when it names a Vouch-managed profile
/// 3. the only Vouch-managed profile in `~/.aws/config`
///
/// # Errors
/// Returns an error when the named profile is missing or is not Vouch-managed,
/// when no Vouch profile exists, or when several exist and none was requested.
/// Picking one silently would sign requests for an account the user never asked
/// for, which surfaces as an opaque 403 from the target AWS service.
pub(crate) fn resolve_vouch_profile(explicit: Option<&str>) -> anyhow::Result<VouchProfile> {
    let config = AwsConfig::load()?;
    let env_profile = std::env::var("AWS_PROFILE").ok();
    select_vouch_profile(&config, explicit, env_profile.as_deref())
}

/// Apply the profile resolution order to an already-loaded config.
///
/// Split from [`resolve_vouch_profile`] so the ordering can be tested without
/// touching the filesystem or the process environment.
fn select_vouch_profile(
    config: &AwsConfig,
    explicit: Option<&str>,
    env_profile: Option<&str>,
) -> anyhow::Result<VouchProfile> {
    if let Some(name) = explicit {
        return named_vouch_profile(config, name);
    }

    if let Some(name) = env_profile {
        match named_vouch_profile(config, name) {
            Ok(profile) => return Ok(profile),
            // AWS_PROFILE is ambient and commonly set for other tooling, so a
            // value that is not Vouch-managed is ignored rather than fatal.
            Err(e) => tracing::debug!("ignoring AWS_PROFILE='{name}': {e}"),
        }
    }

    match config.vouch_profiles_with_role().as_slice() {
        [] => Err(CliError::ConfigError(
            "No Vouch AWS profile found in ~/.aws/config.\n\
             Run 'vouch setup aws --role <role-arn>' first."
                .to_string(),
        )
        .into()),
        [only] => Ok(only.clone()),
        candidates => {
            let width = candidates.iter().map(|p| p.name.len()).max().unwrap_or(0);
            let mut listing = String::new();
            for profile in candidates {
                listing.push_str(&format!(
                    "  {:<width$}  {}\n",
                    profile.name, profile.role_arn
                ));
            }
            Err(CliError::ConfigError(format!(
                "Multiple Vouch AWS profiles found in ~/.aws/config; \
                 refusing to guess which account you meant:\n\n\
                 {listing}\n\
                 Set AWS_PROFILE, or name the account with --profile or --role."
            ))
            .into())
        }
    }
}

/// Look up a specific profile by name and extract the role it targets.
fn named_vouch_profile(config: &AwsConfig, name: &str) -> anyhow::Result<VouchProfile> {
    let Some(profile) = config.get_profile(name) else {
        return Err(CliError::ConfigError(format!(
            "AWS profile '{name}' not found in ~/.aws/config.\n\
             Run 'vouch setup aws --profile {name} --role <role-arn>' to create it."
        ))
        .into());
    };

    let Some(credential_process) = profile.credential_process else {
        return Err(CliError::ConfigError(format!(
            "AWS profile '{name}' has no credential_process and is not managed by Vouch.\n\
             Run 'vouch setup aws --profile {name} --role <role-arn>'."
        ))
        .into());
    };

    if let Some(role_arn) = extract_role_from_credential_process(&credential_process) {
        return Ok(VouchProfile {
            name: name.to_string(),
            role_arn,
        });
    }

    if let Some(target) = extract_idc_target_from_credential_process(&credential_process) {
        return Err(CliError::ConfigError(format!(
            "AWS profile '{name}' uses Identity Center ({target}).\n\
             This command needs a role-based profile — run \
             'vouch setup aws --profile <name> --role <role-arn>'."
        ))
        .into());
    }

    Err(CliError::ConfigError(format!(
        "AWS profile '{name}' has no --role in its credential_process."
    ))
    .into())
}

/// Find a region from an explicit flag, a named profile, then the environment.
///
/// Returns `None` when no source names a region, leaving the caller to choose
/// between erroring and falling back to a partition default.
fn find_region(region: Option<&str>, profile_name: Option<&str>) -> anyhow::Result<Option<String>> {
    if let Some(r) = region {
        return Ok(Some(r.to_string()));
    }

    // Check the AWS profile's region setting
    if let Some(profile_name) = profile_name {
        let aws_config = AwsConfig::load()?;
        if let Some(profile) = aws_config.get_profile(profile_name)
            && let Some(r) = profile.region
        {
            tracing::debug!("using region from AWS profile '{}': {}", profile_name, r);
            return Ok(Some(r));
        }
    }

    // Check environment variables
    if let Ok(r) = std::env::var("AWS_DEFAULT_REGION") {
        return Ok(Some(r));
    }
    if let Ok(r) = std::env::var("AWS_REGION") {
        return Ok(Some(r));
    }

    Ok(None)
}

/// The error returned when no region could be determined from any source.
fn no_region_error() -> CliError {
    CliError::ConfigError(
        "Could not determine AWS region.\n\
         Specify --region, or set a region in your AWS profile or AWS_DEFAULT_REGION."
            .to_string(),
    )
}

/// Resolve the AWS region, checking profile config then environment variables.
pub(crate) fn resolve_region(region: Option<&str>, profile_name: &str) -> anyhow::Result<String> {
    find_region(region, Some(profile_name))?.ok_or_else(|| no_region_error().into())
}

/// Resolve the AWS region, falling back to the partition's default STS region
/// derived from the role ARN when no region is configured.
///
/// The region comes from the profile that targets `role_arn`, so a machine with
/// several Vouch profiles does not borrow an unrelated profile's region.
pub(crate) fn resolve_region_with_fallback(role_arn: &str) -> anyhow::Result<String> {
    let profile_name = AwsConfig::load().ok().and_then(|config| {
        config
            .find_vouch_profile_for_role(role_arn)
            // A chained role, or an Identity Center profile (which names no
            // role), matches nothing above. Borrowing the region of the only
            // Vouch profile is still unambiguous, and beats silently dropping
            // to the partition default in a region-restricted account.
            .or_else(|| match config.find_all_vouch_profiles().as_slice() {
                [only] => Some(only.clone()),
                _ => None,
            })
            .map(|profile| profile.name)
    });

    if let Some(r) = find_region(None, profile_name.as_deref())? {
        return Ok(r);
    }

    let arn = sts::parse_role_arn(role_arn)?;
    let default = arn.partition.default_sts_region();
    tracing::debug!("no region configured, defaulting to {default} for STS");
    Ok(default.to_string())
}

/// Resolve AWS role ARN and region from CLI flags or local config.
///
/// This is the standard resolution pattern used by credential commands
/// that need both a role and region (EKS, RDS, Redshift). It:
/// 1. Uses the `--role` flag if provided, otherwise resolves a Vouch profile
/// 2. Resolves the region from `--region`, that same profile, or env vars
pub(crate) fn resolve_role_and_region(
    role: Option<&str>,
    region: Option<&str>,
    profile: Option<&str>,
) -> anyhow::Result<(String, String)> {
    let (profile_name, role_arn) = match role {
        // An explicit --role wins. The region comes from the profile targeting
        // that role, falling back to the only Vouch profile when the role is not
        // in ~/.aws/config at all (a chained or cross-account ARN) — otherwise
        // a single-profile user who passes --role loses their configured region.
        Some(r) => {
            let owning = AwsConfig::load()
                .ok()
                .and_then(|config| config.find_vouch_profile_for_role(r))
                .map(|profile| profile.name)
                .or_else(|| resolve_vouch_profile(profile).ok().map(|p| p.name));
            (owning, r.to_string())
        }
        None => {
            let resolved = resolve_vouch_profile(profile)?;
            (Some(resolved.name), resolved.role_arn)
        }
    };

    let region_name = find_region(region, profile_name.as_deref())?.ok_or_else(no_region_error)?;

    Ok((role_arn, region_name))
}

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};
use crate::config::Config;

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
struct ProfileSummary {
    name: String,
    /// Pre-formatted credential target: STS role ARN, or `"IdC {account}/{permission-set}"`.
    target: Option<String>,
}

/// What `vouch status` learned about the AWS integration.
enum AwsStatusKind {
    /// No vouch-managed profiles in `~/.aws/config`.
    NotConfigured,
    /// One or more vouch profiles are present.
    Configured {
        profiles: Vec<ProfileSummary>,
        org_count: usize,
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
        let vouch_aws = vouch_cfg.as_ref().and_then(|c| c.aws());
        render(check_aws_status(&aws_config, vouch_aws))
    }
}

/// Pure logic: classify the AWS integration state from parsed `~/.aws/config`.
fn check_aws_status(
    aws_config: &AwsConfig,
    vouch_aws: Option<&crate::config::AwsOrgsConfig>,
) -> AwsStatusKind {
    let org_count = vouch_aws.map_or(0, |a| a.organizations.len());
    let profiles: Vec<ProfileSummary> = aws_config
        .find_all_vouch_profiles()
        .into_iter()
        .map(|p| {
            let target = p.credential_process.as_ref().and_then(|cp| {
                extract_role_from_credential_process(cp)
                    .or_else(|| config::extract_idc_target_from_credential_process(cp))
            });
            ProfileSummary {
                name: p.name,
                target,
            }
        })
        .collect();

    if profiles.is_empty() {
        AwsStatusKind::NotConfigured
    } else {
        AwsStatusKind::Configured {
            profiles,
            org_count,
        }
    }
}

/// Map an `AwsStatusKind` into the shared `IntegrationState` enum.
fn render(kind: AwsStatusKind) -> IntegrationState {
    match kind {
        AwsStatusKind::NotConfigured => IntegrationState::NotConfigured {
            setup_hint: SETUP_HINT.to_string(),
        },
        AwsStatusKind::Configured {
            profiles,
            org_count,
        } => render_configured(&profiles, org_count),
    }
}

fn render_configured(profiles: &[ProfileSummary], org_count: usize) -> IntegrationState {
    match profiles {
        [] => IntegrationState::NotConfigured {
            setup_hint: SETUP_HINT.to_string(),
        },
        [single] => render_single(single, org_count),
        _ => render_multi(profiles, org_count),
    }
}

fn render_single(p: &ProfileSummary, org_count: usize) -> IntegrationState {
    let summary = if p.name == "default" {
        "default profile".to_string()
    } else {
        format!("profile: {}", p.name)
    };
    let mut details = Vec::new();
    if let Some(target) = &p.target {
        details.push(("Role".to_string(), target.clone()));
    }
    if org_count > 0 {
        details.push(("Organizations".to_string(), org_count.to_string()));
    }
    IntegrationState::Configured(ConfiguredDetails { summary, details })
}

fn render_multi(profiles: &[ProfileSummary], org_count: usize) -> IntegrationState {
    let count = profiles.len();
    let shown = count.min(MAX_LISTED_PROFILES);
    let orgs_suffix = if org_count > 0 {
        format!(" ({org_count} orgs)")
    } else {
        String::new()
    };
    let summary = if count > shown {
        format!("{count} profiles{orgs_suffix}, showing {shown}")
    } else {
        format!("{count} profiles{orgs_suffix}")
    };
    let name_width = profiles
        .iter()
        .take(shown)
        .map(|p| p.name.len())
        .max()
        .unwrap_or(0);
    // Use empty key + pre-formatted "name = target" so the renderer emits raw
    // lines. Avoids stacking the kv `:` against the colon-heavy ARN.
    let details = profiles
        .iter()
        .take(shown)
        .map(|p| {
            let name = &p.name;
            let target = p.target.as_deref().unwrap_or("(no --role)");
            let row = format!("{name:name_width$} = {target}");
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
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn load_config(content: &str) -> AwsConfig {
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        file.write_all(content.as_bytes())
            .expect("failed to write temp file");
        AwsConfig::load_from(file.path().to_path_buf()).expect("failed to load aws config")
    }

    /// Two vouch profiles, in the order that made this a bug: the demo profile
    /// sorts second, so "first match wins" signed every request as the admin
    /// account and AWS answered 403 with nothing naming the cause.
    const TWO_PROFILES: &str = r#"
[profile alpha-admin]
credential_process = vouch credential aws --role arn:aws:iam::111111111111:role/vouch/VouchAdmin
region = us-west-2

[profile vouch-demo]
credential_process = vouch credential aws --role arn:aws:iam::222222222222:role/demo
region = us-east-1
"#;

    #[test]
    fn selects_the_only_vouch_profile() {
        let aws = load_config(
            r#"
[profile vouch-demo]
credential_process = vouch credential aws --role arn:aws:iam::222222222222:role/demo
"#,
        );
        let resolved = select_vouch_profile(&aws, None, None).expect("single profile resolves");
        assert_eq!(resolved.name, "vouch-demo");
        assert_eq!(resolved.role_arn, "arn:aws:iam::222222222222:role/demo");
    }

    #[test]
    fn refuses_to_guess_between_several_profiles() {
        let aws = load_config(TWO_PROFILES);
        let err = select_vouch_profile(&aws, None, None)
            .expect_err("ambiguous choice must not silently pick one")
            .to_string();

        // The message has to name both candidates and their accounts; that is
        // the whole point of failing instead of guessing.
        assert!(err.contains("alpha-admin"), "{err}");
        assert!(err.contains("vouch-demo"), "{err}");
        assert!(
            err.contains("arn:aws:iam::111111111111:role/vouch/VouchAdmin"),
            "{err}"
        );
        assert!(err.contains("arn:aws:iam::222222222222:role/demo"), "{err}");
        assert!(err.contains("--profile"), "{err}");
    }

    #[test]
    fn explicit_profile_wins_over_ambiguity() {
        let aws = load_config(TWO_PROFILES);
        let resolved =
            select_vouch_profile(&aws, Some("vouch-demo"), None).expect("named profile resolves");
        assert_eq!(resolved.role_arn, "arn:aws:iam::222222222222:role/demo");
    }

    #[test]
    fn aws_profile_env_resolves_ambiguity() {
        let aws = load_config(TWO_PROFILES);
        let resolved = select_vouch_profile(&aws, None, Some("vouch-demo"))
            .expect("AWS_PROFILE resolves the choice");
        assert_eq!(resolved.name, "vouch-demo");
    }

    #[test]
    fn explicit_profile_outranks_aws_profile_env() {
        let aws = load_config(TWO_PROFILES);
        let resolved = select_vouch_profile(&aws, Some("alpha-admin"), Some("vouch-demo"))
            .expect("explicit profile wins");
        assert_eq!(resolved.name, "alpha-admin");
    }

    /// AWS_PROFILE is ambient and often set for unrelated tooling, so a value
    /// that names no vouch profile is ignored rather than fatal — but it must
    /// not paper over the ambiguity either.
    #[test]
    fn non_vouch_aws_profile_env_is_ignored() {
        let aws = load_config(TWO_PROFILES);
        let err = select_vouch_profile(&aws, None, Some("some-other-profile"))
            .expect_err("still ambiguous")
            .to_string();
        assert!(err.contains("alpha-admin"), "{err}");
    }

    #[test]
    fn non_vouch_aws_profile_env_still_allows_single_profile() {
        let aws = load_config(
            r#"
[profile vouch-demo]
credential_process = vouch credential aws --role arn:aws:iam::222222222222:role/demo
"#,
        );
        let resolved = select_vouch_profile(&aws, None, Some("some-other-profile"))
            .expect("falls through to the sole profile");
        assert_eq!(resolved.name, "vouch-demo");
    }

    #[test]
    fn errors_when_no_vouch_profile_exists() {
        let aws = load_config(
            r#"
[profile prod]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
"#,
        );
        let err = select_vouch_profile(&aws, None, None)
            .expect_err("nothing to resolve")
            .to_string();
        assert!(err.contains("vouch setup aws"), "{err}");
    }

    #[test]
    fn unknown_named_profile_is_reported() {
        let aws = load_config(TWO_PROFILES);
        let err = select_vouch_profile(&aws, Some("typo"), None)
            .expect_err("unknown profile")
            .to_string();
        assert!(err.contains("'typo' not found"), "{err}");
    }

    /// Identity Center profiles match the "vouch" substring but name no role,
    /// so they cannot serve these commands. Auto-selection skips them; naming
    /// one explicitly must say why rather than claim AWS is unconfigured.
    #[test]
    fn identity_center_profile_is_skipped_but_explained() {
        let aws = load_config(
            r#"
[profile vouch-idc]
credential_process = vouch credential aws --account 111111111111 --permission-set Admin

[profile vouch-demo]
credential_process = vouch credential aws --role arn:aws:iam::222222222222:role/demo
"#,
        );

        let resolved =
            select_vouch_profile(&aws, None, None).expect("IdC profile is not a candidate");
        assert_eq!(resolved.name, "vouch-demo");

        let err = select_vouch_profile(&aws, Some("vouch-idc"), None)
            .expect_err("IdC profile cannot mint role credentials")
            .to_string();
        assert!(err.contains("Identity Center"), "{err}");
        assert!(err.contains("111111111111/Admin"), "{err}");
    }

    #[test]
    fn profile_without_credential_process_is_reported() {
        let aws = load_config(
            r#"
[profile prod]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
"#,
        );
        let err = select_vouch_profile(&aws, Some("prod"), None)
            .expect_err("not a vouch profile")
            .to_string();
        assert!(err.contains("not managed by Vouch"), "{err}");
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
        let AwsStatusKind::Configured {
            profiles,
            org_count: _,
        } = check_aws_status(&aws, None)
        else {
            panic!("expected Configured");
        };
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "vouch");
        assert_eq!(
            profiles[0].target.as_deref(),
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
        let AwsStatusKind::Configured {
            profiles,
            org_count: _,
        } = check_aws_status(&aws, None)
        else {
            panic!("expected Configured");
        };
        assert_eq!(profiles.len(), 1);
        assert!(profiles[0].target.is_none());
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
        let AwsStatusKind::Configured {
            profiles,
            org_count: _,
        } = check_aws_status(&aws, None)
        else {
            panic!("expected Configured");
        };
        assert_eq!(profiles.len(), 3);
    }

    #[test]
    fn sso_session_block_alongside_vouch_profile_returns_configured() {
        // SSO session blocks are not profiles; a co-located vouch profile is still Configured.
        let content = r#"
[sso-session sealodge]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1

[profile vouch-x]
credential_process = vouch credential aws --role arn:aws:iam::111:role/X
"#;
        let aws = load_config(content);
        assert!(matches!(
            check_aws_status(&aws, None),
            AwsStatusKind::Configured { .. }
        ));
    }

    #[test]
    fn render_single_profile_preserves_existing_shape() {
        let p = ProfileSummary {
            name: "sealodge-admin".to_string(),
            target: Some("arn:aws:iam::861:role/VouchAdmin".to_string()),
        };
        let IntegrationState::Configured(details) = render_single(&p, 0) else {
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
        let p = ProfileSummary {
            name: "default".to_string(),
            target: Some("arn:aws:iam::111:role/Default".to_string()),
        };
        let IntegrationState::Configured(details) = render_single(&p, 0) else {
            panic!("expected Configured");
        };
        assert_eq!(details.summary, "default profile");
    }

    #[test]
    fn render_single_omits_role_line_when_missing() {
        let p = ProfileSummary {
            name: "vouch".to_string(),
            target: None,
        };
        let IntegrationState::Configured(details) = render_single(&p, 0) else {
            panic!("expected Configured");
        };
        assert!(details.details.is_empty());
    }

    #[test]
    fn render_single_shows_org_count_when_nonzero() {
        let p = ProfileSummary {
            name: "vouch-prod".to_string(),
            target: Some("arn:aws:iam::111:role/Admin".to_string()),
        };
        let IntegrationState::Configured(details) = render_single(&p, 2) else {
            panic!("expected Configured");
        };
        assert_eq!(
            details.details,
            vec![
                (
                    "Role".to_string(),
                    "arn:aws:iam::111:role/Admin".to_string()
                ),
                ("Organizations".to_string(), "2".to_string()),
            ]
        );
    }

    fn make_profiles(count: usize) -> Vec<ProfileSummary> {
        (1..=count)
            .map(|i| ProfileSummary {
                name: format!("vouch-{i}"),
                target: Some(format!("arn:aws:iam::{i}11:role/R{i}")),
            })
            .collect()
    }

    #[test]
    fn render_three_profiles_lists_all() {
        let IntegrationState::Configured(details) = render_multi(&make_profiles(3), 0) else {
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
            ProfileSummary {
                name: "short".to_string(),
                target: Some("arn:aws:iam::111:role/A".to_string()),
            },
            ProfileSummary {
                name: "much-longer-name".to_string(),
                target: Some("arn:aws:iam::222:role/B".to_string()),
            },
        ];
        let IntegrationState::Configured(details) = render_multi(&profiles, 0) else {
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
        let IntegrationState::Configured(details) = render_multi(&make_profiles(5), 0) else {
            panic!("expected Configured");
        };
        assert_eq!(details.summary, "5 profiles, showing 3");
        assert_eq!(details.details.len(), 3);
    }

    #[test]
    fn render_multi_with_orgs_folds_org_count_into_summary() {
        let IntegrationState::Configured(details) = render_multi(&make_profiles(2), 3) else {
            panic!("expected Configured");
        };
        assert_eq!(details.summary, "2 profiles (3 orgs)");
    }

    #[test]
    fn render_profile_without_role_shows_placeholder() {
        let profiles = vec![
            ProfileSummary {
                name: "vouch-a".to_string(),
                target: None,
            },
            ProfileSummary {
                name: "vouch-b".to_string(),
                target: Some("arn:aws:iam::111:role/B".to_string()),
            },
        ];
        let IntegrationState::Configured(details) = render_multi(&profiles, 0) else {
            panic!("expected Configured");
        };
        assert!(details.details[0].1.ends_with("= (no --role)"));
        assert!(details.details[1].1.ends_with("= arn:aws:iam::111:role/B"));
    }

    #[test]
    fn render_idc_profile_shows_idc_target() {
        let profiles = vec![ProfileSummary {
            name: "vouch-prod-admin".to_string(),
            target: Some("IdC 123456789012/AdministratorAccess".to_string()),
        }];
        let IntegrationState::Configured(details) = render_configured(&profiles, 1) else {
            panic!("expected Configured");
        };
        assert_eq!(details.summary, "profile: vouch-prod-admin");
        assert_eq!(
            details.details,
            vec![
                (
                    "Role".to_string(),
                    "IdC 123456789012/AdministratorAccess".to_string()
                ),
                ("Organizations".to_string(), "1".to_string()),
            ]
        );
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
