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

use vouch_cli::{tr, tr_args};

use crate::exit_code::CliError;

/// Which override flag(s) the invoking command accepts.
///
/// Threaded into [`resolve_vouch_profile`] from the call site so an ambiguous-
/// profile error suggests a flag the invoking command actually has — some
/// credential commands (EKS, RDS, Redshift) expose only `--role`, most setup
/// commands and CodeArtifact/Docker/CodeCommit expose only `--profile`, and
/// `aws console` takes either.
#[derive(Clone, Copy)]
pub(crate) enum ProfileOverride {
    /// The command accepts `--profile <name>`.
    Profile,
    /// The command accepts `--role <arn>`.
    Role,
    /// The command accepts both `--profile <name>` and `--role <arn>`.
    ProfileOrRole,
}

impl ProfileOverride {
    /// Rendered into the ambiguity error's Fluent variable.
    fn hint(self) -> String {
        match self {
            Self::Profile => tr!("aws-override-hint-profile"),
            Self::Role => tr!("aws-override-hint-role"),
            Self::ProfileOrRole => tr!("aws-override-hint-profile-or-role"),
        }
    }
}

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
pub(crate) fn resolve_vouch_profile(
    explicit: Option<&str>,
    accepts: ProfileOverride,
) -> anyhow::Result<VouchProfile> {
    let config = AwsConfig::load()?;
    let env_profile = std::env::var("AWS_PROFILE").ok();
    select_vouch_profile(&config, explicit, env_profile.as_deref(), accepts)
}

/// Apply the profile resolution order to an already-loaded config.
///
/// Split from [`resolve_vouch_profile`] so the ordering can be tested without
/// touching the filesystem or the process environment. Re-used by the
/// CodeCommit remote helper's region resolution, which needs to resolve the
/// Vouch profile against an already-loaded config rather than re-reading disk.
pub(crate) fn select_vouch_profile(
    config: &AwsConfig,
    explicit: Option<&str>,
    env_profile: Option<&str>,
    accepts: ProfileOverride,
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
        [] => Err(CliError::ConfigError(tr!("aws-err-no-vouch-profile")).into()),
        [only] => Ok(only.clone()),
        candidates => {
            let width = candidates.iter().map(|p| p.name.len()).max().unwrap_or(0);
            // Leading newline: joined with the Fluent message's own line break
            // before this variable, it reproduces the blank line that sets the
            // listing apart from the heading above and the suggestion below.
            let mut listing = String::from("\n");
            for profile in candidates {
                listing.push_str(&format!(
                    "  {:<width$}  {}\n",
                    profile.name, profile.role_arn
                ));
            }
            Err(CliError::ConfigError(tr_args!(
                "aws-err-ambiguous-profile",
                listing = listing,
                override_hint = accepts.hint(),
            ))
            .into())
        }
    }
}

/// Look up a specific profile by name and extract the role it targets.
fn named_vouch_profile(config: &AwsConfig, name: &str) -> anyhow::Result<VouchProfile> {
    let Some(profile) = config.get_profile(name) else {
        return Err(
            CliError::ConfigError(tr_args!("aws-err-profile-not-found", profile = name)).into(),
        );
    };

    let Some(credential_process) = profile.credential_process else {
        return Err(
            CliError::ConfigError(tr_args!("aws-err-profile-not-managed", profile = name)).into(),
        );
    };

    if let Some(role_arn) = extract_role_from_credential_process(&credential_process) {
        return Ok(VouchProfile {
            name: name.to_string(),
            role_arn,
        });
    }

    if let Some(target) = extract_idc_target_from_credential_process(&credential_process) {
        return Err(CliError::ConfigError(tr_args!(
            "aws-err-profile-is-identity-center",
            profile = name,
            target = target,
        ))
        .into());
    }

    Err(CliError::ConfigError(tr_args!("aws-err-profile-missing-role", profile = name)).into())
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

    Ok(env_region())
}

/// Region from the process environment, treating empty values as unset.
///
/// An empty `AWS_REGION=""` must fall through to the next source instead of
/// producing endpoints like `https://sts..amazonaws.com`. `AWS_DEFAULT_REGION`
/// keeps its historical precedence over `AWS_REGION` here.
pub(crate) fn env_region() -> Option<String> {
    vouch_common::env::non_empty_env("AWS_DEFAULT_REGION")
        .or_else(|| vouch_common::env::non_empty_env("AWS_REGION"))
}

/// The error returned when no region could be determined from any source.
fn no_region_error() -> CliError {
    CliError::ConfigError(tr!("aws-err-no-region"))
}

/// Validate that a resolved region belongs to the same AWS partition as the
/// role ARN.
///
/// The STS endpoint DNS suffix is derived from the role ARN's partition, so a
/// region from a different partition (e.g., `cn-north-1` with a commercial
/// role ARN) would produce an invalid endpoint URL — the request fails with a
/// confusing DNS or connection error. Catch the mismatch early with a clear
/// message instead.
///
/// # Errors
///
/// Returns a [`CliError::ConfigError`] when the partition inferred from
/// `region` (via [`Partition::from_region`]) differs from `arn_partition`.
fn validate_region_partition(
    region: &str,
    arn_partition: vouch_common::aws::Partition,
) -> Result<(), crate::exit_code::CliError> {
    let region_partition = vouch_common::aws::Partition::from_region(region);
    if region_partition == arn_partition {
        return Ok(());
    }
    Err(crate::exit_code::CliError::ConfigError(tr_args!(
        "aws-err-region-partition-mismatch",
        region = region.to_string(),
        region_partition = region_partition.as_str().to_string(),
        arn_partition = arn_partition.as_str().to_string(),
    )))
}

/// Validate that a region belongs to the same AWS partition as a role ARN.
///
/// Thin wrapper over [`validate_region_partition`] for callers that hold the
/// ARN string rather than an already-parsed partition — region/ARN pairs that
/// only meet at a service call, such as the CodeCommit helpers, where the
/// endpoint is built from the region while credentials mint under the role's
/// partition.
///
/// # Errors
///
/// Returns a [`CliError::ConfigError`] when the ARN's partition cannot be
/// parsed or the region belongs to a different partition.
pub(crate) fn validate_region_for_role(region: &str, role_arn: &str) -> Result<(), CliError> {
    let arn_partition = vouch_common::aws::Partition::from_arn(role_arn)
        .map_err(|_| CliError::ConfigError(tr!("aws-console-err-invalid-role-arn")))?;
    validate_region_partition(region, arn_partition)
}

/// Resolve the AWS region, checking profile config then environment variables.
///
/// When `role_arn` is provided, validates that the resolved region belongs
/// to the same AWS partition as the ARN so a mismatched region fails early
/// with a clear message — whether the caller builds a service endpoint from
/// the ARN's partition (STS, EKS `describe_cluster`) or hands the region to
/// the native AWS CLI while `credential_process` mints credentials under the
/// ARN's partition (`setup ssm`). Callers with no role ARN to validate
/// against (e.g. `setup ssm` with an explicit non-Vouch `--profile`) pass
/// `None` and accept the region as-is.
pub(crate) fn resolve_region(
    region: Option<&str>,
    profile_name: &str,
    role_arn: Option<&str>,
) -> anyhow::Result<String> {
    let Some(resolved) = find_region(region, Some(profile_name))? else {
        return Err(no_region_error().into());
    };
    if let Some(arn) = role_arn {
        validate_region_for_role(&resolved, arn)?;
    }
    Ok(resolved)
}

/// Resolve the AWS region, falling back to the partition's default STS region
/// derived from the role ARN when no region is configured.
///
/// The region comes from the profile that targets `role_arn`, so a machine with
/// several Vouch profiles does not borrow an unrelated profile's region.
///
/// Validates that the resolved region belongs to the same AWS partition as
/// `role_arn`. A mismatched region (e.g., a China region with a commercial
/// role ARN) would produce an invalid STS endpoint URL, since the DNS suffix
/// is derived from the role ARN's partition.
pub(crate) fn resolve_region_with_fallback(role_arn: &str) -> anyhow::Result<String> {
    let arn_partition = vouch_common::aws::Partition::from_arn(role_arn).map_err(|_| {
        crate::exit_code::CliError::ConfigError(tr!("aws-console-err-invalid-role-arn"))
    })?;

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
        validate_region_partition(&r, arn_partition)?;
        return Ok(r);
    }

    let default = arn_partition.default_sts_region();
    tracing::debug!("no region configured, defaulting to {default} for STS");
    Ok(default.to_string())
}

/// Resolve AWS role ARN and region from CLI flags or local config.
///
/// This is the standard resolution pattern used by credential commands
/// that need both a role and region (EKS, RDS, Redshift). It:
/// 1. Uses the `--role` flag if provided, otherwise resolves a Vouch profile
/// 2. Resolves the region from `--region`, that same profile, or env vars
///
/// Every current caller exposes only `--role` (no `--profile` flag), so an
/// ambiguous-profile error here always points at `--role`. Thread a
/// [`ProfileOverride`] through instead if a `--profile`-accepting caller is
/// ever added.
///
/// Validates that the resolved region belongs to the same AWS partition as
/// the role ARN. A mismatched region (e.g., a China region with a commercial
/// role ARN) would produce an invalid STS endpoint URL, since the DNS suffix
/// is derived from the role ARN's partition.
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
                .or_else(|| {
                    resolve_vouch_profile(profile, ProfileOverride::Role)
                        .ok()
                        .map(|p| p.name)
                });
            (owning, r.to_string())
        }
        None => {
            let resolved = resolve_vouch_profile(profile, ProfileOverride::Role)?;
            (Some(resolved.name), resolved.role_arn)
        }
    };

    let arn_partition = vouch_common::aws::Partition::from_arn(&role_arn).map_err(|_| {
        crate::exit_code::CliError::ConfigError(tr!("aws-console-err-invalid-role-arn"))
    })?;
    let region_name = find_region(region, profile_name.as_deref())?.ok_or_else(no_region_error)?;
    validate_region_partition(&region_name, arn_partition)?;

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
    clippy::unwrap_used,
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
        let resolved = select_vouch_profile(&aws, None, None, ProfileOverride::ProfileOrRole)
            .expect("single profile resolves");
        assert_eq!(resolved.name, "vouch-demo");
        assert_eq!(resolved.role_arn, "arn:aws:iam::222222222222:role/demo");
    }

    #[test]
    fn refuses_to_guess_between_several_profiles() {
        let aws = load_config(TWO_PROFILES);
        let err = select_vouch_profile(&aws, None, None, ProfileOverride::ProfileOrRole)
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

    /// The ambiguity error suggests only the flag(s) the invoking command
    /// actually accepts — a role-only command (EKS/RDS/Redshift) must not be
    /// told to pass `--profile`, which it doesn't have.
    #[test]
    fn ambiguous_profile_error_names_only_the_accepted_override() {
        let aws = load_config(TWO_PROFILES);

        let role_only = select_vouch_profile(&aws, None, None, ProfileOverride::Role)
            .expect_err("still ambiguous")
            .to_string();
        assert!(role_only.contains("--role"), "{role_only}");
        assert!(!role_only.contains("--profile"), "{role_only}");

        let profile_only = select_vouch_profile(&aws, None, None, ProfileOverride::Profile)
            .expect_err("still ambiguous")
            .to_string();
        assert!(profile_only.contains("--profile"), "{profile_only}");
        assert!(!profile_only.contains("--role"), "{profile_only}");
    }

    #[test]
    fn explicit_profile_wins_over_ambiguity() {
        let aws = load_config(TWO_PROFILES);
        let resolved = select_vouch_profile(
            &aws,
            Some("vouch-demo"),
            None,
            ProfileOverride::ProfileOrRole,
        )
        .expect("named profile resolves");
        assert_eq!(resolved.role_arn, "arn:aws:iam::222222222222:role/demo");
    }

    #[test]
    fn aws_profile_env_resolves_ambiguity() {
        let aws = load_config(TWO_PROFILES);
        let resolved = select_vouch_profile(
            &aws,
            None,
            Some("vouch-demo"),
            ProfileOverride::ProfileOrRole,
        )
        .expect("AWS_PROFILE resolves the choice");
        assert_eq!(resolved.name, "vouch-demo");
    }

    #[test]
    fn explicit_profile_outranks_aws_profile_env() {
        let aws = load_config(TWO_PROFILES);
        let resolved = select_vouch_profile(
            &aws,
            Some("alpha-admin"),
            Some("vouch-demo"),
            ProfileOverride::ProfileOrRole,
        )
        .expect("explicit profile wins");
        assert_eq!(resolved.name, "alpha-admin");
    }

    /// AWS_PROFILE is ambient and often set for unrelated tooling, so a value
    /// that names no vouch profile is ignored rather than fatal — but it must
    /// not paper over the ambiguity either.
    #[test]
    fn non_vouch_aws_profile_env_is_ignored() {
        let aws = load_config(TWO_PROFILES);
        let err = select_vouch_profile(
            &aws,
            None,
            Some("some-other-profile"),
            ProfileOverride::ProfileOrRole,
        )
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
        let resolved = select_vouch_profile(
            &aws,
            None,
            Some("some-other-profile"),
            ProfileOverride::ProfileOrRole,
        )
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
        let err = select_vouch_profile(&aws, None, None, ProfileOverride::ProfileOrRole)
            .expect_err("nothing to resolve")
            .to_string();
        assert!(err.contains("vouch setup aws"), "{err}");
    }

    #[test]
    fn unknown_named_profile_is_reported() {
        let aws = load_config(TWO_PROFILES);
        let err = select_vouch_profile(&aws, Some("typo"), None, ProfileOverride::ProfileOrRole)
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

        let resolved = select_vouch_profile(&aws, None, None, ProfileOverride::ProfileOrRole)
            .expect("IdC profile is not a candidate");
        assert_eq!(resolved.name, "vouch-demo");

        let err = select_vouch_profile(
            &aws,
            Some("vouch-idc"),
            None,
            ProfileOverride::ProfileOrRole,
        )
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
        let err = select_vouch_profile(&aws, Some("prod"), None, ProfileOverride::ProfileOrRole)
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

    // =========================================================================
    // validate_region_partition tests
    // =========================================================================

    /// Matching region+partition combinations are accepted for every partition.
    #[test]
    fn validate_region_partition_accepts_matching_partitions() {
        validate_region_partition("us-east-1", vouch_common::aws::Partition::Aws).unwrap();
        validate_region_partition("cn-north-1", vouch_common::aws::Partition::AwsCn).unwrap();
        validate_region_partition("us-gov-west-1", vouch_common::aws::Partition::AwsUsGov).unwrap();
        validate_region_partition("eusc-de-east-1", vouch_common::aws::Partition::AwsEusc).unwrap();
        validate_region_partition("us-iso-east-1", vouch_common::aws::Partition::AwsIso).unwrap();
        validate_region_partition("us-isob-east-1", vouch_common::aws::Partition::AwsIsoB).unwrap();
        validate_region_partition("eu-isoe-west-1", vouch_common::aws::Partition::AwsIsoE).unwrap();
        validate_region_partition("us-isof-south-1", vouch_common::aws::Partition::AwsIsoF)
            .unwrap();
    }

    /// The exact scenario from the bug report: commercial role ARN with a
    /// China region from env vars. The error must name the region, both
    /// partitions, and the remediation hint.
    #[test]
    fn validate_region_partition_rejects_china_region_with_commercial_arn() {
        let err = validate_region_partition("cn-north-1", vouch_common::aws::Partition::Aws)
            .expect_err("China region must not match commercial partition");
        let msg = err.to_string();
        assert!(
            msg.contains("cn-north-1"),
            "error should name the region: {msg}"
        );
        assert!(
            msg.contains("aws-cn"),
            "error should name the region partition: {msg}"
        );
        assert!(
            msg.contains("partition 'aws'."),
            "error should name the ARN partition: {msg}"
        );
    }

    /// The reverse mismatch: China role ARN with a commercial region.
    #[test]
    fn validate_region_partition_rejects_commercial_region_with_china_arn() {
        let err = validate_region_partition("us-east-1", vouch_common::aws::Partition::AwsCn)
            .expect_err("commercial region must not match China partition");
        let msg = err.to_string();
        assert!(msg.contains("us-east-1"), "{msg}");
        assert!(
            msg.contains("partition 'aws'"),
            "error should name region partition: {msg}"
        );
        assert!(
            msg.contains("partition 'aws-cn'."),
            "error should name the ARN partition: {msg}"
        );
    }

    /// `from_region` falls back to the commercial partition for unknown
    /// regions, so an unrecognized region is accepted against a commercial
    /// ARN. This is intentional: a new commercial region that the prefix
    /// table doesn't yet know about should not break credential issuance.
    #[test]
    fn validate_region_partition_accepts_unknown_region_for_commercial() {
        validate_region_partition("us-unknown-99", vouch_common::aws::Partition::Aws)
            .expect("unknown region defaults to commercial partition");
    }

    /// An unknown region is rejected against a non-commercial ARN, because
    /// `from_region` maps it to commercial, which differs from the ARN
    /// partition.
    #[test]
    fn validate_region_partition_rejects_unknown_region_for_china() {
        validate_region_partition("us-unknown-99", vouch_common::aws::Partition::AwsCn)
            .expect_err("unknown region defaults to commercial, not China");
    }

    /// The error must be a `CliError::ConfigError` so it is mapped to the
    /// same exit code as other configuration errors.
    #[test]
    fn validate_region_partition_error_is_cli_config_error() {
        let err = validate_region_partition("cn-north-1", vouch_common::aws::Partition::Aws)
            .expect_err("mismatch");
        assert!(
            matches!(err, CliError::ConfigError(_)),
            "expected CliError::ConfigError, got: {err:?}"
        );
    }

    /// Matching region/ARN partition pairs pass for commercial, China, and
    /// GovCloud roles.
    #[test]
    fn validate_region_for_role_accepts_matching_partitions() {
        validate_region_for_role("us-east-1", "arn:aws:iam::123456789012:role/demo").unwrap();
        validate_region_for_role("cn-north-1", "arn:aws-cn:iam::123456789012:role/demo").unwrap();
        validate_region_for_role(
            "us-gov-west-1",
            "arn:aws-us-gov:iam::123456789012:role/demo",
        )
        .unwrap();
    }

    /// The CodeCommit failure mode: a region in one partition with a role ARN
    /// in another must be rejected before any request is signed.
    #[test]
    fn validate_region_for_role_rejects_cross_partition() {
        let err = validate_region_for_role("cn-north-1", "arn:aws:iam::123456789012:role/demo")
            .expect_err("commercial role must not pair with a China region");
        let msg = err.to_string();
        assert!(msg.contains("cn-north-1"), "{msg}");
    }

    /// An ARN whose partition cannot be parsed is a configuration error, not
    /// a silently skipped check.
    #[test]
    fn validate_region_for_role_rejects_unparsable_arn() {
        validate_region_for_role("us-east-1", "not-an-arn")
            .expect_err("unparsable ARN cannot be validated");
    }
}
