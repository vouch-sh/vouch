// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS config file (~/.aws/config) parsing utilities.
//!
//! Uses proper INI parsing instead of fragile string manipulation.
//! This preserves existing configuration when adding/modifying profiles.

use anyhow::{Context, Result};
use ini::Ini;
use std::path::PathBuf;
use vouch_cli::{tr, tr_args};

/// Represents an AWS profile configuration.
#[derive(Debug, Clone, Default)]
pub(crate) struct AwsProfile {
    /// Profile name (e.g., "vouch", "default", "prod").
    pub name: String,
    /// The credential_process command if configured.
    pub credential_process: Option<String>,
    /// The AWS region if configured.
    pub region: Option<String>,
    /// The output format if configured (e.g., "json", "text", "table").
    pub output: Option<String>,
}

/// A Vouch-managed AWS profile and the role ARN its `credential_process` targets.
#[derive(Debug, Clone)]
pub(crate) struct VouchProfile {
    /// Profile name as it appears in `~/.aws/config`.
    pub name: String,
    /// Role ARN extracted from the profile's `credential_process`.
    pub role_arn: String,
}

/// AWS config file parser and writer.
///
/// Uses rust-ini to properly parse and modify ~/.aws/config files,
/// preserving existing sections and keys when making changes.
pub(crate) struct AwsConfig {
    ini: Ini,
    path: PathBuf,
}

impl AwsConfig {
    /// Load AWS config from the default path (~/.aws/config).
    pub(crate) fn load() -> Result<Self> {
        let path = Self::default_path()?;
        Self::load_from(path)
    }

    /// Load AWS config from a specific path.
    pub(crate) fn load_from(path: PathBuf) -> Result<Self> {
        let ini = if path.exists() {
            Ini::load_from_file(&path)
                .with_context(|| tr_args!("err-failed-load", value = path.display().to_string()))?
        } else {
            Ini::new()
        };
        Ok(Self { ini, path })
    }

    /// Create an empty config for a specific path.
    #[must_use]
    pub(crate) fn empty(path: PathBuf) -> Self {
        Self {
            ini: Ini::new(),
            path,
        }
    }

    /// Check if a profile exists in the config.
    #[must_use]
    pub(crate) fn profile_exists(&self, name: &str) -> bool {
        let section = Self::profile_to_section(name);
        self.ini.section(Some(section.as_str())).is_some()
    }

    /// Get a profile by name.
    #[must_use]
    pub(crate) fn get_profile(&self, name: &str) -> Option<AwsProfile> {
        let section_name = Self::profile_to_section(name);
        let section = self.ini.section(Some(section_name.as_str()))?;
        Some(AwsProfile {
            name: name.to_string(),
            credential_process: section.get("credential_process").map(|s| s.to_string()),
            // A bare `region =` line means unset, matching the env-var handling
            // in `env_region` — an empty region would otherwise short-circuit
            // the fallback chain and build endpoints like
            // `https://sts..amazonaws.com`.
            region: vouch_common::env::non_empty(section.get("region").map(|s| s.to_string())),
            output: section.get("output").map(|s| s.to_string()),
        })
    }

    /// Find every vouch profile that names a role ARN, in file order.
    ///
    /// Identity Center profiles written by `vouch setup aws --discover` also use
    /// a vouch `credential_process`, but carry `--account`/`--permission-set`
    /// instead of `--role`, so they cannot serve the role-based credential
    /// commands and are excluded here.
    #[must_use]
    pub(crate) fn vouch_profiles_with_role(&self) -> Vec<VouchProfile> {
        let mut profiles = Vec::new();
        for profile in self.find_all_vouch_profiles() {
            let Some(line) = profile
                .credential_process
                .as_deref()
                .and_then(CredentialProcessLine::parse)
            else {
                continue;
            };
            match line {
                CredentialProcessLine::Role { role_arn, via: _ } => profiles.push(VouchProfile {
                    name: profile.name,
                    role_arn,
                }),
                CredentialProcessLine::IdentityCenter {
                    application_arn: _,
                    account: _,
                    permission_set: _,
                } => {}
            }
        }
        profiles
    }

    /// Find all profiles that use vouch via `credential_process`.
    #[must_use]
    pub(crate) fn find_all_vouch_profiles(&self) -> Vec<AwsProfile> {
        let mut profiles = Vec::new();
        for (section_name, props) in &self.ini {
            let Some(section_str) = section_name else {
                continue;
            };
            let Some(profile_name) = Self::section_to_profile(section_str) else {
                continue;
            };

            let is_vouch_cp = props
                .get("credential_process")
                .is_some_and(|cp| cp.contains("vouch"));

            if is_vouch_cp {
                profiles.push(Self::props_to_profile(profile_name, props));
            }
        }
        profiles
    }

    /// Build an `AwsProfile` from INI section properties.
    fn props_to_profile(name: String, props: &ini::Properties) -> AwsProfile {
        AwsProfile {
            name,
            credential_process: props.get("credential_process").map(|s| s.to_string()),
            // Bare `region =` means unset — see `get_profile`.
            region: vouch_common::env::non_empty(props.get("region").map(|s| s.to_string())),
            output: props.get("output").map(|s| s.to_string()),
        }
    }

    /// Find an existing vouch profile that targets a specific role ARN.
    #[must_use]
    pub(crate) fn find_vouch_profile_for_role(&self, role_arn: &str) -> Option<AwsProfile> {
        self.find_all_vouch_profiles().into_iter().find(|p| {
            match p
                .credential_process
                .as_deref()
                .and_then(CredentialProcessLine::parse)
            {
                Some(CredentialProcessLine::Role {
                    role_arn: existing,
                    via: _,
                }) => existing == role_arn,
                Some(CredentialProcessLine::IdentityCenter {
                    application_arn: _,
                    account: _,
                    permission_set: _,
                })
                | None => false,
            }
        })
    }

    /// Get the next available vouch profile name.
    ///
    /// Returns "vouch" if it doesn't exist, otherwise "vouch-2", "vouch-3", etc.
    #[must_use]
    pub(crate) fn next_vouch_profile_name(&self) -> String {
        if !self.profile_exists("vouch") {
            return "vouch".to_string();
        }
        let mut n = 2u32;
        loop {
            let candidate = format!("vouch-{n}");
            if !self.profile_exists(&candidate) {
                return candidate;
            }
            n = n.saturating_add(1);
        }
    }

    /// Set or update a profile in the config.
    ///
    /// This preserves existing keys in the profile section that are not
    /// explicitly set in the `AwsProfile`. Fields set to `None` are left
    /// unchanged (not removed).
    pub(crate) fn set_profile(&mut self, profile: &AwsProfile) {
        let section = Self::profile_to_section(&profile.name);
        if let Some(ref cp) = profile.credential_process {
            self.ini
                .with_section(Some(section.clone()))
                .set("credential_process", cp);
        }
        if let Some(ref region) = profile.region {
            self.ini
                .with_section(Some(section.clone()))
                .set("region", region);
        }
        if let Some(ref output) = profile.output {
            self.ini.with_section(Some(section)).set("output", output);
        }
    }

    /// Save the config to its file path.
    ///
    /// Uses atomic write (temp file + rename) to prevent corruption
    /// if the process is interrupted mid-write.
    pub(crate) fn save(&self) -> Result<()> {
        let mut buf = Vec::new();
        self.ini.write_to(&mut buf).with_context(|| {
            tr_args!(
                "err-failed-serialize",
                value = self.path.display().to_string()
            )
        })?;
        vouch_common::fs::atomic_write(&self.path, &buf).with_context(|| {
            tr_args!(
                "err-failed-write-5",
                value = self.path.display().to_string()
            )
        })
    }

    /// Convert a profile name to its INI section name.
    ///
    /// The "default" profile is stored as `[default]`, while all other
    /// profiles are stored as `[profile name]`.
    fn profile_to_section(name: &str) -> String {
        if name == "default" {
            "default".to_string()
        } else {
            format!("profile {name}")
        }
    }

    /// Extract a profile name from an INI section name.
    ///
    /// Returns None for sections that are not profiles (e.g., `[sso-session]`).
    fn section_to_profile(section: &str) -> Option<String> {
        if section == "default" {
            Some("default".to_string())
        } else {
            section.strip_prefix("profile ").map(|s| s.to_string())
        }
    }

    /// Get the default AWS config path (~/.aws/config).
    pub(crate) fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context(tr!("err-could-not-determine-home-directory"))?;
        Ok(home.join(".aws").join("config"))
    }
}

/// A vouch `credential_process` command line, as written to `~/.aws/config`.
///
/// This is the single source of truth for the wire format: profiles are
/// generated with [`CredentialProcessLine::render`] and read back with
/// [`CredentialProcessLine::parse`], so every consumer (status display,
/// name-collision classification, the discovery sweep's org-boundary check)
/// works on typed fields instead of substring extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CredentialProcessLine {
    /// `--role <arn> [--via <management-role-arn>]` — an STS role profile,
    /// vended directly or chained through a management role.
    Role {
        role_arn: String,
        via: Option<String>,
    },
    /// `[--idc-application <arn>] --account <id> --permission-set <name>` —
    /// an Identity Center permission-set profile. Discovery always writes
    /// `--idc-application`; when absent, the credential command resolves
    /// the configured org's Identity Center instead.
    IdentityCenter {
        application_arn: Option<String>,
        account: String,
        permission_set: String,
    },
}

impl CredentialProcessLine {
    /// Parse a `credential_process` command line.
    ///
    /// Tokenizes quote-aware (values may be double-quoted) and matches
    /// flags as whole tokens, so `--account` can never match inside another
    /// flag name and a trailing flag with no value is treated as absent.
    /// Returns `None` for lines that are neither profile form — including a
    /// `--role` whose value is not an ARN.
    #[must_use]
    pub(crate) fn parse(credential_process: &str) -> Option<Self> {
        let mut role_arn = None;
        let mut via = None;
        let mut application_arn = None;
        let mut account = None;
        let mut permission_set = None;
        let mut tokens = tokenize(credential_process).into_iter();
        while let Some(token) = tokens.next() {
            match token.as_str() {
                "--role" => role_arn = tokens.next(),
                "--via" => via = tokens.next(),
                "--idc-application" => application_arn = tokens.next(),
                "--account" => account = tokens.next(),
                "--permission-set" => permission_set = tokens.next(),
                _ => {}
            }
        }
        // `arn:aws` also prefixes the GovCloud/China partitions
        // (`arn:aws-us-gov:`, `arn:aws-cn:`).
        if let Some(role_arn) = role_arn.filter(|arn| arn.starts_with("arn:aws")) {
            return Some(Self::Role { role_arn, via });
        }
        if let (Some(account), Some(permission_set)) = (account, permission_set) {
            return Some(Self::IdentityCenter {
                application_arn,
                account,
                permission_set,
            });
        }
        None
    }

    /// Render the `credential_process` command line for this profile.
    #[must_use]
    pub(crate) fn render(&self, vouch_path: &std::path::Path) -> String {
        match self {
            Self::Role {
                role_arn,
                via: Some(via),
            } => format!(
                "\"{}\" credential aws --role {role_arn} --via {via}",
                vouch_path.display()
            ),
            Self::Role {
                role_arn,
                via: None,
            } => format!(
                "\"{}\" credential aws --role {role_arn}",
                vouch_path.display()
            ),
            // Permission-set names cannot contain whitespace or quotes
            // (AWS allows only `[\w+=,.@-]`), so the value is unquoted;
            // parse still accepts quoted values from older configs.
            Self::IdentityCenter {
                application_arn: Some(application_arn),
                account,
                permission_set,
            } => format!(
                "\"{}\" credential aws --idc-application {application_arn} \
                 --account {account} --permission-set {permission_set}",
                vouch_path.display()
            ),
            Self::IdentityCenter {
                application_arn: None,
                account,
                permission_set,
            } => format!(
                "\"{}\" credential aws --account {account} --permission-set {permission_set}",
                vouch_path.display()
            ),
        }
    }
}

/// Split a command line into tokens, treating double-quoted spans as part
/// of the enclosing token (quotes are dropped).
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in line.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_ascii_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// Wrapper that writes config content to a file inside a temporary directory.
    /// The file handle is released immediately, but the directory (and file) persist
    /// until this struct is dropped. This avoids Windows "Access is denied" errors
    /// when `atomic_write` tries to rename over an open file handle.
    struct TempConfig {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl TempConfig {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    fn create_temp_config(content: &str) -> TempConfig {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("config");
        std::fs::write(&path, content).expect("failed to write temp config");
        TempConfig { _dir: dir, path }
    }

    #[test]
    fn test_profile_exists_vouch() {
        let content = r#"
[profile vouch]
credential_process = /usr/local/bin/vouch credential aws --role arn:aws:iam::123456789012:role/MyRole
region = us-east-1
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.profile_exists("vouch"));
        assert!(!config.profile_exists("nonexistent"));
    }

    #[test]
    fn test_profile_exists_default() {
        let content = r#"
[default]
credential_process = vouch credential aws --role arn:aws:iam::123456789012:role/DefaultRole
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.profile_exists("default"));
        assert!(!config.profile_exists("vouch"));
    }

    #[test]
    fn test_get_profile() {
        let content = r#"
[profile vouch]
credential_process = /usr/local/bin/vouch credential aws --role arn:aws:iam::123456789012:role/MyRole
region = us-east-1
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        let profile = config.get_profile("vouch").expect("profile should exist");
        assert_eq!(profile.name, "vouch");
        assert_eq!(
            profile.credential_process,
            Some(
                "/usr/local/bin/vouch credential aws --role arn:aws:iam::123456789012:role/MyRole"
                    .to_string()
            )
        );
        assert_eq!(profile.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn test_get_profile_default() {
        let content = r#"
[default]
credential_process = vouch credential aws --role arn:aws:iam::123456789012:role/DefaultRole
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        let profile = config.get_profile("default").expect("profile should exist");
        assert_eq!(profile.name, "default");
        assert_eq!(
            profile.credential_process,
            Some(
                "vouch credential aws --role arn:aws:iam::123456789012:role/DefaultRole"
                    .to_string()
            )
        );
        assert_eq!(profile.region, None);
    }

    #[test]
    fn test_get_profile_empty_region_is_unset() {
        let content = r#"
[profile vouch]
credential_process = vouch credential aws --role arn:aws:iam::123456789012:role/MyRole
region =
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        let profile = config.get_profile("vouch").expect("profile should exist");
        assert_eq!(profile.region, None);

        let vouch_profiles = config.find_all_vouch_profiles();
        let profile = vouch_profiles
            .first()
            .expect("vouch profile should be found");
        assert_eq!(profile.region, None);
    }

    #[test]
    fn test_vouch_profiles_with_role() {
        let content = r#"
[profile prod]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-west-2

[profile vouch]
credential_process = /usr/local/bin/vouch credential aws --role arn:aws:iam::123456789012:role/MyRole
region = us-east-1
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        let profiles = config.vouch_profiles_with_role();
        assert_eq!(profiles.len(), 1);
        let profile = profiles.first().unwrap();
        assert_eq!(profile.name, "vouch");
        assert_eq!(profile.role_arn, "arn:aws:iam::123456789012:role/MyRole");
    }

    #[test]
    fn test_vouch_profiles_with_role_in_default() {
        let content = r#"
[default]
credential_process = vouch credential aws --role arn:aws:iam::123456789012:role/DefaultRole
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        let profiles = config.vouch_profiles_with_role();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles.first().unwrap().name, "default");
    }

    #[test]
    fn test_vouch_profiles_with_role_none() {
        let content = r#"
[profile prod]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.vouch_profiles_with_role().is_empty());
    }

    #[test]
    fn test_sso_session_is_not_profile() {
        // [sso-session] sections should not be treated as profiles
        let content = r#"
[sso-session my-sso]
sso_start_url = https://my-sso.awsapps.com/start
credential_process = vouch credential aws --role some-role
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        // Should not find vouch because [sso-session] is not a profile
        assert!(config.vouch_profiles_with_role().is_empty());
        assert!(!config.profile_exists("my-sso"));
    }

    #[test]
    fn test_set_profile_new() {
        let content = r#"
[profile existing]
region = us-west-2
"#;
        let file = create_temp_config(content);
        let mut config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        config.set_profile(&AwsProfile {
            name: "vouch".to_string(),
            credential_process: Some(
                "vouch credential aws --role arn:aws:iam::123:role/Test".to_string(),
            ),
            region: Some("us-east-1".to_string()),
            output: Some("json".to_string()),
        });
        config.save().unwrap();

        // Reload and verify
        let reloaded = AwsConfig::load_from(file.path().to_path_buf()).unwrap();
        assert!(reloaded.profile_exists("vouch"));
        assert!(reloaded.profile_exists("existing"));

        let vouch = reloaded.get_profile("vouch").unwrap();
        assert_eq!(
            vouch.credential_process,
            Some("vouch credential aws --role arn:aws:iam::123:role/Test".to_string())
        );
        assert_eq!(vouch.region, Some("us-east-1".to_string()));
        assert_eq!(vouch.output, Some("json".to_string()));

        // Verify existing profile is preserved
        let existing = reloaded.get_profile("existing").unwrap();
        assert_eq!(existing.region, Some("us-west-2".to_string()));
    }

    #[test]
    fn test_set_profile_default() {
        let file = create_temp_config("");
        let mut config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        config.set_profile(&AwsProfile {
            name: "default".to_string(),
            credential_process: Some(
                "vouch credential aws --role arn:aws:iam::123:role/Test".to_string(),
            ),
            region: None,
            output: None,
        });
        config.save().unwrap();

        let reloaded = AwsConfig::load_from(file.path().to_path_buf()).unwrap();
        assert!(reloaded.profile_exists("default"));
        let profile = reloaded.get_profile("default").unwrap();
        assert!(
            profile
                .credential_process
                .as_ref()
                .unwrap()
                .contains("vouch")
        );
    }

    #[test]
    fn test_complex_config_preservation() {
        // Test that complex configs with SSO sessions, multiple profiles, etc. are preserved
        let content = r#"
[sso-session my-sso]
sso_start_url = https://my-sso.awsapps.com/start
sso_region = us-east-1

[profile sso-user]
sso_session = my-sso
sso_account_id = 123456789012
sso_role_name = Developer
region = us-east-1

[profile prod]
role_arn = arn:aws:iam::111111111111:role/AdminRole
source_profile = sso-user
region = us-west-2

[default]
region = us-east-1
output = json
"#;
        let file = create_temp_config(content);
        let mut config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        // Add a new vouch profile
        config.set_profile(&AwsProfile {
            name: "vouch".to_string(),
            credential_process: Some(
                "vouch credential aws --role arn:aws:iam::123:role/Test".to_string(),
            ),
            region: None,
            output: Some("json".to_string()),
        });
        config.save().unwrap();

        // Reload and verify all existing sections are preserved
        let reloaded = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        // Check vouch profile was added
        assert!(reloaded.profile_exists("vouch"));

        // Check existing profiles are preserved
        assert!(reloaded.profile_exists("sso-user"));
        assert!(reloaded.profile_exists("prod"));
        assert!(reloaded.profile_exists("default"));

        // Verify sso-user has its settings
        let sso_user = reloaded.get_profile("sso-user").unwrap();
        assert_eq!(sso_user.region, Some("us-east-1".to_string()));

        // Verify default has its settings
        let default = reloaded.get_profile("default").unwrap();
        assert_eq!(default.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn test_empty_file() {
        let file = create_temp_config("");
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(!config.profile_exists("vouch"));
        assert!(!config.profile_exists("default"));
        assert!(config.vouch_profiles_with_role().is_empty());
    }

    #[test]
    fn test_load_nonexistent_file() {
        let path = PathBuf::from("/tmp/nonexistent_aws_config_test_12345");
        let config = AwsConfig::load_from(path).unwrap();

        assert!(!config.profile_exists("vouch"));
        assert!(config.vouch_profiles_with_role().is_empty());
    }

    #[test]
    fn test_parse_role_line() {
        assert_eq!(
            CredentialProcessLine::parse(
                "/usr/local/bin/vouch credential aws --role arn:aws:iam::123456789012:role/MyRole"
            ),
            Some(CredentialProcessLine::Role {
                role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
                via: None,
            })
        );
        // Extra whitespace between flag and value.
        assert_eq!(
            CredentialProcessLine::parse(
                "vouch credential aws --role   arn:aws:iam::999888777666:role/DevRole"
            ),
            Some(CredentialProcessLine::Role {
                role_arn: "arn:aws:iam::999888777666:role/DevRole".to_string(),
                via: None,
            })
        );
        // GovCloud partition ARNs share the `arn:aws` prefix.
        assert_eq!(
            CredentialProcessLine::parse(
                "vouch credential aws --role arn:aws-us-gov:iam::123456789012:role/GovRole"
            ),
            Some(CredentialProcessLine::Role {
                role_arn: "arn:aws-us-gov:iam::123456789012:role/GovRole".to_string(),
                via: None,
            })
        );
    }

    #[test]
    fn test_parse_chained_role_line() {
        assert_eq!(
            CredentialProcessLine::parse(
                "\"/usr/local/bin/vouch\" credential aws --role arn:aws:iam::1:role/R \
                 --via arn:aws:iam::2:role/vouch/Hub"
            ),
            Some(CredentialProcessLine::Role {
                role_arn: "arn:aws:iam::1:role/R".to_string(),
                via: Some("arn:aws:iam::2:role/vouch/Hub".to_string()),
            })
        );
        // A trailing flag with no value is treated as absent, not empty.
        assert_eq!(
            CredentialProcessLine::parse("vouch credential aws --role arn:aws:iam::1:role/R --via"),
            Some(CredentialProcessLine::Role {
                role_arn: "arn:aws:iam::1:role/R".to_string(),
                via: None,
            })
        );
    }

    #[test]
    fn test_parse_identity_center_line() {
        // Older discovery runs quoted the permission-set name; parse must
        // keep accepting those lines even though render no longer quotes.
        assert_eq!(
            CredentialProcessLine::parse(
                r#""/usr/local/bin/vouch" credential aws --idc-application arn:aws:sso::1:application/ssoins-x/apl-y --account 111111111111 --permission-set "Admin""#
            ),
            Some(CredentialProcessLine::IdentityCenter {
                application_arn: Some("arn:aws:sso::1:application/ssoins-x/apl-y".to_string()),
                account: "111111111111".to_string(),
                permission_set: "Admin".to_string(),
            })
        );
        // `--idc-application` is optional: the credential command resolves
        // the configured org's Identity Center when it is absent.
        assert_eq!(
            CredentialProcessLine::parse(
                "vouch credential aws --account 111111111111 --permission-set Admin"
            ),
            Some(CredentialProcessLine::IdentityCenter {
                application_arn: None,
                account: "111111111111".to_string(),
                permission_set: "Admin".to_string(),
            })
        );
    }

    #[test]
    fn test_parse_rejects_non_profile_lines() {
        // No flags at all.
        assert_eq!(CredentialProcessLine::parse("vouch credential aws"), None);
        // A --role value that is not an ARN.
        assert_eq!(
            CredentialProcessLine::parse("vouch credential aws --role not-an-arn"),
            None
        );
        // An Identity Center line needs both --account and --permission-set.
        assert_eq!(
            CredentialProcessLine::parse("vouch credential aws --account 111111111111"),
            None
        );
    }

    mod roundtrip {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Every rendered role line parses back to itself.
            #[test]
            fn role_line_roundtrips(
                account in "[0-9]{12}",
                role_name in "[A-Za-z0-9+=,.@_-]{1,64}",
                chained in proptest::bool::ANY,
            ) {
                let line = CredentialProcessLine::Role {
                    role_arn: format!("arn:aws:iam::{account}:role/vouch/{role_name}"),
                    via: chained
                        .then(|| format!("arn:aws:iam::{account}:role/vouch/Hub")),
                };
                let rendered = line.render(std::path::Path::new("/usr/local/bin/vouch"));
                prop_assert_eq!(CredentialProcessLine::parse(&rendered), Some(line));
            }

            /// Every rendered Identity Center line parses back to itself.
            #[test]
            fn identity_center_line_roundtrips(
                account in "[0-9]{12}",
                permission_set in "[A-Za-z0-9+=,.@_-]{1,32}",
                pinned_application in proptest::bool::ANY,
            ) {
                let line = CredentialProcessLine::IdentityCenter {
                    application_arn: pinned_application.then(|| format!(
                        "arn:aws:sso::{account}:application/ssoins-1/apl-1"
                    )),
                    account,
                    permission_set,
                };
                let rendered = line.render(std::path::Path::new("/usr/local/bin/vouch"));
                prop_assert_eq!(CredentialProcessLine::parse(&rendered), Some(line));
            }
        }
    }

    #[test]
    fn test_multiple_profiles_returns_every_candidate() {
        let content = r#"
[profile regular]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = secret

[profile vouch-prod]
credential_process = vouch credential aws --role arn:aws:iam::111:role/Prod

[profile vouch-staging]
credential_process = vouch credential aws --role arn:aws:iam::222:role/Staging
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        // Every candidate must be reported so the caller can refuse to guess;
        // silently returning whichever came first signed requests for the wrong
        // account.
        let profiles = config.vouch_profiles_with_role();
        let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["vouch-prod", "vouch-staging"]);
        assert_eq!(
            profiles.first().unwrap().role_arn,
            "arn:aws:iam::111:role/Prod"
        );
    }

    #[test]
    fn test_identity_center_profile_is_not_a_role_candidate() {
        // `vouch setup aws --discover` writes IdC profiles whose credential_process
        // matches "vouch" but names no --role, so they cannot serve role-based
        // credential commands.
        let content = r#"
[profile vouch-idc]
credential_process = vouch credential aws --account 111111111111 --permission-set Admin

[profile vouch-role]
credential_process = vouch credential aws --role arn:aws:iam::222:role/Staging
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert_eq!(config.find_all_vouch_profiles().len(), 2);
        let profiles = config.vouch_profiles_with_role();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles.first().unwrap().name, "vouch-role");
    }

    #[test]
    fn test_whitespace_handling() {
        let content = r#"
  [profile vouch]
  credential_process = vouch credential aws --role arn:aws:iam::123:role/Test
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        // rust-ini handles whitespace properly
        assert!(config.profile_exists("vouch"));
        let profiles = config.vouch_profiles_with_role();
        assert_eq!(profiles.first().unwrap().name, "vouch");
    }

    #[test]
    fn test_find_all_vouch_profiles() {
        let content = r#"
[profile regular]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE

[profile vouch]
credential_process = vouch credential aws --role arn:aws:iam::111:role/Prod

[profile vouch-2]
credential_process = vouch credential aws --role arn:aws:iam::222:role/Staging
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        let profiles = config.find_all_vouch_profiles();
        assert_eq!(profiles.len(), 2);
        let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"vouch"));
        assert!(names.contains(&"vouch-2"));
    }

    #[test]
    fn test_find_all_vouch_profiles_empty() {
        let content = r#"
[profile regular]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.find_all_vouch_profiles().is_empty());
    }

    #[test]
    fn test_find_vouch_profile_for_role_found() {
        let content = r#"
[profile vouch]
credential_process = vouch credential aws --role arn:aws:iam::111:role/Prod

[profile vouch-2]
credential_process = vouch credential aws --role arn:aws:iam::222:role/Staging
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        let found = config
            .find_vouch_profile_for_role("arn:aws:iam::222:role/Staging")
            .expect("should find profile for role");
        assert_eq!(found.name, "vouch-2");
    }

    #[test]
    fn test_find_vouch_profile_for_role_not_found() {
        let content = r#"
[profile vouch]
credential_process = vouch credential aws --role arn:aws:iam::111:role/Prod
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(
            config
                .find_vouch_profile_for_role("arn:aws:iam::999:role/Other")
                .is_none()
        );
    }

    #[test]
    fn test_next_vouch_profile_name_empty() {
        let file = create_temp_config("");
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert_eq!(config.next_vouch_profile_name(), "vouch");
    }

    #[test]
    fn test_next_vouch_profile_name_vouch_exists() {
        let content = r#"
[profile vouch]
credential_process = vouch credential aws --role arn:aws:iam::111:role/Prod
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert_eq!(config.next_vouch_profile_name(), "vouch-2");
    }

    #[test]
    fn test_next_vouch_profile_name_vouch_and_vouch2_exist() {
        let content = r#"
[profile vouch]
credential_process = vouch credential aws --role arn:aws:iam::111:role/Prod

[profile vouch-2]
credential_process = vouch credential aws --role arn:aws:iam::222:role/Staging
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert_eq!(config.next_vouch_profile_name(), "vouch-3");
    }
}
