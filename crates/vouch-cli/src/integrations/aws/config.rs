// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS config file (~/.aws/config) parsing utilities.
//!
//! Uses proper INI parsing instead of fragile string manipulation.
//! This preserves existing configuration when adding/modifying profiles.

use anyhow::{Context, Result};
use ini::Ini;
use std::path::PathBuf;

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
                .with_context(|| format!("failed to load {}", path.display()))?
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
    #[allow(dead_code)] // Used in tests and useful for future features
    pub(crate) fn get_profile(&self, name: &str) -> Option<AwsProfile> {
        let section_name = Self::profile_to_section(name);
        let section = self.ini.section(Some(section_name.as_str()))?;
        Some(AwsProfile {
            name: name.to_string(),
            credential_process: section.get("credential_process").map(|s| s.to_string()),
            region: section.get("region").map(|s| s.to_string()),
            output: section.get("output").map(|s| s.to_string()),
        })
    }

    /// Find the first profile that uses vouch for credential_process.
    #[must_use]
    pub(crate) fn find_vouch_profile(&self) -> Option<AwsProfile> {
        self.find_all_vouch_profiles().into_iter().next()
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
            region: props.get("region").map(|s| s.to_string()),
            output: props.get("output").map(|s| s.to_string()),
        }
    }

    /// Find an existing vouch profile that targets a specific role ARN.
    #[must_use]
    pub(crate) fn find_vouch_profile_for_role(&self, role_arn: &str) -> Option<AwsProfile> {
        self.find_all_vouch_profiles().into_iter().find(|p| {
            p.credential_process
                .as_deref()
                .and_then(extract_role_from_credential_process)
                .as_deref()
                == Some(role_arn)
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
        self.ini
            .write_to(&mut buf)
            .with_context(|| format!("failed to serialize {}", self.path.display()))?;
        crate::utils::atomic_write(&self.path, &buf)
            .with_context(|| format!("failed to write {}", self.path.display()))
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
        let home = dirs::home_dir().context("could not determine home directory")?;
        Ok(home.join(".aws").join("config"))
    }
}

/// An SSO session from a `[sso-session <name>]` block in `~/.aws/config`.
#[derive(Debug, Clone)]
pub(crate) struct SsoSession {
    /// Session name (e.g., "smoketurner").
    pub name: String,
    /// SSO start URL.
    pub start_url: String,
    /// SSO region.
    pub region: String,
    /// OAuth scopes (default: `["sso:account:access"]`).
    pub scopes: Vec<String>,
}

impl AwsConfig {
    /// Find an SSO session by name, or return the first one found if `name` is `None`.
    #[must_use]
    pub(crate) fn find_sso_session(&self, name: Option<&str>) -> Option<SsoSession> {
        self.find_all_sso_sessions()
            .into_iter()
            .find(|s| name.is_none_or(|target| s.name == target))
    }

    /// Return all `[sso-session]` blocks from `~/.aws/config`, in file order.
    #[must_use]
    pub(crate) fn find_all_sso_sessions(&self) -> Vec<SsoSession> {
        let mut sessions = Vec::new();
        for (section_name, props) in &self.ini {
            let Some(section_str) = section_name else {
                continue;
            };
            let Some(session_name) = section_str.strip_prefix("sso-session ") else {
                continue;
            };
            let Some(start_url) = props.get("sso_start_url") else {
                continue;
            };
            let Some(region) = props.get("sso_region") else {
                continue;
            };
            let scopes = props
                .get("sso_registration_scopes")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["sso:account:access".to_string()]);
            sessions.push(SsoSession {
                name: session_name.to_string(),
                start_url: start_url.to_string(),
                region: region.to_string(),
                scopes,
            });
        }
        sessions
    }
}

/// Extract the AWS role ARN from a credential_process command.
///
/// Looks for `--role <arn>` in the command string.
#[must_use]
pub(crate) fn extract_role_from_credential_process(credential_process: &str) -> Option<String> {
    // Find --role and extract the next token
    if let Some(role_start) = credential_process.find("--role") {
        let after_flag = credential_process.get(role_start + 6..)?.trim_start();
        // Role ARN is the next whitespace-delimited token
        let role_arn = after_flag.split_whitespace().next()?;
        if role_arn.starts_with("arn:aws") {
            return Some(role_arn.to_string());
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
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
    fn test_find_vouch_profile() {
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

        let profile = config
            .find_vouch_profile()
            .expect("should find vouch profile");
        assert_eq!(profile.name, "vouch");
        assert!(
            profile
                .credential_process
                .as_ref()
                .unwrap()
                .contains("vouch")
        );
    }

    #[test]
    fn test_find_vouch_profile_in_default() {
        let content = r#"
[default]
credential_process = vouch credential aws --role arn:aws:iam::123456789012:role/DefaultRole
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        let profile = config
            .find_vouch_profile()
            .expect("should find vouch profile");
        assert_eq!(profile.name, "default");
    }

    #[test]
    fn test_find_vouch_profile_none() {
        let content = r#"
[profile prod]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.find_vouch_profile().is_none());
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
        assert!(config.find_vouch_profile().is_none());
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
        assert!(config.find_vouch_profile().is_none());
    }

    #[test]
    fn test_load_nonexistent_file() {
        let path = PathBuf::from("/tmp/nonexistent_aws_config_test_12345");
        let config = AwsConfig::load_from(path).unwrap();

        assert!(!config.profile_exists("vouch"));
        assert!(config.find_vouch_profile().is_none());
    }

    #[test]
    fn test_extract_role_from_credential_process() {
        assert_eq!(
            extract_role_from_credential_process(
                "/usr/local/bin/vouch credential aws --role arn:aws:iam::123456789012:role/MyRole"
            ),
            Some("arn:aws:iam::123456789012:role/MyRole".to_string())
        );
    }

    #[test]
    fn test_extract_role_with_extra_spaces() {
        assert_eq!(
            extract_role_from_credential_process(
                "vouch credential aws --role   arn:aws:iam::999888777666:role/DevRole"
            ),
            Some("arn:aws:iam::999888777666:role/DevRole".to_string())
        );
    }

    #[test]
    fn test_extract_role_govcloud() {
        assert_eq!(
            extract_role_from_credential_process(
                "vouch credential aws --role arn:aws-us-gov:iam::123456789012:role/GovRole"
            ),
            Some("arn:aws-us-gov:iam::123456789012:role/GovRole".to_string())
        );
    }

    #[test]
    fn test_extract_role_no_role_flag() {
        assert_eq!(
            extract_role_from_credential_process("vouch credential aws"),
            None
        );
    }

    #[test]
    fn test_extract_role_invalid_arn() {
        assert_eq!(
            extract_role_from_credential_process("vouch credential aws --role not-an-arn"),
            None
        );
    }

    #[test]
    fn test_multiple_profiles_finds_first_vouch() {
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

        let profile = config
            .find_vouch_profile()
            .expect("should find vouch profile");
        // Should find one of the vouch profiles (order depends on INI iteration)
        assert!(profile.name == "vouch-prod" || profile.name == "vouch-staging");
        assert!(
            profile
                .credential_process
                .as_ref()
                .unwrap()
                .contains("vouch")
        );
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
        let profile = config
            .find_vouch_profile()
            .expect("should find vouch profile");
        assert_eq!(profile.name, "vouch");
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

    #[test]
    fn test_find_sso_session_by_name() {
        let content = r#"
[sso-session smoketurner]
sso_start_url = https://smoketurner.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[sso-session other]
sso_start_url = https://other.awsapps.com/start
sso_region = eu-west-1
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        let session = config.find_sso_session(Some("smoketurner")).unwrap();
        assert_eq!(session.name, "smoketurner");
        assert_eq!(session.start_url, "https://smoketurner.awsapps.com/start");
        assert_eq!(session.region, "us-east-1");
        assert_eq!(session.scopes, vec!["sso:account:access"]);
    }

    #[test]
    fn test_find_sso_session_first_when_no_name() {
        let content = r#"
[sso-session only-session]
sso_start_url = https://example.awsapps.com/start
sso_region = us-west-2
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        // Without a name, returns the first session found
        let session = config.find_sso_session(None).unwrap();
        assert_eq!(session.name, "only-session");
        assert_eq!(session.region, "us-west-2");
    }

    #[test]
    fn test_find_sso_session_not_found() {
        let content = r#"
[profile vouch]
credential_process = vouch credential aws --role arn:aws:iam::111:role/Prod
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.find_sso_session(Some("nonexistent")).is_none());
        assert!(config.find_sso_session(None).is_none());
    }

    #[test]
    fn test_find_sso_session_default_scopes() {
        // When sso_registration_scopes is absent, default to "sso:account:access"
        let content = r#"
[sso-session my-session]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        let session = config.find_sso_session(None).unwrap();
        assert_eq!(session.scopes, vec!["sso:account:access"]);
    }

    #[test]
    fn test_find_sso_session_skips_wrong_name() {
        let content = r#"
[sso-session dev]
sso_start_url = https://dev.awsapps.com/start
sso_region = us-east-1
"#;
        let file = create_temp_config(content);
        let config = AwsConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.find_sso_session(Some("prod")).is_none());
    }
}
