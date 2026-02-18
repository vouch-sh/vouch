// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Configuration and token storage for vouch CLI.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// CLI configuration stored in ~/.vouch/config.json
///
/// Note: The token is stored as a plain string in the file for serialization purposes.
/// The config file is protected with 0600 permissions on Unix systems.
/// In memory, the token is wrapped in `SecretString` for protection and automatic
/// zeroing on drop.
#[derive(Default)]
pub struct Config {
    /// Vouch server URL.
    server_url: Option<String>,
    /// Current session token (JWT), protected in memory.
    token: Option<SecretString>,
    /// User's email address (for session naming).
    email: Option<String>,
    /// CodeArtifact profile configuration.
    codeartifact: Option<CodeArtifactConfig>,
}

/// CodeArtifact configuration with named profiles (similar to AWS CLI profiles).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CodeArtifactConfig {
    /// Name of the default profile (used when `--profile` is omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Named profiles, keyed by user-chosen name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, CodeArtifactProfile>,
}

/// A single CodeArtifact domain profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeArtifactProfile {
    /// CodeArtifact domain name.
    pub domain: String,
    /// AWS account ID that owns the domain.
    pub domain_owner: String,
    /// AWS region (e.g., "us-east-1").
    pub region: String,
}

/// Intermediate type for serialization/deserialization.
/// `SecretString` doesn't implement Serialize/Deserialize, so we use this.
/// Implements `ZeroizeOnDrop` to clear sensitive data from memory.
#[derive(Debug, Default, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
struct ConfigFile {
    server_url: Option<String>,
    token: Option<String>,
    email: Option<String>,
    #[zeroize(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    codeartifact: Option<CodeArtifactConfig>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("server_url", &self.server_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("email", &self.email)
            .field("codeartifact", &self.codeartifact)
            .finish()
    }
}

impl Config {
    /// Load configuration from disk, or return defaults if not found.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read config from {}", path.display()))?;
            let config_file: ConfigFile = serde_json::from_str(&content)
                .with_context(|| format!("failed to parse config from {}", path.display()))?;
            Ok(Self::from(config_file))
        } else {
            Ok(Self::default())
        }
    }

    /// Save configuration to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create config directory {}", parent.display())
            })?;
        }

        let config_file = ConfigFile::from(self);
        let content =
            serde_json::to_string_pretty(&config_file).context("failed to serialize config")?;

        // Write with restrictive permissions (0600)
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true).mode(0o600);
            let mut file = options
                .open(&path)
                .with_context(|| format!("failed to create config file {}", path.display()))?;
            file.write_all(content.as_bytes())
                .with_context(|| format!("failed to write config to {}", path.display()))?;
        }

        #[cfg(not(unix))]
        {
            fs::write(&path, &content)
                .with_context(|| format!("failed to write config to {}", path.display()))?;
        }

        Ok(())
    }

    /// Get the configured server URL.
    #[must_use]
    pub fn server_url(&self) -> Option<&str> {
        self.server_url.as_deref()
    }

    /// Get the current session token.
    ///
    /// Returns a reference to the `SecretString`. Use `.expose_secret()` to access
    /// the underlying string only when necessary (e.g., building HTTP headers).
    #[must_use]
    pub fn token(&self) -> Option<&SecretString> {
        self.token.as_ref()
    }

    /// Set the server URL (in memory only, call `save()` to persist).
    pub fn set_server_url(&mut self, url: &str) {
        self.server_url = Some(url.to_string());
    }

    /// Save the server URL.
    pub fn save_server_url(&mut self, url: &str) -> Result<()> {
        self.set_server_url(url);
        self.save()
    }

    /// Set a new session token (in memory only, call `save()` to persist).
    pub fn set_token(&mut self, token: &str) {
        self.token = Some(SecretString::from(token.to_string()));
    }

    /// Save a new session token.
    pub fn save_token(&mut self, token: &str) -> Result<()> {
        self.set_token(token);
        self.save()
    }

    /// Clear the session token (logout).
    pub fn clear_token(&mut self) -> Result<()> {
        self.token = None;
        self.save()
    }

    /// Get the user's email address.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Set the user's email address (in memory only, call `save()` to persist).
    pub fn set_email(&mut self, email: &str) {
        self.email = Some(email.to_string());
    }

    /// Save the user's email address.
    pub fn save_email(&mut self, email: &str) -> Result<()> {
        self.set_email(email);
        self.save()
    }

    /// Clear the user's email address.
    pub fn clear_email(&mut self) -> Result<()> {
        self.email = None;
        self.save()
    }

    /// Get the CodeArtifact configuration.
    #[must_use]
    pub fn codeartifact(&self) -> Option<&CodeArtifactConfig> {
        self.codeartifact.as_ref()
    }

    /// Save a CodeArtifact profile. If this is the first profile, it becomes the default.
    pub fn save_codeartifact_profile(
        &mut self,
        name: &str,
        profile: CodeArtifactProfile,
    ) -> Result<()> {
        let ca = self
            .codeartifact
            .get_or_insert_with(CodeArtifactConfig::default);
        if ca.profiles.is_empty() && ca.default.is_none() {
            ca.default = Some(name.to_string());
        }
        ca.profiles.insert(name.to_string(), profile);
        self.save()
    }

    /// Get the path to the config file.
    fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("could not determine home directory")?;
        Ok(home.join(".vouch").join("config.json"))
    }
}

impl From<ConfigFile> for Config {
    fn from(mut file: ConfigFile) -> Self {
        // Use std::mem::take to move values out while leaving defaults behind.
        // This works with ZeroizeOnDrop because the struct will still be dropped
        // but with default (empty) values that will be zeroed.
        Self {
            server_url: std::mem::take(&mut file.server_url),
            token: std::mem::take(&mut file.token).map(SecretString::from),
            email: std::mem::take(&mut file.email),
            codeartifact: file.codeartifact.take(),
        }
    }
}

impl From<&Config> for ConfigFile {
    fn from(config: &Config) -> Self {
        Self {
            server_url: config.server_url.clone(),
            token: config.token.as_ref().map(|s| s.expose_secret().to_string()),
            email: config.email.clone(),
            codeartifact: config.codeartifact.clone(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_codeartifact_config_round_trip() {
        let json = r#"{
            "server_url": "https://vouch.example.com",
            "token": "test-token",
            "email": "alice@example.com",
            "codeartifact": {
                "default": "prod",
                "profiles": {
                    "prod": {
                        "domain": "my-domain",
                        "domain_owner": "123456789012",
                        "region": "us-east-1"
                    },
                    "staging": {
                        "domain": "staging-domain",
                        "domain_owner": "987654321098",
                        "region": "eu-west-1"
                    }
                }
            }
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        assert_eq!(config.server_url(), Some("https://vouch.example.com"));
        assert_eq!(config.email(), Some("alice@example.com"));

        let ca = config
            .codeartifact()
            .expect("codeartifact config should exist");
        assert_eq!(ca.default.as_deref(), Some("prod"));
        assert_eq!(ca.profiles.len(), 2);

        let prod = ca.profiles.get("prod").expect("prod profile should exist");
        assert_eq!(prod.domain, "my-domain");
        assert_eq!(prod.domain_owner, "123456789012");
        assert_eq!(prod.region, "us-east-1");

        let staging = ca
            .profiles
            .get("staging")
            .expect("staging profile should exist");
        assert_eq!(staging.domain, "staging-domain");
        assert_eq!(staging.domain_owner, "987654321098");
        assert_eq!(staging.region, "eu-west-1");

        // Round-trip back to ConfigFile
        let file2 = ConfigFile::from(&config);
        let json2 = serde_json::to_string(&file2).unwrap();
        let file3: ConfigFile = serde_json::from_str(&json2).unwrap();
        let config2 = Config::from(file3);

        assert_eq!(config2.server_url(), config.server_url());
        assert_eq!(config2.email(), config.email());
        let ca2 = config2
            .codeartifact()
            .expect("round-tripped codeartifact config");
        assert_eq!(ca2.default, ca.default);
        assert_eq!(ca2.profiles.len(), ca.profiles.len());
    }

    #[test]
    fn test_config_without_codeartifact() {
        let json = r#"{
            "server_url": "https://vouch.example.com",
            "token": "test-token"
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        assert!(config.codeartifact().is_none());

        // Round-trip should not add a codeartifact field
        let file2 = ConfigFile::from(&config);
        let json2 = serde_json::to_string(&file2).unwrap();
        assert!(!json2.contains("codeartifact"));
    }

    #[test]
    fn test_empty_codeartifact_not_serialized() {
        let ca = CodeArtifactConfig::default();
        let json = serde_json::to_string(&ca).unwrap();
        // Empty profiles map should be omitted via skip_serializing_if
        assert!(!json.contains("profiles"));
    }

    #[test]
    fn test_save_codeartifact_profile_sets_default_for_first() {
        let mut config = Config::default();

        config
            .save_codeartifact_profile(
                "myteam",
                CodeArtifactProfile {
                    domain: "team-domain".into(),
                    domain_owner: "111111111111".into(),
                    region: "us-west-2".into(),
                },
            )
            .unwrap_or_default(); // save may fail in test env (no home dir)

        let ca = config
            .codeartifact()
            .expect("should have codeartifact config");
        assert_eq!(ca.default.as_deref(), Some("myteam"));
        assert_eq!(ca.profiles.len(), 1);
    }
}
