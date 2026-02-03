// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Configuration and token storage for vouch CLI.

use anyhow::{Context, Result};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// CLI configuration stored in ~/.vouch/config.json
///
/// The config file is protected with 0600 permissions on Unix systems.
/// The token field stores the raw string for serialization, but the public
/// API wraps it in SecretString for secure memory handling:
/// - Automatic zeroization when dropped
/// - Protection against accidental logging/debug output
/// - Explicit exposure required via `.expose_secret()`
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// Vouch server URL.
    server_url: Option<String>,
    /// Current session token (JWT).
    /// Note: Stored as String for serde, but exposed as SecretString via API.
    token: Option<String>,
}

impl Config {
    /// Load configuration from disk, or return defaults if not found.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read config from {}", path.display()))?;
            serde_json::from_str(&content)
                .with_context(|| format!("failed to parse config from {}", path.display()))
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

        let content = serde_json::to_string_pretty(self).context("failed to serialize config")?;

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
    /// Returns the token wrapped in SecretString for secure memory handling.
    /// Callers must explicitly call `.expose_secret()` to access the underlying value.
    #[must_use]
    pub fn token(&self) -> Option<SecretString> {
        self.token.as_ref().map(|t| SecretString::from(t.clone()))
    }

    /// Save the server URL.
    pub fn save_server_url(&mut self, url: &str) -> Result<()> {
        self.server_url = Some(url.to_string());
        self.save()
    }

    /// Save a new session token.
    pub fn save_token(&mut self, token: &str) -> Result<()> {
        self.token = Some(token.to_string());
        self.save()
    }

    /// Clear the session token (logout).
    pub fn clear_token(&mut self) -> Result<()> {
        self.token = None;
        self.save()
    }

    /// Get the path to the config file.
    fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("could not determine home directory")?;
        Ok(home.join(".vouch").join("config.json"))
    }
}
