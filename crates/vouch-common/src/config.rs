// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Read-only configuration reader for `~/.vouch/config.json`.
//!
//! This module provides read-only access to the Vouch config file.
//! The agent uses this to recover session state on startup.
//! Only the CLI should write to this file.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

/// Read-only view of the Vouch CLI configuration.
///
/// Deserialize-only — the agent must never write to `config.json`.
#[derive(Debug, Default, Deserialize)]
pub struct VouchConfig {
    /// Vouch server URL.
    pub server_url: Option<String>,
    /// Current session token (JWT).
    pub token: Option<String>,
}

/// Get the path to the config file (`~/.vouch/config.json`).
pub fn config_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".vouch").join("config.json"))
}

/// Read the config file from disk.
///
/// Returns `Ok(None)` if the file does not exist.
/// Returns an error if the file exists but cannot be read or parsed.
///
/// On Unix, rejects files that are group/other-readable (mode & 0o077 != 0).
pub fn read_config() -> Result<Option<VouchConfig>> {
    let path = config_path()?;

    if !path.exists() {
        return Ok(None);
    }

    // Reject files with overly permissive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to stat config file {}", path.display()))?;
        let mode = metadata.mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "config file {} has insecure permissions {:o} (expected 0600)",
                path.display(),
                mode & 0o777,
            );
        }
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read config from {}", path.display()))?;

    let config: VouchConfig = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse config from {}", path.display()))?;

    Ok(Some(config))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_config_path() {
        let path = config_path();
        assert!(path.is_ok());
        let path = path.expect("config_path should succeed");
        assert!(path.ends_with(".vouch/config.json"));
    }

    #[test]
    fn test_deserialize_config() {
        let json = r#"{"server_url": "https://vouch.example.com", "token": "jwt-token"}"#;
        let config: VouchConfig = serde_json::from_str(json).expect("should parse");
        assert_eq!(
            config.server_url.as_deref(),
            Some("https://vouch.example.com")
        );
        assert_eq!(config.token.as_deref(), Some("jwt-token"));
    }

    #[test]
    fn test_deserialize_empty_config() {
        let json = "{}";
        let config: VouchConfig = serde_json::from_str(json).expect("should parse");
        assert!(config.server_url.is_none());
        assert!(config.token.is_none());
    }

    #[test]
    fn test_deserialize_partial_config() {
        let json = r#"{"server_url": "https://vouch.example.com"}"#;
        let config: VouchConfig = serde_json::from_str(json).expect("should parse");
        assert_eq!(
            config.server_url.as_deref(),
            Some("https://vouch.example.com")
        );
        assert!(config.token.is_none());
    }
}
