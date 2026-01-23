//! Configuration management for vouch CLI

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// CLI configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Server URL override
    pub server_url: Option<String>,
    /// Cached session token
    pub session_token: Option<String>,
    /// User email (from last login)
    pub user_email: Option<String>,
}

impl Config {
    /// Load config from disk
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config from {:?}", path))?;
        
        let config: Config = serde_json::from_str(&contents)
            .with_context(|| "failed to parse config file")?;
        
        Ok(config)
    }

    /// Save config to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create config directory {:?}", parent))?;
        }

        let contents = serde_json::to_string_pretty(self)?;
        fs::write(&path, contents)
            .with_context(|| format!("failed to write config to {:?}", path))?;

        // Restrict permissions on config file (contains session token)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&path, perms)?;
        }

        Ok(())
    }

    /// Get config file path
    fn config_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("sh", "vouch", "vouch")
            .context("failed to determine config directory")?;
        
        Ok(dirs.config_dir().join("config.json"))
    }

    /// Get path for cached credentials
    pub fn credentials_cache_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("sh", "vouch", "vouch")
            .context("failed to determine cache directory")?;
        
        Ok(dirs.cache_dir().join("credentials"))
    }

    /// Get socket path for agent IPC
    pub fn agent_socket_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("sh", "vouch", "vouch")
            .context("failed to determine runtime directory")?;
        
        // Prefer XDG_RUNTIME_DIR on Linux, fall back to cache dir
        let runtime_dir = dirs
            .runtime_dir()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| dirs.cache_dir().to_path_buf());
        
        Ok(runtime_dir.join("vouch.sock"))
    }

    /// Clear session (logout)
    pub fn clear_session(&mut self) -> Result<()> {
        self.session_token = None;
        self.user_email = None;
        self.save()
    }

    /// Update session
    pub fn set_session(&mut self, token: String, email: String) -> Result<()> {
        self.session_token = Some(token);
        self.user_email = Some(email);
        self.save()
    }
}
