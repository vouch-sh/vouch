//! Server configuration

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Server host
    #[serde(default = "default_host")]
    pub host: String,

    /// Server port
    #[serde(default = "default_port")]
    pub port: u16,

    /// SQLite database URL
    #[serde(default = "default_database_url")]
    pub database_url: String,

    /// WebAuthn Relying Party ID (typically the domain)
    pub rp_id: String,

    /// WebAuthn Relying Party origin (full URL)
    pub rp_origin: url::Url,

    /// WebAuthn Relying Party name (display name)
    #[serde(default = "default_rp_name")]
    pub rp_name: String,

    /// JWT signing secret
    pub jwt_secret: String,

    /// Session TTL in seconds (default: 8 hours)
    #[serde(default = "default_session_ttl")]
    pub session_ttl_seconds: u64,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    3000
}

fn default_database_url() -> String {
    "sqlite:vouch.db?mode=rwc".to_string()
}

fn default_rp_name() -> String {
    "vouch".to_string()
}

fn default_session_ttl() -> u64 {
    8 * 60 * 60 // 8 hours
}

impl ServerConfig {
    pub fn load() -> Result<Self> {
        let config = config::Config::builder()
            // Start with defaults
            .set_default("host", default_host())?
            .set_default("port", default_port())?
            .set_default("database_url", default_database_url())?
            .set_default("rp_name", default_rp_name())?
            .set_default("session_ttl_seconds", default_session_ttl())?
            // Load from config file if present
            .add_source(config::File::with_name("vouch").required(false))
            // Override with environment variables (VOUCH_*)
            .add_source(config::Environment::with_prefix("VOUCH").separator("__"))
            .build()
            .context("failed to load configuration")?;

        config
            .try_deserialize()
            .context("failed to parse configuration")
    }
}
