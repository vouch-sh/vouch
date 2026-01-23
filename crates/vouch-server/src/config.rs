//! Server configuration.

use anyhow::{Context, Result};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::db;

/// Configuration keys used in the database.
pub mod config_keys {
    pub const OIDC_ISSUER: &str = "oidc_issuer";
    pub const OIDC_CLIENT_ID: &str = "oidc_client_id";
    pub const OIDC_CLIENT_SECRET: &str = "oidc_client_secret";
    pub const ALLOWED_DOMAINS: &str = "allowed_domains";
    pub const ORG_NAME: &str = "org_name";
    pub const CLI_DOWNLOAD_MACOS: &str = "cli_download_macos";
    pub const CLI_DOWNLOAD_LINUX: &str = "cli_download_linux";
    pub const CLI_DOWNLOAD_WINDOWS: &str = "cli_download_windows";
}

/// Server configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to listen on (e.g., "0.0.0.0:3000").
    pub listen_addr: String,
    /// `SQLite` database URL (e.g., "sqlite:vouch.db").
    pub database_url: String,
    /// Relying Party ID (domain, e.g., "vouch.sh").
    pub rp_id: String,
    /// Relying Party name for display.
    pub rp_name: String,
    /// JWT signing secret (must be at least 32 characters).
    pub jwt_secret: String,
    /// Session duration in hours (default: 8).
    pub session_hours: u64,
    /// OIDC issuer URL (e.g., "<https://accounts.google.com>").
    pub oidc_issuer_url: Option<String>,
    /// OIDC client ID.
    pub oidc_client_id: Option<String>,
    /// OIDC client secret.
    pub oidc_client_secret: Option<String>,
    /// Base URL for device verification (defaults to `https://{rp_id}`).
    pub verification_base_url: String,
    /// Device code expiration in seconds (default: 600).
    pub device_code_expires_seconds: u64,
    /// Device code polling interval in seconds (default: 5).
    pub device_poll_interval_seconds: u64,
    /// Bootstrap token for initial admin setup.
    pub admin_bootstrap_token: Option<String>,
    /// Email addresses that are admins (from env var, comma-separated).
    pub admin_emails: Vec<String>,
    /// Allowed email domains for enrollment (comma-separated).
    pub allowed_domains: Option<Vec<String>>,
    /// Organization name for branding.
    pub org_name: Option<String>,
    /// CLI download URL for macOS.
    pub cli_download_macos: Option<String>,
    /// CLI download URL for Linux.
    pub cli_download_linux: Option<String>,
    /// CLI download URL for Windows.
    pub cli_download_windows: Option<String>,
}

impl ServerConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self> {
        let database_url = std::env::var("VOUCH_DATABASE_URL")
            .unwrap_or_else(|_| "sqlite:vouch.db?mode=rwc".to_string());

        let listen_addr =
            std::env::var("VOUCH_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

        let rp_id =
            std::env::var("VOUCH_RP_ID").context("VOUCH_RP_ID environment variable is required")?;

        let rp_name = std::env::var("VOUCH_RP_NAME").unwrap_or_else(|_| "Vouch".to_string());

        let jwt_secret = std::env::var("VOUCH_JWT_SECRET")
            .context("VOUCH_JWT_SECRET environment variable is required")?;

        if jwt_secret.len() < 32 {
            anyhow::bail!("VOUCH_JWT_SECRET must be at least 32 characters");
        }

        let session_hours = std::env::var("VOUCH_SESSION_HOURS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8);

        // OIDC configuration (optional - only needed for enrollment)
        let oidc_issuer_url = std::env::var("VOUCH_OIDC_ISSUER").ok();
        let oidc_client_id = std::env::var("VOUCH_OIDC_CLIENT_ID").ok();
        let oidc_client_secret = std::env::var("VOUCH_OIDC_CLIENT_SECRET").ok();

        // Default verification URL to https://{rp_id}
        let verification_base_url =
            std::env::var("VOUCH_VERIFICATION_URL").unwrap_or_else(|_| format!("https://{rp_id}"));

        let device_code_expires_seconds = std::env::var("VOUCH_DEVICE_CODE_EXPIRES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(600);

        let device_poll_interval_seconds = std::env::var("VOUCH_DEVICE_POLL_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        // Admin configuration
        let admin_bootstrap_token = std::env::var("VOUCH_ADMIN_BOOTSTRAP_TOKEN").ok();
        let admin_emails = std::env::var("VOUCH_ADMIN_EMAILS")
            .ok()
            .map(|s| s.split(',').map(|e| e.trim().to_lowercase()).collect())
            .unwrap_or_default();

        // Allowed domains (optional)
        let allowed_domains = std::env::var("VOUCH_ALLOWED_DOMAINS").ok().map(|s| {
            s.split(',')
                .map(|d| d.trim().to_lowercase())
                .filter(|d| !d.is_empty())
                .collect()
        });

        // Branding
        let org_name = std::env::var("VOUCH_ORG_NAME").ok();
        let cli_download_macos = std::env::var("VOUCH_CLI_DOWNLOAD_MACOS").ok();
        let cli_download_linux = std::env::var("VOUCH_CLI_DOWNLOAD_LINUX").ok();
        let cli_download_windows = std::env::var("VOUCH_CLI_DOWNLOAD_WINDOWS").ok();

        Ok(Self {
            listen_addr,
            database_url,
            rp_id,
            rp_name,
            jwt_secret,
            session_hours,
            oidc_issuer_url,
            oidc_client_id,
            oidc_client_secret,
            verification_base_url,
            device_code_expires_seconds,
            device_poll_interval_seconds,
            admin_bootstrap_token,
            admin_emails,
            allowed_domains,
            org_name,
            cli_download_macos,
            cli_download_linux,
            cli_download_windows,
        })
    }

    /// Load additional configuration from database (overrides env vars where set).
    pub async fn load_from_db(&mut self, pool: &SqlitePool) -> Result<()> {
        // OIDC settings (DB overrides env vars)
        if let Some(issuer) = db::get_config(pool, config_keys::OIDC_ISSUER).await? {
            self.oidc_issuer_url = Some(issuer);
        }
        if let Some(client_id) = db::get_config(pool, config_keys::OIDC_CLIENT_ID).await? {
            self.oidc_client_id = Some(client_id);
        }
        if let Some(client_secret) = db::get_config(pool, config_keys::OIDC_CLIENT_SECRET).await? {
            self.oidc_client_secret = Some(client_secret);
        }

        // Allowed domains (DB overrides env vars)
        if let Some(domains) = db::get_config(pool, config_keys::ALLOWED_DOMAINS).await? {
            self.allowed_domains = Some(
                domains
                    .split(',')
                    .map(|d| d.trim().to_lowercase())
                    .filter(|d| !d.is_empty())
                    .collect(),
            );
        }

        // Branding (DB overrides env vars)
        if let Some(org_name) = db::get_config(pool, config_keys::ORG_NAME).await? {
            self.org_name = Some(org_name);
        }
        if let Some(url) = db::get_config(pool, config_keys::CLI_DOWNLOAD_MACOS).await? {
            self.cli_download_macos = Some(url);
        }
        if let Some(url) = db::get_config(pool, config_keys::CLI_DOWNLOAD_LINUX).await? {
            self.cli_download_linux = Some(url);
        }
        if let Some(url) = db::get_config(pool, config_keys::CLI_DOWNLOAD_WINDOWS).await? {
            self.cli_download_windows = Some(url);
        }

        Ok(())
    }

    /// Check if OIDC is configured (all required fields present).
    #[must_use]
    pub fn oidc_configured(&self) -> bool {
        self.oidc_issuer_url.is_some()
            && self.oidc_client_id.is_some()
            && self.oidc_client_secret.is_some()
    }

    /// Check if admin bootstrap token is valid.
    #[must_use]
    pub fn verify_bootstrap_token(&self, token: &str) -> bool {
        self.admin_bootstrap_token
            .as_ref()
            .is_some_and(|t| t == token)
    }

    /// Check if an email is in the admin list (env var list only).
    #[must_use]
    pub fn is_env_admin(&self, email: &str) -> bool {
        self.admin_emails
            .iter()
            .any(|e| e.eq_ignore_ascii_case(email))
    }

    /// Get the organization display name.
    #[must_use]
    pub fn get_org_display_name(&self) -> &str {
        self.org_name.as_deref().unwrap_or(&self.rp_name)
    }
}

/// Dynamic configuration that can be reloaded at runtime.
#[allow(dead_code)]
pub struct DynamicConfig {
    inner: Arc<RwLock<ServerConfig>>,
}

#[allow(dead_code)]
impl DynamicConfig {
    /// Create a new dynamic config wrapper.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(config)),
        }
    }

    /// Get a read lock on the configuration.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, ServerConfig> {
        self.inner.read().await
    }

    /// Reload configuration from database.
    pub async fn reload(&self, pool: &SqlitePool) -> Result<()> {
        let mut config = self.inner.write().await;
        config.load_from_db(pool).await
    }

    /// Clone the inner Arc for sharing.
    pub fn clone_inner(&self) -> Arc<RwLock<ServerConfig>> {
        Arc::clone(&self.inner)
    }
}
