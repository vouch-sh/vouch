//! Server configuration.

use anyhow::{Context, Result};
use clap::Parser;
use secrecy::{ExposeSecret, SecretString};
use sqlx::SqlitePool;
use std::sync::Arc;
use subtle::ConstantTimeEq;
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

// ============================================================================
// Custom Value Parsers
// ============================================================================

/// Parse a comma-separated list of strings, trimming and normalizing to lowercase.
fn parse_comma_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|item| item.trim().to_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

/// Parse a comma-separated list of strings (preserving case).
fn parse_comma_list_preserve_case(s: &str) -> Vec<String> {
    s.split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

/// Parse a boolean value that defaults to true (false only if "false" or "0").
fn parse_bool_default_true(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower != "false" && s != "0"
}

/// Parse a boolean value that defaults to false (true only if "true" or "1").
fn parse_bool_default_false(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower == "true" || s == "1"
}

// ============================================================================
// Command Line Arguments
// ============================================================================

/// Vouch identity server.
#[derive(Parser)]
#[command(name = "vouch-server", about = "Vouch identity server")]
pub struct Args {
    /// Address to listen on (e.g., "0.0.0.0:3000").
    #[arg(long, env = "VOUCH_LISTEN_ADDR", default_value = "0.0.0.0:3000")]
    pub listen_addr: String,

    /// SQLite database URL (e.g., "sqlite:vouch.db").
    #[arg(
        long,
        env = "VOUCH_DATABASE_URL",
        default_value = "sqlite:vouch.db?mode=rwc"
    )]
    pub database_url: String,

    /// Relying Party ID (domain, e.g., "vouch.sh").
    #[arg(long, env = "VOUCH_RP_ID")]
    pub rp_id: String,

    /// Relying Party name for display.
    #[arg(long, env = "VOUCH_RP_NAME", default_value = "Vouch")]
    pub rp_name: String,

    /// JWT signing secret (must be at least 32 characters).
    #[arg(long, env = "VOUCH_JWT_SECRET")]
    pub jwt_secret: String,

    /// Session duration in hours.
    #[arg(long, env = "VOUCH_SESSION_HOURS", default_value = "8")]
    pub session_hours: u64,

    /// OIDC issuer URL (e.g., "https://accounts.google.com").
    #[arg(long, env = "VOUCH_OIDC_ISSUER")]
    pub oidc_issuer: Option<String>,

    /// OIDC client ID.
    #[arg(long, env = "VOUCH_OIDC_CLIENT_ID")]
    pub oidc_client_id: Option<String>,

    /// OIDC client secret.
    #[arg(long, env = "VOUCH_OIDC_CLIENT_SECRET")]
    pub oidc_client_secret: Option<String>,

    /// Base URL for device verification (defaults to https://{rp_id}).
    #[arg(long, env = "VOUCH_VERIFICATION_URL")]
    pub verification_url: Option<String>,

    /// Device code expiration in seconds.
    #[arg(long, env = "VOUCH_DEVICE_CODE_EXPIRES", default_value = "600")]
    pub device_code_expires: u64,

    /// Device code polling interval in seconds.
    #[arg(long, env = "VOUCH_DEVICE_POLL_INTERVAL", default_value = "5")]
    pub device_poll_interval: u64,

    /// Bootstrap token for initial admin setup.
    #[arg(long, env = "VOUCH_ADMIN_BOOTSTRAP_TOKEN")]
    pub admin_bootstrap_token: Option<String>,

    /// Email addresses that are admins (comma-separated).
    #[arg(long, env = "VOUCH_ADMIN_EMAILS")]
    pub admin_emails: Option<String>,

    /// Allowed email domains for enrollment (comma-separated).
    #[arg(long, env = "VOUCH_ALLOWED_DOMAINS")]
    pub allowed_domains: Option<String>,

    /// Organization name for branding.
    #[arg(long, env = "VOUCH_ORG_NAME")]
    pub org_name: Option<String>,

    /// CLI download URL for macOS.
    #[arg(long, env = "VOUCH_CLI_DOWNLOAD_MACOS")]
    pub cli_download_macos: Option<String>,

    /// CLI download URL for Linux.
    #[arg(long, env = "VOUCH_CLI_DOWNLOAD_LINUX")]
    pub cli_download_linux: Option<String>,

    /// CLI download URL for Windows.
    #[arg(long, env = "VOUCH_CLI_DOWNLOAD_WINDOWS")]
    pub cli_download_windows: Option<String>,

    /// Path to SSH CA private key file. Set to empty string to disable SSH CA.
    #[arg(long, env = "VOUCH_SSH_CA_KEY_PATH", default_value = "./ssh_ca_key")]
    pub ssh_ca_key_path: String,

    /// Enable RFC 9449 DPoP support.
    #[arg(long, env = "VOUCH_DPOP_ENABLED")]
    pub dpop_enabled: Option<String>,

    /// Require DPoP nonce in proofs.
    #[arg(long, env = "VOUCH_DPOP_NONCE_REQUIRED")]
    pub dpop_nonce_required: Option<String>,

    /// Maximum age of DPoP proofs in seconds.
    #[arg(long, env = "VOUCH_DPOP_MAX_AGE", default_value = "300")]
    pub dpop_max_age: i64,

    /// Cleanup task interval in minutes. Set to 0 to disable.
    #[arg(long, env = "VOUCH_CLEANUP_INTERVAL", default_value = "15")]
    pub cleanup_interval: u64,

    /// Retention period for auth events in days.
    #[arg(long, env = "VOUCH_AUTH_EVENTS_RETENTION_DAYS", default_value = "90")]
    pub auth_events_retention_days: i64,

    /// Retention period for OAuth usage events in days.
    #[arg(long, env = "VOUCH_OAUTH_EVENTS_RETENTION_DAYS", default_value = "30")]
    pub oauth_events_retention_days: i64,

    /// CORS allowed origins (comma-separated). Empty means same-origin only.
    /// Use "*" to allow all origins (not recommended for production).
    #[arg(long, env = "VOUCH_CORS_ORIGINS")]
    pub cors_origins: Option<String>,
}

// ============================================================================
// Server Configuration
// ============================================================================

/// Server configuration loaded from command-line arguments and environment variables.
#[derive(Clone)]
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
    pub jwt_secret: SecretString,
    /// Session duration in hours (default: 8).
    pub session_hours: u64,
    /// OIDC issuer URL (e.g., "<https://accounts.google.com>").
    pub oidc_issuer_url: Option<String>,
    /// OIDC client ID.
    pub oidc_client_id: Option<String>,
    /// OIDC client secret.
    pub oidc_client_secret: Option<SecretString>,
    /// Base URL for device verification (defaults to `https://{rp_id}`).
    pub verification_base_url: String,
    /// Device code expiration in seconds (default: 600).
    pub device_code_expires_seconds: u64,
    /// Device code polling interval in seconds (default: 5).
    pub device_poll_interval_seconds: u64,
    /// Bootstrap token for initial admin setup.
    pub admin_bootstrap_token: Option<SecretString>,
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
    /// Path to SSH CA private key file (default: `./ssh_ca_key`).
    /// Set to empty string to disable SSH CA.
    pub ssh_ca_key_path: Option<String>,
    /// Enable RFC 9449 DPoP support (default: true).
    pub dpop_enabled: bool,
    /// Require DPoP nonce in proofs (default: false).
    pub dpop_nonce_required: bool,
    /// Maximum age of DPoP proofs in seconds (default: 300).
    pub dpop_max_age_seconds: i64,
    /// Cleanup task interval in minutes (default: 15).
    /// Set to 0 to disable background cleanup.
    pub cleanup_interval_minutes: u64,
    /// Retention period for auth events in days (default: 90).
    pub auth_events_retention_days: i64,
    /// Retention period for OAuth usage events in days (default: 30).
    pub oauth_events_retention_days: i64,
    /// CORS allowed origins (comma-separated). Empty means same-origin only.
    /// Use "*" to allow all origins (not recommended for production).
    pub cors_origins: Option<Vec<String>>,
}

impl ServerConfig {
    /// Create configuration from parsed command-line arguments.
    pub fn from_args(args: Args) -> Result<Self> {
        // Validate JWT secret length
        if args.jwt_secret.len() < 32 {
            anyhow::bail!("JWT secret must be at least 32 characters");
        }

        // Compute default verification URL
        let verification_base_url = args
            .verification_url
            .unwrap_or_else(|| format!("https://{}", args.rp_id));

        // Parse admin emails
        let admin_emails = args
            .admin_emails
            .map(|s| parse_comma_list(&s))
            .unwrap_or_default();

        // Parse allowed domains
        let allowed_domains = args.allowed_domains.map(|s| parse_comma_list(&s));

        // Parse DPoP booleans
        let dpop_enabled = args
            .dpop_enabled
            .map(|s| parse_bool_default_true(&s))
            .unwrap_or(true);

        let dpop_nonce_required = args
            .dpop_nonce_required
            .map(|s| parse_bool_default_false(&s))
            .unwrap_or(false);

        // Parse CORS origins
        let cors_origins = args
            .cors_origins
            .map(|s| parse_comma_list_preserve_case(&s));

        // Handle SSH CA key path (empty string = disabled)
        let ssh_ca_key_path = if args.ssh_ca_key_path.is_empty() {
            None
        } else {
            Some(args.ssh_ca_key_path)
        };

        Ok(Self {
            listen_addr: args.listen_addr,
            database_url: args.database_url,
            rp_id: args.rp_id,
            rp_name: args.rp_name,
            jwt_secret: SecretString::from(args.jwt_secret),
            session_hours: args.session_hours,
            oidc_issuer_url: args.oidc_issuer,
            oidc_client_id: args.oidc_client_id,
            oidc_client_secret: args.oidc_client_secret.map(SecretString::from),
            verification_base_url,
            device_code_expires_seconds: args.device_code_expires,
            device_poll_interval_seconds: args.device_poll_interval,
            admin_bootstrap_token: args.admin_bootstrap_token.map(SecretString::from),
            admin_emails,
            allowed_domains,
            org_name: args.org_name,
            cli_download_macos: args.cli_download_macos,
            cli_download_linux: args.cli_download_linux,
            cli_download_windows: args.cli_download_windows,
            ssh_ca_key_path,
            dpop_enabled,
            dpop_nonce_required,
            dpop_max_age_seconds: args.dpop_max_age,
            cleanup_interval_minutes: args.cleanup_interval,
            auth_events_retention_days: args.auth_events_retention_days,
            oauth_events_retention_days: args.oauth_events_retention_days,
            cors_origins,
        })
    }

    /// Load configuration from environment variables (legacy method).
    /// Prefer using `Args::parse()` and `from_args()` instead.
    pub fn from_env() -> Result<Self> {
        let database_url = std::env::var("VOUCH_DATABASE_URL")
            .unwrap_or_else(|_| "sqlite:vouch.db?mode=rwc".to_string());

        let listen_addr =
            std::env::var("VOUCH_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

        let rp_id =
            std::env::var("VOUCH_RP_ID").context("VOUCH_RP_ID environment variable is required")?;

        let rp_name = std::env::var("VOUCH_RP_NAME").unwrap_or_else(|_| "Vouch".to_string());

        let jwt_secret_raw = std::env::var("VOUCH_JWT_SECRET")
            .context("VOUCH_JWT_SECRET environment variable is required")?;

        if jwt_secret_raw.len() < 32 {
            anyhow::bail!("VOUCH_JWT_SECRET must be at least 32 characters");
        }
        let jwt_secret = SecretString::from(jwt_secret_raw);

        let session_hours = std::env::var("VOUCH_SESSION_HOURS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8);

        // OIDC configuration (optional - only needed for enrollment)
        let oidc_issuer_url = std::env::var("VOUCH_OIDC_ISSUER").ok();
        let oidc_client_id = std::env::var("VOUCH_OIDC_CLIENT_ID").ok();
        let oidc_client_secret = std::env::var("VOUCH_OIDC_CLIENT_SECRET")
            .ok()
            .map(SecretString::from);

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
        let admin_bootstrap_token = std::env::var("VOUCH_ADMIN_BOOTSTRAP_TOKEN")
            .ok()
            .map(SecretString::from);
        let admin_emails = std::env::var("VOUCH_ADMIN_EMAILS")
            .ok()
            .map(|s| parse_comma_list(&s))
            .unwrap_or_default();

        // Allowed domains (optional)
        let allowed_domains = std::env::var("VOUCH_ALLOWED_DOMAINS")
            .ok()
            .map(|s| parse_comma_list(&s));

        // Branding
        let org_name = std::env::var("VOUCH_ORG_NAME").ok();
        let cli_download_macos = std::env::var("VOUCH_CLI_DOWNLOAD_MACOS").ok();
        let cli_download_linux = std::env::var("VOUCH_CLI_DOWNLOAD_LINUX").ok();
        let cli_download_windows = std::env::var("VOUCH_CLI_DOWNLOAD_WINDOWS").ok();

        // SSH CA configuration (default: enabled with ./ssh_ca_key)
        let ssh_ca_key_path = std::env::var("VOUCH_SSH_CA_KEY_PATH").ok().or_else(|| {
            // Default to ssh_ca_key in current directory
            Some("./ssh_ca_key".to_string())
        });

        // RFC 9449 DPoP configuration
        let dpop_enabled = std::env::var("VOUCH_DPOP_ENABLED")
            .ok()
            .map(|s| parse_bool_default_true(&s))
            .unwrap_or(true);

        let dpop_nonce_required = std::env::var("VOUCH_DPOP_NONCE_REQUIRED")
            .ok()
            .map(|s| parse_bool_default_false(&s))
            .unwrap_or(false);

        let dpop_max_age_seconds = std::env::var("VOUCH_DPOP_MAX_AGE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300);

        // Cleanup task configuration
        let cleanup_interval_minutes = std::env::var("VOUCH_CLEANUP_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);

        let auth_events_retention_days = std::env::var("VOUCH_AUTH_EVENTS_RETENTION_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(90);

        let oauth_events_retention_days = std::env::var("VOUCH_OAUTH_EVENTS_RETENTION_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        // CORS configuration
        let cors_origins = std::env::var("VOUCH_CORS_ORIGINS")
            .ok()
            .map(|s| parse_comma_list_preserve_case(&s));

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
            ssh_ca_key_path,
            dpop_enabled,
            dpop_nonce_required,
            dpop_max_age_seconds,
            cleanup_interval_minutes,
            auth_events_retention_days,
            oauth_events_retention_days,
            cors_origins,
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
            self.oidc_client_secret = Some(SecretString::from(client_secret));
        }

        // Allowed domains (DB overrides env vars)
        if let Some(domains) = db::get_config(pool, config_keys::ALLOWED_DOMAINS).await? {
            self.allowed_domains = Some(parse_comma_list(&domains));
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

    /// Check if admin bootstrap token is valid using constant-time comparison.
    #[must_use]
    pub fn verify_bootstrap_token(&self, token: &str) -> bool {
        self.admin_bootstrap_token.as_ref().is_some_and(|t| {
            let expected = t.expose_secret().as_bytes();
            let provided = token.as_bytes();
            // Use constant-time comparison to prevent timing attacks
            expected.len() == provided.len() && bool::from(expected.ct_eq(provided))
        })
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

    /// Get the JWT secret as bytes for encoding/decoding.
    /// This method exposes the secret - use with care.
    #[must_use]
    pub fn jwt_secret_bytes(&self) -> &[u8] {
        self.jwt_secret.expose_secret().as_bytes()
    }

    /// Get the OIDC client secret (exposed) if configured.
    #[must_use]
    pub fn oidc_client_secret_exposed(&self) -> Option<&str> {
        self.oidc_client_secret.as_ref().map(|s| s.expose_secret())
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
