// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server configuration.

use anyhow::{Context, Result};
use clap::Parser;
use ipnet::IpNet;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;

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

/// Parse a log format string.
fn parse_log_format(s: &str) -> Result<LogFormat> {
    match s.trim().to_lowercase().as_str() {
        "text" | "" => Ok(LogFormat::Text),
        "json" => Ok(LogFormat::Json),
        other => anyhow::bail!(
            "Invalid VOUCH_LOG_FORMAT '{}': expected 'text' or 'json'",
            other
        ),
    }
}

/// Parse a comma-separated list of CIDR networks.
fn parse_trusted_proxies(s: &str) -> Result<Vec<IpNet>> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    s.split(',')
        .map(|cidr| {
            let trimmed = cidr.trim();
            trimmed.parse::<IpNet>().map_err(|e| {
                anyhow::anyhow!("Invalid CIDR in VOUCH_TRUSTED_PROXIES '{}': {}", trimmed, e)
            })
        })
        .collect()
}

/// Parse a comma-separated list of strings (preserving case).
fn parse_comma_list_preserve_case(s: &str) -> Vec<String> {
    s.split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

/// Validate a per-IdP slug: `[a-z0-9_-]+`, 1-32 chars.
fn validate_idp_slug(slug: &str) -> Result<()> {
    if slug.is_empty() || slug.len() > 32 {
        anyhow::bail!("IdP slug '{slug}' invalid: must be 1-32 characters of [a-z0-9_-]");
    }
    if !slug
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        anyhow::bail!("IdP slug '{slug}' invalid: must match [a-z0-9_-]+ (got '{slug}')");
    }
    Ok(())
}

/// Parse a comma-separated allowlist of GUIDs (lowercased, validated).
fn parse_tenant_allowlist(raw: &str) -> Result<Vec<String>> {
    let tenants: Vec<String> = raw
        .split(',')
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    for t in &tenants {
        if !crate::services::idp::oidc::is_guid(t) {
            anyhow::bail!("tenant '{t}' is not a valid GUID");
        }
    }
    Ok(tenants)
}

/// Build the slug-prefixed env var name (e.g. `VOUCH_IDP_FOO_ISSUER`).
fn idp_env(slug: &str, suffix: &str) -> String {
    format!("VOUCH_IDP_{}_{}", slug.to_ascii_uppercase(), suffix)
}

/// Parse one `VOUCH_IDP_<SLUG>_*` group from the environment.
fn parse_idp_slug_entry(slug: &str) -> Result<IdpEntryConfig> {
    use std::env;

    let issuer = env::var(idp_env(slug, "ISSUER")).ok();
    let metadata_url = env::var(idp_env(slug, "METADATA_URL")).ok();

    let kind = match (issuer.is_some(), metadata_url.is_some()) {
        (true, true) => anyhow::bail!(
            "IdP '{slug}' has both VOUCH_IDP_{}_ISSUER and \
             VOUCH_IDP_{}_METADATA_URL set; pick one",
            slug.to_ascii_uppercase(),
            slug.to_ascii_uppercase(),
        ),
        (true, false) => IdpKind::Oidc,
        (false, true) => IdpKind::Saml,
        (false, false) => anyhow::bail!(
            "IdP '{slug}' has neither VOUCH_IDP_{}_ISSUER (OIDC) nor \
             VOUCH_IDP_{}_METADATA_URL (SAML) set",
            slug.to_ascii_uppercase(),
            slug.to_ascii_uppercase(),
        ),
    };

    let allowed_domains = env::var(idp_env(slug, "ALLOWED_DOMAINS"))
        .ok()
        .map(|s| parse_comma_list(&s))
        .filter(|v| !v.is_empty());
    let allowed_tenants = match env::var(idp_env(slug, "ALLOWED_TENANTS")) {
        Ok(raw) => {
            let parsed = parse_tenant_allowlist(&raw).with_context(|| {
                format!("VOUCH_IDP_{}_ALLOWED_TENANTS", slug.to_ascii_uppercase())
            })?;
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        }
        Err(_) => None,
    };

    let (
        oidc_client_id,
        oidc_client_secret,
        saml_sp_entity_id,
        saml_email_attribute,
        saml_domain_attribute,
    ) = match kind {
        IdpKind::Oidc => {
            let client_id = env::var(idp_env(slug, "CLIENT_ID")).ok();
            let client_secret = env::var(idp_env(slug, "CLIENT_SECRET")).ok();
            if client_id.is_none() || client_secret.is_none() {
                anyhow::bail!(
                    "IdP '{slug}' OIDC: VOUCH_IDP_{}_CLIENT_ID and \
                     VOUCH_IDP_{}_CLIENT_SECRET are both required",
                    slug.to_ascii_uppercase(),
                    slug.to_ascii_uppercase(),
                );
            }
            (
                client_id,
                client_secret.map(SecretString::from),
                None,
                None,
                None,
            )
        }
        IdpKind::Saml => (
            None,
            None,
            env::var(idp_env(slug, "SP_ENTITY_ID")).ok(),
            env::var(idp_env(slug, "EMAIL_ATTRIBUTE")).ok(),
            env::var(idp_env(slug, "DOMAIN_ATTRIBUTE")).ok(),
        ),
    };

    Ok(IdpEntryConfig {
        slug: slug.to_string(),
        kind,
        allowed_domains,
        allowed_tenants,
        oidc_issuer: issuer,
        oidc_client_id,
        oidc_client_secret,
        saml_metadata_url: metadata_url,
        saml_sp_entity_id,
        saml_email_attribute,
        saml_domain_attribute,
    })
}

/// Build the complete `Vec<IdpEntryConfig>` from the merged legacy
/// `VOUCH_OIDC_*` / `VOUCH_SAML_*` shorthand and the slug-prefixed
/// `VOUCH_IDP_<SLUG>_*` family.
///
/// The legacy entry (when present) is emitted first under slug `"default"`;
/// subsequent slug-form entries follow in the order they appear in
/// `idps_var` (typically `VOUCH_IDPS`).
fn build_idps(
    idps_var: Option<&str>,
    partial_config: &ServerConfig,
) -> Result<Vec<IdpEntryConfig>> {
    let mut entries: Vec<IdpEntryConfig> = Vec::new();

    if partial_config.oidc_configured() {
        entries.push(IdpEntryConfig {
            slug: "default".to_string(),
            kind: IdpKind::Oidc,
            allowed_domains: None,
            allowed_tenants: None,
            oidc_issuer: partial_config.oidc_issuer_url.clone(),
            oidc_client_id: partial_config.oidc_client_id.clone(),
            oidc_client_secret: partial_config.oidc_client_secret.clone(),
            saml_metadata_url: None,
            saml_sp_entity_id: None,
            saml_email_attribute: None,
            saml_domain_attribute: None,
        });
    } else if partial_config.saml_configured() {
        entries.push(IdpEntryConfig {
            slug: "default".to_string(),
            kind: IdpKind::Saml,
            allowed_domains: None,
            allowed_tenants: None,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            saml_metadata_url: partial_config.saml_idp_metadata_url.clone(),
            saml_sp_entity_id: partial_config.saml_sp_entity_id.clone(),
            saml_email_attribute: partial_config.saml_email_attribute.clone(),
            saml_domain_attribute: partial_config.saml_domain_attribute.clone(),
        });
    }

    if let Some(raw_slugs) = idps_var.filter(|s| !s.trim().is_empty()) {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for entry in &entries {
            seen.insert(entry.slug.clone());
        }
        for slug in raw_slugs
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let normalized = slug.to_ascii_lowercase();
            validate_idp_slug(&normalized).with_context(|| format!("VOUCH_IDPS slug '{slug}'"))?;
            if normalized == "default" {
                anyhow::bail!(
                    "VOUCH_IDPS may not contain the reserved slug 'default' \
                     (legacy VOUCH_OIDC_* / VOUCH_SAML_* occupies it)"
                );
            }
            if !seen.insert(normalized.clone()) {
                anyhow::bail!("VOUCH_IDPS lists slug '{normalized}' more than once");
            }
            entries.push(parse_idp_slug_entry(&normalized)?);
        }
    }

    Ok(entries)
}

// ============================================================================
// Command Line Arguments
// ============================================================================

/// Vouch identity server.
#[derive(Parser)]
#[command(name = "vouch-server", about = "Vouch identity server")]
pub struct Args {
    /// Address to listen on (e.g., "[::]:3000").
    #[arg(long, env = "VOUCH_LISTEN_ADDR", default_value = "[::]:3000")]
    pub listen_addr: String,

    /// Database URL (sqlite, postgres, or DSQL).
    #[arg(
        long,
        env = "VOUCH_DATABASE_URL",
        default_value = "sqlite:vouch.db?mode=rwc"
    )]
    pub database_url: String,

    /// Relying Party ID (domain, e.g., "vouch.sh").
    #[arg(long, env = "VOUCH_RP_ID", default_value = "localhost")]
    pub rp_id: String,

    /// Relying Party name for display.
    #[arg(long, env = "VOUCH_RP_NAME", default_value = "Vouch")]
    pub rp_name: String,

    /// JWT signing secret (must be at least 32 characters).
    #[arg(long, env = "VOUCH_JWT_SECRET", default_value = "")]
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

    /// SAML IdP metadata URL.
    #[arg(long, env = "VOUCH_SAML_IDP_METADATA_URL")]
    pub saml_idp_metadata_url: Option<String>,

    /// SAML SP entity ID (defaults to base_url if not set).
    #[arg(long, env = "VOUCH_SAML_SP_ENTITY_ID")]
    pub saml_sp_entity_id: Option<String>,

    /// SAML attribute name for email extraction.
    #[arg(long, env = "VOUCH_SAML_EMAIL_ATTRIBUTE")]
    pub saml_email_attribute: Option<String>,

    /// SAML attribute name for domain extraction.
    #[arg(long, env = "VOUCH_SAML_DOMAIN_ATTRIBUTE")]
    pub saml_domain_attribute: Option<String>,

    /// Base URL for this server (defaults to https://{rp_id}).
    #[arg(long, env = "VOUCH_BASE_URL")]
    pub base_url: Option<String>,

    /// Device code expiration in seconds.
    #[arg(long, env = "VOUCH_DEVICE_CODE_EXPIRES", default_value = "600")]
    pub device_code_expires: u64,

    /// Device code polling interval in seconds.
    #[arg(long, env = "VOUCH_DEVICE_POLL_INTERVAL", default_value = "5")]
    pub device_poll_interval: u64,

    /// Allowed email domains for enrollment (comma-separated).
    #[arg(long, env = "VOUCH_ALLOWED_DOMAINS")]
    pub allowed_domains: Option<String>,

    /// Organization name for branding.
    #[arg(long, env = "VOUCH_ORG_NAME")]
    pub org_name: Option<String>,

    /// Human-readable name of this protected resource (RFC 9728 §2).
    /// Appears in the `resource_name` field of the Protected Resource
    /// Metadata document. Defaults to "Vouch" when unset.
    #[arg(long, env = "VOUCH_RESOURCE_NAME")]
    pub resource_name: Option<String>,

    /// URL of developer documentation for this protected resource
    /// (RFC 9728 §2 `resource_documentation`).
    /// Defaults to "https://vouch.sh/docs/" when unset.
    #[arg(long, env = "VOUCH_RESOURCE_DOCUMENTATION")]
    pub resource_documentation: Option<String>,

    /// URL of the resource's data-use policy
    /// (RFC 9728 §2 `resource_policy_uri`).
    /// Defaults to "https://vouch.sh/privacy/" when unset.
    #[arg(long, env = "VOUCH_RESOURCE_POLICY_URI")]
    pub resource_policy_uri: Option<String>,

    /// URL of the resource's terms of service
    /// (RFC 9728 §2 `resource_tos_uri`).
    /// Defaults to "https://vouch.sh/terms/" when unset.
    #[arg(long, env = "VOUCH_RESOURCE_TOS_URI")]
    pub resource_tos_uri: Option<String>,

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

    /// SSH CA private key content (PEM format, Ed25519).
    /// If set, takes precedence over VOUCH_SSH_CA_KEY_PATH.
    #[arg(long, env = "VOUCH_SSH_CA_KEY")]
    pub ssh_ca_key: Option<String>,

    /// AWS KMS key ID for SSH CA signing (multi-region mrk- prefix).
    /// When set, KMS signing is used instead of local SSH CA key.
    #[arg(long, env = "VOUCH_SSH_CA_KMS_KEY_ID")]
    pub ssh_ca_kms_key_id: Option<String>,

    /// OIDC signing key content (PEM format, P-256 EC).
    /// Used for signing OIDC ID tokens with ES256 algorithm.
    /// If not set, an ephemeral key will be generated.
    #[arg(long, env = "VOUCH_OIDC_SIGNING_KEY")]
    pub oidc_signing_key: Option<String>,

    /// AWS KMS key ID for OIDC signing (multi-region mrk- prefix).
    /// When set, KMS signing is used instead of local OIDC signing key.
    #[arg(long, env = "VOUCH_OIDC_SIGNING_KMS_KEY_ID")]
    pub oidc_signing_kms_key_id: Option<String>,

    /// OIDC RSA signing key (PEM-encoded RSA-3072 private key, base64).
    /// When set, enables RS256 ID token signing.
    #[arg(long, env = "VOUCH_OIDC_RSA_SIGNING_KEY")]
    pub oidc_rsa_signing_key: Option<String>,

    /// AWS KMS key ID for OIDC RSA signing (RSA_3072, SIGN_VERIFY).
    /// When set, KMS signing is used instead of local RSA signing key.
    #[arg(long, env = "VOUCH_OIDC_RSA_SIGNING_KMS_KEY_ID")]
    pub oidc_rsa_signing_kms_key_id: Option<String>,

    /// AWS KMS key ID for HMAC state token signing.
    /// When set, KMS HMAC-SHA256 is used instead of local VOUCH_JWT_SECRET.
    #[arg(long, env = "VOUCH_JWT_HMAC_KMS_KEY_ID")]
    pub jwt_hmac_kms_key_id: Option<String>,

    /// mTLS listener port (default: 8443).
    #[arg(long, env = "VOUCH_MTLS_PORT", default_value = "8443")]
    pub mtls_port: u16,

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
    #[arg(long, env = "VOUCH_OAUTH_EVENTS_RETENTION_DAYS", default_value = "90")]
    pub oauth_events_retention_days: i64,

    /// CORS allowed origins (comma-separated). Empty means same-origin only.
    /// Use "*" to allow all origins (not recommended for production).
    #[arg(long, env = "VOUCH_CORS_ORIGINS")]
    pub cors_origins: Option<String>,

    /// GitHub App ID (assigned when creating the app on github.com).
    #[arg(long, env = "VOUCH_GITHUB_APP_ID")]
    pub github_app_id: Option<u64>,

    /// GitHub App name (the slug from github.com/apps/{name}).
    #[arg(long, env = "VOUCH_GITHUB_APP_NAME")]
    pub github_app_name: Option<String>,

    /// GitHub App private key (PEM format, RSA). Can use literal \n for newlines.
    #[arg(long, env = "VOUCH_GITHUB_APP_KEY")]
    pub github_app_key: Option<String>,

    /// GitHub webhook secret for verifying webhook signatures.
    #[arg(long, env = "VOUCH_GITHUB_WEBHOOK_SECRET")]
    pub github_webhook_secret: Option<String>,

    /// GitHub App Client ID (for OAuth user authentication).
    /// This is found in the GitHub App settings, different from App ID.
    #[arg(long, env = "VOUCH_GITHUB_APP_CLIENT_ID")]
    pub github_app_client_id: Option<String>,

    /// GitHub App Client Secret (for OAuth user authentication).
    #[arg(long, env = "VOUCH_GITHUB_APP_CLIENT_SECRET")]
    pub github_app_client_secret: Option<String>,

    /// TLS certificate (base64-encoded PEM). If not set, HTTP is used.
    #[arg(long, env = "VOUCH_TLS_CERT")]
    pub tls_cert: Option<String>,

    /// TLS private key (base64-encoded PEM). Required if VOUCH_TLS_CERT is set.
    #[arg(long, env = "VOUCH_TLS_KEY")]
    pub tls_key: Option<String>,

    /// S3 bucket for configuration file. If set, config is loaded from S3.
    #[arg(long, env = "VOUCH_S3_CONFIG_BUCKET")]
    pub s3_config_bucket: Option<String>,

    /// S3 key for configuration file.
    #[arg(
        long,
        env = "VOUCH_S3_CONFIG_KEY",
        default_value = "config/vouch-server.json"
    )]
    pub s3_config_key: String,

    /// S3 region (optional, uses default credential chain region if not set).
    #[arg(long, env = "VOUCH_S3_CONFIG_REGION")]
    pub s3_config_region: Option<String>,

    /// S3 config polling interval in seconds.
    #[arg(long, env = "VOUCH_S3_CONFIG_POLL_INTERVAL", default_value = "60")]
    pub s3_config_poll_interval: u64,

    /// Maximum lifetime for JWT assertions in seconds (RFC 7523).
    #[arg(long, env = "VOUCH_JWT_ASSERTION_MAX_LIFETIME", default_value = "300")]
    pub jwt_assertion_max_lifetime: i64,

    /// AAGUID allowlist policy for WebAuthn registration.
    ///
    /// Controls which authenticator models are accepted:
    /// - Empty or unset: any hardware key accepted
    /// - `fips-only`: only FIPS-certified YubiKey models
    /// - `yubikey-5`: any YubiKey 5 series model
    /// - Comma-separated UUIDs: explicit allowlist
    #[arg(long, env = "VOUCH_ALLOWED_AAGUIDS", default_value = "")]
    pub allowed_aaguids: String,

    /// Require x5c attestation certificates during WebAuthn registration.
    ///
    /// When enabled, self-attestation (no certificate chain) is rejected.
    /// Only authenticators that provide a full attestation certificate chain
    /// (e.g., YubiKeys with packed attestation) will be accepted.
    #[arg(long, env = "VOUCH_REQUIRE_ATTESTATION_CERT", default_value = "false")]
    pub require_attestation_cert: bool,

    /// Log output format: "text" (default, human-readable) or "json" (structured).
    #[arg(long, env = "VOUCH_LOG_FORMAT", default_value = "text")]
    pub log_format: String,

    /// Trusted proxy CIDRs for X-Forwarded-For parsing (comma-separated).
    ///
    /// When set, the server parses X-Forwarded-For rightmost-first and stops
    /// at the first IP not in the trusted CIDRs. When unset, the TCP peer IP
    /// is used directly (safe for direct exposure without a reverse proxy).
    #[arg(long, env = "VOUCH_TRUSTED_PROXIES", default_value = "")]
    pub trusted_proxies: String,

    /// Bearer token for /metrics endpoint. If unset, /metrics is disabled.
    #[arg(long, env = "VOUCH_METRICS_BEARER_TOKEN")]
    pub metrics_bearer_token: Option<String>,

    /// Secret token for the certification test-mode login endpoint.
    /// When set, enables GET /certification/complete-login for automated OpenID conformance
    /// testing. MUST NOT be set in production deployments.
    #[arg(long, env = "VOUCH_CERTIFICATION_TEST_TOKEN")]
    pub certification_test_token: Option<String>,

    /// Path to a PEM file containing extra CA certificates to trust for
    /// outbound HTTPS requests (e.g., to conformance suite endpoints with
    /// self-signed certs). Multiple certs can be concatenated in one file.
    #[arg(long, env = "VOUCH_EXTRA_CA_CERTS")]
    pub extra_ca_certs: Option<String>,

    /// Maximum number of database connections in the pool.
    #[arg(long, env = "VOUCH_DB_MAX_CONNECTIONS", default_value = "25")]
    pub db_max_connections: u32,

    /// Minimum number of idle database connections in the pool.
    #[arg(long, env = "VOUCH_DB_MIN_CONNECTIONS", default_value = "2")]
    pub db_min_connections: u32,

    /// Idle connection timeout in seconds.
    #[arg(long, env = "VOUCH_DB_IDLE_TIMEOUT_SECS", default_value = "300")]
    pub db_idle_timeout_secs: u64,

    /// Connection acquire timeout in seconds.
    #[arg(long, env = "VOUCH_DB_ACQUIRE_TIMEOUT_SECS", default_value = "5")]
    pub db_acquire_timeout_secs: u64,

    /// Maximum number of entries in the session lookup cache.
    #[arg(
        long,
        env = "VOUCH_SESSION_CACHE_MAX_CAPACITY",
        default_value = "10000"
    )]
    pub session_cache_max_capacity: u64,

    /// Time-to-live for session cache entries in seconds.
    #[arg(long, env = "VOUCH_SESSION_CACHE_TTL_SECS", default_value = "30")]
    pub session_cache_ttl_secs: u64,

    /// Comma-separated list of additional upstream IdP slugs.
    ///
    /// Each slug enables a `VOUCH_IDP_<SLUG>_*` family of env vars
    /// (issuer, client_id, client_secret, or metadata_url, etc.).
    /// Adds to the legacy `VOUCH_OIDC_*` / `VOUCH_SAML_*` shorthand;
    /// both can coexist.
    #[arg(long, env = "VOUCH_IDPS")]
    pub idps: Option<String>,
}

// ============================================================================
// Server Configuration
// ============================================================================

/// Server configuration loaded from command-line arguments and environment variables.
#[derive(Clone)]
pub struct ServerConfig {
    /// Address to listen on (e.g., "[::]:3000").
    pub listen_addr: String,
    /// Database URL (sqlite, postgres, or DSQL).
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
    /// SAML IdP metadata URL.
    pub saml_idp_metadata_url: Option<String>,
    /// SAML SP entity ID (defaults to base_url if not set).
    pub saml_sp_entity_id: Option<String>,
    /// SAML attribute name for email extraction.
    pub saml_email_attribute: Option<String>,
    /// SAML attribute name for domain extraction.
    pub saml_domain_attribute: Option<String>,
    /// Base URL for this server (defaults to `https://{rp_id}`, or `http://localhost:port` for local dev).
    pub base_url: String,
    /// Device code expiration in seconds (default: 600).
    pub device_code_expires_seconds: u64,
    /// Device code polling interval in seconds (default: 5).
    pub device_poll_interval_seconds: u64,
    /// Allowed email domains for enrollment (comma-separated).
    pub allowed_domains: Option<Vec<String>>,
    /// Organization name for branding.
    pub org_name: Option<String>,
    /// Human-readable name of this protected resource
    /// (RFC 9728 §2 `resource_name`). Defaults to `"Vouch"`.
    pub resource_name: Option<String>,
    /// URL of developer documentation for this protected resource
    /// (RFC 9728 §2 `resource_documentation`).
    /// Defaults to `"https://vouch.sh/docs/"`.
    pub resource_documentation: Option<String>,
    /// URL of the resource's data-use policy
    /// (RFC 9728 §2 `resource_policy_uri`).
    /// Defaults to `"https://vouch.sh/privacy/"`.
    pub resource_policy_uri: Option<String>,
    /// URL of the resource's terms of service
    /// (RFC 9728 §2 `resource_tos_uri`).
    /// Defaults to `"https://vouch.sh/terms/"`.
    pub resource_tos_uri: Option<String>,
    /// CLI download URL for macOS.
    pub cli_download_macos: Option<String>,
    /// CLI download URL for Linux.
    pub cli_download_linux: Option<String>,
    /// CLI download URL for Windows.
    pub cli_download_windows: Option<String>,
    /// Path to SSH CA private key file (default: `./ssh_ca_key`).
    /// Set to empty string to disable SSH CA.
    pub ssh_ca_key_path: Option<String>,
    /// SSH CA private key content (PEM format, Ed25519).
    /// If set, takes precedence over `ssh_ca_key_path`.
    pub ssh_ca_key: Option<SecretString>,
    /// AWS KMS key ID for SSH CA signing (multi-region `mrk-` prefix).
    /// When set, KMS signing is used and `ssh_ca_key` is ignored.
    pub ssh_ca_kms_key_id: Option<String>,
    /// OIDC signing key content (PEM format, P-256 EC).
    /// Used for signing OIDC ID tokens with ES256 algorithm.
    pub oidc_signing_key: Option<SecretString>,
    /// AWS KMS key ID for OIDC signing (multi-region `mrk-` prefix).
    /// When set, KMS signing is used and `oidc_signing_key` is ignored.
    pub oidc_signing_kms_key_id: Option<String>,
    /// OIDC RSA signing key (PEM-encoded RSA-3072 private key, base64).
    /// When set, enables RS256 ID token signing.
    pub oidc_rsa_signing_key: Option<SecretString>,
    /// AWS KMS key ID for OIDC RSA signing (RSA_3072, SIGN_VERIFY).
    /// When set, KMS signing is used instead of local RSA signing key.
    pub oidc_rsa_signing_kms_key_id: Option<String>,
    /// AWS KMS key ID for HMAC state token signing.
    /// When set, KMS HMAC-SHA256 is used instead of local `jwt_secret`.
    pub jwt_hmac_kms_key_id: Option<String>,
    /// mTLS listener port (default: 8443).
    pub mtls_port: u16,
    /// Maximum age of DPoP proofs in seconds (default: 300).
    pub dpop_max_age_seconds: i64,
    /// Cleanup task interval in minutes (default: 15).
    /// Set to 0 to disable background cleanup.
    pub cleanup_interval_minutes: u64,
    /// Retention period for auth events in days (default: 90).
    pub auth_events_retention_days: i64,
    /// Retention period for OAuth usage events in days (default: 90).
    pub oauth_events_retention_days: i64,
    /// CORS allowed origins (comma-separated). Empty means same-origin only.
    /// Use "*" to allow all origins (not recommended for production).
    pub cors_origins: Option<Vec<String>>,
    /// GitHub App ID (assigned when creating the app on github.com).
    pub github_app_id: Option<u64>,
    /// GitHub App name (the slug from github.com/apps/{name}).
    pub github_app_name: Option<String>,
    /// GitHub App private key (PEM format, RSA).
    pub github_app_key: Option<SecretString>,
    /// GitHub webhook secret for verifying webhook signatures.
    pub github_webhook_secret: Option<SecretString>,
    /// GitHub App Client ID (for OAuth user authentication).
    /// This is found in the GitHub App settings, different from App ID.
    pub github_app_client_id: Option<String>,
    /// GitHub App Client Secret (for OAuth user authentication).
    pub github_app_client_secret: Option<SecretString>,
    /// TLS certificate (base64-encoded PEM format).
    pub tls_cert: Option<String>,
    /// TLS private key (base64-encoded PEM format).
    pub tls_key: Option<SecretString>,
    /// S3 config bucket (if configured).
    pub s3_config_bucket: Option<String>,
    /// S3 config key.
    pub s3_config_key: String,
    /// S3 config region.
    pub s3_config_region: Option<String>,
    /// S3 config poll interval in seconds.
    pub s3_config_poll_interval: u64,
    /// Maximum lifetime for JWT assertions in seconds (RFC 7523, default: 300).
    pub jwt_assertion_max_lifetime_seconds: i64,
    /// AAGUID allowlist policy for WebAuthn registration (default: `Any`).
    pub allowed_aaguids: vouch_common::AaguidPolicy,
    /// Require x5c attestation certificates during WebAuthn registration.
    pub require_attestation_cert: bool,
    /// Log output format: `text` or `json`.
    pub log_format: LogFormat,
    /// Trusted proxy CIDRs for X-Forwarded-For parsing.
    pub trusted_proxies: Vec<IpNet>,
    /// Bearer token for /metrics endpoint access control.
    /// If `None`, the /metrics endpoint is not exposed.
    pub metrics_bearer_token: Option<SecretString>,
    /// Secret token for the certification test-mode endpoint.
    /// When `Some`, `GET /certification/complete-login` is registered.
    /// MUST NOT be set in production deployments.
    pub certification_test_token: Option<SecretString>,
    /// Path to a PEM file containing extra CA certificates to trust for
    /// outbound HTTPS requests (e.g., peers with self-signed certs).
    pub extra_ca_certs: Option<String>,
    /// Database pool configuration.
    pub pool_config: crate::db::pool::PoolConfig,
    /// Maximum entries in the session lookup cache.
    pub session_cache_max_capacity: u64,
    /// TTL for session cache entries in seconds.
    pub session_cache_ttl_secs: u64,
    /// Configured upstream IdP entries (legacy shorthand + slug-form
    /// `VOUCH_IDPS` merged into a single ordered list).
    pub idps: Vec<IdpEntryConfig>,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable text (default).
    #[default]
    Text,
    /// Structured JSON for machine consumption.
    Json,
}

/// Upstream IdP protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdpKind {
    /// OpenID Connect (RFC 8414 discovery + OAuth 2.0 code flow).
    Oidc,
    /// SAML 2.0 (metadata + AuthnRequest/Response).
    Saml,
}

/// A single configured upstream IdP, before discovery.
///
/// Populated either from the legacy `VOUCH_OIDC_*` / `VOUCH_SAML_*` env vars
/// (slug = `"default"`) or from the new `VOUCH_IDPS=...` +
/// `VOUCH_IDP_<SLUG>_*` form. Validated by [`ServerConfig::validate`] and
/// fed into [`crate::infra::startup`] to produce one `ConfiguredIdp` per
/// entry.
#[derive(Debug, Clone)]
pub struct IdpEntryConfig {
    /// Internal slug (`[a-z0-9_-]+`, 1-32 chars). `default` is reserved for
    /// the legacy shorthand entry.
    pub slug: String,
    /// OIDC or SAML.
    pub kind: IdpKind,
    /// Optional per-IdP allowed-domains allowlist. Narrows the global
    /// `VOUCH_ALLOWED_DOMAINS` for this IdP only.
    pub allowed_domains: Option<Vec<String>>,
    /// Optional Entra tenant GUID allowlist (lowercased). Only consulted
    /// when discovery resolves the issuer to multi-tenant Entra.
    pub allowed_tenants: Option<Vec<String>>,
    /// OIDC-specific: issuer URL.
    pub oidc_issuer: Option<String>,
    /// OIDC-specific: registered client_id.
    pub oidc_client_id: Option<String>,
    /// OIDC-specific: registered client secret.
    pub oidc_client_secret: Option<SecretString>,
    /// SAML-specific: IdP metadata URL.
    pub saml_metadata_url: Option<String>,
    /// SAML-specific: SP entity ID override (defaults to base_url).
    pub saml_sp_entity_id: Option<String>,
    /// SAML-specific: attribute name carrying email.
    pub saml_email_attribute: Option<String>,
    /// SAML-specific: attribute name carrying domain.
    pub saml_domain_attribute: Option<String>,
}

impl ServerConfig {
    /// Create configuration from parsed command-line arguments.
    pub fn from_args(args: Args) -> Result<Self> {
        // Note: Validation of rp_id and jwt_secret is deferred to validate()
        // to allow these values to come from S3 config.

        // Compute base URL (handles both production https and local http)
        let base_url = if let Some(url) = args.base_url {
            url
        } else {
            let derived = if vouch_common::is_loopback_host(&args.rp_id) {
                // For local development (localhost/127.0.0.1), use http with port
                let port = args.listen_addr.rsplit(':').next().unwrap_or("3000");
                format!("http://{}:{}", args.rp_id, port)
            } else {
                // Production: use https without port (assumes standard 443)
                format!("https://{}", args.rp_id)
            };
            tracing::debug!("VOUCH_BASE_URL not set, derived from rp_id: {}", derived);
            derived
        };

        // Parse allowed domains
        let allowed_domains = args
            .allowed_domains
            .map(|s| parse_comma_list(&s))
            .filter(|v| !v.is_empty());

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

        // Parse AAGUID policy
        let allowed_aaguids = vouch_common::AaguidPolicy::parse(&args.allowed_aaguids)
            .map_err(|e| anyhow::anyhow!("Invalid VOUCH_ALLOWED_AAGUIDS: {}", e))?;

        // Parse log format
        let log_format = parse_log_format(&args.log_format)?;

        // Parse trusted proxies
        let trusted_proxies = parse_trusted_proxies(&args.trusted_proxies)?;

        // Capture VOUCH_IDPS before `args` is partially moved into `config`.
        let idps_var = args.idps.clone();

        let mut config = Self {
            listen_addr: args.listen_addr,
            database_url: args.database_url,
            rp_id: args.rp_id,
            rp_name: args.rp_name,
            jwt_secret: SecretString::from(args.jwt_secret),
            session_hours: args.session_hours,
            oidc_issuer_url: args.oidc_issuer.clone(),
            oidc_client_id: args.oidc_client_id.clone(),
            oidc_client_secret: args.oidc_client_secret.clone().map(SecretString::from),
            saml_idp_metadata_url: args.saml_idp_metadata_url,
            saml_sp_entity_id: args.saml_sp_entity_id,
            saml_email_attribute: args.saml_email_attribute,
            saml_domain_attribute: args.saml_domain_attribute,
            base_url,
            device_code_expires_seconds: args.device_code_expires,
            device_poll_interval_seconds: args.device_poll_interval,
            allowed_domains,
            org_name: args.org_name,
            resource_name: args.resource_name.or_else(|| Some("Vouch".to_string())),
            resource_documentation: args
                .resource_documentation
                .or_else(|| Some("https://vouch.sh/docs/".to_string())),
            resource_policy_uri: args
                .resource_policy_uri
                .or_else(|| Some("https://vouch.sh/privacy/".to_string())),
            resource_tos_uri: args
                .resource_tos_uri
                .or_else(|| Some("https://vouch.sh/terms/".to_string())),
            cli_download_macos: args.cli_download_macos,
            cli_download_linux: args.cli_download_linux,
            cli_download_windows: args.cli_download_windows,
            ssh_ca_key_path,
            ssh_ca_key: args.ssh_ca_key.map(SecretString::from),
            ssh_ca_kms_key_id: args.ssh_ca_kms_key_id,
            oidc_signing_key: args.oidc_signing_key.map(SecretString::from),
            oidc_signing_kms_key_id: args.oidc_signing_kms_key_id,
            oidc_rsa_signing_key: args.oidc_rsa_signing_key.map(SecretString::from),
            oidc_rsa_signing_kms_key_id: args.oidc_rsa_signing_kms_key_id,
            jwt_hmac_kms_key_id: args.jwt_hmac_kms_key_id,
            mtls_port: args.mtls_port,
            dpop_max_age_seconds: args.dpop_max_age,
            cleanup_interval_minutes: args.cleanup_interval,
            auth_events_retention_days: args.auth_events_retention_days,
            oauth_events_retention_days: args.oauth_events_retention_days,
            cors_origins,
            github_app_id: args.github_app_id,
            github_app_name: args.github_app_name,
            github_app_key: args.github_app_key.map(SecretString::from),
            github_webhook_secret: args.github_webhook_secret.map(SecretString::from),
            github_app_client_id: args.github_app_client_id,
            github_app_client_secret: args.github_app_client_secret.map(SecretString::from),
            tls_cert: args.tls_cert,
            tls_key: args.tls_key.map(SecretString::from),
            s3_config_bucket: args.s3_config_bucket,
            s3_config_key: args.s3_config_key,
            s3_config_region: args.s3_config_region,
            s3_config_poll_interval: args.s3_config_poll_interval,
            jwt_assertion_max_lifetime_seconds: args.jwt_assertion_max_lifetime,
            allowed_aaguids,
            require_attestation_cert: args.require_attestation_cert,
            log_format,
            trusted_proxies,
            metrics_bearer_token: args.metrics_bearer_token.map(SecretString::from),
            certification_test_token: args.certification_test_token.map(SecretString::from),
            extra_ca_certs: args.extra_ca_certs,
            pool_config: crate::db::pool::PoolConfig {
                max_connections: args.db_max_connections,
                min_connections: args.db_min_connections,
                idle_timeout_secs: args.db_idle_timeout_secs,
                acquire_timeout_secs: args.db_acquire_timeout_secs,
            },
            session_cache_max_capacity: args.session_cache_max_capacity,
            session_cache_ttl_secs: args.session_cache_ttl_secs,
            // Filled in below after `config` exists so build_idps can read
            // the legacy oidc_*/saml_* fields back out as a partial view.
            idps: Vec::new(),
        };

        config.idps = build_idps(idps_var.as_deref(), &config)?;
        Ok(config)
    }

    /// Check if OIDC is configured (all required fields present).
    #[must_use]
    pub fn oidc_configured(&self) -> bool {
        self.oidc_issuer_url.is_some()
            && self.oidc_client_id.is_some()
            && self.oidc_client_secret.is_some()
    }

    /// Check if SAML is configured.
    #[must_use]
    pub fn saml_configured(&self) -> bool {
        self.saml_idp_metadata_url.is_some()
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

    /// Check if GitHub App is configured (all required fields present).
    #[must_use]
    pub fn github_app_configured(&self) -> bool {
        self.github_app_id.is_some() && self.github_app_key.is_some()
    }

    /// Get the GitHub App private key (exposed) if configured.
    #[must_use]
    pub fn github_app_key_exposed(&self) -> Option<&str> {
        self.github_app_key.as_ref().map(|s| s.expose_secret())
    }

    /// Get the GitHub webhook secret (exposed) if configured.
    #[must_use]
    pub fn github_webhook_secret_exposed(&self) -> Option<&str> {
        self.github_webhook_secret
            .as_ref()
            .map(|s| s.expose_secret())
    }

    /// Check if GitHub App OAuth is configured (client ID and secret present).
    #[must_use]
    pub fn github_oauth_configured(&self) -> bool {
        self.github_app_client_id.is_some() && self.github_app_client_secret.is_some()
    }

    /// Get the GitHub App Client Secret (exposed) if configured.
    #[must_use]
    pub fn github_app_client_secret_exposed(&self) -> Option<&str> {
        self.github_app_client_secret
            .as_ref()
            .map(|s| s.expose_secret())
    }

    /// Check if TLS is configured (both cert and key present).
    #[must_use]
    pub fn tls_configured(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }

    /// Validate that all required configuration is present.
    /// Call this after all config sources (env, S3) have been merged.
    pub fn validate(&mut self) -> Result<()> {
        // Legacy shorthand mutual exclusivity: VOUCH_OIDC_* and VOUCH_SAML_*
        // can't both be set, because they share the `default` slug. Mixing
        // OIDC and SAML upstreams is supported via the slug-form
        // `VOUCH_IDPS=...` family, where each slug stands alone.
        if self.oidc_configured() && self.saml_configured() {
            anyhow::bail!(
                "VOUCH_OIDC_* and VOUCH_SAML_* cannot both be configured. \
                 To mix OIDC and SAML upstreams, configure additional IdPs \
                 via VOUCH_IDPS=... + VOUCH_IDP_<SLUG>_* env vars."
            );
        }

        // Re-sync the legacy entry. After an S3-config merge the legacy
        // fields may have changed since `from_args` ran; rebuild so
        // `idps[0]` reflects the merged values.
        let idps_var = std::env::var("VOUCH_IDPS").ok();
        let rebuilt = build_idps(idps_var.as_deref(), self)?;
        self.idps = rebuilt;

        // Skip jwt_secret validation when KMS HMAC signing is configured.
        if self.jwt_hmac_kms_key_id.is_none() {
            let secret = self.jwt_secret.expose_secret();
            if secret.len() < 32 {
                anyhow::bail!(
                    "VOUCH_JWT_SECRET must be at least 32 characters \
                     (set via env var or S3 config), or set VOUCH_JWT_HMAC_KMS_KEY_ID \
                     to use KMS HMAC signing instead"
                );
            }

            // Reject degenerate secrets (e.g., all same character like "aaaaa...").
            let bytes = secret.as_bytes();
            let first = bytes.first().copied().unwrap_or(0);
            let all_same = bytes.iter().all(|&b| b == first);
            if all_same {
                anyhow::bail!("VOUCH_JWT_SECRET must not consist of a single repeated character");
            }

            // Warn if the secret has low entropy (fewer than 8 unique bytes).
            let mut unique = std::collections::HashSet::new();
            for &b in bytes {
                unique.insert(b);
            }
            if unique.len() < 8 {
                tracing::warn!(
                    target: "security",
                    "VOUCH_JWT_SECRET has low entropy ({} unique bytes out of {}). \
                     Consider using a stronger secret with more character variety.",
                    unique.len(),
                    bytes.len(),
                );
            }
        }

        Ok(())
    }
}

/// Resolve DSQL endpoint from AZ or region map.
///
/// Lookup priority:
/// 1. `AWS_AZ` (e.g., "us-east-1a") - for AZ-specific endpoint routing
/// 2. `AWS_REGION` / `AWS_DEFAULT_REGION` (e.g., "us-east-1") - fallback for regional endpoints
///
/// Returns an error if no environment variable is set or if the location is not in the map.
pub fn resolve_dsql_endpoints(endpoints: &HashMap<String, String>) -> Result<String> {
    // Try AZ first (e.g., "us-east-1a")
    if let Ok(az) = std::env::var("AWS_AZ") {
        if let Some(url) = endpoints.get(&az) {
            tracing::debug!("Resolved DSQL endpoint using AWS_AZ={}", az);
            return Ok(url.clone());
        }
        // AZ not in map, fall through to region lookup
        tracing::debug!(
            "AWS_AZ={} not found in dsql_endpoints, trying region fallback",
            az
        );
    }

    // Fall back to region (e.g., "us-east-1")
    let region = std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .context("Neither AWS_AZ nor AWS_REGION is set - required for dsql_endpoints lookup")?;

    let url = endpoints.get(&region).with_context(|| {
        format!(
            "Location '{}' not found in dsql_endpoints. Available: {:?}",
            region,
            endpoints.keys().collect::<Vec<_>>()
        )
    })?;

    Ok(url.clone())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use crate::test_utils::test_config;
    use secrecy::SecretString;

    #[test]
    fn test_saml_configured_returns_true_when_metadata_url_set() {
        let mut config = test_config();
        config.saml_idp_metadata_url = Some("https://idp.example.com/saml/metadata".to_string());

        assert!(config.saml_configured());
    }

    #[test]
    fn test_saml_configured_returns_false_when_none() {
        let mut config = test_config();
        config.saml_idp_metadata_url = None;

        assert!(!config.saml_configured());
    }

    #[test]
    fn test_validate_mutual_exclusivity_oidc_and_saml() {
        let mut config = test_config();
        // test_config already sets OIDC fields; add SAML too
        config.saml_idp_metadata_url = Some("https://idp.example.com/saml/metadata".to_string());

        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("cannot both be configured"),
            "Error should mention mutual exclusivity: {err}"
        );
    }

    #[test]
    fn test_validate_saml_only_passes() {
        let mut config = test_config();
        // Remove OIDC fields, keep only SAML
        config.oidc_issuer_url = None;
        config.oidc_client_id = None;
        config.oidc_client_secret = None;
        config.saml_idp_metadata_url = Some("https://idp.example.com/saml/metadata".to_string());

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_saml_configured_implies_oidc_not_configured() {
        // Covers CC-2: when only SAML is set, oidc_configured() must be false.
        let mut config = test_config();
        config.oidc_issuer_url = None;
        config.oidc_client_id = None;
        config.oidc_client_secret = None;
        config.saml_idp_metadata_url = Some("https://idp.example.com/saml/metadata".to_string());

        assert!(
            !config.oidc_configured(),
            "oidc_configured should be false when only SAML set"
        );
        assert!(config.saml_configured(), "saml_configured should be true");
    }

    #[test]
    fn test_validate_kms_key_id_bypasses_secret_check() {
        let mut config = test_config();
        config.jwt_secret = SecretString::from("");
        config.jwt_hmac_kms_key_id = Some("mrk-test-key".to_string());

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_short_secret_without_kms_fails() {
        let mut config = test_config();
        config.jwt_secret = SecretString::from("short");
        config.jwt_hmac_kms_key_id = None;

        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("at least 32 characters"),
            "Error should mention length: {err}"
        );
    }

    #[test]
    fn test_validate_degenerate_secret_rejected() {
        let mut config = test_config();
        config.jwt_secret = SecretString::from("a".repeat(32));
        config.jwt_hmac_kms_key_id = None;

        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("repeated character"),
            "Error should mention repeated: {err}"
        );
    }

    #[test]
    fn test_validate_good_secret_accepted() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
    }
}
