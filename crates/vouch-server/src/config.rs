// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server configuration.

use crate::crypto::webauthn_verify::OriginPolicy;
use anyhow::{Context, Result};
use aws_config::FrameworkMetadata;
use clap::{ArgAction, CommandFactory, Parser, parser::ValueSource};
use ipnet::IpNet;
use secrecy::{ExposeSecret, SecretString};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;

/// Build an AWS SDK config loader tagged with vouch-server framework metadata.
///
/// The metadata renders as `lib/vouch-server/{version}` in the `x-amz-user-agent`
/// header, so operators can attribute KMS and S3 API calls to Vouch in CloudTrail.
/// It is additive: it composes with any `sdk_ua_app_id` the operator configures
/// instead of overriding it. `region` overrides the default region provider chain
/// (env / shared config / IMDS) only when `Some`. `use_fips` overrides the
/// `AWS_USE_FIPS_ENDPOINT` provider chain only when `Some` — needed because that
/// variable is resolved from `ServerConfig` (env or the bootstrap parameter), not
/// necessarily from real process environment.
///
/// # Errors
///
/// Returns an error if the framework metadata cannot be constructed. This is
/// unreachable for any valid build: the crate name and version are always within
/// the SDK's permitted user-agent charset.
pub(crate) fn aws_config_loader(
    region: Option<&str>,
    use_fips: Option<bool>,
) -> Result<aws_config::ConfigLoader> {
    let metadata = FrameworkMetadata::new("vouch-server", Some(env!("CARGO_PKG_VERSION")))
        .context("failed to build AWS SDK framework metadata")?;
    let mut loader =
        aws_config::defaults(aws_config::BehaviorVersion::latest()).framework_metadata(metadata);
    if let Some(region) = region {
        loader = loader.region(aws_config::Region::new(region.to_string()));
    }
    if let Some(use_fips) = use_fips {
        loader = loader.use_fips(use_fips);
    }
    Ok(loader)
}

// ============================================================================
// IdP Config (unified OIDC + SAML)
// ============================================================================

/// Per-provider OIDC configuration (issuer + client credentials).
#[derive(Debug, Clone)]
pub struct OidcProviderConfig {
    /// Operator-chosen slug (validated: `[a-z0-9-]{1,32}`).
    pub id: String,
    /// OIDC issuer URL (e.g., "<https://accounts.google.com>").
    pub issuer_url: String,
    /// OIDC client ID.
    pub client_id: String,
    /// OIDC client secret.
    pub client_secret: SecretString,
}

/// Per-provider SAML configuration (metadata URL + SP details).
#[derive(Debug, Clone)]
pub struct SamlProviderConfig {
    /// Operator-chosen slug (validated: `[a-z0-9-]{1,32}`).
    pub id: String,
    /// SAML IdP metadata URL.
    pub metadata_url: String,
    /// SP entity ID (defaults to `base_url` at startup if `None`).
    pub sp_entity_id: Option<String>,
    /// SAML attribute name for email (None = use NameID).
    pub email_attribute: Option<String>,
    /// SAML attribute name for domain (None = extract from email).
    pub domain_attribute: Option<String>,
}

/// Unified identity provider configuration (OIDC or SAML).
#[derive(Debug, Clone)]
pub enum IdpConfig {
    Oidc(OidcProviderConfig),
    Saml(SamlProviderConfig),
}

impl IdpConfig {
    /// Operator-chosen slug.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Oidc(c) => &c.id,
            Self::Saml(c) => &c.id,
        }
    }

    /// Kind name (`"oidc"` or `"saml"`) — matches the `type` field operators set.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Oidc(_) => "oidc",
            Self::Saml(_) => "saml",
        }
    }
}

/// Validate that a provider slug matches `[a-z0-9-]{1,32}` and does not start
/// or end with a hyphen.
pub fn validate_provider_slug(slug: &str) -> Result<()> {
    if slug.is_empty() || slug.chars().count() > 32 {
        anyhow::bail!("Provider slug '{}' must be 1-32 characters long", slug);
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        anyhow::bail!(
            "Provider slug '{}' must match [a-z0-9-] (lowercase letters, digits, hyphens)",
            slug
        );
    }
    if slug.starts_with('-') || slug.ends_with('-') {
        anyhow::bail!(
            "Provider slug '{}' must not start or end with a hyphen",
            slug
        );
    }
    Ok(())
}

/// Parse `VOUCH_IDPS` and the per-provider env vars into a `Vec<IdpConfig>`.
fn parse_idps(idp_list: Option<&str>) -> Result<Vec<IdpConfig>> {
    let Some(list) = idp_list else {
        return Ok(Vec::new());
    };
    let slugs: Vec<&str> = list
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if slugs.is_empty() {
        return Ok(Vec::new());
    }
    let mut idps = Vec::with_capacity(slugs.len());
    for slug in slugs {
        validate_provider_slug(slug)?;
        idps.push(parse_idp_from_env(slug)?);
    }
    Ok(idps)
}

/// Parse a single IdP's env vars based on its `_TYPE` discriminator.
fn parse_idp_from_env(slug: &str) -> Result<IdpConfig> {
    let upper = slug.to_uppercase().replace('-', "_");
    let type_key = format!("VOUCH_IDP_{upper}_TYPE");
    let kind = std::env::var(&type_key)
        .with_context(|| format!("IdP '{slug}' requires {type_key} to be set (oidc|saml)"))?;
    match kind.trim().to_ascii_lowercase().as_str() {
        "oidc" => parse_oidc_idp_env(slug, &upper).map(IdpConfig::Oidc),
        "saml" => parse_saml_idp_env(slug, &upper).map(IdpConfig::Saml),
        other => anyhow::bail!(
            "IdP '{slug}' has invalid {type_key}='{other}' (expected 'oidc' or 'saml')"
        ),
    }
}

fn parse_oidc_idp_env(slug: &str, upper: &str) -> Result<OidcProviderConfig> {
    let issuer_key = format!("VOUCH_IDP_{upper}_ISSUER");
    let client_id_key = format!("VOUCH_IDP_{upper}_CLIENT_ID");
    let secret_key = format!("VOUCH_IDP_{upper}_CLIENT_SECRET");

    let issuer_url = std::env::var(&issuer_key)
        .with_context(|| format!("OIDC IdP '{slug}' requires {issuer_key} to be set"))?;
    let client_id = std::env::var(&client_id_key)
        .with_context(|| format!("OIDC IdP '{slug}' requires {client_id_key} to be set"))?;
    let client_secret = std::env::var(&secret_key)
        .with_context(|| format!("OIDC IdP '{slug}' requires {secret_key} to be set"))?;

    Ok(OidcProviderConfig {
        id: slug.to_string(),
        issuer_url,
        client_id,
        client_secret: SecretString::from(client_secret),
    })
}

fn parse_saml_idp_env(slug: &str, upper: &str) -> Result<SamlProviderConfig> {
    let metadata_key = format!("VOUCH_IDP_{upper}_METADATA_URL");
    let metadata_url = std::env::var(&metadata_key)
        .with_context(|| format!("SAML IdP '{slug}' requires {metadata_key} to be set"))?;
    let sp_entity_id = std::env::var(format!("VOUCH_IDP_{upper}_SP_ENTITY_ID")).ok();
    let email_attribute = std::env::var(format!("VOUCH_IDP_{upper}_EMAIL_ATTRIBUTE")).ok();
    let domain_attribute = std::env::var(format!("VOUCH_IDP_{upper}_DOMAIN_ATTRIBUTE")).ok();

    Ok(SamlProviderConfig {
        id: slug.to_string(),
        metadata_url,
        sp_entity_id,
        email_attribute,
        domain_attribute,
    })
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

    /// Comma-separated list of IdP slugs (e.g., "google,entra,corp-saml").
    /// Each slug must have a corresponding `VOUCH_IDP_<SLUG>_TYPE=oidc|saml` env
    /// var plus the type-specific vars (see docs/src/idp/overview.md).
    #[arg(long, env = "VOUCH_IDPS")]
    pub idps: Option<String>,

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

    /// Security contact email for `/.well-known/security.txt`
    /// (RFC 9116 `Contact`). Defaults to "security@vouch.sh" when unset.
    #[arg(long, env = "VOUCH_SECURITY_CONTACT")]
    pub security_contact: Option<String>,

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

    /// AWS region. Used for KMS/S3 calls, resolving `dsql_endpoints`, and
    /// cross-account KMS ARN construction. Falls back to `AWS_DEFAULT_REGION`,
    /// then to IMDS when running on EC2 with no upstream bootstrap parameter.
    #[arg(long, env = "AWS_REGION", hide = true)]
    pub aws_region: Option<String>,

    /// AWS availability zone, checked first when resolving `dsql_endpoints`.
    /// Falls back to IMDS when running on EC2.
    #[arg(long, env = "AWS_AZ", hide = true)]
    pub aws_az: Option<String>,

    /// AWS partition segment (`aws`, `aws-us-gov`, ...) for cross-account KMS
    /// ARN construction. Falls back to IMDS `services/partition` when running
    /// on EC2 (absent on older instance generations).
    #[arg(long, env = "AWS_PARTITION", hide = true)]
    pub aws_partition: Option<String>,

    /// Whether AWS SDK clients should use FIPS endpoints. Per-deployment (not
    /// baked into the AMI, since FIPS endpoint availability varies by region),
    /// so it is delivered the same way as other bootstrap-parameter values.
    #[arg(long, env = "AWS_USE_FIPS_ENDPOINT", hide = true)]
    pub aws_use_fips_endpoint: Option<String>,

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
    ///
    /// When set, this is a broad **test-mode switch** for automated OpenID
    /// conformance testing, not just one route. It enables
    /// `GET /certification/complete-login` (a login bypass that mints a session
    /// for a synthetic test user without a FIDO2 key), **disables global rate
    /// limiting**, and **relaxes the upstream-IdP requirement** (the server may
    /// boot with no IdP). MUST NOT be set in production deployments — a leaked
    /// or mistakenly set value enables a login-bypass-shaped endpoint.
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
}

// ============================================================================
// Bootstrap Overlay
// ============================================================================

/// Build `--flag=value` overlay tokens for every `Args` field whose current
/// value source is `None` or `DefaultValue`, so a bootstrap-supplied blob
/// (see `infra::bootstrap`) can fill gaps without ever overriding an explicit
/// CLI flag or process environment variable.
///
/// `matches` is the already-parsed `ArgMatches` for `Args` — the top-level
/// matches in legacy invocation, or the `serve` subcommand's matches when
/// invoked as `vouch-server serve`. The env-name-to-arg mapping is built from
/// `Args::command()` rather than hand-maintained, so adding a new `Args`
/// field with an `env = "..."` attribute is automatically covered.
#[must_use]
pub fn bootstrap_overlay_args(
    matches: &clap::ArgMatches,
    blob: &BTreeMap<String, String>,
) -> Vec<OsString> {
    let command = Args::command();
    let mut tokens = Vec::new();
    for arg in command.get_arguments() {
        let Some(env_name) = arg.get_env().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(value) = blob.get(env_name).filter(|v| !v.is_empty()) else {
            continue;
        };
        if !matches!(
            matches.value_source(arg.get_id().as_str()),
            None | Some(ValueSource::DefaultValue)
        ) {
            continue;
        }
        let Some(long) = arg.get_long() else {
            continue;
        };
        if matches!(arg.get_action(), ArgAction::SetTrue) {
            // SetTrue args cannot accept `--flag=value`, so parse the blob
            // value leniently and emit the bare flag only when truthy.
            let truthy = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "true" | "1" | "yes" | "on"
            );
            if truthy {
                tokens.push(OsString::from(format!("--{long}")));
            }
        } else {
            tokens.push(OsString::from(format!("--{long}={value}")));
        }
    }
    tokens
}

// ============================================================================
// Server Configuration
// ============================================================================

/// A server base URL with no trailing slash.
///
/// Normalization happens in [`BaseUrl::new`], which is the only way to build
/// one, so every value is already normalized and no call site needs to trim.
/// A trailing slash here produces `https://host//oauth/token` in every
/// derived endpoint and an issuer that fails the exact-match comparison
/// clients perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseUrl(String);

impl BaseUrl {
    /// Build a base URL, stripping any trailing slashes.
    #[must_use]
    pub fn new(raw: impl AsRef<str>) -> Self {
        Self(raw.as_ref().trim_end_matches('/').to_string())
    }

    /// The normalized URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for BaseUrl {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BaseUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// Comparisons against plain strings keep call sites readable — notably the
// WebAuthn origin check, which compares a browser-supplied origin to this.
impl PartialEq<str> for BaseUrl {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<String> for BaseUrl {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl PartialEq<BaseUrl> for String {
    fn eq(&self, other: &BaseUrl) -> bool {
        self == &other.0
    }
}

impl PartialEq<&str> for BaseUrl {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<BaseUrl> for &str {
    fn eq(&self, other: &BaseUrl) -> bool {
        *self == other.0
    }
}

// Serialized in config snapshots and template contexts; the wire form is the
// normalized string, so this is transparent.
impl serde::Serialize for BaseUrl {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

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
    /// Configured identity providers (OIDC + SAML), in operator-specified order.
    pub idps: Vec<IdpConfig>,
    /// Base URL for this server (defaults to `https://{rp_id}`, or `http://localhost:port` for local dev).
    pub base_url: BaseUrl,
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
    /// Security contact email for `/.well-known/security.txt`
    /// (RFC 9116 `Contact`). Defaults to `"security@vouch.sh"`.
    pub security_contact: String,
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
    /// AWS account ID that owns the KMS keys configured above (for
    /// cross-account access). When set, bare key IDs are wrapped into full
    /// ARNs using `AWS_PARTITION` and `AWS_REGION` from the environment.
    pub kms_account_id: Option<String>,
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
    /// AWS region, resolved from `AWS_REGION`/`AWS_DEFAULT_REGION` or, on EC2
    /// with no bootstrap parameter override, from IMDS.
    pub aws_region: Option<String>,
    /// AWS availability zone, resolved from `AWS_AZ` or IMDS.
    pub aws_az: Option<String>,
    /// AWS partition segment, resolved from `AWS_PARTITION` or IMDS.
    pub aws_partition: Option<String>,
    /// Whether AWS SDK clients should use FIPS endpoints.
    pub aws_use_fips_endpoint: Option<bool>,
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

/// Compute the base URL: the explicit value if provided, otherwise derived
/// from `rp_id` (http with port for loopback development, https for
/// production).
fn derive_base_url(base_url: Option<String>, rp_id: &str, listen_addr: &str) -> String {
    if let Some(url) = base_url {
        return url;
    }
    let derived = if vouch_common::is_loopback_host(rp_id) {
        // For local development (localhost/127.0.0.1), use http with port
        let port = listen_addr.rsplit(':').next().unwrap_or("3000");
        format!("http://{rp_id}:{port}")
    } else {
        // Production: use https without port (assumes standard 443)
        format!("https://{rp_id}")
    };
    tracing::debug!("VOUCH_BASE_URL not set, derived from rp_id: {}", derived);
    derived
}

impl ServerConfig {
    /// Host of `base_url` (e.g. `us.vouch.sh`), or `None` if `base_url` does
    /// not parse as a URL with a hostname.
    #[must_use]
    pub fn primary_host(&self) -> Option<String> {
        url::Url::parse(&self.base_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
    }

    /// Per-org OIDC issuer for a claimed subdomain label: `base_url` with the
    /// host replaced by `{label}.{host}`, preserving scheme and port (so
    /// loopback dev yields `http://acme.localhost:3000`).
    ///
    /// The issuer is always built from the stored label plus the configured
    /// `base_url` — never from a request `Host` header. Returns `None` if
    /// `base_url` cannot be parsed or re-assembled.
    #[must_use]
    pub fn org_issuer(&self, label: &str) -> Option<String> {
        let mut url = url::Url::parse(&self.base_url).ok()?;
        let host = url.host_str()?.to_ascii_lowercase();
        url.set_host(Some(&format!("{label}.{host}"))).ok()?;
        Some(url.to_string().trim_end_matches('/').to_string())
    }

    /// Create configuration from parsed command-line arguments.
    ///
    /// `instance` carries IMDS-discovered facts (region, availability zone,
    /// partition) used only as a fallback beneath `AWS_REGION`/`AWS_AZ`/
    /// `AWS_PARTITION` — see `infra::bootstrap`.
    pub fn from_args(
        args: Args,
        instance: Option<&crate::infra::bootstrap::Bootstrap>,
    ) -> Result<Self> {
        // Note: Validation of rp_id and jwt_secret is deferred to validate()
        // to allow these values to come from S3 config.

        // Empty strings are treated as unset so the fallback chain can
        // progress to IMDS-derived values and the AWS SDK default region
        // provider chain (env / shared config / IMDS) is not overridden with
        // a blank `Region::new("")` — see `aws_config_loader`. The same
        // empty-means-unset pattern is already used by `ssh_ca_key_path` and
        // `allowed_domains` below.
        let aws_region = vouch_common::env::non_empty(args.aws_region)
            .or_else(|| vouch_common::env::non_empty_env("AWS_DEFAULT_REGION"))
            .or_else(|| instance.map(|b| b.region.clone()));
        let aws_az = vouch_common::env::non_empty(args.aws_az)
            .or_else(|| instance.map(|b| b.availability_zone.clone()));
        let aws_partition = vouch_common::env::non_empty(args.aws_partition)
            .or_else(|| instance.and_then(|b| b.partition.clone()));
        let aws_use_fips_endpoint = vouch_common::env::non_empty(args.aws_use_fips_endpoint)
            .map(|v| v.eq_ignore_ascii_case("true"));

        // Normalize: strip any trailing slashes so the issuer and every
        // endpoint derived from `base_url` (OIDC discovery, JWT `iss`, DPoP
        // `htu`, authorization code validation) are spec-compliant. OIDC
        // Discovery 1.0 §4.3 requires exact string equality between the
        // issuer used to fetch the discovery document and the `issuer` value
        // returned; a trailing slash breaks that comparison and produces
        // double-slash endpoint URLs (e.g. `https://host//oauth/token`).
        let base_url = derive_base_url(args.base_url, &args.rp_id, &args.listen_addr)
            .trim_end_matches('/')
            .to_string();

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

        // Parse unified IdP list (OIDC + SAML).
        let idps = parse_idps(args.idps.as_deref())?;

        Ok(Self {
            listen_addr: args.listen_addr,
            database_url: args.database_url,
            rp_id: args.rp_id,
            rp_name: args.rp_name,
            jwt_secret: SecretString::from(args.jwt_secret),
            session_hours: args.session_hours,
            idps,
            base_url: BaseUrl::new(base_url),
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
            security_contact: vouch_common::env::non_empty(args.security_contact)
                .unwrap_or_else(|| "security@vouch.sh".to_string()),
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
            kms_account_id: None,
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
            s3_config_region: vouch_common::env::non_empty(args.s3_config_region),
            s3_config_poll_interval: args.s3_config_poll_interval,
            aws_region,
            aws_az,
            aws_partition,
            aws_use_fips_endpoint,
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
        })
    }

    /// Check if at least one IdP (of any kind) is configured.
    #[must_use]
    pub fn has_idps(&self) -> bool {
        !self.idps.is_empty()
    }

    /// Check if at least one OIDC IdP is configured.
    #[must_use]
    pub fn has_oidc_idp(&self) -> bool {
        self.idps.iter().any(|i| matches!(i, IdpConfig::Oidc(_)))
    }

    /// Check if at least one SAML IdP is configured.
    #[must_use]
    pub fn has_saml_idp(&self) -> bool {
        self.idps.iter().any(|i| matches!(i, IdpConfig::Saml(_)))
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
    pub fn validate(&self) -> Result<()> {
        // Refuse to start with no IdP. Enrollment and login both depend on
        // upstream identity verification to bind a security key to a real
        // email; without it the server can only create users keyed on
        // placeholder strings, which silently degrades the security model.
        //
        // Certification-test mode is the one exception: the cert-login
        // handler mints a synthetic session without touching IdP discovery
        // or callback, and the token is gated to non-production use.
        if self.idps.is_empty() && self.certification_test_token.is_none() {
            anyhow::bail!(
                "No upstream IdP configured. Set VOUCH_IDPS=<slug>[,<slug>...] \
                 with per-provider VOUCH_IDP_<SLUG>_TYPE plus type-specific vars."
            );
        }

        // Reject duplicate IdP slugs — order matters for UI but ids must be unique.
        // Also enforce slug format here so all merged sources (env, S3) are
        // checked consistently — env parsing already runs validate_provider_slug,
        // but S3-sourced IdPs would otherwise bypass it.
        let mut seen = std::collections::HashSet::new();
        for idp in &self.idps {
            validate_provider_slug(idp.id())?;
            if !seen.insert(idp.id()) {
                anyhow::bail!(
                    "Duplicate IdP slug '{}' in VOUCH_IDPS / idps[].id",
                    idp.id()
                );
            }
        }

        // An AAGUID policy restricts which authenticator *models* may enroll,
        // and the model is only knowable from an attestation certificate. With
        // require_attestation_cert off, the policy would be enforced against
        // the self-reported AAGUID in authData, which any client can set to
        // whatever value the allowlist wants to see. Reject the pairing rather
        // than serve a restriction that does not restrict.
        if !matches!(self.allowed_aaguids, vouch_common::AaguidPolicy::Any)
            && !self.require_attestation_cert
        {
            anyhow::bail!(
                "VOUCH_ALLOWED_AAGUIDS restricts authenticator models, which \
                 requires VOUCH_REQUIRE_ATTESTATION_CERT=true. Without a \
                 verified attestation certificate the AAGUID is self-reported \
                 and the restriction can be bypassed."
            );
        }

        // Reject partial TLS configuration. With only one of cert/key set the
        // server silently runs plain HTTP (serving and discovery both require
        // tls_configured()), which is never what the operator intended.
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            anyhow::bail!(
                "Partial TLS configuration: set both VOUCH_TLS_CERT and \
                 VOUCH_TLS_KEY (or tls.cert and tls.key in the S3 config), \
                 or neither."
            );
        }

        // Retention windows are subtracted from `now` to form a deletion cutoff;
        // a negative value yields a future cutoff, which matches every row and
        // wipes the entire audit log. Reject at startup so an operator typo or
        // malicious config change can't silently destroy forensic data.
        if self.auth_events_retention_days < 0 {
            anyhow::bail!(
                "VOUCH_AUTH_EVENTS_RETENTION_DAYS must be non-negative (got {})",
                self.auth_events_retention_days
            );
        }
        if self.oauth_events_retention_days < 0 {
            anyhow::bail!(
                "VOUCH_OAUTH_EVENTS_RETENTION_DAYS must be non-negative (got {})",
                self.oauth_events_retention_days
            );
        }

        // Temporal posture policies evaluate a 24h window of audit history.
        // Retention shorter than that silently truncates the window: the
        // sweep deletes evidence a live policy still needs, so aggregation
        // policies under-count and recency policies deny.
        for (name, days) in [
            (
                "VOUCH_AUTH_EVENTS_RETENTION_DAYS",
                self.auth_events_retention_days,
            ),
            (
                "VOUCH_OAUTH_EVENTS_RETENTION_DAYS",
                self.oauth_events_retention_days,
            ),
        ] {
            if days < 2 {
                tracing::warn!(
                    "{name}={days} is shorter than the 24h window temporal posture \
                     policies evaluate; their evidence may be deleted before use"
                );
            }
        }

        // Reject wildcard in VOUCH_CORS_ORIGINS for UI routes: those routes use
        // cookie-based credentialed sessions, and `Access-Control-Allow-Origin: *`
        // is forbidden with `Access-Control-Allow-Credentials: true` (CORS spec
        // §3.2 and tower-http panic at router build time). List explicit origins.
        if let Some(origins) = &self.cors_origins {
            for origin in origins {
                if origin == "*" {
                    anyhow::bail!(
                        "VOUCH_CORS_ORIGINS must not contain '*'. UI routes use credentialed \
                         cookie sessions; wildcard origin is forbidden with Allow-Credentials. \
                         List explicit origins instead, e.g. https://app.example.com"
                    );
                }
                // An origin is scheme + host + optional port (RFC 6454 §6.1) —
                // no path, not even a bare "/". A value carrying one parses
                // into a `HeaderValue` happily and is then compared verbatim
                // against the browser's `Origin` header, so it silently never
                // matches and every cross-origin UI request fails with nothing
                // logged. Reject it here rather than rewrite it: the operator
                // meant something specific and should be told it is wrong.
                let after_scheme = origin.split_once("://").map_or(origin.as_str(), |(_, r)| r);
                if after_scheme.contains('/') {
                    anyhow::bail!(
                        "VOUCH_CORS_ORIGINS entry '{origin}' must not contain a path or \
                         trailing slash. An origin is scheme://host[:port] only — a browser \
                         never sends a path in the Origin header, so this entry would never \
                         match. Use '{}' instead.",
                        origin.trim_end_matches('/')
                    );
                }
            }
        }

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

impl From<&ServerConfig> for OriginPolicy {
    /// A TLS-configured server is a real deployment, where an origin mismatch
    /// is always an error. Without TLS the server is a local development
    /// instance reached over loopback, where the browser's origin may differ
    /// from the configured one by host spelling or port.
    fn from(config: &ServerConfig) -> Self {
        if config.tls_configured() {
            Self::Strict
        } else {
            Self::AllowLoopbackVariations
        }
    }
}

/// Resolve DSQL endpoint from AZ or region map.
///
/// Lookup priority:
/// 1. `aws_az` (e.g., "us-east-1a") - for AZ-specific endpoint routing
/// 2. `aws_region` (e.g., "us-east-1") - fallback for regional endpoints
///
/// Both values are `ServerConfig` fields (resolved from env or, on EC2, IMDS)
/// rather than raw environment reads, so this stays a pure function of its
/// arguments.
///
/// Returns an error if neither value is set or if the location is not in the map.
pub fn resolve_dsql_endpoints(
    endpoints: &HashMap<String, String>,
    aws_az: Option<&str>,
    aws_region: Option<&str>,
) -> Result<String> {
    // Try AZ first (e.g., "us-east-1a")
    if let Some(az) = aws_az {
        if let Some(url) = endpoints.get(az) {
            tracing::debug!("Resolved DSQL endpoint using aws_az={}", az);
            return Ok(url.clone());
        }
        // AZ not in map, fall through to region lookup
        tracing::debug!(
            "aws_az={} not found in dsql_endpoints, trying region fallback",
            az
        );
    }

    // Fall back to region (e.g., "us-east-1")
    let region = aws_region
        .context("Neither aws_az nor aws_region is set - required for dsql_endpoints lookup")?;

    let url = endpoints.get(region).with_context(|| {
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
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use crate::config::{
        Args, IdpConfig, SamlProviderConfig, ServerConfig, bootstrap_overlay_args,
        resolve_dsql_endpoints, validate_provider_slug,
    };
    use crate::test_utils::test_config;
    use clap::{CommandFactory, Parser};
    use secrecy::SecretString;
    use std::collections::{BTreeMap, HashMap};

    fn saml_provider_for_tests() -> SamlProviderConfig {
        SamlProviderConfig {
            id: "corp-saml".to_string(),
            metadata_url: "https://idp.example.com/saml/metadata".to_string(),
            sp_entity_id: None,
            email_attribute: None,
            domain_attribute: None,
        }
    }

    #[test]
    fn test_org_issuer_preserves_scheme_and_port() {
        let mut config = test_config();
        config.base_url = crate::config::BaseUrl::new("http://localhost:3000");
        assert_eq!(config.primary_host().as_deref(), Some("localhost"));
        assert_eq!(
            config.org_issuer("acme").as_deref(),
            Some("http://acme.localhost:3000")
        );
    }

    #[test]
    fn test_org_issuer_production_shape() {
        let mut config = test_config();
        config.base_url = crate::config::BaseUrl::new("https://us.vouch.sh");
        assert_eq!(config.primary_host().as_deref(), Some("us.vouch.sh"));
        assert_eq!(
            config.org_issuer("acme").as_deref(),
            Some("https://acme.us.vouch.sh")
        );
    }

    #[test]
    fn test_org_issuer_unparseable_base_url() {
        let mut config = test_config();
        config.base_url = crate::config::BaseUrl::new("not a url");
        assert!(config.primary_host().is_none());
        assert!(config.org_issuer("acme").is_none());
    }

    #[test]
    fn test_has_saml_idp_when_configured() {
        let mut config = test_config();
        config.idps.push(IdpConfig::Saml(saml_provider_for_tests()));
        assert!(config.has_saml_idp());
    }

    #[test]
    fn test_has_saml_idp_returns_false_when_none() {
        let mut config = test_config();
        config.idps.retain(|i| matches!(i, IdpConfig::Oidc(_)));
        assert!(!config.has_saml_idp());
    }

    #[test]
    fn test_validate_accepts_mixed_oidc_and_saml() {
        // Mutual exclusivity removed — both kinds can coexist in the same idps list.
        let mut config = test_config();
        config.idps.push(IdpConfig::Saml(saml_provider_for_tests()));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_aaguid_policy_without_attestation_cert() {
        // An AAGUID policy names authenticator *models*, which only an
        // attestation certificate can establish. Without the certificate
        // requirement the policy is enforced against a self-reported value the
        // client chooses, so the pairing must not start.
        let mut config = test_config();
        config.allowed_aaguids = vouch_common::AaguidPolicy::FipsOnly;
        config.require_attestation_cert = false;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("VOUCH_REQUIRE_ATTESTATION_CERT"),
            "error must name the variable the operator has to set, got: {err}"
        );
    }

    #[test]
    fn test_validate_accepts_aaguid_policy_with_attestation_cert() {
        let mut config = test_config();
        config.allowed_aaguids = vouch_common::AaguidPolicy::FipsOnly;
        config.require_attestation_cert = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_accepts_any_policy_without_attestation_cert() {
        // The default pairing is unchanged: no model restriction, no
        // certificate requirement.
        let mut config = test_config();
        config.allowed_aaguids = vouch_common::AaguidPolicy::Any;
        config.require_attestation_cert = false;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_partial_tls_config() {
        let mut config = test_config();
        config.tls_cert = Some("cert-pem".to_string());
        config.tls_key = None;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("Partial TLS configuration"),
            "expected partial-TLS error, got: {err}"
        );

        let mut config = test_config();
        config.tls_cert = None;
        config.tls_key = Some(secrecy::SecretString::from("key-pem".to_string()));
        assert!(config.validate().is_err());

        // Both set (or neither) is fine.
        let mut config = test_config();
        config.tls_cert = Some("cert-pem".to_string());
        config.tls_key = Some(secrecy::SecretString::from("key-pem".to_string()));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_duplicate_idp_slugs() {
        let mut config = test_config();
        let dup = SamlProviderConfig {
            id: config.idps[0].id().to_string(),
            ..saml_provider_for_tests()
        };
        config.idps.push(IdpConfig::Saml(dup));
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("Duplicate IdP slug"),
            "expected duplicate-slug error, got: {err}"
        );
    }

    #[test]
    fn test_validate_saml_only_passes() {
        let mut config = test_config();
        config.idps = vec![IdpConfig::Saml(saml_provider_for_tests())];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_has_oidc_idp_false_when_only_saml() {
        let mut config = test_config();
        config.idps = vec![IdpConfig::Saml(saml_provider_for_tests())];
        assert!(!config.has_oidc_idp(), "should be false when only SAML set");
        assert!(config.has_saml_idp(), "has_saml_idp should be true");
    }

    #[test]
    fn test_validate_kms_key_id_bypasses_secret_check() {
        let mut config = test_config();
        config.jwt_secret = SecretString::from("");
        config.jwt_hmac_kms_key_id = Some("mrk-test-key".to_string());

        assert!(config.validate().is_ok());
    }

    // RFC 7518 §3.2: "A key of the same size as the hash output (for instance,
    // 256 bits for "HS256") or larger MUST be used with this algorithm."
    // State tokens are signed HS256 with this secret, so the 32-character
    // floor is that 256-bit minimum.
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
        let config = test_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_negative_auth_events_retention() {
        let mut config = test_config();
        config.auth_events_retention_days = -1;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("AUTH_EVENTS_RETENTION_DAYS"),
            "Error should name the offending field: {err}"
        );
    }

    #[test]
    fn test_validate_rejects_negative_oauth_events_retention() {
        let mut config = test_config();
        config.oauth_events_retention_days = -1;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("OAUTH_EVENTS_RETENTION_DAYS"),
            "Error should name the offending field: {err}"
        );
    }

    #[test]
    fn test_validate_rejects_i64_min_retention() {
        // i64::MIN is the worst case: days_to_span(i64::MIN) would panic in
        // jiff because i64::MIN * 24 overflows; validation must catch it first.
        let mut config = test_config();
        config.auth_events_retention_days = i64::MIN;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_accepts_zero_retention() {
        // Zero days is a valid choice: deletes everything older than "now",
        // i.e. effectively disables retention. Only negative values are rejected.
        let mut config = test_config();
        config.auth_events_retention_days = 0;
        config.oauth_events_retention_days = 0;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_provider_slug_valid() {
        assert!(validate_provider_slug("google").is_ok());
        assert!(validate_provider_slug("entra").is_ok());
        assert!(validate_provider_slug("my-idp-2").is_ok());
        assert!(validate_provider_slug("a").is_ok());
        let long_slug = "a".repeat(32);
        assert!(validate_provider_slug(&long_slug).is_ok());
    }

    #[test]
    fn test_validate_provider_slug_invalid() {
        assert!(validate_provider_slug("").is_err(), "empty slug must fail");
        let too_long = "a".repeat(33);
        assert!(
            validate_provider_slug(&too_long).is_err(),
            "33 chars must fail"
        );
        assert!(
            validate_provider_slug("Google").is_err(),
            "uppercase must fail"
        );
        assert!(
            validate_provider_slug("my_idp").is_err(),
            "underscore must fail"
        );
        assert!(validate_provider_slug("my idp").is_err(), "space must fail");
        assert!(
            validate_provider_slug("-google").is_err(),
            "leading hyphen must fail"
        );
        assert!(
            validate_provider_slug("google-").is_err(),
            "trailing hyphen must fail"
        );
    }

    #[test]
    fn test_has_idps_empty() {
        let mut config = test_config();
        config.idps = Vec::new();
        assert!(!config.has_idps());
        assert!(!config.has_oidc_idp());
        assert!(!config.has_saml_idp());
    }

    #[test]
    fn test_validate_rejects_zero_idps() {
        // Without an IdP we cannot verify user identity, so the server must
        // refuse to boot rather than silently degrade to placeholder users.
        let mut config = test_config();
        config.idps = Vec::new();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("No upstream IdP configured"),
            "expected zero-IdP rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_cert_token_bypasses_idp_requirement() {
        // Certification-test mode mints sessions via the cert-login handler
        // without contacting an upstream IdP, so requiring one would block
        // the OpenID conformance suite from running.
        let mut config = test_config();
        config.idps = Vec::new();
        config.certification_test_token = Some(SecretString::from("cert-token"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_has_idps_with_providers() {
        let config = test_config();
        // test_config sets one OIDC provider
        assert!(config.has_idps());
        assert!(config.has_oidc_idp());
    }

    /// Regression for #541: wildcard CORS origin must be rejected at startup
    /// (rationale on the check in `validate`).
    #[test]
    fn test_validate_rejects_wildcard_cors_origin() {
        let mut config = test_config();
        config.cors_origins = Some(vec!["*".to_string()]);
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("VOUCH_CORS_ORIGINS"),
            "Error should name the offending variable: {err}"
        );
        assert!(
            err.to_string().contains("wildcard"),
            "Error should mention wildcard: {err}"
        );
    }

    /// Regression for #541: explicit HTTPS origins must be accepted.
    #[test]
    fn test_validate_accepts_explicit_cors_origins() {
        let mut config = test_config();
        config.cors_origins = Some(vec![
            "https://app.example.com".to_string(),
            "https://other.example.com:8443".to_string(),
        ]);
        assert!(config.validate().is_ok());
    }

    /// A trailing slash parses into a `HeaderValue` but never matches the
    /// browser's `Origin`, so the misconfiguration is invisible at runtime —
    /// every cross-origin UI request just fails. Reject it at startup.
    #[test]
    fn test_validate_rejects_cors_origin_with_trailing_slash() {
        let mut config = test_config();
        config.cors_origins = Some(vec!["https://app.example.com/".to_string()]);
        let err = config
            .validate()
            .expect_err("an origin with a trailing slash must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("must not contain a path"), "message: {msg}");
        assert!(
            msg.contains("https://app.example.com'"),
            "message should suggest the corrected value: {msg}"
        );
    }

    #[test]
    fn test_validate_rejects_cors_origin_with_path() {
        let mut config = test_config();
        config.cors_origins = Some(vec!["https://app.example.com/callback".to_string()]);
        assert!(
            config.validate().is_err(),
            "an origin carrying a path must be rejected"
        );
    }

    /// The whole point of the newtype: there is no way to hold an
    /// unnormalized base URL, so no call site needs to trim.
    #[test]
    fn base_url_normalizes_on_construction() {
        use super::BaseUrl;
        assert_eq!(
            BaseUrl::new("https://vouch.example.com/"),
            "https://vouch.example.com"
        );
        assert_eq!(
            BaseUrl::new("https://vouch.example.com///"),
            "https://vouch.example.com"
        );
        assert_eq!(
            BaseUrl::new("https://vouch.example.com"),
            "https://vouch.example.com"
        );
        // A path-bearing base URL keeps its path, losing only the trailing slash.
        assert_eq!(
            BaseUrl::new("https://example.com/vouch/"),
            "https://example.com/vouch"
        );
    }

    // ========================================================================
    // Bootstrap overlay precedence
    //
    // These construct `ArgMatches` directly via `Command::try_get_matches_from`
    // rather than mutating real process environment variables, per the no-`unsafe`
    // policy (`std::env::set_var` requires `unsafe` and is denied workspace-wide).
    // There is no test asserting a real environment variable beats the blob: the
    // overlay's guard (`matches!(value_source, None | Some(ValueSource::DefaultValue))`)
    // treats `EnvVariable` and `CommandLine` identically -- both are excluded -- so
    // `bootstrap_overlay_does_not_override_explicit_cli_flag` below already exercises
    // the shared branch; only clap's own (independently tested) env resolution would
    // differ, not any code in this crate.
    // ========================================================================

    fn blob(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// Parse `argv` with every arg's `env` attachment cleared, so variables
    /// exported in the developer's shell (e.g. a sourced `.env` setting
    /// `VOUCH_REQUIRE_ATTESTATION_CERT` or `AWS_REGION`) cannot leak into
    /// `value_source` and flip these precedence assertions.
    fn matches_ignoring_process_env(argv: &[&str]) -> clap::ArgMatches {
        let mut command = Args::command();
        let arg_ids: Vec<clap::Id> = command
            .get_arguments()
            .map(|a| a.get_id().clone())
            .collect();
        for id in arg_ids {
            command = command.mut_arg(id, |arg| arg.env(None::<&'static str>));
        }
        command.try_get_matches_from(argv).expect("parse test argv")
    }

    #[test]
    fn bootstrap_overlay_fills_unset_option_arg() {
        // s3_config_bucket has no default_value, so with no CLI flag and no
        // env var, its value_source is None -- the arm the issue calls "essential".
        let matches = matches_ignoring_process_env(&["vouch-server"]);
        let blob = blob(&[("VOUCH_S3_CONFIG_BUCKET", "my-bucket")]);
        let tokens = bootstrap_overlay_args(&matches, &blob);
        assert_eq!(
            tokens,
            vec![std::ffi::OsString::from("--s3-config-bucket=my-bucket")]
        );
    }

    #[test]
    fn bootstrap_overlay_fills_defaulted_arg() {
        // mtls_port defaults to "8443"; with no CLI flag and no env var its
        // value_source is Some(DefaultValue), the other arm the overlay covers.
        let matches = matches_ignoring_process_env(&["vouch-server"]);
        let blob = blob(&[("VOUCH_MTLS_PORT", "9443")]);
        let tokens = bootstrap_overlay_args(&matches, &blob);
        assert_eq!(tokens, vec![std::ffi::OsString::from("--mtls-port=9443")]);
    }

    #[test]
    fn bootstrap_overlay_does_not_override_explicit_cli_flag() {
        let matches = matches_ignoring_process_env(&["vouch-server", "--mtls-port", "1234"]);
        let blob = blob(&[("VOUCH_MTLS_PORT", "9999")]);
        let tokens = bootstrap_overlay_args(&matches, &blob);
        assert!(
            tokens.is_empty(),
            "blob must not override an explicit CLI flag, got: {tokens:?}"
        );
    }

    #[test]
    fn bootstrap_overlay_ignores_unmapped_blob_keys() {
        let matches = matches_ignoring_process_env(&["vouch-server"]);
        let blob = blob(&[("RUST_LOG", "debug"), ("SOME_UNRELATED_KEY", "x")]);
        let tokens = bootstrap_overlay_args(&matches, &blob);
        assert!(
            tokens.is_empty(),
            "blob keys with no matching Args env name must be ignored, got: {tokens:?}"
        );
    }

    #[test]
    fn bootstrap_overlay_emits_bare_flag_for_truthy_bool() {
        // require_attestation_cert is ArgAction::SetTrue (plain bool field),
        // which cannot accept `--flag=value` on the command line.
        let matches = matches_ignoring_process_env(&["vouch-server"]);
        let blob = blob(&[("VOUCH_REQUIRE_ATTESTATION_CERT", "true")]);
        let tokens = bootstrap_overlay_args(&matches, &blob);
        assert_eq!(
            tokens,
            vec![std::ffi::OsString::from("--require-attestation-cert")]
        );
    }

    #[test]
    fn bootstrap_overlay_emits_nothing_for_falsy_bool() {
        let matches = matches_ignoring_process_env(&["vouch-server"]);
        let blob = blob(&[("VOUCH_REQUIRE_ATTESTATION_CERT", "false")]);
        let tokens = bootstrap_overlay_args(&matches, &blob);
        assert!(tokens.is_empty(), "got: {tokens:?}");
    }

    #[test]
    fn bootstrap_overlay_skips_empty_blob_values() {
        // Regression: an empty value in the bootstrap blob used to emit
        // `--flag=`, which clap parses as `Some("")`. That blocked the
        // IMDS fallback and overrode the AWS SDK default region provider
        // chain downstream in `ServerConfig::from_args`. Empty blob values
        // must be treated as absent so the next provider in the chain wins.
        let matches = matches_ignoring_process_env(&["vouch-server"]);
        let blob = blob(&[
            ("AWS_REGION", ""),
            ("AWS_AZ", ""),
            ("AWS_PARTITION", ""),
            ("VOUCH_S3_CONFIG_BUCKET", "real-bucket"),
        ]);
        let tokens = bootstrap_overlay_args(&matches, &blob);
        // Only the non-empty entry should produce a token; the three empty
        // AWS_* entries must be skipped entirely (no `--aws-region=` etc.).
        assert_eq!(
            tokens,
            vec![std::ffi::OsString::from("--s3-config-bucket=real-bucket")]
        );
    }

    // ========================================================================
    // ServerConfig::from_args — AWS region/AZ/partition empty-string handling
    //
    // These tests construct `Args` via `Args::try_parse_from` (parsing CLI
    // flags) and pass a synthetic `Bootstrap` as the IMDS fallback. The
    // `AWS_DEFAULT_REGION` env fallback cannot be unit-tested here because
    // `std::env::set_var` is `unsafe` under edition 2024 and `unsafe_code`
    // is denied workspace-wide — the same constraint documented above the
    // "Bootstrap overlay precedence" section. The `.filter(|s| !s.is_empty())`
    // guard on that branch mirrors the guard on the CLI branch, which is
    // exercised below.
    // ========================================================================

    fn imds_bootstrap() -> crate::infra::bootstrap::Bootstrap {
        crate::infra::bootstrap::Bootstrap {
            region: "us-east-1".to_string(),
            availability_zone: "us-east-1a".to_string(),
            partition: Some("aws".to_string()),
            params: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn from_args_empty_aws_region_cli_falls_back_to_imds() {
        // Regression: `--aws-region=` used to leave `aws_region = Some("")`,
        // which blocked the IMDS fallback. With the fix, the empty CLI value
        // is filtered out and the IMDS region wins.
        let args = Args::try_parse_from(["vouch-server", "--aws-region="])
            .expect("parse with empty --aws-region");
        let instance = imds_bootstrap();
        let config = ServerConfig::from_args(args, Some(&instance)).expect("config builds");
        assert_eq!(
            config.aws_region.as_deref(),
            Some("us-east-1"),
            "empty CLI aws_region should fall back to IMDS region"
        );
    }

    #[test]
    fn from_args_empty_aws_values_without_imds_yield_none() {
        // No IMDS instance available (non-EC2). Empty CLI values must become
        // `None`, NOT `Some("")` — otherwise `aws_config_loader` would call
        // `Region::new("")`, overriding the SDK default region provider chain.
        let args = Args::try_parse_from([
            "vouch-server",
            "--aws-region=",
            "--aws-az=",
            "--aws-partition=",
        ])
        .expect("parse with empty AWS flags");
        let config = ServerConfig::from_args(args, None).expect("config builds");
        assert!(
            config.aws_region.is_none(),
            "empty CLI aws_region without IMDS must be None, got {:?}",
            config.aws_region
        );
        assert!(
            config.aws_az.is_none(),
            "empty CLI aws_az without IMDS must be None, got {:?}",
            config.aws_az
        );
        assert!(
            config.aws_partition.is_none(),
            "empty CLI aws_partition without IMDS must be None, got {:?}",
            config.aws_partition
        );
    }

    #[test]
    fn from_args_empty_s3_config_region_yields_none() {
        // `s3_config_region` feeds `aws_config_loader` directly (S3 config
        // loading and the doc-key KMS client), so an empty value must become
        // `None` for the same reason as `aws_region` above.
        let args = Args::try_parse_from(["vouch-server", "--s3-config-region="])
            .expect("parse with empty --s3-config-region");
        let config = ServerConfig::from_args(args, None).expect("config builds");
        assert!(
            config.s3_config_region.is_none(),
            "empty CLI s3_config_region must be None, got {:?}",
            config.s3_config_region
        );
    }

    #[test]
    fn from_args_empty_aws_use_fips_endpoint_yields_none() {
        // `aws_use_fips_endpoint` feeds `aws_config_loader`, where `Some(false)`
        // explicitly disables FIPS and overrides the AWS SDK's
        // `AWS_USE_FIPS_ENDPOINT` provider chain. An empty CLI value must become
        // `None` (matching the SDK's own `parse_bool`, which rejects `""` as
        // invalid and falls through to the next provider), NOT `Some(false)`.
        //
        // The env-var path (`AWS_USE_FIPS_ENDPOINT=""`) is not exercised here
        // because `std::env::set_var` is `unsafe` under edition 2024 and
        // `unsafe_code` is denied workspace-wide (see the note above the
        // "ServerConfig::from_args" section). Clap's `#[arg(env = ...)]`
        // resolution populates the same `Option<String>` field whether the
        // value came from the CLI or the environment, so this CLI case covers
        // both: in either path the field is `Some("")`, which the
        // `.filter(|s| !s.is_empty())` guard converts to `None`.
        let args = Args::try_parse_from(["vouch-server", "--aws-use-fips-endpoint="])
            .expect("parse with empty --aws-use-fips-endpoint");
        let config = ServerConfig::from_args(args, None).expect("config builds");
        assert!(
            config.aws_use_fips_endpoint.is_none(),
            "empty CLI aws_use_fips_endpoint must be None, got {:?}",
            config.aws_use_fips_endpoint
        );
    }

    // ========================================================================
    // ServerConfig::from_args — base_url trailing-slash normalization
    //
    // OIDC Discovery 1.0 §4.3 requires exact string equality between the
    // issuer used to fetch the discovery document and the `issuer` value
    // returned. A trailing slash on `VOUCH_BASE_URL` would otherwise produce
    // an issuer with a trailing slash and double-slash endpoint URLs
    // (`https://host//oauth/token`), breaking spec-compliant clients and
    // DPoP `htu` validation.
    // ========================================================================

    #[test]
    fn from_args_trims_single_trailing_slash_from_base_url() {
        let args = Args::try_parse_from(["vouch-server", "--base-url=https://auth.example.com/"])
            .expect("parse with trailing-slash base_url");
        let config = ServerConfig::from_args(args, None).expect("config builds");
        assert_eq!(
            config.base_url, "https://auth.example.com",
            "single trailing slash must be stripped from base_url"
        );
    }

    #[test]
    fn from_args_trims_multiple_trailing_slashes_from_base_url() {
        let args = Args::try_parse_from(["vouch-server", "--base-url=https://auth.example.com//"])
            .expect("parse with double trailing-slash base_url");
        let config = ServerConfig::from_args(args, None).expect("config builds");
        assert_eq!(
            config.base_url, "https://auth.example.com",
            "all trailing slashes must be stripped from base_url"
        );
    }

    #[test]
    fn from_args_preserves_base_url_without_trailing_slash() {
        let args = Args::try_parse_from(["vouch-server", "--base-url=https://auth.example.com"])
            .expect("parse with clean base_url");
        let config = ServerConfig::from_args(args, None).expect("config builds");
        assert_eq!(
            config.base_url, "https://auth.example.com",
            "base_url without trailing slash must be unchanged"
        );
    }

    #[test]
    fn from_args_derived_base_url_has_no_trailing_slash() {
        // When VOUCH_BASE_URL is unset, base_url is derived from rp_id and
        // must never carry a trailing slash.
        let args = Args::try_parse_from(["vouch-server", "--rp-id=auth.example.com"])
            .expect("parse with rp_id only");
        let config = ServerConfig::from_args(args, None).expect("config builds");
        assert_eq!(
            config.base_url, "https://auth.example.com",
            "derived base_url must not have a trailing slash"
        );
        assert!(
            !config.base_url.ends_with('/'),
            "derived base_url must never end with '/'"
        );
    }

    #[test]
    fn from_args_trailing_slash_does_not_produce_double_slash_endpoints() {
        // Regression: a trailing slash on base_url used to produce
        // `https://host//oauth/token` for discovery endpoints. Verify the
        // normalized base_url concatenates cleanly with a path segment.
        let args = Args::try_parse_from(["vouch-server", "--base-url=https://auth.example.com/"])
            .expect("parse with trailing-slash base_url");
        let config = ServerConfig::from_args(args, None).expect("config builds");
        let token_endpoint = format!("{}/oauth/token", config.base_url);
        assert_eq!(
            token_endpoint, "https://auth.example.com/oauth/token",
            "endpoint URLs must not contain double slashes"
        );
        assert!(
            !token_endpoint.contains("//oauth"),
            "no double-slash path component allowed in endpoints"
        );
    }

    // ========================================================================
    // resolve_dsql_endpoints
    // ========================================================================

    #[test]
    fn resolve_dsql_endpoints_prefers_az_over_region() {
        let mut endpoints = HashMap::new();
        endpoints.insert(
            "us-east-1a".to_string(),
            "postgres://az.example/postgres".to_string(),
        );
        endpoints.insert(
            "us-east-1".to_string(),
            "postgres://region.example/postgres".to_string(),
        );
        let resolved =
            resolve_dsql_endpoints(&endpoints, Some("us-east-1a"), Some("us-east-1")).unwrap();
        assert_eq!(resolved, "postgres://az.example/postgres");
    }

    #[test]
    fn resolve_dsql_endpoints_falls_back_to_region_when_az_not_in_map() {
        let mut endpoints = HashMap::new();
        endpoints.insert(
            "us-east-1".to_string(),
            "postgres://region.example/postgres".to_string(),
        );
        let resolved =
            resolve_dsql_endpoints(&endpoints, Some("us-east-1z"), Some("us-east-1")).unwrap();
        assert_eq!(resolved, "postgres://region.example/postgres");
    }

    #[test]
    fn resolve_dsql_endpoints_errors_when_neither_az_nor_region_set() {
        let mut endpoints = HashMap::new();
        endpoints.insert("us-east-1".to_string(), "postgres://x/postgres".to_string());
        let err = resolve_dsql_endpoints(&endpoints, None, None).unwrap_err();
        assert!(err.to_string().contains("aws_az"), "got: {err}");
    }

    #[test]
    fn resolve_dsql_endpoints_errors_when_location_not_in_map() {
        let mut endpoints = HashMap::new();
        endpoints.insert("us-east-1".to_string(), "postgres://x/postgres".to_string());
        let err = resolve_dsql_endpoints(&endpoints, None, Some("us-west-2")).unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    }
}
