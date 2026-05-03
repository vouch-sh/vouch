// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DNS-over-HTTPS resolver for outbound HTTP clients.
//!
//! Provides a [`DohResolver`] that implements [`reqwest::dns::Resolve`] backed
//! by `hickory-resolver` configured for DoH against a chosen public provider
//! (Google, Cloudflare, Quad9) or a custom HTTPS endpoint.
//!
//! Opt-in via the `VOUCH_DOH` env var or the `network.dns_over_https` field in
//! `~/.vouch/config.json`. When unset, the system resolver is used.
//!
//! Both `vouch-cli` and `vouch-agent` install the process-wide state via
//! [`init_from`] before any HTTP client is constructed; [`process_resolver`]
//! then surfaces it to every reqwest client factory.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use hickory_resolver::Resolver;
use hickory_resolver::config::{CLOUDFLARE, GOOGLE, NameServerConfig, QUAD9, ResolverConfig};
use reqwest::dns::{Addrs, Name as ReqName, Resolve, Resolving};
use serde::{Deserialize, Serialize};

/// Environment variable consulted by [`init_from`].
pub const DOH_ENV_VAR: &str = "VOUCH_DOH";

// =============================================================================
// DohEndpoint — validated custom DoH URL
// =============================================================================

/// Validated custom DoH endpoint: an `https://` URL whose host is an IP
/// literal.
///
/// Hostname-only endpoints are rejected at construction because they would
/// require DNS to look up the DNS resolver — a chicken-and-egg bootstrap
/// problem. All preprocessing for hickory's [`NameServerConfig`] is done
/// once at construction, leaving downstream usage infallible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohEndpoint {
    url: url::Url,
    ip: std::net::IpAddr,
    server_name: Arc<str>,
    path: Option<Arc<str>>,
    /// Explicit non-default port from the URL, if any. `None` means the
    /// hickory default (443) is used.
    port: Option<u16>,
}

impl DohEndpoint {
    /// Construct from a URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the scheme is not `https://`, the URL has no
    /// host, or the host is not an IP literal.
    pub fn new(url: url::Url) -> Result<Self> {
        if url.scheme() != "https" {
            anyhow::bail!("DoH endpoint must use https://: {url}");
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("custom DoH URL has no host: {url}"))?;
        let ip: std::net::IpAddr = host.parse().with_context(|| {
            format!(
                "custom DoH URL must use an IP literal (got host={host:?}); \
                 hostnames create a DNS bootstrap problem"
            )
        })?;
        let server_name: Arc<str> = host.into();
        let path = match url.path() {
            "" | "/" => None,
            p => Some(Arc::from(p)),
        };
        let port = url.port();
        Ok(Self {
            url,
            ip,
            server_name,
            path,
            port,
        })
    }

    /// The validated URL.
    #[must_use]
    pub fn url(&self) -> &url::Url {
        &self.url
    }
}

// =============================================================================
// DohConfig — the parsed user choice
// =============================================================================

/// DoH provider selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DohConfig {
    /// Use the system resolver. No DoH.
    Off,
    /// Google Public DNS over HTTPS (default when DoH is enabled without a
    /// named provider).
    Google,
    /// Cloudflare 1.1.1.1 over HTTPS.
    Cloudflare,
    /// Quad9 9.9.9.9 over HTTPS.
    Quad9,
    /// User-specified DoH endpoint (validated at parse time).
    Custom(DohEndpoint),
}

impl DohConfig {
    /// Parse a textual DoH selector.
    ///
    /// Accepts: `off`, `on` (== `google`), `google`, `cloudflare`, `quad9`,
    /// or any `https://…` URL whose host is an IP literal.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown keyword, a non-HTTPS URL, or a custom
    /// URL whose host is not an IP literal.
    pub fn parse(value: &str) -> Result<Self> {
        let trimmed = value.trim();
        match trimmed.to_ascii_lowercase().as_str() {
            "" | "off" | "false" | "0" | "no" => Ok(Self::Off),
            "on" | "true" | "1" | "yes" | "google" => Ok(Self::Google),
            "cloudflare" => Ok(Self::Cloudflare),
            "quad9" => Ok(Self::Quad9),
            _ => {
                let url = url::Url::parse(trimmed)
                    .with_context(|| format!("invalid DoH provider: {trimmed:?}"))?;
                Ok(Self::Custom(DohEndpoint::new(url)?))
            }
        }
    }

    /// Returns true when DoH is active (anything other than `Off`).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Short human label for diagnostics (`vouch doctor`, log messages).
    ///
    /// Returns a borrow — static for the keyword variants, the URL string
    /// for `Custom`. No allocation.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Off => "off",
            Self::Google => "google",
            Self::Cloudflare => "cloudflare",
            Self::Quad9 => "quad9",
            Self::Custom(endpoint) => endpoint.url.as_str(),
        }
    }
}

// =============================================================================
// DohConfigSerde — config-file representation
// =============================================================================

/// Serializable form for `~/.vouch/config.json`. Accepts a string keyword,
/// a URL, or a bare boolean (`true` -> Google, `false` -> Off).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DohConfigSerde {
    /// Boolean shortcut: `true` = Google DoH, `false` = system resolver.
    Bool(bool),
    /// String keyword (`off`, `google`, `cloudflare`, `quad9`) or a custom
    /// `https://…/dns-query` URL.
    Text(String),
}

impl DohConfigSerde {
    /// Resolve to a concrete [`DohConfig`].
    ///
    /// # Errors
    ///
    /// Returns an error if the textual form is not a known keyword or a
    /// valid custom URL.
    pub fn resolve(&self) -> Result<DohConfig> {
        match self {
            Self::Bool(true) => Ok(DohConfig::Google),
            Self::Bool(false) => Ok(DohConfig::Off),
            Self::Text(s) => DohConfig::parse(s),
        }
    }
}

// =============================================================================
// NetworkConfig — shared deserialization shape for CLI/agent config files
// =============================================================================

/// Global network options for the vouch CLI/agent configuration files.
///
/// Lives here so both `vouch-cli` and `vouch-agent` deserialize the same
/// `network` section without divergent definitions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// DNS-over-HTTPS provider. Accepts a boolean (`true` = Google, `false`
    /// = off), a keyword (`off`, `google`, `cloudflare`, `quad9`), or a
    /// custom `https://…/dns-query` URL. Overridden at runtime by the
    /// `VOUCH_DOH` environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_over_https: Option<DohConfigSerde>,
}

impl NetworkConfig {
    /// Configured DoH provider, if any.
    #[must_use]
    pub fn doh(&self) -> Option<&DohConfigSerde> {
        self.dns_over_https.as_ref()
    }
}

// =============================================================================
// Precedence
// =============================================================================

/// Determine the effective [`DohConfig`] from the `VOUCH_DOH` env var
/// falling back to a config-file value.
///
/// Env wins over config; config wins over the `Off` default.
///
/// # Errors
///
/// Returns an error if either source is malformed.
pub fn resolve_doh_config(
    env_value: Option<&str>,
    config_value: Option<&DohConfigSerde>,
) -> Result<DohConfig> {
    if let Some(raw) = env_value {
        return DohConfig::parse(raw);
    }
    if let Some(serde_value) = config_value {
        return serde_value.resolve();
    }
    Ok(DohConfig::Off)
}

// =============================================================================
// DohResolver — reqwest-compatible DoH resolver
// =============================================================================

/// reqwest-compatible DoH resolver backed by `hickory-resolver`.
///
/// The underlying `TokioResolver` is built lazily on the first DNS query so
/// that [`for_config`](Self::for_config) can be called from any context
/// (including outside a tokio runtime). Hickory spawns background tasks at
/// construction; building inside `resolve()` guarantees `Handle::current()`
/// is available.
pub struct DohResolver {
    config: ResolverConfig,
    label: String,
    // FIXME: replace with `OnceLock::get_or_try_init` once stable
    // (rust-lang/rust#109737). Until then we stringify the build error so
    // every subsequent caller sees the same message.
    inner: OnceLock<Result<hickory_resolver::TokioResolver, String>>,
}

impl std::fmt::Debug for DohResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohResolver")
            .field("provider", &self.label)
            .field("initialized", &self.inner.get().is_some())
            .finish_non_exhaustive()
    }
}

impl DohResolver {
    /// Build a resolver for the given configuration.
    ///
    /// Returns `None` when `cfg` is [`DohConfig::Off`]. DNSSEC validation is
    /// always enabled when DoH is enabled: signed responses must validate or
    /// the lookup fails; unsigned zones (e.g. `*.amazonaws.com`) pass
    /// through unchanged.
    ///
    /// The hickory resolver is built lazily on first use, so this is safe
    /// to call outside a tokio runtime context.
    #[must_use]
    pub fn for_config(cfg: &DohConfig) -> Option<Arc<Self>> {
        let config = match cfg {
            DohConfig::Off => return None,
            DohConfig::Google => ResolverConfig::https(&GOOGLE),
            DohConfig::Cloudflare => ResolverConfig::https(&CLOUDFLARE),
            DohConfig::Quad9 => ResolverConfig::https(&QUAD9),
            DohConfig::Custom(endpoint) => custom_https_config(endpoint),
        };
        Some(Arc::new(Self {
            config,
            label: cfg.label().to_string(),
            inner: OnceLock::new(),
        }))
    }

    /// Provider label used for diagnostics.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Get (or lazily construct) the underlying hickory resolver.
    ///
    /// Must be called from within a tokio runtime context — hickory spawns
    /// background tasks at construction.
    fn get_or_init(&self) -> Result<&hickory_resolver::TokioResolver> {
        self.inner
            .get_or_init(|| {
                let mut builder =
                    Resolver::builder_with_config(self.config.clone(), Default::default());
                builder.options_mut().validate = true;
                builder
                    .build()
                    .map_err(|e| format!("failed to construct DoH resolver: {e}"))
            })
            .as_ref()
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Perform a DNS lookup through the DoH resolver.
    ///
    /// Used by `vouch doctor` to verify that DoH is working end-to-end.
    /// Must be called from within a tokio runtime context.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails (network error, NXDOMAIN, …).
    pub async fn lookup_ip(&self, host: &str) -> Result<Vec<std::net::IpAddr>> {
        let resolver = self.get_or_init()?;
        let lookup = resolver
            .lookup_ip(host)
            .await
            .with_context(|| format!("DoH lookup for {host:?} failed"))?;
        Ok(lookup.iter().collect())
    }
}

// =============================================================================
// Process-wide state
// =============================================================================

/// Process-wide DoH state.
///
/// Set once via [`install_process_resolver`] (typically from
/// [`init_from`]) at the binary's startup path, read by every HTTP client
/// factory in this crate plus `vouch_cli::http::ReqwestClient::new`. The
/// resolver itself is built lazily on first use, so installation is safe
/// outside a tokio runtime.
struct ProcessState {
    config: DohConfig,
    resolver: Option<Arc<DohResolver>>,
}

static PROCESS_STATE: OnceLock<ProcessState> = OnceLock::new();

/// Install the process-wide DoH state.
///
/// **First call wins; subsequent calls are silently ignored** — there is no
/// error and the state is not replaced. This makes re-entry from tests safe
/// and means binaries should call [`init_from`] exactly once before any
/// HTTP client is constructed.
pub fn install_process_resolver(cfg: DohConfig, resolver: Option<Arc<DohResolver>>) {
    drop(PROCESS_STATE.set(ProcessState {
        config: cfg,
        resolver,
    }));
}

/// Resolver previously installed via [`install_process_resolver`].
///
/// Returns `None` if nothing has been installed or if the installed
/// configuration was [`DohConfig::Off`]. There is intentionally no env-var
/// fallback here — [`init_from`] is the single canonical entry point so
/// that env and config-file precedence cannot disagree.
#[must_use]
pub fn process_resolver() -> Option<Arc<DohResolver>> {
    PROCESS_STATE.get().and_then(|s| s.resolver.clone())
}

/// Effective [`DohConfig`] for the current process (for diagnostics).
///
/// Returns `Off` if no resolver has been installed.
#[must_use]
pub fn process_config() -> DohConfig {
    PROCESS_STATE
        .get()
        .map_or(DohConfig::Off, |s| s.config.clone())
}

/// Single canonical init path for both `vouch-cli` and `vouch-agent`.
///
/// Reads `VOUCH_DOH` (env wins), then the supplied config-file value, and
/// installs the process-wide resolver. **Hard-fails** if a DoH provider is
/// configured but the resolver cannot be constructed — silent fallback to
/// the system resolver would defeat opt-in.
///
/// Idempotent in the same way as [`install_process_resolver`]: subsequent
/// calls have no effect.
///
/// # Errors
///
/// Returns an error if the configured provider is invalid.
pub fn init_from(env: Option<&str>, config: Option<&DohConfigSerde>) -> Result<()> {
    let cfg = resolve_doh_config(env, config).context("invalid DNS-over-HTTPS configuration")?;
    let resolver = DohResolver::for_config(&cfg);
    if cfg.is_enabled() {
        tracing::info!(provider = %cfg.label(), dnssec = true, "DNS-over-HTTPS enabled");
    }
    install_process_resolver(cfg, resolver);
    Ok(())
}

// =============================================================================
// Custom URL → ResolverConfig
// =============================================================================

/// Build a `ResolverConfig` from a [`DohEndpoint`]. Infallible — all
/// validation happened at construction time.
fn custom_https_config(endpoint: &DohEndpoint) -> ResolverConfig {
    let mut nsc = NameServerConfig::https(
        endpoint.ip,
        endpoint.server_name.clone(),
        endpoint.path.clone(),
    );
    // `NameServerConfig::https` defaults to 443. Apply the URL's port only
    // when the user wrote a non-default port — `Url::port` returns `Some`
    // only in that case — otherwise `https://1.1.1.1:8443/dns-query` would
    // silently connect to 443.
    if let Some(port) = endpoint.port
        && let Some(connection) = nsc.connections.first_mut()
    {
        connection.port = port;
    }
    ResolverConfig::from_parts(None, vec![], vec![nsc])
}

// =============================================================================
// reqwest::dns::Resolve
// =============================================================================

impl Resolve for DohResolver {
    fn resolve(&self, name: ReqName) -> Resolving {
        // `get_or_init` runs the build closure inside the async context of
        // the first request — guarantees `Handle::current()` is available.
        let resolver = match self.get_or_init() {
            Ok(r) => r.clone(),
            Err(e) => {
                let msg = e.to_string();
                return Box::pin(async move { Err(Box::new(std::io::Error::other(msg)).into()) });
            }
        };
        let host = name.as_str().to_string();
        Box::pin(async move {
            let lookup = resolver.lookup_ip(host.as_str()).await.map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::other(format!(
                        "DoH lookup for {host:?} failed: {e}"
                    )))
                },
            )?;
            let v: Vec<SocketAddr> = lookup.iter().map(|ip| SocketAddr::new(ip, 0)).collect();
            let addrs: Addrs = Box::new(v.into_iter());
            Ok(addrs)
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_off_keywords() {
        for s in ["off", "OFF", "false", "0", "no", ""] {
            assert_eq!(DohConfig::parse(s).unwrap(), DohConfig::Off, "input={s:?}");
        }
    }

    #[test]
    fn parse_provider_keywords() {
        assert_eq!(DohConfig::parse("on").unwrap(), DohConfig::Google);
        assert_eq!(DohConfig::parse("google").unwrap(), DohConfig::Google);
        assert_eq!(DohConfig::parse("Google").unwrap(), DohConfig::Google);
        assert_eq!(
            DohConfig::parse("cloudflare").unwrap(),
            DohConfig::Cloudflare
        );
        assert_eq!(DohConfig::parse("quad9").unwrap(), DohConfig::Quad9);
    }

    #[test]
    fn parse_custom_https_url_with_ip() {
        let cfg = DohConfig::parse("https://1.1.1.1/dns-query").unwrap();
        match cfg {
            DohConfig::Custom(endpoint) => {
                assert_eq!(endpoint.url().scheme(), "https");
                assert_eq!(endpoint.url().as_str(), "https://1.1.1.1/dns-query");
            }
            other => panic!("expected Custom, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_non_https() {
        assert!(DohConfig::parse("http://1.1.1.1/dns-query").is_err());
    }

    #[test]
    fn parse_rejects_unknown_keyword() {
        assert!(DohConfig::parse("nonsense").is_err());
    }

    #[test]
    fn parse_rejects_hostname_in_custom_url() {
        // Hostname-only custom endpoints would create a DNS bootstrap
        // problem; rejected at construction.
        let err = DohConfig::parse("https://dns.example/dns-query").unwrap_err();
        assert!(
            err.to_string().contains("IP literal"),
            "expected IP-literal complaint, got: {err}"
        );
    }

    #[test]
    fn doh_endpoint_new_requires_https_scheme() {
        let url = url::Url::parse("http://1.1.1.1/dns-query").unwrap();
        assert!(DohEndpoint::new(url).is_err());
    }

    #[test]
    fn doh_endpoint_new_requires_ip_literal() {
        let url = url::Url::parse("https://dns.example/dns-query").unwrap();
        assert!(DohEndpoint::new(url).is_err());
    }

    #[test]
    fn is_enabled_only_when_not_off() {
        assert!(!DohConfig::Off.is_enabled());
        assert!(DohConfig::Google.is_enabled());
        assert!(DohConfig::Cloudflare.is_enabled());
    }

    #[test]
    fn label_returns_static_for_keyword_variants() {
        assert_eq!(DohConfig::Off.label(), "off");
        assert_eq!(DohConfig::Google.label(), "google");
        assert_eq!(DohConfig::Cloudflare.label(), "cloudflare");
        assert_eq!(DohConfig::Quad9.label(), "quad9");
    }

    #[test]
    fn label_returns_url_for_custom_variant() {
        let cfg = DohConfig::parse("https://1.1.1.1/dns-query").unwrap();
        assert_eq!(cfg.label(), "https://1.1.1.1/dns-query");
    }

    #[test]
    fn serde_bool_resolves_to_google() {
        assert_eq!(
            DohConfigSerde::Bool(true).resolve().unwrap(),
            DohConfig::Google
        );
        assert_eq!(
            DohConfigSerde::Bool(false).resolve().unwrap(),
            DohConfig::Off
        );
    }

    #[test]
    fn serde_text_dispatches_to_parse() {
        assert_eq!(
            DohConfigSerde::Text("cloudflare".into()).resolve().unwrap(),
            DohConfig::Cloudflare
        );
    }

    #[test]
    fn precedence_env_wins_over_config() {
        let cfg = DohConfigSerde::Text("cloudflare".into());
        let resolved = resolve_doh_config(Some("quad9"), Some(&cfg)).unwrap();
        assert_eq!(resolved, DohConfig::Quad9);
    }

    #[test]
    fn precedence_config_used_when_env_absent() {
        let cfg = DohConfigSerde::Text("cloudflare".into());
        let resolved = resolve_doh_config(None, Some(&cfg)).unwrap();
        assert_eq!(resolved, DohConfig::Cloudflare);
    }

    #[test]
    fn precedence_default_off() {
        assert_eq!(resolve_doh_config(None, None).unwrap(), DohConfig::Off);
    }

    #[test]
    fn for_config_off_returns_none() {
        assert!(DohResolver::for_config(&DohConfig::Off).is_none());
    }

    #[test]
    fn for_config_google_builds_resolver() {
        let r = DohResolver::for_config(&DohConfig::Google).unwrap();
        assert_eq!(r.label(), "google");
    }

    #[test]
    fn for_config_custom_with_ip_builds() {
        let cfg = DohConfig::parse("https://1.1.1.1/dns-query").unwrap();
        let r = DohResolver::for_config(&cfg).unwrap();
        assert_eq!(r.label(), "https://1.1.1.1/dns-query");
    }

    #[test]
    fn custom_endpoint_preserves_non_default_port() {
        let endpoint =
            DohEndpoint::new(url::Url::parse("https://1.1.1.1:8443/dns-query").unwrap()).unwrap();
        let cfg = custom_https_config(&endpoint);
        let port = cfg
            .name_servers()
            .first()
            .and_then(|ns| ns.connections.first())
            .map(|c| c.port);
        assert_eq!(port, Some(8443));
    }

    #[test]
    fn custom_endpoint_default_port_is_443() {
        let endpoint =
            DohEndpoint::new(url::Url::parse("https://1.1.1.1/dns-query").unwrap()).unwrap();
        let cfg = custom_https_config(&endpoint);
        let port = cfg
            .name_servers()
            .first()
            .and_then(|ns| ns.connections.first())
            .map(|c| c.port);
        assert_eq!(port, Some(443));
    }

    #[test]
    fn network_config_doh_accessor() {
        let nc = NetworkConfig::default();
        assert!(nc.doh().is_none());

        let nc = NetworkConfig {
            dns_over_https: Some(DohConfigSerde::Text("cloudflare".into())),
        };
        assert!(matches!(nc.doh(), Some(DohConfigSerde::Text(_))));
    }

    #[test]
    fn network_config_deserializes_from_json() {
        // Boolean shortcut.
        let nc: NetworkConfig = serde_json::from_str(r#"{"dns_over_https": true}"#).unwrap();
        assert!(matches!(
            nc.dns_over_https,
            Some(DohConfigSerde::Bool(true))
        ));

        // Text keyword.
        let nc: NetworkConfig = serde_json::from_str(r#"{"dns_over_https": "quad9"}"#).unwrap();
        assert!(matches!(
            nc.dns_over_https,
            Some(DohConfigSerde::Text(ref s)) if s == "quad9"
        ));

        // Empty object — DoH unset.
        let nc: NetworkConfig = serde_json::from_str("{}").unwrap();
        assert!(nc.dns_over_https.is_none());
    }
}
