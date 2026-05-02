// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DNS-over-HTTPS resolver for outbound HTTP clients.
//!
//! Provides a [`DohResolver`] that implements [`reqwest::dns::Resolve`] backed
//! by `hickory-resolver` configured for DoH against a chosen public provider
//! (Google, Cloudflare, Quad9) or a custom HTTPS endpoint.
//!
//! Opt-in via the `VOUCH_DOH` env var or the `network.dns_over_https` field in
//! `~/.vouch/config.json`. When unset, the system resolver is used (default
//! behavior).

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use hickory_resolver::Resolver;
use hickory_resolver::config::{CLOUDFLARE, GOOGLE, NameServerConfig, QUAD9, ResolverConfig};
use reqwest::dns::{Addrs, Name as ReqName, Resolve, Resolving};
use serde::{Deserialize, Serialize};

/// Environment variable consulted by [`process_resolver`] when no explicit
/// resolver has been installed.
pub const DOH_ENV_VAR: &str = "VOUCH_DOH";

/// DoH provider selection.
///
/// `Off` means use the system resolver (current default behavior). All other
/// variants route DNS over HTTPS to the named provider.
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
    /// User-specified DoH endpoint (must be `https://…/dns-query`).
    Custom(url::Url),
}

impl DohConfig {
    /// Parse a textual DoH selector.
    ///
    /// Accepts: `off`, `on` (== `google`), `google`, `cloudflare`, `quad9`,
    /// or any `https://…` URL.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown keyword or a non-HTTPS URL.
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
                if url.scheme() != "https" {
                    anyhow::bail!("DoH endpoint must use https://: {url}");
                }
                Ok(Self::Custom(url))
            }
        }
    }

    /// Returns true when DoH is active (anything other than `Off`).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Short human label for diagnostics (`vouch doctor`, log messages).
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Off => "off".to_string(),
            Self::Google => "google".to_string(),
            Self::Cloudflare => "cloudflare".to_string(),
            Self::Quad9 => "quad9".to_string(),
            Self::Custom(url) => url.to_string(),
        }
    }
}

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
    /// Returns an error if the textual form is not a known keyword or HTTPS URL.
    pub fn resolve(&self) -> Result<DohConfig> {
        match self {
            Self::Bool(true) => Ok(DohConfig::Google),
            Self::Bool(false) => Ok(DohConfig::Off),
            Self::Text(s) => DohConfig::parse(s),
        }
    }
}

/// Determine the effective [`DohConfig`] from the `VOUCH_DOH` env var falling
/// back to a config-file value.
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

/// reqwest-compatible DoH resolver backed by `hickory-resolver`.
pub struct DohResolver {
    inner: hickory_resolver::TokioResolver,
    label: String,
}

impl std::fmt::Debug for DohResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohResolver")
            .field("provider", &self.label)
            .finish_non_exhaustive()
    }
}

impl DohResolver {
    /// Build a resolver for the given configuration.
    ///
    /// Returns `Ok(None)` when `cfg` is [`DohConfig::Off`].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying resolver cannot be constructed
    /// (e.g., a malformed custom URL).
    pub fn for_config(cfg: &DohConfig) -> Result<Option<Arc<Self>>> {
        let resolver_config = match cfg {
            DohConfig::Off => return Ok(None),
            DohConfig::Google => ResolverConfig::https(&GOOGLE),
            DohConfig::Cloudflare => ResolverConfig::https(&CLOUDFLARE),
            DohConfig::Quad9 => ResolverConfig::https(&QUAD9),
            DohConfig::Custom(url) => custom_https_config(url)?,
        };
        let inner = Resolver::builder_with_config(resolver_config, Default::default())
            .build()
            .context("failed to construct DoH resolver")?;
        Ok(Some(Arc::new(Self {
            inner,
            label: cfg.label(),
        })))
    }

    /// Provider label used for diagnostics.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Process-wide DoH resolver slot.
///
/// Set once via [`install_process_resolver`] from the binary's startup path
/// (after loading the CLI/agent config) and read by every HTTP client
/// factory in this crate plus `vouch_cli::http::ReqwestClient::new`.
static PROCESS_RESOLVER: OnceLock<Option<Arc<DohResolver>>> = OnceLock::new();

/// Install the process-wide DoH resolver. Idempotent — subsequent calls are
/// silently ignored so that re-entry from tests doesn't panic.
///
/// The binary should call this once on startup from inside a tokio runtime
/// context — hickory's resolver spawns background tasks at construction.
/// HTTP client factories then pick up the installed resolver automatically.
pub fn install_process_resolver(resolver: Option<Arc<DohResolver>>) {
    drop(PROCESS_RESOLVER.set(resolver));
}

/// Resolver previously installed via [`install_process_resolver`].
///
/// If nothing has been installed yet, this falls back to the `VOUCH_DOH`
/// environment variable so that minimal/test contexts (no config file) still
/// honor the user's intent. Errors from env parsing or resolver construction
/// are silently treated as "no DoH" — the binary's startup path is the
/// loud failure mode.
#[must_use]
pub fn process_resolver() -> Option<Arc<DohResolver>> {
    if let Some(slot) = PROCESS_RESOLVER.get() {
        return slot.clone();
    }
    let env = std::env::var(DOH_ENV_VAR).ok();
    let cfg = resolve_doh_config(env.as_deref(), None).unwrap_or(DohConfig::Off);
    let resolver = DohResolver::for_config(&cfg).ok().flatten();
    drop(PROCESS_RESOLVER.set(resolver.clone()));
    resolver
}

/// Build a `ResolverConfig` for a user-supplied DoH endpoint URL.
///
/// The URL host must be a literal IP (so the resolver knows where to dial
/// without needing DNS first). Hostname-only custom endpoints would create a
/// chicken-and-egg bootstrap problem.
fn custom_https_config(url: &url::Url) -> Result<ResolverConfig> {
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
    let path = if url.path().is_empty() || url.path() == "/" {
        None
    } else {
        Some(Arc::from(url.path()))
    };
    let nsc = NameServerConfig::https(ip, server_name, path);
    Ok(ResolverConfig::from_parts(None, vec![], vec![nsc]))
}

impl Resolve for DohResolver {
    fn resolve(&self, name: ReqName) -> Resolving {
        let resolver = self.inner.clone();
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
    fn parse_custom_https_url() {
        let cfg = DohConfig::parse("https://1.1.1.1/dns-query").unwrap();
        match cfg {
            DohConfig::Custom(url) => assert_eq!(url.scheme(), "https"),
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
    fn is_enabled_only_when_not_off() {
        assert!(!DohConfig::Off.is_enabled());
        assert!(DohConfig::Google.is_enabled());
        assert!(DohConfig::Cloudflare.is_enabled());
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
        assert!(DohResolver::for_config(&DohConfig::Off).unwrap().is_none());
    }

    #[test]
    fn for_config_google_builds_resolver() {
        let r = DohResolver::for_config(&DohConfig::Google)
            .unwrap()
            .unwrap();
        assert_eq!(r.label(), "google");
    }

    #[test]
    fn custom_url_requires_ip_literal() {
        let cfg = DohConfig::Custom(url::Url::parse("https://dns.example/dns-query").unwrap());
        assert!(DohResolver::for_config(&cfg).is_err());
    }

    #[test]
    fn custom_url_with_ip_builds() {
        let cfg = DohConfig::Custom(url::Url::parse("https://1.1.1.1/dns-query").unwrap());
        let r = DohResolver::for_config(&cfg).unwrap().unwrap();
        assert_eq!(r.label(), "https://1.1.1.1/dns-query");
    }
}
