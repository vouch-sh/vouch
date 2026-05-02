// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Initialize the process-wide DoH resolver from config + env.
//!
//! Called once from `main.rs` before any HTTP traffic. After this runs, every
//! reqwest client built via `vouch_common::http::*` or
//! `vouch_cli::http::ReqwestClient::new` automatically uses the configured
//! DoH resolver (or none, the default).

use anyhow::{Context, Result};
use vouch_common::dns::{DOH_ENV_VAR, DohResolver, install_process_resolver, resolve_doh_config};

use crate::config::Config;

/// Initialize the process-wide DoH resolver.
///
/// Reads `VOUCH_DOH` first, then `network.dns_over_https` from
/// `~/.vouch/config.json`. Defaults to `Off`. **Hard-fails** when DoH is
/// explicitly enabled and the resolver cannot be constructed — silent
/// fallback would defeat the security intent of opting in.
///
/// # Errors
///
/// Returns an error if the configured provider is invalid or the resolver
/// cannot be built.
pub(crate) fn init() -> Result<()> {
    let env = std::env::var(DOH_ENV_VAR).ok();
    let config = Config::load().ok();
    let cfg = resolve_doh_config(env.as_deref(), config.as_ref().and_then(Config::doh))
        .context("invalid DNS-over-HTTPS configuration")?;

    let resolver = DohResolver::for_config(&cfg).with_context(|| {
        format!(
            "failed to build DNS-over-HTTPS resolver for provider {}",
            cfg.label()
        )
    })?;

    if cfg.is_enabled() {
        tracing::debug!(provider = %cfg.label(), "DNS-over-HTTPS enabled");
    }

    install_process_resolver(cfg, resolver);
    Ok(())
}
