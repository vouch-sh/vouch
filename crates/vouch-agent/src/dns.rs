// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Initialize the process-wide DoH resolver from `~/.vouch/config.json` + env.
//!
//! Called once from `main.rs` before any HTTP traffic. Mirrors the CLI's
//! `vouch_cli::dns::init` so that the agent honors the same configuration.

use anyhow::{Context, Result};
use vouch_common::dns::{DOH_ENV_VAR, DohResolver, install_process_resolver, resolve_doh_config};

use crate::config::read_config;

/// Initialize the process-wide DoH resolver.
///
/// Hard-fails when DoH is explicitly enabled and the resolver cannot be
/// constructed.
///
/// # Errors
///
/// Returns an error if the configured provider is invalid or the resolver
/// cannot be built.
pub fn init() -> Result<()> {
    let env = std::env::var(DOH_ENV_VAR).ok();
    let config = read_config().ok().flatten();
    let cfg = resolve_doh_config(env.as_deref(), config.as_ref().and_then(|c| c.doh()))
        .context("invalid DNS-over-HTTPS configuration")?;

    // DNSSEC validation is on whenever DoH is on; see vouch_cli::dns::init.
    let resolver = DohResolver::for_config(&cfg, true).with_context(|| {
        format!(
            "failed to build DNS-over-HTTPS resolver for provider {}",
            cfg.label()
        )
    })?;

    if cfg.is_enabled() {
        tracing::info!(provider = %cfg.label(), dnssec = true, "DNS-over-HTTPS enabled");
    }

    install_process_resolver(cfg, resolver);
    Ok(())
}
