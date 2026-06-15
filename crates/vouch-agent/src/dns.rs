// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Initialize the process-wide DoH resolver from
//! `$XDG_CONFIG_HOME/vouch/config.json` + env.
//!
//! Called once from `main.rs` before any HTTP traffic. Mirrors the CLI's
//! `vouch_cli::dns::init` so that the agent honors the same configuration.

use anyhow::{Context, Result};

use crate::config::read_config;

/// Initialize the process-wide DoH resolver.
///
/// Hard-fails when DoH is explicitly enabled and the resolver cannot be
/// constructed.
///
/// # Errors
///
/// Returns an error if the configured provider is invalid.
pub fn init() -> Result<()> {
    let env = std::env::var(vouch_common::dns::DOH_ENV_VAR).ok();
    let config = read_config().ok().flatten();
    vouch_common::dns::init_from(env.as_deref(), config.as_ref().and_then(|c| c.doh()))
        .context("invalid DNS-over-HTTPS configuration")
}
