// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Initialize the process-wide DoH resolver from config + env.
//!
//! Called once from `main.rs` before any HTTP traffic. After this runs, every
//! reqwest client built via `vouch_common::http::*` or
//! `vouch_cli::http::ReqwestClient::new` automatically uses the configured
//! DoH resolver (or none, the default).

use anyhow::{Context, Result};

use crate::config::Config;

/// Initialize the process-wide DoH resolver.
///
/// Reads `VOUCH_DOH` first, then `network.dns_over_https` from the supplied
/// config (loaded once by the caller). Hard-fails when DoH is explicitly
/// enabled and the resolver cannot be constructed.
///
/// # Errors
///
/// Returns an error if the configured provider is invalid.
pub(crate) fn init(config: Option<&Config>) -> Result<()> {
    let env = std::env::var(vouch_common::dns::DOH_ENV_VAR).ok();
    vouch_common::dns::init_from(env.as_deref(), config.and_then(Config::doh))
        .context("invalid DNS-over-HTTPS configuration")
}
