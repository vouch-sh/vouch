// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DNS resolution helpers for domain-ownership verification.
//!
//! Used by the admin "additional domains" flow to confirm an organization
//! controls a domain before it participates in login matching. The TXT
//! record format is `_vouch-verification.<domain>` with the token issued
//! when the domain was added.

use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_resolver::Resolver;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use subtle::ConstantTimeEq;

const TXT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Process-wide TXT-lookup resolver, built once from system DNS config.
///
/// Hickory reads `/etc/resolv.conf` and spins up background tasks at build
/// time; doing that on every `verify_txt_record` call burns file descriptors
/// and syscalls under the per-domain re-verification loop. Build it once and
/// reuse the handle.
///
/// The inner result is cached, so a transient resolv.conf parse failure at
/// startup stays cached for the life of the process — operators must restart
/// the server after fixing system DNS configuration. This trade matches how
/// the resolver is loaded elsewhere in the workspace (see vouch-common DoH).
static RESOLVER: LazyLock<std::result::Result<TokioResolver, String>> = LazyLock::new(|| {
    let builder = Resolver::builder_tokio()
        .map_err(|e| format!("failed to read system DNS configuration: {e}"))?;
    builder
        .build()
        .map_err(|e| format!("failed to build DNS resolver: {e}"))
});

fn resolver() -> Result<&'static TokioResolver> {
    RESOLVER.as_ref().map_err(|e| anyhow::anyhow!("{e}"))
}

/// Resolve a hostname to the IP addresses it currently maps to, using the
/// process-wide system resolver.
///
/// Used by the SSRF egress guard ([`crate::infra::ssrf`]) to vet
/// client-controlled fetch destinations before they are requested. The same
/// system resolver backs the server's `reqwest` client (no DoH override is
/// installed server-side), so the addresses returned here are the ones the
/// HTTP client will dial.
///
/// # Errors
///
/// Returns an error if the resolver is unavailable, the lookup fails, or the
/// lookup times out.
pub(crate) async fn resolve_host_ips(host: &str) -> Result<Vec<std::net::IpAddr>> {
    let resolver = resolver().context("DNS resolver unavailable")?;
    let lookup = match tokio::time::timeout(TXT_QUERY_TIMEOUT, resolver.lookup_ip(host)).await {
        Ok(Ok(l)) => l,
        Ok(Err(e)) => {
            return Err(anyhow::Error::from(e).context(format!("DNS lookup for {host} failed")));
        }
        Err(_) => anyhow::bail!("DNS lookup for {host} timed out after {TXT_QUERY_TIMEOUT:?}"),
    };
    Ok(lookup.iter().collect())
}

/// Returns true if any TXT record at `_vouch-verification.<domain>` equals
/// the expected token.
///
/// Uses the process-wide system resolver (see [`RESOLVER`]). Records that
/// contain multiple character-strings (RFC 1035) are concatenated before
/// comparison so admins can publish the token in either single- or
/// multi-string form.
///
/// # Errors
///
/// Returns an error if the resolver cannot be constructed or the lookup
/// fails with a non-NXDOMAIN error. NXDOMAIN is reported as "no matching
/// record" so callers can present a friendly message.
pub async fn verify_txt_record(domain: &str, expected_token: &str) -> Result<bool> {
    let query = format!("_vouch-verification.{domain}.");
    let resolver = resolver().context("DNS resolver unavailable")?;
    let lookup_fut = resolver.txt_lookup(query.as_str());
    let lookup = match tokio::time::timeout(TXT_QUERY_TIMEOUT, lookup_fut).await {
        Ok(Ok(l)) => l,
        Ok(Err(e)) => {
            if e.is_no_records_found() {
                return Ok(false);
            }
            return Err(anyhow::Error::from(e).context(format!("TXT lookup for {query} failed")));
        }
        Err(_) => anyhow::bail!("TXT lookup for {query} timed out after {TXT_QUERY_TIMEOUT:?}"),
    };

    let expected_bytes = expected_token.as_bytes();
    for record in lookup.answers() {
        let RData::TXT(ref txt) = record.data else {
            continue;
        };
        let mut buf = String::new();
        for chunk in txt.txt_data.iter() {
            if let Ok(s) = std::str::from_utf8(chunk) {
                buf.push_str(s);
            }
        }
        // Constant-time compare: the expected_token is the per-domain secret
        // an admin publishes in DNS. Length-aware ct_eq returns false on
        // mismatched lengths without leaking via early exit.
        if buf.as_bytes().ct_eq(expected_bytes).into() {
            return Ok(true);
        }
    }
    Ok(false)
}
