// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DNS resolution helpers for domain-ownership verification.
//!
//! Used by the admin "additional domains" flow to confirm an organization
//! controls a domain before it participates in login matching. The TXT
//! record format is `_vouch-verification.<domain>` with the token issued
//! when the domain was added.

use std::time::Duration;

use anyhow::{Context, Result};
use hickory_resolver::Resolver;
use hickory_resolver::proto::rr::RData;

const TXT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Returns true if any TXT record at `_vouch-verification.<domain>` equals
/// the expected token.
///
/// Uses the system resolver. Records that contain multiple character-strings
/// (RFC 1035) are concatenated before comparison so admins can publish the
/// token in either single- or multi-string form.
///
/// # Errors
///
/// Returns an error if the resolver cannot be constructed or the lookup
/// fails with a non-NXDOMAIN error. NXDOMAIN is reported as "no matching
/// record" so callers can present a friendly message.
pub async fn verify_txt_record(domain: &str, expected_token: &str) -> Result<bool> {
    let query = format!("_vouch-verification.{domain}.");
    let resolver = Resolver::builder_tokio()
        .context("failed to read system DNS configuration")?
        .build()
        .context("failed to build DNS resolver")?;
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
        if buf == expected_token {
            return Ok(true);
        }
    }
    Ok(false)
}
