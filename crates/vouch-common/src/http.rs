// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP client configuration with appropriate timeouts.
//!
//! Provides pre-configured HTTP clients for different contexts, ensuring
//! consistent timeout behavior across the codebase.

use std::time::Duration;

use crate::dns::process_resolver;

/// Timeout values for different contexts.
pub mod timeouts {
    use super::Duration;

    /// Total timeout for credential helper operations.
    pub const CREDENTIAL_TOTAL: Duration = Duration::from_secs(10);
    /// Connection timeout for credential helper operations.
    pub const CREDENTIAL_CONNECT: Duration = Duration::from_secs(5);

    /// Total timeout for agent background operations.
    pub const AGENT_TOTAL: Duration = Duration::from_secs(5);
    /// Connection timeout for agent background operations.
    pub const AGENT_CONNECT: Duration = Duration::from_secs(3);

    /// Total timeout for server-side API calls.
    pub const SERVER_TOTAL: Duration = Duration::from_secs(15);
    /// Connection timeout for server-side API calls.
    pub const SERVER_CONNECT: Duration = Duration::from_secs(5);
    /// Idle gap allowed between reads on a server-side response body.
    ///
    /// [`SERVER_TOTAL`] already caps how long a hostile host can hold a
    /// connection, but it lets one that has gone silent sit on the slot for the
    /// full budget. This bounds the gap between frames instead, so a stalled
    /// peer is dropped promptly rather than at the total deadline — the outbound
    /// counterpart to refusing a client that dribbles a request.
    pub const SERVER_READ: Duration = Duration::from_secs(5);
}

/// Apply the process-wide DoH resolver to a builder, if one is installed.
///
/// Public so `vouch-cli` (which builds its own `reqwest::Client` for
/// authenticated CLI traffic) can route through the same helper as the
/// common factories below.
pub fn with_process_doh(mut builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    if let Some(resolver) = process_resolver() {
        builder = builder.dns_resolver(resolver);
    }
    builder
}

/// Create an HTTP client for credential helper operations.
///
/// Uses short timeouts (10s total, 5s connect) for fast failure.
/// Credential helpers are called by tools (aws, docker, gcloud) that have
/// their own retry logic.
///
/// Redirects are disabled: vouch and AWS endpoints don't redirect, and
/// allowing them could leak traffic over plain HTTP — undermining the
/// "TCP/443 only" property when DoH is enabled.
///
/// # Arguments
///
/// * `user_agent` - The User-Agent header value for outgoing requests.
///
/// # Errors
///
/// Returns an error if the client cannot be built.
pub fn credential_client(user_agent: &str) -> Result<reqwest::Client, reqwest::Error> {
    let builder = reqwest::Client::builder()
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeouts::CREDENTIAL_TOTAL)
        .connect_timeout(timeouts::CREDENTIAL_CONNECT);
    with_process_doh(builder).build()
}

/// Create an HTTP client for agent background operations.
///
/// Uses short timeouts (5s total, 3s connect) for best-effort,
/// non-blocking background work. Redirects disabled (see
/// [`credential_client`]).
///
/// # Arguments
///
/// * `user_agent` - The User-Agent header value for outgoing requests.
///
/// # Errors
///
/// Returns an error if the client cannot be built.
pub fn agent_client(user_agent: &str) -> Result<reqwest::Client, reqwest::Error> {
    let builder = reqwest::Client::builder()
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeouts::AGENT_TOTAL)
        .connect_timeout(timeouts::AGENT_CONNECT);
    with_process_doh(builder).build()
}

/// Create an HTTP client for server-side API calls.
///
/// Uses moderate timeouts (15s total, 5s connect) since external
/// APIs may be slower but we still want to fail reasonably fast.
/// Redirects are disabled to prevent SSRF attacks where an HTTPS
/// URL redirects to an internal HTTP endpoint.
///
/// Extra CA certificates can be provided to trust peers with
/// self-signed or private CA certs (e.g., conformance suite endpoints).
///
/// # Arguments
///
/// * `user_agent` - The User-Agent header value for outgoing requests.
/// * `extra_ca_certs` - Optional PEM-encoded CA certificates to trust.
///
/// # Errors
///
/// Returns an error if the client cannot be built or certs are invalid.
pub fn server_client(
    user_agent: &str,
    extra_ca_certs: Option<&[u8]>,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeouts::SERVER_TOTAL)
        .connect_timeout(timeouts::SERVER_CONNECT)
        .read_timeout(timeouts::SERVER_READ);

    if let Some(pem_data) = extra_ca_certs {
        let certs = reqwest::Certificate::from_pem_bundle(pem_data)
            .map_err(|e| anyhow::anyhow!("Invalid PEM in extra CA certs: {e}"))?;
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }

    Ok(with_process_doh(builder).build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_client_builds() {
        let client = credential_client("test-credential/1.0.0");
        assert!(client.is_ok());
    }

    #[test]
    fn test_agent_client_builds() {
        let client = agent_client("test-agent/1.0.0");
        assert!(client.is_ok());
    }

    #[test]
    fn test_server_client_builds() {
        let client = server_client("test-agent", None);
        assert!(client.is_ok());
    }

    #[test]
    fn test_timeout_values() {
        assert!(timeouts::CREDENTIAL_CONNECT < timeouts::CREDENTIAL_TOTAL);
        assert!(timeouts::AGENT_CONNECT < timeouts::AGENT_TOTAL);
        assert!(timeouts::SERVER_CONNECT < timeouts::SERVER_TOTAL);

        // Agent should be fastest
        assert!(timeouts::AGENT_TOTAL < timeouts::CREDENTIAL_TOTAL);
        assert!(timeouts::CREDENTIAL_TOTAL < timeouts::SERVER_TOTAL);
    }
}
