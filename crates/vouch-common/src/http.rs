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
    ///
    /// Shorter than [`CREDENTIAL_TOTAL`]: the CLI waits on the server, which
    /// waits on this call, so a slow upstream must fail on the server in time
    /// for the CLI to receive the server's error rather than its own timeout.
    pub const SERVER_TOTAL: Duration = Duration::from_secs(5);
    /// Connection timeout for server-side API calls.
    pub const SERVER_CONNECT: Duration = Duration::from_secs(3);
    /// Idle gap allowed between reads on a server-side response body.
    ///
    /// [`SERVER_TOTAL`] already caps how long a hostile host can hold a
    /// connection, but it lets one that has gone silent sit on the slot for the
    /// full budget. This bounds the gap between frames instead, so a stalled
    /// peer is dropped promptly rather than at the total deadline — the outbound
    /// counterpart to refusing a client that dribbles a request.
    pub const SERVER_READ: Duration = Duration::from_secs(3);

    /// Per-call total timeout for outbound IdP calls made by the OIDC
    /// enrollment callback (`GET /oauth/callback`): the token-exchange POST
    /// and the IdP JWKS fetch for ID-token verification.
    ///
    /// Restores the pre-`94991ed6` per-call budget: that commit lowered
    /// [`SERVER_TOTAL`] 15s→5s (and [`SERVER_READ`] 5s→3s), and the enrollment
    /// callback relies on the shared [`server_client`] (which inherits both).
    /// A self-hosted IdP (Keycloak, Dex, Authentik) under load can return a
    /// token in the 5–15s band that the 5s total rejects; a token endpoint
    /// that takes 5–15s to send the *head* is cut even earlier, at the 3s
    /// [`SERVER_READ`]. The callback is browser-initiated (the CLI polls a
    /// separate device-flow endpoint on a minutes-scale `expires_in`), so the
    /// `SERVER_TOTAL < CREDENTIAL_TOTAL` layering rationale does not tightly
    /// bind this per-call budget. [`enroll_idp_client`] uses this total as its
    /// client default; per-request `.timeout()` overrides on the two calls
    /// fit inside it (15s token exchange, 5s JWKS fetch).
    pub const ENROLL_IDP_TOTAL: Duration = Duration::from_secs(15);
    /// Connection timeout for the enrollment callback's outbound IdP calls.
    ///
    /// Matches [`SERVER_CONNECT`]: the TCP+TLS handshake to the operator's
    /// configured IdP should still be fast; only the token computation is
    /// allowed to be slow.
    pub const ENROLL_IDP_CONNECT: Duration = Duration::from_secs(3);
    /// Idle gap allowed between reads on an enrollment-callback IdP response.
    ///
    /// Widened from [`SERVER_READ`] (3s) to 15s so a token endpoint that takes
    /// 5–15s to send the *head* (the natural "slow IdP under load" shape —
    /// the IdP computes the token, then sends head and body together) is not
    /// cut at 3s. `reqwest`'s per-request `.timeout()` only overrides the
    /// *total*, not `read_timeout`, so widening the total alone (as a
    /// per-request override on the shared `server_client`) does not help —
    /// the client-level `read_timeout` still fires mid-head. This dedicated
    /// client is the only lever. The 15s value matches [`ENROLL_IDP_TOTAL`]:
    /// a head that arrives just inside the total is admitted, and a body
    /// that then stalls is still capped by the per-request total (15s for the
    /// token exchange, 5s for the JWKS fetch).
    pub const ENROLL_IDP_READ: Duration = Duration::from_secs(15);
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
/// Uses short timeouts (5s total, 3s connect) so a slow upstream fails
/// well inside the server's request timeout, and the caller gets the
/// upstream error rather than a 408.
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

/// Create an HTTP client for the OIDC enrollment callback's outbound IdP
/// calls (token-exchange POST + IdP JWKS fetch).
///
/// A separate client from [`server_client`] because the enrollment callback
/// legitimately outlives a single server-side API call: a self-hosted IdP
/// (Keycloak, Dex, Authentik) under load can take 5–15s to return a token, a
/// band the shared `server_client`'s 5s [`timeouts::SERVER_TOTAL`] / 3s
/// [`timeouts::SERVER_READ`] rejects. The read gap is widened to
/// [`timeouts::ENROLL_IDP_READ`] (15s) because `reqwest` exposes no per-request
/// `read_timeout` override — a per-request `.timeout()` on the shared
/// `server_client` would widen the *total* but leave the 3s read gap firing
/// mid-head. The total stays per-call sized
/// ([`timeouts::ENROLL_IDP_TOTAL`], 15s); per-request `.timeout()` overrides
/// on the two calls fit inside it (15s token exchange, 5s JWKS fetch) and are
/// the bounds the route's `ENROLL_CALLBACK_TIMEOUT` (20s) admits. Connect
/// stays tight ([`timeouts::ENROLL_IDP_CONNECT`], 3s): the IdP's TCP+TLS
/// handshake should still be fast; only the token computation is allowed to
/// be slow. Redirects disabled and extra CA certs honored for the same
/// reasons as [`server_client`].
///
/// # Arguments
///
/// * `user_agent` - The User-Agent header value for outgoing requests.
/// * `extra_ca_certs` - Optional PEM-encoded CA certificates to trust.
///
/// # Errors
///
/// Returns an error if the client cannot be built or certs are invalid.
pub fn enroll_idp_client(
    user_agent: &str,
    extra_ca_certs: Option<&[u8]>,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeouts::ENROLL_IDP_TOTAL)
        .connect_timeout(timeouts::ENROLL_IDP_CONNECT)
        .read_timeout(timeouts::ENROLL_IDP_READ);

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
    fn test_enroll_idp_client_builds() {
        let client = enroll_idp_client("test-enroll-idp/1.0.0", None);
        assert!(client.is_ok());
    }

    #[test]
    fn test_timeout_values() {
        assert!(timeouts::CREDENTIAL_CONNECT < timeouts::CREDENTIAL_TOTAL);
        assert!(timeouts::AGENT_CONNECT < timeouts::AGENT_TOTAL);
        assert!(timeouts::SERVER_CONNECT < timeouts::SERVER_TOTAL);

        assert!(timeouts::SERVER_READ < timeouts::SERVER_TOTAL);

        // Agent should be fastest
        assert!(timeouts::AGENT_TOTAL < timeouts::CREDENTIAL_TOTAL);
        // The server's upstream calls finish before the CLI stops waiting.
        assert!(timeouts::SERVER_TOTAL < timeouts::CREDENTIAL_TOTAL);

        // The enrollment callback's outbound IdP calls get a wider per-call
        // budget than the shared server client: a self-hosted IdP under load
        // can take 5–15s to return a token, a band the 5s `SERVER_TOTAL`
        // rejects. Regression for `94991ed6` (which lowered SERVER_TOTAL 15s→5s
        // and SERVER_READ 5s→3s).
        assert!(timeouts::ENROLL_IDP_TOTAL > timeouts::SERVER_TOTAL);
        assert!(timeouts::ENROLL_IDP_READ > timeouts::SERVER_READ);
        assert!(timeouts::ENROLL_IDP_CONNECT == timeouts::SERVER_CONNECT);
        // The widened read gap must not exceed the total — the per-request
        // `.timeout()` (15s token / 5s JWKS) is what caps the call, and a head
        // admitted under the read gap fits under the total too.
        assert!(timeouts::ENROLL_IDP_READ <= timeouts::ENROLL_IDP_TOTAL);
        assert_eq!(timeouts::ENROLL_IDP_TOTAL, Duration::from_secs(15));
        assert_eq!(timeouts::ENROLL_IDP_READ, Duration::from_secs(15));
        assert_eq!(timeouts::ENROLL_IDP_CONNECT, Duration::from_secs(3));
    }
}
