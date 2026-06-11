// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSRF egress guard for server-side fetches of client-controlled URLs.
//!
//! OAuth clients can register a `jwks_uri` (RFC 7517 / RFC 7591) and supply a
//! JAR `request_uri` (RFC 9101), both of which the server fetches
//! **server-side** — `jwks_uri` while *verifying* a `private_key_jwt`
//! assertion, i.e. before client authentication has even succeeded. Dynamic
//! client registration (`POST /oauth/register`) is unauthenticated, so without
//! an egress policy an anonymous caller could coerce the server into requesting
//! arbitrary internal addresses (link-local metadata endpoints, RFC 1918
//! services, loopback). HTTPS-only enforcement does not help: `https://[::1]`
//! and `https://169.254.169.254` are valid HTTPS URLs.
//!
//! [`assert_public_destination`] vets a URL immediately before it is fetched.
//! It parses the host and — resolving hostnames through the same system
//! resolver the server's `reqwest` client uses — rejects any destination that
//! maps to a non-global address. Combined with the existing HTTPS requirement
//! and `redirect(Policy::none())`, this closes the private-network reach.
//!
//! This guard is intentionally scoped to **client-controlled** fetches. The
//! operator-configured upstream-IdP discovery fetch
//! (`services::idp::oidc::fetch_discovery`) is deliberately *not* gated here:
//! it is trusted operator input and may legitimately target a private/internal
//! IdP, and it keeps its own loopback-for-development allowance.

use std::net::IpAddr;

use url::Host;

use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};

/// Returns `true` for IP addresses that must never be the target of a
/// server-side fetch of a client-controlled URL: loopback, RFC 1918 private,
/// link-local, CGNAT, IETF-protocol, 6to4-relay, benchmarking, documentation,
/// multicast, broadcast, unspecified, ULA, and other non-globally-routable
/// ranges.
///
/// Callers should pass a [canonicalised](IpAddr::to_canonical) address so an
/// IPv4-mapped IPv6 address such as `::ffff:127.0.0.1` is classified as the
/// underlying IPv4 loopback rather than slipping through the IPv6 checks.
pub(crate) fn is_non_global(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _d] = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || v4.is_multicast()
                || (a == 100 && (b & 0xC0 == 64)) // CGNAT 100.64.0.0/10
                || (a == 192 && b == 0 && c == 0) // IETF protocol 192.0.0.0/24
                || (a == 192 && b == 88 && c == 99) // 6to4 relay anycast 192.88.99.0/24
                || (a == 198 && (b & 0xFE == 18)) // benchmarking 198.18.0.0/15
                || (a & 0xF0 == 240) // reserved 240.0.0.0/4
        }
        IpAddr::V6(v6) => {
            let [o0, o1, o2, o3, o4, o5, o6, o7, ..] = v6.octets();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (o0 & 0xfe == 0xfc) // ULA fc00::/7
                || (o0 == 0xfe && o1 & 0xc0 == 0x80) // link-local fe80::/10
                || (o0 == 0x20 && o1 == 0x01 && o2 == 0x0d && o3 == 0xb8) // doc 2001:db8::/32
                || (o0 == 0x20 && o1 == 0x01 && o2 == 0x00 && o3 == 0x02) // benchmarking 2001:2::/48
                || (o0 == 0x01
                    && o1 == 0x00
                    && o2 == 0x00
                    && o3 == 0x00
                    && o4 == 0x00
                    && o5 == 0x00
                    && o6 == 0x00
                    && o7 == 0x00) // discard-only 100::/64
        }
    }
}

/// Reject a URL whose host is — or resolves to — a non-global address.
///
/// Call this immediately before fetching a client-controlled URL. The host is
/// resolved through the process-wide system resolver (the same path the
/// server's `reqwest` client uses, since no DoH override is installed
/// server-side), so the addresses vetted here are the ones the HTTP client
/// will dial. If a hostname has multiple A/AAAA records, **all** are checked
/// and any non-global address rejects the URL.
///
/// `allow_loopback` permits loopback destinations (`127.0.0.0/8`, `::1`,
/// `localhost`) for local development and testing — wired from
/// `!ServerConfig::tls_configured()`, matching the WebAuthn
/// `allow_localhost_origin` relaxation. It only relaxes **loopback**: private,
/// link-local, CGNAT and other internal ranges (e.g. the `169.254.169.254`
/// cloud metadata endpoint) stay blocked even in development.
///
/// `code` is the OAuth error code surfaced to the caller — the JWKS path uses
/// `invalid_client`, the JAR `request_uri` path uses `invalid_request_uri`.
///
/// # Errors
///
/// Returns an OAuth error if the URL is unparseable, has no host, fails to
/// resolve, or resolves to a blocked address.
pub(crate) async fn assert_public_destination(
    url: &str,
    allow_loopback: bool,
    code: OAuthErrorCode,
) -> ServiceResult<()> {
    let parsed = url::Url::parse(url)
        .map_err(|_| ServiceError::oauth(code, "destination URL is not parseable"))?;

    match parsed.host() {
        Some(Host::Ipv4(v4)) => reject_if_blocked(IpAddr::V4(v4), allow_loopback, code),
        Some(Host::Ipv6(v6)) => reject_if_blocked(IpAddr::V6(v6), allow_loopback, code),
        Some(Host::Domain(domain)) => {
            let ips = crate::infra::dns::resolve_host_ips(domain)
                .await
                .map_err(|e| {
                    tracing::warn!("SSRF guard: failed to resolve {domain}: {e}");
                    ServiceError::oauth(code, "destination host could not be resolved")
                })?;
            if ips.is_empty() {
                return Err(ServiceError::oauth(
                    code,
                    "destination host did not resolve to any address",
                ));
            }
            for ip in ips {
                reject_if_blocked(ip, allow_loopback, code)?;
            }
            Ok(())
        }
        None => Err(ServiceError::oauth(code, "destination URL has no host")),
    }
}

/// Reject a single resolved address if it is blocked, logging a security event
/// when the guard fires. Loopback is permitted when `allow_loopback` is set;
/// all other non-global ranges are always rejected.
fn reject_if_blocked(ip: IpAddr, allow_loopback: bool, code: OAuthErrorCode) -> ServiceResult<()> {
    let canonical = ip.to_canonical();
    if allow_loopback && canonical.is_loopback() {
        return Ok(());
    }
    if is_non_global(&canonical) {
        tracing::warn!(
            target: "security",
            %ip,
            "SSRF guard: blocked outbound fetch to non-global address"
        );
        return Err(ServiceError::oauth(
            code,
            "destination resolves to a non-routable address",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: unwrap on parse is acceptable"
)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn classifies_v4_non_global() {
        for [a, b, c, d] in [
            [127, 0, 0, 1],       // loopback
            [10, 0, 0, 1],        // RFC 1918
            [172, 16, 0, 1],      // RFC 1918
            [192, 168, 1, 1],     // RFC 1918
            [169, 254, 169, 254], // link-local (AWS IMDS)
            [100, 64, 0, 1],      // CGNAT
            [192, 0, 0, 1],       // IETF protocol
            [198, 18, 0, 1],      // benchmarking
            [0, 0, 0, 0],         // unspecified
            [255, 255, 255, 255], // broadcast
        ] {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            assert!(is_non_global(&ip), "expected non-global: {ip}");
        }
    }

    #[test]
    fn classifies_v4_global() {
        for [a, b, c, d] in [[1, 1, 1, 1], [8, 8, 8, 8], [93, 184, 216, 34]] {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            assert!(!is_non_global(&ip), "expected global: {ip}");
        }
    }

    #[test]
    fn classifies_v6() {
        assert!(is_non_global(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_non_global(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(is_non_global(&v6("fe80::1"))); // link-local
        assert!(is_non_global(&v6("fc00::1"))); // ULA
        assert!(is_non_global(&v6("2001:db8::1"))); // documentation
        assert!(!is_non_global(&v6("2606:4700:4700::1111"))); // Cloudflare DNS
    }

    #[test]
    fn canonicalizes_mapped_v4_loopback() {
        // ::ffff:127.0.0.1 must classify as loopback once canonicalised.
        let mapped = v6("::ffff:127.0.0.1");
        assert!(is_non_global(&mapped.to_canonical()));
    }

    #[tokio::test]
    async fn rejects_loopback_ip_literal_in_production() {
        assert!(
            assert_public_destination(
                "https://127.0.0.1/jwks.json",
                false,
                OAuthErrorCode::InvalidClient
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn allows_loopback_ip_literal_in_dev() {
        // allow_loopback=true models a non-TLS local-dev deployment.
        assert!(
            assert_public_destination(
                "https://127.0.0.1/jwks.json",
                true,
                OAuthErrorCode::InvalidClient
            )
            .await
            .is_ok()
        );
        assert!(
            assert_public_destination(
                "https://[::1]/jwks",
                true,
                OAuthErrorCode::InvalidRequestUri
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn rejects_imds_even_in_dev() {
        // Link-local (cloud metadata) must stay blocked regardless of dev mode.
        assert!(
            assert_public_destination(
                "https://169.254.169.254/latest/meta-data/",
                true,
                OAuthErrorCode::InvalidClient
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_private_ip_even_in_dev() {
        assert!(
            assert_public_destination("https://10.1.2.3/jwks", true, OAuthErrorCode::InvalidClient)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_bracketed_ipv6_loopback_in_production() {
        assert!(
            assert_public_destination(
                "https://[::1]/jwks",
                false,
                OAuthErrorCode::InvalidRequestUri
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn allows_public_ip_literal() {
        assert!(
            assert_public_destination("https://1.1.1.1/jwks", false, OAuthErrorCode::InvalidClient)
                .await
                .is_ok()
        );
    }
}
