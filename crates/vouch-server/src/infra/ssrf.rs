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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Host;

use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use crate::infra::dns;

/// Whether an address may be the target of a server-side fetch of a
/// client-controlled URL.
///
/// Non-global means every block the IANA special-purpose address registries
/// (<https://www.iana.org/assignments/iana-ipv4-special-registry>,
/// <https://www.iana.org/assignments/iana-ipv6-special-registry>) do not mark
/// globally reachable, plus multicast and deprecated ranges.
///
/// An IPv6 address that embeds an IPv4 address is as reachable as the IPv4
/// address it carries, so it is classified by that address: IPv4-mapped and
/// IPv4-compatible (RFC 4291 §2.5.5), NAT64 `64:ff9b::/96` (RFC 6052 §3.1:
/// "The Well-Known Prefix MUST NOT be used to represent non-global IPv4
/// addresses"), 6to4 `2002::/16` (RFC 3056 §2), and Teredo `2001::/32`
/// (RFC 4380 §4), whose server address and obfuscated client address are both
/// checked.
pub(crate) trait GlobalReachability {
    /// `true` if the address must never be the target of such a fetch.
    fn is_non_global(&self) -> bool;
}

impl GlobalReachability for IpAddr {
    fn is_non_global(&self) -> bool {
        match self {
            IpAddr::V4(v4) => v4.is_non_global(),
            IpAddr::V6(v6) => v6.is_non_global(),
        }
    }
}

impl GlobalReachability for Ipv4Addr {
    fn is_non_global(&self) -> bool {
        let [a, b, c, _d] = self.octets();
        a == 0 // "this network" 0.0.0.0/8
            || self.is_loopback()
            || self.is_private()
            || self.is_link_local()
            || self.is_broadcast()
            || self.is_documentation()
            || self.is_multicast()
            || (a == 100 && (b & 0xC0 == 64)) // CGNAT 100.64.0.0/10
            || (a == 192 && b == 0 && c == 0) // IETF protocol 192.0.0.0/24
            || (a == 192 && b == 88 && c == 99) // 6to4 relay anycast 192.88.99.0/24
            || (a == 198 && (b & 0xFE == 18)) // benchmarking 198.18.0.0/15
            || (a & 0xF0 == 240) // reserved 240.0.0.0/4
    }
}

impl GlobalReachability for Ipv6Addr {
    fn is_non_global(&self) -> bool {
        if let Some(embedded) = self.embedded_ipv4() {
            return embedded.into_iter().flatten().any(|v4| v4.is_non_global());
        }
        let [s0, s1, s2, s3, ..] = self.segments();
        self.is_loopback()
            || self.is_unspecified()
            || self.is_multicast()
            || (s0 & 0xfe00 == 0xfc00) // unique-local fc00::/7
            || (s0 & 0xffc0 == 0xfe80) // link-local fe80::/10
            || (s0 == 0x0100 && s1 == 0 && s2 == 0 && s3 <= 1) // discard-only 100::/64, dummy 100:0:0:1::/64
            || (s0 == 0x0064 && s1 == 0xff9b && s2 == 1) // local-use NAT64 64:ff9b:1::/48
            || (s0 == 0x2001 && s1 == 0x0db8) // documentation 2001:db8::/32
            || (s0 == 0x3fff && s1 & 0xf000 == 0) // documentation 3fff::/20
            || s0 == 0x5f00 // SRv6 SIDs 5f00::/16
            || (s0 == 0x2001 && s1 < 0x0200 && !self.is_global_ietf_assignment()) // IETF protocol assignments 2001::/23
    }
}

/// How an IPv6 address relates to IPv4 and to the IETF protocol assignments,
/// for [`GlobalReachability`].
trait Ipv6Special {
    /// The IPv4 addresses the address embeds, or `None` if it is not one of
    /// the embedding formats. Teredo carries two: the server, and the client
    /// address stored with every bit inverted (RFC 4380 §4).
    fn embedded_ipv4(&self) -> Option<[Option<Ipv4Addr>; 2]>;
    /// Whether an address in `2001::/23` falls in one of the sub-blocks the
    /// IANA registry marks globally reachable.
    fn is_global_ietf_assignment(&self) -> bool;
}

impl Ipv6Special for Ipv6Addr {
    fn embedded_ipv4(&self) -> Option<[Option<Ipv4Addr>; 2]> {
        // IPv4-mapped ::ffff:0:0/96 and IPv4-compatible ::/96 (RFC 4291
        // §2.5.5); the latter also holds :: and ::1, which classify as
        // 0.0.0.0/8.
        if let Some(v4) = self.to_ipv4() {
            return Some([Some(v4), None]);
        }
        let v4 = |hi: u16, lo: u16| {
            let [a, b] = hi.to_be_bytes();
            let [c, d] = lo.to_be_bytes();
            Ipv4Addr::new(a, b, c, d)
        };
        match self.segments() {
            // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052 §2.1)
            [0x0064, 0xff9b, 0, 0, 0, 0, hi, lo] => Some([Some(v4(hi, lo)), None]),
            // 6to4 2002:V4ADDR::/48 (RFC 3056 §2)
            [0x2002, hi, lo, ..] => Some([Some(v4(hi, lo)), None]),
            // Teredo 2001:0000:SERVER:FLAGS:PORT:~CLIENT (RFC 4380 §4)
            [0x2001, 0, server_hi, server_lo, _, _, client_hi, client_lo] => Some([
                Some(v4(server_hi, server_lo)),
                Some(v4(!client_hi, !client_lo)),
            ]),
            _ => None,
        }
    }

    fn is_global_ietf_assignment(&self) -> bool {
        match self.segments() {
            [_, 0x0001, 0, 0, 0, 0, 0, 1..=3] // anycast 2001:1::1, ::2, ::3
            | [_, 0x0003, ..] // AMT 2001:3::/32
            | [_, 0x0004, 0x0112, ..] => true, // AS112-v6 2001:4:112::/48
            [_, s1, ..] => s1 & 0xfff0 == 0x0020 || s1 & 0xfff0 == 0x0030, // ORCHIDv2, Drone Remote ID
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
/// `OriginPolicy` loopback relaxation. It only relaxes **loopback**: private,
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
            let ips = dns::resolve_host_ips(domain).await.map_err(|e| {
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
    if canonical.is_non_global() {
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
            assert!(ip.is_non_global(), "expected non-global: {ip}");
        }
    }

    #[test]
    fn classifies_v4_global() {
        for [a, b, c, d] in [[1, 1, 1, 1], [8, 8, 8, 8], [93, 184, 216, 34]] {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            assert!(!ip.is_non_global(), "expected global: {ip}");
        }
    }

    #[test]
    fn classifies_v6() {
        assert!(IpAddr::V6(Ipv6Addr::LOCALHOST).is_non_global());
        assert!(IpAddr::V6(Ipv6Addr::UNSPECIFIED).is_non_global());
        assert!(v6("fe80::1").is_non_global()); // link-local
        assert!(v6("fc00::1").is_non_global()); // ULA
        assert!(v6("2001:db8::1").is_non_global()); // documentation
        assert!(!v6("2606:4700:4700::1111").is_non_global()); // Cloudflare DNS
    }

    /// One address per block of the IANA special-purpose registries
    /// (iana-ipv4-special-registry, iana-ipv6-special-registry, fetched
    /// 2026-09-30), classified as the registry's "Globally Reachable" column
    /// says, plus a global address for contrast.
    #[test]
    fn classifies_every_iana_special_purpose_block() {
        let cases: &[(&str, bool)] = &[
            // IPv4: (address, non-global)
            ("0.1.2.3", true),      // "this network" 0.0.0.0/8
            ("100.64.0.1", true),   // shared address space
            ("192.0.0.170", true),  // NAT64/DNS64 discovery, in 192.0.0.0/24
            ("198.51.100.7", true), // TEST-NET-2
            ("203.0.113.7", true),  // TEST-NET-3
            ("192.88.99.2", true),  // 6a44 relay anycast
            ("8.8.8.8", false),     // global
            // IPv6
            ("::ffff:10.0.0.1", true), // IPv4-mapped, not canonicalised
            ("::10.0.0.1", true),      // IPv4-compatible
            ("64:ff9b:1::1", true),    // local-use NAT64 (RFC 8215)
            ("100::1", true),          // discard-only
            ("100:0:0:1::1", true),    // dummy prefix
            ("2001:2::1", true),       // benchmarking
            ("2001:10::1", true),      // deprecated ORCHID
            ("2001:1::4", true),       // IETF protocol assignments, no exception
            ("2001:1::1", false),      // PCP anycast
            ("2001:1:0:5::1", true),   // not the anycast address
            ("2001:3::1", false),      // AMT
            ("2001:4:112::1", false),  // AS112-v6
            ("2001:20::1", false),     // ORCHIDv2
            ("2001:30::1", false),     // Drone Remote ID
            ("3fff::1", true),         // documentation 3fff::/20
            ("5f00::1", true),         // SRv6 SIDs
            ("2606:4700:4700::1111", false),
        ];
        for (addr, non_global) in cases {
            let ip: IpAddr = addr.parse().unwrap();
            assert_eq!(ip.is_non_global(), *non_global, "{addr}");
        }
    }

    // RFC 6052 §3.1: "The Well-Known Prefix MUST NOT be used to represent
    // non-global IPv4 addresses". An address in an embedding format is as
    // reachable as the IPv4 address it carries.
    #[test]
    fn classifies_embedded_ipv4_by_the_address_it_carries() {
        let cases: &[(&str, bool)] = &[
            ("64:ff9b::a00:1", true),     // NAT64 of 10.0.0.1
            ("64:ff9b::a9fe:a9fe", true), // NAT64 of 169.254.169.254
            ("64:ff9b::808:808", false),  // NAT64 of 8.8.8.8
            ("2002:c0a8:101::1", true),   // 6to4 of 192.168.1.1
            ("2002:808:808::1", false),   // 6to4 of 8.8.8.8
            // Teredo: server 8.8.8.8, client ~0xf5fffffe = 10.0.0.1
            ("2001:0:808:808:0:0:f5ff:fffe", true),
            // Teredo: server 8.8.8.8, client ~0xf7f7f7f7 = 8.8.8.8
            ("2001:0:808:808:0:0:f7f7:f7f7", false),
            // Teredo: server 127.0.0.1, client 8.8.8.8
            ("2001:0:7f00:1:0:0:f7f7:f7f7", true),
        ];
        for (addr, non_global) in cases {
            let ip: IpAddr = addr.parse().unwrap();
            assert_eq!(ip.is_non_global(), *non_global, "{addr}");
        }
    }

    #[tokio::test]
    async fn rejects_nat64_of_a_private_address() {
        assert!(
            assert_public_destination(
                "https://[64:ff9b::a00:1]/jwks",
                true,
                OAuthErrorCode::InvalidClient
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn canonicalizes_mapped_v4_loopback() {
        // ::ffff:127.0.0.1 must classify as loopback once canonicalised.
        let mapped = v6("::ffff:127.0.0.1");
        assert!(mapped.to_canonical().is_non_global());
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
