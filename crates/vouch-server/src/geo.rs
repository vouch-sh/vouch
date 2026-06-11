// SPDX-License-Identifier: Apache-2.0 OR MIT
//! IP geolocation using MaxMind GeoLite2 databases.
//!
//! Two databases are embedded at compile time:
//! - GeoLite2-Country for country code lookups
//! - GeoLite2-ASN for autonomous system number and organization

use std::net::IpAddr;
use std::sync::LazyLock;

use maxminddb::Reader;

static COUNTRY_DB: LazyLock<Option<Reader<&'static [u8]>>> = LazyLock::new(|| {
    static BYTES: &[u8] = include_bytes!("../data/GeoLite2-Country.mmdb");
    Reader::from_source(BYTES)
        .map_err(|e| {
            tracing::error!("Failed to load GeoIP Country database: {e}");
        })
        .ok()
});

static ASN_DB: LazyLock<Option<Reader<&'static [u8]>>> = LazyLock::new(|| {
    static BYTES: &[u8] = include_bytes!("../data/GeoLite2-ASN.mmdb");
    Reader::from_source(BYTES)
        .map_err(|e| {
            tracing::error!("Failed to load GeoIP ASN database: {e}");
        })
        .ok()
});

/// Geolocation result for an IP address.
pub(crate) struct GeoLocation {
    pub country_code: String,
    pub asn: Option<u32>,
    pub org_name: Option<String>,
}

/// Look up country code and ASN for an IP address.
///
/// Returns `None` for private, loopback, or unresolvable addresses,
/// or if the GeoIP database failed to load.
pub(crate) fn lookup(ip: IpAddr) -> Option<GeoLocation> {
    let ip = ip.to_canonical();
    if crate::infra::ssrf::is_non_global(&ip) {
        return None;
    }
    let country_db = COUNTRY_DB.as_ref()?;
    let country: maxminddb::geoip2::Country = country_db.lookup(ip).ok()?.decode().ok()??;
    let code = country.country.iso_code?;

    let (asn, org_name) = ASN_DB
        .as_ref()
        .and_then(|db| {
            let asn: maxminddb::geoip2::Asn = db.lookup(ip).ok()?.decode().ok()??;
            Some((
                asn.autonomous_system_number,
                asn.autonomous_system_organization.map(String::from),
            ))
        })
        .unwrap_or((None, None));

    Some(GeoLocation {
        country_code: code.to_string(),
        asn,
        org_name,
    })
}

/// Force-initialize the GeoIP databases.
/// Call during startup to avoid cold-start latency on first request.
pub(crate) fn warmup() {
    let _ = COUNTRY_DB.as_ref();
    let _ = ASN_DB.as_ref();
}

/// Convert a two-letter country code to a flag emoji.
///
/// Uses Unicode Regional Indicator Symbols to form flag sequences.
pub(crate) fn country_flag(code: &str) -> Option<String> {
    let bytes = code.as_bytes();
    if bytes.len() != 2 {
        return None;
    }
    let (&a, &b) = (bytes.first()?, bytes.get(1)?);
    if !a.is_ascii_alphabetic() || !b.is_ascii_alphabetic() {
        return None;
    }
    let ri_a = char::from_u32(
        0x1F1E6_u32.saturating_add(u32::from(a.to_ascii_uppercase().wrapping_sub(b'A'))),
    )?;
    let ri_b = char::from_u32(
        0x1F1E6_u32.saturating_add(u32::from(b.to_ascii_uppercase().wrapping_sub(b'A'))),
    )?;
    Some(format!("{ri_a}{ri_b}"))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    // ====================================================================
    // lookup tests
    // ====================================================================

    #[test]
    fn test_lookup_public_ip() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let geo = lookup(ip);
        assert!(geo.is_some(), "8.8.8.8 should resolve to a country");
        let geo = geo.unwrap();
        assert_eq!(geo.country_code, "US");
    }

    #[test]
    fn test_lookup_public_ip_has_asn() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let geo = lookup(ip).unwrap();
        assert!(geo.asn.is_some(), "8.8.8.8 should have an ASN");
        assert_eq!(geo.asn, Some(15169));
    }

    #[test]
    fn test_lookup_public_ip_has_org_name() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let geo = lookup(ip).unwrap();
        assert!(geo.org_name.is_some(), "8.8.8.8 should have an org name");
    }

    // ====================================================================
    // is_non_global — IPv4 branches
    // ====================================================================

    #[test]
    fn test_lookup_loopback_returns_none() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_private_returns_none() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_link_local_returns_none() {
        let ip: IpAddr = "169.254.0.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_broadcast_returns_none() {
        let ip: IpAddr = "255.255.255.255".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_unspecified_v4_returns_none() {
        let ip: IpAddr = "0.0.0.0".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    // ====================================================================
    // is_non_global — IPv6 branches
    // ====================================================================

    #[test]
    fn test_lookup_ipv6_loopback_returns_none() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_ipv6_unspecified_returns_none() {
        let ip: IpAddr = "::".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_ipv6_ula_returns_none() {
        let ip: IpAddr = "fd12:3456:789a::1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_ipv6_link_local_returns_none() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    // ====================================================================
    // is_non_global — additional IPv4 ranges
    // ====================================================================

    #[test]
    fn test_lookup_cgnat_returns_none() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_cgnat_upper_bound_returns_none() {
        let ip: IpAddr = "100.127.255.254".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_documentation_test_net_1_returns_none() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_documentation_test_net_2_returns_none() {
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_documentation_test_net_3_returns_none() {
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_ietf_protocol_returns_none() {
        let ip: IpAddr = "192.0.0.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_6to4_relay_returns_none() {
        let ip: IpAddr = "192.88.99.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_benchmarking_returns_none() {
        let ip: IpAddr = "198.18.0.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_benchmarking_upper_returns_none() {
        let ip: IpAddr = "198.19.255.254".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_reserved_returns_none() {
        let ip: IpAddr = "240.0.0.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_multicast_v4_returns_none() {
        let ip: IpAddr = "224.0.0.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    // ====================================================================
    // is_non_global — additional IPv6 ranges
    // ====================================================================

    #[test]
    fn test_lookup_ipv6_documentation_returns_none() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_ipv6_benchmarking_returns_none() {
        let ip: IpAddr = "2001:2::1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_ipv6_discard_returns_none() {
        let ip: IpAddr = "100::1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_ipv6_multicast_returns_none() {
        let ip: IpAddr = "ff02::1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    // ====================================================================
    // IPv4-mapped IPv6 address tests
    // ====================================================================

    #[test]
    fn test_lookup_ipv4_mapped_ipv6_resolves() {
        // ::ffff:8.8.8.8 should resolve the same as 8.8.8.8
        let ip: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        let geo = lookup(ip);
        assert!(geo.is_some(), "::ffff:8.8.8.8 should resolve to a country");
        assert_eq!(geo.unwrap().country_code, "US");
    }

    #[test]
    fn test_lookup_ipv4_mapped_ipv6_private_returns_none() {
        // ::ffff:192.168.1.1 should be filtered as private
        let ip: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    #[test]
    fn test_lookup_ipv4_mapped_ipv6_loopback_returns_none() {
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(lookup(ip).is_none());
    }

    // ====================================================================
    // country_flag tests
    // ====================================================================

    #[test]
    fn test_country_flag_us() {
        let flag = country_flag("US");
        assert_eq!(flag, Some("\u{1F1FA}\u{1F1F8}".to_string()));
    }

    #[test]
    fn test_country_flag_gb() {
        let flag = country_flag("GB");
        assert_eq!(flag, Some("\u{1F1EC}\u{1F1E7}".to_string()));
    }

    #[test]
    fn test_country_flag_invalid() {
        assert!(country_flag("").is_none());
        assert!(country_flag("A").is_none());
        assert!(country_flag("USA").is_none());
        assert!(country_flag("12").is_none());
    }

    // ====================================================================
    // warmup tests
    // ====================================================================

    #[test]
    fn test_warmup() {
        warmup();
        assert!(
            COUNTRY_DB.is_some(),
            "GeoIP Country database should load successfully"
        );
        assert!(
            ASN_DB.is_some(),
            "GeoIP ASN database should load successfully"
        );
    }
}
