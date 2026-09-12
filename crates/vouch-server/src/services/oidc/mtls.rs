// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8705: mTLS client certificate parsing and verification.
//!
//! Provides:
//! - Certificate DER parsing and field extraction
//! - `x5t#S256` thumbprint computation (RFC 8705 Section 3.1)
//! - `tls_client_auth` subject/SAN matching (RFC 8705 Section 2.1.2)
//! - `self_signed_tls_client_auth` JWKS x5c matching (RFC 8705 Section 2.2.2)

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use der::{Decode, oid::ObjectIdentifier};
use subtle::ConstantTimeEq;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

/// Subject Alternative Name extension OID (2.5.29.17).
const SAN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// RFC 8705 §3.1 `x5t#S256`: the base64url-encoded SHA-256 of a certificate's
/// DER encoding.
///
/// Only [`compute_cert_thumbprint`] builds one, so a `cnf.x5t#S256` cannot be
/// minted from a string that never came from a presented certificate — the
/// same guarantee `ValidatedDpopProof` gives the `jkt` half of the binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertThumbprint(String);

impl CertThumbprint {
    /// The wire value, for the `cnf` claim and for comparisons.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CertThumbprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Parsed client certificate with extracted identity fields.
#[derive(Debug, Clone)]
pub(crate) struct ClientCertificate {
    /// `x5t#S256`: base64url-encoded SHA-256 of the DER certificate.
    /// RFC 8705 Section 3.1 / RFC 7515 Section 4.1.8.
    pub thumbprint: CertThumbprint,
    /// RFC 4514 subject distinguished name string.
    pub subject_dn: Option<String>,
    /// Subject Alternative Name — DNS names.
    pub san_dns: Vec<String>,
    /// Subject Alternative Name — email addresses.
    pub san_email: Vec<String>,
    /// Subject Alternative Name — URIs.
    pub san_uri: Vec<String>,
    /// Subject Alternative Name — IP addresses.
    ///
    /// Stored as a canonical [`std::net::IpAddr`] (parsed from the raw
    /// `iPAddress` SAN octets per RFC 5280 §4.2.1.6) rather than a formatted
    /// string, so the `tls_client_auth` SAN-IP comparison (RFC 8705 §2.1.2)
    /// is representation-agnostic: every valid textual form of one address
    /// (`2001:db8::1`, `2001:db8:0:0:0:0:0:1`, `2001:DB8::1`, …) reduces to
    /// the same 128-bit value here and compares equal against the registered
    /// `tls_client_auth_san_ip` string.
    pub san_ip: Vec<std::net::IpAddr>,
}

/// Errors from mTLS certificate processing.
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum MtlsError {
    /// Certificate DER could not be parsed.
    #[error("invalid certificate format: {0}")]
    InvalidCertificateFormat(String),
    /// Certificate subject/SAN does not match registered client.
    #[error("subject mismatch: expected {expected}, found {found}")]
    SubjectMismatch { expected: String, found: String },
    /// Certificate not registered for this client.
    #[error("certificate not registered for this client")]
    CertificateNotRegistered,
}

/// Compute the `x5t#S256` thumbprint of a DER-encoded certificate.
///
/// RFC 8705 Section 3.1: base64url(SHA-256(DER(cert))).
pub(crate) fn compute_cert_thumbprint(der: &[u8]) -> CertThumbprint {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der);
    CertThumbprint(URL_SAFE_NO_PAD.encode(digest.as_ref()))
}

/// Parse a DER-encoded X.509 certificate into a [`ClientCertificate`].
pub(crate) fn parse_client_certificate(der: &[u8]) -> Result<ClientCertificate, MtlsError> {
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| MtlsError::InvalidCertificateFormat(format!("DER parse error: {e}")))?;

    let thumbprint = compute_cert_thumbprint(der);
    let subject_dn = {
        let s = cert.tbs_certificate.subject.to_string();
        if s.is_empty() { None } else { Some(s) }
    };

    // Extract SANs
    let mut san_dns = Vec::new();
    let mut san_email = Vec::new();
    let mut san_uri = Vec::new();
    let mut san_ip = Vec::new();

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions {
            if ext.extn_id == SAN_OID
                && let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes())
            {
                for name in &san.0 {
                    match name {
                        GeneralName::DnsName(dns) => {
                            san_dns.push(dns.to_string());
                        }
                        GeneralName::Rfc822Name(email) => {
                            san_email.push(email.to_string());
                        }
                        GeneralName::UniformResourceIdentifier(uri) => {
                            san_uri.push(uri.to_string());
                        }
                        GeneralName::IpAddress(ip) => {
                            if let Some(addr) = parse_ip_bytes(ip.as_bytes()) {
                                san_ip.push(addr);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(ClientCertificate {
        thumbprint,
        subject_dn,
        san_dns,
        san_email,
        san_uri,
        san_ip,
    })
}

/// Parse IP address bytes into a canonical [`std::net::IpAddr`].
///
/// Per RFC 5280 §4.2.1.6, an `iPAddress` GeneralName carries 32 bits (IPv4)
/// or 128 bits (IPv6) in network byte order. Any other length is not a valid
/// IP GeneralName and returns `None` so the malformed entry is dropped from
/// the parsed SANs rather than admitted into the comparison set.
///
/// Returning a canonical `IpAddr` (rather than a formatted string) is what
/// makes the `tls_client_auth` SAN-IP comparison (RFC 8705 §2.1.2)
/// representation-agnostic: the registered `tls_client_auth_san_ip` value is
/// parsed to the same `IpAddr` type before comparison, so every valid textual
/// form of one address (`2001:db8::1`, `2001:db8:0:0:0:0:0:1`, `2001:DB8::1`,
/// …) reduces to the same 128-bit value and compares equal regardless of the
/// specific rendering either side used.
fn parse_ip_bytes(bytes: &[u8]) -> Option<std::net::IpAddr> {
    match bytes {
        [a, b, c, d] => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            *a, *b, *c, *d,
        ))),
        [..] if bytes.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Canonicalize an RFC 4514 distinguished-name string for comparison.
///
/// Parses the string into a DER `RdnSequence` (via
/// [`x509_cert::name::RdnSequence`]'s `FromStr`) and re-renders it,
/// so both sides of a DN comparison reduce to the same rendering regardless
/// of the spacing and attribute-name casing the input used. Returns `None`
/// when the string is not a parseable RFC 4514 DN, in which case the caller
/// falls back to exact string comparison.
///
/// Before parsing, whitespace adjacent to a *structural* separator is
/// stripped: immediately after an RDN-separator comma, and on both sides of
/// the `=` that separates each attribute type from its value. `x509-cert`
/// 0.2.5's `RdnSequence::from_str` splits RDNs on a bare `,` and locates the
/// attribute type with `s.find('=')` without trimming either side, so a
/// leading space on the next attribute-type name (e.g. `CN=foo, O=Acme`) or a
/// space padding the `=` (e.g. `O = Acme`) breaks the parse and the caller
/// falls back to exact equality — which always rejects, since the cert-side
/// `Name::to_string` rendering joins RDNs with a bare comma and emits a bare
/// `=`. Stripping separator-adjacent whitespace makes both of the renderings
/// an operator is likely to paste in canonicalize identically to
/// `O=Acme,CN=foo`:
///
/// - `O=Acme, CN=foo` — comma-space, bare `=`. This is what `openssl x509
///   -noout -subject` prints by default (verified against OpenSSL 3.6.4), and
///   what `-text` shows on the `Subject:` line.
/// - `O = Acme, CN = foo` — `=` padded on both sides. This is the `oneline`
///   name format, which the operator gets by passing `-nameopt oneline`
///   explicitly; it is *not* the default for `-subject`.
///
/// The `=`-padded form is handled because it is a plausible paste, not
/// because any command emits it by default.
///
/// Only a *structural* comma separates RDNs, and only the *first* unescaped
/// `=` in an RDN is the type/value separator (a later `=` belongs to the
/// value). RFC 4514 §2.4 lets a comma appear inside an attribute value when
/// escaped with a backslash, and §4 gives
/// `CN=James \"Jim\" Smith\, III,DC=example,DC=net` as a valid DN. Stripping
/// whitespace after every comma or around every `=` would rewrite
/// `Smith\, III` to `Smith\,III` (changing the value rather than the
/// separator spacing), so the escape state is tracked and whitespace is only
/// stripped around *unescaped* separators — while still in the
/// attribute-type region (before the RDN's first unescaped `=`) or
/// immediately after that `=`. Interior value whitespace, and whitespace
/// around a value-internal `=`, is significant and preserved.
fn canonicalize_dn(dn: &str) -> Option<String> {
    use std::str::FromStr as _;
    let mut normalized = String::with_capacity(dn.len());
    let mut escaped = false;
    // `in_value` is `false` while we are still in the attribute-type region of
    // the current RDN (before its first unescaped `=`). Whitespace there is
    // separator-adjacent formatting and is stripped so `O = Acme, CN = foo`
    // reduces to `O=Acme,CN=foo`; an unescaped `,` returns us here for the
    // next RDN. A later `=` already lives in the value and does not reset
    // this flag, so whitespace around a value-internal `=` is preserved.
    let mut in_value = false;
    // `after_eq` is set immediately after the RDN's type/value separator `=`
    // so the leading whitespace of the value (e.g. the `= Acme` padding) is
    // stripped until the first non-whitespace value character. Interior value
    // whitespace after that character is preserved.
    let mut after_eq = false;
    for c in dn.chars() {
        if (!in_value || after_eq) && c.is_whitespace() {
            continue;
        }
        after_eq = false;
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '=' && !in_value {
            // First unescaped `=` in this RDN — the type/value separator.
            in_value = true;
            after_eq = true;
        } else if c == ',' {
            // Structural comma ends this RDN; the next one starts in its
            // attribute-type region.
            in_value = false;
        }
        normalized.push(c);
    }
    let rdns = x509_cert::name::RdnSequence::from_str(&normalized).ok()?;
    let der = der::Encode::to_der(&rdns).ok()?;
    let rdns = x509_cert::name::RdnSequence::from_der(&der).ok()?;
    Some(rdns.to_string())
}

/// Verify `tls_client_auth` — match certificate against registered
/// subject DN or SAN fields (RFC 8705 Section 2.1.2).
///
/// Exactly one of the `tls_client_auth_*` fields must match.
pub(crate) fn verify_tls_client_auth(
    cert: &ClientCertificate,
    expected_subject_dn: Option<&str>,
    expected_san_dns: Option<&str>,
    expected_san_email: Option<&str>,
    expected_san_uri: Option<&str>,
    expected_san_ip: Option<&str>,
) -> Result<(), MtlsError> {
    if let Some(expected) = expected_subject_dn {
        let found = cert.subject_dn.as_deref().unwrap_or("");
        // Compare DNs via a canonical form, not one specific rendering:
        // `found` is whatever `Name::to_string` emitted at parse time, while
        // the registered `tls_client_auth_subject_dn` is operator-supplied
        // RFC 4514 text. Round-tripping both sides through the DER encoding
        // (RFC 4514 string -> RdnSequence -> canonical string) makes the
        // comparison insensitive to spacing and attribute-name case
        // (`CN=a, O=b` vs `cn=a,o=b`). If either side does not parse as an
        // RFC 4514 DN the comparison falls back to exact string equality,
        // preserving the previous behavior (fail closed on mismatch).
        let matches = match (canonicalize_dn(expected), canonicalize_dn(found)) {
            (Some(e), Some(f)) => e == f,
            _ => expected == found,
        };
        if matches {
            return Ok(());
        }
        return Err(MtlsError::SubjectMismatch {
            expected: expected.to_string(),
            found: found.to_string(),
        });
    }

    if let Some(expected) = expected_san_dns {
        // RFC 4343: DNS names compare case-insensitively (RFC 6125 §6.4.1
        // for certificate identity matching), so `Client.Example.COM` in the
        // SAN must match a registered `client.example.com`.
        if cert
            .san_dns
            .iter()
            .any(|d| d.eq_ignore_ascii_case(expected))
        {
            return Ok(());
        }
        return Err(MtlsError::SubjectMismatch {
            expected: format!("DNS:{expected}"),
            found: format!("DNS:{}", cert.san_dns.join(",")),
        });
    }

    if let Some(expected) = expected_san_email {
        if cert.san_email.iter().any(|e| e == expected) {
            return Ok(());
        }
        return Err(MtlsError::SubjectMismatch {
            expected: format!("email:{expected}"),
            found: format!("email:{}", cert.san_email.join(",")),
        });
    }

    if let Some(expected) = expected_san_uri {
        if cert.san_uri.iter().any(|u| u == expected) {
            return Ok(());
        }
        return Err(MtlsError::SubjectMismatch {
            expected: format!("URI:{expected}"),
            found: format!("URI:{}", cert.san_uri.join(",")),
        });
    }

    if let Some(expected) = expected_san_ip {
        // Normalize both sides to a canonical `IpAddr` before comparing so that
        // any valid textual representation of the registered
        // `tls_client_auth_san_ip` (RFC 5952 canonical `2001:db8::1`,
        // uncompressed `2001:db8:0:0:0:0:0:1`, uppercase `2001:DB8::1`, …)
        // matches the same 128-bit address carried by the certificate's
        // `iPAddress` SAN bytes (RFC 5280 §4.2.1.6). Comparing raw strings
        // would only match the one rendering `parse_ip_bytes` happens to
        // emit, rejecting every other valid form with `SubjectMismatch`.
        if let Ok(expected_addr) = expected.parse::<std::net::IpAddr>()
            && cert.san_ip.contains(&expected_addr)
        {
            return Ok(());
        }
        let found = cert
            .san_ip
            .iter()
            .map(std::net::IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(",");
        return Err(MtlsError::SubjectMismatch {
            expected: format!("IP:{expected}"),
            found: format!("IP:{found}"),
        });
    }

    Err(MtlsError::CertificateNotRegistered)
}

/// Verify `self_signed_tls_client_auth` — match certificate against
/// client's JWKS x5c entries (RFC 8705 Section 2.2).
///
/// The TLS handshake proves possession of the private key. This
/// function verifies the presented certificate matches one registered
/// in the client's JWKS via the x5c parameter.
pub(crate) fn verify_self_signed_tls_client_auth(
    cert: &ClientCertificate,
    jwks: &serde_json::Value,
) -> Result<(), MtlsError> {
    // Parse JWKS keys array
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or(MtlsError::CertificateNotRegistered)?;

    // Check each key's x5c entries
    for key in keys {
        if let Some(x5c_array) = key.get("x5c").and_then(|v| v.as_array()) {
            for x5c_entry in x5c_array {
                if let Some(x5c_b64) = x5c_entry.as_str() {
                    // x5c uses standard base64 (NOT base64url) per RFC 7517 Section 4.7
                    if let Ok(x5c_der) = STANDARD.decode(x5c_b64) {
                        let x5c_thumbprint = compute_cert_thumbprint(&x5c_der);
                        let is_match: bool = x5c_thumbprint
                            .as_str()
                            .as_bytes()
                            .ct_eq(cert.thumbprint.as_str().as_bytes())
                            .into();
                        if is_match {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    Err(MtlsError::CertificateNotRegistered)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// Generate a self-signed test certificate with the given CN.
    fn make_test_cert(cn: &str) -> Vec<u8> {
        make_self_signed_cert_with_san(cn, &[], &[], &[], &[])
    }

    #[test]
    fn test_compute_cert_thumbprint() {
        let cert_der = make_test_cert("test-thumbprint");
        let thumbprint = compute_cert_thumbprint(&cert_der);
        assert!(!thumbprint.as_str().is_empty());
        // base64url encoded SHA-256 should be 43 chars (256 bits)
        assert_eq!(thumbprint.as_str().len(), 43);
    }

    #[test]
    fn test_parse_client_certificate() {
        let cert_der = make_test_cert("test-parse");
        let cert = parse_client_certificate(&cert_der).expect("parse");
        assert!(
            cert.subject_dn
                .as_deref()
                .unwrap_or("")
                .contains("test-parse"),
            "subject_dn should contain CN, got: {:?}",
            cert.subject_dn
        );
        assert!(!cert.thumbprint.as_str().is_empty());
    }

    #[test]
    fn test_verify_tls_client_auth_subject_dn() {
        let cert_der = make_test_cert("test-verify");
        let cert = parse_client_certificate(&cert_der).expect("parse");
        let subject_dn = cert.subject_dn.as_deref().unwrap();

        // Matching subject DN should succeed
        assert!(verify_tls_client_auth(&cert, Some(subject_dn), None, None, None, None).is_ok());

        // Non-matching should fail
        assert!(verify_tls_client_auth(&cert, Some("CN=wrong"), None, None, None, None).is_err());
    }

    #[test]
    fn test_parse_invalid_der() {
        let result = parse_client_certificate(b"not a certificate");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ip_bytes_v4() {
        let addr = parse_ip_bytes(&[192, 168, 1, 1]);
        assert_eq!(
            addr,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 1
            )))
        );
    }

    #[test]
    fn test_parse_ip_bytes_v6() {
        let bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result = parse_ip_bytes(&bytes);
        assert_eq!(
            result,
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
            )))
        );
        // The canonical `IpAddr` (not a formatted string) is what the
        // comparison path relies on: every valid text form of this address
        // parses back to this same value.
        assert_eq!(
            "2001:db8::1".parse::<std::net::IpAddr>().unwrap(),
            result.unwrap(),
            "RFC 5952 canonical compressed form must reduce to the same IpAddr"
        );
        assert_eq!(
            "2001:0db8:0000:0000:0000:0000:0000:0001"
                .parse::<std::net::IpAddr>()
                .unwrap(),
            result.unwrap(),
            "fully-expanded zero-padded form must reduce to the same IpAddr"
        );
    }

    // =========================================================================
    // verify_tls_client_auth — all-None case (RFC 8705 Section 2.1.2)
    // =========================================================================

    /// When all expected identity fields are None, the certificate cannot be
    /// matched against any registered identity — return CertificateNotRegistered.
    #[test]
    fn test_verify_tls_client_auth_all_none() {
        let cert_der = make_test_cert("all-none-test");
        let cert = parse_client_certificate(&cert_der).expect("parse");

        let result = verify_tls_client_auth(&cert, None, None, None, None, None);

        assert!(
            matches!(result, Err(MtlsError::CertificateNotRegistered)),
            "all-None fields must return CertificateNotRegistered, got: {result:?}"
        );
    }

    // =========================================================================
    // compute_cert_thumbprint — determinism and uniqueness
    // =========================================================================

    /// The same DER bytes must always produce the same thumbprint.
    #[test]
    fn test_thumbprint_determinism() {
        let cert_der = make_test_cert("determinism-test");
        let t1 = compute_cert_thumbprint(&cert_der);
        let t2 = compute_cert_thumbprint(&cert_der);
        assert_eq!(t1, t2, "identical DER must produce identical thumbprint");
    }

    /// Different DER bytes must produce different thumbprints.
    #[test]
    fn test_thumbprint_uniqueness() {
        let cert_a = make_test_cert("uniqueness-cert-a");
        let cert_b = make_test_cert("uniqueness-cert-b");
        let t_a = compute_cert_thumbprint(&cert_a);
        let t_b = compute_cert_thumbprint(&cert_b);
        assert_ne!(t_a, t_b, "different DER must produce different thumbprints");
    }

    // =========================================================================
    // parse_ip_bytes — IPv6 leading-zero groups are canonical, not formatted
    // =========================================================================

    /// IPv6 bytes with leading zeros must parse to the canonical `IpAddr`
    /// (so all valid text forms of that address compare equal), rather than
    /// to a specific zero-padded string rendering.
    #[test]
    fn test_parse_ip_bytes_v6_leading_zeros_canonical() {
        // 0x0001:0000:0000:0000:0000:0000:0000:0001
        let bytes = [
            0x00u8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let result = parse_ip_bytes(&bytes);
        let expected = std::net::IpAddr::V6(std::net::Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(result, Some(expected));
        // RFC 5952 canonical, uncompressed, uppercase, and fully zero-padded
        // forms all reduce to the same canonical `IpAddr` — this is the
        // property the comparison path depends on.
        for form in [
            "1::1",
            "1:0:0:0:0:0:0:1",
            "1:0::0:0:0:1",
            "0001:0000:0000:0000:0000:0000:0000:0001",
            "1::0000:0000:0000:0:1",
        ] {
            assert_eq!(
                form.parse::<std::net::IpAddr>().unwrap(),
                expected,
                "form {form:?} must reduce to the same canonical IpAddr"
            );
        }
    }

    // =========================================================================
    // parse_ip_bytes — non-standard lengths are dropped (None), never panic
    // =========================================================================

    /// Bytes that are neither 4 (IPv4) nor 16 (IPv6) bytes long are not a valid
    /// `iPAddress` GeneralName (RFC 5280 §4.2.1.6) and must return `None` so
    /// they are dropped from the parsed SANs — not panic or produce garbage.
    #[test]
    fn test_parse_ip_bytes_unknown_length_returns_none() {
        // 5 bytes — not IPv4 (4) or IPv6 (16)
        assert_eq!(parse_ip_bytes(&[0xde, 0xad, 0xbe, 0xef, 0x42]), None);
    }

    /// A single byte must also return `None` (not crash).
    #[test]
    fn test_parse_ip_bytes_single_byte_returns_none() {
        assert_eq!(parse_ip_bytes(&[0x0f]), None);
    }

    /// An empty byte slice must return `None` (no IP at all).
    #[test]
    fn test_parse_ip_bytes_empty_slice_returns_none() {
        assert_eq!(parse_ip_bytes(&[]), None);
    }

    // =========================================================================
    // parse_client_certificate — empty subject DN coverage note
    // =========================================================================
    //
    // RFC 5280 permits certificates with an empty subject DN (when a SAN
    // extension is present). `parse_client_certificate` handles this by
    // returning `None` for `subject_dn` when `to_string()` on the DN is empty.
    //
    // Constructing such a certificate requires a CA that supports empty subject
    // DNs — the `make_test_cert` helper always sets a non-empty CN, so this
    // branch cannot be exercised here. Coverage should be added in
    // `vouch-tests` (integration tests) once a suitable cert fixture exists.

    // =========================================================================
    // SAN-capable certificate generator
    // =========================================================================

    /// Generate a self-signed P-256 certificate with given CN and SANs.
    ///
    /// All SAN slices may be empty — if none are provided the cert has no SAN
    /// extension, matching the behaviour of `make_test_cert`.
    fn make_self_signed_cert_with_san(
        cn: &str,
        dns_names: &[&str],
        emails: &[&str],
        uris: &[&str],
        ips: &[std::net::IpAddr],
    ) -> Vec<u8> {
        use der::{Encode, asn1::Ia5String};
        use p256::ecdsa::SigningKey;
        use spki::EncodePublicKey;
        use x509_cert::builder::{Builder as _, CertificateBuilder, Profile};
        use x509_cert::ext::pkix::SubjectAltName;
        use x509_cert::ext::pkix::name::GeneralName;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

        // Build CN-only subject
        let cn_oid = der::oid::ObjectIdentifier::new_unwrap("2.5.4.3");
        let cn_value = der::asn1::Utf8StringRef::new(cn).expect("CN string");
        let atv = x509_cert::attr::AttributeTypeAndValue {
            oid: cn_oid,
            value: der::asn1::Any::from(cn_value),
        };
        let mut rdn_set = der::asn1::SetOfVec::new();
        rdn_set.insert(atv).expect("insert RDN");
        let subject =
            x509_cert::name::RdnSequence(vec![x509_cert::name::RelativeDistinguishedName(rdn_set)]);

        let validity =
            Validity::from_now(core::time::Duration::from_secs(86400)).expect("validity");
        let serial = SerialNumber::new(&[1u8]).expect("serial");
        let spki_der = key.verifying_key().to_public_key_der().expect("spki DER");
        let spki =
            spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_ref()).expect("parse spki");

        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            serial,
            validity,
            subject,
            spki,
            &key,
        )
        .expect("cert builder");

        // Build SAN extension if any names provided
        let mut names = Vec::new();
        for dns in dns_names {
            names.push(GeneralName::DnsName(Ia5String::new(dns).expect("dns")));
        }
        for email in emails {
            names.push(GeneralName::Rfc822Name(
                Ia5String::new(email).expect("email"),
            ));
        }
        for uri in uris {
            names.push(GeneralName::UniformResourceIdentifier(
                Ia5String::new(uri).expect("uri"),
            ));
        }
        for ip in ips {
            let bytes = match ip {
                std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            names.push(GeneralName::IpAddress(
                der::asn1::OctetString::new(bytes).expect("ip"),
            ));
        }

        if !names.is_empty() {
            let san = SubjectAltName(names);
            builder.add_extension(&san).expect("add SAN");
        }

        let cert = builder
            .build::<p256::ecdsa::DerSignature>()
            .expect("build cert");
        cert.to_der().expect("DER encode")
    }

    // =========================================================================
    // Multi-RDN subject certificate generator
    // =========================================================================

    /// Build an `RdnSequence` from a list of `(OID string, UTF-8 value)`
    /// attribute pairs, in the order given (the order `RdnSequence`'s `Display`
    /// renders in reverse).
    ///
    /// `make_test_cert` / `make_self_signed_cert_with_san` only build CN-only
    /// subjects, so this helper is needed to exercise the multi-RDN path
    /// through `canonicalize_dn` / `verify_tls_client_auth` (the path the
    /// comma-space bug lives on).
    fn make_rdn_sequence(rdns: &[(&str, &str)]) -> x509_cert::name::RdnSequence {
        let mut sequence = Vec::new();
        for (oid, val) in rdns {
            let oid = der::oid::ObjectIdentifier::new_unwrap(oid);
            let v = der::asn1::Utf8StringRef::new(val).expect("val");
            let atv = x509_cert::attr::AttributeTypeAndValue {
                oid,
                value: der::asn1::Any::from(v),
            };
            let mut set = der::asn1::SetOfVec::new();
            set.insert(atv).expect("insert RDN");
            sequence.push(x509_cert::name::RelativeDistinguishedName(set));
        }
        x509_cert::name::RdnSequence(sequence)
    }

    /// Build a self-signed P-256 certificate with an arbitrary multi-RDN
    /// subject and no SANs, for exercising the subject-DN comparison path
    /// with DNs the CN-only generators cannot produce.
    fn make_self_signed_cert_with_subject(subject: x509_cert::name::RdnSequence) -> Vec<u8> {
        use der::Encode;
        use p256::ecdsa::SigningKey;
        use spki::EncodePublicKey;
        use x509_cert::builder::{Builder as _, CertificateBuilder, Profile};
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let validity =
            Validity::from_now(core::time::Duration::from_secs(86400)).expect("validity");
        let serial = SerialNumber::new(&[1u8]).expect("serial");
        let spki_der = key.verifying_key().to_public_key_der().expect("spki DER");
        let spki =
            spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_ref()).expect("parse spki");
        let builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            serial,
            validity,
            subject,
            spki,
            &key,
        )
        .expect("cert builder");
        let cert = builder
            .build::<p256::ecdsa::DerSignature>()
            .expect("build cert");
        cert.to_der().expect("DER encode")
    }

    // =========================================================================
    // verify_tls_client_auth — SAN DNS
    // =========================================================================

    #[test]
    fn test_verify_tls_client_auth_san_dns() {
        let cert_der =
            make_self_signed_cert_with_san("test-san-dns", &["test.example.com"], &[], &[], &[]);
        let cert = parse_client_certificate(&cert_der).expect("parse");

        // Matching DNS SAN succeeds
        assert!(
            verify_tls_client_auth(&cert, None, Some("test.example.com"), None, None, None).is_ok(),
            "matching DNS SAN should succeed"
        );

        // Non-matching DNS SAN fails
        assert!(
            verify_tls_client_auth(&cert, None, Some("other.example.com"), None, None, None)
                .is_err(),
            "non-matching DNS SAN should fail"
        );
    }

    // =========================================================================
    // verify_tls_client_auth — SAN email
    // =========================================================================

    #[test]
    fn test_verify_tls_client_auth_san_email() {
        let cert_der =
            make_self_signed_cert_with_san("test-san-email", &[], &["user@example.com"], &[], &[]);
        let cert = parse_client_certificate(&cert_der).expect("parse");

        // Matching email SAN succeeds
        assert!(
            verify_tls_client_auth(&cert, None, None, Some("user@example.com"), None, None).is_ok(),
            "matching email SAN should succeed"
        );

        // Non-matching email SAN fails
        assert!(
            verify_tls_client_auth(&cert, None, None, Some("other@example.com"), None, None)
                .is_err(),
            "non-matching email SAN should fail"
        );
    }

    // =========================================================================
    // verify_tls_client_auth — SAN URI
    // =========================================================================

    #[test]
    fn test_verify_tls_client_auth_san_uri() {
        let cert_der =
            make_self_signed_cert_with_san("test-san-uri", &[], &[], &["https://example.com"], &[]);
        let cert = parse_client_certificate(&cert_der).expect("parse");

        // Matching URI SAN succeeds
        assert!(
            verify_tls_client_auth(&cert, None, None, None, Some("https://example.com"), None)
                .is_ok(),
            "matching URI SAN should succeed"
        );

        // Non-matching URI SAN fails
        assert!(
            verify_tls_client_auth(&cert, None, None, None, Some("https://other.com"), None)
                .is_err(),
            "non-matching URI SAN should fail"
        );
    }

    // =========================================================================
    // verify_tls_client_auth — SAN IP v4
    // =========================================================================

    #[test]
    fn test_verify_tls_client_auth_san_ip_v4() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let cert_der = make_self_signed_cert_with_san("test-san-ip", &[], &[], &[], &[ip]);
        let cert = parse_client_certificate(&cert_der).expect("parse");

        // IP SAN must be extracted as a canonical IpAddr
        assert_eq!(cert.san_ip, vec![ip]);

        // Matching IP SAN succeeds
        assert!(
            verify_tls_client_auth(&cert, None, None, None, None, Some("192.168.1.1")).is_ok(),
            "matching IP SAN should succeed"
        );

        // Non-matching IP SAN fails
        assert!(
            verify_tls_client_auth(&cert, None, None, None, None, Some("10.0.0.1")).is_err(),
            "non-matching IP SAN should fail"
        );
    }

    // =========================================================================
    // verify_tls_client_auth — SAN IP v6 (RFC 8705 §2.1.2 + RFC 5952)
    // =========================================================================
    //
    // Regression coverage for the IPv6 SAN-IP comparison bug: the cert-side
    // `iPAddress` SAN is parsed from its raw 16 octets, and the registered
    // `tls_client_auth_san_ip` string is parsed to the same `IpAddr` before
    // comparison, so every valid textual representation of one address must
    // authenticate — not only the one rendering the old `format_ip_bytes`
    // helper happened to emit.

    /// Every valid text form of the cert's IPv6 SAN must authenticate against
    /// a `tls_client_auth_san_ip` registered in that same form. This is the
    /// core RFC 8705 §2.1.2 interoperability guarantee and the behaviour that
    /// was broken by the previous verbatim `String == String` comparison.
    #[test]
    fn test_verify_tls_client_auth_san_ipv6_registered_form() {
        let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let cert_der = make_self_signed_cert_with_san("test-san-ipv6", &[], &[], &[], &[ip]);
        let cert = parse_client_certificate(&cert_der).expect("parse");

        // The cert-side SAN is the canonical IpAddr built from the 16 octets.
        assert_eq!(cert.san_ip, vec![ip]);

        // Every valid textual representation of the same 128-bit address must
        // match — these all parse to the same IpAddr as the cert's SAN bytes.
        let matching_forms = [
            "2001:db8::1",                             // RFC 5952 canonical compressed
            "2001:db8:0:0:0:0:0:1",                    // uncompressed, no zero-padding
            "2001:0db8:0000:0000:0000:0000:0000:0001", // fully-expanded zero-padded
            "2001:DB8::1",                             // uppercase hex
            "2001:db8::0000:0000:0000:0:1",            // mixed compressed/padded
        ];
        for form in matching_forms {
            assert!(
                form.parse::<std::net::Ipv6Addr>().is_ok(),
                "test fixture: {form:?} must be a valid Ipv6Addr"
            );
            assert!(
                verify_tls_client_auth(&cert, None, None, None, None, Some(form)).is_ok(),
                "registered form {form:?} must match the cert's IPv6 SAN (same address)"
            );
        }

        // A genuinely different IPv6 address must still be rejected.
        assert!(
            verify_tls_client_auth(&cert, None, None, None, None, Some("2001:db8::2")).is_err(),
            "a different IPv6 address must not match"
        );
    }

    /// A malformed `tls_client_auth_san_ip` that does not parse to any IpAddr
    /// must be rejected with `SubjectMismatch` rather than panicking or
    /// accidentally authenticating.
    #[test]
    fn test_verify_tls_client_auth_san_ip_unparseable_rejected() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let cert_der = make_self_signed_cert_with_san("test-san-ip-bad", &[], &[], &[], &[ip]);
        let cert = parse_client_certificate(&cert_der).expect("parse");

        let result = verify_tls_client_auth(&cert, None, None, None, None, Some("not-an-ip"));
        assert!(
            matches!(result, Err(MtlsError::SubjectMismatch { .. })),
            "unparseable registered IP must yield SubjectMismatch, got: {result:?}"
        );
    }

    /// An IPv4 address registered as an IPv6 text form (or vice versa) must
    /// NOT authenticate against a cert carrying the other family: per
    /// RFC 5280 §4.2.1.6 the `iPAddress` GeneralName encodes the family in
    /// its byte length (4 = IPv4, 16 = IPv6), so the two are distinct
    /// GeneralNames and a registered V4 string must not match a V6 cert SAN
    /// even when both denote the same 32-bit value.
    #[test]
    fn test_verify_tls_client_auth_san_ip_v4_mapped_v6_distinct() {
        let v6 = std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x1234, 0x5678,
        ));
        let cert_der = make_self_signed_cert_with_san("test-san-v4mapped", &[], &[], &[], &[v6]);
        let cert = parse_client_certificate(&cert_der).expect("parse");

        // The IPv4 form `18.52.86.120` denotes the same 32-bit value as the
        // IPv4-mapped IPv6 cert SAN, but they are different GeneralName
        // encodings and must not compare equal.
        assert!(
            verify_tls_client_auth(&cert, None, None, None, None, Some("18.52.86.120")).is_err(),
            "IPv4 text must not match an IPv4-mapped IPv6 SAN (different family)"
        );
        // The native IPv6 text form of the same mapped address must match.
        assert!(
            verify_tls_client_auth(&cert, None, None, None, None, Some("::ffff:18.52.86.120"))
                .is_ok(),
            "the IPv6 text form of the mapped address must match"
        );
    }

    // =========================================================================
    // parse_client_certificate — all SAN types roundtrip
    // =========================================================================

    #[test]
    fn test_parse_certificate_with_sans() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let cert_der = make_self_signed_cert_with_san(
            "test-all-sans",
            &["api.example.com"],
            &["admin@example.com"],
            &["https://example.com/client"],
            &[ip],
        );

        let cert = parse_client_certificate(&cert_der).expect("parse");

        assert_eq!(cert.san_dns, vec!["api.example.com"]);
        assert_eq!(cert.san_email, vec!["admin@example.com"]);
        assert_eq!(cert.san_uri, vec!["https://example.com/client"]);
        assert_eq!(cert.san_ip, vec![ip]);
        assert!(
            cert.subject_dn
                .as_deref()
                .unwrap_or("")
                .contains("test-all-sans"),
            "subject_dn should include CN"
        );
    }

    // =========================================================================
    // parse_client_certificate_pem
    // =========================================================================
    // verify_self_signed_tls_client_auth
    // =========================================================================

    /// Build a JWKS JSON value with the cert's DER as an x5c entry.
    fn make_jwks_with_x5c(cert_der: &[u8]) -> serde_json::Value {
        use base64::Engine;
        let x5c_b64 = base64::engine::general_purpose::STANDARD.encode(cert_der);
        serde_json::json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x5c": [x5c_b64]
                }
            ]
        })
    }

    #[test]
    fn test_verify_self_signed_tls_client_auth_matching() {
        let cert_der = make_test_cert("self-signed-match");
        let cert = parse_client_certificate(&cert_der).expect("parse");
        let jwks = make_jwks_with_x5c(&cert_der);

        let result = verify_self_signed_tls_client_auth(&cert, &jwks);
        assert!(
            result.is_ok(),
            "matching x5c entry must authenticate successfully: {result:?}"
        );
    }

    #[test]
    fn test_verify_self_signed_tls_client_auth_no_match() {
        let cert_a_der = make_test_cert("self-signed-cert-a");
        let cert_b_der = make_test_cert("self-signed-cert-b");
        let cert_a = parse_client_certificate(&cert_a_der).expect("parse cert A");

        // JWKS contains cert B's DER, but cert A is presented
        let jwks = make_jwks_with_x5c(&cert_b_der);

        let result = verify_self_signed_tls_client_auth(&cert_a, &jwks);
        assert!(
            matches!(result, Err(MtlsError::CertificateNotRegistered)),
            "non-matching cert must return CertificateNotRegistered: {result:?}"
        );
    }

    #[test]
    fn test_verify_self_signed_tls_client_auth_no_x5c() {
        let cert_der = make_test_cert("self-signed-no-x5c");
        let cert = parse_client_certificate(&cert_der).expect("parse");

        // JWKS has keys but no x5c field
        let jwks = serde_json::json!({
            "keys": [
                { "kty": "EC", "crv": "P-256", "x": "dGVzdA", "y": "dGVzdA" }
            ]
        });

        let result = verify_self_signed_tls_client_auth(&cert, &jwks);
        assert!(
            matches!(result, Err(MtlsError::CertificateNotRegistered)),
            "JWKS without x5c must return CertificateNotRegistered"
        );
    }

    #[test]
    fn test_verify_self_signed_tls_client_auth_invalid_base64() {
        let cert_der = make_test_cert("self-signed-bad-b64");
        let cert = parse_client_certificate(&cert_der).expect("parse");

        // JWKS with garbage base64 in x5c — must not panic
        let jwks = serde_json::json!({
            "keys": [
                { "kty": "EC", "x5c": ["not!!valid!!base64!!!"] }
            ]
        });

        let result = verify_self_signed_tls_client_auth(&cert, &jwks);
        assert!(
            matches!(result, Err(MtlsError::CertificateNotRegistered)),
            "invalid base64 in x5c must return CertificateNotRegistered, not panic"
        );
    }

    #[test]
    fn test_verify_self_signed_tls_client_auth_empty_keys() {
        let cert_der = make_test_cert("self-signed-empty-keys");
        let cert = parse_client_certificate(&cert_der).expect("parse");

        let jwks = serde_json::json!({ "keys": [] });

        let result = verify_self_signed_tls_client_auth(&cert, &jwks);
        assert!(
            matches!(result, Err(MtlsError::CertificateNotRegistered)),
            "empty keys array must return CertificateNotRegistered"
        );
    }

    // =========================================================================
    // verify_tls_client_auth — SAN DNS case-insensitivity (RFC 4343 / RFC 6125)
    // =========================================================================

    // RFC 4343 (and RFC 6125 §6.4.1 for certificate identity matching): DNS
    // names compare case-insensitively, so a SAN of `Client.Example.COM`
    // must match a registered `client.example.com` and vice versa.
    #[test]
    fn test_verify_tls_client_auth_san_dns_case_insensitive() {
        let cert_der = make_self_signed_cert_with_san(
            "test-san-dns-case",
            &["Client.Example.COM"],
            &[],
            &[],
            &[],
        );
        let cert = parse_client_certificate(&cert_der).expect("parse");

        assert!(
            verify_tls_client_auth(&cert, None, Some("client.example.com"), None, None, None)
                .is_ok(),
            "lowercase registered name must match mixed-case SAN"
        );
        assert!(
            verify_tls_client_auth(&cert, None, Some("CLIENT.EXAMPLE.COM"), None, None, None)
                .is_ok(),
            "uppercase registered name must match mixed-case SAN"
        );
    }

    // RFC 6125 §6.4.1: case folding must not make distinct names match.
    #[test]
    fn test_verify_tls_client_auth_san_dns_case_fold_rejects_different_name() {
        let cert_der = make_self_signed_cert_with_san(
            "test-san-dns-neg",
            &["Client.Example.COM"],
            &[],
            &[],
            &[],
        );
        let cert = parse_client_certificate(&cert_der).expect("parse");

        assert!(
            verify_tls_client_auth(&cert, None, Some("other.example.com"), None, None, None)
                .is_err(),
            "a different DNS name must still mismatch"
        );
    }

    // =========================================================================
    // verify_tls_client_auth — subject DN canonical comparison (RFC 4514)
    // =========================================================================

    // RFC 8705 §2.1.2 matches the certificate subject against the registered
    // `tls_client_auth_subject_dn` expressed as an RFC 4514 string. The
    // comparison must not depend on one specific rendering: spacing after
    // commas and attribute-type casing vary between producers.
    #[test]
    fn test_verify_tls_client_auth_subject_dn_rendering_insensitive() {
        let cert_der = make_test_cert("dn-canon");
        let cert = parse_client_certificate(&cert_der).expect("parse");
        let rendered = cert.subject_dn.as_deref().expect("subject DN");

        // The registered value uses lowercase attribute types; the parsed
        // rendering uses `CN=`. Canonical comparison must equate them.
        let lowercased_attr = rendered.replace("CN=", "cn=");
        assert_ne!(rendered, lowercased_attr, "precondition: strings differ");
        assert!(
            verify_tls_client_auth(&cert, Some(&lowercased_attr), None, None, None, None).is_ok(),
            "attribute-type case must not affect DN matching"
        );
    }

    // RFC 4514: canonicalization must not make distinct DNs match.
    #[test]
    fn test_verify_tls_client_auth_subject_dn_canonical_still_rejects_mismatch() {
        let cert_der = make_test_cert("dn-canon-neg");
        let cert = parse_client_certificate(&cert_der).expect("parse");

        assert!(
            verify_tls_client_auth(&cert, Some("cn=different"), None, None, None, None).is_err(),
            "a different DN must still mismatch after canonicalization"
        );
    }

    // A registered value that is not a parseable RFC 4514 DN falls back to
    // exact string comparison and (mismatching) fails closed.
    #[test]
    fn test_verify_tls_client_auth_subject_dn_unparseable_expected_fails_closed() {
        let cert_der = make_test_cert("dn-unparseable");
        let cert = parse_client_certificate(&cert_der).expect("parse");

        assert!(
            verify_tls_client_auth(&cert, Some("not a dn at all"), None, None, None, None).is_err(),
            "an unparseable registered DN must not match"
        );
    }

    // =========================================================================
    // canonicalize_dn — whitespace-after-comma tolerance (RFC 4514 spacing)
    // =========================================================================

    // The cert-side `Name::to_string` rendering joins RDNs with a bare comma,
    // but operators commonly register DNs with a space after the comma (e.g.
    // copied from `openssl x509 -noout -subject`, whose default output uses
    // `, `). `x509-cert` 0.2.5's `RdnSequence::from_str` splits on
    // a bare `,` without trimming the next segment, so the un-normalized parse
    // failed and `verify_tls_client_auth` fell back to exact equality — which
    // always rejects because the two renderings differ by that one space.
    // The fix strips whitespace immediately following a comma before parsing.

    /// A DN with whitespace after a comma must canonicalize to the same string
    /// as the bare-comma form. Multiple spaces and tabs after a comma are all
    /// stripped so the common operator-facing renderings reduce to one form.
    #[test]
    fn test_canonicalize_dn_tolerates_whitespace_after_comma() {
        let nospace = canonicalize_dn("O=Acme,CN=foo");
        let single_space = canonicalize_dn("O=Acme, CN=foo");
        let multi_space = canonicalize_dn("O=Acme,   CN=foo");
        let tab = canonicalize_dn("O=Acme,\tCN=foo");

        assert!(nospace.is_some(), "bare-comma DN must parse");
        assert!(single_space.is_some(), "comma-space DN must parse");
        assert!(multi_space.is_some(), "comma-multi-space DN must parse");
        assert!(tab.is_some(), "comma-tab DN must parse");

        let nospace = nospace.expect("checked Some above");
        assert_eq!(
            nospace,
            single_space.expect("checked Some above"),
            "single space after comma must not change canonical form"
        );
        assert_eq!(
            nospace,
            multi_space.expect("checked Some above"),
            "multiple spaces after comma must not change canonical form"
        );
        assert_eq!(
            nospace,
            tab.expect("checked Some above"),
            "tab after comma must not change canonical form"
        );
    }

    // =========================================================================
    // canonicalize_dn — whitespace around the type/value `=` separator
    // =========================================================================

    // OpenSSL's `oneline` name format pads the `=` separating each attribute
    // type from its value on both sides: `O = Acme, CN = foo`. An operator
    // reaches it with `openssl x509 -noout -subject -nameopt oneline`; the
    // bare `-subject` default prints `O=Acme, CN=foo` with a bare `=`
    // (verified against OpenSSL 3.6.4), which the comma-space handling
    // already covers. The pre-parser stripped whitespace only after a
    // structural comma, never the `=`-adjacent spaces, so
    // `RdnSequence::from_str` rejected `O ` as a type name and
    // `canonicalize_dn` returned `None` — `verify_tls_client_auth` then fell
    // back to exact string equality and rejected a legitimately matching
    // client. It now also strips whitespace around the first unescaped `=`
    // of each RDN.

    /// A DN with whitespace around the `=` type/value separator must
    /// canonicalize to the same string as the bare-`=` form, in both the
    /// multi-RDN and the single-RDN (the most common operator DN) case. Space
    /// before `=`, after `=`, both, multiple, and tabs are all stripped so
    /// OpenSSL's `oneline` name format reduces to one form.
    #[test]
    fn test_canonicalize_dn_tolerates_whitespace_around_equals() {
        let canonical = canonicalize_dn("O=Acme,CN=foo").expect("bare form parses");

        // Multi-RDN: spaces around the `=` (OpenSSL's `oneline` format).
        let both = canonicalize_dn("O = Acme, CN = foo").expect("spaced `=` parses");
        let before = canonicalize_dn("O =Acme,CN =foo").expect("space-before `=` parses");
        let after = canonicalize_dn("O= Acme,CN= foo").expect("space-after `=` parses");
        let multi = canonicalize_dn("O  =  Acme,  CN  =  foo").expect("multi-space `=` parses");
        let tab = canonicalize_dn("O\t=\tAcme,\tCN\t=\tfoo").expect("tab `=` parses");

        assert_eq!(
            both, canonical,
            "spaces around `=` must not change canonical form (OpenSSL `-nameopt oneline`)"
        );
        assert_eq!(before, canonical, "space before `=` must be stripped");
        assert_eq!(after, canonical, "space after `=` must be stripped");
        assert_eq!(
            multi, canonical,
            "multiple spaces around `=` must be stripped"
        );
        assert_eq!(tab, canonical, "tabs around `=` must be stripped");

        // Single-RDN — the most common operator DN (`CN = foo`), same property.
        let single = canonicalize_dn("CN=foo").expect("single bare parses");
        assert_eq!(
            canonicalize_dn("CN = foo").expect("single spaced parses"),
            single,
            "single-RDN `=`-adjacent whitespace must be stripped"
        );
        assert_eq!(
            canonicalize_dn("CN\t=\tfoo").expect("single tabbed parses"),
            single,
            "single-RDN tab around `=` must be stripped"
        );
    }

    /// The verbatim output of `openssl x509 -noout -subject -nameopt oneline`
    /// must canonicalize identically to the cert-side
    /// `Name::to_string` rendering, so an operator can copy-paste that
    /// command's output as the `tls_client_auth_subject_dn`.
    #[test]
    fn test_canonicalize_dn_oneline_nameopt_matches_canonical() {
        // cert-side rendering: what x509_cert `Name::to_string` emits.
        let cert_side = canonicalize_dn("O=Acme,CN=foo").expect("cert side parses");
        // OpenSSL `-nameopt oneline` rendering of the same subject.
        let openssl_oneline =
            canonicalize_dn("O = Acme, CN = foo").expect("openssl oneline parses");
        assert_eq!(
            openssl_oneline, cert_side,
            "OpenSSL `oneline` output must canonicalize to the cert-side rendering"
        );
    }

    /// Only the *first* unescaped `=` in an RDN is the type/value separator; a
    /// later `=` lives in the value, and whitespace around it is significant.
    /// Stripping separator-adjacent whitespace must not collapse `a = b`-style
    /// interior value whitespace into `a=b`.
    #[test]
    fn test_canonicalize_dn_preserves_whitespace_around_value_equals() {
        let with_value_eq_space =
            canonicalize_dn("CN=a = b").expect("value-internal `=` with spaces parses");
        let without_value_eq_space =
            canonicalize_dn("CN=a=b").expect("value-internal `=` no spaces parses");
        assert_ne!(
            with_value_eq_space, without_value_eq_space,
            "whitespace around a value-internal `=` is significant and must be preserved"
        );
        // x509_cert's `Display` does not escape interior value whitespace (see
        // `test_canonicalize_dn_preserves_non_separator_whitespace`), so the
        // spaces around the value-internal `=` round-trip untouched.
        assert!(
            with_value_eq_space.contains("a = b"),
            "value-internal `=` whitespace must round-trip: got {with_value_eq_space}"
        );
    }

    /// Whitespace NOT following a comma must be preserved: it is part of the
    /// attribute value (RFC 4514 treats unescaped internal whitespace as
    /// significant), so the fix must not turn a different value into a match.
    #[test]
    fn test_canonicalize_dn_preserves_non_separator_whitespace() {
        let with_value_space = canonicalize_dn("CN=foo bar,O=Acme").expect("value space");
        let no_value_space = canonicalize_dn("CN=foobar,O=Acme").expect("no value space");
        assert_ne!(
            with_value_space, no_value_space,
            "internal value whitespace is significant and must be preserved"
        );
        assert_eq!(
            with_value_space, "CN=foo bar,O=Acme",
            "value-internal space must round-trip unchanged"
        );
    }

    /// RFC 4514 §2.4 permits a comma inside an attribute value when it is
    /// escaped, and §4 gives `CN=James \"Jim\" Smith\, III,DC=example,DC=net`
    /// as a valid DN. Only an *unescaped* comma separates RDNs, so the
    /// whitespace strip must not fire after an escaped one — doing so rewrites
    /// `Smith\, III` to `Smith\,III` and changes the value.
    #[test]
    fn test_canonicalize_dn_preserves_space_after_escaped_comma() {
        let rfc_example = canonicalize_dn(r#"CN=James \"Jim\" Smith\, III,DC=example,DC=net"#)
            .expect("RFC 4514 §4 example must parse");
        assert!(
            rfc_example.contains(r"Smith\, III"),
            "space after an escaped comma belongs to the value: got {rfc_example}"
        );

        // The same DN written with a space after the *structural* comma must
        // canonicalize identically — separator spacing is not significant.
        let spaced = canonicalize_dn(r#"CN=Doe\, John, O=Acme"#).expect("spaced separator");
        let tight = canonicalize_dn(r#"CN=Doe\, John,O=Acme"#).expect("tight separator");
        assert_eq!(
            spaced, tight,
            "separator spacing must normalize while the escaped comma is preserved"
        );
        assert!(
            spaced.contains(r"Doe\, John"),
            "escaped comma and its following space must survive: got {spaced}"
        );
    }

    /// Attribute-type names compare case-insensitively (`cn` vs `CN`),
    /// but attribute-value case is significant (`Acme` vs `acme`).
    #[test]
    fn test_canonicalize_dn_attribute_type_case_insensitive_value_sensitive() {
        let upper_types = canonicalize_dn("O=Acme,CN=foo").expect("upper types");
        let lower_types = canonicalize_dn("o=Acme,cn=foo").expect("lower types");
        assert_eq!(
            upper_types, lower_types,
            "attribute-type name case must not affect canonical form"
        );

        let lower_value = canonicalize_dn("O=acme,CN=foo").expect("lower value");
        assert_ne!(
            upper_types, lower_value,
            "attribute-value case must remain significant after canonicalization"
        );
    }

    /// Single-RDN DNs (no comma) are untouched by the comma-space fix and must
    /// still canonicalize, including attribute-type case folding.
    #[test]
    fn test_canonicalize_dn_single_rdn_unchanged() {
        assert_eq!(canonicalize_dn("CN=foo").expect("single RDN"), "CN=foo");
        assert_eq!(
            canonicalize_dn("cn=foo").expect("single RDN lower"),
            "CN=foo",
            "lowercase attribute type must canonicalize to the standard name"
        );
    }

    /// Garbage that is not a valid RFC 4514 DN still returns `None` so the
    /// caller falls back to exact string comparison and fails closed.
    #[test]
    fn test_canonicalize_dn_unparseable_returns_none() {
        assert!(canonicalize_dn("").is_none(), "empty string is not a DN");
        assert!(
            canonicalize_dn("not a dn at all").is_none(),
            "garbage without `=` is not a parseable DN"
        );
    }

    // =========================================================================
    // verify_tls_client_auth — multi-RDN subject DN spacing (end-to-end)
    // =========================================================================

    // End-to-end regression for the comma-space bug: a multi-RDN cert (rendered
    // by `Name::to_string` with bare commas) must authenticate against a
    // registered `tls_client_auth_subject_dn` that differs only by whitespace
    // after the comma. Before the fix this path returned `SubjectMismatch`.

    /// A two-RDN certificate rendered as `O=Acme,CN=foo` must match the same
    /// DN registered with a space after the comma (`O=Acme, CN=foo`), the
    /// no-space form, and a lowercase-attribute-type form — all of which are
    /// spacing/case variants the documented contract says are equivalent.
    #[test]
    fn test_verify_tls_client_auth_subject_dn_multi_rdn_space_insensitive() {
        // Internal order [CN=foo, O=Acme] renders (Display reverses) as
        // "O=Acme,CN=foo" with a bare comma — the cert-side rendering.
        let subject = make_rdn_sequence(&[("2.5.4.3", "foo"), ("2.5.4.10", "Acme")]);
        let cert_der = make_self_signed_cert_with_subject(subject);
        let cert = parse_client_certificate(&cert_der).expect("parse");
        let rendered = cert.subject_dn.as_deref().expect("subject DN");

        // Lock in the fixture rendering so a future change to `Display` fails
        // this test loudly rather than silently weakening the assertions.
        assert_eq!(
            rendered, "O=Acme,CN=foo",
            "fixture: cert renders bare-comma DN"
        );

        // Comma-space form: what `openssl x509 -noout -subject` prints by
        // default. The `=`-padded `O = Acme, CN = foo` form, which `-nameopt
        // oneline` emits, is covered by
        // `test_verify_tls_client_auth_subject_dn_oneline_nameopt`.
        let spaced = "O=Acme, CN=foo";
        assert_ne!(rendered, spaced, "precondition: strings differ by spacing");
        assert!(
            verify_tls_client_auth(&cert, Some(spaced), None, None, None, None).is_ok(),
            "multi-RDN DN differing only by whitespace after the comma must authenticate"
        );

        // Bare-comma form still matches.
        assert!(
            verify_tls_client_auth(&cert, Some("O=Acme,CN=foo"), None, None, None, None).is_ok(),
            "multi-RDN DN with bare commas must authenticate"
        );

        // Lowercase attribute-type names still match (value case preserved).
        assert!(
            verify_tls_client_auth(&cert, Some("o=Acme, cn=foo"), None, None, None, None).is_ok(),
            "multi-RDN DN with lowercase attribute types must authenticate"
        );
    }

    /// Canonicalization must not make distinct multi-RDN DNs match: a different
    /// value, a different number of RDNs, and a different RDN ordering must
    /// all still be rejected — including when the registered value uses the
    // comma-space rendering the fix now tolerates.
    #[test]
    fn test_verify_tls_client_auth_subject_dn_multi_rdn_still_rejects_mismatch() {
        let subject = make_rdn_sequence(&[("2.5.4.3", "foo"), ("2.5.4.10", "Acme")]);
        let cert_der = make_self_signed_cert_with_subject(subject);
        let cert = parse_client_certificate(&cert_der).expect("parse");

        // Different attribute value (CN=bar vs CN=foo), comma-space rendering.
        assert!(
            verify_tls_client_auth(&cert, Some("O=Acme, CN=bar"), None, None, None, None).is_err(),
            "a multi-RDN DN with a different value must mismatch"
        );
        // Different organization value.
        assert!(
            verify_tls_client_auth(&cert, Some("O=Other, CN=foo"), None, None, None, None).is_err(),
            "a multi-RDN DN with a different org value must mismatch"
        );
        // Fewer RDNs (single-RDN registration vs multi-RDN cert).
        assert!(
            verify_tls_client_auth(&cert, Some("CN=foo"), None, None, None, None).is_err(),
            "a single-RDN registration must not match a multi-RDN cert"
        );
        // Same RDNs in a different order — DN ordering is significant.
        assert!(
            verify_tls_client_auth(&cert, Some("CN=foo, O=Acme"), None, None, None, None).is_err(),
            "a different RDN ordering must mismatch (DN ordering is significant)"
        );
    }

    // =========================================================================
    // verify_tls_client_auth — OpenSSL `oneline` subject (`=`-spacing)
    // =========================================================================

    // End-to-end regression for the `=`-adjacent whitespace bug: an operator
    // who registers a `tls_client_auth_subject_dn` by copying the verbatim
    // output of `openssl x509 -noout -subject -nameopt oneline` (which pads
    // `=` on both sides, e.g. `O = Acme, CN = foo`) must authenticate.
    // Before the fix `canonicalize_dn` returned `None` on the verbatim form
    // and `verify_tls_client_auth` fell back to exact string equality — which
    // rejects because the cert-side `Name::to_string` rendering has no
    // `=`-padding.

    /// A two-RDN cert rendered `O=Acme,CN=foo` must authenticate against the
    /// verbatim `-nameopt oneline` output `O = Acme, CN = foo` and against every
    /// `=`-spacing/attribute-type-case variant of it.
    #[test]
    fn test_verify_tls_client_auth_subject_dn_oneline_nameopt() {
        let subject = make_rdn_sequence(&[("2.5.4.3", "foo"), ("2.5.4.10", "Acme")]);
        let cert_der = make_self_signed_cert_with_subject(subject);
        let cert = parse_client_certificate(&cert_der).expect("parse");
        let rendered = cert.subject_dn.as_deref().expect("subject DN");
        assert_eq!(
            rendered, "O=Acme,CN=foo",
            "fixture: cert renders bare-`=` bare-comma DN"
        );

        // The verbatim `openssl x509 -noout -subject -nameopt oneline` output
        // (minus the `subject=` prefix) — must authenticate.
        let openssl_oneline = "O = Acme, CN = foo";
        assert_ne!(
            rendered, openssl_oneline,
            "precondition: cert rendering differs from the `oneline` form by `=`-spacing"
        );
        assert!(
            verify_tls_client_auth(&cert, Some(openssl_oneline), None, None, None, None).is_ok(),
            "OpenSSL `oneline` output must authenticate against the matching cert"
        );

        // Variants that differ only by `=`-spacing or attribute-type case
        // (value case preserved) must also authenticate.
        for registered in [
            "O = Acme,CN = foo",
            "O=Acme, CN = foo",
            "O= Acme,CN= foo",
            "O =Acme,CN =foo",
            "O  =  Acme,  CN  =  foo",
            "o = Acme, cn = foo",
        ] {
            assert!(
                verify_tls_client_auth(&cert, Some(registered), None, None, None, None).is_ok(),
                "`=`-spacing/case variant {registered:?} must authenticate"
            );
        }
    }

    /// The single-RDN case — `CN = foo`, the most common operator DN — must
    /// authenticate against a `CN=foo` cert using the verbatim `-nameopt
    /// oneline` output, and against `=`-spacing variants of it.
    #[test]
    fn test_verify_tls_client_auth_subject_dn_single_rdn_oneline_nameopt() {
        let cert_der = make_test_cert("foo");
        let cert = parse_client_certificate(&cert_der).expect("parse");
        let rendered = cert.subject_dn.as_deref().expect("subject DN");
        // `make_test_cert` builds a CN-only subject.
        assert_eq!(
            rendered, "CN=foo",
            "fixture: single-RDN cert renders as CN=foo"
        );

        // OpenSSL `-nameopt oneline` output for a single-CN subject.
        assert!(
            verify_tls_client_auth(&cert, Some("CN = foo"), None, None, None, None).is_ok(),
            "single-RDN OpenSSL `oneline` `CN = foo` must authenticate"
        );
        for registered in ["CN= foo", "CN =foo", "CN  =  foo", "cn = foo"] {
            assert!(
                verify_tls_client_auth(&cert, Some(registered), None, None, None, None).is_ok(),
                "single-RDN `=`-spacing/case variant {registered:?} must authenticate"
            );
        }
    }

    /// `=`-spacing tolerance must not make a genuinely different DN match: a
    /// different value, a different number of RDNs, and a different RDN order
    /// must all still be rejected — including when the registered value uses
    /// the `=`-spaced rendering the fix now tolerates.
    #[test]
    fn test_verify_tls_client_auth_subject_dn_eq_spacing_still_rejects_mismatch() {
        let subject = make_rdn_sequence(&[("2.5.4.3", "foo"), ("2.5.4.10", "Acme")]);
        let cert_der = make_self_signed_cert_with_subject(subject);
        let cert = parse_client_certificate(&cert_der).expect("parse");

        // Same `=`-spacing as the OpenSSL default, but a different CN value.
        assert!(
            verify_tls_client_auth(&cert, Some("O = Acme, CN = bar"), None, None, None, None)
                .is_err(),
            "a `=`-spaced DN with a different value must mismatch"
        );
        // Different org value.
        assert!(
            verify_tls_client_auth(&cert, Some("O = Other, CN = foo"), None, None, None, None)
                .is_err(),
            "a `=`-spaced DN with a different org value must mismatch"
        );
        // Fewer RDNs (single-RDN registration vs multi-RDN cert).
        assert!(
            verify_tls_client_auth(&cert, Some("CN = foo"), None, None, None, None).is_err(),
            "a `=`-spaced single-RDN registration must not match a multi-RDN cert"
        );
        // Same RDNs, different order — DN ordering is significant.
        assert!(
            verify_tls_client_auth(&cert, Some("CN = foo, O = Acme"), None, None, None, None)
                .is_err(),
            "a `=`-spaced DN with a different RDN order must mismatch"
        );
    }
}
