// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8705: mTLS client certificate parsing and verification.
//!
//! Provides:
//! - Certificate DER parsing and field extraction
//! - `x5t#S256` thumbprint computation (RFC 8705 Section 3.1)
//! - `tls_client_auth` subject/SAN matching (RFC 8705 Section 2.1.1)
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
    pub san_ip: Vec<String>,
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
                            san_ip.push(format_ip_bytes(ip.as_bytes()));
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

/// Format IP address bytes to string.
fn format_ip_bytes(bytes: &[u8]) -> String {
    match bytes {
        [a, b, c, d] => format!("{a}.{b}.{c}.{d}"),
        [..] if bytes.len() == 16 => {
            let mut parts = Vec::new();
            for chunk in bytes.chunks(2) {
                if let (Some(&a), Some(&b)) = (chunk.first(), chunk.get(1)) {
                    parts.push(format!("{a:02x}{b:02x}"));
                }
            }
            parts.join(":")
        }
        _ => hex::encode(bytes),
    }
}

/// Verify `tls_client_auth` — match certificate against registered
/// subject DN or SAN fields (RFC 8705 Section 2.1.1).
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
        if found == expected {
            return Ok(());
        }
        return Err(MtlsError::SubjectMismatch {
            expected: expected.to_string(),
            found: found.to_string(),
        });
    }

    if let Some(expected) = expected_san_dns {
        if cert.san_dns.iter().any(|d| d == expected) {
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
        if cert.san_ip.iter().any(|i| i == expected) {
            return Ok(());
        }
        return Err(MtlsError::SubjectMismatch {
            expected: format!("IP:{expected}"),
            found: format!("IP:{}", cert.san_ip.join(",")),
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
    fn test_format_ip_bytes_v4() {
        assert_eq!(format_ip_bytes(&[192, 168, 1, 1]), "192.168.1.1");
    }

    #[test]
    fn test_format_ip_bytes_v6() {
        let bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result = format_ip_bytes(&bytes);
        assert_eq!(result, "2001:0db8:0000:0000:0000:0000:0000:0001");
    }

    // =========================================================================
    // verify_tls_client_auth — all-None case (RFC 8705 Section 2.1.1)
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
    // format_ip_bytes — IPv6 leading-zero padding
    // =========================================================================

    /// IPv6 bytes with leading zeros must be zero-padded to 4 hex digits per group.
    /// For example, the bytes [0x00, 0x01, ...] must produce "0001:..." not "1:...".
    #[test]
    fn test_format_ip_bytes_zero_padding() {
        // 0x0001:0000:0000:0000:0000:0000:0000:0001
        let bytes = [
            0x00u8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let result = format_ip_bytes(&bytes);
        assert_eq!(result, "0001:0000:0000:0000:0000:0000:0000:0001");
        assert!(
            result.starts_with("0001"),
            "leading-zero group must be zero-padded: got {result}"
        );
    }

    // =========================================================================
    // format_ip_bytes — unknown / non-standard length falls back to hex
    // =========================================================================

    /// Bytes that are neither 4 (IPv4) nor 16 (IPv6) bytes long must fall
    /// back to `hex::encode` rather than panicking or producing garbage.
    #[test]
    fn test_format_ip_bytes_unknown_length() {
        // 5 bytes — not IPv4 (4) or IPv6 (16)
        assert_eq!(
            format_ip_bytes(&[0xde, 0xad, 0xbe, 0xef, 0x42]),
            "deadbeef42"
        );
    }

    /// A single byte must also fall back to hex (not crash).
    #[test]
    fn test_format_ip_bytes_single_byte_hex_fallback() {
        assert_eq!(format_ip_bytes(&[0x0f]), "0f");
    }

    /// An empty byte slice must produce an empty string (hex of nothing).
    #[test]
    fn test_format_ip_bytes_empty_slice() {
        assert_eq!(format_ip_bytes(&[]), "");
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

        // IP SAN must be extracted correctly
        assert_eq!(cert.san_ip, vec!["192.168.1.1"]);

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
        assert_eq!(cert.san_ip, vec!["10.0.0.1"]);
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
}
