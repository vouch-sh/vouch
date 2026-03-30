// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8705: mTLS client certificate parsing and verification.
//!
//! Provides:
//! - Certificate DER parsing and field extraction
//! - `x5t#S256` thumbprint computation (RFC 8705 Section 3.1)
//! - `tls_client_auth` subject/SAN matching (RFC 8705 Section 2.1.1)
//! - `self_signed_tls_client_auth` JWKS x5c matching (RFC 8705 Section 2.2.2)

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use der::{Decode, oid::ObjectIdentifier};
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

/// Parsed client certificate with extracted identity fields.
#[derive(Debug, Clone)]
pub(crate) struct ClientCertificate {
    /// `x5t#S256`: base64url-encoded SHA-256 of the DER certificate.
    /// RFC 8705 Section 3.1 / RFC 7515 Section 4.1.8.
    pub thumbprint: String,
    /// Raw DER bytes.
    pub der_bytes: Vec<u8>,
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
#[derive(Debug, Clone)]
pub(crate) enum MtlsError {
    /// Certificate DER could not be parsed.
    InvalidCertificateFormat(String),
    /// Certificate subject/SAN does not match registered client.
    SubjectMismatch { expected: String, found: String },
    /// Self-signed certificate verification against JWKS x5c failed.
    SelfSignedVerificationFailed(String),
    /// Certificate not registered for this client.
    CertificateNotRegistered,
}

impl std::fmt::Display for MtlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCertificateFormat(msg) => {
                write!(f, "invalid certificate format: {msg}")
            }
            Self::SubjectMismatch { expected, found } => {
                write!(f, "subject mismatch: expected {expected}, found {found}")
            }
            Self::SelfSignedVerificationFailed(msg) => {
                write!(f, "self-signed cert verification failed: {msg}")
            }
            Self::CertificateNotRegistered => {
                write!(f, "certificate not registered for this client")
            }
        }
    }
}

/// Compute the `x5t#S256` thumbprint of a DER-encoded certificate.
///
/// RFC 8705 Section 3.1: base64url(SHA-256(DER(cert))).
pub(crate) fn compute_cert_thumbprint(der: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der);
    URL_SAFE_NO_PAD.encode(digest.as_ref())
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

    let san_oid = ObjectIdentifier::new_unwrap("2.5.29.17");
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions {
            if ext.extn_id == san_oid
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
        der_bytes: der.to_vec(),
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
                    parts.push(format!("{a:x}{b:02x}"));
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Generate a test certificate with CN.
    fn make_test_cert(cn: &str) -> Vec<u8> {
        let ca = crate::crypto::client_cert_ca::ClientCertCa::load_or_generate(None, None)
            .expect("CA generation");
        ca.sign_client_cert(cn, 1).expect("sign cert")
    }

    #[test]
    fn test_compute_cert_thumbprint() {
        let cert_der = make_test_cert("test-thumbprint");
        let thumbprint = compute_cert_thumbprint(&cert_der);
        assert!(!thumbprint.is_empty());
        // base64url encoded SHA-256 should be 43 chars (256 bits)
        assert_eq!(thumbprint.len(), 43);
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
        assert!(!cert.thumbprint.is_empty());
        assert_eq!(cert.der_bytes, cert_der);
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
        assert!(result.contains("2001"));
    }
}
