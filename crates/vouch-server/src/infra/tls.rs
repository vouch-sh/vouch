// SPDX-License-Identifier: Apache-2.0 OR MIT
//! TLS configuration for optional HTTPS support with hot reloading.
//!
//! Both the main HTTPS listener and the mTLS listener (see
//! `mtls_listener.rs`) support TLS 1.3 and TLS 1.2 with BCP 195
//! (RFC 9325) cipher suites only. TLS 1.2 uses only ECDHE+AEAD suites
//! per FAPI2-SP-FINAL-5.2.2.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use secrecy::{ExposeSecret, SecretString};

use crate::config::ServerConfig;

/// Build TLS configuration from ServerConfig.
pub fn build_tls_config(config: &ServerConfig) -> Result<RustlsConfig> {
    let cert_pem = config
        .tls_cert
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS certificate not configured"))?;

    let key_secret = config
        .tls_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS private key not configured"))?;

    let cert_was_base64 = !cert_pem.trim().starts_with("-----BEGIN");
    let cert_bytes = crate::crypto::pem::decode_base64_pem(cert_pem)
        .context("Failed to decode TLS certificate")?
        .into_bytes();

    let key_was_base64 = !key_secret.expose_secret().trim().starts_with("-----BEGIN");
    let key_bytes = crate::crypto::pem::decode_base64_pem(key_secret.expose_secret())
        .context("Failed to decode TLS private key")?
        .into_bytes();

    let cert_source = if cert_was_base64 {
        "base64-encoded PEM"
    } else {
        "PEM"
    };
    let key_source = if key_was_base64 {
        "base64-encoded PEM"
    } else {
        "PEM"
    };
    tracing::info!(
        "TLS certificate loaded ({}, {} bytes), private key loaded ({}, {} bytes)",
        cert_source,
        cert_bytes.len(),
        key_source,
        key_bytes.len(),
    );

    let server_config = build_server_config(&cert_bytes, &key_bytes)
        .context("Failed to build TLS configuration from certificate and key")?;

    Ok(RustlsConfig::from_config(server_config))
}

/// Reload TLS configuration from ServerConfig values.
///
/// This is used by the S3 config poller when TLS cert/key changes.
/// The cert and key are expected to be base64-encoded PEM strings.
pub fn reload_tls_from_config(
    tls_config: &RustlsConfig,
    cert: &str,
    key: &SecretString,
) -> Result<()> {
    let cert_bytes = crate::crypto::pem::decode_base64_pem(cert)
        .context("Failed to decode TLS certificate")?
        .into_bytes();
    let key_bytes = crate::crypto::pem::decode_base64_pem(key.expose_secret())
        .context("Failed to decode TLS private key")?
        .into_bytes();

    let server_config = build_server_config(&cert_bytes, &key_bytes)
        .context("Failed to reload TLS configuration from S3 config")?;

    tls_config.reload_from_config(server_config);
    Ok(())
}

/// BCP 195 (RFC 9325) crypto provider with only ECDHE+AEAD cipher suites.
///
/// Shared by both the main TLS listener and the mTLS listener to satisfy
/// FAPI2-SP-FINAL-5.2.2 (`RequireOnlyBCP195RecommendedCiphersForTLS12`).
/// All TLS 1.3 suites are BCP 195 compliant by design; TLS 1.2 is restricted
/// to ECDHE+AEAD suites only.
pub(crate) fn bcp195_crypto_provider() -> rustls::crypto::CryptoProvider {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let bcp195_suites: Vec<rustls::SupportedCipherSuite> = provider
        .cipher_suites
        .iter()
        .filter(|cs| {
            matches!(
                cs.suite(),
                // TLS 1.3 suites (all BCP 195 compliant)
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
                    | rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                    | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                    // TLS 1.2 ECDHE+AEAD suites (BCP 195 recommended)
                    | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                    | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            )
        })
        .copied()
        .collect();

    rustls::crypto::CryptoProvider {
        cipher_suites: bcp195_suites,
        ..provider
    }
}

/// Build a hardened `rustls::ServerConfig` from PEM-encoded certificate and key.
///
/// Enforces:
/// - TLS 1.3 + TLS 1.2 with BCP 195 (RFC 9325) cipher suites only
/// - ALPN: h2, http/1.1
/// - No client authentication (public-facing server)
fn build_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<rustls::ServerConfig>> {
    validate_pem(cert_pem, "CERTIFICATE").context("Invalid TLS certificate format")?;
    validate_pem(key_pem, "PRIVATE KEY").context("Invalid TLS private key format")?;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse PEM certificate chain")?;

    let key = PrivateKeyDer::from_pem_slice(key_pem).context("Failed to parse PEM private key")?;

    let mut config =
        rustls::ServerConfig::builder_with_provider(Arc::new(bcp195_crypto_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| anyhow::anyhow!("Failed to configure TLS versions: {e}"))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Failed to build rustls ServerConfig")?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    tracing::info!(
        "TLS configuration: TLS 1.3 + TLS 1.2 (BCP 195 ciphers only), ALPN=[h2, http/1.1]"
    );

    Ok(Arc::new(config))
}

/// Parse TLS certificate chain and private key from PEM bytes.
///
/// Used by the mTLS listener to reuse the same server identity as the
/// main HTTPS listener.
pub(crate) fn parse_server_cert_and_key(
    config: &ServerConfig,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert_pem = config
        .tls_cert
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS certificate not configured"))?;
    let key_secret = config
        .tls_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS private key not configured"))?;

    parse_cert_and_key_pem(cert_pem, key_secret)
}

/// Parse a certificate chain and private key from (possibly base64-wrapped)
/// PEM strings. Shared by mTLS listener startup and certificate hot reload.
pub(crate) fn parse_cert_and_key_pem(
    cert_pem: &str,
    key_secret: &SecretString,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert_bytes = crate::crypto::pem::decode_base64_pem(cert_pem)
        .context("Failed to decode TLS certificate")?
        .into_bytes();
    let key_bytes = crate::crypto::pem::decode_base64_pem(key_secret.expose_secret())
        .context("Failed to decode TLS private key")?
        .into_bytes();

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse PEM certificate chain")?;

    let key =
        PrivateKeyDer::from_pem_slice(&key_bytes).context("Failed to parse PEM private key")?;

    Ok((certs, key))
}

/// Validate that PEM content contains expected type.
fn validate_pem(pem_bytes: &[u8], expected_type: &str) -> Result<()> {
    let pem_str = std::str::from_utf8(pem_bytes).context("PEM content is not valid UTF-8")?;

    if !pem_str.contains(expected_type) {
        bail!(
            "PEM does not contain expected type '{}'. Found: {}...",
            expected_type,
            pem_str.get(..50).unwrap_or(pem_str)
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pem_certificate() {
        let pem = b"-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----";
        assert!(validate_pem(pem, "CERTIFICATE").is_ok());
        assert!(validate_pem(pem, "PRIVATE KEY").is_err());
    }

    #[test]
    fn test_validate_pem_private_key() {
        let pem = b"-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----";
        assert!(validate_pem(pem, "PRIVATE KEY").is_ok());
        assert!(validate_pem(pem, "CERTIFICATE").is_err());
    }

    #[test]
    fn test_validate_pem_rsa_private_key() {
        // RSA PRIVATE KEY also contains "PRIVATE KEY"
        let pem = b"-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----";
        assert!(validate_pem(pem, "PRIVATE KEY").is_ok());
    }

    #[test]
    fn test_validate_pem_ec_private_key() {
        // EC PRIVATE KEY also contains "PRIVATE KEY"
        let pem = b"-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----";
        assert!(validate_pem(pem, "PRIVATE KEY").is_ok());
    }

    // Throwaway self-signed P-256 cert + PKCS#8 key, generated for tests only.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBiDCCAS2gAwIBAgIUAzsi4KkqvGaw6UTFs4DrQEe2KWwwCgYIKoZIzj0EAwIw\n\
GTEXMBUGA1UEAwwOdm91Y2gtdGxzLXRlc3QwHhcNMjYwNjEwMTYxMjM3WhcNMzYw\n\
NjA3MTYxMjM3WjAZMRcwFQYDVQQDDA52b3VjaC10bHMtdGVzdDBZMBMGByqGSM49\n\
AgEGCCqGSM49AwEHA0IABAOqxc9YgMgXu2BGQ3KOgFNtVxG7pdencd5TOnjrr6zJ\n\
nPi66MVoVlQ9bi3ydlRJ1ce7HHOEui/G0U0aoDJtgVmjUzBRMB0GA1UdDgQWBBQW\n\
yEA6dBvaxTzloNCzXuJLG5z9/DAfBgNVHSMEGDAWgBQWyEA6dBvaxTzloNCzXuJL\n\
G5z9/DAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQC9cwWPeNND\n\
WFbJkO8dqEVE69Xzdj+NMgenQFOJsOW2yAIhAISz7zP/KDBC6jVhH7qJTR9E7Rnr\n\
3wT8S2AL3BFHW6+2\n\
-----END CERTIFICATE-----\n";

    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghUolejGt3e2SfwZJ\n\
BRRya1VbXh8fYhiJfLvrVBbs/lqhRANCAAQDqsXPWIDIF7tgRkNyjoBTbVcRu6XX\n\
p3HeUzp466+syZz4uujFaFZUPW4t8nZUSdXHuxxzhLovxtFNGqAybYFZ\n\
-----END PRIVATE KEY-----\n";

    #[test]
    fn test_build_server_config_parses_real_pem() {
        // Exercises the rustls-pki-types PemObject parsing path end-to-end:
        // PEM cert chain + PKCS#8 key must yield a usable ServerConfig.
        let config = build_server_config(TEST_CERT_PEM.as_bytes(), TEST_KEY_PEM.as_bytes());
        assert!(
            config.is_ok(),
            "valid PEM cert/key must build a ServerConfig, got: {:?}",
            config.err()
        );
    }

    #[test]
    fn test_build_server_config_rejects_malformed_cert_pem() {
        // Passes the validate_pem check (contains "CERTIFICATE") but has
        // undecodable base64, so PemObject parsing must surface an error.
        let bad_cert =
            b"-----BEGIN CERTIFICATE-----\nnot valid base64 @@@@\n-----END CERTIFICATE-----\n";
        let config = build_server_config(bad_cert, TEST_KEY_PEM.as_bytes());
        assert!(
            config.is_err(),
            "malformed certificate PEM must be rejected"
        );
    }
}
