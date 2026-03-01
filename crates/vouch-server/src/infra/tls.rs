// SPDX-License-Identifier: BUSL-1.1
//! TLS configuration for optional HTTPS support with hot reloading.
//!
//! Enforces TLS 1.3 only — TLS 1.2 is compiled out via rustls feature flags
//! and explicitly excluded via `builder_with_protocol_versions`. This eliminates
//! CBC mode attacks, RSA key exchange, and protocol downgrade vectors.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum_server::tls_rustls::RustlsConfig;
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

/// Build a hardened `rustls::ServerConfig` from PEM-encoded certificate and key.
///
/// Enforces:
/// - TLS 1.3 only (no TLS 1.2 or earlier)
/// - ALPN: h2, http/1.1
/// - No client authentication (public-facing server)
fn build_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<rustls::ServerConfig>> {
    validate_pem(cert_pem, "CERTIFICATE").context("Invalid TLS certificate format")?;
    validate_pem(key_pem, "PRIVATE KEY").context("Invalid TLS private key format")?;

    let certs: Vec<rustls::pki_types::CertificateDer<'_>> = rustls_pemfile::certs(&mut &*cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse PEM certificate chain")?;

    let key = rustls_pemfile::private_key(&mut &*key_pem)
        .context("Failed to parse PEM private key")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in PEM data"))?;

    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Failed to build rustls ServerConfig")?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    tracing::info!("TLS configuration: TLS 1.3 only, ALPN=[h2, http/1.1]");

    Ok(Arc::new(config))
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
    #![allow(clippy::unwrap_used)]
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
}
