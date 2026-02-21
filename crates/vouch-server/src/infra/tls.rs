// SPDX-License-Identifier: BUSL-1.1
//! TLS configuration for optional HTTPS support with hot reloading.

use anyhow::{Context, Result, bail};
use axum_server::tls_rustls::RustlsConfig;
use secrecy::{ExposeSecret, SecretString};

use crate::config::ServerConfig;

/// Build TLS configuration from ServerConfig.
pub async fn build_tls_config(config: &ServerConfig) -> Result<RustlsConfig> {
    let (cert_bytes, key_bytes) = load_cert_and_key(config)?;

    RustlsConfig::from_pem(cert_bytes, key_bytes)
        .await
        .context("Failed to build TLS configuration from certificate and key")
}

/// Reload TLS configuration by re-reading environment variables.
///
/// This reads fresh values from the environment (not from config),
/// allowing certificate updates without process restart.
pub async fn reload_tls_config(tls_config: &RustlsConfig) -> Result<()> {
    let cert_env = std::env::var("VOUCH_TLS_CERT").context("VOUCH_TLS_CERT not set")?;
    let key_env = std::env::var("VOUCH_TLS_KEY").context("VOUCH_TLS_KEY not set")?;

    let cert_bytes = crate::crypto::pem::decode_base64_pem(&cert_env)
        .context("Failed to decode TLS certificate")?
        .into_bytes();
    let key_bytes = crate::crypto::pem::decode_base64_pem(&key_env)
        .context("Failed to decode TLS private key")?
        .into_bytes();

    validate_pem(&cert_bytes, "CERTIFICATE").context("Invalid TLS certificate format")?;
    validate_pem(&key_bytes, "PRIVATE KEY").context("Invalid TLS private key format")?;

    tls_config
        .reload_from_pem(cert_bytes, key_bytes)
        .await
        .context("Failed to reload TLS configuration")
}

/// Reload TLS configuration from ServerConfig values.
///
/// This is used by the S3 config poller when TLS cert/key changes.
/// The cert and key are expected to be base64-encoded PEM strings.
pub async fn reload_tls_from_config(
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

    validate_pem(&cert_bytes, "CERTIFICATE").context("Invalid TLS certificate format")?;
    validate_pem(&key_bytes, "PRIVATE KEY").context("Invalid TLS private key format")?;

    tls_config
        .reload_from_pem(cert_bytes, key_bytes)
        .await
        .context("Failed to reload TLS configuration")
}

/// Load and decode certificate and key from config.
fn load_cert_and_key(config: &ServerConfig) -> Result<(Vec<u8>, Vec<u8>)> {
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

    validate_pem(&cert_bytes, "CERTIFICATE").context("Invalid TLS certificate format")?;
    validate_pem(&key_bytes, "PRIVATE KEY").context("Invalid TLS private key format")?;

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

    Ok((cert_bytes, key_bytes))
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
