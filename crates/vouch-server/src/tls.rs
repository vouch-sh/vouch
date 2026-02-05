// SPDX-License-Identifier: BUSL-1.1
//! TLS configuration for optional HTTPS support with hot reloading.

use anyhow::{Context, Result, bail};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
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

    let cert_bytes = decode_base64_pem(&cert_env).context("Failed to decode TLS certificate")?;
    let key_bytes = decode_base64_pem(&key_env).context("Failed to decode TLS private key")?;

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
    let cert_bytes = decode_base64_pem(cert).context("Failed to decode TLS certificate")?;
    let key_bytes =
        decode_base64_pem(key.expose_secret()).context("Failed to decode TLS private key")?;

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

    let cert_bytes = decode_base64_pem(cert_pem).context("Failed to decode TLS certificate")?;
    let key_bytes = decode_base64_pem(key_secret.expose_secret())
        .context("Failed to decode TLS private key")?;

    validate_pem(&cert_bytes, "CERTIFICATE").context("Invalid TLS certificate format")?;
    validate_pem(&key_bytes, "PRIVATE KEY").context("Invalid TLS private key format")?;

    Ok((cert_bytes, key_bytes))
}

/// Decode base64-encoded PEM content.
/// Supports both URL-safe and standard base64. If already PEM, returns as-is.
fn decode_base64_pem(content: &str) -> Result<Vec<u8>> {
    let trimmed = content.trim();

    if trimmed.starts_with("-----BEGIN") {
        return Ok(trimmed.as_bytes().to_vec());
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| STANDARD.decode(trimmed))
        .context("Invalid base64 encoding")?;

    let pem_str = std::str::from_utf8(&decoded).context("Decoded content is not valid UTF-8")?;
    let pem_trimmed = pem_str.trim().trim_start_matches('\u{feff}');

    if !pem_trimmed.starts_with("-----BEGIN") {
        bail!(
            "Expected base64-encoded PEM starting with '-----BEGIN', got {} bytes of non-PEM data",
            decoded.len()
        );
    }

    Ok(pem_trimmed.as_bytes().to_vec())
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
    fn test_decode_already_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let result = decode_base64_pem(pem).unwrap();
        assert_eq!(result, pem.as_bytes());
    }

    #[test]
    fn test_decode_base64_encoded() {
        let pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let encoded = STANDARD.encode(pem.as_bytes());
        let result = decode_base64_pem(&encoded).unwrap();
        assert_eq!(result, pem.as_bytes());
    }

    #[test]
    fn test_decode_url_safe_base64() {
        let pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let encoded = URL_SAFE_NO_PAD.encode(pem.as_bytes());
        let result = decode_base64_pem(&encoded).unwrap();
        assert_eq!(result, pem.as_bytes());
    }

    #[test]
    fn test_decode_invalid() {
        assert!(decode_base64_pem("not-valid!!!").is_err());
    }

    #[test]
    fn test_decode_base64_non_pem() {
        // Valid base64 but not PEM content
        let encoded = STANDARD.encode("just some text");
        assert!(decode_base64_pem(&encoded).is_err());
    }

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
