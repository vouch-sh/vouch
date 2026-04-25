// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared PEM decoding utilities.
//!
//! Supports both raw PEM content and base64-encoded PEM, which is useful for
//! environment variables where multiline values are inconvenient.
//!
//! ```bash
//! # Encode a PEM file for use in an environment variable:
//! cat your-key.pem | base64 | tr -d '\n'
//! ```

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

/// Decode PEM content that may be base64-encoded.
///
/// Supports:
/// - Raw PEM content (returned as-is)
/// - Base64-encoded PEM (standard or URL-safe base64)
///
/// For environment variables, base64 encode the entire PEM file:
/// ```bash
/// cat your-key.pem | base64 | tr -d '\n'
/// ```
pub(crate) fn decode_base64_pem(content: &str) -> Result<String> {
    let trimmed = content.trim();

    if trimmed.starts_with("-----BEGIN") {
        return Ok(trimmed.to_string());
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

    Ok(pem_trimmed.to_string())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_already_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let result = decode_base64_pem(pem).unwrap();
        assert_eq!(result, pem);
    }

    #[test]
    fn test_decode_base64_encoded() {
        let pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let encoded = STANDARD.encode(pem.as_bytes());
        let result = decode_base64_pem(&encoded).unwrap();
        assert_eq!(result, pem);
    }

    #[test]
    fn test_decode_url_safe_base64() {
        let pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let encoded = URL_SAFE_NO_PAD.encode(pem.as_bytes());
        let result = decode_base64_pem(&encoded).unwrap();
        assert_eq!(result, pem);
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
    fn test_decode_with_whitespace() {
        let pem = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";
        let encoded = format!("  {}  ", STANDARD.encode(pem.as_bytes()));
        let result = decode_base64_pem(&encoded).unwrap();
        assert_eq!(result, pem);
    }

    #[test]
    fn test_decode_openssh_key() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----";
        let encoded = STANDARD.encode(pem.as_bytes());
        let result = decode_base64_pem(&encoded).unwrap();
        assert_eq!(result, pem);
    }
}
