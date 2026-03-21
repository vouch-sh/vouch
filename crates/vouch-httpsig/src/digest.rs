// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9530 Content-Digest field generation and verification.
//!
//! Content-Digest provides end-to-end integrity for HTTP message bodies.
//! The digest is formatted as an SFV Dictionary with standard base64 byte sequences.

use aws_lc_rs::constant_time;
use aws_lc_rs::digest;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::HttpSigError;

/// Supported digest algorithms per RFC 9530.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256 digest.
    Sha256,
    /// SHA-512 digest.
    Sha512,
}

impl DigestAlgorithm {
    fn algorithm_name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha512 => "sha-512",
        }
    }

    fn digest_algorithm(self) -> &'static digest::Algorithm {
        match self {
            Self::Sha256 => &digest::SHA256,
            Self::Sha512 => &digest::SHA512,
        }
    }
}

/// Compute a Content-Digest header value for the given body.
///
/// Returns a string in SFV Dictionary format: `sha-256=:base64(hash):`
#[must_use]
pub fn content_digest(body: &[u8], algorithm: DigestAlgorithm) -> String {
    let hash = digest::digest(algorithm.digest_algorithm(), body);
    let b64 = STANDARD.encode(hash.as_ref());
    format!("{}=:{}:", algorithm.algorithm_name(), b64)
}

/// Set the `Content-Digest` header on a header map.
///
/// # Errors
///
/// Returns [`HttpSigError::BaseConstruction`] if the header value is invalid.
pub fn set_content_digest(
    headers: &mut http::HeaderMap,
    body: &[u8],
    algorithm: DigestAlgorithm,
) -> Result<(), HttpSigError> {
    let value = content_digest(body, algorithm);
    let hv = http::HeaderValue::from_str(&value)
        .map_err(|e| HttpSigError::BaseConstruction(format!("Content-Digest header: {e}")))?;
    headers.insert("content-digest", hv);
    Ok(())
}

/// Verify a `Content-Digest` header value against a body.
///
/// Parses the header as an SFV Dictionary and verifies ALL recognized
/// algorithms match the body. If any recognized algorithm's digest does not
/// match, verification fails immediately.
///
/// # Errors
///
/// Returns [`HttpSigError::DigestMismatch`] if any recognized algorithm doesn't match.
/// Returns [`HttpSigError::SfvParse`] if the header cannot be parsed.
pub fn verify_content_digest(header_value: &str, body: &[u8]) -> Result<(), HttpSigError> {
    let dict = crate::sfv::parse::parse_dictionary(header_value)
        .map_err(|e| HttpSigError::SfvParse(format!("Content-Digest parse: {e}")))?;

    let mut found_recognized = false;

    for (algo_name, member) in &dict.entries {
        let algorithm = match algo_name.as_str() {
            "sha-256" => DigestAlgorithm::Sha256,
            "sha-512" => DigestAlgorithm::Sha512,
            _ => continue,
        };

        let expected = match member {
            crate::sfv::types::SfvDictMember::Item(item) => match &item.value {
                crate::sfv::types::SfvBareItem::ByteSequence(bytes) => bytes,
                _ => {
                    return Err(HttpSigError::SfvParse(format!(
                        "Content-Digest '{algo_name}' value must be a byte sequence"
                    )));
                }
            },
            _ => {
                return Err(HttpSigError::SfvParse(format!(
                    "Content-Digest '{algo_name}' must be an item"
                )));
            }
        };

        found_recognized = true;

        let actual = digest::digest(algorithm.digest_algorithm(), body);

        // Constant-time comparison — fail immediately if any recognized algo mismatches
        if constant_time::verify_slices_are_equal(actual.as_ref(), expected).is_err() {
            return Err(HttpSigError::DigestMismatch(format!(
                "{algo_name} digest does not match body"
            )));
        }
    }

    if found_recognized {
        Ok(())
    } else {
        Err(HttpSigError::DigestMismatch(
            "no recognized digest algorithm in Content-Digest header".into(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_digest() {
        let value = content_digest(b"hello world", DigestAlgorithm::Sha256);
        assert!(value.starts_with("sha-256=:"));
        assert!(value.ends_with(':'));
    }

    #[test]
    fn test_sha512_digest() {
        let value = content_digest(b"hello world", DigestAlgorithm::Sha512);
        assert!(value.starts_with("sha-512=:"));
        assert!(value.ends_with(':'));
    }

    #[test]
    fn test_empty_body() {
        let value = content_digest(b"", DigestAlgorithm::Sha256);
        let expected_hash = digest::digest(&digest::SHA256, b"");
        let expected_b64 = STANDARD.encode(expected_hash.as_ref());
        assert_eq!(value, format!("sha-256=:{expected_b64}:"));
    }

    #[test]
    fn test_verify_sha256_success() {
        let body = b"test body content";
        let header = content_digest(body, DigestAlgorithm::Sha256);
        verify_content_digest(&header, body).unwrap();
    }

    #[test]
    fn test_verify_sha512_success() {
        let body = b"test body content";
        let header = content_digest(body, DigestAlgorithm::Sha512);
        verify_content_digest(&header, body).unwrap();
    }

    #[test]
    fn test_verify_tampered_body() {
        let header = content_digest(b"original", DigestAlgorithm::Sha256);
        let result = verify_content_digest(&header, b"tampered");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_multiple_algorithms_first_matches() {
        let body = b"multi-algo body";
        let sha256 = content_digest(body, DigestAlgorithm::Sha256);
        let sha512 = content_digest(body, DigestAlgorithm::Sha512);
        let header = format!("{sha256}, {sha512}");
        verify_content_digest(&header, body).unwrap();
    }

    #[test]
    fn test_verify_multiple_algorithms_wrong_first_rejects() {
        // ALL recognized algorithms must match — wrong sha-256 fails even if sha-512 is correct
        let body = b"multi-algo body";
        let wrong_sha256 = content_digest(b"wrong", DigestAlgorithm::Sha256);
        let correct_sha512 = content_digest(body, DigestAlgorithm::Sha512);
        let header = format!("{wrong_sha256}, {correct_sha512}");
        let result = verify_content_digest(&header, body);
        assert!(result.is_err(), "wrong sha-256 must cause failure");
    }

    #[test]
    fn test_set_content_digest() {
        let mut headers = http::HeaderMap::new();
        set_content_digest(&mut headers, b"body", DigestAlgorithm::Sha256).unwrap();
        assert!(headers.contains_key("content-digest"));
    }

    #[test]
    fn test_verify_unknown_algorithm() {
        let result = verify_content_digest("sha-999=:AAAA:", b"body");
        assert!(result.is_err());
    }
}
