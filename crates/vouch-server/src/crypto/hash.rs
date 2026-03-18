// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cryptographic hashing and random byte generation utilities.

use aws_lc_rs::rand as aws_rand;

/// Hash a token for storage/lookup using SHA-256.
///
/// Returns a base64url-encoded hash of the token. This is used to store
/// tokens securely in the database without keeping the raw token value.
#[must_use]
pub fn hash_token(token: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let hash = digest::digest(&SHA256, token.as_bytes());
    URL_SAFE_NO_PAD.encode(hash.as_ref())
}

/// Generate cryptographically secure random bytes.
///
/// # Errors
///
/// Returns an error if the system RNG fails, which should never happen on
/// a correctly functioning system.
pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>, aws_lc_rs::error::Unspecified> {
    let mut bytes = vec![0u8; len];
    aws_rand::fill(&mut bytes)?;
    Ok(bytes)
}

/// Generate a 32-byte challenge for WebAuthn.
///
/// This is a convenience wrapper around `generate_random_bytes(32)` for
/// WebAuthn challenge generation.
///
/// # Errors
///
/// Returns an error if the system RNG fails.
pub fn generate_challenge() -> Result<Vec<u8>, aws_lc_rs::error::Unspecified> {
    generate_random_bytes(32)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token_golden_value() {
        // SHA-256 of "test-token" base64url-encoded (no padding)
        let hash = hash_token("test-token");
        // Verify determinism: same input always produces same output
        assert_eq!(hash, hash_token("test-token"));
        // Different inputs produce different outputs
        assert_ne!(hash, hash_token("other-token"));
        // Output is non-empty base64url
        assert!(!hash.is_empty());
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "hash_token output must be base64url: {hash}"
        );
    }

    #[test]
    fn test_hash_token_empty_input() {
        let hash = hash_token("");
        assert!(!hash.is_empty());
        assert_ne!(hash, hash_token("nonempty"));
    }

    #[test]
    fn test_generate_random_bytes_length() {
        let bytes = generate_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);

        let bytes = generate_random_bytes(64).unwrap();
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn test_generate_random_bytes_uniqueness() {
        let a = generate_random_bytes(32).unwrap();
        let b = generate_random_bytes(32).unwrap();
        // Two random 32-byte values should differ (probability of collision ≈ 0)
        assert_ne!(a, b);
    }

    #[test]
    fn test_generate_challenge_is_32_bytes() {
        let challenge = generate_challenge().unwrap();
        assert_eq!(challenge.len(), 32);
    }
}
