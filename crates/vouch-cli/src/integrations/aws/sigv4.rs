// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS Signature Version 4 utilities.
//!
//! Shared SigV4 helper functions used by the ECR Docker credential helper
//! and the CodeCommit git credential helper.

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// Format timestamp for AWS `X-Amz-Date` header (`YYYYMMDDTHHMMSSZ`).
#[must_use]
pub fn format_amz_date(ts: jiff::Timestamp) -> String {
    let dt = ts.to_zoned(jiff::tz::TimeZone::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// Format timestamp for AWS date stamp (`YYYYMMDD`).
#[must_use]
pub fn format_date_stamp(ts: jiff::Timestamp) -> String {
    let dt = ts.to_zoned(jiff::tz::TimeZone::UTC);
    format!("{:04}{:02}{:02}", dt.year(), dt.month(), dt.day())
}

/// Compute SHA-256 hash and return as hex string.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    use aws_lc_rs::digest::{SHA256, digest};
    hex::encode(digest(&SHA256, data).as_ref())
}

/// Compute HMAC-SHA256.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use aws_lc_rs::hmac::{HMAC_SHA256, Key, sign};
    let key = Key::new(HMAC_SHA256, key);
    sign(&key, data).as_ref().to_vec()
}

/// Derive an AWS SigV4 signing key.
///
/// Performs the 4-step HMAC chain:
/// 1. `HMAC("AWS4" + secret_access_key, date_stamp)`
/// 2. `HMAC(step1, region)`
/// 3. `HMAC(step2, service)`
/// 4. `HMAC(step3, "aws4_request")`
///
/// Accepts `&SecretString` so the secret is only exposed at this single call site.
/// Returns `Zeroizing<Vec<u8>>` so the signing key is zeroed on drop.
#[must_use]
pub fn derive_signing_key(
    secret_access_key: &SecretString,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Zeroizing<Vec<u8>> {
    let k_secret = Zeroizing::new(format!("AWS4{}", secret_access_key.expose_secret()));
    let k_date = Zeroizing::new(hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes()));
    let k_region = Zeroizing::new(hmac_sha256(&k_date, region.as_bytes()));
    let k_service = Zeroizing::new(hmac_sha256(&k_region, service.as_bytes()));
    Zeroizing::new(hmac_sha256(&k_service, b"aws4_request"))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_format_amz_date() {
        // Create a known timestamp: 2024-01-15 10:50:45 UTC
        let ts = jiff::Timestamp::from_second(1705315845).expect("valid timestamp");
        let result = format_amz_date(ts);
        assert_eq!(result, "20240115T105045Z");
    }

    #[test]
    fn test_format_date_stamp() {
        // Create a known timestamp: 2024-01-15 10:50:45 UTC
        let ts = jiff::Timestamp::from_second(1705315845).expect("valid timestamp");
        let result = format_date_stamp(ts);
        assert_eq!(result, "20240115");
    }

    #[test]
    fn test_sha256_hex_empty() {
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hex_data() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_hmac_sha256_not_empty() {
        let result = hmac_sha256(b"key", b"data");
        assert!(!result.is_empty());
        assert_eq!(result.len(), 32); // SHA-256 output is 32 bytes
    }

    #[test]
    fn test_derive_signing_key() {
        let secret = SecretString::from("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string());
        let key = derive_signing_key(&secret, "20120215", "us-east-1", "iam");
        assert_eq!(key.len(), 32);
        // AWS test vector from docs
        assert_eq!(
            hex::encode(key.as_slice()),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }
}
