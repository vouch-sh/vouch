// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS Signature Version 4 utilities.
//!
//! Shared SigV4 helper functions used by ECR, CodeArtifact, CodeCommit,
//! and other AWS API calls (both JSON-RPC and REST style).

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use super::sts::StsCredentials;

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

/// Send a SigV4-signed JSON-RPC style POST request to an AWS service.
///
/// Many AWS services (ECR, etc.) use the same pattern:
/// - `POST /` with `Content-Type: application/x-amz-json-1.1`
/// - `X-Amz-Target` header to specify the operation
/// - SigV4 signature over the request
///
/// This function handles the signing and HTTP call, returning the raw
/// response body on success.
///
/// # Arguments
/// * `endpoint` - Full URL (e.g., `https://api.ecr.us-east-1.amazonaws.com`)
/// * `service` - AWS service name for signing (e.g., `ecr`, `codeartifact`)
/// * `target` - `X-Amz-Target` value (e.g., `AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken`)
/// * `region` - AWS region
/// * `creds` - Temporary AWS credentials from STS
/// * `body` - JSON request body
pub async fn sign_and_send_json_rpc(
    endpoint: &str,
    service: &str,
    target: &str,
    region: &str,
    creds: &StsCredentials,
    body: &serde_json::Value,
) -> Result<String> {
    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    // Extract host from endpoint URL
    let host = endpoint
        .strip_prefix("https://")
        .unwrap_or(endpoint)
        .trim_end_matches('/');

    let body_str = body.to_string();
    let now = jiff::Timestamp::now();
    let amz_date = format_amz_date(now);
    let date_stamp = format_date_stamp(now);

    let payload_hash = sha256_hex(body_str.as_bytes());

    let canonical_headers = format!(
        "content-type:application/x-amz-json-1.1\nhost:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{}\nx-amz-target:{target}\n",
        creds.session_token.expose_secret()
    );
    let signed_headers = "content-type;host;x-amz-date;x-amz-security-token;x-amz-target";

    let canonical_request =
        format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    let string_to_sign =
        format!("{algorithm}\n{amz_date}\n{credential_scope}\n{canonical_request_hash}");

    let k_signing = derive_signing_key(&creds.secret_access_key, &date_stamp, region, service);
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "{algorithm} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id
    );

    let response = http_client
        .post(endpoint)
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Date", &amz_date)
        .header("X-Amz-Security-Token", creds.session_token.expose_secret())
        .header("X-Amz-Target", target)
        .header("Authorization", &authorization)
        .body(body_str)
        .send()
        .await
        .context("failed to send AWS API request")?;

    if !response.status().is_success() {
        let status = response.status();
        let response_body = response.text().await.unwrap_or_default();
        anyhow::bail!("{service} returned error {status}: {response_body}");
    }

    response
        .text()
        .await
        .context("failed to read AWS API response body")
}

/// URI-encode a string per AWS SigV4 rules (RFC 3986 unreserved characters).
///
/// Encodes all characters except `A-Z a-z 0-9 - _ . ~`.
fn uri_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                use std::fmt::Write;
                let _res = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

/// Send a SigV4-signed REST-style POST request to an AWS service.
///
/// Some AWS services (e.g., CodeArtifact) use REST APIs with query parameters
/// instead of JSON-RPC. This function handles:
/// - `POST /{path}?{sorted query params}` with no request body
/// - SigV4 signature over the request
///
/// # Arguments
/// * `endpoint` - Base URL (e.g., `https://codeartifact.us-east-1.amazonaws.com`)
/// * `path` - URI path (e.g., `/v1/authorization-token`)
/// * `query_params` - Query parameter key-value pairs (will be sorted for signing)
/// * `service` - AWS service name for signing (e.g., `codeartifact`)
/// * `region` - AWS region
/// * `creds` - Temporary AWS credentials from STS
pub async fn sign_and_send_rest_post(
    endpoint: &str,
    path: &str,
    query_params: &[(&str, &str)],
    service: &str,
    region: &str,
    creds: &StsCredentials,
) -> Result<String> {
    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    // Extract host from endpoint URL
    let host = endpoint
        .strip_prefix("https://")
        .unwrap_or(endpoint)
        .trim_end_matches('/');

    // Build sorted canonical query string (SigV4 requires alphabetical order)
    let mut sorted_params: Vec<(&str, &str)> = query_params.to_vec();
    sorted_params.sort_by(|a, b| a.0.cmp(b.0));
    let canonical_query_string: String = sorted_params
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let now = jiff::Timestamp::now();
    let amz_date = format_amz_date(now);
    let date_stamp = format_date_stamp(now);

    // Empty body for REST-style requests with query parameters
    let payload_hash = sha256_hex(b"");

    let canonical_headers = format!(
        "host:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{}\n",
        creds.session_token.expose_secret()
    );
    let signed_headers = "host;x-amz-date;x-amz-security-token";

    let canonical_request = format!(
        "POST\n{path}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    let string_to_sign =
        format!("{algorithm}\n{amz_date}\n{credential_scope}\n{canonical_request_hash}");

    let k_signing = derive_signing_key(&creds.secret_access_key, &date_stamp, region, service);
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "{algorithm} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id
    );

    let url = format!("{endpoint}{path}?{canonical_query_string}");

    let response = http_client
        .post(&url)
        .header("X-Amz-Date", &amz_date)
        .header("X-Amz-Security-Token", creds.session_token.expose_secret())
        .header("Authorization", &authorization)
        .send()
        .await
        .context("failed to send AWS API request")?;

    if !response.status().is_success() {
        let status = response.status();
        let response_body = response.text().await.unwrap_or_default();
        anyhow::bail!("{service} returned error {status}: {response_body}");
    }

    response
        .text()
        .await
        .context("failed to read AWS API response body")
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

    #[test]
    fn test_uri_encode_unreserved() {
        // Unreserved characters should not be encoded
        assert_eq!(uri_encode("abc123"), "abc123");
        assert_eq!(uri_encode("my-domain"), "my-domain");
        assert_eq!(uri_encode("a_b.c~d"), "a_b.c~d");
    }

    #[test]
    fn test_uri_encode_special_chars() {
        assert_eq!(uri_encode("hello world"), "hello%20world");
        assert_eq!(uri_encode("a+b"), "a%2Bb");
        assert_eq!(uri_encode("foo/bar"), "foo%2Fbar");
        assert_eq!(uri_encode("key=value"), "key%3Dvalue");
    }

    #[test]
    fn test_uri_encode_empty() {
        assert_eq!(uri_encode(""), "");
    }
}
