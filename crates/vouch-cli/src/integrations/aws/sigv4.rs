// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS Signature Version 4 utilities.
//!
//! Shared SigV4 helper functions used by ECR, CodeArtifact, CodeCommit,
//! and other AWS API calls (both JSON-RPC and REST style).

use std::collections::BTreeMap;

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
    http_client: &reqwest::Client,
    endpoint: &str,
    service: &str,
    target: &str,
    region: &str,
    creds: &StsCredentials,
    body: &serde_json::Value,
) -> Result<String> {
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
        let truncated = truncate_error_body(&response_body, 500);
        anyhow::bail!("{service} returned error {status}: {truncated}");
    }

    response
        .text()
        .await
        .context("failed to read AWS API response body")
}

/// Send a SigV4-signed REST-style request to an AWS service.
///
/// Handles both GET and POST for REST APIs that use query parameters
/// instead of JSON-RPC (e.g., EKS `DescribeCluster`, CodeArtifact
/// `GetAuthorizationToken`).
///
/// # Arguments
/// * `method` - HTTP method (GET or POST)
/// * `endpoint` - Base URL (e.g., `https://eks.us-east-1.amazonaws.com`)
/// * `path` - URI path (e.g., `/clusters/my-cluster`)
/// * `query_params` - Query parameter key-value pairs (sorted for signing)
/// * `service` - AWS service name for signing (e.g., `eks`, `codeartifact`)
/// * `region` - AWS region
/// * `creds` - Temporary AWS credentials from STS
#[allow(clippy::too_many_arguments)]
pub async fn sign_and_send_rest(
    http_client: &reqwest::Client,
    method: reqwest::Method,
    endpoint: &str,
    path: &str,
    query_params: &[(&str, &str)],
    service: &str,
    region: &str,
    creds: &StsCredentials,
) -> Result<String> {
    let host = endpoint
        .strip_prefix("https://")
        .unwrap_or(endpoint)
        .trim_end_matches('/');

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

    let payload_hash = sha256_hex(b"");

    let canonical_headers = format!(
        "host:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{}\n",
        creds.session_token.expose_secret()
    );
    let signed_headers = "host;x-amz-date;x-amz-security-token";

    let method_str = method.as_str();
    let canonical_request = format!(
        "{method_str}\n{path}\n{canonical_query_string}\n\
         {canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    let string_to_sign = format!(
        "{algorithm}\n{amz_date}\n{credential_scope}\n\
         {canonical_request_hash}"
    );

    let k_signing = derive_signing_key(&creds.secret_access_key, &date_stamp, region, service);
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "{algorithm} Credential={}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id
    );

    let url = if canonical_query_string.is_empty() {
        format!("{endpoint}{path}")
    } else {
        format!("{endpoint}{path}?{canonical_query_string}")
    };

    let response = http_client
        .request(method, &url)
        .header("X-Amz-Date", &amz_date)
        .header("X-Amz-Security-Token", creds.session_token.expose_secret())
        .header("Authorization", &authorization)
        .send()
        .await
        .context("failed to send AWS API request")?;

    if !response.status().is_success() {
        let status = response.status();
        let response_body = response.text().await.unwrap_or_default();
        let truncated = truncate_error_body(&response_body, 500);
        anyhow::bail!("{service} returned error {status}: {truncated}");
    }

    response
        .text()
        .await
        .context("failed to read AWS API response body")
}

/// Send a SigV4-signed form-encoded POST request to an AWS service.
///
/// Some AWS services (e.g., Redshift) use the Query API pattern with
/// `application/x-www-form-urlencoded` content type. This function handles
/// SigV4 signing over the form body.
pub async fn sign_and_send_form_post(
    http_client: &reqwest::Client,
    endpoint: &str,
    service: &str,
    region: &str,
    creds: &StsCredentials,
    form_params: &[(&str, &str)],
) -> Result<String> {
    let host = endpoint
        .strip_prefix("https://")
        .unwrap_or(endpoint)
        .trim_end_matches('/');

    // Build sorted form body (SigV4 requires sorted params in body)
    let mut sorted_params: Vec<(&str, &str)> = form_params.to_vec();
    sorted_params.sort_by(|a, b| a.0.cmp(b.0));
    let body_str: String = sorted_params
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let now = jiff::Timestamp::now();
    let amz_date = format_amz_date(now);
    let date_stamp = format_date_stamp(now);

    let payload_hash = sha256_hex(body_str.as_bytes());

    let canonical_headers = format!(
        "content-type:application/x-www-form-urlencoded\n\
         host:{host}\nx-amz-date:{amz_date}\n\
         x-amz-security-token:{}\n",
        creds.session_token.expose_secret()
    );
    let signed_headers = "content-type;host;x-amz-date;x-amz-security-token";

    let canonical_request =
        format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    let string_to_sign = format!(
        "{algorithm}\n{amz_date}\n{credential_scope}\n\
         {canonical_request_hash}"
    );

    let k_signing = derive_signing_key(&creds.secret_access_key, &date_stamp, region, service);
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "{algorithm} Credential={}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id
    );

    let response = http_client
        .post(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Amz-Date", &amz_date)
        .header("X-Amz-Security-Token", creds.session_token.expose_secret())
        .header("Authorization", &authorization)
        .body(body_str)
        .send()
        .await
        .context("failed to send AWS API request")?;

    if !response.status().is_success() {
        let status = response.status();
        let response_body = response.text().await.unwrap_or_default();
        let truncated = truncate_error_body(&response_body, 500);
        anyhow::bail!("{service} returned error {status}: {truncated}");
    }

    response
        .text()
        .await
        .context("failed to read AWS API response body")
}

/// Parameters for building a SigV4 presigned URL.
pub struct PresignedUrlParams<'a> {
    /// HTTP method (typically "GET").
    pub method: &'a str,
    /// Base URL (e.g., `https://sts.us-east-1.amazonaws.com`).
    pub endpoint: &'a str,
    /// URI path (e.g., "/").
    pub path: &'a str,
    /// Query params for the API call itself.
    pub query_params: &'a [(&'a str, &'a str)],
    /// Additional headers to sign (e.g., `x-k8s-aws-id`).
    pub extra_signed_headers: &'a [(&'a str, &'a str)],
    /// AWS service name for signing (e.g., "sts", "rds-db").
    pub service: &'a str,
    /// AWS region.
    pub region: &'a str,
    /// Temporary AWS credentials from STS.
    pub creds: &'a StsCredentials,
    /// How long the URL is valid in seconds (e.g., 60 for EKS).
    pub expires_seconds: u64,
}

/// Build a SigV4 presigned URL (query-string authentication).
///
/// Unlike the `sign_and_send_*` functions which put the signature in the
/// `Authorization` header, presigned URLs embed all auth parameters in the
/// query string. Used by EKS tokens and RDS IAM auth tokens.
#[must_use]
pub fn build_presigned_url(params: &PresignedUrlParams<'_>) -> String {
    let PresignedUrlParams {
        method,
        endpoint,
        path,
        query_params: base_query_params,
        extra_signed_headers,
        service,
        region,
        creds,
        expires_seconds,
    } = params;
    let host = endpoint
        .strip_prefix("https://")
        .unwrap_or(endpoint)
        .trim_end_matches('/');

    let now = jiff::Timestamp::now();
    let amz_date = format_amz_date(now);
    let date_stamp = format_date_stamp(now);

    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let credential = format!("{}/{credential_scope}", creds.access_key_id);

    // BTreeMap guarantees alphabetical ordering per SigV4 spec
    let mut headers: BTreeMap<&str, &str> = BTreeMap::new();
    headers.insert("host", host);
    for &(name, value) in *extra_signed_headers {
        headers.insert(name, value);
    }

    let signed_headers_str: String = headers.keys().copied().collect::<Vec<_>>().join(";");
    let canonical_headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();

    // Build the canonical query string including SigV4 auth params
    let mut all_params: BTreeMap<&str, String> = BTreeMap::new();
    all_params.insert("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string());
    all_params.insert("X-Amz-Credential", credential.clone());
    all_params.insert("X-Amz-Date", amz_date.clone());
    all_params.insert("X-Amz-Expires", expires_seconds.to_string());
    all_params.insert(
        "X-Amz-Security-Token",
        creds.session_token.expose_secret().to_string(),
    );
    all_params.insert("X-Amz-SignedHeaders", signed_headers_str.clone());

    // Add the base query params from the API call
    for &(k, v) in *base_query_params {
        all_params.insert(k, v.to_string());
    }

    // BTreeMap is already sorted by key
    let canonical_query_string: String = all_params
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    // Presigned URLs use UNSIGNED-PAYLOAD
    let payload_hash = "UNSIGNED-PAYLOAD";

    let canonical_request = format!(
        "{method}\n{path}\n{canonical_query_string}\n\
         {canonical_headers}\n{signed_headers_str}\n{payload_hash}"
    );

    let algorithm = "AWS4-HMAC-SHA256";
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    let string_to_sign = format!(
        "{algorithm}\n{amz_date}\n{credential_scope}\n\
         {canonical_request_hash}"
    );

    let k_signing = derive_signing_key(&creds.secret_access_key, &date_stamp, region, service);
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    format!(
        "{endpoint}{path}?{canonical_query_string}\
         &X-Amz-Signature={signature}"
    )
}

/// URI-encode a string per AWS SigV4 rules (RFC 3986 unreserved characters).
///
/// Encodes all characters except `A-Z a-z 0-9 - _ . ~`.
pub(crate) fn uri_encode(input: &str) -> String {
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

/// Validate that a value is safe for use in SigV4 headers/URLs.
///
/// Rejects newlines, carriage returns, and null bytes which could
/// cause header injection or signature corruption.
pub(crate) fn validate_sigv4_input(value: &str, label: &str) -> Result<()> {
    anyhow::ensure!(!value.is_empty(), "{label} must not be empty");
    anyhow::ensure!(
        !value.contains('\n') && !value.contains('\r') && !value.contains('\0'),
        "{label} contains invalid characters (newline, carriage return, or null)"
    );
    Ok(())
}

/// Truncate an error response body for inclusion in error messages.
///
/// AWS error XML/JSON can contain account IDs, ARNs, and request IDs.
/// Limiting the length avoids leaking excessive detail.
fn truncate_error_body(body: &str, max_len: usize) -> &str {
    if body.len() <= max_len {
        return body;
    }
    // Find the last char boundary at or before max_len
    let mut end = max_len;
    while !body.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    body.get(..end).unwrap_or(body)
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

    #[test]
    fn test_build_presigned_url_structure() {
        let creds = StsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            session_token: SecretString::from("FwoGZXIvYXdzEBY".to_string()),
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };

        let url = build_presigned_url(&PresignedUrlParams {
            method: "GET",
            endpoint: "https://sts.us-east-1.amazonaws.com",
            path: "/",
            query_params: &[("Action", "GetCallerIdentity"), ("Version", "2011-06-15")],
            extra_signed_headers: &[("x-k8s-aws-id", "my-cluster")],
            service: "sts",
            region: "us-east-1",
            creds: &creds,
            expires_seconds: 60,
        });

        // Verify the URL starts with the endpoint
        assert!(url.starts_with("https://sts.us-east-1.amazonaws.com/"));
        // Verify required SigV4 query parameters are present
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(url.contains("X-Amz-Credential="));
        assert!(url.contains("X-Amz-Date="));
        assert!(url.contains("X-Amz-Expires=60"));
        assert!(url.contains("X-Amz-Security-Token="));
        assert!(url.contains("X-Amz-SignedHeaders="));
        assert!(url.contains("X-Amz-Signature="));
        // Verify API params are included
        assert!(url.contains("Action=GetCallerIdentity"));
        assert!(url.contains("Version=2011-06-15"));
        // Verify signed headers include the extra header
        assert!(url.contains("host%3Bx-k8s-aws-id"));
    }

    #[test]
    fn test_build_presigned_url_no_extra_headers() {
        let creds = StsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            session_token: SecretString::from("token".to_string()),
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };

        let url = build_presigned_url(&PresignedUrlParams {
            method: "GET",
            endpoint: "https://my-rds-host.us-east-1.rds.amazonaws.com",
            path: "/",
            query_params: &[("Action", "connect"), ("DBUser", "admin")],
            extra_signed_headers: &[],
            service: "rds-db",
            region: "us-east-1",
            creds: &creds,
            expires_seconds: 900,
        });

        assert!(url.starts_with("https://my-rds-host.us-east-1.rds.amazonaws.com/"));
        assert!(url.contains("X-Amz-Expires=900"));
        assert!(url.contains("Action=connect"));
        assert!(url.contains("DBUser=admin"));
        // Only host should be in signed headers (no extras)
        assert!(url.contains("X-Amz-SignedHeaders=host"));
    }

    #[test]
    fn test_build_presigned_url_header_sorts_before_host() {
        let creds = StsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            session_token: SecretString::from("token".to_string()),
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };

        let url = build_presigned_url(&PresignedUrlParams {
            method: "GET",
            endpoint: "https://sts.us-east-1.amazonaws.com",
            path: "/",
            query_params: &[("Action", "GetCallerIdentity")],
            extra_signed_headers: &[("a-test-header", "test-value")],
            service: "sts",
            region: "us-east-1",
            creds: &creds,
            expires_seconds: 60,
        });

        // "a-test-header" sorts before "host" alphabetically
        // BTreeMap ensures correct ordering for both signed headers
        // and canonical headers
        assert!(url.contains("a-test-header%3Bhost"));
    }

    #[test]
    fn test_validate_sigv4_input_valid() {
        assert!(validate_sigv4_input("my-cluster", "cluster").is_ok());
        assert!(validate_sigv4_input("db.example.com", "hostname").is_ok());
        assert!(validate_sigv4_input("admin_user", "username").is_ok());
    }

    #[test]
    fn test_validate_sigv4_input_empty() {
        let result = validate_sigv4_input("", "cluster");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must not be empty")
        );
    }

    #[test]
    fn test_validate_sigv4_input_newline() {
        assert!(validate_sigv4_input("bad\nvalue", "header").is_err());
        assert!(validate_sigv4_input("bad\rvalue", "header").is_err());
        assert!(validate_sigv4_input("bad\0value", "header").is_err());
    }

    #[test]
    fn test_truncate_error_body_short() {
        let body = "short error";
        assert_eq!(truncate_error_body(body, 500), "short error");
    }

    #[test]
    fn test_truncate_error_body_long() {
        let body = "a".repeat(1000);
        let truncated = truncate_error_body(&body, 500);
        assert_eq!(truncated.len(), 500);
    }

    #[test]
    fn test_truncate_error_body_exact() {
        let body = "a".repeat(500);
        assert_eq!(truncate_error_body(&body, 500).len(), 500);
    }
}
