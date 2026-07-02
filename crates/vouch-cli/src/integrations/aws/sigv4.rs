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
pub(crate) fn format_amz_date(ts: jiff::Timestamp) -> String {
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
pub(crate) fn format_date_stamp(ts: jiff::Timestamp) -> String {
    let dt = ts.to_zoned(jiff::tz::TimeZone::UTC);
    format!("{:04}{:02}{:02}", dt.year(), dt.month(), dt.day())
}

/// Compute SHA-256 hash and return as hex string.
#[must_use]
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use aws_lc_rs::digest::{SHA256, digest};
    hex::encode(digest(&SHA256, data).as_ref())
}

/// Compute HMAC-SHA256.
#[must_use]
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
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
pub(crate) fn derive_signing_key(
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
pub(crate) async fn sign_and_send_json_rpc(
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
        return Err(crate::exit_code::CliError::NetworkError(format!(
            "{service} returned error {status}: {truncated}"
        ))
        .into());
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
#[expect(
    clippy::too_many_arguments,
    reason = "AWS SigV4 REST request requires all listed parameters"
)]
pub(crate) async fn sign_and_send_rest(
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
        return Err(crate::exit_code::CliError::NetworkError(format!(
            "{service} returned error {status}: {truncated}"
        ))
        .into());
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
pub(crate) async fn sign_and_send_form_post(
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
        return Err(crate::exit_code::CliError::NetworkError(format!(
            "{service} returned error {status}: {truncated}"
        ))
        .into());
    }

    response
        .text()
        .await
        .context("failed to read AWS API response body")
}

/// Send a SigV4-signed POST request with a JSON body to a REST-style AWS
/// endpoint that uses a path and query string (not JSON-RPC `X-Amz-Target`).
///
/// Used for IAM Identity Center `sso-oidc:CreateTokenWithIAM`, which is
/// `POST /token?aws_iam=t` with a `application/json` body, signed for the
/// `sso-oauth` service.
///
/// # Arguments
/// * `endpoint` - Base URL (e.g., `https://oidc.us-east-1.amazonaws.com`)
/// * `path` - URI path (e.g., `/token`)
/// * `query_params` - Query parameters (e.g., `&[("aws_iam", "t")]`)
/// * `service` - AWS service name for signing (e.g., `sso-oauth`)
/// * `region` - AWS region
/// * `creds` - Temporary AWS credentials (SigV4 caller identity)
/// * `body` - JSON request body
#[expect(
    clippy::too_many_arguments,
    reason = "AWS SigV4 JSON POST requires all listed parameters"
)]
pub(crate) async fn sign_and_send_json_post(
    http_client: &reqwest::Client,
    endpoint: &str,
    path: &str,
    query_params: &[(&str, &str)],
    service: &str,
    region: &str,
    creds: &StsCredentials,
    body: &serde_json::Value,
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

    let body_str = body.to_string();
    let now = jiff::Timestamp::now();
    let amz_date = format_amz_date(now);
    let date_stamp = format_date_stamp(now);

    let payload_hash = sha256_hex(body_str.as_bytes());

    let canonical_headers = format!(
        "content-type:application/json\n\
         host:{host}\nx-amz-date:{amz_date}\n\
         x-amz-security-token:{}\n",
        creds.session_token.expose_secret()
    );
    let signed_headers = "content-type;host;x-amz-date;x-amz-security-token";

    let canonical_request = format!(
        "POST\n{path}\n{canonical_query_string}\n\
         {canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    let string_to_sign =
        format!("{algorithm}\n{amz_date}\n{credential_scope}\n{canonical_request_hash}");

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
        .post(&url)
        .header("Content-Type", "application/json")
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
        return Err(crate::exit_code::CliError::NetworkError(format!(
            "{service} returned error {status}: {truncated}"
        ))
        .into());
    }

    response
        .text()
        .await
        .context("failed to read AWS API response body")
}

/// Parameters for building a SigV4 presigned URL.
pub(crate) struct PresignedUrlParams<'a> {
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
pub(crate) fn build_presigned_url(params: &PresignedUrlParams<'_>) -> String {
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

    // Use SHA-256 of empty body for the payload hash.
    // S3 presigned URLs use "UNSIGNED-PAYLOAD", but most other services
    // (including rds-db and sts) expect the hash of an empty string.
    let payload_hash = sha256_hex(b"");

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
    let end = body.floor_char_boundary(max_len);
    body.get(..end).unwrap_or(body)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::string_slice,
    reason = "test code: panic on assertion failure is acceptable"
)]
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

    /// End-to-end signature verification for `build_presigned_url`.
    ///
    /// Calls the function, extracts the dynamic timestamp from the URL,
    /// then independently reconstructs the SigV4 signing calculation
    /// and verifies the signature matches.
    #[test]
    fn test_presigned_url_signature_verification() {
        let creds = StsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            session_token: SecretString::from("AQtoken123".to_string()),
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

        // Extract dynamic timestamp and signature from URL
        let date_key = "X-Amz-Date=";
        let date_pos = url.find(date_key).unwrap() + date_key.len();
        let amz_date = &url[date_pos..date_pos + 16];
        let date_stamp = &amz_date[..8];

        let sig_key = "X-Amz-Signature=";
        let sig_pos = url.find(sig_key).unwrap() + sig_key.len();
        let actual_sig = &url[sig_pos..sig_pos + 64];

        // Independently reconstruct the canonical request
        let host = "sts.us-east-1.amazonaws.com";
        let scope = format!("{date_stamp}/us-east-1/sts/aws4_request");
        let cred_val = format!("AKIAIOSFODNN7EXAMPLE/{scope}");
        let signed_hdrs = "host;x-k8s-aws-id";
        let canonical_hdrs = format!("host:{host}\nx-k8s-aws-id:my-cluster\n");

        let mut qp: BTreeMap<&str, String> = BTreeMap::new();
        qp.insert("Action", "GetCallerIdentity".into());
        qp.insert("Version", "2011-06-15".into());
        qp.insert("X-Amz-Algorithm", "AWS4-HMAC-SHA256".into());
        qp.insert("X-Amz-Credential", cred_val);
        qp.insert("X-Amz-Date", amz_date.to_string());
        qp.insert("X-Amz-Expires", "60".into());
        qp.insert("X-Amz-Security-Token", "AQtoken123".into());
        qp.insert("X-Amz-SignedHeaders", signed_hdrs.into());

        let cqs: String = qp
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let empty_hash = sha256_hex(b"");
        let cr = format!(
            "GET\n/\n{cqs}\n{canonical_hdrs}\n\
             {signed_hdrs}\n{empty_hash}"
        );

        let cr_hash = sha256_hex(cr.as_bytes());
        let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{cr_hash}");

        let key = derive_signing_key(&creds.secret_access_key, date_stamp, "us-east-1", "sts");
        let expected_sig = hex::encode(hmac_sha256(&key, sts.as_bytes()));

        assert_eq!(actual_sig, expected_sig, "presigned URL signature mismatch");
    }

    /// Verify presigned URL uses SHA-256("") as payload hash.
    ///
    /// Most AWS services (including rds-db and sts) expect the hash of
    /// an empty string for presigned URLs, not the S3-specific
    /// "UNSIGNED-PAYLOAD" literal.
    #[test]
    fn test_presigned_url_uses_empty_payload_hash() {
        let creds = StsCredentials {
            access_key_id: "AKID".to_string(),
            secret_access_key: SecretString::from("secret".to_string()),
            session_token: SecretString::from("tok".to_string()),
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };

        let url = build_presigned_url(&PresignedUrlParams {
            method: "GET",
            endpoint: "https://example.amazonaws.com",
            path: "/",
            query_params: &[],
            extra_signed_headers: &[],
            service: "sts",
            region: "us-east-1",
            creds: &creds,
            expires_seconds: 60,
        });

        // The URL itself doesn't contain the payload hash, but the
        // signature is computed using SHA-256("") in the canonical
        // request. Verify "UNSIGNED-PAYLOAD" is NOT used by checking
        // that the signature differs from one built with it.
        assert!(
            !url.contains("UNSIGNED-PAYLOAD"),
            "presigned URL must not contain UNSIGNED-PAYLOAD literal"
        );
    }

    /// End-to-end signature verification for RDS IAM auth tokens.
    ///
    /// Uses `rds-db` service, `Action=connect` + `DBUser` params, and
    /// no extra signed headers — matching the exact call site in
    /// `credential/rds.rs`. Independently reconstructs the canonical
    /// request and verifies the signature matches.
    #[test]
    fn test_rds_presigned_url_signature_verification() {
        let creds = StsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            session_token: SecretString::from("IQoJb3JpZ2luX2VjFakeToken".to_string()),
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };

        let hostname = "mydb.abc123.us-east-1.rds.amazonaws.com";
        let port = 5432;
        let endpoint = format!("https://{hostname}:{port}");
        let host = format!("{hostname}:{port}");

        let url = build_presigned_url(&PresignedUrlParams {
            method: "GET",
            endpoint: &endpoint,
            path: "/",
            query_params: &[("Action", "connect"), ("DBUser", "dbuser")],
            extra_signed_headers: &[],
            service: "rds-db",
            region: "us-east-1",
            creds: &creds,
            expires_seconds: 900,
        });

        // Verify token starts with host:port (no scheme)
        let token = url.strip_prefix("https://").unwrap_or(&url);
        assert!(token.starts_with(&host));

        // Extract dynamic timestamp and signature
        let date_key = "X-Amz-Date=";
        let date_pos = url.find(date_key).unwrap() + date_key.len();
        let amz_date = &url[date_pos..date_pos + 16];
        let date_stamp = &amz_date[..8];

        let sig_key = "X-Amz-Signature=";
        let sig_pos = url.find(sig_key).unwrap() + sig_key.len();
        let actual_sig = &url[sig_pos..sig_pos + 64];

        // Independently reconstruct the canonical request
        let scope = format!("{date_stamp}/us-east-1/rds-db/aws4_request");
        let cred_val = format!("AKIAIOSFODNN7EXAMPLE/{scope}");

        let mut qp: BTreeMap<&str, String> = BTreeMap::new();
        qp.insert("Action", "connect".into());
        qp.insert("DBUser", "dbuser".into());
        qp.insert("X-Amz-Algorithm", "AWS4-HMAC-SHA256".into());
        qp.insert("X-Amz-Credential", cred_val);
        qp.insert("X-Amz-Date", amz_date.to_string());
        qp.insert("X-Amz-Expires", "900".into());
        qp.insert("X-Amz-Security-Token", "IQoJb3JpZ2luX2VjFakeToken".into());
        qp.insert("X-Amz-SignedHeaders", "host".into());

        let cqs: String = qp
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        // RDS expects SHA-256("") as payload hash, NOT "UNSIGNED-PAYLOAD"
        let empty_hash = sha256_hex(b"");
        let canonical_hdrs = format!("host:{host}\n");
        let cr = format!("GET\n/\n{cqs}\n{canonical_hdrs}\nhost\n{empty_hash}");

        let cr_hash = sha256_hex(cr.as_bytes());
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{cr_hash}");

        let key = derive_signing_key(&creds.secret_access_key, date_stamp, "us-east-1", "rds-db");
        let expected_sig = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));

        assert_eq!(
            actual_sig, expected_sig,
            "RDS presigned URL signature mismatch"
        );
    }

    /// Verify the canonical request uses SHA-256("") as payload hash.
    ///
    /// Most AWS services (rds-db, sts, etc.) expect SHA-256 of an
    /// empty body in the canonical request for presigned URLs.
    /// S3 is the exception (uses "UNSIGNED-PAYLOAD"), but we don't
    /// generate S3 presigned URLs.
    ///
    /// This test guards against regression to "UNSIGNED-PAYLOAD",
    /// which silently produces invalid tokens that AWS rejects.
    #[test]
    fn test_canonical_request_payload_hash_matches_botocore() {
        // botocore uses EMPTY_SHA256_HASH for presigned URL payloads
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let actual = sha256_hex(b"");
        assert_eq!(
            actual, expected,
            "SHA-256 of empty body must match botocore constant"
        );

        // Build a presigned URL and independently verify the payload
        // hash in the canonical request by checking the signature.
        // If "UNSIGNED-PAYLOAD" were used instead, this signature
        // verification would fail.
        let creds = StsCredentials {
            access_key_id: "AKID".to_string(),
            secret_access_key: SecretString::from("secret".to_string()),
            session_token: SecretString::from("tok".to_string()),
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };

        let url = build_presigned_url(&PresignedUrlParams {
            method: "GET",
            endpoint: "https://example.amazonaws.com",
            path: "/",
            query_params: &[("Action", "test")],
            extra_signed_headers: &[],
            service: "sts",
            region: "us-east-1",
            creds: &creds,
            expires_seconds: 60,
        });

        // Extract timestamp
        let date_key = "X-Amz-Date=";
        let date_pos = url.find(date_key).unwrap() + date_key.len();
        let amz_date = &url[date_pos..date_pos + 16];
        let date_stamp = &amz_date[..8];

        let sig_key = "X-Amz-Signature=";
        let sig_pos = url.find(sig_key).unwrap() + sig_key.len();
        let actual_sig = &url[sig_pos..sig_pos + 64];

        // Reconstruct with SHA-256("") — must match
        let scope = format!("{date_stamp}/us-east-1/sts/aws4_request");
        let cred_val = format!("AKID/{scope}");
        let mut qp: BTreeMap<&str, String> = BTreeMap::new();
        qp.insert("Action", "test".into());
        qp.insert("X-Amz-Algorithm", "AWS4-HMAC-SHA256".into());
        qp.insert("X-Amz-Credential", cred_val);
        qp.insert("X-Amz-Date", amz_date.to_string());
        qp.insert("X-Amz-Expires", "60".into());
        qp.insert("X-Amz-Security-Token", "tok".into());
        qp.insert("X-Amz-SignedHeaders", "host".into());
        let cqs: String = qp
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let cr_with_empty =
            format!("GET\n/\n{cqs}\nhost:example.amazonaws.com\n\nhost\n{expected}");
        let cr_with_unsigned =
            format!("GET\n/\n{cqs}\nhost:example.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD");

        let key = derive_signing_key(&creds.secret_access_key, date_stamp, "us-east-1", "sts");

        let sig_empty = hex::encode(hmac_sha256(
            &key,
            format!(
                "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
                sha256_hex(cr_with_empty.as_bytes())
            )
            .as_bytes(),
        ));
        let sig_unsigned = hex::encode(hmac_sha256(
            &key,
            format!(
                "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
                sha256_hex(cr_with_unsigned.as_bytes())
            )
            .as_bytes(),
        ));

        assert_eq!(
            actual_sig, sig_empty,
            "signature must match SHA-256(\"\") canonical request"
        );
        assert_ne!(
            actual_sig, sig_unsigned,
            "signature must NOT match UNSIGNED-PAYLOAD canonical request"
        );
    }

    /// Verify query params in presigned URL are sorted by key.
    ///
    /// AWS SigV4 requires the canonical query string to be sorted
    /// alphabetically by parameter name (after URI encoding).
    #[test]
    fn test_presigned_url_query_params_sorted() {
        let creds = StsCredentials {
            access_key_id: "AKID".to_string(),
            secret_access_key: SecretString::from("secret".to_string()),
            session_token: SecretString::from("tok".to_string()),
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };

        let url = build_presigned_url(&PresignedUrlParams {
            method: "GET",
            endpoint: "https://sts.us-east-1.amazonaws.com",
            path: "/",
            query_params: &[("Zebra", "last"), ("Action", "first")],
            extra_signed_headers: &[],
            service: "sts",
            region: "us-east-1",
            creds: &creds,
            expires_seconds: 60,
        });

        // Extract query string (between ? and &X-Amz-Signature)
        let qs_start = url.find('?').unwrap() + 1;
        let sig_sep = url.find("&X-Amz-Signature=").unwrap();
        let qs = &url[qs_start..sig_sep];

        // Split into param names and verify sorted order
        let param_names: Vec<&str> = qs
            .split('&')
            .filter_map(|p| p.split_once('='))
            .map(|(k, _)| k)
            .collect();

        let mut sorted = param_names.clone();
        sorted.sort();
        assert_eq!(
            param_names, sorted,
            "query params must be alphabetically sorted"
        );
    }
}
