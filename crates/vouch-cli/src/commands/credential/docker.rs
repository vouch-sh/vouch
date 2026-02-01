// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Docker credential helper for container registries.
//!
//! This module implements a Docker credential helper that provides authentication
//! for container registries using Vouch. It supports:
//! - AWS ECR (Elastic Container Registry)
//! - GCP Artifact Registry and GCR (Google Container Registry)
//! - GitHub Container Registry (ghcr.io)
//!
//! Usage: Configure Docker to use this helper:
//!   ~/.docker/config.json:
//!   {
//!     "credHelpers": {
//!       "123456789012.dkr.ecr.us-east-1.amazonaws.com": "vouch",
//!       "gcr.io": "vouch",
//!       "ghcr.io": "vouch"
//!     }
//!   }
//!
//! Or use `vouch setup docker --configure` to set this up automatically.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};

use crate::aws_config::{AwsConfig, extract_role_from_credential_process};
use crate::client::VouchClient;
use crate::config::Config;

/// Docker credential helper output format.
/// See: https://docs.docker.com/engine/reference/commandline/login/#credential-helper-protocol
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct DockerCredential {
    username: String,
    secret: String,
}

/// Registry type detected from the server URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryType {
    /// AWS Elastic Container Registry
    AwsEcr {
        account_id: String,
        region: String,
        /// Domain suffix (e.g., "amazonaws.com", "amazonaws.cn", "amazonaws.eu")
        domain_suffix: String,
    },
    /// Google Container Registry (gcr.io)
    Gcr,
    /// Google Artifact Registry (*-docker.pkg.dev)
    GarDocker {
        region: String,
        project: Option<String>,
    },
    /// GitHub Container Registry (ghcr.io)
    Ghcr,
    /// Unknown registry type
    Unknown,
}

/// Response from Vouch GCP token endpoint.
#[derive(Debug, Deserialize)]
struct GcpTokenResponse {
    id_token: String,
    #[allow(dead_code)]
    expires_in: u64,
}

/// Response from Vouch GitHub token endpoint.
#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    token: String,
}

/// GitHub token request.
#[derive(Debug, Serialize)]
struct GitHubTokenRequest {
    owner: Option<String>,
    repositories: Option<Vec<String>>,
}

/// Response from Vouch AWS token endpoint.
#[derive(Debug, Deserialize)]
struct AwsOidcTokenResponse {
    id_token: String,
}

/// AWS STS AssumeRoleWithWebIdentity response (simplified).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    assume_role_with_web_identity_result: AssumeRoleResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssumeRoleResult {
    credentials: StsCredentials,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StsCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    #[allow(dead_code)]
    expiration: String,
}

/// Run the Docker credential helper.
///
/// This is called when Docker invokes `docker-credential-vouch <operation>`.
///
/// # Arguments
/// * `operation` - The Docker credential operation ("get", "store", "erase", or "list")
pub async fn run(operation: &str) -> Result<()> {
    match operation {
        "get" => get_credential().await,
        "store" | "erase" => {
            // These operations are no-ops for Vouch since we don't store credentials
            // Just consume stdin to avoid broken pipe
            let _ = read_server_url();
            Ok(())
        }
        "list" => {
            // Return empty JSON object - we don't maintain a list
            println!("{{}}");
            Ok(())
        }
        _ => {
            // Unknown operation, silently ignore
            Ok(())
        }
    }
}

/// Read the server URL from stdin (Docker protocol).
fn read_server_url() -> Result<String> {
    let stdin = std::io::stdin();
    let mut url = String::new();

    // Docker sends just the URL on a single line
    if let Some(line) = stdin.lock().lines().next() {
        let line = line.context("failed to read stdin")?;
        if !line.is_empty() {
            url = line;
        }
    }

    Ok(url.trim().to_string())
}

/// Detect the registry type from the server URL.
pub fn detect_registry_type(server_url: &str) -> RegistryType {
    let url = server_url.to_lowercase();

    // AWS ECR: account.dkr.ecr.region.amazonaws.{com,cn,eu}
    // Supports all AWS partitions:
    // - Commercial: amazonaws.com
    // - China: amazonaws.cn
    // - EU Sovereign Cloud: amazonaws.eu
    // - GovCloud: amazonaws.com (but with us-gov-* regions)
    if let Some((account_id, rest)) = url.split_once(".dkr.ecr.") {
        // rest = "region.amazonaws.com" or "region.amazonaws.cn" or "region.amazonaws.eu"
        // Split on first dot to separate region from domain
        if let Some((region, domain_suffix)) = rest.split_once('.') {
            // domain_suffix = "amazonaws.com", "amazonaws.cn", or "amazonaws.eu"
            // Validate it looks like an AWS domain
            if domain_suffix.starts_with("amazonaws.") {
                return RegistryType::AwsEcr {
                    account_id: account_id.to_string(),
                    region: region.to_string(),
                    domain_suffix: domain_suffix.to_string(),
                };
            }
        }
    }

    // GitHub Container Registry: ghcr.io
    if url == "ghcr.io" || url.ends_with(".ghcr.io") {
        return RegistryType::Ghcr;
    }

    // Google Container Registry: gcr.io, us.gcr.io, eu.gcr.io, asia.gcr.io
    if url == "gcr.io"
        || url == "us.gcr.io"
        || url == "eu.gcr.io"
        || url == "asia.gcr.io"
        || url.ends_with(".gcr.io")
    {
        return RegistryType::Gcr;
    }

    // Google Artifact Registry: us-docker.pkg.dev, europe-docker.pkg.dev, etc.
    if let Some(region) = url.strip_suffix("-docker.pkg.dev") {
        return RegistryType::GarDocker {
            region: region.to_string(),
            project: None,
        };
    }

    RegistryType::Unknown
}

/// Handle the "get" operation - provide credentials to Docker.
async fn get_credential() -> Result<()> {
    // Read server URL from stdin
    let server_url = read_server_url()?;

    if server_url.is_empty() {
        anyhow::bail!("no server URL provided");
    }

    // Detect registry type
    let registry_type = detect_registry_type(&server_url);

    // Load config
    let config = Config::load().map_err(|e| {
        eprintln!("vouch: failed to load config: {e}");
        e
    })?;

    let server = config.server_url().ok_or_else(|| {
        eprintln!("vouch: not configured - run 'vouch enroll' first");
        anyhow::anyhow!("not configured")
    })?;

    // Get credentials based on registry type
    let credential = match registry_type {
        RegistryType::AwsEcr {
            region,
            domain_suffix,
            ..
        } => get_ecr_credential(server, &region, &domain_suffix, &server_url).await?,
        RegistryType::Gcr | RegistryType::GarDocker { .. } => get_gcp_credential(server).await?,
        RegistryType::Ghcr => get_ghcr_credential(server).await?,
        RegistryType::Unknown => {
            eprintln!("vouch: unknown registry type for URL: {}", server_url);
            anyhow::bail!("unsupported registry: {}", server_url);
        }
    };

    // Output credentials to stdout in Docker credential helper format
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let json = serde_json::to_string(&credential).context("failed to serialize credentials")?;
    writeln!(out, "{json}")?;

    Ok(())
}

/// Try to read the AWS role ARN from the local ~/.aws/config file.
///
/// Finds the first vouch profile and extracts the role ARN from its credential_process.
fn get_local_aws_role() -> Option<String> {
    let config = AwsConfig::load().ok()?;
    let profile = config.find_vouch_profile()?;
    extract_role_from_credential_process(&profile.credential_process?)
}

/// Get credentials for AWS ECR.
async fn get_ecr_credential(
    server: &str,
    region: &str,
    domain_suffix: &str,
    registry_url: &str,
) -> Result<DockerCredential> {
    let client = VouchClient::new(server)?;

    // First, get OIDC token from Vouch server
    let token_response: AwsOidcTokenResponse = client
        .get_authenticated("/v1/credentials/aws/token")
        .await
        .context("failed to get OIDC token from Vouch server")?;

    // Get the AWS role ARN from local ~/.aws/config
    // This uses the same role configured via 'vouch setup aws --role ...'
    let role_arn = get_local_aws_role().ok_or_else(|| {
        anyhow::anyhow!(
            "AWS not configured. Run 'vouch setup aws --role <role-arn>' with a role that has ECR permissions"
        )
    })?;

    // Call STS AssumeRoleWithWebIdentity
    let sts_creds = assume_role_with_web_identity(
        &role_arn,
        "vouch-docker",
        &token_response.id_token,
        region,
        domain_suffix,
    )
    .await
    .context("failed to assume AWS role")?;

    // Call ECR GetAuthorizationToken
    let ecr_token = get_ecr_authorization_token(
        region,
        domain_suffix,
        registry_url,
        &sts_creds.assume_role_with_web_identity_result.credentials,
    )
    .await
    .context("failed to get ECR authorization token")?;

    Ok(DockerCredential {
        username: "AWS".to_string(),
        secret: ecr_token,
    })
}

/// Call AWS STS AssumeRoleWithWebIdentity.
async fn assume_role_with_web_identity(
    role_arn: &str,
    role_session_name: &str,
    web_identity_token: &str,
    region: &str,
    domain_suffix: &str,
) -> Result<AssumeRoleWithWebIdentityResponse> {
    let http_client = reqwest::Client::new();

    // Use regional STS endpoint for the appropriate partition
    // e.g., "sts.us-east-1.amazonaws.com" or "sts.cn-north-1.amazonaws.cn"
    let sts_url = format!("https://sts.{region}.{domain_suffix}/");

    let response = http_client
        .post(&sts_url)
        .form(&[
            ("Action", "AssumeRoleWithWebIdentity"),
            ("Version", "2011-06-15"),
            ("RoleArn", role_arn),
            ("RoleSessionName", role_session_name),
            ("WebIdentityToken", web_identity_token),
        ])
        .send()
        .await
        .context("failed to call AWS STS")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("AWS STS returned error {status}: {body}");
    }

    let body = response
        .text()
        .await
        .context("failed to read STS response")?;

    parse_sts_xml_response(&body)
}

/// Parse AWS STS XML response.
fn parse_sts_xml_response(xml: &str) -> Result<AssumeRoleWithWebIdentityResponse> {
    fn extract_tag(xml: &str, tag: &str) -> Option<String> {
        let start_tag = format!("<{tag}>");
        let end_tag = format!("</{tag}>");
        let start = xml.find(&start_tag)? + start_tag.len();
        let end = xml.find(&end_tag)?;
        if start < end {
            Some(xml.get(start..end)?.to_string())
        } else {
            None
        }
    }

    let access_key_id =
        extract_tag(xml, "AccessKeyId").context("missing AccessKeyId in STS response")?;
    let secret_access_key =
        extract_tag(xml, "SecretAccessKey").context("missing SecretAccessKey in STS response")?;
    let session_token =
        extract_tag(xml, "SessionToken").context("missing SessionToken in STS response")?;
    let expiration =
        extract_tag(xml, "Expiration").context("missing Expiration in STS response")?;

    Ok(AssumeRoleWithWebIdentityResponse {
        assume_role_with_web_identity_result: AssumeRoleResult {
            credentials: StsCredentials {
                access_key_id,
                secret_access_key,
                session_token,
                expiration,
            },
        },
    })
}

/// Get ECR authorization token using AWS credentials.
async fn get_ecr_authorization_token(
    region: &str,
    domain_suffix: &str,
    registry_url: &str,
    creds: &StsCredentials,
) -> Result<String> {
    // Extract account ID from registry URL
    let account_id = registry_url
        .split('.')
        .next()
        .context("invalid ECR registry URL")?;

    // Build the ECR GetAuthorizationToken request
    // This requires AWS Signature Version 4 signing
    // Use the domain suffix from registry detection for the appropriate partition
    let ecr_endpoint = format!("https://api.ecr.{region}.{domain_suffix}");

    // We need to sign the request with AWS SigV4
    // For simplicity, we'll use the aws-sigv4 crate approach
    let http_client = reqwest::Client::new();

    // ECR uses JSON-RPC style API
    let request_body = serde_json::json!({
        "registryIds": [account_id]
    });

    let now = jiff::Timestamp::now();
    let amz_date = format_amz_date(now);
    let date_stamp = format_date_stamp(now);

    // Create canonical request for signing
    let host = format!("api.ecr.{region}.{domain_suffix}");
    let payload_hash = sha256_hex(request_body.to_string().as_bytes());

    let canonical_headers = format!(
        "content-type:application/x-amz-json-1.1\nhost:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{}\nx-amz-target:AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken\n",
        creds.session_token
    );
    let signed_headers = "content-type;host;x-amz-date;x-amz-security-token;x-amz-target";

    let canonical_request =
        format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{date_stamp}/{region}/ecr/aws4_request");
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    let string_to_sign =
        format!("{algorithm}\n{amz_date}\n{credential_scope}\n{canonical_request_hash}");

    // Derive signing key
    let k_date = hmac_sha256(
        format!("AWS4{}", creds.secret_access_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"ecr");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "{algorithm} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id
    );

    let response = http_client
        .post(&ecr_endpoint)
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Date", &amz_date)
        .header("X-Amz-Security-Token", &creds.session_token)
        .header(
            "X-Amz-Target",
            "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken",
        )
        .header("Authorization", &authorization)
        .body(request_body.to_string())
        .send()
        .await
        .context("failed to call ECR")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("ECR returned error {status}: {body}");
    }

    let ecr_response: EcrAuthorizationResponse = response
        .json()
        .await
        .context("failed to parse ECR response")?;

    // The authorization token is base64(username:password)
    // We need to extract just the password part
    let auth_data = ecr_response
        .authorization_data
        .first()
        .context("no authorization data in ECR response")?;

    // Decode base64 to get "AWS:password"
    let decoded = base64_decode(&auth_data.authorization_token)
        .context("failed to decode ECR authorization token")?;
    let decoded_str =
        String::from_utf8(decoded).context("ECR authorization token is not valid UTF-8")?;

    // Split on ':' to get the password part
    let password = decoded_str
        .split_once(':')
        .map(|(_, p)| p.to_string())
        .unwrap_or(decoded_str);

    Ok(password)
}

/// ECR GetAuthorizationToken response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcrAuthorizationResponse {
    authorization_data: Vec<EcrAuthorizationData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcrAuthorizationData {
    authorization_token: String,
}

/// Format timestamp for AWS X-Amz-Date header.
fn format_amz_date(ts: jiff::Timestamp) -> String {
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

/// Format timestamp for AWS date stamp (YYYYMMDD).
fn format_date_stamp(ts: jiff::Timestamp) -> String {
    let dt = ts.to_zoned(jiff::tz::TimeZone::UTC);
    format!("{:04}{:02}{:02}", dt.year(), dt.month(), dt.day())
}

/// Compute SHA-256 hash and return as hex string.
fn sha256_hex(data: &[u8]) -> String {
    use aws_lc_rs::digest::{SHA256, digest};
    hex::encode(digest(&SHA256, data).as_ref())
}

/// Compute HMAC-SHA256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use aws_lc_rs::hmac::{HMAC_SHA256, Key, sign};
    let key = Key::new(HMAC_SHA256, key);
    sign(&key, data).as_ref().to_vec()
}

/// Decode base64 string.
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .context("invalid base64")
}

/// GCP external account credential configuration (partial, for reading audience).
#[derive(Debug, Deserialize)]
struct GcpExternalAccountConfig {
    audience: Option<String>,
}

/// Try to read the GCP audience from local config files.
///
/// Looks for vouch credential files in ~/.config/gcloud/vouch-credentials*.json
fn get_local_gcp_audience() -> Option<String> {
    let home = dirs::home_dir()?;
    let gcloud_dir = home.join(".config/gcloud");

    if !gcloud_dir.exists() {
        return None;
    }

    // Look for vouch credential files
    let entries = std::fs::read_dir(&gcloud_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let filename = path.file_name()?.to_string_lossy();

        // Match vouch-credentials.json or vouch-credentials-*.json
        if filename.starts_with("vouch-credentials")
            && filename.ends_with(".json")
            && let Ok(content) = std::fs::read_to_string(&path)
            && let Ok(config) = serde_json::from_str::<GcpExternalAccountConfig>(&content)
            && let Some(audience) = config.audience
        {
            return Some(audience);
        }
    }

    None
}

/// Get credentials for GCP (GCR and Artifact Registry).
async fn get_gcp_credential(server: &str) -> Result<DockerCredential> {
    let client = VouchClient::new(server)?;

    // Get GCP audience from local config (created by 'vouch setup gcp --configure')
    let audience = get_local_gcp_audience().ok_or_else(|| {
        anyhow::anyhow!(
            "GCP not configured. Run 'vouch setup gcp --configure' to set up GCP Workload Identity Federation"
        )
    })?;

    // URL-encode the audience parameter
    let encoded_audience: String =
        url::form_urlencoded::byte_serialize(audience.as_bytes()).collect();
    let path = format!("/v1/credentials/gcp/token?audience={encoded_audience}");

    // Get OIDC token from Vouch server
    let token_response: GcpTokenResponse = client
        .get_authenticated(&path)
        .await
        .context("failed to get GCP OIDC token")?;

    // For GCP registries, we use the OIDC token directly as the password
    // with "oauth2accesstoken" as the username
    Ok(DockerCredential {
        username: "oauth2accesstoken".to_string(),
        secret: token_response.id_token,
    })
}

/// Get credentials for GitHub Container Registry.
async fn get_ghcr_credential(server: &str) -> Result<DockerCredential> {
    let client = VouchClient::new(server)?;

    // Request token from server (no specific owner/repo for GHCR)
    let request = GitHubTokenRequest {
        owner: None,
        repositories: None,
    };

    let response: GitHubTokenResponse = client
        .post_authenticated("/v1/credentials/github/token", &request)
        .await
        .context("failed to get GitHub token")?;

    Ok(DockerCredential {
        username: "x-access-token".to_string(),
        secret: response.token,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_aws_ecr() {
        let result = detect_registry_type("123456789012.dkr.ecr.us-east-1.amazonaws.com");
        assert_eq!(
            result,
            RegistryType::AwsEcr {
                account_id: "123456789012".to_string(),
                region: "us-east-1".to_string(),
                domain_suffix: "amazonaws.com".to_string(),
            }
        );
    }

    #[test]
    fn test_detect_aws_ecr_other_region() {
        let result = detect_registry_type("999888777666.dkr.ecr.eu-west-2.amazonaws.com");
        assert_eq!(
            result,
            RegistryType::AwsEcr {
                account_id: "999888777666".to_string(),
                region: "eu-west-2".to_string(),
                domain_suffix: "amazonaws.com".to_string(),
            }
        );
    }

    #[test]
    fn test_detect_aws_ecr_china() {
        let result = detect_registry_type("123456789012.dkr.ecr.cn-north-1.amazonaws.cn");
        assert_eq!(
            result,
            RegistryType::AwsEcr {
                account_id: "123456789012".to_string(),
                region: "cn-north-1".to_string(),
                domain_suffix: "amazonaws.cn".to_string(),
            }
        );
    }

    #[test]
    fn test_detect_aws_ecr_china_northwest() {
        let result = detect_registry_type("123456789012.dkr.ecr.cn-northwest-1.amazonaws.cn");
        assert_eq!(
            result,
            RegistryType::AwsEcr {
                account_id: "123456789012".to_string(),
                region: "cn-northwest-1".to_string(),
                domain_suffix: "amazonaws.cn".to_string(),
            }
        );
    }

    #[test]
    fn test_detect_aws_ecr_eu_sovereign() {
        let result = detect_registry_type("097677866361.dkr.ecr.eusc-de-east-1.amazonaws.eu");
        assert_eq!(
            result,
            RegistryType::AwsEcr {
                account_id: "097677866361".to_string(),
                region: "eusc-de-east-1".to_string(),
                domain_suffix: "amazonaws.eu".to_string(),
            }
        );
    }

    #[test]
    fn test_detect_aws_ecr_govcloud() {
        let result = detect_registry_type("123456789012.dkr.ecr.us-gov-west-1.amazonaws.com");
        assert_eq!(
            result,
            RegistryType::AwsEcr {
                account_id: "123456789012".to_string(),
                region: "us-gov-west-1".to_string(),
                domain_suffix: "amazonaws.com".to_string(),
            }
        );
    }

    #[test]
    fn test_detect_aws_ecr_govcloud_east() {
        let result = detect_registry_type("123456789012.dkr.ecr.us-gov-east-1.amazonaws.com");
        assert_eq!(
            result,
            RegistryType::AwsEcr {
                account_id: "123456789012".to_string(),
                region: "us-gov-east-1".to_string(),
                domain_suffix: "amazonaws.com".to_string(),
            }
        );
    }

    #[test]
    fn test_detect_ghcr() {
        assert_eq!(detect_registry_type("ghcr.io"), RegistryType::Ghcr);
    }

    #[test]
    fn test_detect_gcr() {
        assert_eq!(detect_registry_type("gcr.io"), RegistryType::Gcr);
        assert_eq!(detect_registry_type("us.gcr.io"), RegistryType::Gcr);
        assert_eq!(detect_registry_type("eu.gcr.io"), RegistryType::Gcr);
        assert_eq!(detect_registry_type("asia.gcr.io"), RegistryType::Gcr);
    }

    #[test]
    fn test_detect_gar() {
        assert_eq!(
            detect_registry_type("us-docker.pkg.dev"),
            RegistryType::GarDocker {
                region: "us".to_string(),
                project: None,
            }
        );
        assert_eq!(
            detect_registry_type("europe-docker.pkg.dev"),
            RegistryType::GarDocker {
                region: "europe".to_string(),
                project: None,
            }
        );
    }

    #[test]
    fn test_detect_unknown() {
        assert_eq!(detect_registry_type("docker.io"), RegistryType::Unknown);
        assert_eq!(detect_registry_type("quay.io"), RegistryType::Unknown);
    }

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
    fn test_parse_sts_xml_response_valid() {
        let xml = r#"
            <AssumeRoleWithWebIdentityResponse>
                <AssumeRoleWithWebIdentityResult>
                    <Credentials>
                        <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
                        <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
                        <SessionToken>FwoGZXIvYXdzEBYaDM...</SessionToken>
                        <Expiration>2024-01-15T18:30:45Z</Expiration>
                    </Credentials>
                </AssumeRoleWithWebIdentityResult>
            </AssumeRoleWithWebIdentityResponse>
        "#;

        let result = parse_sts_xml_response(xml).expect("valid XML");
        let creds = &result.assume_role_with_web_identity_result.credentials;
        assert_eq!(creds.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            creds.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(creds.session_token, "FwoGZXIvYXdzEBYaDM...");
        assert_eq!(creds.expiration, "2024-01-15T18:30:45Z");
    }

    #[test]
    fn test_parse_sts_xml_response_missing_access_key() {
        let xml = r#"
            <AssumeRoleWithWebIdentityResponse>
                <AssumeRoleWithWebIdentityResult>
                    <Credentials>
                        <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
                        <SessionToken>FwoGZXIvYXdzEBYaDM...</SessionToken>
                        <Expiration>2024-01-15T18:30:45Z</Expiration>
                    </Credentials>
                </AssumeRoleWithWebIdentityResult>
            </AssumeRoleWithWebIdentityResponse>
        "#;

        let result = parse_sts_xml_response(xml);
        assert!(result.is_err());
        let err = result.expect_err("should fail with missing AccessKeyId");
        assert!(err.to_string().contains("AccessKeyId"));
    }

    #[test]
    fn test_base64_decode_valid() {
        // "AWS:password" encoded in base64
        let encoded = "QVdTOnBhc3N3b3Jk";
        let result = base64_decode(encoded).expect("valid base64");
        let decoded = String::from_utf8(result).expect("valid UTF-8");
        assert_eq!(decoded, "AWS:password");
    }

    #[test]
    fn test_base64_decode_invalid() {
        let invalid = "not-valid-base64!!!";
        let result = base64_decode(invalid);
        assert!(result.is_err());
    }
}
