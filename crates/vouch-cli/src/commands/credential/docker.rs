// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Docker credential helper for container registries.
//!
//! This module implements a Docker credential helper that provides authentication
//! for container registries using Vouch. It supports:
//! - AWS ECR (Elastic Container Registry)
//! - GitHub Container Registry (ghcr.io)
//!
//! Usage: Configure Docker to use this helper:
//!   ~/.docker/config.json:
//!   {
//!     "credHelpers": {
//!       "123456789012.dkr.ecr.us-east-1.amazonaws.com": "vouch",
//!       "ghcr.io": "vouch"
//!     }
//!   }
//!
//! Or use `vouch setup docker --configure` to set this up automatically.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::io::{BufRead, Write};
use vouch_common::{GitHubTokenRequest, GitHubTokenResponse};

use crate::client::VouchClient;
use crate::commands::credential::aws::{StsExchangeOptions, exchange_for_sts_credentials};
use crate::integrations::aws::get_local_aws_role;
use crate::integrations::aws::sigv4::sign_and_send_json_rpc;
use crate::integrations::aws::sts::StsCredentials;
use crate::session::resolve_session;

/// Docker credential helper output format.
/// See: https://docs.docker.com/engine/reference/commandline/login/#credential-helper-protocol
struct DockerCredential {
    username: String,
    secret: SecretString,
}

impl DockerCredential {
    /// Serialize to the JSON format expected by Docker.
    ///
    /// Field names MUST be PascalCase: `Username`, `Secret`.
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "Username": self.username,
            "Secret": self.secret.expose_secret(),
        })
    }
}

impl std::fmt::Debug for DockerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerCredential")
            .field("username", &self.username)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Registry type detected from the server URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegistryType {
    /// AWS Elastic Container Registry
    AwsEcr {
        account_id: String,
        region: String,
        /// Domain suffix (e.g., "amazonaws.com", "amazonaws.cn", "amazonaws.eu")
        domain_suffix: String,
    },
    /// GitHub Container Registry (ghcr.io)
    Ghcr,
    /// Unknown registry type
    Unknown,
}

/// Run the Docker credential helper.
///
/// This is called when Docker invokes `docker-credential-vouch <operation>`.
///
/// # Arguments
/// * `operation` - The Docker credential operation ("get", "store", "erase", or "list")
pub(crate) async fn run(operation: &str) -> Result<()> {
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
pub(crate) fn detect_registry_type(server_url: &str) -> RegistryType {
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

    RegistryType::Unknown
}

/// Handle the "get" operation - provide credentials to Docker.
async fn get_credential() -> Result<()> {
    // Read server URL from stdin
    let server_url = read_server_url()?;

    if server_url.is_empty() {
        return Err(
            crate::exit_code::CliError::ConfigError("no server URL provided".to_string()).into(),
        );
    }

    // Detect registry type
    let registry_type = detect_registry_type(&server_url);

    // Resolve session (tries agent first, then config)
    let session = resolve_session().await.inspect_err(|_| {
        eprintln!("vouch: not configured - run 'vouch enroll' first");
    })?;
    let server = session.server_url.as_str();

    // Get credentials based on registry type
    let credential = match registry_type {
        RegistryType::AwsEcr {
            region,
            domain_suffix,
            ..
        } => {
            get_ecr_credential(server, &session.token, &region, &domain_suffix, &server_url).await?
        }
        RegistryType::Ghcr => get_ghcr_credential(server, &session.token).await?,
        RegistryType::Unknown => {
            eprintln!("vouch: unknown registry type for URL: {}", server_url);
            return Err(crate::exit_code::CliError::ConfigError(format!(
                "unsupported registry: {server_url}"
            ))
            .into());
        }
    };

    // Output credentials to stdout in Docker credential helper format
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let json_str =
        serde_json::to_string(&credential.to_json()).context("failed to serialize credentials")?;
    writeln!(out, "{json_str}")?;

    Ok(())
}

/// Get credentials for AWS ECR.
async fn get_ecr_credential(
    server: &str,
    _token: &SecretString,
    region: &str,
    domain_suffix: &str,
    registry_url: &str,
) -> Result<DockerCredential> {
    let role_arn = get_local_aws_role().ok_or_else(|| {
        anyhow::anyhow!(
            "AWS not configured. Run 'vouch setup aws --role <role-arn>' \
             with a role that has ECR permissions"
        )
    })?;

    let result = exchange_for_sts_credentials(
        server,
        &role_arn,
        region,
        "vouch-docker",
        &StsExchangeOptions::default(),
    )
    .await?;

    // Call ECR GetAuthorizationToken
    let ecr_token = get_ecr_authorization_token(
        &result.http_client,
        region,
        domain_suffix,
        registry_url,
        &result.credentials,
    )
    .await
    .context("failed to get ECR authorization token")?;

    Ok(DockerCredential {
        username: "AWS".to_string(),
        secret: ecr_token,
    })
}

/// Get ECR authorization token using AWS credentials.
async fn get_ecr_authorization_token(
    http_client: &reqwest::Client,
    region: &str,
    domain_suffix: &str,
    registry_url: &str,
    creds: &StsCredentials,
) -> Result<SecretString> {
    // Extract account ID from registry URL
    let account_id = registry_url
        .split('.')
        .next()
        .context("invalid ECR registry URL")?;

    let ecr_endpoint = format!("https://api.ecr.{region}.{domain_suffix}");

    let request_body = serde_json::json!({
        "registryIds": [account_id]
    });

    let response_body = sign_and_send_json_rpc(
        http_client,
        &ecr_endpoint,
        "ecr",
        "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken",
        region,
        creds,
        &request_body,
    )
    .await
    .context("failed to call ECR GetAuthorizationToken")?;

    let ecr_response: EcrAuthorizationResponse =
        serde_json::from_str(&response_body).context("failed to parse ECR response")?;

    // The authorization token is base64(username:password)
    // We need to extract just the password part
    let auth_data = ecr_response
        .authorization_data
        .first()
        .context("no authorization data in ECR response")?;

    // Decode base64 to get "AWS:password"
    let decoded = base64_decode(auth_data.authorization_token.expose_secret())
        .context("failed to decode ECR authorization token")?;
    let decoded_str =
        String::from_utf8(decoded).context("ECR authorization token is not valid UTF-8")?;

    // Split on ':' to get the password part
    let password = decoded_str
        .split_once(':')
        .map(|(_, p)| p.to_string())
        .unwrap_or(decoded_str);

    Ok(SecretString::from(password))
}

/// ECR GetAuthorizationToken response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcrAuthorizationResponse {
    authorization_data: Vec<EcrAuthorizationData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcrAuthorizationData {
    authorization_token: SecretString,
}

impl std::fmt::Debug for EcrAuthorizationData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcrAuthorizationData")
            .field("authorization_token", &"[REDACTED]")
            .finish()
    }
}

/// Decode base64 string.
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .context("invalid base64")
}

/// Get credentials for GitHub Container Registry.
async fn get_ghcr_credential(server: &str, token: &SecretString) -> Result<DockerCredential> {
    let mut client = VouchClient::unauthenticated(server)?;
    client.set_token(token.clone());

    // Request token from server (no specific owner/repo for GHCR)
    let request = GitHubTokenRequest::default();

    let response: GitHubTokenResponse = client
        .post_authenticated("/v1/credentials/github/token", &request)
        .await
        .context("failed to get GitHub token")?;

    Ok(DockerCredential {
        username: "x-access-token".to_string(),
        secret: response.token.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
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
    fn test_detect_unknown() {
        assert_eq!(detect_registry_type("docker.io"), RegistryType::Unknown);
        assert_eq!(detect_registry_type("quay.io"), RegistryType::Unknown);
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

    /// Verify the Docker credential helper JSON matches the format Docker expects.
    /// Field names must be PascalCase: `Username`, `Secret`.
    /// See: https://docs.docker.com/engine/reference/commandline/login/#credential-helper-protocol
    #[test]
    fn test_docker_credential_json_format() {
        let cred = DockerCredential {
            username: "AWS".to_string(),
            secret: SecretString::from("docker-password-here".to_string()),
        };

        let json = cred.to_json();

        assert_eq!(json["Username"], "AWS");
        assert_eq!(json["Secret"], "docker-password-here");
        // Must have exactly 2 fields
        assert_eq!(json.as_object().unwrap().len(), 2);
    }

    /// Verify GHCR credential uses the correct username.
    #[test]
    fn test_docker_credential_ghcr_format() {
        let cred = DockerCredential {
            username: "x-access-token".to_string(),
            secret: SecretString::from("ghu_example_token".to_string()),
        };

        let json = cred.to_json();

        assert_eq!(json["Username"], "x-access-token");
        assert_eq!(json["Secret"], "ghu_example_token");
    }
}
