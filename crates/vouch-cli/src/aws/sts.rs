// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS STS (Security Token Service) utilities.
//!
//! Provides shared types and functions for calling AWS STS, with sensitive
//! credential fields protected using `SecretString`.

use anyhow::{Context, Result};
use secrecy::SecretString;

/// AWS STS `AssumeRoleWithWebIdentity` response.
#[derive(Debug)]
pub struct AssumeRoleWithWebIdentityResponse {
    pub assume_role_with_web_identity_result: AssumeRoleResult,
}

#[derive(Debug)]
pub struct AssumeRoleResult {
    pub credentials: StsCredentials,
}

/// AWS STS temporary credentials.
///
/// Sensitive fields (`secret_access_key`, `session_token`) use `SecretString`
/// for memory protection and automatic zeroing on drop.
pub struct StsCredentials {
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    pub session_token: SecretString,
    pub expiration: String,
}

impl std::fmt::Debug for StsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StsCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Call AWS STS `AssumeRoleWithWebIdentity`.
///
/// Uses regional STS endpoints to support all AWS partitions
/// (commercial, China, GovCloud, EU Sovereign Cloud).
///
/// # Arguments
/// * `role_arn` - The ARN of the role to assume
/// * `role_session_name` - An identifier for the assumed role session
/// * `web_identity_token` - The OIDC ID token from Vouch
/// * `region` - AWS region (e.g., "us-east-1", "cn-north-1")
/// * `domain_suffix` - AWS domain suffix (e.g., "amazonaws.com", "amazonaws.cn")
pub async fn assume_role_with_web_identity(
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
                secret_access_key: SecretString::from(secret_access_key),
                session_token: SecretString::from(session_token),
                expiration,
            },
        },
    })
}

/// Extract region from an AWS role ARN.
///
/// Role ARNs are region-agnostic (IAM is global), but we can infer the partition
/// from the ARN and use an appropriate default region.
///
/// Returns `None` if the ARN doesn't have enough information to determine a region.
#[must_use]
pub fn extract_partition_from_role_arn(role_arn: &str) -> Option<&str> {
    // ARN format: arn:partition:iam::account-id:role/role-name
    // e.g., arn:aws:iam::123456789012:role/MyRole
    //       arn:aws-cn:iam::123456789012:role/MyRole
    //       arn:aws-us-gov:iam::123456789012:role/MyRole
    let parts: Vec<&str> = role_arn.split(':').collect();
    if parts.len() >= 2 && parts.first() == Some(&"arn") {
        return parts.get(1).copied();
    }
    None
}

/// Get the domain suffix for an AWS partition.
///
/// # Arguments
/// * `partition` - AWS partition identifier (e.g., "aws", "aws-cn", "aws-us-gov")
#[must_use]
pub fn get_domain_suffix_for_partition(partition: &str) -> &'static str {
    match partition {
        "aws-cn" => "amazonaws.cn",
        "aws-iso" => "c2s.ic.gov",
        "aws-iso-b" => "sc2s.sgov.gov",
        "aws-iso-e" => "cloud.adc-e.uk",
        "aws-iso-f" => "csp.hci.ic.gov",
        // Commercial (aws), GovCloud (aws-us-gov), and EU Sovereign (implicit)
        // all use amazonaws.com
        _ => "amazonaws.com",
    }
}

/// Get the default region for an AWS partition.
///
/// # Arguments
/// * `partition` - AWS partition identifier (e.g., "aws", "aws-cn", "aws-us-gov")
#[must_use]
pub fn get_default_region_for_partition(partition: &str) -> &'static str {
    match partition {
        "aws-cn" => "cn-north-1",
        "aws-us-gov" => "us-gov-west-1",
        "aws-iso" => "us-iso-east-1",
        "aws-iso-b" => "us-isob-east-1",
        "aws-iso-e" => "eu-isoe-west-1",
        "aws-iso-f" => "us-isof-south-1",
        _ => "us-east-1",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

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
        assert_eq!(creds.expiration, "2024-01-15T18:30:45Z");

        // Verify SecretString fields work correctly
        use secrecy::ExposeSecret;
        assert_eq!(
            creds.secret_access_key.expose_secret(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(creds.session_token.expose_secret(), "FwoGZXIvYXdzEBYaDM...");
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
    fn test_credentials_debug_redacted() {
        let creds = StsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from("wJalrXUtnFEMI/K7MDENG".to_string()),
            session_token: SecretString::from("FwoGZXIvYXdzEBYaDM".to_string()),
            expiration: "2024-01-15T18:30:45Z".to_string(),
        };
        let debug = format!("{:?}", creds);
        // Verify sensitive data is not exposed in Debug output
        assert!(!debug.contains("wJalrXUtnFEMI/K7MDENG"));
        assert!(!debug.contains("FwoGZXIvYXdzEBYaDM"));
        assert!(debug.contains("[REDACTED]"));
        // Non-sensitive data should still be visible
        assert!(debug.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(debug.contains("2024-01-15T18:30:45Z"));
    }

    #[test]
    fn test_extract_partition_from_role_arn() {
        assert_eq!(
            extract_partition_from_role_arn("arn:aws:iam::123456789012:role/MyRole"),
            Some("aws")
        );
        assert_eq!(
            extract_partition_from_role_arn("arn:aws-cn:iam::123456789012:role/MyRole"),
            Some("aws-cn")
        );
        assert_eq!(
            extract_partition_from_role_arn("arn:aws-us-gov:iam::123456789012:role/MyRole"),
            Some("aws-us-gov")
        );
        assert_eq!(extract_partition_from_role_arn("invalid"), None);
        assert_eq!(extract_partition_from_role_arn(""), None);
    }

    #[test]
    fn test_get_domain_suffix_for_partition() {
        assert_eq!(get_domain_suffix_for_partition("aws"), "amazonaws.com");
        assert_eq!(get_domain_suffix_for_partition("aws-cn"), "amazonaws.cn");
        assert_eq!(
            get_domain_suffix_for_partition("aws-us-gov"),
            "amazonaws.com"
        );
        assert_eq!(get_domain_suffix_for_partition("aws-iso"), "c2s.ic.gov");
        assert_eq!(get_domain_suffix_for_partition("unknown"), "amazonaws.com");
    }

    #[test]
    fn test_get_default_region_for_partition() {
        assert_eq!(get_default_region_for_partition("aws"), "us-east-1");
        assert_eq!(get_default_region_for_partition("aws-cn"), "cn-north-1");
        assert_eq!(
            get_default_region_for_partition("aws-us-gov"),
            "us-gov-west-1"
        );
        assert_eq!(get_default_region_for_partition("aws-iso"), "us-iso-east-1");
        assert_eq!(get_default_region_for_partition("unknown"), "us-east-1");
    }
}
