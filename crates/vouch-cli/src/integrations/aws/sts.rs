// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS STS (Security Token Service) utilities.
//!
//! Provides shared types and functions for calling AWS STS, with sensitive
//! credential fields protected using `SecretString`.

use anyhow::{Context, Result};
use jiff::Timestamp;
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
    pub expiration: Timestamp,
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
    http_client: &reqwest::Client,
    role_arn: &str,
    role_session_name: &str,
    web_identity_token: &str,
    region: &str,
    domain_suffix: &str,
    tags: &[(String, String)],
) -> Result<AssumeRoleWithWebIdentityResponse> {
    // Use regional STS endpoint for the appropriate partition
    // e.g., "sts.us-east-1.amazonaws.com" or "sts.cn-north-1.amazonaws.cn"
    let sts_url = format!("https://sts.{region}.{domain_suffix}/");

    let mut form_params: Vec<(String, String)> = vec![
        (
            "Action".to_string(),
            "AssumeRoleWithWebIdentity".to_string(),
        ),
        ("Version".to_string(), "2011-06-15".to_string()),
        ("RoleArn".to_string(), role_arn.to_string()),
        ("RoleSessionName".to_string(), role_session_name.to_string()),
        (
            "WebIdentityToken".to_string(),
            web_identity_token.to_string(),
        ),
    ];

    // Add session tags using AWS Tags.member.N format (1-based indexing)
    append_tag_form_params(&mut form_params, tags);

    let response = http_client
        .post(&sts_url)
        .form(&form_params)
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

/// Append session tag parameters to the form body.
///
/// Uses the AWS `Tags.member.N.Key` / `Tags.member.N.Value` format
/// with 1-based indexing.
fn append_tag_form_params(params: &mut Vec<(String, String)>, tags: &[(String, String)]) {
    for (i, (key, value)) in tags.iter().enumerate() {
        let n = i + 1;
        params.push((format!("Tags.member.{n}.Key"), key.clone()));
        params.push((format!("Tags.member.{n}.Value"), value.clone()));
    }
}

/// Parse AWS STS XML response using `roxmltree`.
fn parse_sts_xml_response(xml: &str) -> Result<AssumeRoleWithWebIdentityResponse> {
    let doc = roxmltree::Document::parse(xml).context("failed to parse STS XML response")?;

    // Find the Credentials element anywhere in the document
    let credentials_node = doc
        .descendants()
        .find(|n| n.has_tag_name("Credentials"))
        .context("missing Credentials element in STS response")?;

    let extract_child_text = |parent: roxmltree::Node, tag: &str| -> Result<String> {
        parent
            .children()
            .find(|n| n.has_tag_name(tag))
            .and_then(|n| n.text())
            .map(String::from)
            .with_context(|| format!("missing {tag} in STS response"))
    };

    let access_key_id = extract_child_text(credentials_node, "AccessKeyId")?;
    let secret_access_key = extract_child_text(credentials_node, "SecretAccessKey")?;
    let session_token = extract_child_text(credentials_node, "SessionToken")?;
    let expiration_str = extract_child_text(credentials_node, "Expiration")?;
    let expiration = expiration_str
        .parse::<Timestamp>()
        .with_context(|| format!("failed to parse STS Expiration: {expiration_str}"))?;

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

/// Validate that a role ARN has the expected format.
///
/// Expected format: `arn:{partition}:iam::{account-id}:role/{role-name}`
///
/// # Errors
///
/// Returns an error if the ARN does not match the expected format.
pub fn validate_role_arn(role_arn: &str) -> Result<()> {
    let parts: Vec<&str> = role_arn.split(':').collect();
    // A valid IAM role ARN has exactly 6 colon-separated parts:
    // arn : partition : iam : (empty region) : account-id : role/role-name
    if parts.len() < 6
        || parts.first() != Some(&"arn")
        || parts.get(2) != Some(&"iam")
        || !parts
            .get(5)
            .is_some_and(|s| s.starts_with("role/") && s.len() > 5)
    {
        anyhow::bail!(
            "Invalid role ARN format: {role_arn}\n\
             Expected: arn:<partition>:iam::<account-id>:role/<role-name>\n\
             Example:  arn:aws:iam::123456789012:role/MyRole"
        );
    }
    Ok(())
}

/// Extract partition from an AWS role ARN.
///
/// Role ARNs are region-agnostic (IAM is global), but we can infer the partition
/// from the ARN and use an appropriate default region.
///
/// The ARN must be validated with [`validate_role_arn`] before calling this.
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
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
        assert_eq!(
            creds.expiration,
            "2024-01-15T18:30:45Z".parse::<Timestamp>().unwrap()
        );

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
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };
        let debug = format!("{:?}", creds);
        // Verify sensitive data is not exposed in Debug output
        assert!(!debug.contains("wJalrXUtnFEMI/K7MDENG"));
        assert!(!debug.contains("FwoGZXIvYXdzEBYaDM"));
        assert!(debug.contains("[REDACTED]"));
        // Non-sensitive data should still be visible
        assert!(debug.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(debug.contains("2024-01-15T18:30:45"));
    }

    #[test]
    fn test_validate_role_arn_valid() {
        assert!(validate_role_arn("arn:aws:iam::123456789012:role/MyRole").is_ok());
        assert!(validate_role_arn("arn:aws-cn:iam::123456789012:role/MyRole").is_ok());
        assert!(validate_role_arn("arn:aws-us-gov:iam::123456789012:role/MyRole").is_ok());
        assert!(validate_role_arn("arn:aws:iam::123456789012:role/path/to/MyRole").is_ok());
    }

    #[test]
    fn test_validate_role_arn_invalid() {
        assert!(validate_role_arn("invalid").is_err());
        assert!(validate_role_arn("").is_err());
        assert!(validate_role_arn("arn:aws:s3:::my-bucket").is_err());
        assert!(validate_role_arn("arn:aws:iam::123456789012:user/MyUser").is_err());
        assert!(validate_role_arn("arn:aws:iam::123456789012:role/").is_err());
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

    #[test]
    fn test_append_tag_form_params_empty() {
        let mut params = Vec::new();
        append_tag_form_params(&mut params, &[]);
        assert!(params.is_empty());
    }

    #[test]
    fn test_append_tag_form_params_single_tag() {
        let mut params = Vec::new();
        let tags = vec![("email".to_string(), "alice@example.com".to_string())];
        append_tag_form_params(&mut params, &tags);
        assert_eq!(params.len(), 2);
        assert_eq!(
            params[0],
            ("Tags.member.1.Key".to_string(), "email".to_string())
        );
        assert_eq!(
            params[1],
            (
                "Tags.member.1.Value".to_string(),
                "alice@example.com".to_string()
            )
        );
    }

    #[test]
    fn test_append_tag_form_params_multiple_tags() {
        let mut params = vec![(
            "Action".to_string(),
            "AssumeRoleWithWebIdentity".to_string(),
        )];
        let tags = vec![
            ("email".to_string(), "alice@example.com".to_string()),
            ("domain".to_string(), "example.com".to_string()),
        ];
        append_tag_form_params(&mut params, &tags);
        // Original param + 2 tags * 2 params each = 5 total
        assert_eq!(params.len(), 5);
        assert_eq!(
            params[1],
            ("Tags.member.1.Key".to_string(), "email".to_string())
        );
        assert_eq!(
            params[2],
            (
                "Tags.member.1.Value".to_string(),
                "alice@example.com".to_string()
            )
        );
        assert_eq!(
            params[3],
            ("Tags.member.2.Key".to_string(), "domain".to_string())
        );
        assert_eq!(
            params[4],
            ("Tags.member.2.Value".to_string(), "example.com".to_string())
        );
    }
}
