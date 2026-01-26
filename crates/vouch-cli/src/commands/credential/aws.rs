//! AWS credential command.
//!
//! Obtains temporary AWS credentials using Vouch session and STS.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::client::VouchClient;

/// AWS credential process output format.
/// See: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct CredentialProcessOutput {
    version: u32,
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
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
    expiration: String,
}

/// Response from Vouch OIDC token endpoint.
#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    id_token: String,
}

/// Run the AWS credential command.
///
/// This command:
/// 1. Gets an OIDC ID token from the Vouch server
/// 2. Calls AWS STS AssumeRoleWithWebIdentity
/// 3. Outputs credentials in credential_process format
pub async fn run(server: &str, role_arn: &str, session_name: Option<&str>) -> Result<()> {
    let client = VouchClient::new(server)?;

    // Get OIDC token from Vouch server
    let token_response: OidcTokenResponse = client
        .get_authenticated("/v1/credentials/aws/token")
        .await
        .context("failed to get OIDC token from Vouch server")?;

    // Call AWS STS AssumeRoleWithWebIdentity
    let session = session_name.unwrap_or("vouch-session");
    let sts_response = assume_role_with_web_identity(role_arn, session, &token_response.id_token)
        .await
        .context("failed to assume AWS role")?;

    // Output in credential_process format
    let output = CredentialProcessOutput {
        version: 1,
        access_key_id: sts_response
            .assume_role_with_web_identity_result
            .credentials
            .access_key_id,
        secret_access_key: sts_response
            .assume_role_with_web_identity_result
            .credentials
            .secret_access_key,
        session_token: sts_response
            .assume_role_with_web_identity_result
            .credentials
            .session_token,
        expiration: sts_response
            .assume_role_with_web_identity_result
            .credentials
            .expiration,
    };

    let json = serde_json::to_string(&output).context("failed to serialize credentials")?;
    println!("{json}");

    Ok(())
}

/// Call AWS STS AssumeRoleWithWebIdentity.
async fn assume_role_with_web_identity(
    role_arn: &str,
    role_session_name: &str,
    web_identity_token: &str,
) -> Result<AssumeRoleWithWebIdentityResponse> {
    let http_client = reqwest::Client::new();

    // AWS STS uses query parameters for this API
    let response = http_client
        .post("https://sts.amazonaws.com/")
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

    // AWS STS returns XML, but we can ask for JSON
    let body = response
        .text()
        .await
        .context("failed to read STS response")?;

    // Parse XML response (AWS STS returns XML by default)
    parse_sts_xml_response(&body)
}

/// Parse AWS STS XML response.
fn parse_sts_xml_response(xml: &str) -> Result<AssumeRoleWithWebIdentityResponse> {
    // Simple XML parsing for the specific fields we need
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
