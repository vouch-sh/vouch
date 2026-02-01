// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS credential command.
//!
//! Obtains temporary AWS credentials using Vouch session and STS.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::aws::sts::{
    assume_role_with_web_identity, extract_partition_from_role_arn,
    get_default_region_for_partition, get_domain_suffix_for_partition,
};
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

/// Response from Vouch OIDC token endpoint.
#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    id_token: String,
}

/// Run the AWS credential command.
///
/// This command:
/// 1. Gets an OIDC ID token from the Vouch server
/// 2. Calls AWS STS `AssumeRoleWithWebIdentity`
/// 3. Outputs credentials in `credential_process` format
pub async fn run(server: &str, role_arn: &str, session_name: Option<&str>) -> Result<()> {
    let client = VouchClient::new(server)?;

    // Get OIDC token from Vouch server
    let token_response: OidcTokenResponse = client
        .get_authenticated("/v1/credentials/aws/token")
        .await
        .context("failed to get OIDC token from Vouch server")?;

    // Determine region and domain suffix from role ARN partition
    let partition = extract_partition_from_role_arn(role_arn).unwrap_or("aws");
    let region = get_default_region_for_partition(partition);
    let domain_suffix = get_domain_suffix_for_partition(partition);

    // Call AWS STS AssumeRoleWithWebIdentity
    let session = session_name.unwrap_or("vouch-session");
    let sts_response = assume_role_with_web_identity(
        role_arn,
        session,
        &token_response.id_token,
        region,
        domain_suffix,
    )
    .await
    .context("failed to assume AWS role")?;

    // Output in credential_process format
    let creds = &sts_response
        .assume_role_with_web_identity_result
        .credentials;
    let output = CredentialProcessOutput {
        version: 1,
        access_key_id: creds.access_key_id.clone(),
        secret_access_key: creds.secret_access_key.expose_secret().to_string(),
        session_token: creds.session_token.expose_secret().to_string(),
        expiration: creds.expiration.clone(),
    };

    let json = serde_json::to_string(&output).context("failed to serialize credentials")?;
    println!("{json}");

    Ok(())
}
