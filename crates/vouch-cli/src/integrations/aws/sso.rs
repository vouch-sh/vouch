// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS SSO portal API client for IAM Identity Center.
//!
//! These APIs use bearer token authentication (the SSO access token from
//! `CreateTokenWithIAM`), not SigV4.
//!
//! # Reference
//!
//! <https://docs.aws.amazon.com/singlesignon/latest/PortalAPIReference/ssoportal-api.pdf>

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

/// Temporary AWS credentials from `GetRoleCredentials`.
pub struct SsoRoleCredentials {
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    pub session_token: SecretString,
    /// Milliseconds since epoch.
    pub expiration: i64,
}

impl std::fmt::Debug for SsoRoleCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoRoleCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .field("expiration", &self.expiration)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetRoleCredentialsResponse {
    role_credentials: RoleCredentialsInner,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleCredentialsInner {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: i64,
}

/// An AWS account available via SSO.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct SsoAccount {
    pub account_id: String,
    pub account_name: String,
    pub email_address: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct ListAccountsResponse {
    account_list: Vec<SsoAccount>,
}

/// An IAM role available for an account via SSO.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct SsoAccountRole {
    pub role_name: String,
    pub account_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct ListAccountRolesResponse {
    role_list: Vec<SsoAccountRole>,
}

/// Build the SSO portal base URL for the given region and DNS suffix.
fn portal_base_url(region: &str, domain_suffix: &str) -> String {
    format!("https://portal.sso.{region}.{domain_suffix}")
}

/// Get temporary AWS credentials for a specific account and role.
///
/// # Arguments
/// * `access_token` - SSO access token from `CreateTokenWithIAM`
/// * `account_id` - Target AWS account ID
/// * `role_name` - Permission set role name
/// * `region` - Identity Center region
/// * `domain_suffix` - DNS suffix for the partition
pub async fn get_role_credentials(
    http_client: &reqwest::Client,
    access_token: &SecretString,
    account_id: &str,
    role_name: &str,
    region: &str,
    domain_suffix: &str,
) -> Result<SsoRoleCredentials> {
    let url = format!(
        "{}/federation/credentials?account_id={account_id}&role_name={role_name}",
        portal_base_url(region, domain_suffix),
    );

    let response = http_client
        .get(&url)
        .header(
            "x-amz-sso_bearer_token",
            access_token.expose_secret(),
        )
        .send()
        .await
        .context("failed to call SSO GetRoleCredentials")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let truncated = body.get(..500).unwrap_or(&body);
        anyhow::bail!("SSO GetRoleCredentials returned {status}: {truncated}");
    }

    let resp: GetRoleCredentialsResponse = response
        .json()
        .await
        .context("failed to parse GetRoleCredentials response")?;

    let rc = resp.role_credentials;
    Ok(SsoRoleCredentials {
        access_key_id: rc.access_key_id,
        secret_access_key: SecretString::from(rc.secret_access_key),
        session_token: SecretString::from(rc.session_token),
        expiration: rc.expiration,
    })
}

#[allow(dead_code)]
/// List all AWS accounts available to the authenticated user.
///
/// # Arguments
/// * `access_token` - SSO access token from `CreateTokenWithIAM`
/// * `region` - Identity Center region
/// * `domain_suffix` - DNS suffix for the partition
pub async fn list_accounts(
    http_client: &reqwest::Client,
    access_token: &SecretString,
    region: &str,
    domain_suffix: &str,
) -> Result<Vec<SsoAccount>> {
    let url = format!(
        "{}/assignment/accounts",
        portal_base_url(region, domain_suffix),
    );

    let response = http_client
        .get(&url)
        .header(
            "x-amz-sso_bearer_token",
            access_token.expose_secret(),
        )
        .send()
        .await
        .context("failed to call SSO ListAccounts")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let truncated = body.get(..500).unwrap_or(&body);
        anyhow::bail!("SSO ListAccounts returned {status}: {truncated}");
    }

    let resp: ListAccountsResponse = response
        .json()
        .await
        .context("failed to parse ListAccounts response")?;

    Ok(resp.account_list)
}

#[allow(dead_code)]
/// List all roles available for a specific account.
///
/// # Arguments
/// * `access_token` - SSO access token from `CreateTokenWithIAM`
/// * `account_id` - AWS account ID
/// * `region` - Identity Center region
/// * `domain_suffix` - DNS suffix for the partition
pub async fn list_account_roles(
    http_client: &reqwest::Client,
    access_token: &SecretString,
    account_id: &str,
    region: &str,
    domain_suffix: &str,
) -> Result<Vec<SsoAccountRole>> {
    let url = format!(
        "{}/assignment/roles?account_id={account_id}",
        portal_base_url(region, domain_suffix),
    );

    let response = http_client
        .get(&url)
        .header(
            "x-amz-sso_bearer_token",
            access_token.expose_secret(),
        )
        .send()
        .await
        .context("failed to call SSO ListAccountRoles")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let truncated = body.get(..500).unwrap_or(&body);
        anyhow::bail!("SSO ListAccountRoles returned {status}: {truncated}");
    }

    let resp: ListAccountRolesResponse = response
        .json()
        .await
        .context("failed to parse ListAccountRoles response")?;

    Ok(resp.role_list)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_role_credentials_response() {
        let json = r#"{
            "roleCredentials": {
                "accessKeyId": "ASIAEXAMPLE",
                "secretAccessKey": "secret123",
                "sessionToken": "token456",
                "expiration": 1710000000000
            }
        }"#;
        let resp: GetRoleCredentialsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.role_credentials.access_key_id, "ASIAEXAMPLE");
        assert_eq!(resp.role_credentials.expiration, 1_710_000_000_000);
    }

    #[test]
    fn test_parse_list_accounts_response() {
        let json = r#"{
            "accountList": [
                {
                    "accountId": "123456789012",
                    "accountName": "Production",
                    "emailAddress": "prod@example.com"
                },
                {
                    "accountId": "234567890123",
                    "accountName": "Development",
                    "emailAddress": "dev@example.com"
                }
            ]
        }"#;
        let resp: ListAccountsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.account_list.len(), 2);
        assert_eq!(resp.account_list.first().unwrap().account_id, "123456789012");
        assert_eq!(resp.account_list[1].account_name, "Development");
    }

    #[test]
    fn test_parse_list_account_roles_response() {
        let json = r#"{
            "roleList": [
                {
                    "roleName": "AdministratorAccess",
                    "accountId": "123456789012"
                },
                {
                    "roleName": "ReadOnlyAccess",
                    "accountId": "123456789012"
                }
            ]
        }"#;
        let resp: ListAccountRolesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.role_list.len(), 2);
        assert_eq!(
            resp.role_list.first().unwrap().role_name,
            "AdministratorAccess"
        );
    }

    #[test]
    fn test_portal_base_url() {
        assert_eq!(
            portal_base_url("us-east-1", "amazonaws.com"),
            "https://portal.sso.us-east-1.amazonaws.com"
        );
    }
}
