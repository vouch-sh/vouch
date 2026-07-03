// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS SSO Portal API for listing accounts and roles and retrieving role
//! credentials.
//!
//! Uses Bearer token auth via the `x-amz-sso_bearer_token` header (not
//! standard `Authorization: Bearer` — this is what the AWS SDK uses).

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use vouch_cli::tr;
use vouch_common::aws::Partition;

use super::sts::StsCredentials;

/// AWS SSO Portal `GetRoleCredentials` response envelope.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleCredentialsResponse {
    role_credentials: PortalRoleCredentials,
}

/// Temporary role credentials returned by the SSO Portal `GetRoleCredentials`
/// API. `expiration` is Unix epoch **milliseconds** (not seconds).
///
/// The secret fields are deserialized as plain `String` (the workspace builds
/// `secrecy` without its `serde` feature, so `SecretString` is not
/// `Deserialize`) and wrapped into `SecretString` in [`get_role_credentials`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PortalRoleCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    /// Expiry as Unix epoch milliseconds.
    expiration: i64,
}

/// An AWS account the user has access to via SSO.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SsoAccount {
    pub account_id: String,
    pub account_name: String,
    #[allow(
        dead_code,
        reason = "deserialized from AWS SSO portal listing; read in tests, dead in non-test builds"
    )]
    pub email_address: String,
}

/// A role available to the user in a specific SSO-assigned account.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SsoRole {
    pub role_name: String,
    #[allow(
        dead_code,
        reason = "deserialized from AWS SSO portal listing; read in tests, dead in non-test builds"
    )]
    pub account_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListAccountsResponse {
    account_list: Vec<SsoAccount>,
    next_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListAccountRolesResponse {
    role_list: Vec<SsoRole>,
    next_token: Option<String>,
}

/// List all AWS accounts assigned to the user via SSO.
///
/// Paginates automatically with a 100-page safety cap (~10,000 accounts max).
pub(crate) async fn list_accounts(
    http_client: &reqwest::Client,
    region: &str,
    access_token: &SecretString,
) -> Result<Vec<SsoAccount>> {
    let partition = Partition::from_region(region);
    let base_url = partition.sso_portal_endpoint(region);
    let url = format!("{base_url}/assignment/accounts");

    let mut accounts = Vec::new();
    let mut next_token: Option<String> = None;
    let max_pages: u32 = 100;

    for page in 0..max_pages {
        let mut request = http_client
            .get(&url)
            .header("x-amz-sso_bearer_token", access_token.expose_secret())
            .query(&[("max_result", "100")]);

        if let Some(ref token) = next_token {
            request = request.query(&[("next_token", token.as_str())]);
        }

        let response = request
            .send()
            .await
            .context("failed to call SSO Portal list accounts")?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(crate::exit_code::CliError::NotAuthenticated {
                reason: tr!("sso-portal-err-token-expired"),
            }
            .into());
        }

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(crate::exit_code::CliError::NetworkError(format!(
                "SSO Portal list accounts failed {status}: {text}"
            ))
            .into());
        }

        let resp: ListAccountsResponse = response
            .json()
            .await
            .context("failed to parse SSO Portal accounts response")?;

        accounts.extend(resp.account_list);

        match resp.next_token {
            Some(token) if !token.is_empty() => {
                next_token = Some(token);
            }
            _ => break,
        }

        if page == max_pages - 1 {
            tracing::warn!(
                "SSO account list reached {max_pages}-page safety cap; results may be incomplete"
            );
        }
    }

    Ok(accounts)
}

/// List roles available to the user in a specific SSO-assigned account.
///
/// Paginates automatically with a 100-page safety cap.
pub(crate) async fn list_account_roles(
    http_client: &reqwest::Client,
    region: &str,
    access_token: &SecretString,
    account_id: &str,
) -> Result<Vec<SsoRole>> {
    let partition = Partition::from_region(region);
    let base_url = partition.sso_portal_endpoint(region);
    let url = format!("{base_url}/assignment/roles");

    let mut roles = Vec::new();
    let mut next_token: Option<String> = None;
    let max_pages: u32 = 100;

    for page in 0..max_pages {
        let mut request = http_client
            .get(&url)
            .header("x-amz-sso_bearer_token", access_token.expose_secret())
            .query(&[("account_id", account_id), ("max_result", "100")]);

        if let Some(ref token) = next_token {
            request = request.query(&[("next_token", token.as_str())]);
        }

        let response = request
            .send()
            .await
            .context("failed to call SSO Portal list roles")?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(crate::exit_code::CliError::NotAuthenticated {
                reason: tr!("sso-portal-err-token-expired"),
            }
            .into());
        }

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(crate::exit_code::CliError::NetworkError(format!(
                "SSO Portal list roles failed {status}: {text}"
            ))
            .into());
        }

        let resp: ListAccountRolesResponse = response
            .json()
            .await
            .context("failed to parse SSO Portal roles response")?;

        roles.extend(resp.role_list);

        match resp.next_token {
            Some(token) if !token.is_empty() => {
                next_token = Some(token);
            }
            _ => break,
        }

        if page == max_pages - 1 {
            tracing::warn!(
                "SSO roles list for account {account_id} reached {max_pages}-page safety cap"
            );
        }
    }

    Ok(roles)
}

/// Retrieve temporary AWS credentials for a permission-set role in a specific
/// account, on behalf of the SSO-authenticated user.
///
/// This is the credential-issuing counterpart to [`list_accounts`] /
/// [`list_account_roles`]: given an account and a role name from those
/// listings, it returns STS-equivalent credentials directly from the SSO
/// Portal — no `AssumeRole` chaining and no per-role IAM trust policy. Access
/// is governed entirely by the user's IAM Identity Center permission-set
/// assignments.
///
/// `role_name` is the permission-set name (as returned by
/// [`list_account_roles`]); the portal resolves it to the corresponding
/// `AWSReservedSSO_*` role in `account_id`.
pub(crate) async fn get_role_credentials(
    http_client: &reqwest::Client,
    region: &str,
    access_token: &SecretString,
    account_id: &str,
    role_name: &str,
) -> Result<StsCredentials> {
    let partition = Partition::from_region(region);
    let base_url = partition.sso_portal_endpoint(region);
    let url = format!("{base_url}/federation/credentials");

    let response = http_client
        .get(&url)
        .header("x-amz-sso_bearer_token", access_token.expose_secret())
        .query(&[("account_id", account_id), ("role_name", role_name)])
        .send()
        .await
        .context("failed to call SSO Portal get role credentials")?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(crate::exit_code::CliError::NotAuthenticated {
            reason: tr!("sso-portal-err-token-expired"),
        }
        .into());
    }

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(crate::exit_code::CliError::NetworkError(format!(
            "SSO Portal get role credentials failed {status}: {text}"
        ))
        .into());
    }

    let resp: RoleCredentialsResponse = response
        .json()
        .await
        .context("failed to parse SSO Portal role credentials response")?;

    let expiration = jiff::Timestamp::from_millisecond(resp.role_credentials.expiration)
        .context("SSO Portal returned an out-of-range credential expiration")?;

    Ok(StsCredentials {
        access_key_id: resp.role_credentials.access_key_id,
        secret_access_key: SecretString::from(resp.role_credentials.secret_access_key),
        session_token: SecretString::from(resp.role_credentials.session_token),
        expiration,
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_list_accounts_response_deserialization() {
        let json = r#"{
            "accountList": [
                {
                    "accountId": "111111111111",
                    "accountName": "Production",
                    "emailAddress": "prod@example.com"
                },
                {
                    "accountId": "222222222222",
                    "accountName": "Staging",
                    "emailAddress": "staging@example.com"
                }
            ],
            "nextToken": null
        }"#;

        let resp: ListAccountsResponse = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(resp.account_list.len(), 2);
        assert_eq!(resp.account_list[0].account_id, "111111111111");
        assert_eq!(resp.account_list[0].account_name, "Production");
        assert_eq!(resp.account_list[1].account_id, "222222222222");
        assert!(resp.next_token.is_none());
    }

    #[test]
    fn test_list_accounts_response_with_pagination() {
        let json = r#"{
            "accountList": [
                {
                    "accountId": "111111111111",
                    "accountName": "Production",
                    "emailAddress": "prod@example.com"
                }
            ],
            "nextToken": "abc123"
        }"#;

        let resp: ListAccountsResponse = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(resp.account_list.len(), 1);
        assert_eq!(resp.next_token.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_list_account_roles_response_deserialization() {
        let json = r#"{
            "roleList": [
                {
                    "roleName": "AdministratorAccess",
                    "accountId": "111111111111"
                },
                {
                    "roleName": "ViewOnlyAccess",
                    "accountId": "111111111111"
                }
            ],
            "nextToken": null
        }"#;

        let resp: ListAccountRolesResponse = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(resp.role_list.len(), 2);
        assert_eq!(resp.role_list[0].role_name, "AdministratorAccess");
        assert_eq!(resp.role_list[1].role_name, "ViewOnlyAccess");
        assert!(resp.next_token.is_none());
    }

    #[test]
    fn test_list_account_roles_with_pagination() {
        let json = r#"{
            "roleList": [
                {
                    "roleName": "VouchAccess",
                    "accountId": "333333333333"
                }
            ],
            "nextToken": "page2token"
        }"#;

        let resp: ListAccountRolesResponse = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(resp.role_list.len(), 1);
        assert_eq!(resp.next_token.as_deref(), Some("page2token"));
    }

    #[test]
    fn test_sso_account_fields() {
        let json = r#"{
            "accountId": "123456789012",
            "accountName": "My Account",
            "emailAddress": "admin@example.com"
        }"#;
        let account: SsoAccount = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(account.account_id, "123456789012");
        assert_eq!(account.account_name, "My Account");
        assert_eq!(account.email_address, "admin@example.com");
    }

    #[test]
    fn test_sso_role_fields() {
        let json = r#"{
            "roleName": "ReadOnly",
            "accountId": "987654321098"
        }"#;
        let role: SsoRole = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(role.role_name, "ReadOnly");
        assert_eq!(role.account_id, "987654321098");
    }

    #[test]
    fn test_role_credentials_response_deserialization() {
        // `expiration` is Unix epoch milliseconds in the SSO Portal response.
        let json = r#"{
            "roleCredentials": {
                "accessKeyId": "ASIAEXAMPLE",
                "secretAccessKey": "secretkeyexample",
                "sessionToken": "sessiontokenexample",
                "expiration": 1705257600000
            }
        }"#;

        let resp: RoleCredentialsResponse = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(resp.role_credentials.access_key_id, "ASIAEXAMPLE");
        assert_eq!(resp.role_credentials.expiration, 1_705_257_600_000);
        let ts = jiff::Timestamp::from_millisecond(resp.role_credentials.expiration)
            .expect("valid timestamp");
        assert_eq!(ts.as_millisecond(), 1_705_257_600_000);
    }
}
