// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS SSO Portal API for listing accounts and roles.
//!
//! Uses Bearer token auth via the `x-amz-sso_bearer_token` header (not
//! standard `Authorization: Bearer` — this is what the AWS SDK uses).

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use vouch_common::aws::Partition;

/// An AWS account the user has access to via SSO.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SsoAccount {
    pub account_id: String,
    pub account_name: String,
    pub email_address: String,
}

/// A role available to the user in a specific SSO-assigned account.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SsoRole {
    pub role_name: String,
    #[allow(dead_code)]
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
                reason: "SSO token is invalid or expired. Run 'vouch aws login' first.".to_string(),
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
                reason: "SSO token is invalid or expired. Run 'vouch aws login' first.".to_string(),
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
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
}
