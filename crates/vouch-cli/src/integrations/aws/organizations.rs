// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS Organizations integration.
//!
//! Lists member accounts in the organization via the
//! `AWSOrganizationsV20161128.ListAccounts` JSON-RPC target, using SigV4
//! credentials obtained from an STS `AssumeRole` call.

use anyhow::{Context, Result};
use serde::Deserialize;

use super::sigv4::sign_and_send_json_rpc;
use super::sts::StsCredentials;

/// A member account returned by `ListAccounts`.
#[derive(Debug, Clone)]
pub(crate) struct Account {
    /// 12-digit AWS account ID.
    pub id: String,
    /// Human-readable account name.
    pub name: String,
}

/// List all active member accounts in the organization.
///
/// Signs requests with the provided STS credentials against the Organizations
/// global endpoint for the partition inferred from `region`. Only `ACTIVE`
/// accounts are returned; `SUSPENDED` accounts are skipped. Paginates via
/// `NextToken` with a 1 000-page safety cap (~100 000 accounts max).
///
/// # Errors
///
/// Returns an error if the partition derived from `region` does not have an
/// Organizations endpoint (e.g. EUSC / ISO partitions), or if any API call
/// fails.
pub(crate) async fn list_accounts(
    http_client: &reqwest::Client,
    region: &str,
    creds: &StsCredentials,
) -> Result<Vec<Account>> {
    let partition = vouch_common::aws::Partition::from_region(region);
    let endpoint = partition.organizations_endpoint().with_context(|| {
        format!("AWS Organizations is not available in the {partition} partition")
    })?;
    let signing_region = partition.organizations_signing_region().with_context(|| {
        format!("AWS Organizations is not available in the {partition} partition")
    })?;

    let mut accounts = Vec::new();
    let mut next_token: Option<String> = None;
    // Safety cap — prevents infinite loops on malformed pagination responses.
    let max_pages: u32 = 1_000;

    for page in 0..max_pages {
        let body = match &next_token {
            Some(token) => serde_json::json!({ "NextToken": token }),
            None => serde_json::json!({}),
        };

        let response_text = sign_and_send_json_rpc(
            http_client,
            &endpoint,
            "organizations",
            "AWSOrganizationsV20161128.ListAccounts",
            signing_region,
            creds,
            &body,
        )
        .await
        .context("failed to call Organizations ListAccounts")?;

        let resp: ListAccountsResponse = serde_json::from_str(&response_text)
            .context("failed to parse Organizations ListAccounts response")?;

        for acct in resp.accounts {
            if acct.status == "ACTIVE" {
                accounts.push(Account {
                    id: acct.id,
                    name: acct.name,
                });
            }
        }

        match resp.next_token {
            Some(token) if !token.is_empty() => {
                next_token = Some(token);
            }
            _ => break,
        }

        if page == max_pages.saturating_sub(1) {
            tracing::warn!(
                "Organizations account list reached {max_pages}-page safety cap; \
                 results may be incomplete"
            );
        }
    }

    Ok(accounts)
}

/// Raw API envelope for `ListAccounts`.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAccountsResponse {
    accounts: Vec<RawAccount>,
    next_token: Option<String>,
}

/// A single account entry in the `ListAccounts` response.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawAccount {
    id: String,
    name: String,
    status: String,
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_accounts_response() {
        let json = r#"{
            "Accounts": [
                {"Id": "111111111111", "Name": "prod", "Status": "ACTIVE",
                 "Email": "prod@example.com", "Arn": "arn:aws:...", "JoinedMethod": "CREATED",
                 "JoinedTimestamp": 1700000000.0},
                {"Id": "222222222222", "Name": "suspended", "Status": "SUSPENDED",
                 "Email": "s@example.com", "Arn": "arn:aws:...", "JoinedMethod": "INVITED",
                 "JoinedTimestamp": 1700000000.0}
            ]
        }"#;

        let resp: ListAccountsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.accounts.len(), 2);
        assert_eq!(resp.accounts[0].id, "111111111111");
        assert_eq!(resp.accounts[0].status, "ACTIVE");
        assert_eq!(resp.accounts[1].status, "SUSPENDED");
        assert!(resp.next_token.is_none());
    }

    #[test]
    fn parses_paginated_response() {
        let json = r#"{
            "Accounts": [
                {"Id": "111111111111", "Name": "prod", "Status": "ACTIVE",
                 "Email": "prod@example.com", "Arn": "arn:aws:...", "JoinedMethod": "CREATED",
                 "JoinedTimestamp": 1700000000.0}
            ],
            "NextToken": "token-abc-123"
        }"#;

        let resp: ListAccountsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.next_token.as_deref(), Some("token-abc-123"));
    }

    #[test]
    fn filters_suspended_accounts() {
        // Manually replicate the active-filter logic used in list_accounts.
        let raw = vec![
            RawAccount {
                id: "111111111111".to_string(),
                name: "active".to_string(),
                status: "ACTIVE".to_string(),
            },
            RawAccount {
                id: "222222222222".to_string(),
                name: "suspended".to_string(),
                status: "SUSPENDED".to_string(),
            },
        ];
        let active: Vec<Account> = raw
            .into_iter()
            .filter(|a| a.status == "ACTIVE")
            .map(|a| Account {
                id: a.id,
                name: a.name,
            })
            .collect();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "111111111111");
    }
}
