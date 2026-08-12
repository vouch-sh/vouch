// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS Identity Store API for resolving Identity Center users and their
//! group memberships.
//!
//! json-1.1 protocol with `X-Amz-Target: AWSIdentityStore.<Operation>`;
//! SigV4 signing name `identitystore`.

use anyhow::{Context, Result};
use serde::Deserialize;
use vouch_cli::tr;
use vouch_common::aws::Partition;

use super::sigv4::sign_and_send_json_rpc;
use super::sts::StsCredentials;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetUserIdResponse {
    user_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListGroupMembershipsResponse {
    #[serde(default)]
    group_memberships: Vec<GroupMembership>,
    next_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GroupMembership {
    group_id: Option<String>,
}

/// Request body for `GetUserId`, looking a user up by email.
///
/// `emails.value` and `userName` are the only unique-attribute paths the
/// API accepts.
fn get_user_id_body(identity_store_id: &str, email: &str) -> serde_json::Value {
    serde_json::json!({
        "IdentityStoreId": identity_store_id,
        "AlternateIdentifier": {
            "UniqueAttribute": {
                "AttributePath": "emails.value",
                "AttributeValue": email,
            }
        }
    })
}

/// Request body for `ListGroupMembershipsForMember`.
fn list_memberships_body(
    identity_store_id: &str,
    user_id: &str,
    next_token: Option<&str>,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "IdentityStoreId": identity_store_id,
        "MemberId": { "UserId": user_id },
        "MaxResults": 100,
    });
    if let Some(token) = next_token
        && let Some(map) = body.as_object_mut()
    {
        map.insert("NextToken".to_string(), serde_json::json!(token));
    }
    body
}

/// Resolve the Identity Center user ID for a verified email address.
pub(crate) async fn get_user_id(
    http_client: &reqwest::Client,
    region: &str,
    creds: &StsCredentials,
    identity_store_id: &str,
    email: &str,
) -> Result<String> {
    let partition = Partition::from_region(region);
    let endpoint = partition.identity_store_endpoint(region);

    let response_body = sign_and_send_json_rpc(
        http_client,
        &endpoint,
        "identitystore",
        "AWSIdentityStore.GetUserId",
        region,
        creds,
        &get_user_id_body(identity_store_id, email),
    )
    .await
    .context(tr!("err-failed-resolve-idc-user"))?;

    let resp: GetUserIdResponse = serde_json::from_str(&response_body)
        .context(tr!("err-failed-parse-identitystore-response"))?;
    Ok(resp.user_id)
}

/// List the IDs of groups the user is a direct member of.
///
/// The API returns direct memberships only — nested groups are not
/// expanded. Paginates automatically with a 100-page safety cap.
pub(crate) async fn list_group_ids_for_member(
    http_client: &reqwest::Client,
    region: &str,
    creds: &StsCredentials,
    identity_store_id: &str,
    user_id: &str,
) -> Result<Vec<String>> {
    let partition = Partition::from_region(region);
    let endpoint = partition.identity_store_endpoint(region);

    let mut group_ids = Vec::new();
    let mut next_token: Option<String> = None;
    let max_pages: u32 = 100;

    for page in 0..max_pages {
        let body = list_memberships_body(identity_store_id, user_id, next_token.as_deref());
        let response_body = sign_and_send_json_rpc(
            http_client,
            &endpoint,
            "identitystore",
            "AWSIdentityStore.ListGroupMembershipsForMember",
            region,
            creds,
            &body,
        )
        .await
        .context(tr!("err-failed-list-group-memberships"))?;

        let resp: ListGroupMembershipsResponse = serde_json::from_str(&response_body)
            .context(tr!("err-failed-parse-identitystore-response"))?;

        for membership in resp.group_memberships {
            if let Some(group_id) = membership.group_id {
                group_ids.push(group_id);
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
                "group membership list reached {max_pages}-page safety cap; \
                 results may be incomplete"
            );
        }
    }

    Ok(group_ids)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn get_user_id_body_uses_emails_value_path() {
        let body = get_user_id_body("d-906705617e", "user@example.com");
        assert_eq!(
            body,
            serde_json::json!({
                "IdentityStoreId": "d-906705617e",
                "AlternateIdentifier": {
                    "UniqueAttribute": {
                        "AttributePath": "emails.value",
                        "AttributeValue": "user@example.com",
                    }
                }
            })
        );
    }

    #[test]
    fn get_user_id_response_parses() {
        let json = r#"{"IdentityStoreId": "d-906705617e",
                       "UserId": "84b89428-b0e1-7015-38c8-d2536dfd030b"}"#;
        let resp: GetUserIdResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.user_id, "84b89428-b0e1-7015-38c8-d2536dfd030b");
    }

    #[test]
    fn list_memberships_body_with_and_without_token() {
        let body = list_memberships_body("d-1", "user-1", None);
        assert_eq!(
            body,
            serde_json::json!({
                "IdentityStoreId": "d-1",
                "MemberId": { "UserId": "user-1" },
                "MaxResults": 100,
            })
        );

        let body = list_memberships_body("d-1", "user-1", Some("tok"));
        assert_eq!(body.get("NextToken"), Some(&serde_json::json!("tok")));
    }

    #[test]
    fn memberships_response_skips_missing_group_id_and_reads_token() {
        let json = r#"{
            "GroupMemberships": [
                {"GroupId": "g-1", "MembershipId": "m-1"},
                {"MembershipId": "m-2"}
            ],
            "NextToken": "next"
        }"#;
        let resp: ListGroupMembershipsResponse = serde_json::from_str(json).unwrap();
        let ids: Vec<&str> = resp
            .group_memberships
            .iter()
            .filter_map(|m| m.group_id.as_deref())
            .collect();
        assert_eq!(ids, vec!["g-1"]);
        assert_eq!(resp.next_token.as_deref(), Some("next"));
    }

    #[test]
    fn memberships_response_tolerates_empty() {
        let resp: ListGroupMembershipsResponse = serde_json::from_str("{}").unwrap();
        assert!(resp.group_memberships.is_empty());
    }
}
