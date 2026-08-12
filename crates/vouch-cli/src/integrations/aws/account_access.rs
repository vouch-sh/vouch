// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center account access manager (`account-access`) API.
//!
//! rest-json protocol (`POST /applications-list`, `POST /entitlements-list`),
//! SigV4 signing name `account-access`. The service exposes only dualstack
//! `account-access.{region}.api.aws` endpoints (no `.amazonaws.com` form)
//! and is commercial-partition only.
//!
//! `ListEntitlements` requires both `applicationArn` and a non-empty
//! `principalRole` filter — an unfiltered dump is rejected with a 400 — so
//! resolving one user's access takes one call for the user plus one per
//! group, each paginated.

use anyhow::{Context, Result};
use serde::Deserialize;
use vouch_cli::tr;
use vouch_common::aws::Partition;

use super::sigv4::sign_and_send_json_post;
use super::sts::StsCredentials;

/// The Identity Center principal an entitlement query is filtered by.
///
/// The API's principal filter is a union — exactly one principal per call.
#[derive(Clone)]
pub(crate) enum AamPrincipal {
    /// Identity store user ID.
    User(String),
    /// Identity store group ID.
    Group(String),
}

/// One entitled role read from `ListEntitlements`.
#[derive(Debug, Clone)]
pub(crate) struct EntitledRole {
    /// Full IAM role ARN, including any path.
    pub role_arn: String,
    /// 12-digit account ID the role lives in.
    pub account: String,
    /// Friendly account name, when the service provides one.
    pub account_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListApplicationsResponse {
    #[serde(default)]
    applications: Vec<ApplicationSummary>,
    next_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationSummary {
    application_arn: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListEntitlementsResponse {
    #[serde(default)]
    entitlements: Vec<EntitlementsListMember>,
    next_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntitlementsListMember {
    entitlement: Option<EntitlementSummary>,
}

/// `EntitlementSummary` is a union; `principalRole` is its only current
/// member. Entries without it (future union members) are skipped.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntitlementSummary {
    principal_role: Option<PrincipalRoleSummary>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrincipalRoleSummary {
    role_arn: Option<String>,
    account: Option<String>,
    account_name: Option<String>,
}

/// Request body for `ListEntitlements`, filtered by one principal.
fn list_entitlements_body(
    application_arn: &str,
    principal: &AamPrincipal,
    next_token: Option<&str>,
) -> serde_json::Value {
    let identity_center = match principal {
        AamPrincipal::User(user_id) => serde_json::json!({ "userId": user_id }),
        AamPrincipal::Group(group_id) => serde_json::json!({ "groupId": group_id }),
    };
    let mut body = serde_json::json!({
        "applicationArn": application_arn,
        "maxResults": 100,
        "filter": {
            "principalRole": {
                "principal": { "identityCenter": identity_center }
            }
        }
    });
    if let Some(token) = next_token
        && let Some(map) = body.as_object_mut()
    {
        map.insert("nextToken".to_string(), serde_json::json!(token));
    }
    body
}

/// List account access manager application ARNs (one per org in practice).
///
/// Paginates automatically with a 100-page safety cap.
pub(crate) async fn list_applications(
    http_client: &reqwest::Client,
    region: &str,
    creds: &StsCredentials,
) -> Result<Vec<String>> {
    let endpoint = Partition::from_region(region).account_access_endpoint(region)?;

    let mut applications = Vec::new();
    let mut next_token: Option<String> = None;
    let max_pages: u32 = 100;

    for page in 0..max_pages {
        let mut body = serde_json::json!({ "maxResults": 100 });
        if let Some(ref token) = next_token
            && let Some(map) = body.as_object_mut()
        {
            map.insert("nextToken".to_string(), serde_json::json!(token));
        }

        let response_body = sign_and_send_json_post(
            http_client,
            &endpoint,
            "/applications-list",
            &[],
            "account-access",
            region,
            creds,
            &body,
        )
        .await
        .context(tr!("err-failed-list-aam-applications"))?;

        let resp: ListApplicationsResponse = serde_json::from_str(&response_body)
            .context(tr!("err-failed-parse-account-access-response"))?;

        for application in resp.applications {
            if let Some(application_arn) = application.application_arn {
                applications.push(application_arn);
            }
        }

        match resp.next_token {
            Some(token) if !token.is_empty() => {
                next_token = Some(token);
            }
            _ => break,
        }

        if page == max_pages.saturating_sub(1) {
            tracing::warn!("account access application list reached {max_pages}-page safety cap");
        }
    }

    Ok(applications)
}

/// List the roles entitled to one principal in an application.
///
/// Paginates automatically with a 100-page safety cap. Entries missing the
/// role ARN or account (or of a future union shape) are skipped.
pub(crate) async fn list_entitlements(
    http_client: &reqwest::Client,
    region: &str,
    creds: &StsCredentials,
    application_arn: &str,
    principal: &AamPrincipal,
) -> Result<Vec<EntitledRole>> {
    let endpoint = Partition::from_region(region).account_access_endpoint(region)?;

    let mut roles = Vec::new();
    let mut next_token: Option<String> = None;
    let max_pages: u32 = 100;

    for page in 0..max_pages {
        let body = list_entitlements_body(application_arn, principal, next_token.as_deref());
        let response_body = sign_and_send_json_post(
            http_client,
            &endpoint,
            "/entitlements-list",
            &[],
            "account-access",
            region,
            creds,
            &body,
        )
        .await
        .context(tr!("err-failed-list-aam-entitlements"))?;

        let resp: ListEntitlementsResponse = serde_json::from_str(&response_body)
            .context(tr!("err-failed-parse-account-access-response"))?;

        for member in resp.entitlements {
            let Some(EntitlementSummary {
                principal_role: Some(principal_role),
            }) = member.entitlement
            else {
                continue;
            };
            if let PrincipalRoleSummary {
                role_arn: Some(role_arn),
                account: Some(account),
                account_name,
            } = principal_role
            {
                roles.push(EntitledRole {
                    role_arn,
                    account,
                    account_name,
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
            tracing::warn!("entitlement list reached {max_pages}-page safety cap");
        }
    }

    Ok(roles)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    const APP: &str = "arn:aws:account-access:us-east-1:111122223333:application/t1RRfzW2i4zfVoR3";

    #[test]
    fn list_entitlements_body_user_filter_exact_shape() {
        let body = list_entitlements_body(APP, &AamPrincipal::User("user-1".to_string()), None);
        assert_eq!(
            body,
            serde_json::json!({
                "applicationArn": APP,
                "maxResults": 100,
                "filter": {
                    "principalRole": {
                        "principal": { "identityCenter": { "userId": "user-1" } }
                    }
                }
            })
        );
    }

    #[test]
    fn list_entitlements_body_group_filter_with_token() {
        let body =
            list_entitlements_body(APP, &AamPrincipal::Group("g-1".to_string()), Some("tok"));
        assert_eq!(
            body.pointer("/filter/principalRole/principal/identityCenter/groupId"),
            Some(&serde_json::json!("g-1"))
        );
        assert_eq!(body.get("nextToken"), Some(&serde_json::json!("tok")));
    }

    #[test]
    fn applications_response_parses_and_skips_missing_arn() {
        let json = r#"{
            "applications": [
                {"applicationArn": "arn:aws:account-access:us-east-1:1:application/x",
                 "tenantId": "aa-1", "createdAt": "2026-08-12T00:18:52Z"},
                {"tenantId": "aa-2"}
            ],
            "nextToken": null
        }"#;
        let resp: ListApplicationsResponse = serde_json::from_str(json).unwrap();
        let arns: Vec<&str> = resp
            .applications
            .iter()
            .filter_map(|a| a.application_arn.as_deref())
            .collect();
        assert_eq!(
            arns,
            vec!["arn:aws:account-access:us-east-1:1:application/x"]
        );
    }

    #[test]
    fn entitlements_response_parses_summary_shape() {
        let json = r#"{
            "entitlements": [
                {
                    "entitlementId": "ent-1",
                    "createdAt": "2026-08-12T00:20:00Z",
                    "entitlement": {
                        "principalRole": {
                            "principal": {"identityCenter": {"userId": "u-1"}},
                            "roleArn": "arn:aws:iam::444455556666:role/vouch/VouchReadOnly",
                            "account": "444455556666",
                            "accountName": "prod-payments"
                        }
                    }
                }
            ],
            "nextToken": "next"
        }"#;
        let resp: ListEntitlementsResponse = serde_json::from_str(json).unwrap();
        let member = resp.entitlements.first().unwrap();
        let summary = member.entitlement.as_ref().unwrap();
        let role = summary.principal_role.as_ref().unwrap();
        assert_eq!(
            role.role_arn.as_deref(),
            Some("arn:aws:iam::444455556666:role/vouch/VouchReadOnly")
        );
        assert_eq!(role.account.as_deref(), Some("444455556666"));
        assert_eq!(role.account_name.as_deref(), Some("prod-payments"));
        assert_eq!(resp.next_token.as_deref(), Some("next"));
    }

    #[test]
    fn entitlements_response_skips_unknown_union_member_and_missing_name() {
        let json = r#"{
            "entitlements": [
                {"entitlementId": "ent-1", "entitlement": {"futureShape": {}}},
                {
                    "entitlementId": "ent-2",
                    "entitlement": {
                        "principalRole": {
                            "roleArn": "arn:aws:iam::1:role/R",
                            "account": "000000000001"
                        }
                    }
                }
            ]
        }"#;
        let resp: ListEntitlementsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.entitlements.len(), 2);
        assert!(
            resp.entitlements
                .first()
                .unwrap()
                .entitlement
                .as_ref()
                .unwrap()
                .principal_role
                .is_none()
        );
        let role = resp
            .entitlements
            .get(1)
            .and_then(|member| member.entitlement.as_ref())
            .and_then(|summary| summary.principal_role.as_ref())
            .unwrap();
        assert!(role.account_name.is_none());
    }

    #[test]
    fn entitlements_response_tolerates_empty() {
        let resp: ListEntitlementsResponse =
            serde_json::from_str(r#"{"entitlements":[]}"#).unwrap();
        assert!(resp.entitlements.is_empty());
        assert!(resp.next_token.is_none());
    }
}
