// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center admin (`sso-admin`) API.
//!
//! json-1.1 protocol with `X-Amz-Target: SWBExternalService.<Operation>`;
//! SigV4 signing name is `sso` (the service's endpoint prefix, not
//! `sso-admin`).

use anyhow::{Context, Result};
use serde::Deserialize;
use vouch_cli::tr;
use vouch_common::aws::Partition;

use super::sigv4::sign_and_send_json_rpc;
use super::sts::StsCredentials;

/// An IAM Identity Center instance visible to the caller.
#[derive(Debug, Clone)]
pub(crate) struct SsoInstance {
    /// Instance ARN (`arn:aws:sso:::instance/ssoins-…`).
    pub instance_arn: String,
    /// Identity store ID (`d-…`) backing the instance.
    pub identity_store_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListInstancesResponse {
    #[serde(default)]
    instances: Vec<InstanceMetadata>,
    next_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InstanceMetadata {
    instance_arn: Option<String>,
    identity_store_id: Option<String>,
}

/// List the Identity Center instances visible to the caller (usually one).
///
/// Paginates automatically with a 100-page safety cap.
pub(crate) async fn list_instances(
    http_client: &reqwest::Client,
    region: &str,
    creds: &StsCredentials,
) -> Result<Vec<SsoInstance>> {
    let partition = Partition::from_region(region);
    let endpoint = partition.sso_admin_endpoint(region);

    let mut instances = Vec::new();
    let mut next_token: Option<String> = None;
    let max_pages: u32 = 100;

    for page in 0..max_pages {
        let mut body = serde_json::json!({ "MaxResults": 100 });
        if let Some(ref token) = next_token
            && let Some(map) = body.as_object_mut()
        {
            map.insert("NextToken".to_string(), serde_json::json!(token));
        }

        let response_body = sign_and_send_json_rpc(
            http_client,
            &endpoint,
            "sso",
            "SWBExternalService.ListInstances",
            region,
            creds,
            &body,
        )
        .await
        .context(tr!("err-failed-list-idc-instances"))?;

        let resp: ListInstancesResponse = serde_json::from_str(&response_body)
            .context(tr!("err-failed-parse-sso-admin-response"))?;

        for instance in resp.instances {
            if let InstanceMetadata {
                instance_arn: Some(instance_arn),
                identity_store_id: Some(identity_store_id),
            } = instance
            {
                instances.push(SsoInstance {
                    instance_arn,
                    identity_store_id,
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
                "Identity Center instance list reached {max_pages}-page safety cap; \
                 results may be incomplete"
            );
        }
    }

    Ok(instances)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn list_instances_response_parses_pascal_case() {
        let json = r#"{
            "Instances": [
                {
                    "InstanceArn": "arn:aws:sso:::instance/ssoins-722325820ad4410d",
                    "IdentityStoreId": "d-906705617e",
                    "OwnerAccountId": "860114833029",
                    "Status": "ACTIVE"
                }
            ],
            "NextToken": null
        }"#;
        let resp: ListInstancesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.instances.len(), 1);
        let first = resp.instances.first().unwrap();
        assert_eq!(
            first.instance_arn.as_deref(),
            Some("arn:aws:sso:::instance/ssoins-722325820ad4410d")
        );
        assert_eq!(first.identity_store_id.as_deref(), Some("d-906705617e"));
        assert!(resp.next_token.is_none());
    }

    #[test]
    fn list_instances_response_tolerates_missing_fields() {
        let json = r#"{"Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-1"}]}"#;
        let resp: ListInstancesResponse = serde_json::from_str(json).unwrap();
        let first = resp.instances.first().unwrap();
        assert!(first.identity_store_id.is_none());
    }

    #[test]
    fn list_instances_response_tolerates_empty() {
        let resp: ListInstancesResponse = serde_json::from_str("{}").unwrap();
        assert!(resp.instances.is_empty());
        assert!(resp.next_token.is_none());
    }
}
