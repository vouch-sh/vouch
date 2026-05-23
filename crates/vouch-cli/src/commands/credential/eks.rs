// SPDX-License-Identifier: Apache-2.0 OR MIT
//! EKS credential command.
//!
//! Generates a Kubernetes bearer token for EKS authentication using a
//! presigned STS `GetCallerIdentity` URL. This eliminates the need for
//! `aws eks get-token` as a runtime dependency.
//!
//! Protocol:
//! 1. Exchange Vouch session for STS credentials (OIDC → STS)
//! 2. Build a presigned `GetCallerIdentity` URL with `x-k8s-aws-id` header
//! 3. Base64url-encode it, prepend `k8s-aws-v1.`
//! 4. Output as Kubernetes `ExecCredential` JSON

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::commands::credential::aws::{StsRequest, exchange_for_sts_credentials};
use crate::commands::credential::cache;
use crate::integrations::aws;
use crate::integrations::aws::sigv4::{
    PresignedUrlParams, build_presigned_url, validate_sigv4_input,
};

/// EKS presigned URL validity: 60 seconds (matches `aws eks get-token`).
const EKS_TOKEN_EXPIRES_SECONDS: u64 = 60;

/// Safety margin subtracted from the presigned URL lifetime.
///
/// The presigned STS URL embedded in the token expires after
/// `EKS_TOKEN_EXPIRES_SECONDS`. We cache for slightly less to ensure
/// the URL is still valid when EKS calls STS to verify it.
const EKS_EXPIRY_MARGIN_SECONDS: i64 = 15;

/// Run the EKS credential command.
///
/// Outputs a Kubernetes `ExecCredential` JSON to stdout for use as a
/// kubeconfig exec-based credential plugin.
pub(crate) async fn run(
    server: &str,
    cluster_name: &str,
    region: Option<&str>,
    role: Option<&str>,
) -> Result<()> {
    validate_sigv4_input(cluster_name, "cluster name")?;

    let (role_arn, region_name) = aws::resolve_role_and_region(role, region)?;

    let cache_key = format!("eks:{cluster_name}:{role_arn}");

    let data = cache::get_or_fetch(&cache_key, "EKS token", || async {
        let token = generate_eks_token(server, cluster_name, &region_name, &role_arn).await?;
        let exec_cred = build_exec_credential(&token)?;
        let expires_at = expiration_rfc3339()?;
        Ok((exec_cred, expires_at))
    })
    .await?;

    let json = serde_json::to_string(&data).context("failed to serialize ExecCredential")?;
    println!("{json}");
    Ok(())
}

/// Generate a `k8s-aws-v1.` bearer token for EKS.
async fn generate_eks_token(
    server: &str,
    cluster_name: &str,
    region: &str,
    role_arn: &str,
) -> Result<String> {
    let agent_source = crate::commands::credential::aws::detect_agent_source();
    let result = exchange_for_sts_credentials(StsRequest {
        server,
        role_arn,
        region,
        management_role: None,
        agent_source: agent_source.as_deref(),
    })
    .await?;

    // Build presigned STS GetCallerIdentity URL with cluster ID
    let sts_endpoint = format!("https://sts.{region}.{}", result.domain_suffix);
    let presigned = build_presigned_url(&PresignedUrlParams {
        method: "GET",
        endpoint: &sts_endpoint,
        path: "/",
        query_params: &[("Action", "GetCallerIdentity"), ("Version", "2011-06-15")],
        extra_signed_headers: &[("x-k8s-aws-id", cluster_name)],
        service: "sts",
        region,
        creds: &result.credentials,
        expires_seconds: EKS_TOKEN_EXPIRES_SECONDS,
    });

    // Base64url encode (no padding) and prepend prefix
    let encoded = URL_SAFE_NO_PAD.encode(presigned.as_bytes());
    Ok(format!("k8s-aws-v1.{encoded}"))
}

/// Build the Kubernetes `ExecCredential` JSON value.
fn build_exec_credential(token: &str) -> Result<serde_json::Value> {
    let expiration = expiration_rfc3339()?;
    Ok(serde_json::json!({
        "kind": "ExecCredential",
        "apiVersion": "client.authentication.k8s.io/v1",
        "status": {
            "token": token,
            "expirationTimestamp": expiration,
        }
    }))
}

/// Compute the expiration timestamp as RFC 3339.
///
/// The lifetime matches the presigned STS URL validity minus a safety
/// margin, so cached tokens are never served after the URL expires.
fn expiration_rfc3339() -> Result<String> {
    #[expect(
        clippy::cast_possible_wrap,
        reason = "EKS_TOKEN_EXPIRES_SECONDS is bounded to <2^63 by AWS EKS token TTL"
    )]
    let ttl_seconds = (EKS_TOKEN_EXPIRES_SECONDS as i64).saturating_sub(EKS_EXPIRY_MARGIN_SECONDS);
    let expires = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(ttl_seconds))
        .context("failed to compute EKS token expiration")?;
    Ok(expires.to_string())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_build_exec_credential_shape() {
        let token = "k8s-aws-v1.aHR0cHM6Ly9zdHM";
        let cred = build_exec_credential(token).expect("should build");

        assert_eq!(cred["kind"], "ExecCredential");
        assert_eq!(cred["apiVersion"], "client.authentication.k8s.io/v1");
        assert_eq!(cred["status"]["token"], token);
        assert!(
            cred["status"]["expirationTimestamp"]
                .as_str()
                .unwrap()
                .contains('T')
        );
    }

    #[test]
    fn test_exec_credential_has_no_extra_fields() {
        let cred = build_exec_credential("k8s-aws-v1.test").expect("should build");
        let obj = cred.as_object().unwrap();
        assert_eq!(obj.len(), 3); // kind, apiVersion, status
        let status = cred["status"].as_object().unwrap();
        assert_eq!(status.len(), 2); // token, expirationTimestamp
    }

    #[test]
    fn test_token_prefix() {
        let url = "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity";
        let encoded = URL_SAFE_NO_PAD.encode(url.as_bytes());
        let token = format!("k8s-aws-v1.{encoded}");
        assert!(token.starts_with("k8s-aws-v1."));
        // Verify no padding characters
        assert!(!token.contains('='));
    }

    #[test]
    fn test_expiration_rfc3339_valid() {
        let ts = expiration_rfc3339().expect("should compute");
        assert!(ts.parse::<jiff::Timestamp>().is_ok());
    }
}
