// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Amazon EKS setup command.
//!
//! Configures kubeconfig so kubectl authenticates via `vouch credential eks`,
//! which natively generates EKS bearer tokens without requiring the AWS CLI.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

use crate::commands::credential::aws::{StsRequest, exchange_for_sts_credentials};
use crate::integrations::aws;
use crate::integrations::aws::sigv4::sign_and_send_rest;

use super::kubeconfig::{
    ExecConfig, KubeconfigCluster, KubeconfigClusterData, KubeconfigContext, KubeconfigContextData,
    KubeconfigUser, KubeconfigUserData, default_kubeconfig_path, load_kubeconfig, save_kubeconfig,
};

// ============================================================================
// EKS describe-cluster response (partial)
// ============================================================================

#[derive(Debug, Deserialize)]
struct DescribeClusterOutput {
    cluster: ClusterInfo,
}

#[derive(Debug, Deserialize)]
struct ClusterInfo {
    endpoint: String,
    #[serde(rename = "certificateAuthority")]
    certificate_authority: Option<CertificateAuthority>,
}

#[derive(Debug, Deserialize)]
struct CertificateAuthority {
    data: String,
}

// ============================================================================
// Auto-discovery Helpers
// ============================================================================

/// Fetch EKS cluster endpoint and CA data via native SigV4-signed REST API.
async fn describe_cluster(
    server: &str,
    cluster_name: &str,
    region: &str,
    role_arn: &str,
) -> Result<(String, String)> {
    let agent_source = crate::commands::credential::aws::detect_agent_source();
    let result = exchange_for_sts_credentials(StsRequest {
        server,
        role_arn,
        region,
        management_role: None,
        agent_source: agent_source.as_deref(),
    })
    .await?;

    // Call EKS DescribeCluster REST API
    let endpoint = format!("https://eks.{region}.{}", result.domain_suffix);
    let path = format!(
        "/clusters/{}",
        crate::integrations::aws::sigv4::uri_encode(cluster_name)
    );

    let response_body = sign_and_send_rest(
        &result.http_client,
        reqwest::Method::GET,
        &endpoint,
        &path,
        &[],
        "eks",
        region,
        &result.credentials,
    )
    .await
    .with_context(|| {
        format!(
            "failed to describe EKS cluster '{cluster_name}' in \
             region '{region}'. Ensure the cluster exists and your \
             IAM role has EKS access."
        )
    })?;

    let parsed: DescribeClusterOutput = serde_json::from_str(&response_body)
        .context("failed to parse EKS DescribeCluster response")?;

    let ca_data = parsed
        .cluster
        .certificate_authority
        .map(|ca| ca.data)
        .unwrap_or_default();

    Ok((parsed.cluster.endpoint, ca_data))
}

// ============================================================================
// Main Command
// ============================================================================

/// Run the EKS setup command.
///
/// Configures kubeconfig so kubectl uses `vouch credential eks` for
/// native EKS token generation (no AWS CLI required).
pub(crate) async fn run(
    server: &str,
    cluster_name: &str,
    region: Option<&str>,
    profile: Option<&str>,
    kubeconfig_path: Option<&str>,
) -> Result<()> {
    let kubeconfig_path = kubeconfig_path.map_or_else(
        || default_kubeconfig_path().unwrap_or_else(|_| PathBuf::from("~/.kube/config")),
        PathBuf::from,
    );

    // Auto-discover profile, region, and role
    let profile_name = aws::resolve_profile(profile)?;
    let region_name = aws::resolve_region(region, &profile_name)?;
    let role_arn = aws::get_local_aws_role()
        .ok_or_else(|| anyhow::anyhow!(vouch_cli::tr!("setup-eks-err-aws-not-configured")))?;

    vouch_cli::tr_println!(
        "setup-eks-header-block",
        cluster = cluster_name,
        region = region_name.as_str(),
        profile = profile_name.as_str(),
    );
    println!();

    // Fetch cluster info from AWS using native SigV4 API call
    vouch_cli::tr_println!("setup-eks-fetching");
    let (endpoint, ca_data) =
        describe_cluster(server, cluster_name, &region_name, &role_arn).await?;

    // Naming convention
    let user_name = format!("vouch-eks-{cluster_name}");
    let context_name = format!("{cluster_name}-vouch");

    // Build vouch credential eks args
    let mut exec_args = vec![
        "credential".to_string(),
        "eks".to_string(),
        "--cluster-name".to_string(),
        cluster_name.to_string(),
        "--region".to_string(),
        region_name.clone(),
    ];
    exec_args.push("--role".to_string());
    exec_args.push(role_arn);

    // Load existing kubeconfig
    let mut config = load_kubeconfig(&kubeconfig_path)?;

    // Upsert cluster
    config.clusters.retain(|c| c.name != cluster_name);
    config.clusters.push(KubeconfigCluster {
        name: cluster_name.to_string(),
        cluster: KubeconfigClusterData {
            server: endpoint.clone(),
            certificate_authority_data: if ca_data.is_empty() {
                None
            } else {
                Some(ca_data)
            },
        },
    });

    // Upsert user with vouch credential eks exec config
    config.users.retain(|u| u.name != user_name);
    config.users.push(KubeconfigUser {
        name: user_name.clone(),
        user: KubeconfigUserData {
            exec: Some(ExecConfig {
                api_version: "client.authentication.k8s.io/v1".to_string(),
                command: "vouch".to_string(),
                args: exec_args,
                env: None,
                interactive_mode: Some("Never".to_string()),
            }),
            other: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        },
    });

    // Upsert context
    config.contexts.retain(|c| c.name != context_name);
    config.contexts.push(KubeconfigContext {
        name: context_name.clone(),
        context: KubeconfigContextData {
            cluster: cluster_name.to_string(),
            namespace: None,
            user: user_name.clone(),
        },
    });

    // Save
    save_kubeconfig(&kubeconfig_path, &config)?;

    // Print summary
    println!();
    vouch_cli::tr_println!(
        "setup-eks-result-block",
        kubeconfig = kubeconfig_path.display().to_string(),
        cluster = cluster_name,
        endpoint = endpoint.as_str(),
        user_name = user_name.as_str(),
        context = context_name.as_str(),
    );

    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_describe_cluster_json_parsing() {
        let json = r#"{
            "cluster": {
                "name": "test-cluster",
                "endpoint": "https://ABCDEF.gr7.us-east-1.eks.amazonaws.com",
                "certificateAuthority": {
                    "data": "LS0tLS1CRUdJTiBDRVJU..."
                },
                "status": "ACTIVE"
            }
        }"#;

        let parsed: DescribeClusterOutput =
            serde_json::from_str(json).expect("should parse describe-cluster output");
        assert!(parsed.cluster.endpoint.contains("eks.amazonaws.com"));
        assert_eq!(
            parsed
                .cluster
                .certificate_authority
                .expect("should have CA")
                .data,
            "LS0tLS1CRUdJTiBDRVJU..."
        );
    }
}
