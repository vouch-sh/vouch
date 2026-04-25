// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Amazon EKS setup command.
//!
//! Configures kubeconfig so kubectl authenticates via `vouch credential eks`,
//! which natively generates EKS bearer tokens without requiring the AWS CLI.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

use crate::commands::credential::aws::exchange_for_sts_credentials;
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
    let result = exchange_for_sts_credentials(server, role_arn, region, None).await?;

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
    let kubeconfig_path = kubeconfig_path.map(PathBuf::from).unwrap_or_else(|| {
        default_kubeconfig_path().unwrap_or_else(|_| PathBuf::from("~/.kube/config"))
    });

    // Auto-discover profile, region, and role
    let profile_name = aws::resolve_profile(profile)?;
    let region_name = aws::resolve_region(region, &profile_name)?;
    let role_arn = aws::get_local_aws_role().ok_or_else(|| {
        anyhow::anyhow!("AWS not configured. Run 'vouch setup aws --role <role-arn>' first.")
    })?;

    println!("Amazon EKS Setup");
    println!("================");
    println!();
    println!("Cluster:  {cluster_name}");
    println!("Region:   {region_name}");
    println!("Profile:  {profile_name}");
    println!();

    // Fetch cluster info from AWS using native SigV4 API call
    println!("Fetching cluster details...");
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
    println!("Updated kubeconfig: {}", kubeconfig_path.display());
    println!("  Cluster: {cluster_name} ({endpoint})");
    println!("  User:    {user_name} (via vouch credential eks)");
    println!("  Context: {context_name}");
    println!();
    println!("To use:");
    println!("  kubectl config use-context {context_name}");
    println!("  kubectl get pods");
    println!();
    println!("Prerequisites:");
    println!("  1. Run 'vouch login' to authenticate");
    println!("  2. EKS Access Entry must exist for the IAM role in your AWS profile");

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
