// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Amazon EKS setup command.
//!
//! Configures kubeconfig so kubectl authenticates via `vouch credential eks`,
//! which natively generates EKS bearer tokens without requiring the AWS CLI.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::commands::credential::aws::exchange_for_sts_credentials;
use crate::integrations::aws;
use crate::integrations::aws::sigv4::sign_and_send_rest;
use crate::utils::{ensure_secure_dir, write_secure_file};

// ============================================================================
// Kubeconfig Types
// ============================================================================

/// Kubeconfig structure (partial - only what we need to read/modify).
#[derive(Debug, Default, Serialize, Deserialize)]
struct Kubeconfig {
    #[serde(default, rename = "apiVersion")]
    api_version: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    clusters: Vec<KubeconfigCluster>,
    #[serde(default)]
    contexts: Vec<KubeconfigContext>,
    #[serde(default, rename = "current-context")]
    current_context: Option<String>,
    #[serde(default)]
    users: Vec<KubeconfigUser>,
    #[serde(default)]
    preferences: serde_yaml::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KubeconfigCluster {
    name: String,
    cluster: KubeconfigClusterData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KubeconfigClusterData {
    server: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "certificate-authority-data"
    )]
    certificate_authority_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KubeconfigContext {
    name: String,
    context: KubeconfigContextData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KubeconfigContextData {
    cluster: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
    user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KubeconfigUser {
    name: String,
    user: KubeconfigUserData,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct KubeconfigUserData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exec: Option<ExecConfig>,
    #[serde(flatten)]
    other: serde_yaml::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecConfig {
    api_version: String,
    command: String,
    args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    env: Option<Vec<EnvVar>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interactive_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnvVar {
    name: String,
    value: String,
}

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
// Kubeconfig Helpers
// ============================================================================

/// Get the default kubeconfig path (~/.kube/config).
fn default_kubeconfig_path() -> Result<PathBuf> {
    // Check KUBECONFIG env var first
    if let Ok(kubeconfig) = std::env::var("KUBECONFIG") {
        // KUBECONFIG can contain multiple paths separated by ':'
        // We only use the first one for writing
        if let Some(first_path) = kubeconfig.split(':').next()
            && !first_path.is_empty()
        {
            return Ok(PathBuf::from(first_path));
        }
    }

    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".kube").join("config"))
}

/// Load kubeconfig from file, or return empty config if file doesn't exist.
fn load_kubeconfig(path: &std::path::Path) -> Result<Kubeconfig> {
    if !path.exists() {
        return Ok(Kubeconfig {
            api_version: Some("v1".to_string()),
            kind: Some("Config".to_string()),
            ..Default::default()
        });
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read kubeconfig: {}", path.display()))?;
    let config: Kubeconfig = serde_yaml::from_str(&content)
        .with_context(|| format!("failed to parse kubeconfig: {}", path.display()))?;
    Ok(config)
}

/// Save kubeconfig to file.
fn save_kubeconfig(path: &std::path::Path, config: &Kubeconfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_secure_dir(parent)?;
    }

    let content = serde_yaml::to_string(config).context("failed to serialize kubeconfig")?;
    write_secure_file(path, &content)?;
    Ok(())
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
    let result = exchange_for_sts_credentials(server, role_arn, region, "vouch-eks-setup").await?;

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
pub async fn run(
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
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_kubeconfig_parsing() {
        let yaml = r#"
apiVersion: v1
kind: Config
clusters:
- name: production
  cluster:
    server: https://ABCDEF.gr7.us-east-1.eks.amazonaws.com
    certificate-authority-data: LS0tLS1...
contexts:
- name: production-vouch
  context:
    cluster: production
    user: vouch-eks-production
users:
- name: vouch-eks-production
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: aws
      args:
        - eks
        - get-token
        - --cluster-name
        - production
        - --region
        - us-east-1
      env:
        - name: AWS_PROFILE
          value: vouch
      interactiveMode: Never
"#;

        let config: Kubeconfig = serde_yaml::from_str(yaml).expect("should parse");

        assert_eq!(config.clusters.len(), 1);
        assert_eq!(config.clusters[0].name, "production");
        assert!(
            config.clusters[0]
                .cluster
                .server
                .contains("eks.amazonaws.com")
        );
        assert_eq!(config.contexts.len(), 1);
        assert_eq!(config.contexts[0].name, "production-vouch");
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].name, "vouch-eks-production");

        let exec = config.users[0]
            .user
            .exec
            .as_ref()
            .expect("should have exec");
        assert_eq!(exec.command, "aws");
        assert_eq!(exec.args[0], "eks");
        assert_eq!(exec.args[1], "get-token");
    }

    #[test]
    fn test_empty_kubeconfig() {
        let yaml = r#"
apiVersion: v1
kind: Config
clusters: []
contexts: []
users: []
"#;

        let config: Kubeconfig = serde_yaml::from_str(yaml).expect("should parse");

        assert!(config.clusters.is_empty());
        assert!(config.contexts.is_empty());
        assert!(config.users.is_empty());
    }

    #[test]
    fn test_exec_config_serialization_vouch() {
        let exec = ExecConfig {
            api_version: "client.authentication.k8s.io/v1".to_string(),
            command: "vouch".to_string(),
            args: vec![
                "credential".to_string(),
                "eks".to_string(),
                "--cluster-name".to_string(),
                "test-cluster".to_string(),
                "--region".to_string(),
                "us-west-2".to_string(),
                "--role".to_string(),
                "arn:aws:iam::123456789012:role/MyRole".to_string(),
            ],
            env: None,
            interactive_mode: Some("Never".to_string()),
        };

        let yaml = serde_yaml::to_string(&exec).expect("should serialize");
        assert!(yaml.contains("apiVersion: client.authentication.k8s.io/v1"));
        assert!(yaml.contains("command: vouch"));
        assert!(yaml.contains("interactiveMode: Never"));
        assert!(yaml.contains("credential"));
        assert!(yaml.contains("eks"));
        assert!(yaml.contains("--cluster-name"));
        assert!(!yaml.contains("env:"));
    }

    #[test]
    fn test_kubeconfig_context() {
        let context = KubeconfigContext {
            name: "my-cluster-vouch".to_string(),
            context: KubeconfigContextData {
                cluster: "my-cluster".to_string(),
                namespace: None,
                user: "vouch-eks-my-cluster".to_string(),
            },
        };

        let yaml = serde_yaml::to_string(&context).expect("should serialize");
        assert!(yaml.contains("name: my-cluster-vouch"));
        assert!(yaml.contains("cluster: my-cluster"));
        assert!(yaml.contains("user: vouch-eks-my-cluster"));
        assert!(!yaml.contains("namespace"));
    }

    #[test]
    fn test_kubeconfig_cluster_with_ca() {
        let cluster = KubeconfigCluster {
            name: "prod".to_string(),
            cluster: KubeconfigClusterData {
                server: "https://ABCDEF.gr7.us-east-1.eks.amazonaws.com".to_string(),
                certificate_authority_data: Some("LS0tLS1CRUdJTi...".to_string()),
            },
        };

        let yaml = serde_yaml::to_string(&cluster).expect("should serialize");
        assert!(yaml.contains("name: prod"));
        assert!(yaml.contains("server:"));
        assert!(yaml.contains("certificate-authority-data:"));
    }

    #[test]
    fn test_kubeconfig_cluster_without_ca() {
        let cluster = KubeconfigCluster {
            name: "dev".to_string(),
            cluster: KubeconfigClusterData {
                server: "https://ABCDEF.gr7.us-west-2.eks.amazonaws.com".to_string(),
                certificate_authority_data: None,
            },
        };

        let yaml = serde_yaml::to_string(&cluster).expect("should serialize");
        assert!(yaml.contains("name: dev"));
        assert!(!yaml.contains("certificate-authority-data"));
    }

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
