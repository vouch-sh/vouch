// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Generic Kubernetes OIDC setup command.
//!
//! Configures kubeconfig so kubectl authenticates via `vouch credential k8s`,
//! which fetches a short-lived OIDC token from the Vouch server.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
// Kubeconfig Helpers
// ============================================================================

/// Get the default kubeconfig path (~/.kube/config).
fn default_kubeconfig_path() -> Result<PathBuf> {
    if let Ok(kubeconfig) = std::env::var("KUBECONFIG")
        && let Some(first_path) = kubeconfig.split(':').next()
        && !first_path.is_empty()
    {
        return Ok(PathBuf::from(first_path));
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

/// Read and base64-encode a certificate authority file.
fn read_ca_data(ca_path: &str) -> Result<String> {
    let bytes = std::fs::read(ca_path)
        .with_context(|| format!("failed to read certificate authority file: {ca_path}"))?;
    Ok(STANDARD.encode(&bytes))
}

// ============================================================================
// Main Command
// ============================================================================

/// Run the Kubernetes setup command.
///
/// Configures kubeconfig so kubectl uses `vouch credential k8s` for
/// OIDC token generation against a Vouch-backed Kubernetes cluster.
pub async fn run(
    server: &str,
    cluster: &str,
    k8s_server: &str,
    ca_path: Option<&str>,
    audience: Option<&str>,
    kubeconfig_path: Option<&str>,
) -> Result<()> {
    let aud = audience.unwrap_or("kubernetes");

    let kubeconfig_path = match kubeconfig_path {
        Some(p) => PathBuf::from(p),
        None => default_kubeconfig_path()?,
    };

    // Read CA data if provided
    let ca_data = ca_path.map(read_ca_data).transpose()?;

    println!("Kubernetes OIDC Setup");
    println!("=====================");
    println!();
    println!("Cluster:   {cluster}");
    println!("Server:    {k8s_server}");
    println!("Audience:  {aud}");
    println!("Vouch:     {server}");
    println!();

    // Naming convention
    let user_name = format!("vouch-k8s-{cluster}");
    let context_name = format!("{cluster}-vouch");

    // Build vouch credential k8s args
    let exec_args = vec![
        "credential".to_string(),
        "k8s".to_string(),
        "--cluster".to_string(),
        cluster.to_string(),
        "--audience".to_string(),
        aud.to_string(),
    ];

    // Load existing kubeconfig
    let mut config = load_kubeconfig(&kubeconfig_path)?;

    // Upsert cluster
    config.clusters.retain(|c| c.name != cluster);
    config.clusters.push(KubeconfigCluster {
        name: cluster.to_string(),
        cluster: KubeconfigClusterData {
            server: k8s_server.to_string(),
            certificate_authority_data: ca_data,
        },
    });

    // Upsert user with vouch credential k8s exec config
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
            cluster: cluster.to_string(),
            namespace: None,
            user: user_name.clone(),
        },
    });

    // Save
    save_kubeconfig(&kubeconfig_path, &config)?;

    // Print summary
    println!("Updated kubeconfig: {}", kubeconfig_path.display());
    println!("  Cluster: {cluster} ({k8s_server})");
    println!("  User:    {user_name} (via vouch credential k8s)");
    println!("  Context: {context_name}");
    println!();
    println!("To use:");
    println!("  kubectl config use-context {context_name}");
    println!("  kubectl get pods");
    println!();
    println!("Prerequisites:");
    println!("  1. Run 'vouch login' to authenticate");
    println!(
        "  2. Kubernetes API server must be configured with \
         --oidc-issuer-url={server} --oidc-client-id={aud}"
    );

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_kubeconfig_parsing() {
        let yaml = r#"
apiVersion: v1
kind: Config
clusters:
- name: my-cluster
  cluster:
    server: https://k8s.example.com:6443
    certificate-authority-data: LS0tLS1...
contexts:
- name: my-cluster-vouch
  context:
    cluster: my-cluster
    user: vouch-k8s-my-cluster
users:
- name: vouch-k8s-my-cluster
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: vouch
      args:
        - credential
        - k8s
        - --cluster
        - my-cluster
        - --audience
        - kubernetes
      interactiveMode: Never
"#;

        let config: Kubeconfig = serde_yaml::from_str(yaml).expect("should parse");

        assert_eq!(config.clusters.len(), 1);
        assert_eq!(config.clusters[0].name, "my-cluster");
        assert_eq!(
            config.clusters[0].cluster.server,
            "https://k8s.example.com:6443"
        );
        assert_eq!(config.contexts.len(), 1);
        assert_eq!(config.contexts[0].name, "my-cluster-vouch");
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].name, "vouch-k8s-my-cluster");

        let exec = config.users[0]
            .user
            .exec
            .as_ref()
            .expect("should have exec");
        assert_eq!(exec.command, "vouch");
        assert_eq!(exec.args[0], "credential");
        assert_eq!(exec.args[1], "k8s");
        assert_eq!(exec.args[2], "--cluster");
        assert_eq!(exec.args[3], "my-cluster");
        assert_eq!(exec.args[4], "--audience");
        assert_eq!(exec.args[5], "kubernetes");
    }

    #[test]
    fn test_exec_config_serialization() {
        let exec = ExecConfig {
            api_version: "client.authentication.k8s.io/v1".to_string(),
            command: "vouch".to_string(),
            args: vec![
                "credential".to_string(),
                "k8s".to_string(),
                "--cluster".to_string(),
                "prod".to_string(),
                "--audience".to_string(),
                "kubernetes".to_string(),
            ],
            env: None,
            interactive_mode: Some("Never".to_string()),
        };

        let yaml = serde_yaml::to_string(&exec).expect("should serialize");
        assert!(yaml.contains("apiVersion: client.authentication.k8s.io/v1"));
        assert!(yaml.contains("command: vouch"));
        assert!(yaml.contains("interactiveMode: Never"));
        assert!(yaml.contains("credential"));
        assert!(yaml.contains("k8s"));
        assert!(!yaml.contains("env:"));
    }

    #[test]
    fn test_kubeconfig_cluster_without_ca() {
        let cluster = KubeconfigCluster {
            name: "dev".to_string(),
            cluster: KubeconfigClusterData {
                server: "https://k8s.dev.example.com:6443".to_string(),
                certificate_authority_data: None,
            },
        };

        let yaml = serde_yaml::to_string(&cluster).expect("should serialize");
        assert!(yaml.contains("name: dev"));
        assert!(!yaml.contains("certificate-authority-data"));
    }

    #[test]
    fn test_kubeconfig_cluster_with_ca() {
        let cluster = KubeconfigCluster {
            name: "prod".to_string(),
            cluster: KubeconfigClusterData {
                server: "https://k8s.prod.example.com:6443".to_string(),
                certificate_authority_data: Some("LS0tLS1CRUdJTi...".to_string()),
            },
        };

        let yaml = serde_yaml::to_string(&cluster).expect("should serialize");
        assert!(yaml.contains("certificate-authority-data:"));
        assert!(yaml.contains("LS0tLS1CRUdJTi..."));
    }
}
