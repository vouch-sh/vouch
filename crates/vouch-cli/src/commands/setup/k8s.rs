// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kubernetes setup command.
//!
//! Configures kubectl to use Vouch for OIDC authentication via exec credential plugin.
//! See: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::utils::{ensure_secure_dir, write_secure_file};

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
    cluster: serde_yaml::Value,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provide_cluster_info: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnvVar {
    name: String,
    value: String,
}

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
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        ensure_secure_dir(parent)?;
    }

    let content = serde_yaml::to_string(config).context("failed to serialize kubeconfig")?;
    write_secure_file(path, &content)?;
    Ok(())
}

/// Build the exec config for Vouch.
fn build_exec_config(
    vouch_path: &std::path::Path,
    audience: &str,
    server: Option<&str>,
) -> ExecConfig {
    let args = vec![
        "credential".to_string(),
        "k8s".to_string(),
        "--audience".to_string(),
        audience.to_string(),
    ];

    let env = server.map(|s| {
        vec![EnvVar {
            name: "VOUCH_SERVER".to_string(),
            value: s.to_string(),
        }]
    });

    ExecConfig {
        api_version: "client.authentication.k8s.io/v1".to_string(),
        command: vouch_path.to_string_lossy().to_string(),
        args,
        env,
        interactive_mode: Some("Never".to_string()),
        provide_cluster_info: None,
    }
}

/// Run the Kubernetes setup command.
///
/// This command:
/// 1. Reads existing kubeconfig
/// 2. Lists available clusters if no cluster specified
/// 3. Adds exec credential provider for selected cluster
/// 4. Displays cluster OIDC configuration instructions
pub async fn run(
    server: &str,
    cluster: Option<&str>,
    audience: Option<&str>,
    kubeconfig_path: Option<&str>,
    configure: bool,
) -> Result<()> {
    let kubeconfig_path = kubeconfig_path.map(PathBuf::from).unwrap_or_else(|| {
        default_kubeconfig_path().unwrap_or_else(|_| PathBuf::from("~/.kube/config"))
    });

    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));

    println!("Kubernetes OIDC Authentication Setup");
    println!("=====================================");
    println!();

    // Load existing kubeconfig
    let mut config = load_kubeconfig(&kubeconfig_path)?;

    // If no cluster specified, list available clusters
    let cluster_name = match cluster {
        Some(c) => c.to_string(),
        None => {
            if config.clusters.is_empty() {
                bail!(
                    "No clusters found in kubeconfig: {}\n\
                     Add a cluster to your kubeconfig first, or specify --cluster.",
                    kubeconfig_path.display()
                );
            }

            println!("Available clusters in {}:", kubeconfig_path.display());
            for (i, c) in config.clusters.iter().enumerate() {
                println!("  {}. {}", i + 1, c.name);
            }
            println!();

            // Use inquire to select cluster
            let cluster_names: Vec<&str> =
                config.clusters.iter().map(|c| c.name.as_str()).collect();
            let selected = inquire::Select::new("Select cluster to configure:", cluster_names)
                .prompt()
                .context("cluster selection cancelled")?;
            selected.to_string()
        }
    };

    // Verify cluster exists
    if !config.clusters.iter().any(|c| c.name == cluster_name) {
        bail!(
            "Cluster '{}' not found in kubeconfig.\n\
             Available clusters: {}",
            cluster_name,
            config
                .clusters
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Determine audience (default to cluster name)
    let audience = audience.unwrap_or(&cluster_name);

    // User and context names
    let user_name = format!("vouch-{}", cluster_name);
    let context_name = format!("{}-vouch", cluster_name);

    if configure {
        // Add or update user
        let exec_config = build_exec_config(&vouch_path, audience, Some(server));
        let new_user = KubeconfigUser {
            name: user_name.clone(),
            user: KubeconfigUserData {
                exec: Some(exec_config),
                other: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            },
        };

        // Remove existing user with same name
        config.users.retain(|u| u.name != user_name);
        config.users.push(new_user);

        // Add or update context
        let new_context = KubeconfigContext {
            name: context_name.clone(),
            context: KubeconfigContextData {
                cluster: cluster_name.clone(),
                namespace: None,
                user: user_name.clone(),
            },
        };

        // Remove existing context with same name
        config.contexts.retain(|c| c.name != context_name);
        config.contexts.push(new_context);

        // Save kubeconfig
        save_kubeconfig(&kubeconfig_path, &config)?;

        println!("Updated kubeconfig: {}", kubeconfig_path.display());
        println!("  - Added user: {}", user_name);
        println!("  - Added context: {}", context_name);
        println!();
    }

    // Show the configuration that would be added
    println!("Kubeconfig user configuration:");
    println!();
    println!("users:");
    println!("- name: {}", user_name);
    println!("  user:");
    println!("    exec:");
    println!("      apiVersion: client.authentication.k8s.io/v1");
    println!("      command: {}", vouch_path.display());
    println!("      args:");
    println!("        - credential");
    println!("        - k8s");
    println!("        - --audience");
    println!("        - {}", audience);
    println!("      env:");
    println!("        - name: VOUCH_SERVER");
    println!("          value: {}", server);
    println!("      interactiveMode: Never");
    println!();

    println!("Context configuration:");
    println!();
    println!("contexts:");
    println!("- name: {}", context_name);
    println!("  context:");
    println!("    cluster: {}", cluster_name);
    println!("    user: {}", user_name);
    println!();

    // Usage instructions
    println!("To use Vouch for Kubernetes authentication:");
    println!();
    println!("1. Switch to the Vouch context:");
    println!();
    println!("   kubectl config use-context {}", context_name);
    println!();
    println!("2. Log in with Vouch and use kubectl:");
    println!();
    println!("   vouch login");
    println!("   kubectl get pods");
    println!();

    // Cluster configuration instructions
    println!("=======================================================");
    println!("IMPORTANT: Kubernetes Cluster OIDC Configuration");
    println!("=======================================================");
    println!();
    println!("The Kubernetes API server must be configured to trust Vouch as an OIDC provider.");
    println!("Configuration varies by cluster type:");
    println!();

    println!("Self-managed Kubernetes:");
    println!("------------------------");
    println!("Add these flags to kube-apiserver:");
    println!();
    println!("  --oidc-issuer-url={}", server);
    println!("  --oidc-client-id={}", audience);
    println!("  --oidc-username-claim=email");
    println!("  --oidc-username-prefix=-");
    println!();

    println!("Amazon EKS:");
    println!("-----------");
    println!("Use OIDC identity provider association:");
    println!();
    println!("  aws eks associate-identity-provider-config \\");
    println!("    --cluster-name {} \\", cluster_name);
    println!("    --oidc \\");
    println!("    --identity-provider-config-name vouch \\");
    println!(
        "    --identity-provider-config issuerUrl={},clientId={},usernameClaim=email",
        server, audience
    );
    println!();

    println!("Google GKE:");
    println!("-----------");
    println!("Use Identity Service (requires GKE Enterprise or Anthos):");
    println!();
    println!("  gcloud container clusters update {} \\", cluster_name);
    println!("    --identity-provider=vouch \\");
    println!("    --issuer-url={} \\", server);
    println!("    --client-id={}", audience);
    println!();

    println!("Azure AKS:");
    println!("----------");
    println!("AKS requires Entra ID integration or custom webhook authentication.");
    println!("See: https://learn.microsoft.com/azure/aks/use-oidc-issuer");
    println!();

    // RBAC configuration
    println!("=======================================================");
    println!("RBAC Configuration");
    println!("=======================================================");
    println!();
    println!("After OIDC is configured, grant users access via RBAC:");
    println!();
    println!("Example RoleBinding (namespace-scoped):");
    println!();
    println!("  apiVersion: rbac.authorization.k8s.io/v1");
    println!("  kind: RoleBinding");
    println!("  metadata:");
    println!("    name: vouch-user-binding");
    println!("    namespace: default");
    println!("  subjects:");
    println!("  - kind: User");
    println!("    name: user@example.com  # Email from Vouch token");
    println!("    apiGroup: rbac.authorization.k8s.io");
    println!("  roleRef:");
    println!("    kind: Role");
    println!("    name: developer");
    println!("    apiGroup: rbac.authorization.k8s.io");
    println!();

    println!("Example ClusterRoleBinding (cluster-scoped):");
    println!();
    println!("  apiVersion: rbac.authorization.k8s.io/v1");
    println!("  kind: ClusterRoleBinding");
    println!("  metadata:");
    println!("    name: vouch-admin-binding");
    println!("  subjects:");
    println!("  - kind: User");
    println!("    name: admin@example.com  # Email from Vouch token");
    println!("    apiGroup: rbac.authorization.k8s.io");
    println!("  roleRef:");
    println!("    kind: ClusterRole");
    println!("    name: cluster-admin");
    println!("    apiGroup: rbac.authorization.k8s.io");
    println!();

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
    server: https://k8s.prod.example.com:6443
- name: staging
  cluster:
    server: https://k8s.staging.example.com:6443
contexts:
- name: production
  context:
    cluster: production
    user: admin
users:
- name: admin
  user:
    token: existing-token
"#;

        let config: Kubeconfig = serde_yaml::from_str(yaml).expect("should parse");

        assert_eq!(config.clusters.len(), 2);
        assert_eq!(config.clusters[0].name, "production");
        assert_eq!(config.clusters[1].name, "staging");
        assert_eq!(config.contexts.len(), 1);
        assert_eq!(config.users.len(), 1);
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
    fn test_build_exec_config() {
        let vouch_path = std::path::Path::new("/usr/local/bin/vouch");
        let exec = build_exec_config(vouch_path, "my-cluster", Some("https://vouch.example.com"));

        assert_eq!(exec.api_version, "client.authentication.k8s.io/v1");
        assert_eq!(exec.command, "/usr/local/bin/vouch");
        assert_eq!(exec.args.len(), 4);
        assert_eq!(exec.args[0], "credential");
        assert_eq!(exec.args[1], "k8s");
        assert_eq!(exec.args[2], "--audience");
        assert_eq!(exec.args[3], "my-cluster");
        assert_eq!(exec.interactive_mode, Some("Never".to_string()));

        // Check env vars
        let env = exec.env.expect("should have env");
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].name, "VOUCH_SERVER");
        assert_eq!(env[0].value, "https://vouch.example.com");
    }

    #[test]
    fn test_build_exec_config_without_server() {
        let vouch_path = std::path::Path::new("/usr/local/bin/vouch");
        let exec = build_exec_config(vouch_path, "production", None);

        assert!(exec.env.is_none());
        assert_eq!(exec.args[3], "production");
    }

    #[test]
    fn test_exec_config_serialization() {
        let vouch_path = std::path::Path::new("/usr/local/bin/vouch");
        let exec = build_exec_config(vouch_path, "test-cluster", None);

        // Verify it serializes to valid YAML
        let yaml = serde_yaml::to_string(&exec).expect("should serialize");
        assert!(yaml.contains("apiVersion: client.authentication.k8s.io/v1"));
        assert!(yaml.contains("command: /usr/local/bin/vouch"));
        assert!(yaml.contains("interactiveMode: Never"));
    }

    #[test]
    fn test_kubeconfig_user_with_exec() {
        let vouch_path = std::path::Path::new("/usr/local/bin/vouch");
        let exec = build_exec_config(vouch_path, "my-cluster", Some("https://vouch.example.com"));

        let user = KubeconfigUser {
            name: "vouch-my-cluster".to_string(),
            user: KubeconfigUserData {
                exec: Some(exec),
                other: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            },
        };

        let yaml = serde_yaml::to_string(&user).expect("should serialize");
        assert!(yaml.contains("name: vouch-my-cluster"));
        assert!(yaml.contains("credential"));
        assert!(yaml.contains("k8s"));
    }

    #[test]
    fn test_kubeconfig_context() {
        let context = KubeconfigContext {
            name: "my-cluster-vouch".to_string(),
            context: KubeconfigContextData {
                cluster: "my-cluster".to_string(),
                namespace: Some("default".to_string()),
                user: "vouch-my-cluster".to_string(),
            },
        };

        let yaml = serde_yaml::to_string(&context).expect("should serialize");
        assert!(yaml.contains("name: my-cluster-vouch"));
        assert!(yaml.contains("cluster: my-cluster"));
        assert!(yaml.contains("user: vouch-my-cluster"));
        assert!(yaml.contains("namespace: default"));
    }

    #[test]
    fn test_kubeconfig_context_without_namespace() {
        let context = KubeconfigContext {
            name: "prod-vouch".to_string(),
            context: KubeconfigContextData {
                cluster: "prod".to_string(),
                namespace: None,
                user: "vouch-prod".to_string(),
            },
        };

        let yaml = serde_yaml::to_string(&context).expect("should serialize");
        assert!(!yaml.contains("namespace"));
    }
}
