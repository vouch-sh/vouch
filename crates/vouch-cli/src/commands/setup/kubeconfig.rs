// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared kubeconfig types and helpers for Kubernetes setup commands.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::utils::ensure_secure_dir;
use vouch_common::fs::write_secure_file;

// ============================================================================
// Kubeconfig Types
// ============================================================================

/// Kubeconfig structure (partial - only what we need to read/modify).
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Kubeconfig {
    #[serde(default, rename = "apiVersion")]
    pub api_version: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub clusters: Vec<KubeconfigCluster>,
    #[serde(default)]
    pub contexts: Vec<KubeconfigContext>,
    #[serde(default, rename = "current-context")]
    pub current_context: Option<String>,
    #[serde(default)]
    pub users: Vec<KubeconfigUser>,
    #[serde(default)]
    pub preferences: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KubeconfigCluster {
    pub name: String,
    pub cluster: KubeconfigClusterData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KubeconfigClusterData {
    pub server: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "certificate-authority-data"
    )]
    pub certificate_authority_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KubeconfigContext {
    pub name: String,
    pub context: KubeconfigContextData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KubeconfigContextData {
    pub cluster: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KubeconfigUser {
    pub name: String,
    pub user: KubeconfigUserData,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct KubeconfigUserData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecConfig>,
    #[serde(flatten)]
    pub other: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExecConfig {
    pub api_version: String,
    pub command: String,
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<EnvVar>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interactive_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EnvVar {
    pub name: String,
    pub value: String,
}

// ============================================================================
// Kubeconfig Helpers
// ============================================================================

/// Get the default kubeconfig path (~/.kube/config).
pub(crate) fn default_kubeconfig_path() -> Result<PathBuf> {
    if let Ok(kubeconfig) = std::env::var("KUBECONFIG")
        && let Some(first_path) = kubeconfig.split(':').next()
        && !first_path.is_empty()
    {
        return Ok(PathBuf::from(first_path));
    }

    let home = dirs::home_dir().with_context(|| vouch_cli::tr!("setup-err-no-home"))?;
    Ok(home.join(".kube").join("config"))
}

/// Load kubeconfig from file, or return empty config if file doesn't exist.
pub(crate) fn load_kubeconfig(path: &std::path::Path) -> Result<Kubeconfig> {
    if !path.exists() {
        return Ok(Kubeconfig {
            api_version: Some("v1".to_string()),
            kind: Some("Config".to_string()),
            ..Default::default()
        });
    }

    let content = std::fs::read_to_string(path).with_context(|| {
        vouch_cli::tr_args!("setup-kc-err-read", path = path.display().to_string())
    })?;
    let config: Kubeconfig = parse_kubeconfig(&content).with_context(|| {
        vouch_cli::tr_args!("setup-kc-err-parse", path = path.display().to_string())
    })?;
    Ok(config)
}

/// Parse kubeconfig YAML with YAML 1.2 boolean rules.
///
/// Only `true`/`false` are booleans; YAML 1.1 spellings (`no`, `yes`, `on`,
/// `off`, ...) stay strings. Fields we don't model land in `#[serde(flatten)]`
/// `serde_json::Value` catch-alls and are written back verbatim by
/// [`save_kubeconfig`], so without strict booleans another user's unquoted
/// `token: no` would round-trip as `token: false` and break their kubectl auth.
fn parse_kubeconfig(content: &str) -> Result<Kubeconfig, serde_saphyr::Error> {
    let options = serde_saphyr::options! { strict_booleans: true };
    serde_saphyr::from_str_with_options(content, options)
}

/// Save kubeconfig to file.
pub(crate) fn save_kubeconfig(path: &std::path::Path, config: &Kubeconfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_secure_dir(parent)?;
    }

    let content = serde_saphyr::to_string(config)
        .with_context(|| vouch_cli::tr!("setup-kc-err-serialize"))?;
    write_secure_file(path, &content)?;
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
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

        let config: Kubeconfig = serde_saphyr::from_str(yaml).expect("should parse");

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

        let config: Kubeconfig = serde_saphyr::from_str(yaml).expect("should parse");

        assert!(config.clusters.is_empty());
        assert!(config.contexts.is_empty());
        assert!(config.users.is_empty());
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

        let yaml = serde_saphyr::to_string(&exec).expect("should serialize");
        assert!(yaml.contains("apiVersion: client.authentication.k8s.io/v1"));
        assert!(yaml.contains("command: vouch"));
        assert!(yaml.contains("interactiveMode: Never"));
        assert!(yaml.contains("credential"));
        assert!(!yaml.contains("env:"));
    }

    #[test]
    fn test_kubeconfig_context() {
        let context = KubeconfigContext {
            name: "my-cluster-vouch".to_string(),
            context: KubeconfigContextData {
                cluster: "my-cluster".to_string(),
                namespace: None,
                user: "vouch-k8s-my-cluster".to_string(),
            },
        };

        let yaml = serde_saphyr::to_string(&context).expect("should serialize");
        assert!(yaml.contains("name: my-cluster-vouch"));
        assert!(yaml.contains("cluster: my-cluster"));
        assert!(yaml.contains("user: vouch-k8s-my-cluster"));
        assert!(!yaml.contains("namespace"));
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

        let yaml = serde_saphyr::to_string(&cluster).expect("should serialize");
        assert!(yaml.contains("certificate-authority-data:"));
        assert!(yaml.contains("LS0tLS1CRUdJTi..."));
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

        let yaml = serde_saphyr::to_string(&cluster).expect("should serialize");
        assert!(yaml.contains("name: dev"));
        assert!(!yaml.contains("certificate-authority-data"));
    }

    /// The `#[serde(flatten)] other` field must preserve arbitrary user auth
    /// fields (token, client-certificate-data, etc.) losslessly across a
    /// load -> save -> load round-trip. This is the behaviour serde_yaml's
    /// untyped `Value` catch-all provided and that the serde-saphyr +
    /// serde_json::Value migration must keep (#595).
    #[test]
    fn test_kubeconfig_flatten_preserves_arbitrary_user_fields() {
        let yaml = r#"
apiVersion: v1
kind: Config
clusters: []
contexts: []
users:
- name: legacy-user
  user:
    token: super-secret-token
    client-certificate-data: LS0tLS1DRVJU
    username: admin
"#;

        let config: Kubeconfig = serde_saphyr::from_str(yaml).expect("should parse");
        let other = &config.users[0].user.other;
        assert_eq!(other["token"], "super-secret-token");
        assert_eq!(other["client-certificate-data"], "LS0tLS1DRVJU");
        assert_eq!(other["username"], "admin");

        // Round-trip: serialize, then re-parse, and confirm the fields survive.
        let serialized = serde_saphyr::to_string(&config).expect("should serialize");
        assert!(serialized.contains("super-secret-token"), "{serialized}");
        assert!(
            serialized.contains("client-certificate-data"),
            "{serialized}"
        );

        let reparsed: Kubeconfig = serde_saphyr::from_str(&serialized).expect("should re-parse");
        let other2 = &reparsed.users[0].user.other;
        assert_eq!(other2["token"], "super-secret-token");
        assert_eq!(other2["client-certificate-data"], "LS0tLS1DRVJU");
        assert_eq!(other2["username"], "admin");
    }

    /// Unquoted auth values that are YAML 1.1 reserved words (`no`, `yes`,
    /// `on`, `off`) in *other* users' entries must stay strings across a
    /// load -> save -> load round-trip. With default YAML 1.1 typing,
    /// `token: no` parses as `Bool(false)` and `save_kubeconfig` would
    /// persist `token: false`, breaking that user's kubectl auth (#670).
    #[test]
    fn test_yaml11_boolean_like_tokens_survive_roundtrip() {
        let yaml = r#"
apiVersion: v1
kind: Config
clusters: []
contexts: []
users:
- name: legacy-user
  user:
    token: no
    username: yes
    password: on
    client-key-data: off
"#;

        let config: Kubeconfig = parse_kubeconfig(yaml).expect("should parse");
        let other = &config.users[0].user.other;
        for (field, want) in [
            ("token", "no"),
            ("username", "yes"),
            ("password", "on"),
            ("client-key-data", "off"),
        ] {
            let value = other.get(field).expect(field);
            assert!(value.is_string(), "{field}: got {value:?}, want a string");
            assert_eq!(value, want, "{field}");
        }

        // Serialize and re-parse: the serializer quotes ambiguous scalars, so
        // the values survive another strict parse unchanged.
        let serialized = serde_saphyr::to_string(&config).expect("should serialize");
        let reparsed: Kubeconfig = parse_kubeconfig(&serialized).expect("should re-parse");
        let other2 = &reparsed.users[0].user.other;
        assert_eq!(other2["token"], "no");
        assert_eq!(other2["username"], "yes");
        assert_eq!(other2["password"], "on");
        assert_eq!(other2["client-key-data"], "off");

        // Real booleans are still booleans under YAML 1.2 rules.
        let bool_yaml = "users:\n- name: u\n  user:\n    some-flag: true\n";
        let parsed: Kubeconfig = parse_kubeconfig(bool_yaml).expect("should parse");
        assert_eq!(parsed.users[0].user.other["some-flag"], true);
    }
}
