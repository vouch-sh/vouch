// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kubernetes integration status checking.

use serde::Deserialize;
use std::path::PathBuf;

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};

/// Kubernetes integration checker.
pub struct K8sIntegration;

impl K8sIntegration {
    /// Create a new Kubernetes integration checker.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for K8sIntegration {
    fn default() -> Self {
        Self::new()
    }
}

/// Kubeconfig structure (partial - only what we need for status checking).
#[derive(Debug, Deserialize)]
struct Kubeconfig {
    #[serde(default)]
    contexts: Vec<KubeconfigContext>,
    #[serde(default)]
    users: Vec<KubeconfigUser>,
}

#[derive(Debug, Deserialize)]
struct KubeconfigContext {
    name: String,
    context: KubeconfigContextData,
}

#[derive(Debug, Deserialize)]
struct KubeconfigContextData {
    user: String,
}

#[derive(Debug, Deserialize)]
struct KubeconfigUser {
    name: String,
    user: KubeconfigUserData,
}

#[derive(Debug, Default, Deserialize)]
struct KubeconfigUserData {
    #[serde(default)]
    exec: Option<K8sExecConfig>,
}

#[derive(Debug, Deserialize)]
struct K8sExecConfig {
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
}

impl IntegrationCheck for K8sIntegration {
    fn name(&self) -> &'static str {
        "k8s"
    }

    fn check(&self) -> IntegrationState {
        let contexts = find_vouch_contexts();

        if contexts.is_empty() {
            return IntegrationState::NotConfigured {
                setup_hint: "vouch setup k8s --cluster <name>".to_string(),
            };
        }

        match contexts.as_slice() {
            [single] => IntegrationState::Configured(ConfiguredDetails {
                summary: single.clone(),
                details: Vec::new(),
            }),
            _ => IntegrationState::Configured(ConfiguredDetails {
                summary: "configured".to_string(),
                details: vec![("Contexts".to_string(), contexts.join(", "))],
            }),
        }
    }
}

/// Get the default kubeconfig path.
fn default_kubeconfig_path() -> Option<PathBuf> {
    // Check KUBECONFIG env var first
    if let Ok(kubeconfig) = std::env::var("KUBECONFIG")
        // KUBECONFIG can contain multiple paths separated by ':'
        && let Some(first_path) = kubeconfig.split(':').next()
        && !first_path.is_empty()
    {
        return Some(PathBuf::from(first_path));
    }

    dirs::home_dir().map(|h| h.join(".kube").join("config"))
}

/// Find all Kubernetes contexts configured to use Vouch.
fn find_vouch_contexts() -> Vec<String> {
    let kubeconfig_path = match default_kubeconfig_path() {
        Some(p) if p.exists() => p,
        _ => return Vec::new(),
    };

    let content = match std::fs::read_to_string(&kubeconfig_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let config: Kubeconfig = match serde_yaml::from_str(&content) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Find users with vouch exec credential
    let vouch_users: std::collections::HashSet<&str> = config
        .users
        .iter()
        .filter(|u| u.user.exec.as_ref().is_some_and(is_vouch_k8s_exec))
        .map(|u| u.name.as_str())
        .collect();

    // Find contexts using those users
    config
        .contexts
        .iter()
        .filter(|c| vouch_users.contains(c.context.user.as_str()))
        .map(|c| c.name.clone())
        .collect()
}

/// Check if an exec config is a vouch k8s credential.
fn is_vouch_k8s_exec(exec: &K8sExecConfig) -> bool {
    // Check if command contains "vouch"
    let command_has_vouch = exec
        .command
        .as_ref()
        .is_some_and(|cmd| cmd.contains("vouch"));

    // Check if args contain "k8s"
    let args_have_k8s = exec.args.iter().any(|arg| arg == "k8s");

    command_has_vouch && args_have_k8s
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // ==========================================================================
    // Exec Config Detection Tests
    // ==========================================================================

    #[test]
    fn test_is_vouch_k8s_exec_valid() {
        let exec = K8sExecConfig {
            command: Some("/usr/local/bin/vouch".to_string()),
            args: vec![
                "credential".to_string(),
                "k8s".to_string(),
                "--audience".to_string(),
                "my-cluster".to_string(),
            ],
        };

        assert!(is_vouch_k8s_exec(&exec));
    }

    #[test]
    fn test_is_vouch_k8s_exec_vouch_in_path() {
        let exec = K8sExecConfig {
            command: Some("/home/user/.local/bin/vouch".to_string()),
            args: vec!["credential".to_string(), "k8s".to_string()],
        };

        assert!(is_vouch_k8s_exec(&exec));
    }

    #[test]
    fn test_is_vouch_k8s_exec_no_vouch_in_command() {
        let exec = K8sExecConfig {
            command: Some("/usr/bin/other-tool".to_string()),
            args: vec!["credential".to_string(), "k8s".to_string()],
        };

        assert!(!is_vouch_k8s_exec(&exec));
    }

    #[test]
    fn test_is_vouch_k8s_exec_no_k8s_in_args() {
        let exec = K8sExecConfig {
            command: Some("/usr/local/bin/vouch".to_string()),
            args: vec!["credential".to_string(), "aws".to_string()],
        };

        assert!(!is_vouch_k8s_exec(&exec));
    }

    #[test]
    fn test_is_vouch_k8s_exec_empty_args() {
        let exec = K8sExecConfig {
            command: Some("/usr/local/bin/vouch".to_string()),
            args: vec![],
        };

        assert!(!is_vouch_k8s_exec(&exec));
    }

    #[test]
    fn test_is_vouch_k8s_exec_no_command() {
        let exec = K8sExecConfig {
            command: None,
            args: vec!["credential".to_string(), "k8s".to_string()],
        };

        assert!(!is_vouch_k8s_exec(&exec));
    }

    // ==========================================================================
    // Kubeconfig Parsing Tests
    // ==========================================================================

    #[test]
    fn test_kubeconfig_parsing() {
        let yaml = r#"
apiVersion: v1
kind: Config
contexts:
- name: prod-vouch
  context:
    cluster: prod
    user: vouch-prod
- name: staging
  context:
    cluster: staging
    user: regular-user
users:
- name: vouch-prod
  user:
    exec:
      command: /usr/local/bin/vouch
      args:
        - credential
        - k8s
        - --audience
        - prod
- name: regular-user
  user:
    token: some-token
"#;

        let config: Kubeconfig = serde_yaml::from_str(yaml).expect("should parse");

        assert_eq!(config.contexts.len(), 2);
        assert_eq!(config.users.len(), 2);

        // First user should have vouch exec
        let vouch_user = &config.users[0];
        assert_eq!(vouch_user.name, "vouch-prod");
        assert!(vouch_user.user.exec.is_some());
        assert!(is_vouch_k8s_exec(vouch_user.user.exec.as_ref().unwrap()));

        // Second user should not have exec
        let regular_user = &config.users[1];
        assert_eq!(regular_user.name, "regular-user");
        assert!(regular_user.user.exec.is_none());
    }

    #[test]
    fn test_kubeconfig_empty() {
        let yaml = r#"
apiVersion: v1
kind: Config
contexts: []
users: []
"#;

        let config: Kubeconfig = serde_yaml::from_str(yaml).expect("should parse");

        assert!(config.contexts.is_empty());
        assert!(config.users.is_empty());
    }

    #[test]
    fn test_kubeconfig_missing_fields() {
        // Test that missing fields get default values
        let yaml = r#"
apiVersion: v1
kind: Config
"#;

        let config: Kubeconfig = serde_yaml::from_str(yaml).expect("should parse");

        assert!(config.contexts.is_empty());
        assert!(config.users.is_empty());
    }
}
