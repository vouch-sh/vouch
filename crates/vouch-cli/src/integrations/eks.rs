// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Amazon EKS integration status checking.

use serde::Deserialize;
use std::path::PathBuf;

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};

/// EKS integration checker.
pub struct EksIntegration;

impl EksIntegration {
    /// Create a new EKS integration checker.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for EksIntegration {
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
    exec: Option<EksExecConfig>,
}

#[derive(Debug, Deserialize)]
struct EksExecConfig {
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Option<Vec<ExecEnvVar>>,
}

#[derive(Debug, Deserialize)]
struct ExecEnvVar {
    name: String,
    value: String,
}

impl IntegrationCheck for EksIntegration {
    fn name(&self) -> &'static str {
        "eks"
    }

    fn check(&self) -> IntegrationState {
        let contexts = find_vouch_eks_contexts();

        if contexts.is_empty() {
            return IntegrationState::NotConfigured {
                setup_hint: "vouch setup eks --cluster <name>".to_string(),
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
    if let Ok(kubeconfig) = std::env::var("KUBECONFIG")
        && let Some(first_path) = kubeconfig.split(':').next()
        && !first_path.is_empty()
    {
        return Some(PathBuf::from(first_path));
    }

    dirs::home_dir().map(|h| h.join(".kube").join("config"))
}

/// Find all kubeconfig contexts using `aws eks get-token` with a vouch profile.
fn find_vouch_eks_contexts() -> Vec<String> {
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

    // Find users with aws eks get-token exec and a vouch AWS_PROFILE
    let vouch_users: std::collections::HashSet<&str> = config
        .users
        .iter()
        .filter(|u| u.user.exec.as_ref().is_some_and(is_vouch_eks_exec))
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

/// Check if an exec config is an EKS credential backed by a vouch AWS profile.
fn is_vouch_eks_exec(exec: &EksExecConfig) -> bool {
    // Command must be "aws"
    let is_aws_command = exec.command.as_ref().is_some_and(|cmd| cmd == "aws");

    // Args must contain "eks" and "get-token"
    let has_eks = exec.args.iter().any(|a| a == "eks");
    let has_get_token = exec.args.iter().any(|a| a == "get-token");

    // Env must have AWS_PROFILE pointing to a vouch-like profile
    let has_vouch_profile = exec.env.as_ref().is_some_and(|envs| {
        envs.iter()
            .any(|e| e.name == "AWS_PROFILE" && e.value.contains("vouch"))
    });

    is_aws_command && has_eks && has_get_token && has_vouch_profile
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // ==========================================================================
    // Exec Config Detection Tests
    // ==========================================================================

    #[test]
    fn test_is_vouch_eks_exec_valid() {
        let exec = EksExecConfig {
            command: Some("aws".to_string()),
            args: vec![
                "eks".to_string(),
                "get-token".to_string(),
                "--cluster-name".to_string(),
                "my-cluster".to_string(),
                "--region".to_string(),
                "us-east-1".to_string(),
            ],
            env: Some(vec![ExecEnvVar {
                name: "AWS_PROFILE".to_string(),
                value: "vouch".to_string(),
            }]),
        };

        assert!(is_vouch_eks_exec(&exec));
    }

    #[test]
    fn test_is_vouch_eks_exec_vouch_numbered_profile() {
        let exec = EksExecConfig {
            command: Some("aws".to_string()),
            args: vec!["eks".to_string(), "get-token".to_string()],
            env: Some(vec![ExecEnvVar {
                name: "AWS_PROFILE".to_string(),
                value: "vouch-2".to_string(),
            }]),
        };

        assert!(is_vouch_eks_exec(&exec));
    }

    #[test]
    fn test_is_vouch_eks_exec_not_aws_command() {
        let exec = EksExecConfig {
            command: Some("kubectl".to_string()),
            args: vec!["eks".to_string(), "get-token".to_string()],
            env: Some(vec![ExecEnvVar {
                name: "AWS_PROFILE".to_string(),
                value: "vouch".to_string(),
            }]),
        };

        assert!(!is_vouch_eks_exec(&exec));
    }

    #[test]
    fn test_is_vouch_eks_exec_no_eks_arg() {
        let exec = EksExecConfig {
            command: Some("aws".to_string()),
            args: vec!["sts".to_string(), "get-caller-identity".to_string()],
            env: Some(vec![ExecEnvVar {
                name: "AWS_PROFILE".to_string(),
                value: "vouch".to_string(),
            }]),
        };

        assert!(!is_vouch_eks_exec(&exec));
    }

    #[test]
    fn test_is_vouch_eks_exec_non_vouch_profile() {
        let exec = EksExecConfig {
            command: Some("aws".to_string()),
            args: vec!["eks".to_string(), "get-token".to_string()],
            env: Some(vec![ExecEnvVar {
                name: "AWS_PROFILE".to_string(),
                value: "production".to_string(),
            }]),
        };

        assert!(!is_vouch_eks_exec(&exec));
    }

    #[test]
    fn test_is_vouch_eks_exec_no_env() {
        let exec = EksExecConfig {
            command: Some("aws".to_string()),
            args: vec!["eks".to_string(), "get-token".to_string()],
            env: None,
        };

        assert!(!is_vouch_eks_exec(&exec));
    }

    #[test]
    fn test_is_vouch_eks_exec_no_command() {
        let exec = EksExecConfig {
            command: None,
            args: vec!["eks".to_string(), "get-token".to_string()],
            env: Some(vec![ExecEnvVar {
                name: "AWS_PROFILE".to_string(),
                value: "vouch".to_string(),
            }]),
        };

        assert!(!is_vouch_eks_exec(&exec));
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
    user: vouch-eks-prod
- name: staging
  context:
    cluster: staging
    user: regular-user
users:
- name: vouch-eks-prod
  user:
    exec:
      command: aws
      args:
        - eks
        - get-token
        - --cluster-name
        - prod
        - --region
        - us-east-1
      env:
        - name: AWS_PROFILE
          value: vouch
- name: regular-user
  user:
    token: some-token
"#;

        let config: Kubeconfig = serde_yaml::from_str(yaml).expect("should parse");

        assert_eq!(config.contexts.len(), 2);
        assert_eq!(config.users.len(), 2);

        // First user should have vouch EKS exec
        let vouch_user = &config.users[0];
        assert_eq!(vouch_user.name, "vouch-eks-prod");
        assert!(vouch_user.user.exec.is_some());
        assert!(is_vouch_eks_exec(vouch_user.user.exec.as_ref().unwrap()));

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
        let yaml = r#"
apiVersion: v1
kind: Config
"#;

        let config: Kubeconfig = serde_yaml::from_str(yaml).expect("should parse");

        assert!(config.contexts.is_empty());
        assert!(config.users.is_empty());
    }
}
