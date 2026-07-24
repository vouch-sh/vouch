// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Amazon EKS integration status checking.

use serde::Deserialize;

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};

/// EKS integration checker.
pub(crate) struct EksIntegration;

impl EksIntegration {
    /// Create a new EKS integration checker.
    #[must_use]
    pub(crate) fn new() -> Self {
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
}

impl IntegrationCheck for EksIntegration {
    fn name(&self) -> &'static str {
        "EKS"
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

/// Find all kubeconfig contexts using `vouch credential eks`.
fn find_vouch_eks_contexts() -> Vec<String> {
    let kubeconfig_path = match crate::commands::setup::kubeconfig::default_kubeconfig_path().ok() {
        Some(p) if p.exists() => p,
        _ => return Vec::new(),
    };

    let content = match std::fs::read_to_string(&kubeconfig_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let config: Kubeconfig = match serde_saphyr::from_str(&content) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let vouch_users: std::collections::HashSet<&str> = config
        .users
        .iter()
        .filter(|u| u.user.exec.as_ref().is_some_and(is_vouch_eks_exec))
        .map(|u| u.name.as_str())
        .collect();

    config
        .contexts
        .iter()
        .filter(|c| vouch_users.contains(c.context.user.as_str()))
        .map(|c| c.name.clone())
        .collect()
}

/// Check if an exec config is `vouch credential eks`.
fn is_vouch_eks_exec(exec: &EksExecConfig) -> bool {
    let is_vouch_command = exec.command.as_ref().is_some_and(|cmd| cmd == "vouch");
    let has_credential = exec.args.iter().any(|a| a == "credential");
    let has_eks = exec.args.iter().any(|a| a == "eks");

    is_vouch_command && has_credential && has_eks
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

    // ==========================================================================
    // Exec Config Detection Tests
    // ==========================================================================

    #[test]
    fn test_is_vouch_eks_exec_full_args() {
        let exec = EksExecConfig {
            command: Some("vouch".to_string()),
            args: vec![
                "credential".to_string(),
                "eks".to_string(),
                "--cluster-name".to_string(),
                "my-cluster".to_string(),
                "--region".to_string(),
                "us-east-1".to_string(),
                "--role".to_string(),
                "arn:aws:iam::123456789012:role/MyRole".to_string(),
            ],
        };

        assert!(is_vouch_eks_exec(&exec));
    }

    #[test]
    fn test_is_vouch_eks_exec_minimal_args() {
        let exec = EksExecConfig {
            command: Some("vouch".to_string()),
            args: vec![
                "credential".to_string(),
                "eks".to_string(),
                "--cluster-name".to_string(),
                "test".to_string(),
            ],
        };

        assert!(is_vouch_eks_exec(&exec));
    }

    #[test]
    fn test_is_vouch_eks_exec_not_vouch_command() {
        let exec = EksExecConfig {
            command: Some("other-tool".to_string()),
            args: vec!["credential".to_string(), "eks".to_string()],
        };

        assert!(!is_vouch_eks_exec(&exec));
    }

    #[test]
    fn test_is_vouch_eks_exec_no_command() {
        let exec = EksExecConfig {
            command: None,
            args: vec!["credential".to_string(), "eks".to_string()],
        };

        assert!(!is_vouch_eks_exec(&exec));
    }

    #[test]
    fn test_is_vouch_eks_exec_missing_credential_arg() {
        let exec = EksExecConfig {
            command: Some("vouch".to_string()),
            args: vec!["eks".to_string()],
        };

        assert!(!is_vouch_eks_exec(&exec));
    }

    #[test]
    fn test_is_vouch_eks_exec_missing_eks_arg() {
        let exec = EksExecConfig {
            command: Some("vouch".to_string()),
            args: vec!["credential".to_string(), "rds".to_string()],
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
      command: vouch
      args:
        - credential
        - eks
        - --cluster-name
        - prod
        - --region
        - us-east-1
        - --role
        - arn:aws:iam::123456789012:role/MyRole
- name: regular-user
  user:
    token: some-token
"#;

        let config: Kubeconfig = serde_saphyr::from_str(yaml).expect("should parse");

        assert_eq!(config.contexts.len(), 2);
        assert_eq!(config.users.len(), 2);

        let vouch_user = &config.users[0];
        assert_eq!(vouch_user.name, "vouch-eks-prod");
        assert!(vouch_user.user.exec.is_some());
        assert!(is_vouch_eks_exec(vouch_user.user.exec.as_ref().unwrap()));

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

        let config: Kubeconfig = serde_saphyr::from_str(yaml).expect("should parse");

        assert!(config.contexts.is_empty());
        assert!(config.users.is_empty());
    }

    #[test]
    fn test_kubeconfig_missing_fields() {
        let yaml = r#"
apiVersion: v1
kind: Config
"#;

        let config: Kubeconfig = serde_saphyr::from_str(yaml).expect("should parse");

        assert!(config.contexts.is_empty());
        assert!(config.users.is_empty());
    }
}
