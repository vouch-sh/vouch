// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Read-only restriction for AI-agent credentials that were not minted
//! through an `AssumeRole*` call.
//!
//! On the role paths an agent's credentials carry the AWS managed
//! `ReadOnlyAccess` policy as a session policy, attached during
//! `AssumeRoleWithWebIdentity` / `AssumeRole`. Identity Center permission-set
//! credentials and account access manager credentials come from APIs that
//! take no session policy, so they are narrowed afterwards with AWS STS
//! `GetScopedCredentials`.
//!
//! That API accepts only an inline policy of at most 2,048 characters and no
//! managed policy ARNs, so `ReadOnlyAccess` cannot be named here. The policy
//! below allows the read-shaped action names (`Get*`, `List*`, `Describe*`,
//! `BatchGet*`) on every service instead, using a wildcard service prefix so
//! that no per-service list has to be maintained.
//!
//! AWS documents wildcards only in the action name, after the colon; whether
//! a wildcard service prefix is accepted is not stated. If AWS rejects the
//! policy, or accepts it and matches nothing, the agent is denied — it never
//! receives more than the policy allows.
//!
//! <https://docs.aws.amazon.com/STS/latest/APIReference/API_GetScopedCredentials.html>

use anyhow::Result;
use vouch_cli::tr;

use super::sts::{ScopedCredentialsRequest, StsCredentials, get_scoped_credentials};

/// Action-name patterns an AI agent keeps, on any service.
const AGENT_READ_ACTIONS: &[&str] = &["*:Get*", "*:List*", "*:Describe*", "*:BatchGet*"];

/// Read-shaped actions that return a secret value, a token or credentials,
/// denied explicitly because the patterns in [`AGENT_READ_ACTIONS`] would
/// otherwise match them. Each name is as listed in the AWS Service
/// Authorization Reference for its service.
const AGENT_DENIED_ACTIONS: &[&str] = &[
    "secretsmanager:GetSecretValue",
    "secretsmanager:BatchGetSecretValue",
    "ecr:GetAuthorizationToken",
    "ecr-public:GetAuthorizationToken",
    "codeartifact:GetAuthorizationToken",
    // Bearer tokens for CodeArtifact and ECR Public are minted through this.
    "sts:GetServiceBearerToken",
    "redshift:GetClusterCredentials",
    "redshift:GetClusterCredentialsWithIAM",
    "redshift:GetIdentityCenterAuthToken",
    "redshift-serverless:GetCredentials",
    "redshift-serverless:GetIdentityCenterAuthToken",
];

/// The scope-down policy document applied to an AI agent's credentials.
///
/// `kms:Decrypt` matches none of the allowed patterns, which also keeps
/// `SecureString` parameters and KMS-encrypted objects unreadable.
/// `sts:GetScopedCredentials` matches `*:Get*`, so an agent can narrow these
/// credentials further for a sub-agent; that call can only reduce access.
fn agent_scope_down_policy() -> String {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": AGENT_READ_ACTIONS,
                "Resource": "*"
            },
            {
                "Effect": "Deny",
                "Action": AGENT_DENIED_ACTIONS,
                "Resource": "*"
            }
        ]
    })
    .to_string()
}

/// Narrow `credentials` to the agent read-only policy.
///
/// `region` selects the regional STS endpoint; the credentials themselves
/// are not region-bound. `agent_source` is recorded in CloudTrail as the
/// scoped session's description. That is the only attribution available on
/// this path, because `GetScopedCredentials` preserves session tags but
/// cannot add `vouch:AccessType` / `vouch:Agent`.
///
/// # Errors
///
/// Any failure means the agent gets no credentials. The usual cause is a
/// role or permission set that does not allow `sts:GetScopedCredentials`;
/// the error says so.
pub(crate) async fn scope_credentials_for_agent(
    http_client: &reqwest::Client,
    region: &str,
    credentials: &StsCredentials,
    agent_source: &str,
) -> Result<StsCredentials> {
    tracing::info!("AI agent detected ({agent_source}), applying read-only scope-down policy");
    let policy = agent_scope_down_policy();
    get_scoped_credentials(ScopedCredentialsRequest {
        http_client,
        region,
        source_creds: credentials,
        policy: &policy,
        description: &format!("vouch AI agent: {agent_source}"),
    })
    .await
    .map_err(|err| err.context(tr!("aws-err-agent-scope-down-failed")))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::integrations::aws::sts::SCOPE_DOWN_POLICY_MAX_CHARS;

    fn statement(effect: &str) -> serde_json::Value {
        let policy: serde_json::Value = serde_json::from_str(&agent_scope_down_policy()).unwrap();
        let statements = policy["Statement"].as_array().unwrap();
        assert_eq!(statements.len(), 2);
        statements
            .iter()
            .find(|s| s["Effect"] == effect)
            .unwrap()
            .clone()
    }

    fn actions(effect: &str) -> Vec<String> {
        statement(effect)["Action"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_string())
            .collect()
    }

    /// AWS rejects a longer `Policy`, which would deny every agent on the
    /// scoped paths.
    #[test]
    fn policy_fits_the_get_scoped_credentials_limit() {
        let len = agent_scope_down_policy().chars().count();
        assert!(
            len <= SCOPE_DOWN_POLICY_MAX_CHARS,
            "scope-down policy is {len} characters, limit is {SCOPE_DOWN_POLICY_MAX_CHARS}"
        );
    }

    /// Every allowed pattern starts with a read verb, so no pattern can
    /// match a write action or a whole service.
    #[test]
    fn policy_allows_only_read_shaped_actions() {
        const READ_VERBS: &[&str] = &["Get", "List", "Describe", "BatchGet"];
        let allow = statement("Allow");
        assert_eq!(allow["Resource"], "*");
        assert!(allow.get("NotAction").is_none());
        for action in actions("Allow") {
            let (_, name) = action.split_once(':').unwrap();
            let verb = name.strip_suffix('*').unwrap();
            assert!(READ_VERBS.contains(&verb), "{action} is not a read pattern");
        }
    }

    /// The read patterns match these secret- and credential-returning
    /// actions; the explicit deny takes them back. Nothing allowed matches
    /// `kms:Decrypt` or `sts:Assume*`.
    #[test]
    fn policy_withholds_secret_values_and_decryption() {
        assert_eq!(statement("Deny")["Resource"], "*");
        let denied = actions("Deny");
        for action in [
            "secretsmanager:GetSecretValue",
            "secretsmanager:BatchGetSecretValue",
            "ecr:GetAuthorizationToken",
            "codeartifact:GetAuthorizationToken",
            "sts:GetServiceBearerToken",
            "redshift:GetClusterCredentials",
            "redshift-serverless:GetCredentials",
        ] {
            assert!(denied.iter().any(|d| d == action), "{action} is not denied");
        }
        for action in actions("Allow") {
            let (_, name) = action.split_once(':').unwrap();
            let verb = name.strip_suffix('*').unwrap();
            assert!(!"Decrypt".starts_with(verb), "{action}");
            assert!(!"AssumeRole".starts_with(verb), "{action}");
        }
    }
}
