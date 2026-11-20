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
//! below is an allow-list of read actions for commonly used services. A
//! service missing from it is denied to the agent, never writable.
//!
//! <https://docs.aws.amazon.com/STS/latest/APIReference/API_GetScopedCredentials.html>

use anyhow::Result;
use vouch_cli::tr;

use super::sts::{ScopedCredentialsRequest, StsCredentials, get_scoped_credentials};

const DESCRIBE: &str = "Describe*";
const GET: &str = "Get*";
const LIST: &str = "List*";
const BATCH_GET: &str = "BatchGet*";

/// Service prefix → read actions an AI agent keeps on scoped credentials.
///
/// Secrets stay out of reach: `secretsmanager` has no `Get*` (so no
/// `GetSecretValue`), and `kms` has no `Decrypt`, which also keeps
/// `SecureString` parameters and KMS-encrypted objects unreadable.
/// `sts:GetScopedCredentials` is allowed so an agent can narrow these
/// credentials further for a sub-agent; that call can only reduce access.
const AGENT_READ_ACTIONS: &[(&str, &[&str])] = &[
    ("acm", &[DESCRIBE, GET, LIST]),
    ("apigateway", &["GET"]),
    ("athena", &[GET, LIST, BATCH_GET]),
    ("autoscaling", &[DESCRIBE]),
    ("ce", &[GET, LIST]),
    ("cloudformation", &[DESCRIBE, GET, LIST]),
    ("cloudfront", &[GET, LIST]),
    ("cloudtrail", &[DESCRIBE, GET, LIST, "LookupEvents"]),
    ("cloudwatch", &[DESCRIBE, GET, LIST]),
    ("codebuild", &[LIST, BATCH_GET]),
    ("codecommit", &[GET, LIST, BATCH_GET, "GitPull"]),
    ("codepipeline", &[GET, LIST]),
    ("config", &[DESCRIBE, GET, LIST]),
    (
        "dynamodb",
        &[DESCRIBE, GET, LIST, BATCH_GET, "Query", "Scan"],
    ),
    ("ec2", &[DESCRIBE, GET]),
    (
        "ecr",
        &[
            DESCRIBE,
            GET,
            LIST,
            BATCH_GET,
            "BatchCheckLayerAvailability",
        ],
    ),
    ("ecs", &[DESCRIBE, LIST]),
    ("eks", &[DESCRIBE, LIST]),
    ("elasticache", &[DESCRIBE, LIST]),
    ("elasticfilesystem", &[DESCRIBE]),
    ("elasticloadbalancing", &[DESCRIBE]),
    ("es", &[DESCRIBE, LIST, "ESHttpGet", "ESHttpHead"]),
    ("events", &[DESCRIBE, LIST]),
    ("glue", &[GET, LIST, BATCH_GET]),
    ("iam", &[GET, LIST]),
    ("kinesis", &[DESCRIBE, GET, LIST]),
    ("kms", &[DESCRIBE, GET, LIST]),
    ("lambda", &[GET, LIST]),
    (
        "logs",
        &[
            DESCRIBE,
            GET,
            LIST,
            "FilterLogEvents",
            "StartQuery",
            "StopQuery",
        ],
    ),
    ("organizations", &[DESCRIBE, LIST]),
    ("rds", &[DESCRIBE, LIST]),
    ("redshift", &[DESCRIBE]),
    ("route53", &[GET, LIST]),
    ("s3", &[GET, LIST]),
    ("secretsmanager", &[DESCRIBE, LIST]),
    ("servicequotas", &[GET, LIST]),
    ("sns", &[GET, LIST]),
    ("sqs", &[GET, LIST]),
    ("ssm", &[DESCRIBE, GET, LIST]),
    ("sso", &[DESCRIBE, GET, LIST]),
    ("states", &[DESCRIBE, GET, LIST]),
    ("sts", &["GetCallerIdentity", "GetScopedCredentials"]),
    ("tag", &[GET]),
    ("xray", &[GET, LIST, BATCH_GET]),
];

/// The scope-down policy document applied to an AI agent's credentials.
fn agent_scope_down_policy() -> String {
    let actions: Vec<String> = AGENT_READ_ACTIONS
        .iter()
        .flat_map(|(service, verbs)| verbs.iter().map(move |verb| format!("{service}:{verb}")))
        .collect();
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": actions,
            "Resource": "*"
        }]
    })
    .to_string()
}

/// Narrow `credentials` to the agent read-only allow-list.
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

    fn policy_actions() -> Vec<String> {
        let policy: serde_json::Value = serde_json::from_str(&agent_scope_down_policy()).unwrap();
        policy["Statement"][0]["Action"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_string())
            .collect()
    }

    /// AWS rejects a longer `Policy`, which would deny every agent on the
    /// scoped paths, so adding a service must stay within the limit.
    #[test]
    fn policy_fits_the_get_scoped_credentials_limit() {
        let len = agent_scope_down_policy().chars().count();
        assert!(
            len <= SCOPE_DOWN_POLICY_MAX_CHARS,
            "scope-down policy is {len} characters, limit is {SCOPE_DOWN_POLICY_MAX_CHARS}"
        );
    }

    #[test]
    fn policy_is_a_single_allow_statement_over_all_resources() {
        let policy: serde_json::Value = serde_json::from_str(&agent_scope_down_policy()).unwrap();
        let statements = policy["Statement"].as_array().unwrap();
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0]["Effect"], "Allow");
        assert_eq!(statements[0]["Resource"], "*");
        assert!(statements[0].get("NotAction").is_none());
    }

    /// Every action is service-prefixed and none is a service-wide or
    /// write-shaped wildcard.
    #[test]
    fn policy_allows_only_read_shaped_actions() {
        const WRITE_PREFIXES: &[&str] = &[
            "Create",
            "Delete",
            "Put",
            "Update",
            "Modify",
            "Terminate",
            "Run",
            "Attach",
            "Detach",
            "Assume",
            "Send",
            "Publish",
            "Invoke",
            "Tag",
            "Untag",
            "Set",
            "Write",
            "Decrypt",
        ];
        for action in policy_actions() {
            let (service, verb) = action.split_once(':').unwrap();
            assert!(!service.is_empty() && !service.contains('*'), "{action}");
            assert!(!verb.is_empty() && !verb.starts_with('*'), "{action}");
            assert!(
                !WRITE_PREFIXES.iter().any(|w| verb.starts_with(w)),
                "{action} is not a read action"
            );
        }
    }

    #[test]
    fn policy_withholds_secret_values_and_decryption() {
        let actions = policy_actions();
        assert!(!actions.iter().any(|a| a == "secretsmanager:Get*"));
        assert!(!actions.iter().any(|a| a.starts_with("kms:Decrypt")));
        assert!(!actions.iter().any(|a| a.starts_with("sts:Assume")));
    }
}
