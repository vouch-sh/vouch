// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Read-only restriction for AI-agent credentials that were not minted
//! through an `AssumeRole*` call.
//!
//! On the role chain an agent's credentials carry the AWS managed
//! [`AGENT_MANAGED_POLICY`] as a session policy. Identity Center
//! permission-set credentials come from `GetRoleCredentials`, which takes no
//! session policy, so they are narrowed afterwards with AWS STS
//! `GetScopedCredentials`.
//!
//! That API takes an inline `Policy` of at most 2,048 characters and no
//! managed policy ARNs, so [`agent_scope_down_policy`] approximates
//! `ReadOnlyAccess` instead of naming it. When `GetScopedCredentials` accepts
//! a managed policy ARN, pass `ReadOnlyAccess` there and delete the
//! approximation, so both paths grant exactly the same actions.
//!
//! The approximation was built from `ReadOnlyAccess` v192 and the AWS
//! service reference data, which classifies every action as read, list,
//! write, permissions management, or tagging:
//!
//! - **Allow** the action-name verbs `ReadOnlyAccess` uses, on every
//!   service, keeping only verbs whose matches AWS classifies as read or
//!   list (a handful of exceptions are covered below). Verbs that also
//!   match writes on some service (`Check*` matches
//!   `license-manager:CheckoutLicense`, `Is*` matches
//!   `acm-pca:IssueCertificate`, `Retrieve*`, `Test*`, `Generate*`) are left
//!   out, so this policy is narrower than `ReadOnlyAccess` there.
//! - **Deny** reads that return a secret, a token, credentials, or a
//!   presigned URL, by name pattern so actions AWS adds later are covered
//!   too. This also denies some that `ReadOnlyAccess` allows, such as
//!   `ecr:GetAuthorizationToken` and `cognito-identity:GetCredentialsForIdentity`.
//!
//! `kms:Decrypt` matches no allowed verb, as in `ReadOnlyAccess`. That does
//! not make `SecureString` parameters unreadable: the AWS managed `aws/ssm`
//! key grants decryption to every principal in the account, and
//! `ssm:GetParameter` is allowed here as it is in `ReadOnlyAccess`.
//!
//! AWS documents wildcards in the action name, after the colon; whether a
//! wildcard service prefix is accepted is not stated. If AWS rejects the
//! policy the agent is refused — it never receives more than the policy
//! allows.
//!
//! <https://docs.aws.amazon.com/STS/latest/APIReference/API_GetScopedCredentials.html>
//! <https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ReadOnlyAccess.html>

use anyhow::Result;
use jiff::Timestamp;
use vouch_cli::tr;

use super::sts::{ScopedCredentialsRequest, StsCredentials, get_scoped_credentials};
use crate::exit_code::aws_access_denied;

/// The AWS managed policy an AI agent's role-chain credentials carry as a
/// session policy, and the policy [`agent_scope_down_policy`] approximates.
pub(crate) const AGENT_MANAGED_POLICY: &str = "ReadOnlyAccess";

/// Lifetime of an agent's scoped credentials, in seconds: the same hour the
/// role chain vends.
const AGENT_SESSION_SECONDS: u32 = 3600;

/// Headroom kept below the source session's expiry when choosing
/// `DurationSeconds`, so local clock skew cannot push the request past it
/// (AWS rejects that with `InsufficientSessionLifetime`).
const EXPIRY_MARGIN_SECONDS: i64 = 300;

/// Action-name patterns an AI agent keeps, on any service.
const AGENT_READ_ACTIONS: &[&str] = &[
    "*:Get*",
    "*:List*",
    "*:Describe*",
    "*:BatchGet*",
    "*:BatchDescribe*",
    "*:Search*",
    "*:Query*",
    "*:Scan*",
    "*:Lookup*",
    "*:Select*",
    "*:Filter*",
    "*:View*",
    "*:Simulate*",
    "*:Estimate*",
];

/// Reads denied even though [`AGENT_READ_ACTIONS`] matches them: anything
/// that returns a secret, a token, credentials, or a presigned URL, plus the
/// few matching actions AWS classifies as writes.
const AGENT_DENIED_ACTIONS: &[&str] = &[
    "*:Get*Token*",
    "*:Get*Credential*",
    "*:Get*Password*",
    "*:Get*Secret*",
    "*:BatchGet*Secret*",
    "*:Get*ApiKey*",
    "*:*StreamKey*",
    "*:Get*AuthCode*",
    "*:Get*AccessDetails*",
    "*:Get*PresignedUrl*",
    "*:Get*EmbedUrl*",
    "*:Get*LoginUrl*",
    "*:Get*DownloadUrl*",
    "*:Get*UploadUrl*",
    "*:Get*SessionUrl*",
    "*:Get*SessionEndpoint*",
    // Backup data plane: reads of backed-up data, classified as writes.
    "backup-storage:*",
    // Creates an identity in the pool.
    "cognito-identity:GetId",
    // Returns connection passwords.
    "glue:GetConnection*",
    // Vends temporary access to Lake Formation data.
    "lakeformation:GetDataAccess",
    // Copies media into S3.
    "social-messaging:GetWhatsAppMessageMedia",
    // Takes a task off the activity queue.
    "states:GetActivityTask",
];

/// The scope-down policy document applied to an AI agent's credentials.
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

/// `DurationSeconds` for an agent's scoped credentials: one hour when the
/// source session outlives it, otherwise `None` so the scoped session
/// inherits the source's shorter expiry. `GetScopedCredentials` cannot
/// extend a session.
fn agent_scoped_duration(source_expiration: Timestamp, now: Timestamp) -> Option<u32> {
    let remaining = source_expiration.duration_since(now).as_secs();
    let wanted = i64::from(AGENT_SESSION_SECONDS).saturating_add(EXPIRY_MARGIN_SECONDS);
    (remaining > wanted).then_some(AGENT_SESSION_SECONDS)
}

/// Narrow `credentials` to the agent read-only policy, capped at one hour.
///
/// `region` selects the regional STS endpoint; the credentials themselves
/// are not region-bound. `agent_source` is recorded in CloudTrail as the
/// scoped session's description. That is the only attribution available on
/// this path, because `GetScopedCredentials` keeps the permission set's
/// session tags but cannot add `vouch:AccessType` / `vouch:Agent`.
///
/// # Errors
///
/// Any failure means the agent gets no credentials. An access denial means
/// the permission set does not allow `sts:GetScopedCredentials`, and the
/// error says so.
pub(crate) async fn scope_credentials_for_agent(
    http_client: &reqwest::Client,
    region: &str,
    credentials: &StsCredentials,
    agent_source: &str,
) -> Result<StsCredentials> {
    tracing::info!("AI agent detected ({agent_source}), applying read-only scope-down policy");
    #[expect(
        clippy::disallowed_methods,
        reason = "compares against an expiry AWS just returned; no request clock exists in the CLI"
    )]
    let now = Timestamp::now();
    let policy = agent_scope_down_policy();
    get_scoped_credentials(ScopedCredentialsRequest {
        http_client,
        region,
        source_creds: credentials,
        policy: &policy,
        duration_seconds: agent_scoped_duration(credentials.expiration, now),
        description: &format!("vouch AI agent: {agent_source}"),
    })
    .await
    .map_err(|err| {
        if aws_access_denied(&err) {
            err.context(tr!("aws-err-agent-scope-down-denied"))
        } else {
            err.context(tr!("aws-err-agent-scope-down-failed"))
        }
    })
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

    fn actions(effect: &str) -> Vec<String> {
        let policy: serde_json::Value = serde_json::from_str(&agent_scope_down_policy()).unwrap();
        let statements = policy["Statement"].as_array().unwrap();
        assert_eq!(statements.len(), 2);
        let statement = statements.iter().find(|s| s["Effect"] == effect).unwrap();
        assert_eq!(statement["Resource"], "*");
        assert!(statement.get("NotAction").is_none());
        statement["Action"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_string())
            .collect()
    }

    /// IAM action matching: `*` matches any run of characters, and "the
    /// prefix and the action name are case insensitive".
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html>
    fn iam_match(pattern: &str, action: &str) -> bool {
        fn glob(p: &[u8], a: &[u8]) -> bool {
            match p.split_first() {
                None => a.is_empty(),
                Some((b'*', rest)) => (0..=a.len()).any(|i| glob(rest, &a[i..])),
                Some((c, rest)) => a
                    .split_first()
                    .is_some_and(|(d, tail)| c.eq_ignore_ascii_case(d) && glob(rest, tail)),
            }
        }
        glob(pattern.as_bytes(), action.as_bytes())
    }

    /// Evaluate the policy for one action: allowed by some Allow pattern and
    /// not matched by any Deny pattern (an explicit deny always wins).
    fn agent_may(action: &str) -> bool {
        actions("Allow").iter().any(|p| iam_match(p, action))
            && !actions("Deny").iter().any(|p| iam_match(p, action))
    }

    /// AWS rejects a longer `Policy`, which would refuse every agent.
    #[test]
    fn policy_fits_the_get_scoped_credentials_limit() {
        let len = agent_scope_down_policy().chars().count();
        assert!(
            len <= SCOPE_DOWN_POLICY_MAX_CHARS,
            "scope-down policy is {len} characters, limit is {SCOPE_DOWN_POLICY_MAX_CHARS}"
        );
    }

    #[test]
    fn iam_match_follows_iam_wildcard_rules() {
        assert!(iam_match("*:Get*", "s3:GetObject"));
        assert!(iam_match("*:Get*", "apigateway:GET"));
        assert!(iam_match("*:Get*Token*", "ecr:GetAuthorizationToken"));
        assert!(iam_match("backup-storage:*", "backup-storage:GetChunk"));
        assert!(!iam_match("*:Get*", "s3:PutObject"));
        assert!(!iam_match("*:Get*", "s3:BatchGetObject"));
        assert!(!iam_match("glue:GetConnection*", "iot:GetConnection"));
    }

    /// Reads `ReadOnlyAccess` grants that agents rely on stay allowed.
    #[test]
    fn policy_keeps_read_only_access_reads() {
        for action in [
            "s3:GetObject",
            "s3:ListBucket",
            "ec2:DescribeInstances",
            "iam:GetRole",
            "dynamodb:BatchGetItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "logs:FilterLogEvents",
            "cloudtrail:LookupEvents",
            "config:SelectResourceConfig",
            "iam:SimulatePrincipalPolicy",
            "cloudformation:EstimateTemplateCost",
            "ssm:GetParameter",
            "lambda:GetFunction",
            "sqs:GetQueueUrl",
            "kms:DescribeKey",
            "sts:GetCallerIdentity",
        ] {
            assert!(agent_may(action), "{action} should be allowed");
        }
    }

    /// Nothing that changes state is allowed.
    #[test]
    fn policy_refuses_writes() {
        for action in [
            "s3:PutObject",
            "s3:DeleteObject",
            "ec2:RunInstances",
            "ec2:StartInstances",
            "iam:CreateUser",
            "iam:PassRole",
            "lambda:InvokeFunction",
            "sqs:ReceiveMessage",
            "kms:Decrypt",
            "sts:AssumeRole",
            "sts:TagSession",
            "acm-pca:IssueCertificate",
            "license-manager:CheckoutLicense",
            "states:GetActivityTask",
            "cognito-identity:GetId",
        ] {
            assert!(!agent_may(action), "{action} should be refused");
        }
    }

    /// Reads that return a secret, token, credentials, or presigned URL are
    /// refused. Each name is from the AWS Service Authorization Reference.
    #[test]
    fn policy_refuses_secret_and_credential_reads() {
        for action in [
            "secretsmanager:GetSecretValue",
            "secretsmanager:BatchGetSecretValue",
            "ecr:GetAuthorizationToken",
            "ecr-public:GetAuthorizationToken",
            "codeartifact:GetAuthorizationToken",
            "sts:GetServiceBearerToken",
            "sts:GetWebIdentityToken",
            "sts:GetDelegatedAccessToken",
            "sts:GetFederationToken",
            "sts:GetSessionToken",
            "redshift:GetClusterCredentials",
            "redshift:GetClusterCredentialsWithIAM",
            "redshift:GetIdentityCenterAuthToken",
            "redshift-serverless:GetCredentials",
            "cognito-identity:GetCredentialsForIdentity",
            "cognito-identity:GetOpenIdToken",
            "connect:GetFederationToken",
            "ec2:GetPasswordData",
            "lightsail:GetInstanceAccessDetails",
            "lightsail:GetRelationalDatabaseMasterUserPassword",
            "elasticmapreduce:GetClusterSessionCredentials",
            "elasticmapreduce:GetPersistentAppUIPresignedURL",
            "datazone:GetEnvironmentCredentials",
            "lakeformation:GetDataAccess",
            "lakeformation:GetTemporaryGlueTableCredentials",
            "bedrock-agentcore:GetResourceOauth2Token",
            "bedrock-agentcore:GetResourceApiKey",
            "bedrock-agentcore:GetWorkloadAccessToken",
            "wafv2:GetDecryptedAPIKey",
            "ivs:GetStreamKey",
            "ivs:BatchGetStreamKey",
            "quicksight:GetDashboardEmbedUrl",
            "quicksight:GetAuthCode",
            "cloudshell:GetFileDownloadUrls",
            "kinesisvideo:GetHLSStreamingSessionURL",
            "glue:GetConnection",
            "glue:GetConnections",
            "backup-storage:GetChunk",
        ] {
            assert!(!agent_may(action), "{action} should be refused");
        }
    }

    #[test]
    fn duration_is_one_hour_when_the_source_session_outlives_it() {
        let now: Timestamp = "2026-11-20T12:00:00Z".parse().unwrap();
        let in_12h: Timestamp = "2026-11-21T00:00:00Z".parse().unwrap();
        assert_eq!(agent_scoped_duration(in_12h, now), Some(3600));
    }

    /// API_GetScopedCredentials, InsufficientSessionLifetime: "The request
    /// was rejected because the requested DurationSeconds is greater than the
    /// remaining lifetime of the calling session."
    #[test]
    fn duration_is_inherited_when_the_source_session_is_shorter() {
        let now: Timestamp = "2026-11-20T12:00:00Z".parse().unwrap();
        // A default one-hour permission set, already a few seconds old.
        let in_59m: Timestamp = "2026-11-20T12:59:50Z".parse().unwrap();
        assert_eq!(agent_scoped_duration(in_59m, now), None);
        // Inside the margin.
        let in_62m: Timestamp = "2026-11-20T13:02:00Z".parse().unwrap();
        assert_eq!(agent_scoped_duration(in_62m, now), None);
        // Already expired by the local clock.
        let past: Timestamp = "2026-11-20T11:00:00Z".parse().unwrap();
        assert_eq!(agent_scoped_duration(past, now), None);
    }
}
