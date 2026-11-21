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
//! managed policy ARNs, so `ReadOnlyAccess` cannot be named. It also rejects
//! any wildcard in an action's service prefix (`*:Get*` fails with
//! `MalformedPolicyDocument: Invalid service prefix for action '*:Get*'`,
//! in `Action` and `NotAction` alike), so a read-only policy has to name
//! each service, and only about 40 fit. [`agent_scope_down_policy`] covers
//! the most widely used services; on any other service an agent on a
//! permission set is refused, where the role chain would allow reads. When
//! `GetScopedCredentials` accepts a managed policy ARN, pass
//! `ReadOnlyAccess` there and delete this list, so both paths grant exactly
//! the same actions.
//!
//! For each listed service the policy grants only read patterns that
//! `ReadOnlyAccess` v192 grants that service, so it is never broader than the
//! role chain. The AWS service reference data classifies none of the
//! actions they match as a write. A few reads that return credentials are
//! denied even though `ReadOnlyAccess` allows them.
//!
//! `kms:Decrypt` is not allowed, as in `ReadOnlyAccess`. That does not make
//! `SecureString` parameters unreadable: the AWS managed `aws/ssm` key grants
//! decryption to every principal in the account, and `ssm:GetParameter` is
//! allowed here as it is in `ReadOnlyAccess`.
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

/// Actions an AI agent keeps on a permission set: for each listed service,
/// the read patterns `ReadOnlyAccess` grants it. Every entry names its
/// service; AWS rejects a wildcard prefix.
const AGENT_READ_ACTIONS: &[&str] = &[
    "acm:Describe*",
    "acm:Get*",
    "acm:List*",
    "application-autoscaling:Describe*",
    "autoscaling:Describe*",
    "cloudformation:Describe*",
    "cloudformation:Get*",
    "cloudformation:List*",
    "cloudfront:Describe*",
    "cloudfront:Get*",
    "cloudfront:List*",
    "cloudtrail:Describe*",
    "cloudtrail:Get*",
    "cloudtrail:List*",
    "cloudtrail:LookupEvents",
    "cloudwatch:Describe*",
    "cloudwatch:Get*",
    "cloudwatch:List*",
    "codebuild:BatchGet*",
    "codebuild:List*",
    "codepipeline:Get*",
    "codepipeline:List*",
    "config:Describe*",
    "config:Get*",
    "config:List*",
    "dynamodb:BatchGet*",
    "dynamodb:Describe*",
    "dynamodb:Get*",
    "dynamodb:List*",
    "dynamodb:Query",
    "dynamodb:Scan",
    "ec2:Describe*",
    "ec2:Get*",
    "ecr:BatchGet*",
    "ecr:Describe*",
    "ecr:Get*",
    "ecr:List*",
    "ecs:Describe*",
    "ecs:List*",
    "eks:Describe*",
    "eks:List*",
    "elasticache:Describe*",
    "elasticache:List*",
    "elasticloadbalancing:Describe*",
    "events:Describe*",
    "events:List*",
    "firehose:Describe*",
    "firehose:List*",
    "health:Describe*",
    "iam:Get*",
    "iam:List*",
    "kinesis:Describe*",
    "kinesis:Get*",
    "kinesis:List*",
    "kms:Describe*",
    "kms:Get*",
    "kms:List*",
    "lambda:Get*",
    "lambda:List*",
    "logs:Describe*",
    "logs:FilterLogEvents",
    "logs:Get*",
    "logs:StartQuery",
    "organizations:Describe*",
    "organizations:List*",
    "rds:Describe*",
    "rds:List*",
    "route53:Get*",
    "route53:List*",
    "s3:Get*",
    "s3:List*",
    "secretsmanager:Describe*",
    "secretsmanager:List*",
    "sns:Get*",
    "sns:List*",
    "sqs:Get*",
    "sqs:List*",
    "ssm:Describe*",
    "ssm:Get*",
    "ssm:List*",
    "sso:Describe*",
    "sso:Get*",
    "sso:List*",
    "states:Describe*",
    "states:List*",
    "tag:Get*",
    "xray:BatchGet*",
    "xray:Get*",
];

/// Reads [`AGENT_READ_ACTIONS`] matches that return credentials or a
/// password. `ReadOnlyAccess` allows them; an agent does not need them.
const AGENT_DENIED_ACTIONS: &[&str] = &[
    "acm:GetAcmeExternalAccountBindingCredentials",
    "cloudwatch:GetSpaceCredentials*",
    "ec2:GetPasswordData",
    "ecr:GetAuthorizationToken",
    "ssm:GetAccessToken",
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
            "ssm:GetParameter",
            "lambda:GetFunction",
            "sqs:GetQueueUrl",
            "kms:DescribeKey",
        ] {
            assert!(agent_may(action), "{action} should be allowed");
        }
    }

    /// AWS rejects a wildcard service prefix: `GetScopedCredentials`
    /// answered `*:Get*` with "MalformedPolicyDocument: Invalid service
    /// prefix for action '*:Get*'" when tested against a live account.
    #[test]
    fn every_pattern_names_its_service() {
        for action in actions("Allow").iter().chain(actions("Deny").iter()) {
            let (service, name) = action.split_once(':').unwrap();
            assert!(
                !service.is_empty()
                    && service
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{action} has no literal service prefix"
            );
            assert!(!name.is_empty(), "{action} has no action name");
        }
    }

    /// Services outside the list are refused, even for reads the role
    /// chain's `ReadOnlyAccess` allows.
    #[test]
    fn policy_refuses_unlisted_services() {
        for action in [
            "athena:GetQueryResults",
            "glue:GetTable",
            "bedrock:ListFoundationModels",
            "sagemaker:ListModels",
        ] {
            assert!(!agent_may(action), "{action} should be refused");
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
