// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Redshift credential command.
//!
//! Generates temporary Redshift database credentials for both provisioned
//! clusters (`GetClusterCredentialsWithIAM`) and Redshift Serverless
//! workgroups (`GetCredentials`).
//!
//! Protocol:
//! 1. Exchange Vouch session for STS credentials (OIDC → STS)
//! 2. Call the appropriate Redshift API with SigV4 signing
//! 3. Output JSON with DbUser, DbPassword, and Expiration to stdout

use anyhow::{Context, Result, bail};
use secrecy::ExposeSecret;

use crate::commands::credential::aws::{StsRequest, exchange_for_sts_credentials};
use crate::commands::credential::cache;
use crate::integrations::aws;
use crate::integrations::aws::redshift::{get_cluster_credentials, get_serverless_credentials};
use crate::integrations::aws::sigv4::validate_sigv4_input;

/// Default duration for Redshift temporary credentials (seconds).
const DEFAULT_DURATION_SECONDS: u32 = 900;

/// Which Redshift target to fetch credentials for.
#[derive(Debug)]
pub(crate) enum RedshiftTarget<'a> {
    /// Provisioned cluster, identified by cluster ID.
    Cluster {
        cluster_id: &'a str,
        duration: Option<u32>,
    },
    /// Serverless workgroup, identified by workgroup name.
    Serverless { workgroup: &'a str },
}

/// Run the Redshift credential command.
///
/// Outputs JSON with `DbUser`, `DbPassword`, and `Expiration` to stdout.
pub(crate) async fn run(
    server: &str,
    target: RedshiftTarget<'_>,
    db_name: Option<&str>,
    region: Option<&str>,
    role: Option<&str>,
) -> Result<()> {
    // Validate inputs
    match &target {
        RedshiftTarget::Cluster { cluster_id, .. } => {
            validate_sigv4_input(cluster_id, "cluster ID")?;
        }
        RedshiftTarget::Serverless { workgroup } => {
            validate_sigv4_input(workgroup, "workgroup name")?;
        }
    }
    if let Some(name) = db_name {
        validate_sigv4_input(name, "database name")?;
    }

    let (role_arn, region_name) = aws::resolve_role_and_region(role, region)?;

    // Detect agent context BEFORE the cache lookup. Folding the source into
    // the cache key ensures agent and non-agent invocations never share a
    // cached entry, which would otherwise hand the agent credentials minted
    // without ReadOnlyAccess / `vouch:AccessType=ai` tags (issue #426).
    let agent_source = crate::commands::credential::aws::detect_agent_source();
    let agent_suffix = agent_source
        .as_deref()
        .map_or(String::new(), |src| format!(":agent:{src}"));

    let cache_key = match &target {
        RedshiftTarget::Cluster { cluster_id, .. } => {
            format!("redshift:{cluster_id}:{role_arn}{agent_suffix}")
        }
        RedshiftTarget::Serverless { workgroup } => {
            format!("redshift-serverless:{workgroup}:{role_arn}{agent_suffix}")
        }
    };

    let agent = agent_source;
    let data = cache::get_or_fetch(&cache_key, "Redshift credentials", || async {
        let creds = fetch_redshift_credentials(
            server,
            &target,
            db_name,
            &region_name,
            &role_arn,
            agent.as_deref(),
        )
        .await?;

        let expires_at = creds.expiration.clone();
        let output = serde_json::json!({
            "DbUser": creds.db_user,
            "DbPassword": creds.db_password.expose_secret(),
            "Expiration": creds.expiration,
        });

        Ok((output, expires_at))
    })
    .await?;

    let json = serde_json::to_string(&data).context("failed to serialize Redshift credentials")?;
    println!("{json}");
    Ok(())
}

/// Fetch Redshift credentials through the full Vouch → STS → Redshift flow.
///
/// Routes to the provisioned cluster or serverless API based on `target`.
pub(crate) async fn fetch_redshift_credentials(
    server: &str,
    target: &RedshiftTarget<'_>,
    db_name: Option<&str>,
    region: &str,
    role_arn: &str,
    agent_source: Option<&str>,
) -> Result<crate::integrations::aws::redshift::RedshiftCredentials> {
    let result = exchange_for_sts_credentials(StsRequest {
        server,
        role_arn,
        region,
        management_role: None,
        agent_source,
    })
    .await?;

    match target {
        RedshiftTarget::Cluster {
            cluster_id,
            duration,
        } => {
            let duration_seconds = duration.unwrap_or(DEFAULT_DURATION_SECONDS);
            get_cluster_credentials(
                &result.http_client,
                cluster_id,
                db_name,
                Some(duration_seconds),
                region,
                result.domain_suffix,
                &result.credentials,
            )
            .await
            .context("failed to get Redshift cluster credentials")
        }
        RedshiftTarget::Serverless { workgroup } => get_serverless_credentials(
            &result.http_client,
            workgroup,
            db_name,
            region,
            result.domain_suffix,
            &result.credentials,
        )
        .await
        .context("failed to get Redshift Serverless credentials"),
    }
}

/// Build a `RedshiftTarget` from CLI arguments.
///
/// Exactly one of `cluster_id` or `workgroup` must be `Some`.
pub(crate) fn resolve_target<'a>(
    cluster_id: Option<&'a str>,
    workgroup: Option<&'a str>,
    duration: Option<u32>,
) -> Result<RedshiftTarget<'a>> {
    match (cluster_id, workgroup) {
        (Some(id), None) => Ok(RedshiftTarget::Cluster {
            cluster_id: id,
            duration,
        }),
        (None, Some(wg)) => Ok(RedshiftTarget::Serverless { workgroup: wg }),
        (Some(_), Some(_)) => {
            bail!("specify either --cluster-id or --workgroup, not both")
        }
        (None, None) => {
            bail!("specify either --cluster-id or --workgroup")
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_default_duration() {
        assert_eq!(DEFAULT_DURATION_SECONDS, 900);
        // Verify within AWS limits: 900-3600
        const {
            assert!(DEFAULT_DURATION_SECONDS >= 900);
            assert!(DEFAULT_DURATION_SECONDS <= 3600);
        }
    }

    #[test]
    fn test_output_json_shape() {
        let output = serde_json::json!({
            "DbUser": "IAMR:test-role",
            "DbPassword": "temp-password",
            "Expiration": "2025-02-27T19:44:51.001Z",
        });

        let obj = output.as_object().unwrap();
        assert_eq!(obj.len(), 3);
        assert!(obj.contains_key("DbUser"));
        assert!(obj.contains_key("DbPassword"));
        assert!(obj.contains_key("Expiration"));
    }

    /// Mirror the cache-key construction in `run()` so we can lock in the
    /// invariant that agent and non-agent invocations land on different keys.
    fn build_redshift_cache_key(
        target: &RedshiftTarget<'_>,
        role_arn: &str,
        agent: Option<&str>,
    ) -> String {
        let agent_suffix = agent.map_or(String::new(), |src| format!(":agent:{src}"));
        match target {
            RedshiftTarget::Cluster { cluster_id, .. } => {
                format!("redshift:{cluster_id}:{role_arn}{agent_suffix}")
            }
            RedshiftTarget::Serverless { workgroup } => {
                format!("redshift-serverless:{workgroup}:{role_arn}{agent_suffix}")
            }
        }
    }

    #[test]
    fn test_cluster_cache_key_format() {
        let target = RedshiftTarget::Cluster {
            cluster_id: "my-cluster",
            duration: None,
        };
        let role_arn = "arn:aws:iam::123456789012:role/MyRole";
        assert_eq!(
            build_redshift_cache_key(&target, role_arn, None),
            "redshift:my-cluster:arn:aws:iam::123456789012:role/MyRole"
        );
    }

    #[test]
    fn test_serverless_cache_key_format() {
        let target = RedshiftTarget::Serverless {
            workgroup: "my-workgroup",
        };
        let role_arn = "arn:aws:iam::123456789012:role/MyRole";
        assert_eq!(
            build_redshift_cache_key(&target, role_arn, None),
            "redshift-serverless:my-workgroup:arn:aws:iam::123456789012:role/MyRole"
        );
    }

    /// Agent and non-agent invocations must never share a cached entry —
    /// issue #426. The agent invocation receives `ReadOnlyAccess` plus
    /// `vouch:AccessType=ai` tags; a cache hit on a non-agent entry would
    /// silently hand back full-access credentials.
    #[test]
    fn test_cluster_cache_key_differs_when_agent_detected() {
        let target = RedshiftTarget::Cluster {
            cluster_id: "my-cluster",
            duration: None,
        };
        let role_arn = "arn:aws:iam::123456789012:role/MyRole";
        let without = build_redshift_cache_key(&target, role_arn, None);
        let with = build_redshift_cache_key(&target, role_arn, Some("claude-code"));
        assert_ne!(without, with);
    }

    #[test]
    fn test_serverless_cache_key_differs_when_agent_detected() {
        let target = RedshiftTarget::Serverless {
            workgroup: "my-workgroup",
        };
        let role_arn = "arn:aws:iam::123456789012:role/MyRole";
        let without = build_redshift_cache_key(&target, role_arn, None);
        let with = build_redshift_cache_key(&target, role_arn, Some("claude-code"));
        assert_ne!(without, with);
    }

    #[test]
    fn test_cache_key_differs_between_agents() {
        let target = RedshiftTarget::Cluster {
            cluster_id: "my-cluster",
            duration: None,
        };
        let role_arn = "arn:aws:iam::123456789012:role/MyRole";
        let claude = build_redshift_cache_key(&target, role_arn, Some("claude-code"));
        let cursor = build_redshift_cache_key(&target, role_arn, Some("cursor"));
        assert_ne!(claude, cursor);
    }

    #[test]
    fn test_resolve_target_cluster() {
        let target = resolve_target(Some("my-cluster"), None, Some(1200)).unwrap();
        match target {
            RedshiftTarget::Cluster {
                cluster_id,
                duration,
            } => {
                assert_eq!(cluster_id, "my-cluster");
                assert_eq!(duration, Some(1200));
            }
            RedshiftTarget::Serverless { .. } => panic!("expected Cluster"),
        }
    }

    #[test]
    fn test_resolve_target_serverless() {
        let target = resolve_target(None, Some("my-wg"), None).unwrap();
        match target {
            RedshiftTarget::Serverless { workgroup } => {
                assert_eq!(workgroup, "my-wg");
            }
            RedshiftTarget::Cluster { .. } => panic!("expected Serverless"),
        }
    }

    #[test]
    fn test_resolve_target_both_fails() {
        let result = resolve_target(Some("id"), Some("wg"), None);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail")
                .to_string()
                .contains("not both")
        );
    }

    #[test]
    fn test_resolve_target_neither_fails() {
        let result = resolve_target(None, None, None);
        assert!(result.is_err());
    }
}
