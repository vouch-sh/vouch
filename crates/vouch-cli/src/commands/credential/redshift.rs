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
use secrecy::{ExposeSecret, SecretString};
use vouch_cli::tr;

use crate::commands::credential::aws::{
    StsRequest, detect_agent_source, exchange_for_sts_credentials,
};
use crate::commands::credential::cache;
use crate::integrations::aws;
use crate::integrations::aws::redshift::{
    RedshiftCredentials, get_cluster_credentials, get_serverless_credentials,
};
use crate::integrations::aws::sigv4::validate_sigv4_input;
use crate::server_url::ServerUrl;

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
    server: &ServerUrl,
    target: RedshiftTarget<'_>,
    db_name: Option<&str>,
    region: Option<&str>,
    role: Option<&str>,
) -> Result<()> {
    let creds = fetch_cached_redshift_credentials(server, &target, db_name, region, role).await?;
    let json = serde_json::to_string(&credentials_json(&creds))
        .context(tr!("err-failed-serialize-redshift-credentials"))?;
    // Machine-readable JSON output: stays English (consumed by Redshift driver).
    println!("{json}");
    Ok(())
}

/// Fetch Redshift credentials through the credential cache, resolving the
/// role and region first. Shared by `credential redshift` and `exec`/`env`.
pub(crate) async fn fetch_cached_redshift_credentials(
    server: &ServerUrl,
    target: &RedshiftTarget<'_>,
    db_name: Option<&str>,
    region: Option<&str>,
    role: Option<&str>,
) -> Result<RedshiftCredentials> {
    match target {
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

    let (role_arn, region_name) = aws::resolve_role_and_region(role, region, None)?;

    // Detect agent context BEFORE the cache lookup. Folding the source into
    // the cache key ensures agent and non-agent invocations never share a
    // cached entry, which would otherwise hand the agent credentials minted
    // without ReadOnlyAccess / `vouch:AccessType=ai` tags (issue #426).
    let agent = detect_agent_source();
    let key = cache_key(target, db_name, &region_name, &role_arn, agent.as_deref());
    let data = cache::get_or_fetch(&key, "Redshift credentials", || async {
        let creds = fetch_redshift_credentials(
            server,
            target,
            db_name,
            &region_name,
            &role_arn,
            agent.as_deref(),
        )
        .await?;
        Ok((credentials_json(&creds), creds.expiration.clone()))
    })
    .await?;

    let field = |name: &str| {
        data.get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .context(tr!("err-cached-redshift-credentials-malformed"))
    };
    Ok(RedshiftCredentials {
        db_user: field("DbUser")?,
        db_password: SecretString::from(field("DbPassword")?),
        expiration: field("Expiration")?,
    })
}

/// The JSON shape `credential redshift` prints and the cache stores.
fn credentials_json(creds: &RedshiftCredentials) -> serde_json::Value {
    serde_json::json!({
        "DbUser": creds.db_user,
        "DbPassword": creds.db_password.expose_secret(),
        "Expiration": creds.expiration,
    })
}

/// The credential cache key. Every input that changes the minted credentials
/// is part of it: the target, database, duration, region, role, and agent.
fn cache_key(
    target: &RedshiftTarget<'_>,
    db_name: Option<&str>,
    region: &str,
    role_arn: &str,
    agent: Option<&str>,
) -> String {
    let agent_suffix = agent.map_or(String::new(), |src| format!(":agent:{src}"));
    let db = db_name.unwrap_or_default();
    match target {
        RedshiftTarget::Cluster {
            cluster_id,
            duration,
        } => {
            let duration = duration.unwrap_or(DEFAULT_DURATION_SECONDS);
            format!("redshift:{cluster_id}:{db}:{duration}:{region}:{role_arn}{agent_suffix}")
        }
        RedshiftTarget::Serverless { workgroup } => {
            format!("redshift-serverless:{workgroup}:{db}:{region}:{role_arn}{agent_suffix}")
        }
    }
}

/// Fetch Redshift credentials through the full Vouch → STS → Redshift flow.
///
/// Routes to the provisioned cluster or serverless API based on `target`.
async fn fetch_redshift_credentials(
    server: &ServerUrl,
    target: &RedshiftTarget<'_>,
    db_name: Option<&str>,
    region: &str,
    role_arn: &str,
    agent_source: Option<&str>,
) -> Result<RedshiftCredentials> {
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
            .context(tr!("err-failed-get-redshift-cluster-credentials"))
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
        .context(tr!("err-failed-get-redshift-serverless-credentials")),
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
            bail!(tr!("err-specify-either-cluster-id-or-workgroup-not-both"))
        }
        (None, None) => {
            bail!(tr!("err-specify-either-cluster-id-or-workgroup"))
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
        let output = credentials_json(&RedshiftCredentials {
            db_user: "IAMR:test-role".to_string(),
            db_password: SecretString::from("temp-password"),
            expiration: "2025-02-27T19:44:51.001Z".to_string(),
        });

        let obj = output.as_object().unwrap();
        assert_eq!(obj.len(), 3);
        assert_eq!(obj["DbUser"], "IAMR:test-role");
        assert_eq!(obj["DbPassword"], "temp-password");
        assert_eq!(obj["Expiration"], "2025-02-27T19:44:51.001Z");
    }

    const ROLE: &str = "arn:aws:iam::123456789012:role/MyRole";
    const CLUSTER: RedshiftTarget<'static> = RedshiftTarget::Cluster {
        cluster_id: "my-cluster",
        duration: None,
    };
    const SERVERLESS: RedshiftTarget<'static> = RedshiftTarget::Serverless {
        workgroup: "my-workgroup",
    };

    #[test]
    fn test_cluster_cache_key_format() {
        assert_eq!(
            cache_key(&CLUSTER, Some("dev"), "us-east-1", ROLE, None),
            format!("redshift:my-cluster:dev:900:us-east-1:{ROLE}")
        );
    }

    #[test]
    fn test_serverless_cache_key_format() {
        assert_eq!(
            cache_key(&SERVERLESS, None, "us-east-1", ROLE, None),
            format!("redshift-serverless:my-workgroup::us-east-1:{ROLE}")
        );
    }

    /// Credentials minted for one database, duration, or region are not
    /// reused for another.
    #[test]
    fn test_cache_key_differs_by_request_parameters() {
        let base = cache_key(&CLUSTER, Some("a"), "us-east-1", ROLE, None);
        assert_ne!(
            base,
            cache_key(&CLUSTER, Some("b"), "us-east-1", ROLE, None)
        );
        assert_ne!(base, cache_key(&CLUSTER, None, "us-east-1", ROLE, None));
        assert_ne!(
            base,
            cache_key(&CLUSTER, Some("a"), "us-west-2", ROLE, None)
        );
        let longer = RedshiftTarget::Cluster {
            cluster_id: "my-cluster",
            duration: Some(3600),
        };
        assert_ne!(base, cache_key(&longer, Some("a"), "us-east-1", ROLE, None));
        assert_ne!(
            cache_key(&SERVERLESS, Some("a"), "us-east-1", ROLE, None),
            cache_key(&SERVERLESS, Some("b"), "us-east-1", ROLE, None)
        );
    }

    /// Agent and non-agent invocations must never share a cached entry —
    /// issue #426. The agent invocation receives `ReadOnlyAccess` plus
    /// `vouch:AccessType=ai` tags; a cache hit on a non-agent entry would
    /// silently hand back full-access credentials.
    #[test]
    fn test_cache_key_differs_when_agent_detected() {
        for target in [&CLUSTER, &SERVERLESS] {
            assert_ne!(
                cache_key(target, None, "us-east-1", ROLE, None),
                cache_key(target, None, "us-east-1", ROLE, Some("claude-code"))
            );
        }
    }

    #[test]
    fn test_cache_key_differs_between_agents() {
        assert_ne!(
            cache_key(&CLUSTER, None, "us-east-1", ROLE, Some("claude-code")),
            cache_key(&CLUSTER, None, "us-east-1", ROLE, Some("cursor"))
        );
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
