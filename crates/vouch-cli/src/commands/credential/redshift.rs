// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Redshift credential command.
//!
//! Generates temporary Redshift database credentials using
//! `GetClusterCredentialsWithIAM`. This eliminates the need for
//! `aws redshift get-cluster-credentials` as a runtime dependency.
//!
//! Protocol:
//! 1. Exchange Vouch session for STS credentials (OIDC → STS)
//! 2. Call Redshift `GetClusterCredentialsWithIAM` with SigV4 signing
//! 3. Output JSON with DbUser, DbPassword, and Expiration to stdout

use anyhow::{Context, Result};
use secrecy::ExposeSecret;

use crate::commands::credential::aws::exchange_for_sts_credentials;
use crate::commands::credential::cache;
use crate::integrations::aws;
use crate::integrations::aws::redshift::get_cluster_credentials;
use crate::integrations::aws::sigv4::validate_sigv4_input;

/// Default duration for Redshift temporary credentials (seconds).
const DEFAULT_DURATION_SECONDS: u32 = 900;

/// Run the Redshift credential command.
///
/// Outputs JSON with `DbUser`, `DbPassword`, and `Expiration` to stdout.
pub async fn run(
    server: &str,
    cluster_id: &str,
    db_name: Option<&str>,
    region: Option<&str>,
    role: Option<&str>,
    duration: Option<u32>,
) -> Result<()> {
    validate_sigv4_input(cluster_id, "cluster ID")?;
    if let Some(name) = db_name {
        validate_sigv4_input(name, "database name")?;
    }

    // Resolve role ARN from flag or local AWS config
    let role_arn = match role {
        Some(r) => r.to_string(),
        None => aws::get_local_aws_role().ok_or_else(|| {
            anyhow::anyhow!(
                "AWS not configured. Run 'vouch setup aws --role <role-arn>' \
                 first, or specify --role."
            )
        })?,
    };

    // Resolve region
    let profile_name = aws::resolve_profile(None).unwrap_or_default();
    let region_name = aws::resolve_region(region, &profile_name)?;

    let duration_seconds = duration.unwrap_or(DEFAULT_DURATION_SECONDS);

    let cache_key = format!("redshift:{cluster_id}:{role_arn}");

    let data = cache::get_or_fetch(&cache_key, "Redshift credentials", || async {
        let creds = fetch_redshift_credentials(
            server,
            cluster_id,
            db_name,
            &region_name,
            &role_arn,
            duration_seconds,
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
async fn fetch_redshift_credentials(
    server: &str,
    cluster_id: &str,
    db_name: Option<&str>,
    region: &str,
    role_arn: &str,
    duration_seconds: u32,
) -> Result<crate::integrations::aws::redshift::RedshiftCredentials> {
    let result = exchange_for_sts_credentials(server, role_arn, region, "vouch-redshift").await?;

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
    .context("failed to get Redshift credentials")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    #[test]
    fn test_default_duration() {
        assert_eq!(super::DEFAULT_DURATION_SECONDS, 900);
        // Verify within AWS limits: 900-3600
        const {
            assert!(super::DEFAULT_DURATION_SECONDS >= 900);
            assert!(super::DEFAULT_DURATION_SECONDS <= 3600);
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

    #[test]
    fn test_redshift_cache_key_format() {
        let cluster_id = "my-cluster";
        let role_arn = "arn:aws:iam::123456789012:role/MyRole";
        let key = format!("redshift:{cluster_id}:{role_arn}");
        assert_eq!(
            key,
            "redshift:my-cluster:arn:aws:iam::123456789012:role/MyRole"
        );
    }
}
