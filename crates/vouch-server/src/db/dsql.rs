// SPDX-License-Identifier: BUSL-1.1
//! Aurora DSQL authentication token generation.
//!
//! This module provides functions for connecting to Aurora DSQL clusters
//! using IAM-based authentication. DSQL uses short-lived (15 minute default)
//! presigned URL tokens for authentication instead of static passwords.
//!
//! # Credential Chain
//!
//! The AWS SDK automatically tries credentials in this order:
//! 1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
//! 2. AWS profile files (`~/.aws/credentials`, `~/.aws/config`)
//! 3. Web identity token (EKS IRSA via `AWS_WEB_IDENTITY_TOKEN_FILE`)
//! 4. ECS container credentials (via `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`)
//! 5. EC2 instance metadata (IMDS)

use anyhow::Result;
use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_sdk_dsql::auth_token::{AuthTokenGenerator, Config};

/// Load AWS SDK config with credential chain support.
///
/// This function loads AWS credentials using the standard credential chain,
/// which supports environment variables, AWS profiles, EKS IRSA, ECS task roles,
/// and EC2 instance metadata.
///
/// # Arguments
///
/// * `region` - Optional AWS region override. If not provided, the SDK will
///   attempt to determine the region from environment variables or config files.
pub async fn load_sdk_config(region: Option<&str>) -> SdkConfig {
    let mut loader = aws_config::defaults(BehaviorVersion::latest());
    if let Some(r) = region {
        loader = loader.region(Region::new(r.to_string()));
    }
    loader.load().await
}

/// Generate a DSQL authentication token using AWS credentials.
///
/// DSQL authentication tokens are SigV4 presigned URLs that grant temporary
/// access to the database. Tokens are valid for 15 minutes by default.
///
/// # Arguments
///
/// * `sdk_config` - AWS SDK configuration with loaded credentials
/// * `cluster_endpoint` - DSQL cluster hostname (e.g., `cluster-id.dsql.us-east-1.on.aws`)
/// * `region` - AWS region where the cluster is located
/// * `is_admin` - If true, generates an admin token (`DbConnectAdmin` action);
///   otherwise generates a regular user token (`DbConnect` action)
///
/// # Errors
///
/// Returns an error if token generation fails, typically due to missing or
/// invalid AWS credentials.
pub async fn generate_dsql_token(
    sdk_config: &SdkConfig,
    cluster_endpoint: &str,
    region: &str,
    is_admin: bool,
) -> Result<String> {
    let config = Config::builder()
        .hostname(cluster_endpoint)
        .region(Region::new(region.to_string()))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build DSQL auth token config: {e}"))?;

    let signer = AuthTokenGenerator::new(config);

    let token = if is_admin {
        signer
            .db_connect_admin_auth_token(sdk_config)
            .await
            .map_err(|e| anyhow::anyhow!("failed to generate admin DSQL token: {e}"))?
    } else {
        signer
            .db_connect_auth_token(sdk_config)
            .await
            .map_err(|e| anyhow::anyhow!("failed to generate DSQL token: {e}"))?
    };

    Ok(token.to_string())
}

/// Extract AWS region from a DSQL endpoint hostname.
///
/// DSQL endpoints follow the format: `cluster-id.dsql.REGION.on.aws`
///
/// # Arguments
///
/// * `endpoint` - The DSQL cluster endpoint hostname
///
/// # Returns
///
/// The AWS region if the endpoint matches the expected format, or `None` otherwise.
///
/// # Example
///
/// ```
/// use vouch_server::db::dsql::extract_region_from_endpoint;
///
/// let region = extract_region_from_endpoint("abc123.dsql.us-east-1.on.aws");
/// assert_eq!(region, Some("us-east-1"));
/// ```
pub fn extract_region_from_endpoint(endpoint: &str) -> Option<&str> {
    let parts: Vec<&str> = endpoint.split('.').collect();
    // Expected format: cluster-id.dsql.REGION.on.aws (5 parts)
    if parts.len() >= 5 && parts.get(1) == Some(&"dsql") && parts.get(4) == Some(&"aws") {
        parts.get(2).copied()
    } else {
        None
    }
}

/// Check if a hostname is a DSQL endpoint.
///
/// DSQL endpoints contain `.dsql.` and end with `.on.aws`.
///
/// # Arguments
///
/// * `host` - The hostname to check
///
/// # Returns
///
/// `true` if the hostname appears to be a DSQL endpoint.
pub fn is_dsql_endpoint(host: &str) -> bool {
    host.contains(".dsql.") && host.ends_with(".on.aws")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_region_from_endpoint() {
        assert_eq!(
            extract_region_from_endpoint("abc123.dsql.us-east-1.on.aws"),
            Some("us-east-1")
        );
        assert_eq!(
            extract_region_from_endpoint("xyz789.dsql.eu-west-2.on.aws"),
            Some("eu-west-2")
        );
        assert_eq!(
            extract_region_from_endpoint("cluster.dsql.ap-southeast-1.on.aws"),
            Some("ap-southeast-1")
        );
    }

    #[test]
    fn test_extract_region_from_endpoint_invalid() {
        // Standard PostgreSQL hostname
        assert_eq!(extract_region_from_endpoint("localhost"), None);
        assert_eq!(extract_region_from_endpoint("db.example.com"), None);
        // RDS endpoint (not DSQL)
        assert_eq!(
            extract_region_from_endpoint("mydb.abc123.us-east-1.rds.amazonaws.com"),
            None
        );
        // Missing parts
        assert_eq!(extract_region_from_endpoint("dsql.us-east-1.on.aws"), None);
    }

    #[test]
    fn test_is_dsql_endpoint() {
        assert!(is_dsql_endpoint("abc123.dsql.us-east-1.on.aws"));
        assert!(is_dsql_endpoint("xyz.dsql.eu-west-2.on.aws"));
    }

    #[test]
    fn test_is_dsql_endpoint_false() {
        assert!(!is_dsql_endpoint("localhost"));
        assert!(!is_dsql_endpoint("db.example.com"));
        assert!(!is_dsql_endpoint("mydb.abc123.us-east-1.rds.amazonaws.com"));
        // Has dsql but wrong suffix
        assert!(!is_dsql_endpoint("abc123.dsql.us-east-1.amazonaws.com"));
        // Has on.aws but no dsql
        assert!(!is_dsql_endpoint("abc123.on.aws"));
    }
}
