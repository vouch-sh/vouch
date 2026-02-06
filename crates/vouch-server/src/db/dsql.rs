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

use anyhow::{Context, Result, bail};
use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_sdk_dsql::auth_token::{AuthTokenGenerator, Config};
use sqlx::postgres::PgSslMode;

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

// ============================================================================
// DsqlEndpoint enum
// ============================================================================

/// Parsed DSQL connection endpoint.
///
/// Models two connection modes for Aurora DSQL:
/// - **Direct**: connect directly to `cluster-id.dsql.region.on.aws`
/// - **VpcEndpoint**: connect via a PrivateLink VPC endpoint FQDN, with
///   IAM token generation against the cluster's public hostname
///
/// Use [`DsqlEndpoint::from_url`] to parse a database URL and determine
/// the connection type.
#[derive(Debug, Clone)]
pub enum DsqlEndpoint {
    /// Direct DSQL connection: `cluster-id.dsql.region.on.aws`
    Direct {
        /// The cluster endpoint hostname (used for both connection and token generation)
        hostname: String,
        /// AWS region extracted from the hostname
        region: String,
    },
    /// VPC PrivateLink connection: `vpce-xxx.dsql-svc.region.vpce.amazonaws.com`
    VpcEndpoint {
        /// The VPC endpoint FQDN (connect to this)
        hostname: String,
        /// AWS region extracted from the VPC endpoint hostname
        region: String,
        /// DSQL cluster ID (from `dsql_cluster_id` query parameter)
        cluster_id: String,
        /// Hostname for IAM token generation (e.g., `cluster_id.dsql.region.on.aws`)
        auth_hostname: String,
    },
}

impl DsqlEndpoint {
    /// Parse a database URL and determine if it's a DSQL endpoint.
    ///
    /// Returns `Ok(Some(DsqlEndpoint))` for DSQL URLs (direct or VPC endpoint),
    /// `Ok(None)` for non-DSQL postgres URLs, or `Err` if parsing fails.
    ///
    /// # VPC Endpoint Detection
    ///
    /// VPC endpoints match the pattern `*.vpce.amazonaws.com` and require a
    /// `dsql_cluster_id` query parameter in the URL. The DSQL service ID is
    /// extracted from the hostname (the segment containing `dsql`).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Direct DSQL
    /// let ep = DsqlEndpoint::from_url("postgres://admin@abc.dsql.us-east-1.on.aws/postgres")?;
    /// assert!(matches!(ep, Some(DsqlEndpoint::Direct { .. })));
    ///
    /// // VPC endpoint
    /// let url = "postgres://vouch@vpce-xxx.dsql-abc.us-east-1.vpce.amazonaws.com/postgres?dsql_cluster_id=abc";
    /// let ep = DsqlEndpoint::from_url(url)?;
    /// assert!(matches!(ep, Some(DsqlEndpoint::VpcEndpoint { .. })));
    ///
    /// // Plain postgres
    /// let ep = DsqlEndpoint::from_url("postgres://localhost/db")?;
    /// assert!(ep.is_none());
    /// ```
    pub fn from_url(url: &str) -> Result<Option<Self>> {
        let parsed = url::Url::parse(url).context("failed to parse database URL")?;
        let host = parsed.host_str().unwrap_or("");

        if is_dsql_endpoint(host) {
            // Direct DSQL: cluster-id.dsql.region.on.aws
            let region = extract_region_from_endpoint(host)
                .context("failed to extract region from DSQL endpoint")?;
            return Ok(Some(Self::Direct {
                hostname: host.to_string(),
                region: region.to_string(),
            }));
        }

        if is_vpc_endpoint(host) {
            // VPC PrivateLink endpoint
            let cluster_id = parsed
                .query_pairs()
                .find(|(k, _)| k == "dsql_cluster_id")
                .map(|(_, v)| v.to_string())
                .context(
                    "VPC endpoint URL requires a 'dsql_cluster_id' query parameter \
                     (e.g., ?dsql_cluster_id=your-cluster-id)",
                )?;

            if cluster_id.is_empty() {
                bail!("dsql_cluster_id query parameter must not be empty");
            }

            let region = extract_region_from_vpc_endpoint(host)
                .context("failed to extract region from VPC endpoint hostname")?;

            let service_id = extract_service_id_from_vpc_endpoint(host)
                .context("failed to extract DSQL service ID from VPC endpoint hostname")?;

            // Build the auth hostname: cluster_id.service_id.region.on.aws
            let auth_hostname = format!("{cluster_id}.{service_id}.{region}.on.aws");

            return Ok(Some(Self::VpcEndpoint {
                hostname: host.to_string(),
                region: region.to_string(),
                cluster_id,
                auth_hostname,
            }));
        }

        Ok(None)
    }

    /// The hostname to connect to.
    #[must_use]
    pub fn connect_hostname(&self) -> &str {
        match self {
            Self::Direct { hostname, .. } | Self::VpcEndpoint { hostname, .. } => hostname,
        }
    }

    /// The hostname to use for IAM token generation.
    ///
    /// For direct connections this is the same as `connect_hostname()`.
    /// For VPC endpoints this is the cluster's public hostname
    /// (e.g., `cluster_id.dsql.region.on.aws`).
    #[must_use]
    pub fn token_hostname(&self) -> &str {
        match self {
            Self::Direct { hostname, .. } => hostname,
            Self::VpcEndpoint { auth_hostname, .. } => auth_hostname,
        }
    }

    /// The AWS region for this DSQL endpoint.
    #[must_use]
    pub fn region(&self) -> &str {
        match self {
            Self::Direct { region, .. } | Self::VpcEndpoint { region, .. } => region,
        }
    }

    /// The SSL mode to use for the connection.
    ///
    /// Direct connections use `VerifyFull` for full certificate verification.
    /// VPC endpoints use `Require` because the VPC endpoint FQDN does not
    /// match the DSQL cluster's TLS certificate.
    #[must_use]
    pub fn ssl_mode(&self) -> PgSslMode {
        match self {
            Self::Direct { .. } => PgSslMode::VerifyFull,
            Self::VpcEndpoint { .. } => PgSslMode::Require,
        }
    }

    /// The DSQL cluster ID, if this is a VPC endpoint connection.
    #[must_use]
    pub fn cluster_id(&self) -> Option<&str> {
        match self {
            Self::Direct { .. } => None,
            Self::VpcEndpoint { cluster_id, .. } => Some(cluster_id),
        }
    }

    /// Connection options required for DSQL to identify the cluster.
    ///
    /// For VPC endpoints, returns the `amzn-cluster-id` key-value pair suitable
    /// for passing to `PgConnectOptions::options()`. For direct connections,
    /// returns `None`.
    #[must_use]
    pub fn pg_options(&self) -> Option<(&str, &str)> {
        match self {
            Self::Direct { .. } => None,
            Self::VpcEndpoint { cluster_id, .. } => Some(("amzn-cluster-id", cluster_id)),
        }
    }
}

/// Check if a hostname is a VPC PrivateLink endpoint.
///
/// VPC endpoints contain `.vpce.amazonaws.` in the hostname, covering all
/// AWS partitions (`.com`, `.com.cn`, etc.).
///
/// Examples:
/// - `vpce-xxx.dsql-fnh4.us-east-1.vpce.amazonaws.com` (standard)
/// - `vpce-xxx.dsql-fnh4.cn-north-1.vpce.amazonaws.com.cn` (China)
fn is_vpc_endpoint(host: &str) -> bool {
    host.contains(".vpce.amazonaws.")
}

/// Find the position of the `vpce` segment in a dot-split hostname.
///
/// Returns the index of the `vpce` segment that is immediately followed
/// by `amazonaws`, or `None` if no such pair exists.
fn find_vpce_position(parts: &[&str]) -> Option<usize> {
    parts
        .iter()
        .position(|&p| p == "vpce")
        .filter(|&i| parts.get(i + 1) == Some(&"amazonaws"))
}

/// Extract the AWS region from a VPC endpoint hostname.
///
/// The region is the segment immediately before `vpce.amazonaws.*`:
/// `vpce-xxx.svc-id.REGION.vpce.amazonaws.com[.cn]`
fn extract_region_from_vpc_endpoint(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').collect();
    let vpce_idx = find_vpce_position(&parts)?;
    // Region is the segment just before "vpce"
    if vpce_idx == 0 {
        return None;
    }
    parts.get(vpce_idx - 1).map(|s| (*s).to_string())
}

/// Extract the DSQL service ID from a VPC endpoint hostname.
///
/// For `vpce-xxx.dsql-abc.us-east-1.vpce.amazonaws.com`, returns `dsql-abc`.
/// The service ID is the second segment (index 1) — the part between the
/// vpce ID and the region.
fn extract_service_id_from_vpc_endpoint(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').collect();
    // Verify this is actually a VPC endpoint
    find_vpce_position(&parts)?;
    // Service ID is always at index 1 (after the vpce-xxx prefix)
    if parts.len() >= 4 {
        parts.get(1).map(|s| (*s).to_string())
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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

    // ========================================================================
    // VPC endpoint helper tests
    // ========================================================================

    #[test]
    fn test_is_vpc_endpoint() {
        assert!(is_vpc_endpoint(
            "vpce-0abc123.dsql-fnh4.us-east-1.vpce.amazonaws.com"
        ));
        assert!(is_vpc_endpoint(
            "vpce-xxx-us-east-1c.dsql-fnh4.us-east-1.vpce.amazonaws.com"
        ));
        // China partition
        assert!(is_vpc_endpoint(
            "vpce-0abc123.dsql-fnh4.cn-north-1.vpce.amazonaws.com.cn"
        ));
    }

    #[test]
    fn test_is_vpc_endpoint_false() {
        assert!(!is_vpc_endpoint("localhost"));
        assert!(!is_vpc_endpoint("abc123.dsql.us-east-1.on.aws"));
        assert!(!is_vpc_endpoint("mydb.rds.amazonaws.com"));
    }

    #[test]
    fn test_extract_region_from_vpc_endpoint() {
        assert_eq!(
            extract_region_from_vpc_endpoint("vpce-0abc123.dsql-fnh4.us-east-1.vpce.amazonaws.com"),
            Some("us-east-1".to_string())
        );
        assert_eq!(
            extract_region_from_vpc_endpoint(
                "vpce-xxx-us-east-1c.dsql-fnh4.eu-west-2.vpce.amazonaws.com"
            ),
            Some("eu-west-2".to_string())
        );
        // China partition
        assert_eq!(
            extract_region_from_vpc_endpoint(
                "vpce-0abc123.dsql-fnh4.cn-north-1.vpce.amazonaws.com.cn"
            ),
            Some("cn-north-1".to_string())
        );
    }

    #[test]
    fn test_extract_service_id_from_vpc_endpoint() {
        assert_eq!(
            extract_service_id_from_vpc_endpoint(
                "vpce-0abc123.dsql-fnh4.us-east-1.vpce.amazonaws.com"
            ),
            Some("dsql-fnh4".to_string())
        );
        // China partition
        assert_eq!(
            extract_service_id_from_vpc_endpoint(
                "vpce-0abc123.dsql-fnh4.cn-north-1.vpce.amazonaws.com.cn"
            ),
            Some("dsql-fnh4".to_string())
        );
    }

    // ========================================================================
    // DsqlEndpoint::from_url tests
    // ========================================================================

    #[test]
    fn test_from_url_direct_dsql() {
        let url = "postgres://admin@abc123.dsql.us-east-1.on.aws/postgres";
        let ep = DsqlEndpoint::from_url(url).unwrap().unwrap();
        assert!(matches!(ep, DsqlEndpoint::Direct { .. }));
        assert_eq!(ep.connect_hostname(), "abc123.dsql.us-east-1.on.aws");
        assert_eq!(ep.token_hostname(), "abc123.dsql.us-east-1.on.aws");
        assert_eq!(ep.region(), "us-east-1");
        assert!(matches!(ep.ssl_mode(), PgSslMode::VerifyFull));
        assert!(ep.cluster_id().is_none());
        assert!(ep.pg_options().is_none());
    }

    #[test]
    fn test_from_url_vpc_endpoint() {
        let url = "postgres://vouch@vpce-0abc123.dsql-fnh4.us-east-1.vpce.amazonaws.com/postgres?dsql_cluster_id=cntqtno23teyzmet2w6rbxqk2y";
        let ep = DsqlEndpoint::from_url(url).unwrap().unwrap();
        assert!(matches!(ep, DsqlEndpoint::VpcEndpoint { .. }));
        assert_eq!(
            ep.connect_hostname(),
            "vpce-0abc123.dsql-fnh4.us-east-1.vpce.amazonaws.com"
        );
        assert_eq!(
            ep.token_hostname(),
            "cntqtno23teyzmet2w6rbxqk2y.dsql-fnh4.us-east-1.on.aws"
        );
        assert_eq!(ep.region(), "us-east-1");
        assert!(matches!(ep.ssl_mode(), PgSslMode::Require));
        assert_eq!(ep.cluster_id(), Some("cntqtno23teyzmet2w6rbxqk2y"));
        assert_eq!(
            ep.pg_options(),
            Some(("amzn-cluster-id", "cntqtno23teyzmet2w6rbxqk2y"))
        );
    }

    #[test]
    fn test_from_url_vpc_endpoint_with_az_suffix() {
        // VPC endpoint FQDN with AZ-specific prefix
        let url = "postgres://vouch@vpce-xxx-us-east-1c.dsql-fnh4.us-east-1.vpce.amazonaws.com/postgres?dsql_cluster_id=myid";
        let ep = DsqlEndpoint::from_url(url).unwrap().unwrap();
        assert_eq!(
            ep.connect_hostname(),
            "vpce-xxx-us-east-1c.dsql-fnh4.us-east-1.vpce.amazonaws.com"
        );
        assert_eq!(ep.token_hostname(), "myid.dsql-fnh4.us-east-1.on.aws");
        assert_eq!(ep.region(), "us-east-1");
    }

    #[test]
    fn test_from_url_vpc_endpoint_china_partition() {
        let url = "postgres://vouch@vpce-0abc123.dsql-fnh4.cn-north-1.vpce.amazonaws.com.cn/postgres?dsql_cluster_id=mycluster";
        let ep = DsqlEndpoint::from_url(url).unwrap().unwrap();
        assert!(matches!(ep, DsqlEndpoint::VpcEndpoint { .. }));
        assert_eq!(
            ep.connect_hostname(),
            "vpce-0abc123.dsql-fnh4.cn-north-1.vpce.amazonaws.com.cn"
        );
        assert_eq!(ep.token_hostname(), "mycluster.dsql-fnh4.cn-north-1.on.aws");
        assert_eq!(ep.region(), "cn-north-1");
        assert_eq!(ep.cluster_id(), Some("mycluster"));
    }

    #[test]
    fn test_from_url_plain_postgres() {
        let url = "postgres://user:pass@localhost:5432/mydb";
        let ep = DsqlEndpoint::from_url(url).unwrap();
        assert!(ep.is_none());
    }

    #[test]
    fn test_from_url_vpc_endpoint_missing_cluster_id() {
        let url = "postgres://vouch@vpce-0abc123.dsql-fnh4.us-east-1.vpce.amazonaws.com/postgres";
        let err = DsqlEndpoint::from_url(url).unwrap_err();
        assert!(
            err.to_string().contains("dsql_cluster_id"),
            "error should mention dsql_cluster_id: {err}"
        );
    }

    #[test]
    fn test_from_url_vpc_endpoint_empty_cluster_id() {
        let url = "postgres://vouch@vpce-0abc123.dsql-fnh4.us-east-1.vpce.amazonaws.com/postgres?dsql_cluster_id=";
        let err = DsqlEndpoint::from_url(url).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "error should mention empty: {err}"
        );
    }

    #[test]
    fn test_from_url_invalid_url() {
        let err = DsqlEndpoint::from_url("not a url").unwrap_err();
        assert!(err.to_string().contains("failed to parse"));
    }

    #[test]
    fn test_from_url_sqlite() {
        // sqlite URLs won't have a host, so from_url returns None
        let ep = DsqlEndpoint::from_url("postgres://localhost/db").unwrap();
        assert!(ep.is_none());
    }
}
