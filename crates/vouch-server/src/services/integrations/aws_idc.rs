// SPDX-License-Identifier: BUSL-1.1
//! AWS IAM Identity Center (IdC) token exchange service.
//!
//! Performs the server-side Trusted Token Issuer flow:
//!
//! 1. Issue OIDC ID token (reuses [`super::aws::issue_aws_token`])
//! 2. `AssumeRoleWithWebIdentity` with the bootstrap role (unauthenticated STS call)
//! 3. `CreateTokenWithIAM` with bootstrap creds → SSO access token
//!
//! The CLI then only needs one more call (`GetRoleCredentials`) to get
//! final AWS credentials.

use crate::db::{self, store::DocumentStore};
use crate::redact_email;
use crate::services::oidc::OidcSigningKey;
use secrecy::{ExposeSecret, SecretString};
use vouch_common::AwsIntegrationConfig;
use vouch_common::aws::Partition;

/// Error types for IdC token exchange.
#[derive(Debug, thiserror::Error)]
pub enum AwsIdcError {
    /// IdC is not configured for this organization.
    #[error("AWS Identity Center is not configured for this organization")]
    NotConfigured,

    /// Missing required IdC config field.
    #[error("Missing IdC config field: {0}")]
    MissingField(&'static str),

    /// Underlying AWS token issuance failed.
    #[error("Failed to issue OIDC token: {0}")]
    OidcToken(#[from] super::aws::AwsError),

    /// STS `AssumeRoleWithWebIdentity` failed.
    #[error("STS AssumeRoleWithWebIdentity failed: {0}")]
    StsAssume(String),

    /// SSO-OIDC `CreateTokenWithIAM` failed.
    #[error("CreateTokenWithIAM failed: {0}")]
    CreateToken(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),
}

/// Result of a successful IdC token exchange.
pub struct IdcTokenResult {
    /// SSO access token for portal APIs.
    pub access_token: SecretString,
    /// Token validity in seconds.
    pub expires_in: u64,
    /// Identity Center region.
    pub region: String,
    /// DNS suffix for the partition (e.g., `amazonaws.com`).
    pub domain_suffix: String,
}

/// Exchange a Vouch session for an SSO access token.
///
/// Chains three operations server-side so the CLI only needs
/// one call (plus `GetRoleCredentials` on the client side).
///
/// # Arguments
/// * `store` - Document store for reading IdC config
/// * `base_url` - Server base URL (OIDC issuer)
/// * `session_hours` - Session duration for token validity
/// * `oidc_key` - OIDC signing key
/// * `user_email` - Authenticated user's email
/// * `authenticator_id` - Authenticator ID from the session
/// * `hd` - Organization domain (Google Workspace hosted domain)
/// * `org_id` - Organization ID for config lookup
#[allow(clippy::too_many_arguments)]
pub async fn exchange_for_idc_token(
    store: &DocumentStore,
    base_url: &str,
    session_hours: u64,
    oidc_key: &OidcSigningKey,
    user_email: &str,
    authenticator_id: Option<&str>,
    hd: Option<String>,
    org_id: &str,
) -> Result<IdcTokenResult, AwsIdcError> {
    // 1. Read IdC config from DB
    let integration = db::get_cloud_integration(store, org_id, "aws")
        .await?
        .ok_or(AwsIdcError::NotConfigured)?;

    let config: AwsIntegrationConfig = serde_json::from_value(integration.config)
        .map_err(|e| AwsIdcError::Database(anyhow::anyhow!("Failed to parse AWS config: {e}")))?;

    if !config.idc_configured() {
        return Err(AwsIdcError::NotConfigured);
    }

    let bootstrap_role_arn = config
        .idc_bootstrap_role_arn
        .as_deref()
        .ok_or(AwsIdcError::MissingField("idc_bootstrap_role_arn"))?;
    let application_arn = config
        .idc_application_arn
        .as_deref()
        .ok_or(AwsIdcError::MissingField("idc_application_arn"))?;
    let idc_region = config
        .idc_region
        .as_deref()
        .ok_or(AwsIdcError::MissingField("idc_region"))?;

    // 2. Issue OIDC ID token
    let token_result = super::aws::issue_aws_token(
        store,
        base_url,
        session_hours,
        oidc_key,
        user_email,
        authenticator_id,
        hd,
    )
    .await?;

    // Determine region/partition from the bootstrap role ARN
    let partition = Partition::from_arn(bootstrap_role_arn)
        .map_err(|e| AwsIdcError::StsAssume(format!("{e}")))?;
    let domain_suffix = partition.dns_suffix();
    let sts_region = partition.default_sts_region();

    // 3. STS AssumeRoleWithWebIdentity (no credentials needed)
    let sts_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(sts_region.to_string()))
        .no_credentials()
        .load()
        .await;
    let sts_client = aws_sdk_sts::Client::new(&sts_config);

    let session_name = format!(
        "vouch-idc-{}",
        user_email
            .split('@')
            .next()
            .unwrap_or("session")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .take(32)
            .collect::<String>()
    );

    let sts_response = sts_client
        .assume_role_with_web_identity()
        .role_arn(bootstrap_role_arn)
        .role_session_name(&session_name)
        .web_identity_token(token_result.id_token.clone())
        .send()
        .await
        .map_err(|e| AwsIdcError::StsAssume(format!("{e}")))?;

    let sts_creds = sts_response
        .credentials()
        .ok_or_else(|| AwsIdcError::StsAssume("No credentials in STS response".to_string()))?;

    // 4. CreateTokenWithIAM with bootstrap creds
    let access_key = SecretString::from(sts_creds.access_key_id());
    let secret_key = SecretString::from(sts_creds.secret_access_key());
    let session_token = SecretString::from(sts_creds.session_token());

    let bootstrap_creds = aws_credential_types::Credentials::new(
        access_key.expose_secret(),
        secret_key.expose_secret(),
        Some(session_token.expose_secret().to_string()),
        {
            let exp = sts_creds.expiration();
            std::time::SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::new(
                u64::try_from(exp.secs()).unwrap_or(0),
                exp.subsec_nanos(),
            ))
        },
        "vouch-idc-bootstrap",
    );

    let ssooidc_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(idc_region.to_string()))
        .credentials_provider(bootstrap_creds)
        .load()
        .await;
    let ssooidc_client = aws_sdk_ssooidc::Client::new(&ssooidc_config);

    let token_response = ssooidc_client
        .create_token_with_iam()
        .client_id(application_arn)
        .grant_type("urn:ietf:params:oauth:grant-type:jwt-bearer")
        .assertion(token_result.id_token)
        .send()
        .await
        .map_err(|e| AwsIdcError::CreateToken(format!("{e}")))?;

    let sso_access_token = token_response
        .access_token()
        .ok_or_else(|| AwsIdcError::CreateToken("No access token in response".to_string()))?;

    let sso_expires_in = u64::try_from(token_response.expires_in()).unwrap_or(3600);

    tracing::info!(
        "Issued IdC SSO token for {} (org {org_id})",
        redact_email(user_email),
    );

    Ok(IdcTokenResult {
        access_token: SecretString::from(sso_access_token.to_string()),
        expires_in: sso_expires_in,
        region: idc_region.to_string(),
        domain_suffix: domain_suffix.to_string(),
    })
}
