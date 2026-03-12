// SPDX-License-Identifier: BUSL-1.1
//! AWS IAM Identity Center (IdC) token exchange service.
//!
//! Performs the server-side Trusted Token Issuer flow:
//!
//! 1. Issue OIDC ID token (reuses [`super::aws::issue_aws_token`])
//! 2. `AssumeRoleWithWebIdentity` with the bootstrap role (unauthenticated STS call)
//! 3. `CreateTokenWithIAM` with bootstrap creds → SSO access token
//! 4. `GetRoleCredentials` via the SSO portal → final AWS credentials
//!
//! The SSO access token never leaves the server.

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

    /// SSO `GetRoleCredentials` failed.
    #[error("GetRoleCredentials failed: {0}")]
    GetRoleCredentials(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),
}

/// Result of a successful IdC token exchange.
#[derive(Debug)]
pub struct IdcTokenResult {
    /// SSO access token for portal APIs.
    pub access_token: SecretString,
    /// Token validity in seconds.
    pub expires_in: u64,
    /// Identity Center region.
    pub region: String,
    /// DNS suffix for the partition (e.g., `amazonaws.com`).
    pub domain_suffix: String,
    /// Opaque identity context from `CreateTokenWithIAM` additional details.
    pub identity_context: Option<String>,
}

/// Result of a successful IdC credential exchange.
#[derive(Debug)]
pub struct IdcCredentialsResult {
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    pub session_token: SecretString,
    pub expiration: jiff::Timestamp,
}

/// Exchange a Vouch session for an SSO access token.
///
/// Chains three operations server-side. Used internally by
/// [`exchange_for_idc_credentials`], [`list_idc_accounts`],
/// and [`list_idc_account_roles`].
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

    let session_name = sanitize_session_name(user_email);

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

    let identity_context = token_response
        .aws_additional_details()
        .and_then(|d| d.identity_context())
        .map(|s| s.to_string());

    let sso_expires_in = u64::try_from(token_response.expires_in()).unwrap_or(3600);

    tracing::info!(
        "Issued IdC SSO token for {} (org {org_id}, identity_context={})",
        redact_email(user_email),
        if identity_context.is_some() {
            "present"
        } else {
            "absent"
        },
    );

    Ok(IdcTokenResult {
        access_token: SecretString::from(sso_access_token.to_string()),
        expires_in: sso_expires_in,
        region: idc_region.to_string(),
        domain_suffix: domain_suffix.to_string(),
        identity_context,
    })
}

/// Exchange a Vouch session for AWS credentials via Identity Center.
///
/// Chains the full IdC flow server-side:
/// 1. `exchange_for_idc_token` (OIDC → STS bootstrap → `CreateTokenWithIAM`)
/// 2. `GetRoleCredentials` via the SSO portal → final AWS credentials
///
/// The SSO access token never leaves the server.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_for_idc_credentials(
    store: &DocumentStore,
    base_url: &str,
    session_hours: u64,
    oidc_key: &OidcSigningKey,
    user_email: &str,
    authenticator_id: Option<&str>,
    hd: Option<String>,
    org_id: &str,
    account_id: &str,
    role_name: &str,
) -> Result<IdcCredentialsResult, AwsIdcError> {
    // Step 1: Get SSO access token
    let token_result = exchange_for_idc_token(
        store,
        base_url,
        session_hours,
        oidc_key,
        user_email,
        authenticator_id,
        hd,
        org_id,
    )
    .await?;

    // Step 2: GetRoleCredentials via SSO portal
    let sso_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(token_result.region.clone()))
        .no_credentials()
        .load()
        .await;
    let sso_client = aws_sdk_sso::Client::new(&sso_config);

    let role_creds_output = sso_client
        .get_role_credentials()
        .account_id(account_id)
        .role_name(role_name)
        .access_token(token_result.access_token.expose_secret())
        .send()
        .await
        .map_err(|e| AwsIdcError::GetRoleCredentials(format!("{e}")))?;

    let role_creds = role_creds_output
        .role_credentials()
        .ok_or_else(|| AwsIdcError::GetRoleCredentials("No credentials in response".to_string()))?;

    let access_key = role_creds
        .access_key_id()
        .ok_or_else(|| AwsIdcError::GetRoleCredentials("Missing access_key_id".to_string()))?;
    let secret_key = role_creds
        .secret_access_key()
        .ok_or_else(|| AwsIdcError::GetRoleCredentials("Missing secret_access_key".to_string()))?;
    let session_token = role_creds
        .session_token()
        .ok_or_else(|| AwsIdcError::GetRoleCredentials("Missing session_token".to_string()))?;
    let expiration_ms = role_creds.expiration();

    let expiration = jiff::Timestamp::from_millisecond(expiration_ms).map_err(|e| {
        AwsIdcError::GetRoleCredentials(format!("Invalid expiration timestamp: {e}"))
    })?;

    tracing::info!(
        "Issued IdC credentials for {} (org {org_id}, account {account_id}, role {role_name})",
        redact_email(user_email),
    );

    Ok(IdcCredentialsResult {
        access_key_id: access_key.to_string(),
        secret_access_key: SecretString::from(secret_key),
        session_token: SecretString::from(session_token),
        expiration,
    })
}

/// List all AWS accounts available to the user via Identity Center.
///
/// Performs the IdC token exchange, then calls SSO `ListAccounts`.
#[allow(clippy::too_many_arguments)]
pub async fn list_idc_accounts(
    store: &DocumentStore,
    base_url: &str,
    session_hours: u64,
    oidc_key: &OidcSigningKey,
    user_email: &str,
    authenticator_id: Option<&str>,
    hd: Option<String>,
    org_id: &str,
) -> Result<(Vec<vouch_common::IdcAccount>, String), AwsIdcError> {
    let token_result = exchange_for_idc_token(
        store,
        base_url,
        session_hours,
        oidc_key,
        user_email,
        authenticator_id,
        hd,
        org_id,
    )
    .await?;

    let sso_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(token_result.region.clone()))
        .no_credentials()
        .load()
        .await;
    let sso_client = aws_sdk_sso::Client::new(&sso_config);

    let mut accounts = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = sso_client
            .list_accounts()
            .access_token(token_result.access_token.expose_secret());
        if let Some(ref token) = next_token {
            req = req.next_token(token);
        }

        let output = req
            .send()
            .await
            .map_err(|e| AwsIdcError::GetRoleCredentials(format!("ListAccounts: {e}")))?;

        for acct in output.account_list() {
            accounts.push(vouch_common::IdcAccount {
                account_id: acct.account_id().unwrap_or_default().to_string(),
                account_name: acct.account_name().unwrap_or_default().to_string(),
            });
        }

        match output.next_token() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }

    Ok((accounts, token_result.region))
}

/// List all roles available for a specific account via Identity Center.
///
/// Performs the IdC token exchange, then calls SSO `ListAccountRoles`.
#[allow(clippy::too_many_arguments)]
pub async fn list_idc_account_roles(
    store: &DocumentStore,
    base_url: &str,
    session_hours: u64,
    oidc_key: &OidcSigningKey,
    user_email: &str,
    authenticator_id: Option<&str>,
    hd: Option<String>,
    org_id: &str,
    account_id: &str,
) -> Result<Vec<vouch_common::IdcAccountRole>, AwsIdcError> {
    let token_result = exchange_for_idc_token(
        store,
        base_url,
        session_hours,
        oidc_key,
        user_email,
        authenticator_id,
        hd,
        org_id,
    )
    .await?;

    let sso_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(token_result.region.clone()))
        .no_credentials()
        .load()
        .await;
    let sso_client = aws_sdk_sso::Client::new(&sso_config);

    let mut roles = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = sso_client
            .list_account_roles()
            .account_id(account_id)
            .access_token(token_result.access_token.expose_secret());
        if let Some(ref token) = next_token {
            req = req.next_token(token);
        }

        let output = req
            .send()
            .await
            .map_err(|e| AwsIdcError::GetRoleCredentials(format!("ListAccountRoles: {e}")))?;

        for role in output.role_list() {
            roles.push(vouch_common::IdcAccountRole {
                role_name: role.role_name().unwrap_or_default().to_string(),
                account_id: role.account_id().unwrap_or_default().to_string(),
            });
        }

        match output.next_token() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }

    Ok(roles)
}

/// Build a sanitized STS session name from a user email.
///
/// STS session names allow `[a-zA-Z0-9+=,.@_-]` and max 64 characters.
fn sanitize_session_name(user_email: &str) -> String {
    user_email
        .chars()
        .filter(|c| c.is_alphanumeric() || "+=,.@_-".contains(*c))
        .take(64)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_session_name_email() {
        assert_eq!(
            sanitize_session_name("alice@example.com"),
            "alice@example.com"
        );
    }

    #[test]
    fn test_sanitize_session_name_strips_invalid() {
        assert_eq!(
            sanitize_session_name("alice (work)@example.com"),
            "alicework@example.com"
        );
    }

    #[test]
    fn test_sanitize_session_name_truncates_at_64() {
        let long_email = format!("{}@example.com", "a".repeat(100));
        let result = sanitize_session_name(&long_email);
        assert_eq!(result.len(), 64);
    }
}
