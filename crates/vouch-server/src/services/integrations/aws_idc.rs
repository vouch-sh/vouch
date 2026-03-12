// SPDX-License-Identifier: BUSL-1.1
//! AWS IAM Identity Center (IdC) token exchange service.
//!
//! Performs the server-side Trusted Token Issuer flow:
//!
//! 1. Issue OIDC ID token (reuses [`super::aws::issue_aws_token`])
//! 2. `AssumeRoleWithWebIdentity` with the bootstrap role (unauthenticated STS call)
//! 3. `CreateTokenWithIAM` with bootstrap creds → SSO access token
//! 4. Return SSO access token to CLI for local caching in `~/.aws/sso/cache/`.
//!    The AWS SDK/CLI calls `GetRoleCredentials` locally using the cached token.
//!
//! The SSO access token is returned to the CLI for local caching,
//! never stored server-side.

use std::sync::Arc;

use crate::db::{self, store::DocumentStore};
use crate::redact_email;
use crate::services::oidc::OidcSigningKey;
use secrecy::{ExposeSecret, SecretString};
use vouch_common::AwsIntegrationConfig;
use vouch_common::aws::Arn;

/// Error types for IdC token exchange.
#[derive(Debug, thiserror::Error)]
pub enum AwsIdcError {
    /// IdC is not configured for this organization.
    #[error("AWS Identity Center is not configured for this organization")]
    NotConfigured,

    /// Missing required IdC config field.
    #[error("Missing IdC config field: {0}")]
    MissingField(&'static str),

    /// Invalid ARN format.
    #[error("Invalid ARN: {0}")]
    InvalidArn(String),

    /// Underlying AWS token issuance failed.
    #[error("Failed to issue OIDC token: {0}")]
    OidcToken(#[from] super::aws::AwsError),

    /// STS `AssumeRoleWithWebIdentity` failed.
    #[error("STS AssumeRoleWithWebIdentity failed: {0}")]
    StsAssume(String),

    /// SSO-OIDC `CreateTokenWithIAM` failed.
    #[error("CreateTokenWithIAM failed: {0}")]
    CreateToken(String),

    /// User not found or not assigned in Identity Center.
    ///
    /// Returned when `CreateTokenWithIAM` gets `InvalidGrantException`,
    /// which typically means the user's email doesn't match any Identity
    /// Center user or the user isn't assigned to the application.
    #[error(
        "User not found in Identity Center. Ensure the user is created \
         in Identity Center and assigned to the Vouch application."
    )]
    UserNotInIdentityCenter,

    /// The Identity Center application ARN is invalid or not configured
    /// as a trusted token issuer application.
    #[error("Invalid Identity Center application: {0}")]
    InvalidClient(String),

    /// Access denied by Identity Center.
    #[error("Access denied by Identity Center: {0}")]
    AccessDenied(String),

    /// SSO `ListAccounts` failed.
    #[error("ListAccounts failed: {0}")]
    ListAccounts(String),

    /// User has no account assignments in Identity Center.
    ///
    /// Returned when `ListAccounts` gets `UnauthorizedException`, which
    /// typically means the user exists in Identity Center but has no
    /// permission set assignments to any AWS accounts.
    #[error(
        "No account assignments found. The user exists in Identity Center \
         but has no permission sets assigned to any AWS accounts."
    )]
    NoAccountAssignments,

    /// SSO `ListAccountRoles` failed.
    #[error("ListAccountRoles failed: {0}")]
    ListAccountRoles(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),
}

/// Common context for all IdC operations.
///
/// Groups the parameters shared by `exchange_for_idc_token`
/// and `discover_accounts_and_roles`.
pub struct IdcContext<'a> {
    pub store: &'a DocumentStore,
    pub base_url: &'a str,
    pub session_hours: u64,
    pub oidc_key: &'a OidcSigningKey,
    pub user_email: &'a str,
    pub authenticator_id: Option<&'a str>,
    pub hd: Option<String>,
    pub org_id: &'a str,
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
    /// Opaque identity context from `CreateTokenWithIAM` additional details.
    pub identity_context: Option<String>,
}

/// Build an SSO client configured for the given region with no credentials.
async fn build_sso_client(region: &str) -> aws_sdk_sso::Client {
    let sso_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .no_credentials()
        .load()
        .await;
    aws_sdk_sso::Client::new(&sso_config)
}

/// Exchange a Vouch session for an SSO access token.
///
/// Chains three operations server-side: OIDC token issuance →
/// STS bootstrap (`AssumeRoleWithWebIdentity`) → `CreateTokenWithIAM`.
/// Used by the `/sso-token` handler and [`discover_accounts_and_roles`].
pub async fn exchange_for_idc_token(ctx: &IdcContext<'_>) -> Result<IdcTokenResult, AwsIdcError> {
    // 1. Read IdC config from DB
    let integration = db::get_cloud_integration(ctx.store, ctx.org_id, "aws")
        .await?
        .ok_or(AwsIdcError::NotConfigured)?;

    let config: AwsIntegrationConfig = serde_json::from_value(integration.config)
        .map_err(|e| AwsIdcError::Database(anyhow::anyhow!("Failed to parse AWS config: {e}")))?;

    if !config.idc_configured() {
        return Err(AwsIdcError::NotConfigured);
    }

    let bootstrap_role_arn_str = config
        .idc_bootstrap_role_arn
        .as_deref()
        .ok_or(AwsIdcError::MissingField("idc_bootstrap_role_arn"))?;
    let bootstrap_arn =
        Arn::parse(bootstrap_role_arn_str).map_err(|e| AwsIdcError::InvalidArn(e.to_string()))?;
    let application_arn_str = config
        .idc_application_arn
        .as_deref()
        .ok_or(AwsIdcError::MissingField("idc_application_arn"))?;
    let application_arn =
        Arn::parse(application_arn_str).map_err(|e| AwsIdcError::InvalidArn(e.to_string()))?;
    let idc_region = config
        .idc_region
        .as_deref()
        .ok_or(AwsIdcError::MissingField("idc_region"))?;

    // 2. Issue OIDC ID token
    let token_result = super::aws::issue_aws_token(
        ctx.store,
        ctx.base_url,
        ctx.session_hours,
        ctx.oidc_key,
        ctx.user_email,
        ctx.authenticator_id,
        ctx.hd.clone(),
    )
    .await?;

    // 3. Bootstrap IAM credentials via STS
    let bootstrap_creds =
        bootstrap_iam_credentials(&bootstrap_arn, &token_result.id_token, ctx.user_email).await?;

    // 4. Exchange for SSO access token via CreateTokenWithIAM
    let (sso_access_token, sso_expires_in, identity_context) = create_idc_sso_token(
        &application_arn,
        &token_result.id_token,
        idc_region,
        bootstrap_creds,
    )
    .await?;

    tracing::info!(
        "Issued IdC SSO token for {} (org {}, identity_context={})",
        redact_email(ctx.user_email),
        ctx.org_id,
        if identity_context.is_some() {
            "present"
        } else {
            "absent"
        },
    );

    Ok(IdcTokenResult {
        access_token: sso_access_token,
        expires_in: sso_expires_in,
        region: idc_region.to_string(),
        identity_context,
    })
}

/// Bootstrap temporary IAM credentials via STS `AssumeRoleWithWebIdentity`.
///
/// Uses the bootstrap role ARN to determine the correct partition and
/// STS regional endpoint. The returned credentials are short-lived and
/// scoped to the bootstrap role.
async fn bootstrap_iam_credentials(
    bootstrap_arn: &Arn,
    id_token: &str,
    user_email: &str,
) -> Result<aws_credential_types::Credentials, AwsIdcError> {
    let sts_region = bootstrap_arn.partition.default_sts_region();

    let sts_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(sts_region.to_string()))
        .no_credentials()
        .load()
        .await;
    let sts_client = aws_sdk_sts::Client::new(&sts_config);

    let session_name = sanitize_session_name(user_email);

    let bootstrap_role_arn = bootstrap_arn.to_string();
    let sts_response = sts_client
        .assume_role_with_web_identity()
        .role_arn(&bootstrap_role_arn)
        .role_session_name(&session_name)
        .web_identity_token(id_token)
        .send()
        .await
        .map_err(|e| AwsIdcError::StsAssume(format!("{e}")))?;

    let sts_creds = sts_response
        .credentials()
        .ok_or_else(|| AwsIdcError::StsAssume("No credentials in STS response".to_string()))?;

    let access_key = SecretString::from(sts_creds.access_key_id());
    let secret_key = SecretString::from(sts_creds.secret_access_key());
    let session_token = SecretString::from(sts_creds.session_token());

    let exp = sts_creds.expiration();
    let exp_secs = u64::try_from(exp.secs()).map_err(|_| {
        AwsIdcError::StsAssume("STS returned expired bootstrap credentials".to_string())
    })?;
    let exp_duration = std::time::Duration::new(exp_secs, exp.subsec_nanos());

    Ok(aws_credential_types::Credentials::new(
        access_key.expose_secret(),
        secret_key.expose_secret(),
        Some(session_token.expose_secret().to_string()),
        std::time::SystemTime::UNIX_EPOCH.checked_add(exp_duration),
        "vouch-idc-bootstrap",
    ))
}

/// Exchange an OIDC token for an SSO access token via `CreateTokenWithIAM`.
///
/// Returns `(access_token, expires_in, identity_context)`.
async fn create_idc_sso_token(
    application_arn: &Arn,
    id_token: &str,
    idc_region: &str,
    bootstrap_creds: aws_credential_types::Credentials,
) -> Result<(SecretString, u64, Option<String>), AwsIdcError> {
    let ssooidc_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(idc_region.to_string()))
        .credentials_provider(bootstrap_creds)
        .load()
        .await;
    let ssooidc_client = aws_sdk_ssooidc::Client::new(&ssooidc_config);

    let app_arn_str = application_arn.to_string();
    let token_response = ssooidc_client
        .create_token_with_iam()
        .client_id(&app_arn_str)
        .grant_type("urn:ietf:params:oauth:grant-type:jwt-bearer")
        .assertion(id_token)
        .scope("sso:account:access")
        .send()
        .await
        .map_err(|e| classify_create_token_error(&e))?;

    let sso_access_token = token_response
        .access_token()
        .ok_or_else(|| AwsIdcError::CreateToken("No access token in response".to_string()))?;

    let identity_context = token_response
        .aws_additional_details()
        .and_then(|d| d.identity_context())
        .map(|s| s.to_string());

    let raw_expires_in = token_response.expires_in();
    let sso_expires_in = u64::try_from(raw_expires_in).unwrap_or_else(|_| {
        tracing::warn!(
            raw_expires_in,
            "IdC CreateTokenWithIAM returned non-positive expires_in, defaulting to 3600s"
        );
        3600
    });

    Ok((
        SecretString::from(sso_access_token.to_string()),
        sso_expires_in,
        identity_context,
    ))
}

/// Classify a `CreateTokenWithIAM` SDK error into a specific `AwsIdcError`.
///
/// Maps well-known error codes to actionable variants:
/// - `InvalidGrantException` → user not found/assigned in Identity Center
/// - `InvalidClientException` → bad application ARN or trust config
/// - `AccessDeniedException` → IAM permissions issue
/// - Everything else → generic `CreateToken` with debug details
fn classify_create_token_error(
    err: &aws_sdk_ssooidc::error::SdkError<
        aws_sdk_ssooidc::operation::create_token_with_iam::CreateTokenWithIAMError,
    >,
) -> AwsIdcError {
    let Some(service_err) = err.as_service_error() else {
        return AwsIdcError::CreateToken(format!("{err:#}"));
    };

    use aws_sdk_ssooidc::operation::create_token_with_iam::CreateTokenWithIAMError;
    match service_err {
        CreateTokenWithIAMError::InvalidGrantException(_) => AwsIdcError::UserNotInIdentityCenter,
        CreateTokenWithIAMError::InvalidClientException(e) => {
            AwsIdcError::InvalidClient(e.to_string())
        }
        CreateTokenWithIAMError::AccessDeniedException(e) => {
            AwsIdcError::AccessDenied(e.to_string())
        }
        other => AwsIdcError::CreateToken(format!("{other:?}")),
    }
}

/// Classify a `ListAccounts` SDK error into a specific `AwsIdcError`.
///
/// `UnauthorizedException` typically means the SSO token is valid but
/// the user has no permission set assignments to any AWS accounts.
fn classify_list_accounts_error(
    err: &aws_sdk_sso::error::SdkError<aws_sdk_sso::operation::list_accounts::ListAccountsError>,
) -> AwsIdcError {
    let Some(service_err) = err.as_service_error() else {
        return AwsIdcError::ListAccounts(format!("{err:#}"));
    };

    use aws_sdk_sso::operation::list_accounts::ListAccountsError;
    match service_err {
        ListAccountsError::UnauthorizedException(e) => {
            tracing::warn!("ListAccounts UnauthorizedException: {e}");
            AwsIdcError::NoAccountAssignments
        }
        other => AwsIdcError::ListAccounts(format!("{other:?}")),
    }
}

/// Discover all accounts and roles available via Identity Center.
///
/// Performs a single token exchange, then lists all accounts and their
/// roles concurrently (up to 5 at a time). Partial failures for
/// individual accounts are collected in `errors` rather than failing
/// the entire request.
pub async fn discover_accounts_and_roles(
    ctx: &IdcContext<'_>,
) -> Result<vouch_common::IdcDiscoveryResponse, AwsIdcError> {
    let token_result = exchange_for_idc_token(ctx).await?;
    let sso_client = build_sso_client(&token_result.region).await;

    // List all accounts
    let accounts = list_accounts_with_client(&sso_client, &token_result.access_token).await?;

    // List roles for each account concurrently (max 5 at a time)
    let semaphore = Arc::new(tokio::sync::Semaphore::new(5));
    let mut join_set = tokio::task::JoinSet::new();

    for account in &accounts {
        let Some(account_id) = account.account_id() else {
            tracing::warn!("ListAccounts returned entry with no account_id, skipping");
            continue;
        };
        let account_name = account.account_name().unwrap_or(account_id).to_string();
        let account_id = account_id.to_string();

        let client = sso_client.clone();
        let token = token_result.access_token.clone();
        let sem = semaphore.clone();

        join_set.spawn(async move {
            let Ok(_permit) = sem.acquire().await else {
                return (
                    account_id,
                    account_name,
                    Err(AwsIdcError::ListAccountRoles(
                        "semaphore closed".to_string(),
                    )),
                );
            };
            let result = list_account_roles_with_client(&client, &token, &account_id).await;
            (account_id, account_name, result)
        });
    }

    let mut discovered = Vec::new();
    let mut errors = Vec::new();

    while let Some(result) = join_set.join_next().await {
        match result {
            Ok((account_id, account_name, Ok(roles))) => {
                discovered.push(vouch_common::IdcAccountWithRoles {
                    account_id,
                    account_name,
                    roles,
                });
            }
            Ok((account_id, _, Err(e))) => {
                errors.push(vouch_common::IdcDiscoveryError {
                    account_id,
                    message: e.to_string(),
                });
            }
            Err(e) => {
                tracing::warn!("IdC role listing task panicked: {e}");
            }
        }
    }

    // Sort accounts by name for stable output
    discovered.sort_by(|a, b| a.account_name.cmp(&b.account_name));

    Ok(vouch_common::IdcDiscoveryResponse {
        accounts: discovered,
        region: token_result.region,
        errors,
    })
}

/// List all accounts available via an existing SSO client and token.
async fn list_accounts_with_client(
    client: &aws_sdk_sso::Client,
    access_token: &SecretString,
) -> Result<Vec<aws_sdk_sso::types::AccountInfo>, AwsIdcError> {
    let mut accounts = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client
            .list_accounts()
            .access_token(access_token.expose_secret());
        if let Some(ref token) = next_token {
            req = req.next_token(token);
        }

        let output = req
            .send()
            .await
            .map_err(|e| classify_list_accounts_error(&e))?;

        accounts.extend_from_slice(output.account_list());

        match output.next_token() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }

    Ok(accounts)
}

/// List role names for a single account via an existing SSO client.
async fn list_account_roles_with_client(
    client: &aws_sdk_sso::Client,
    access_token: &SecretString,
    account_id: &str,
) -> Result<Vec<String>, AwsIdcError> {
    let mut roles = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client
            .list_account_roles()
            .account_id(account_id)
            .access_token(access_token.expose_secret());
        if let Some(ref token) = next_token {
            req = req.next_token(token);
        }

        let output = req
            .send()
            .await
            .map_err(|e| AwsIdcError::ListAccountRoles(format!("{e}")))?;

        for role in output.role_list() {
            let Some(name) = role.role_name() else {
                tracing::warn!(
                    "ListAccountRoles returned entry with no role_name for account {account_id}, skipping"
                );
                continue;
            };
            roles.push(name.to_string());
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
        .filter(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(*c))
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

    #[test]
    fn test_sanitize_session_name_rejects_unicode() {
        assert_eq!(sanitize_session_name("用户@example.com"), "@example.com");
    }

    #[test]
    fn test_sanitize_session_name_all_invalid() {
        assert_eq!(sanitize_session_name("日本語テスト"), "");
    }

    #[test]
    fn test_sanitize_session_name_mixed_unicode_ascii() {
        assert_eq!(
            sanitize_session_name("alice.müller@example.com"),
            "alice.mller@example.com"
        );
    }

    #[test]
    fn test_sanitize_session_name_exactly_64() {
        let email = format!("{}@b.c", "a".repeat(60));
        let result = sanitize_session_name(&email);
        assert_eq!(result.len(), 64);
        assert_eq!(result, email);
    }

    #[test]
    fn test_sanitize_session_name_preserves_special_chars() {
        assert_eq!(sanitize_session_name("a+=,.@_-b"), "a+=,.@_-b");
    }

    #[test]
    fn test_sanitize_session_name_idempotent() {
        let inputs = [
            "alice@example.com",
            "用户@example.com",
            "a+=,.@_-b",
            "",
            "abc123",
        ];
        for input in &inputs {
            let once = sanitize_session_name(input);
            let twice = sanitize_session_name(&once);
            assert_eq!(once, twice, "not idempotent for input: {input}");
        }
    }
}
