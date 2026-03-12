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
//! Account/role discovery uses SSO Admin + Identity Store APIs (not SSO
//! portal APIs, which are incompatible with Trusted Token Issuer tokens).

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

    /// User has no account assignments in Identity Center.
    #[error(
        "No account assignments found. The user exists in Identity Center \
         but has no permission sets assigned to any AWS accounts."
    )]
    NoAccountAssignments,

    /// Failed to resolve the Identity Center instance.
    #[error("Failed to resolve Identity Center instance: {0}")]
    InstanceResolution(String),

    /// Failed to look up user in Identity Store.
    #[error("Identity Store user lookup failed: {0}")]
    IdentityStoreLookup(String),

    /// Failed to list account assignments via SSO Admin API.
    #[error("ListAccountAssignmentsForPrincipal failed: {0}")]
    ListAssignments(String),

    /// Failed to describe a permission set.
    #[error("DescribePermissionSet failed: {0}")]
    DescribePermissionSet(String),

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

/// Parsed and validated IdC configuration from the database.
struct IdcConfig {
    bootstrap_arn: Arn,
    application_arn: Arn,
    idc_region: String,
}

/// Load and validate IdC configuration from the database.
async fn load_idc_config(store: &DocumentStore, org_id: &str) -> Result<IdcConfig, AwsIdcError> {
    let integration = db::get_cloud_integration(store, org_id, "aws")
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
        .ok_or(AwsIdcError::MissingField("idc_region"))?
        .to_string();

    Ok(IdcConfig {
        bootstrap_arn,
        application_arn,
        idc_region,
    })
}

/// Issue an OIDC token and bootstrap IAM credentials.
///
/// Returns the bootstrap credentials and the raw OIDC ID token (needed
/// for `CreateTokenWithIAM`).
async fn issue_token_and_bootstrap(
    ctx: &IdcContext<'_>,
    idc_config: &IdcConfig,
) -> Result<(aws_credential_types::Credentials, String), AwsIdcError> {
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

    let creds = bootstrap_iam_credentials(
        &idc_config.bootstrap_arn,
        &token_result.id_token,
        ctx.user_email,
    )
    .await?;

    Ok((creds, token_result.id_token))
}

/// Exchange a Vouch session for an SSO access token.
///
/// Chains three operations server-side: OIDC token issuance →
/// STS bootstrap (`AssumeRoleWithWebIdentity`) → `CreateTokenWithIAM`.
/// Used by the `/sso-token` handler.
pub async fn exchange_for_idc_token(ctx: &IdcContext<'_>) -> Result<IdcTokenResult, AwsIdcError> {
    let idc_config = load_idc_config(ctx.store, ctx.org_id).await?;
    let (bootstrap_creds, id_token) = issue_token_and_bootstrap(ctx, &idc_config).await?;

    let (sso_access_token, sso_expires_in, identity_context) = create_idc_sso_token(
        &idc_config.application_arn,
        &id_token,
        &idc_config.idc_region,
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
        region: idc_config.idc_region,
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
    // Omit scope — Identity Center grants all scopes configured on the
    // application, including `sso:account:access`.
    let token_response = ssooidc_client
        .create_token_with_iam()
        .client_id(&app_arn_str)
        .grant_type("urn:ietf:params:oauth:grant-type:jwt-bearer")
        .assertion(id_token)
        .send()
        .await
        .map_err(|e| classify_create_token_error(&e))?;

    let sso_access_token = token_response
        .access_token()
        .ok_or_else(|| AwsIdcError::CreateToken("No access token in response".to_string()))?;

    let granted_scopes = token_response.scope();
    tracing::info!("CreateTokenWithIAM granted scopes: {:?}", granted_scopes);

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

/// Extract the SSO instance ID from an application ARN.
///
/// Application ARN format: `arn:<partition>:sso::<account>:application/<instance-id>/<app-id>`
fn extract_instance_id(application_arn: &Arn) -> Result<&str, AwsIdcError> {
    let rest = application_arn
        .resource
        .strip_prefix("application/")
        .ok_or_else(|| {
            AwsIdcError::InvalidArn(format!(
                "Application ARN resource does not start with 'application/': {}",
                application_arn.resource
            ))
        })?;

    rest.split('/').next().ok_or_else(|| {
        AwsIdcError::InvalidArn(format!(
            "Cannot extract instance ID from application ARN: {}",
            application_arn
        ))
    })
}

/// Build the SSO instance ARN from the application ARN.
fn build_instance_arn(application_arn: &Arn) -> Result<String, AwsIdcError> {
    let instance_id = extract_instance_id(application_arn)?;
    Ok(format!(
        "arn:{}:sso:::instance/{}",
        application_arn.partition.as_str(),
        instance_id,
    ))
}

/// Look up a user's principal ID in Identity Store by email.
async fn resolve_identity_store_user(
    identity_store_id: &str,
    user_email: &str,
    identity_store_client: &aws_sdk_identitystore::Client,
) -> Result<String, AwsIdcError> {
    let unique_attr = aws_sdk_identitystore::types::UniqueAttribute::builder()
        .attribute_path("emails.value")
        .attribute_value(aws_smithy_types::Document::String(user_email.to_string()))
        .build()
        .map_err(|e| {
            AwsIdcError::IdentityStoreLookup(format!("Failed to build UniqueAttribute: {e}"))
        })?;

    let alt_id = aws_sdk_identitystore::types::AlternateIdentifier::UniqueAttribute(unique_attr);

    let response = identity_store_client
        .get_user_id()
        .identity_store_id(identity_store_id)
        .alternate_identifier(alt_id)
        .send()
        .await
        .map_err(|e| {
            if let Some(service_err) = e.as_service_error() {
                use aws_sdk_identitystore::operation::get_user_id::GetUserIdError;
                if let GetUserIdError::ResourceNotFoundException(_) = service_err {
                    return AwsIdcError::UserNotInIdentityCenter;
                }
            }
            AwsIdcError::IdentityStoreLookup(format!("{e}"))
        })?;

    Ok(response.user_id().to_string())
}

/// A (account_id, permission_set_arn) pair from an account assignment.
struct AccountAssignment {
    account_id: String,
    permission_set_arn: String,
}

/// List all account assignments for a principal via SSO Admin API.
async fn list_assignments_for_principal(
    ssoadmin_client: &aws_sdk_ssoadmin::Client,
    instance_arn: &str,
    principal_id: &str,
) -> Result<Vec<AccountAssignment>, AwsIdcError> {
    let mut assignments = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ssoadmin_client
            .list_account_assignments_for_principal()
            .instance_arn(instance_arn)
            .principal_id(principal_id)
            .principal_type(aws_sdk_ssoadmin::types::PrincipalType::User);
        if let Some(ref token) = next_token {
            req = req.next_token(token);
        }

        let output = req
            .send()
            .await
            .map_err(|e| AwsIdcError::ListAssignments(format!("{e}")))?;

        for assignment in output.account_assignments() {
            let Some(account_id) = assignment.account_id() else {
                continue;
            };
            let Some(permission_set_arn) = assignment.permission_set_arn() else {
                continue;
            };
            assignments.push(AccountAssignment {
                account_id: account_id.to_string(),
                permission_set_arn: permission_set_arn.to_string(),
            });
        }

        match output.next_token() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }

    Ok(assignments)
}

/// Resolve permission set ARNs to human-readable names.
///
/// `ListAccountAssignmentsForPrincipal` only returns permission set ARNs
/// (e.g., `arn:aws:sso:::permissionSet/ssoins-abc/ps-xyz`), not names.
/// We need `DescribePermissionSet` to get names like "AdministratorAccess"
/// for CLI profile generation. Already deduplicated — each unique ARN is
/// resolved once regardless of how many accounts it's assigned to.
async fn resolve_permission_set_names(
    ssoadmin_client: &aws_sdk_ssoadmin::Client,
    instance_arn: &str,
    permission_set_arns: &[String],
) -> std::collections::HashMap<String, String> {
    let mut names = std::collections::HashMap::new();

    for arn in permission_set_arns {
        if names.contains_key(arn) {
            continue;
        }
        match ssoadmin_client
            .describe_permission_set()
            .instance_arn(instance_arn)
            .permission_set_arn(arn)
            .send()
            .await
        {
            Ok(output) => {
                if let Some(ps) = output.permission_set() {
                    let name = ps.name().unwrap_or("Unknown").to_string();
                    names.insert(arn.clone(), name);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to describe permission set {arn}: {e}");
                names.insert(arn.clone(), arn.clone());
            }
        }
    }

    names
}

/// Discover all accounts and roles available via Identity Center.
///
/// Reuses a single set of bootstrap IAM credentials for both the SSO
/// token exchange and the Admin API discovery calls:
///
/// 1. Bootstrap IAM creds (1 STS call)
/// 2. `CreateTokenWithIAM` → SSO token for CLI
/// 3. `ListInstances` → identity store ID
/// 4. `GetUserId` → principal ID
/// 5. `ListAccountAssignmentsForPrincipal` → (account, permission set) pairs
/// 6. `DescribePermissionSet` × unique permission sets → names
pub async fn discover_accounts_and_roles(
    ctx: &IdcContext<'_>,
) -> Result<vouch_common::IdcDiscoveryResponse, AwsIdcError> {
    let idc_config = load_idc_config(ctx.store, ctx.org_id).await?;
    let (bootstrap_creds, id_token) = issue_token_and_bootstrap(ctx, &idc_config).await?;

    // 1. Exchange for SSO token (needed for CLI caching)
    let (sso_access_token, sso_expires_in, identity_context) = create_idc_sso_token(
        &idc_config.application_arn,
        &id_token,
        &idc_config.idc_region,
        bootstrap_creds.clone(),
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

    let token_result = IdcTokenResult {
        access_token: sso_access_token,
        expires_in: sso_expires_in,
        region: idc_config.idc_region.clone(),
        identity_context,
    };

    // 2. Build SSO Admin + Identity Store clients (reuse same bootstrap creds)
    let admin_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(idc_config.idc_region.clone()))
        .credentials_provider(bootstrap_creds)
        .load()
        .await;
    let ssoadmin_client = aws_sdk_ssoadmin::Client::new(&admin_config);
    let identity_store_client = aws_sdk_identitystore::Client::new(&admin_config);

    // 3. Resolve instance ARN and identity store ID
    let instance_arn = build_instance_arn(&idc_config.application_arn)?;
    let identity_store_id = resolve_identity_store_id(&ssoadmin_client, &instance_arn).await?;

    // 4. Look up user's principal ID
    let principal_id =
        resolve_identity_store_user(&identity_store_id, ctx.user_email, &identity_store_client)
            .await?;

    tracing::info!(
        "Resolved IdC principal for {}: {}",
        redact_email(ctx.user_email),
        principal_id,
    );

    // 5. List all account assignments
    let assignments =
        list_assignments_for_principal(&ssoadmin_client, &instance_arn, &principal_id).await?;

    if assignments.is_empty() {
        return Err(AwsIdcError::NoAccountAssignments);
    }

    // 6. Resolve permission set names (deduplicated)
    let unique_ps_arns: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        assignments
            .iter()
            .filter(|a| seen.insert(a.permission_set_arn.clone()))
            .map(|a| a.permission_set_arn.clone())
            .collect()
    };

    let ps_names =
        resolve_permission_set_names(&ssoadmin_client, &instance_arn, &unique_ps_arns).await;

    // 7. Group by account
    let mut account_map: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for assignment in &assignments {
        let role_name = ps_names
            .get(&assignment.permission_set_arn)
            .cloned()
            .unwrap_or_else(|| assignment.permission_set_arn.clone());

        account_map
            .entry(assignment.account_id.clone())
            .or_default()
            .push(role_name);
    }

    let mut discovered: Vec<vouch_common::IdcAccountWithRoles> = account_map
        .into_iter()
        .map(|(account_id, roles)| vouch_common::IdcAccountWithRoles {
            account_name: account_id.clone(),
            account_id,
            roles,
        })
        .collect();

    discovered.sort_by(|a, b| a.account_name.cmp(&b.account_name));

    Ok(vouch_common::IdcDiscoveryResponse {
        accounts: discovered,
        region: token_result.region,
        errors: Vec::new(),
    })
}

/// Resolve the identity store ID for an SSO instance.
async fn resolve_identity_store_id(
    ssoadmin_client: &aws_sdk_ssoadmin::Client,
    instance_arn: &str,
) -> Result<String, AwsIdcError> {
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ssoadmin_client.list_instances();
        if let Some(ref token) = next_token {
            req = req.next_token(token);
        }

        let output = req
            .send()
            .await
            .map_err(|e| AwsIdcError::InstanceResolution(format!("ListInstances failed: {e}")))?;

        for instance in output.instances() {
            if instance.instance_arn() == Some(instance_arn) {
                return instance
                    .identity_store_id()
                    .ok_or_else(|| {
                        AwsIdcError::InstanceResolution(
                            "Instance has no identity_store_id".to_string(),
                        )
                    })
                    .map(|s| s.to_string());
            }
        }

        match output.next_token() {
            Some(t) if !t.is_empty() => {
                next_token = Some(t.to_string());
            }
            _ => break,
        }
    }

    Err(AwsIdcError::InstanceResolution(format!(
        "No Identity Center instance found matching ARN: {instance_arn}"
    )))
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

    #[test]
    fn test_extract_instance_id() {
        let arn =
            Arn::parse("arn:aws:sso::123456789012:application/ssoins-abc123/apl-xyz789").unwrap();
        assert_eq!(extract_instance_id(&arn).unwrap(), "ssoins-abc123");
    }

    #[test]
    fn test_extract_instance_id_invalid() {
        let arn = Arn::parse("arn:aws:iam::123456789012:role/MyRole").unwrap();
        assert!(extract_instance_id(&arn).is_err());
    }

    #[test]
    fn test_build_instance_arn() {
        let arn =
            Arn::parse("arn:aws:sso::123456789012:application/ssoins-abc123/apl-xyz789").unwrap();
        assert_eq!(
            build_instance_arn(&arn).unwrap(),
            "arn:aws:sso:::instance/ssoins-abc123"
        );
    }

    #[test]
    fn test_build_instance_arn_govcloud() {
        let arn =
            Arn::parse("arn:aws-us-gov:sso::123456789012:application/ssoins-abc/apl-xyz").unwrap();
        assert_eq!(
            build_instance_arn(&arn).unwrap(),
            "arn:aws-us-gov:sso:::instance/ssoins-abc"
        );
    }
}
