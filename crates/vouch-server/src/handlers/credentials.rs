// SPDX-License-Identifier: BUSL-1.1
//! Credential issuance handlers (SSH certificates, AWS tokens, GitHub tokens, etc.).

use crate::AppState;
use crate::db;
use crate::db::documents::audit::{GitHubCredentialAuditData, IdcCredentialAuditData};
use crate::services::error::ServiceError;
use crate::services::integrations::aws::{AwsError, issue_aws_token};
use crate::services::integrations::github::{GitHubInstallationId, minimal_git_permissions};
use axum::extract::OriginalUri;
use axum::http::Method;
use axum::{Json, extract::State, http::HeaderMap, http::StatusCode};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use serde::Serialize;
use std::sync::Arc;
use vouch_common::{
    AwsTokenResponse, GitHubStatusResponse, GitHubTokenRequest, GitHubTokenResponse,
    SshCaPublicKeyResponse, SshCertificateRequest, SshCertificateResponse,
};

use super::extractors::ClientInfo;
use super::session::{extract_resource_token, extract_resource_token_with_email};
use crate::redact_email;

/// Issue an SSH certificate for the authenticated user.
///
/// POST /v1/credentials/ssh
///
/// Requires Bearer token authentication. Signs the provided SSH public key
/// as a user certificate with principals extracted from the user's email.
pub async fn issue_ssh_certificate(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Json(request): Json<SshCertificateRequest>,
) -> Result<Json<SshCertificateResponse>, ServiceError> {
    // Check config before auth — zero-cost in-memory check avoids DB queries
    if state.ssh_ca.is_none() {
        return Err(ServiceError::api(
            StatusCode::SERVICE_UNAVAILABLE,
            "ssh_ca_not_configured",
            "SSH Certificate Authority is not configured",
        ));
    }

    // Validate token and get user email
    let (_token, user_email) =
        extract_resource_token_with_email(&state, &headers, &jar, method.as_str(), uri.path())
            .await?;

    // Certificate validity matches session duration
    let valid_seconds = state.config().session_hours * 3600;

    // Sign the certificate on a blocking thread to avoid deadlocking
    // the tokio runtime. The ssh-key crate's sign path uses
    // std::thread::scope + block_on internally, which blocks the
    // current worker thread. On a 1-vCPU instance (1 worker thread),
    // this deadlocks because hyper's I/O driver can't make progress.
    let state_clone = state.clone();
    let public_key = request.public_key.clone();
    let email = user_email.clone();
    let signed = tokio::task::spawn_blocking(move || {
        let ssh_ca = state_clone
            .ssh_ca
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SSH CA not configured"))?;
        ssh_ca.sign_certificate(&public_key, &email, valid_seconds)
    })
    .await
    .map_err(|e| {
        tracing::error!("SSH signing task panicked: {e}");
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "signing_failed",
            "Failed to sign certificate",
        )
    })?
    .map_err(|e| {
        tracing::warn!(
            "Failed to sign SSH certificate for {}: {}",
            redact_email(&user_email),
            e
        );
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "signing_failed",
            "Failed to sign certificate",
        )
    })?;

    tracing::info!(
        "Issued SSH certificate for {} with principals {:?}, serial {}",
        redact_email(&user_email),
        signed.principals,
        signed.serial
    );

    Ok(Json(SshCertificateResponse {
        certificate: signed.certificate,
        valid_for_seconds: signed.valid_for_seconds,
        principals: signed.principals,
        serial: signed.serial,
    }))
}

/// Get the SSH CA public key.
///
/// GET /v1/credentials/ssh/ca
///
/// Returns the CA public key in OpenSSH format. This key should be added
/// to SSH server configurations to trust certificates signed by this CA.
pub async fn get_ssh_ca_public_key(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SshCaPublicKeyResponse>, ServiceError> {
    let ssh_ca = state.ssh_ca.as_ref().ok_or_else(|| {
        ServiceError::api(
            StatusCode::SERVICE_UNAVAILABLE,
            "ssh_ca_not_configured",
            "SSH Certificate Authority is not configured",
        )
    })?;

    let public_key = ssh_ca.public_key().map_err(|e| {
        tracing::error!("Failed to get CA public key: {e}");
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "key_error",
            "Failed to get CA public key",
        )
    })?;

    Ok(Json(SshCaPublicKeyResponse {
        public_key,
        comment: ssh_ca.public_key_comment(),
    }))
}

// ============================================================================
// SSH Certificate Revocation
// ============================================================================

/// Response for SSH KRL (Key Revocation List) endpoint.
#[derive(Debug, Serialize)]
pub struct SshKrlResponse {
    /// List of revoked certificate serials.
    pub revoked_serials: Vec<String>,
    /// Total number of revoked certificates.
    pub total: usize,
    /// Timestamp when the list was generated.
    pub generated_at: Timestamp,
}

/// Get the SSH Key Revocation List.
///
/// GET /v1/credentials/ssh/krl
///
/// Returns a list of revoked SSH certificate serials. SSH servers can use
/// this to check if a certificate has been revoked.
///
/// This endpoint does not require authentication to allow SSH servers
/// to check revocation status without needing credentials.
pub async fn get_ssh_krl(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SshKrlResponse>, ServiceError> {
    // Get all revoked certificates
    let certs = db::get_revoked_ssh_certificates(&state.store)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get revoked certificates: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Failed to retrieve revoked certificates",
            )
        })?;

    let revoked_serials: Vec<String> = certs.into_iter().map(|c| c.serial).collect();
    let total = revoked_serials.len();

    Ok(Json(SshKrlResponse {
        revoked_serials,
        total,
        generated_at: Timestamp::now(),
    }))
}

/// Check if a specific SSH certificate serial is revoked.
///
/// GET /v1/credentials/ssh/krl/:serial
///
/// Returns whether the certificate with the given serial is revoked.
pub async fn check_ssh_revocation(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(serial): axum::extract::Path<String>,
) -> Result<Json<SshRevocationCheckResponse>, ServiceError> {
    // Validate serial format before DB query.
    // SSH certificate serials are unsigned 64-bit integers (RFC 4253).
    if serial.is_empty() || serial.len() > 20 || !serial.chars().all(|c| c.is_ascii_digit()) {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_serial",
            "Serial must be a numeric string (u64)",
        ));
    }

    let revoked = db::is_ssh_certificate_revoked(&state.store, &serial)
        .await
        .map_err(|e| {
            tracing::error!("Failed to check revocation status: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Failed to check revocation status",
            )
        })?;

    Ok(Json(SshRevocationCheckResponse {
        serial,
        revoked,
        checked_at: Timestamp::now(),
    }))
}

/// Response for SSH revocation check.
#[derive(Debug, Serialize)]
pub struct SshRevocationCheckResponse {
    /// The certificate serial that was checked.
    pub serial: String,
    /// Whether the certificate is revoked.
    pub revoked: bool,
    /// Timestamp when the check was performed.
    pub checked_at: Timestamp,
}

// ============================================================================
// AWS Token Endpoint
// ============================================================================

/// Get an OIDC ID token for AWS STS AssumeRoleWithWebIdentity.
///
/// GET /v1/credentials/aws/token
///
/// Returns an OIDC ID token that can be used with AWS STS to assume a role.
/// The AWS IAM role must be configured to trust the Vouch OIDC provider.
pub async fn get_aws_token(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> Result<Json<AwsTokenResponse>, ServiceError> {
    // Single auth + user lookup (avoids duplicate get_user_by_id)
    let token = extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    // Get user record once — extract both email and org_id
    let user = db::get_user_by_id(&state.store, &token.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user by ID: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "user_not_found", "User not found")
        })?;

    let user_email = token.email.clone().unwrap_or_else(|| user.email.clone());

    // Get user's organization domain (hd claim) if they belong to an org
    let hd = if let Some(ref org_id) = user.org_id {
        db::get_organization_domain(&state.store, org_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get organization domain: {e}");
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    "Internal database error",
                )
            })?
    } else {
        None
    };

    // Issue AWS token
    let config = state.config();
    let result = issue_aws_token(
        &state.store,
        &config.base_url,
        config.session_hours,
        &state.oidc_key,
        &user_email,
        token.authenticator_id.as_deref(),
        hd,
    )
    .await
    .map_err(|e| match e {
        AwsError::NoAuthenticator => {
            ServiceError::api(StatusCode::FORBIDDEN, "no_authenticator", e.to_string())
        }
        AwsError::Database(ref err) => {
            tracing::error!("AWS token database error: {err}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        }
        AwsError::ClaimsBuild(ref err) => {
            tracing::error!("AWS token claims build error: {err}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "claims_error",
                "Failed to build token claims",
            )
        }
        AwsError::TokenSign(ref err) => {
            tracing::error!("AWS token signing error: {err}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "token_error",
                "Failed to sign token",
            )
        }
    })?;

    Ok(Json(AwsTokenResponse {
        id_token: result.id_token,
        expires_in: result.expires_in,
    }))
}

// ============================================================================
// AWS Identity Center Discovery Endpoint
// ============================================================================

/// Discover all accounts and roles available via Identity Center.
///
/// GET /v1/credentials/aws-idc/discover
///
/// Performs a single server-side token exchange, lists all accounts, then
/// concurrently lists roles for each account. The SSO access token never
/// leaves the server.
pub async fn discover_aws_idc(
    method: Method,
    uri: OriginalUri,
    client_info: ClientInfo,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> Result<Json<vouch_common::IdcDiscoveryResponse>, ServiceError> {
    let (token, user_email, hd, org_id) =
        extract_idc_context(&state, &headers, &jar, &method, &uri).await?;

    let config = state.config();
    let ctx = crate::services::integrations::aws_idc::IdcContext {
        store: &state.store,
        base_url: &config.base_url,
        session_hours: config.session_hours,
        oidc_key: &state.oidc_key,
        user_email: &user_email,
        authenticator_id: token.authenticator_id.as_deref(),
        hd,
        org_id: &org_id,
    };
    let result = crate::services::integrations::aws_idc::discover_accounts_and_roles(&ctx)
        .await
        .map_err(map_idc_error)?;

    if let Err(e) = log_idc_credential_event(
        &state,
        &token.sub,
        &user_email,
        IdcCredentialAuditData {
            event_type: "account_discovery".to_string(),
            org_id: Some(org_id),
            authenticator_id: token.authenticator_id.clone(),
            success: true,
            user_agent: client_info.user_agent,
            ..Default::default()
        },
        client_info.client_ip,
    )
    .await
    {
        tracing::warn!("Failed to log IdC discovery event: {e}");
    }

    Ok(Json(result))
}

// ============================================================================
// AWS Identity Center SSO Token Endpoint
// ============================================================================

/// Get an SSO access token via Identity Center.
///
/// POST /v1/credentials/aws-idc/sso-token
///
/// Performs the server-side exchange:
/// OIDC token → STS bootstrap → `CreateTokenWithIAM` → SSO access token.
/// The CLI writes the token to `~/.aws/sso/cache/` for native AWS tool use.
pub async fn get_aws_idc_sso_token(
    method: Method,
    uri: OriginalUri,
    client_info: ClientInfo,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> Result<Json<vouch_common::IdcTokenResponse>, ServiceError> {
    let (token, user_email, hd, org_id) =
        extract_idc_context(&state, &headers, &jar, &method, &uri).await?;

    let config = state.config();
    let ctx = crate::services::integrations::aws_idc::IdcContext {
        store: &state.store,
        base_url: &config.base_url,
        session_hours: config.session_hours,
        oidc_key: &state.oidc_key,
        user_email: &user_email,
        authenticator_id: token.authenticator_id.as_deref(),
        hd,
        org_id: &org_id,
    };
    let result = crate::services::integrations::aws_idc::exchange_for_idc_token(&ctx)
        .await
        .map_err(map_idc_error)?;

    // Audit log
    if let Err(e) = log_idc_credential_event(
        &state,
        &token.sub,
        &user_email,
        IdcCredentialAuditData {
            event_type: "sso_token_issued".to_string(),
            org_id: Some(org_id),
            authenticator_id: token.authenticator_id.clone(),
            success: true,
            user_agent: client_info.user_agent,
            ..Default::default()
        },
        client_info.client_ip,
    )
    .await
    {
        tracing::warn!("Failed to log IdC credential event: {e}");
    }

    Ok(Json(vouch_common::IdcTokenResponse {
        access_token: result.access_token,
        expires_in: result.expires_in,
        region: result.region,
    }))
}

/// Extract auth context needed by all IdC handlers.
///
/// Returns `(token, user_email, hd, org_id)`.
async fn extract_idc_context(
    state: &AppState,
    headers: &HeaderMap,
    jar: &CookieJar,
    method: &Method,
    uri: &OriginalUri,
) -> Result<
    (
        super::session::ValidatedResourceToken,
        String,
        Option<String>,
        String,
    ),
    ServiceError,
> {
    let token = extract_resource_token(state, headers, jar, method.as_str(), uri.path()).await?;

    let user = db::get_user_by_id(&state.store, &token.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user by ID: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "user_not_found", "User not found")
        })?;

    let org_id = user
        .org_id
        .as_ref()
        .ok_or_else(|| {
            ServiceError::api(
                StatusCode::FORBIDDEN,
                "org_required",
                "Identity Center requires organizational membership",
            )
        })?
        .clone();

    let user_email = token.email.clone().unwrap_or_else(|| user.email.clone());

    let hd = db::get_organization_domain(&state.store, &org_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get organization domain: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    Ok((token, user_email, hd, org_id))
}

/// Map `AwsIdcError` to `ServiceError` for HTTP responses.
///
/// Shared across all IdC credential handlers.
fn map_idc_error(e: crate::services::integrations::aws_idc::AwsIdcError) -> ServiceError {
    use crate::services::integrations::aws_idc::AwsIdcError;
    match e {
        AwsIdcError::NotConfigured | AwsIdcError::MissingField(_) | AwsIdcError::InvalidArn(_) => {
            ServiceError::api(StatusCode::NOT_FOUND, "idc_not_configured", e.to_string())
        }
        AwsIdcError::OidcToken(ref aws_err) => {
            tracing::error!("IdC OIDC token error: {aws_err}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "oidc_token_error",
                "Failed to issue OIDC token",
            )
        }
        AwsIdcError::StsAssume(ref msg) => {
            tracing::error!("IdC STS bootstrap error: {msg}");
            ServiceError::api(
                StatusCode::BAD_GATEWAY,
                "sts_error",
                "Failed to bootstrap IAM credentials",
            )
        }
        AwsIdcError::UserNotInIdentityCenter => {
            tracing::warn!("IdC user not found in Identity Center");
            ServiceError::api(
                StatusCode::FORBIDDEN,
                "idc_user_not_found",
                "Your account was not found in Identity Center. \
                 Ask your administrator to create your user in Identity Center \
                 and assign it to the Vouch application.",
            )
        }
        AwsIdcError::InvalidClient(ref msg) => {
            tracing::error!("IdC invalid client: {msg}");
            ServiceError::api(
                StatusCode::BAD_GATEWAY,
                "idc_invalid_client",
                "The Identity Center application is misconfigured. \
                 Check the application ARN and trusted token issuer settings.",
            )
        }
        AwsIdcError::AccessDenied(ref msg) => {
            tracing::error!("IdC access denied: {msg}");
            ServiceError::api(
                StatusCode::BAD_GATEWAY,
                "idc_access_denied",
                "Access denied by Identity Center. \
                 Check that the bootstrap role has permission to call \
                 CreateTokenWithIAM on the application.",
            )
        }
        AwsIdcError::CreateToken(ref msg) => {
            tracing::error!("IdC CreateTokenWithIAM error: {msg}");
            ServiceError::api(
                StatusCode::BAD_GATEWAY,
                "idc_token_error",
                "Failed to exchange token with Identity Center",
            )
        }
        AwsIdcError::ListAccounts(ref msg) => {
            tracing::error!("IdC ListAccounts error: {msg}");
            ServiceError::api(
                StatusCode::BAD_GATEWAY,
                "idc_list_accounts_error",
                "Failed to list accounts from Identity Center",
            )
        }
        AwsIdcError::ListAccountRoles(ref msg) => {
            tracing::error!("IdC ListAccountRoles error: {msg}");
            ServiceError::api(
                StatusCode::BAD_GATEWAY,
                "idc_list_roles_error",
                "Failed to list account roles from Identity Center",
            )
        }
        AwsIdcError::Database(ref err) => {
            tracing::error!("IdC database error: {err}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        }
    }
}

/// Log an IdC credential audit event.
async fn log_idc_credential_event(
    state: &AppState,
    user_id: &str,
    user_email: &str,
    mut data: IdcCredentialAuditData,
    ip: Option<std::net::IpAddr>,
) -> anyhow::Result<String> {
    data.ip_address = ip.map(|a| a.to_string());
    let geo = ip.and_then(crate::geo::lookup);
    data.country_code = geo.as_ref().map(|g| g.country_code.clone());
    data.asn = geo.as_ref().and_then(|g| g.asn);
    data.org_name = geo.as_ref().and_then(|g| g.org_name.clone());
    let data_json = serde_json::to_string(&data)?;

    state
        .audit
        .insert_event(
            "idc_credential",
            Some(user_id),
            Some(user_email),
            &data_json,
        )
        .await
}

// ============================================================================
// GitHub Token Endpoint
// ============================================================================

/// Get the GitHub integration status.
///
/// GET /v1/credentials/github/status
///
/// Returns whether GitHub is configured and connected for the user's organization.
pub async fn get_github_status(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> Result<Json<GitHubStatusResponse>, ServiceError> {
    // Validate token
    let token = extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    // Get user
    let user = db::get_user_by_id(&state.store, &token.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user by ID: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "user_not_found", "User not found")
        })?;

    // Check if GitHub App is configured
    let configured = state.github_app.is_some();

    // Get all GitHub installations for user's organization
    let github_accounts = if let Some(org_id) = &user.org_id {
        db::get_github_installations_by_org(&state.store, org_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get GitHub installations for org {org_id}: {e}");
            })
            .unwrap_or_default()
            .into_iter()
            .map(|i| vouch_common::GitHubAccountStatus {
                login: i.github_account_login,
                account_type: i.github_account_type,
                suspended: i.suspended_at.is_some(),
                repository_selection: i.repository_selection,
                repositories: i.repositories,
            })
            .collect()
    } else {
        Vec::new()
    };

    let connected = !github_accounts.is_empty();

    Ok(Json(GitHubStatusResponse {
        configured,
        connected,
        github_accounts,
    }))
}

/// Get a GitHub installation access token.
///
/// POST /v1/credentials/github/token
///
/// Returns a short-lived GitHub installation access token that can be used
/// with Git operations. The token is scoped to the user's organization's
/// GitHub installation with minimal permissions (contents:write, metadata:read).
pub async fn get_github_token(
    method: Method,
    uri: OriginalUri,
    client_info: ClientInfo,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Json(request): Json<GitHubTokenRequest>,
) -> Result<Json<GitHubTokenResponse>, ServiceError> {
    // Check config before auth — zero-cost in-memory check avoids DB queries
    let github_app = state.github_app.as_ref().ok_or_else(|| {
        ServiceError::api(
            StatusCode::SERVICE_UNAVAILABLE,
            "github_not_configured",
            "GitHub App is not configured",
        )
    })?;

    // Validate token
    let token = extract_resource_token(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    // Get user
    let user = db::get_user_by_id(&state.store, &token.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user by ID: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "user_not_found", "User not found")
        })?;

    // Verify user has an organization
    let org_id = user.org_id.as_ref().ok_or_else(|| {
        ServiceError::api(
            StatusCode::FORBIDDEN,
            "org_required",
            "GitHub requires organizational membership",
        )
    })?;

    // Determine which GitHub account to use
    // Priority: explicit owner > inferred from repositories > only one connected
    let github_owner = request.owner.clone().or_else(|| {
        // Try to infer from repositories (format: "owner/repo")
        request.repositories.as_ref().and_then(|repos| {
            repos
                .first()
                .and_then(|r| r.split('/').next().map(String::from))
        })
    });

    // Look up installation
    let installation = if let Some(owner) = &github_owner {
        // Specific owner requested
        db::get_github_installation_by_org_and_account(&state.store, org_id, owner)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Failed to get GitHub installation for org {org_id} account {owner}: {e}"
                );
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    "Internal database error",
                )
            })?
            .ok_or_else(|| {
                ServiceError::api(
                    StatusCode::NOT_FOUND,
                    "github_not_connected",
                    format!("GitHub account '{}' is not connected", owner),
                )
            })?
    } else {
        // No specific owner - get all installations and require exactly one
        let installations = db::get_github_installations_by_org(&state.store, org_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get GitHub installations for org {org_id}: {e}");
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    "Internal database error",
                )
            })?;

        if installations.is_empty() {
            return Err(ServiceError::api(
                StatusCode::NOT_FOUND,
                "github_not_connected",
                "Organization has not connected GitHub",
            ));
        } else if installations.len() == 1 {
            installations.into_iter().next().ok_or_else(|| {
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Unexpected empty installations",
                )
            })?
        } else {
            let accounts: Vec<_> = installations
                .iter()
                .map(|i| i.github_account_login.as_str())
                .collect();
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "owner_required",
                format!(
                    "Multiple GitHub accounts connected. Specify 'owner': {}",
                    accounts.join(", ")
                ),
            ));
        }
    };

    // Check if installation is suspended
    if installation.suspended_at.is_some() {
        return Err(ServiceError::api(
            StatusCode::FORBIDDEN,
            "installation_suspended",
            "GitHub installation is suspended",
        ));
    }

    // Get scoped token with minimal permissions
    let permissions = minimal_git_permissions();
    let gh_token = github_app
        .get_installation_token(
            GitHubInstallationId(u64::try_from(installation.installation_id).map_err(|_| {
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid_installation",
                    "Invalid installation ID",
                )
            })?),
            request.repositories.as_deref(),
            Some(&permissions),
        )
        .await
        .map_err(|e| {
            tracing::warn!(
                "Failed to get GitHub token for {} (org {}): {}",
                redact_email(&user.email),
                org_id,
                e
            );
            ServiceError::api(
                StatusCode::BAD_GATEWAY,
                "github_error",
                "Failed to get GitHub token",
            )
        })?;

    // Calculate expires_in from expires_at
    let expires_at: Timestamp = gh_token.expires_at.parse().unwrap_or_else(|e| {
        tracing::warn!(
            "Failed to parse token expires_at '{}': {e}",
            gh_token.expires_at
        );
        Timestamp::now()
    });
    let now = Timestamp::now();
    let expires_in = expires_at
        .as_second()
        .saturating_sub(now.as_second())
        .max(0) as u64;

    // Log audit event
    if let Err(e) = db::log_github_credential_event(
        &state.audit,
        &user.id,
        &user.email,
        GitHubCredentialAuditData {
            event_type: "token_issued".to_string(),
            org_id: Some(org_id.to_string()),
            installation_id: Some(installation.installation_id),
            authenticator_id: token.authenticator_id.clone(),
            repositories: request.repositories.clone(),
            permissions: Some(gh_token.permissions.clone()),
            token_expires_at: Some(gh_token.expires_at.clone()),
            success: true,
            user_agent: client_info.user_agent,
            ..Default::default()
        },
        client_info.client_ip,
    )
    .await
    {
        tracing::warn!("Failed to log GitHub credential event: {e}");
    }

    tracing::info!(
        "Issued GitHub token for {} (org {}, installation {})",
        redact_email(&user.email),
        org_id,
        installation.installation_id
    );

    // Build response with repository names if scoped
    let repositories = gh_token
        .repositories
        .map(|repos| repos.into_iter().map(|r| r.full_name).collect());

    Ok(Json(GitHubTokenResponse {
        token: gh_token.token,
        expires_at,
        expires_in,
        permissions: gh_token.permissions,
        repositories,
    }))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use crate::test_utils::*;
    use axum::http::StatusCode;

    // ========================================================================
    // SSH Serial Validation Tests — Positive
    // ========================================================================

    #[tokio::test]
    async fn test_ssh_serial_valid_numeric() {
        // A valid numeric serial should pass validation (returning 200, not 400)
        let (app, _state) = test_app().await;

        let (status, _body) = http_get(&app, "/v1/credentials/ssh/krl/12345", &[]).await;

        // Should not be 400 — the serial format is valid
        assert_ne!(
            status,
            StatusCode::BAD_REQUEST,
            "Valid numeric serial should pass validation"
        );
    }

    #[tokio::test]
    async fn test_ssh_serial_valid_max_u64() {
        // Maximum u64 value (20 digits) should be accepted
        let (app, _state) = test_app().await;

        let (status, _body) =
            http_get(&app, "/v1/credentials/ssh/krl/18446744073709551615", &[]).await;

        assert_ne!(
            status,
            StatusCode::BAD_REQUEST,
            "Max u64 serial should pass validation"
        );
    }

    #[tokio::test]
    async fn test_ssh_serial_valid_zero() {
        let (app, _state) = test_app().await;

        let (status, _body) = http_get(&app, "/v1/credentials/ssh/krl/0", &[]).await;

        assert_ne!(
            status,
            StatusCode::BAD_REQUEST,
            "Zero serial should pass validation"
        );
    }

    // ========================================================================
    // SSH Serial Validation Tests — Negative
    // ========================================================================

    #[tokio::test]
    async fn test_ssh_serial_rejects_non_numeric() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/v1/credentials/ssh/krl/abc123", &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_serial");
    }

    #[tokio::test]
    async fn test_ssh_serial_rejects_too_long() {
        // 21 digits exceeds the 20-digit maximum for u64
        let (app, _state) = test_app().await;

        let (status, body) =
            http_get(&app, "/v1/credentials/ssh/krl/123456789012345678901", &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_serial");
    }

    #[tokio::test]
    async fn test_ssh_serial_rejects_negative() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/v1/credentials/ssh/krl/-1", &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_serial");
    }

    #[tokio::test]
    async fn test_ssh_serial_rejects_hex() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/v1/credentials/ssh/krl/0xDEADBEEF", &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_serial");
    }

    #[tokio::test]
    async fn test_ssh_serial_rejects_special_chars() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/v1/credentials/ssh/krl/123%3B456", &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_serial");
    }
}
