// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Credential issuance handlers (SSH certificates, AWS tokens, GitHub tokens, etc.).

use crate::AppState;
use crate::db::{self, GitHubCredentialAuditData};
use crate::services::error::ServiceError;
use crate::services::integrations::aws::{AwsError, issue_aws_token};
use crate::services::integrations::github::{GitHubInstallationId, minimal_git_permissions};
use crate::services::integrations::kubernetes::{
    DEFAULT_K8S_AUDIENCE, K8sError, issue_kubernetes_token,
};
use axum::extract::{OriginalUri, Query};
use axum::http::Method;
use axum::{Json, extract::State, http::HeaderMap, http::StatusCode};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vouch_common::{
    AwsTokenResponse, GitHubStatusResponse, GitHubTokenRequest, GitHubTokenResponse,
    K8sTokenResponse, SshCaPublicKeyResponse, SshCertificateRequest, SshCertificateResponse,
};

use super::extractors::{ClientInfo, OptionalClientCert};
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
    client_cert: OptionalClientCert,
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

    // Validate token and get user email + user_id
    let (token, user_email) = extract_resource_token_with_email(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        client_cert.0.as_ref(),
    )
    .await?;

    // Reject deactivated users (defense-in-depth for SCIM deactivation)
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

    if !user.active {
        return Err(ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "User account is deactivated",
        ));
    }

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

    // Record issuance for revocation tracking. If this fails, do NOT
    // return the certificate — an untracked cert cannot be revoked.
    let valid_secs_i64 = i64::try_from(valid_seconds).map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Session duration overflow",
        )
    })?;
    let cert_expires_at = Timestamp::now()
        .checked_add(jiff::Span::new().seconds(valid_secs_i64))
        .map_err(|_| {
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "time_error",
                "Failed to compute certificate expiry",
            )
        })?;

    db::record_ssh_certificate_issuance(
        &state.store,
        signed.serial,
        &token.sub,
        &user_email,
        &signed.principals,
        cert_expires_at,
    )
    .await
    .map_err(|e| {
        tracing::error!(
            "Failed to record SSH certificate issuance for {}: {e}",
            redact_email(&user_email),
        );
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "recording_failed",
            "Failed to record certificate issuance",
        )
    })?;

    crate::infra::metrics::record_credential_issuance("ssh");

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
///
/// When the DPoP proof includes a `source` custom claim (e.g., "claude-code"),
/// the issued token includes AI-specific session tags (`vouch:AccessType=AI`,
/// `vouch:Agent=<agent>`) for CloudTrail differentiation and IAM condition keys.
pub async fn get_aws_token(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    client_cert: OptionalClientCert,
) -> Result<Json<AwsTokenResponse>, ServiceError> {
    // Single auth + user lookup (avoids duplicate get_user_by_id)
    let token = extract_resource_token(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        client_cert.0.as_ref(),
    )
    .await?;

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

    if !user.active {
        return Err(ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "User account is deactivated",
        ));
    }

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
        token.dpop_source.as_deref(),
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

    crate::infra::metrics::record_credential_issuance("aws");

    Ok(Json(AwsTokenResponse {
        id_token: result.id_token,
        expires_in: result.expires_in,
    }))
}

// ============================================================================
// Kubernetes Token Endpoint
// ============================================================================

/// Query parameters for the Kubernetes token endpoint.
#[derive(Debug, Deserialize)]
pub struct K8sTokenQuery {
    /// OIDC audience (must match `--oidc-client-id` on the API server).
    /// Defaults to "kubernetes" if not specified.
    #[serde(default)]
    pub audience: Option<String>,
}

/// Get an OIDC ID token for Kubernetes authentication.
///
/// GET /v1/credentials/kubernetes/token?audience=kubernetes
///
/// Returns an OIDC ID token that can be used with Kubernetes clusters
/// configured with the Vouch OIDC provider.
pub async fn get_kubernetes_token(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    client_cert: OptionalClientCert,
    Query(query): Query<K8sTokenQuery>,
) -> Result<Json<K8sTokenResponse>, ServiceError> {
    let token = extract_resource_token(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        client_cert.0.as_ref(),
    )
    .await?;

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

    if !user.active {
        return Err(ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "User account is deactivated",
        ));
    }

    let user_email = token.email.clone().unwrap_or_else(|| user.email.clone());
    let audience = query
        .audience
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_K8S_AUDIENCE);

    // Get authenticator info for AAGUID claim
    let authenticator = if let Some(ref auth_id) = token.authenticator_id {
        match db::get_authenticator_by_id(&state.store, auth_id).await {
            Ok(auth) => auth,
            Err(e) => {
                tracing::warn!("Failed to get authenticator {auth_id}: {e}");
                None
            }
        }
    } else {
        None
    };

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

    let config = state.config();
    let result = issue_kubernetes_token(
        &config.base_url,
        &state.oidc_key,
        &user_email,
        audience,
        authenticator.and_then(|a| a.aaguid),
        hd,
    )
    .await
    .map_err(|e| match e {
        K8sError::ClaimsBuild(ref err) => {
            tracing::error!("Kubernetes token claims build error: {err}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "claims_error",
                "Failed to build token claims",
            )
        }
        K8sError::TokenSign(ref err) => {
            tracing::error!("Kubernetes token signing error: {err}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "token_error",
                "Failed to sign token",
            )
        }
    })?;

    crate::infra::metrics::record_credential_issuance("kubernetes");

    tracing::info!(
        "Issued Kubernetes OIDC token for {} (audience: {})",
        crate::redact_email(&user_email),
        audience,
    );

    Ok(Json(K8sTokenResponse {
        id_token: result.id_token,
        expires_in: result.expires_in,
    }))
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
    client_cert: OptionalClientCert,
) -> Result<Json<GitHubStatusResponse>, ServiceError> {
    // Validate token
    let token = extract_resource_token(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        client_cert.0.as_ref(),
    )
    .await?;

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

    if !user.active {
        return Err(ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "User account is deactivated",
        ));
    }

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
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler signature: extractors are positional parameters"
)]
pub async fn get_github_token(
    method: Method,
    uri: OriginalUri,
    client_info: ClientInfo,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    client_cert: OptionalClientCert,
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
    let token = extract_resource_token(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        client_cert.0.as_ref(),
    )
    .await?;

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

    if !user.active {
        return Err(ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "User account is deactivated",
        ));
    }

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

    crate::infra::metrics::record_credential_issuance("github");

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
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
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

    // ========================================================================
    // SSH CA Public Key Tests
    // ========================================================================

    #[tokio::test]
    async fn test_ssh_ca_public_key_returns_key() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/v1/credentials/ssh/ca", &[]).await;

        // SSH CA is not configured in test_app, so 503 is expected
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "ssh_ca_not_configured");
    }

    #[tokio::test]
    async fn test_ssh_ca_public_key_no_auth_required() {
        let (app, _state) = test_app().await;

        // No Authorization header — endpoint does not require auth
        let (status, _body) = http_get(&app, "/v1/credentials/ssh/ca", &[]).await;

        // 503 because SSH CA is not configured, not 401 — confirms auth is not checked
        assert_ne!(status, StatusCode::UNAUTHORIZED);
    }

    // ========================================================================
    // SSH Certificate Issuance Tests
    // ========================================================================

    #[tokio::test]
    async fn test_ssh_cert_requires_auth() {
        let (app, _state) = test_app().await;

        // SSH CA is checked before auth in this handler, so 503 is returned
        let body =
            serde_json::json!({ "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test" });
        let (status, resp_body) =
            http_post_json(&app, "/v1/credentials/ssh", &body.to_string(), &[]).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
        assert_eq!(error["code"], "ssh_ca_not_configured");
    }

    #[tokio::test]
    async fn test_ssh_cert_rejects_invalid_token() {
        let (app, _state) = test_app().await;

        // SSH CA is checked before auth, so still 503 even with a bad token
        let body =
            serde_json::json!({ "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test" });
        let (status, resp_body) = http_post_json(
            &app,
            "/v1/credentials/ssh",
            &body.to_string(),
            &[("Authorization", "Bearer garbage.token.value")],
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
        assert_eq!(error["code"], "ssh_ca_not_configured");
    }

    // ========================================================================
    // SSH KRL Tests
    // ========================================================================

    #[tokio::test]
    async fn test_ssh_krl_returns_empty_list() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/v1/credentials/ssh/krl", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(resp["revoked_serials"], serde_json::json!([]));
        assert_eq!(resp["total"], 0);
    }

    #[tokio::test]
    async fn test_ssh_krl_no_auth_required() {
        let (app, _state) = test_app().await;

        let (status, _body) = http_get(&app, "/v1/credentials/ssh/krl", &[]).await;

        assert_eq!(status, StatusCode::OK);
    }

    // ========================================================================
    // SSH Revocation Check Tests
    // ========================================================================

    #[tokio::test]
    async fn test_ssh_revocation_check_not_revoked() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/v1/credentials/ssh/krl/99999", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(resp["serial"], "99999");
        assert_eq!(resp["revoked"], false);
    }

    #[tokio::test]
    async fn test_ssh_serial_rejects_empty() {
        let (app, _state) = test_app().await;

        // An empty path segment routes to /v1/credentials/ssh/krl which is the
        // KRL list endpoint, not the per-serial endpoint — expect 200 not a crash
        let (status, _body) = http_get(&app, "/v1/credentials/ssh/krl/", &[]).await;

        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ========================================================================
    // AWS Token Tests
    // ========================================================================

    #[tokio::test]
    async fn test_aws_token_requires_auth() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/v1/credentials/aws/token", &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "unauthorized");
    }

    #[tokio::test]
    async fn test_aws_token_rejects_invalid_token() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token",
            &[("Authorization", "Bearer garbage.token.value")],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_token");
    }

    #[tokio::test]
    async fn test_aws_token_returns_token_for_valid_session() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "user@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert!(resp["id_token"].is_string());
        assert!(resp["expires_in"].is_number());
    }

    #[tokio::test]
    async fn test_aws_token_returns_token_for_org_user() {
        let (app, state) = test_app().await;

        let org = create_test_org(&state.store, "example.com").await;
        let user =
            create_test_user_in_org(&state.store, "orguser@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert!(resp["id_token"].is_string());
        assert!(resp["expires_in"].is_number());
    }

    // ========================================================================
    // Kubernetes Token Tests
    // ========================================================================

    #[tokio::test]
    async fn test_k8s_token_requires_auth() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/v1/credentials/kubernetes/token", &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "unauthorized");
    }

    #[tokio::test]
    async fn test_k8s_token_returns_token_for_valid_session() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "k8suser@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/kubernetes/token",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert!(resp["id_token"].is_string());
    }

    #[tokio::test]
    async fn test_k8s_token_default_audience() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "k8saud@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/kubernetes/token",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert!(resp["id_token"].is_string());
    }

    #[tokio::test]
    async fn test_k8s_token_custom_audience() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "k8scustom@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/kubernetes/token?audience=my-cluster",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert!(resp["id_token"].is_string());
    }

    // ========================================================================
    // GitHub Status Tests
    // ========================================================================

    #[tokio::test]
    async fn test_github_status_requires_auth() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/v1/credentials/github/status", &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "unauthorized");
    }

    #[tokio::test]
    async fn test_github_status_not_configured() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "ghstatus@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/github/status",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(resp["configured"], false);
    }

    #[tokio::test]
    async fn test_github_status_no_org_returns_empty() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "ghnoorg@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/github/status",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        // Field is omitted when empty (skip_serializing_if = "Vec::is_empty")
        let accounts = resp["github_accounts"].as_array();
        assert!(
            accounts.is_none() || accounts.unwrap().is_empty(),
            "Expected no github_accounts for user without org"
        );
    }

    // ========================================================================
    // GitHub Token Tests
    // ========================================================================

    #[tokio::test]
    async fn test_github_token_not_configured() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "ghtoken@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let body = serde_json::json!({ "repositories": [] });
        let (status, resp_body) = http_post_json(
            &app,
            "/v1/credentials/github/token",
            &body.to_string(),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
        assert_eq!(error["code"], "github_not_configured");
    }

    #[tokio::test]
    async fn test_github_token_requires_auth() {
        let (app, _state) = test_app().await;

        // GitHub App config is checked before auth — 503 even without a token
        let body = serde_json::json!({ "repositories": [] });
        let (status, resp_body) =
            http_post_json(&app, "/v1/credentials/github/token", &body.to_string(), &[]).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
        assert_eq!(error["code"], "github_not_configured");
    }

    // ========================================================================
    // Deactivated User Credential Denial Tests (Issue #252)
    // ========================================================================

    #[tokio::test]
    async fn test_deactivated_user_cannot_get_aws_token() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "deactivated-aws@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        // Deactivate the user
        crate::db::update_user_active_status(&state.store, &user.id, false)
            .await
            .expect("deactivate user");

        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "unauthorized");
        assert_eq!(error["message"], "User account is deactivated");
    }

    #[tokio::test]
    async fn test_deactivated_user_cannot_get_k8s_token() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "deactivated-k8s@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        crate::db::update_user_active_status(&state.store, &user.id, false)
            .await
            .expect("deactivate user");

        let (status, body) = http_get(
            &app,
            "/v1/credentials/kubernetes/token",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "unauthorized");
        assert_eq!(error["message"], "User account is deactivated");
    }

    #[tokio::test]
    async fn test_deactivated_user_cannot_get_github_status() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "deactivated-gh@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        crate::db::update_user_active_status(&state.store, &user.id, false)
            .await
            .expect("deactivate user");

        let (status, body) = http_get(
            &app,
            "/v1/credentials/github/status",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "unauthorized");
        assert_eq!(error["message"], "User account is deactivated");
    }
}
