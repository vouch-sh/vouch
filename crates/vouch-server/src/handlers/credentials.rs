// SPDX-License-Identifier: BUSL-1.1
//! Credential issuance handlers (SSH certificates, AWS tokens, GitHub tokens, etc.).

use crate::AppState;
use crate::db::{self, GitHubCredentialEventParams};
use crate::services::integrations::aws::{AwsError, issue_aws_token};
use crate::services::integrations::github::{GitHubInstallationId, minimal_git_permissions};
use axum::{Json, extract::State, http::StatusCode};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::CookieJar;
use headers::authorization::{Authorization, Bearer};
use jiff::Timestamp;
use secrecy::ExposeSecret;
use serde::Serialize;
use std::sync::Arc;
use vouch_common::{
    ApiError, AwsTokenResponse, GitHubStatusResponse, GitHubTokenRequest, GitHubTokenResponse,
    SshCaPublicKeyResponse, SshCertificateRequest, SshCertificateResponse,
};

use super::session::extract_session;
use super::{extract_session_with_email, json_error};
use crate::redact_email;

/// Issue an SSH certificate for the authenticated user.
///
/// POST /v1/credentials/ssh
///
/// Requires Bearer token authentication. Signs the provided SSH public key
/// as a user certificate with principals extracted from the user's email.
pub async fn issue_ssh_certificate(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Json(request): Json<SshCertificateRequest>,
) -> Result<Json<SshCertificateResponse>, (StatusCode, Json<ApiError>)> {
    // Validate session
    let (_claims, user_email) = extract_session_with_email(&state, auth_header, &jar).await?;

    // Get SSH CA
    let ssh_ca = state.ssh_ca.as_ref().ok_or_else(|| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ssh_ca_not_configured",
            "SSH Certificate Authority is not configured",
        )
    })?;

    // Certificate validity matches session duration
    let valid_seconds = state.config().session_hours * 3600;

    // Sign the certificate
    let signed = ssh_ca
        .sign_certificate(&request.public_key, &user_email, valid_seconds)
        .map_err(|e| {
            tracing::warn!(
                "Failed to sign SSH certificate for {}: {}",
                redact_email(&user_email),
                e
            );
            json_error(
                StatusCode::BAD_REQUEST,
                "signing_failed",
                &format!("Failed to sign certificate: {e}"),
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
) -> Result<Json<SshCaPublicKeyResponse>, (StatusCode, Json<ApiError>)> {
    let ssh_ca = state.ssh_ca.as_ref().ok_or_else(|| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ssh_ca_not_configured",
            "SSH Certificate Authority is not configured",
        )
    })?;

    let public_key = ssh_ca.public_key().map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "key_error",
            &format!("Failed to get CA public key: {e}"),
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
    pub generated_at: String,
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
) -> Result<Json<SshKrlResponse>, (StatusCode, Json<ApiError>)> {
    // Get all revoked certificates
    let certs = db::get_revoked_ssh_certificates(&state.db)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &format!("Failed to get revoked certificates: {e}"),
            )
        })?;

    let revoked_serials: Vec<String> = certs.into_iter().map(|c| c.serial).collect();
    let total = revoked_serials.len();

    Ok(Json(SshKrlResponse {
        revoked_serials,
        total,
        generated_at: Timestamp::now().to_string(),
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
) -> Result<Json<SshRevocationCheckResponse>, (StatusCode, Json<ApiError>)> {
    let revoked = db::is_ssh_certificate_revoked(&state.db, &serial)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &format!("Failed to check revocation: {e}"),
            )
        })?;

    Ok(Json(SshRevocationCheckResponse {
        serial,
        revoked,
        checked_at: Timestamp::now().to_string(),
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
    pub checked_at: String,
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
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
) -> Result<Json<AwsTokenResponse>, (StatusCode, Json<ApiError>)> {
    // Validate session
    let (claims, user_email) = extract_session_with_email(&state, auth_header, &jar).await?;

    // Get user's organization domain (hd claim) if they belong to an org
    let hd = get_user_org_domain(&state, &claims.sub).await?;

    // Issue AWS token
    let config = state.config();
    let result = issue_aws_token(
        &state.db,
        &config.base_url,
        config.session_hours,
        &state.oidc_key,
        &user_email,
        claims.authenticator_id.as_deref(),
        hd,
    )
    .await
    .map_err(|e| match e {
        AwsError::NoAuthenticator => {
            json_error(StatusCode::FORBIDDEN, "no_authenticator", &e.to_string())
        }
        AwsError::Database(ref err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &err.to_string(),
        ),
        AwsError::ClaimsBuild(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "claims_error",
            &e.to_string(),
        ),
        AwsError::TokenSign(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "token_error",
            &e.to_string(),
        ),
    })?;

    Ok(Json(AwsTokenResponse {
        id_token: result.id_token,
        expires_in: result.expires_in,
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the user's organization domain (hd claim) if they belong to an organization.
///
/// This looks up the user by ID, then fetches their organization's domain
/// which is the Google Workspace hosted domain (hd claim) from their OIDC enrollment.
async fn get_user_org_domain(
    state: &AppState,
    user_id: &str,
) -> Result<Option<String>, (StatusCode, Json<ApiError>)> {
    // Get user to find their org_id
    let user = db::get_user_by_id(&state.db, user_id).await.map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    // If user has an org, get the org's domain
    if let Some(user) = user
        && let Some(org_id) = user.org_id
    {
        let domain = db::get_organization_domain(&state.db, &org_id)
            .await
            .map_err(|e| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    &e.to_string(),
                )
            })?;
        return Ok(domain);
    }

    Ok(None)
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
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
) -> Result<Json<GitHubStatusResponse>, (StatusCode, Json<ApiError>)> {
    // Validate session
    let session = extract_session(&state, auth_header, &jar).await?;

    // Get user
    let user = db::get_user_by_id(&state.db, &session.claims.sub)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "user_not_found", "User not found"))?;

    // Check if GitHub App is configured
    let configured = state.github_app.is_some();

    // Get all GitHub installations for user's organization
    let github_accounts = if let Some(org_id) = &user.org_id {
        db::get_github_installations_by_org(&state.db, org_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|i| {
                let repositories: Option<Vec<String>> = i
                    .repositories
                    .as_deref()
                    .and_then(|r| serde_json::from_str(r).ok());
                vouch_common::GitHubAccountStatus {
                    login: i.github_account_login,
                    account_type: i.github_account_type,
                    suspended: i.suspended_at.is_some(),
                    repository_selection: i.repository_selection,
                    repositories,
                }
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
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    Json(request): Json<GitHubTokenRequest>,
) -> Result<Json<GitHubTokenResponse>, (StatusCode, Json<ApiError>)> {
    // Validate session
    let session = extract_session(&state, auth_header, &jar).await?;

    // Get user
    let user = db::get_user_by_id(&state.db, &session.claims.sub)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "user_not_found", "User not found"))?;

    // Get client info for audit log
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(String::from);

    // Verify GitHub App is configured
    let github_app = state.github_app.as_ref().ok_or_else(|| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "github_not_configured",
            "GitHub App is not configured",
        )
    })?;

    // Verify user has an organization
    let org_id = user.org_id.as_ref().ok_or_else(|| {
        json_error(
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
        db::get_github_installation_by_org_and_account(&state.db, org_id, owner)
            .await
            .map_err(|e| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    &e.to_string(),
                )
            })?
            .ok_or_else(|| {
                json_error(
                    StatusCode::NOT_FOUND,
                    "github_not_connected",
                    &format!("GitHub account '{}' is not connected", owner),
                )
            })?
    } else {
        // No specific owner - get all installations and require exactly one
        let installations = db::get_github_installations_by_org(&state.db, org_id)
            .await
            .map_err(|e| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    &e.to_string(),
                )
            })?;

        if installations.is_empty() {
            return Err(json_error(
                StatusCode::NOT_FOUND,
                "github_not_connected",
                "Organization has not connected GitHub",
            ));
        } else if installations.len() == 1 {
            installations.into_iter().next().ok_or_else(|| {
                json_error(
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
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "owner_required",
                &format!(
                    "Multiple GitHub accounts connected. Specify 'owner': {}",
                    accounts.join(", ")
                ),
            ));
        }
    };

    // Check if installation is suspended
    if installation.suspended_at.is_some() {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "installation_suspended",
            "GitHub installation is suspended",
        ));
    }

    // Get scoped token with minimal permissions
    let permissions = minimal_git_permissions();
    let token = github_app
        .get_installation_token(
            GitHubInstallationId(u64::try_from(installation.installation_id).map_err(|_| {
                json_error(
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
            json_error(
                StatusCode::BAD_GATEWAY,
                "github_error",
                "Failed to get GitHub token",
            )
        })?;

    // Calculate expires_in from expires_at
    let expires_at_ts: Timestamp = token.expires_at.parse().unwrap_or_else(|e| {
        tracing::warn!(
            "Failed to parse token expires_at '{}': {e}",
            token.expires_at
        );
        Timestamp::now()
    });
    let now = Timestamp::now();
    let expires_in = expires_at_ts
        .as_second()
        .saturating_sub(now.as_second())
        .max(0) as u64;

    // Serialize repositories for audit log
    let repos_json = request
        .repositories
        .as_ref()
        .map(|r| serde_json::to_string(r).unwrap_or_default());
    let perms_json = serde_json::to_string(&token.permissions).unwrap_or_default();

    // Log audit event
    if let Err(e) = db::log_github_credential_event(
        &state.db,
        GitHubCredentialEventParams {
            event_type: "token_issued",
            user_id: &user.id,
            user_email: &user.email,
            org_id: Some(org_id),
            installation_id: Some(installation.installation_id),
            session_id: None, // Session ID not stored in JWT claims
            authenticator_id: session.claims.authenticator_id.as_deref(),
            repositories: repos_json.as_deref(),
            permissions: Some(&perms_json),
            token_expires_at: Some(&token.expires_at),
            success: true,
            error_code: None,
            ip_address: ip_address.as_deref(),
            user_agent: user_agent.as_deref(),
        },
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
    let repositories = token
        .repositories
        .map(|repos| repos.into_iter().map(|r| r.full_name).collect());

    Ok(Json(GitHubTokenResponse {
        token: token.token.expose_secret().to_string(),
        expires_at: token.expires_at,
        expires_in,
        permissions: token.permissions,
        repositories,
    }))
}
