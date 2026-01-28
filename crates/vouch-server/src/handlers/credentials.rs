// SPDX-License-Identifier: BUSL-1.1
//! Credential issuance handlers (SSH certificates, AWS tokens, GitHub tokens, etc.).

use crate::AppState;
use crate::db::{self, GitHubCredentialEventParams};
use crate::github_app::{GitHubInstallationId, minimal_git_permissions};
use axum::{Json, extract::State, http::StatusCode};
use axum_extra::TypedHeader;
use headers::authorization::{Authorization, Bearer};
use jiff::{Span, Timestamp};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vouch_common::{
    ApiError, AwsTokenResponse, GitHubStatusResponse, GitHubTokenRequest, GitHubTokenResponse,
    SshCaPublicKeyResponse, SshCertificateRequest, SshCertificateResponse,
};

use super::common::extract_session;
use super::{extract_session_with_email, json_error};

/// Issue an SSH certificate for the authenticated user.
///
/// POST /v1/credentials/ssh
///
/// Requires Bearer token authentication. Signs the provided SSH public key
/// as a user certificate with principals extracted from the user's email.
pub async fn issue_ssh_certificate(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    Json(request): Json<SshCertificateRequest>,
) -> Result<Json<SshCertificateResponse>, (StatusCode, Json<ApiError>)> {
    // Validate session
    let (_claims, user_email) = extract_session_with_email(&state, auth_header).await?;

    // Get SSH CA
    let ssh_ca = state.ssh_ca.as_ref().ok_or_else(|| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ssh_ca_not_configured",
            "SSH Certificate Authority is not configured",
        )
    })?;

    // Certificate validity matches session duration
    let valid_seconds = state.config.session_hours * 3600;

    // Sign the certificate
    let signed = ssh_ca
        .sign_certificate(&request.public_key, &user_email, valid_seconds)
        .map_err(|e| {
            tracing::warn!("Failed to sign SSH certificate for {}: {}", user_email, e);
            json_error(
                StatusCode::BAD_REQUEST,
                "signing_failed",
                &format!("Failed to sign certificate: {e}"),
            )
        })?;

    tracing::info!(
        "Issued SSH certificate for {} with principals {:?}, serial {}",
        user_email,
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

/// OIDC ID Token claims for AWS.
#[derive(Debug, Serialize, Deserialize)]
struct AwsIdTokenClaims {
    /// Issuer (Vouch server URL).
    iss: String,
    /// Subject (user email).
    sub: String,
    /// Audience (typically the AWS account or role).
    aud: String,
    /// Expiration time (Unix timestamp).
    exp: i64,
    /// Issued at time (Unix timestamp).
    iat: i64,
    /// User's email address.
    email: String,
    /// Email verified flag.
    email_verified: bool,
    /// Hardware verification flag.
    hardware_verified: bool,
    /// Hardware AAGUID (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_aaguid: Option<String>,
}

/// Get an OIDC ID token for AWS STS AssumeRoleWithWebIdentity.
///
/// GET /v1/credentials/aws/token
///
/// Returns an OIDC ID token that can be used with AWS STS to assume a role.
/// The AWS IAM role must be configured to trust the Vouch OIDC provider.
pub async fn get_aws_token(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<Json<AwsTokenResponse>, (StatusCode, Json<ApiError>)> {
    // Validate session
    let (claims, user_email) = extract_session_with_email(&state, auth_header).await?;

    // Get authenticator info for AAGUID
    let authenticator = db::get_authenticator_by_id(&state.db, &claims.authenticator_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    // Token validity matches session duration
    let expires_in = state.config.session_hours * 3600;

    // Calculate timestamps
    let now = Timestamp::now();
    let exp = now
        .checked_add(Span::new().seconds(i64::try_from(expires_in).unwrap_or(28800)))
        .map(|t| t.as_second())
        .unwrap_or(now.as_second() + i64::try_from(expires_in).unwrap_or(28800));

    // Create ID token claims
    let id_claims = AwsIdTokenClaims {
        iss: state.config.verification_base_url.clone(),
        sub: user_email.clone(),
        aud: state.config.verification_base_url.clone(), // AWS will match this against the OIDC provider
        exp,
        iat: now.as_second(),
        email: user_email.clone(),
        email_verified: true,
        hardware_verified: true,
        hardware_aaguid: authenticator.and_then(|a| a.aaguid),
    };

    // Sign the token with ES256 using the OIDC signing key
    // AWS OIDC requires asymmetric signing (ES256) so it can verify
    // the token using the public key from the JWKS endpoint
    let id_token = state.oidc_key.sign_jwt(&id_claims).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "token_error",
            &format!("Failed to generate ID token: {e}"),
        )
    })?;

    tracing::info!("Issued AWS OIDC token for {}", user_email);

    Ok(Json(AwsTokenResponse {
        id_token,
        expires_in,
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
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<Json<GitHubStatusResponse>, (StatusCode, Json<ApiError>)> {
    // Validate session
    let session = extract_session(&state, auth_header).await?;

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
            .map(|i| vouch_common::GitHubAccountStatus {
                login: i.github_account_login,
                account_type: i.github_account_type,
                suspended: i.suspended_at.is_some(),
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
    headers: axum::http::HeaderMap,
    Json(request): Json<GitHubTokenRequest>,
) -> Result<Json<GitHubTokenResponse>, (StatusCode, Json<ApiError>)> {
    // Validate session
    let session = extract_session(&state, auth_header).await?;

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
            GitHubInstallationId(installation.installation_id as u64),
            request.repositories.as_deref(),
            Some(&permissions),
        )
        .await
        .map_err(|e| {
            tracing::warn!(
                "Failed to get GitHub token for {} (org {}): {}",
                user.email,
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
    let expires_at_ts: Timestamp = token
        .expires_at
        .parse()
        .unwrap_or_else(|_| Timestamp::now());
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
    let _ = db::log_github_credential_event(
        &state.db,
        GitHubCredentialEventParams {
            event_type: "token_issued",
            user_id: &user.id,
            user_email: &user.email,
            org_id: Some(org_id),
            installation_id: Some(installation.installation_id),
            session_id: None, // Session ID not stored in JWT claims
            authenticator_id: Some(&session.claims.authenticator_id),
            repositories: repos_json.as_deref(),
            permissions: Some(&perms_json),
            token_expires_at: Some(&token.expires_at),
            success: true,
            error_code: None,
            ip_address: ip_address.as_deref(),
            user_agent: user_agent.as_deref(),
        },
    )
    .await;

    tracing::info!(
        "Issued GitHub token for {} (org {}, installation {})",
        user.email,
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
