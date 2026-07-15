// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Credential issuance handlers (SSH certificates, AWS tokens, GitHub tokens, etc.).

use crate::AppState;
use crate::db::{self, AwsCredentialAuditData, GitHubCredentialAuditData, SshCredentialAuditData};
use crate::error::ServiceError;
use crate::services::integrations::aws::{AwsError, issue_aws_token};
use crate::services::integrations::github::{GitHubInstallationId, minimal_git_permissions};
use crate::services::oidc;
use axum::extract::{OriginalUri, Query};
use axum::http::Method;
use axum::{Json, extract::State, http::HeaderMap, http::StatusCode};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vouch_common::{
    AwsTokenResponse, GitHubStatusResponse, GitHubTokenRequest, GitHubTokenResponse,
    SshCaPublicKeyResponse, SshCertificateRequest, SshCertificateResponse,
};

use super::extractors::OptionalClientCert;
use super::session::{extract_resource_token, extract_resource_token_with_email};
use crate::db::ClientInfo;
use crate::redact_email;
use crate::services::auth::ValidatedResourceToken;

/// Issue an SSH certificate for the authenticated user.
///
/// POST /v1/credentials/ssh
///
/// Requires Bearer token authentication. Signs the provided SSH public key
/// as a user certificate with principals extracted from the user's email.
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler signature: extractors are positional parameters"
)]
pub(crate) async fn issue_ssh_certificate(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    client_cert: OptionalClientCert,
    client_info: ClientInfo,
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
    let valid_seconds = state.config().session_hours.saturating_mul(3600);

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

    // Record issuance as a queryable audit event alongside the
    // revocation-tracking row. Best-effort: audit failure must not fail
    // issuance (the revocation record above is the load-bearing write).
    if let Err(e) = db::log_ssh_credential_event(
        &state.audit,
        &token.sub,
        &user_email,
        SshCredentialAuditData {
            event_type: "certificate_issued".to_string(),
            org_id: user.org_id.clone(),
            authenticator_id: token.authenticator_id.clone(),
            serial: signed.serial,
            principals: signed.principals.clone(),
            agent: token.dpop_source.clone(),
            cert_expires_at: Some(cert_expires_at.to_string()),
            success: true,
            user_agent: client_info.user_agent.clone(),
            ..Default::default()
        },
        client_info.client_ip,
    )
    .await
    {
        tracing::warn!("Failed to log SSH credential event: {e}");
    }

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
pub(crate) async fn get_ssh_ca_public_key(
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
pub(crate) struct SshKrlResponse {
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
pub(crate) async fn get_ssh_krl(
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
pub(crate) async fn check_ssh_revocation(
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
pub(crate) struct SshRevocationCheckResponse {
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

/// Shared preamble for the AWS credential endpoints: authenticate the request,
/// require a hardware-verified session, confirm the user is active, and resolve
/// the user's email.
///
/// AWS federation mints an OIDC token whose claims hardcode
/// `hardware_verified: true`, so the *current session* must itself be
/// hardware-verified — otherwise a non-verified bootstrap session could be
/// laundered into a verified assertion (#451). The gate is on the access-token
/// `hardware_verified` claim, not `authenticator_id` (a re-enrollment bootstrap
/// session can have an `authenticator_id` while `hardware_verified` is false).
async fn authorize_aws_token_request(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    jar: &CookieJar,
    method: &Method,
    path: &str,
    client_cert: &OptionalClientCert,
) -> Result<AwsIssuanceContext, ServiceError> {
    let token = extract_resource_token(
        state,
        headers,
        jar,
        method.as_str(),
        path,
        client_cert.0.as_ref(),
    )
    .await?;

    if !token.hardware_verified {
        return Err(ServiceError::api(
            StatusCode::FORBIDDEN,
            "hardware_required",
            "AWS federation requires a hardware-verified session - run 'vouch login' to authenticate with your security key",
        ));
    }

    // Confirm the user is still active. Email and federation claims come from
    // the session snapshot, not from current state.
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

    // Resolve the issuer for this user's AWS tokens: the org's claimed
    // issuer subdomain when one exists, otherwise the shared base URL.
    // Built from the stored label + configured base_url — never from the
    // request Host header.
    let config = state.config();
    let mut org = None;
    if let Some(org_id) = user.org_id.as_deref() {
        org = db::get_organization(&state.store, org_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to load organization {org_id}: {e}");
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    "Internal database error",
                )
            })?;
    }
    // Fail closed: an org that claimed a subdomain must never receive tokens
    // minted under the shared issuer — they would not match the org's discovery
    // document or the relying party's OIDC provider config.
    let issuer = oidc::org_issuer_or_base(&config, org.as_ref())?;

    Ok(AwsIssuanceContext {
        token,
        user_email,
        issuer,
        org,
    })
}

/// Authorization result for the AWS token endpoints: the validated resource
/// token, the resolved user email, the issuer (`iss`/`aud`) the token must be
/// minted under, and the caller's organization (for per-org signing-key
/// resolution) — both per-org when the org claimed a subdomain.
struct AwsIssuanceContext {
    token: ValidatedResourceToken,
    user_email: String,
    issuer: String,
    org: Option<db::Organization>,
}

/// Map a per-org signing-key resolution failure to a 500.
fn map_signing_key_error(e: anyhow::Error) -> ServiceError {
    tracing::error!("Failed to resolve org signing key: {e}");
    ServiceError::api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "signing_key_error",
        "Failed to resolve the signing key",
    )
}

/// Map an [`AwsError`] to a `ServiceError`.
fn map_aws_error(e: AwsError) -> ServiceError {
    match e {
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
    }
}

/// Query parameters for `GET /v1/credentials/aws/token`.
#[derive(Debug, Deserialize)]
pub(crate) struct AwsTokenParams {
    /// IAM role ARN to pin the token to via the
    /// `https://aws.amazon.com/roles` claim. Optional: absent means an
    /// unpinned token (issued to CLIs that predate pinning).
    role_arn: Option<String>,
}

/// Maximum length of a role ARN, per the documented constraint on `RoleArn`
/// in STS `AssumeRoleWithWebIdentity` (and `Role.Arn` in the IAM API).
const MAX_ROLE_ARN_LEN: usize = 2048;

/// Validate a requested pin as a plausible IAM role ARN.
///
/// Rejecting malformed ARNs here (400) beats minting a token that can
/// never match its own roles claim and only fails later, opaquely, at the
/// STS exchange. The CLI validates the ARN before calling, so only broken
/// clients hit this.
fn validate_pinned_role(role_arn: &str) -> Result<(), ServiceError> {
    let is_role = role_arn.len() <= MAX_ROLE_ARN_LEN
        && vouch_common::aws::Arn::parse(role_arn).is_ok_and(|arn| arn.is_iam_role());
    if is_role {
        Ok(())
    } else {
        Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_role_arn",
            "role_arn must be an IAM role ARN (arn:<partition>:iam::<account>:role/<name>)",
        ))
    }
}

/// Get an OIDC ID token for AWS.
///
/// GET /v1/credentials/aws/token
///
/// Returns an **RS256** OIDC ID token that serves both AWS consumers: STS
/// `AssumeRoleWithWebIdentity` (the IAM role must trust the Vouch OIDC
/// provider) and IAM Identity Center `sso-oidc:CreateTokenWithIAM`, where it
/// is the `jwt-bearer` assertion (the trusted-token-issuer contract requires
/// RS256; the customer-managed application's Aud claim must be the Vouch
/// issuer URL).
///
/// When `?role_arn=` is present, the token is pinned to that role via the
/// `https://aws.amazon.com/roles` claim — STS refuses to let it assume any
/// other role. Every CLI path pins to the role its `AssumeRoleWithWebIdentity`
/// call assumes, including the Identity Center management-role hop (see the
/// `services::integrations::aws` module docs for the `CreateTokenWithIAM`
/// note).
///
/// When the DPoP proof includes a `source` custom claim (e.g., "claude-code"),
/// the issued token includes AI-specific session tags (`vouch:AccessType=AI`,
/// `vouch:Agent=<agent>`) for CloudTrail differentiation and IAM condition keys.
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler signature: extractors are positional parameters"
)]
pub(crate) async fn get_aws_token(
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Query(params): Query<AwsTokenParams>,
    client_cert: OptionalClientCert,
    client_info: ClientInfo,
) -> Result<Json<AwsTokenResponse>, ServiceError> {
    let pinned_role = params.role_arn.as_deref();
    if let Some(role_arn) = pinned_role {
        validate_pinned_role(role_arn)?;
    }

    let ctx =
        authorize_aws_token_request(&state, &headers, &jar, &method, uri.path(), &client_cert)
            .await?;

    // Issue AWS token using the session-time snapshot of aaguid and org domain.
    // Sign with the org's own RS256 key when it has a claimed subdomain, so the
    // token verifies against the org-host JWKS; otherwise the common RSA key
    // (always initialized at startup; the error branch is defensive).
    let org_keys = oidc::resolve_org_keys(&state, ctx.org.as_ref())
        .await
        .map_err(map_signing_key_error)?;
    let rsa_key = org_keys
        .as_deref()
        .map(|k| &k.signers.rs256)
        .or(state.oidc_rsa_key.as_ref())
        .ok_or_else(|| {
            tracing::error!("AWS token requested but no OIDC RSA key configured");
            ServiceError::api(
                StatusCode::NOT_IMPLEMENTED,
                "rsa_key_unavailable",
                "RS256 signing key is not configured on this server",
            )
        })?;

    let config = state.config();
    let result = issue_aws_token(
        &ctx.issuer,
        config.session_hours,
        rsa_key,
        &ctx.user_email,
        &ctx.token,
        pinned_role,
    )
    .await
    .map_err(map_aws_error)?;

    // Record issuance — including the role ARN the token is pinned to — as a
    // queryable audit event, so operators can see which role each OIDC token
    // was created for. Best-effort: audit failure must not fail issuance.
    let token_expires_at = i64::try_from(result.expires_in)
        .ok()
        .and_then(|secs| {
            Timestamp::now()
                .checked_add(jiff::Span::new().seconds(secs))
                .ok()
        })
        .map(|t| t.to_string());
    if let Err(e) = db::log_aws_credential_event(
        &state.audit,
        &ctx.token.sub,
        &ctx.user_email,
        AwsCredentialAuditData {
            event_type: "token_issued".to_string(),
            org_id: ctx.org.as_ref().map(|o| o.id.clone()),
            authenticator_id: ctx.token.authenticator_id.clone(),
            role_arn: pinned_role.map(str::to_string),
            agent: ctx.token.dpop_source.clone(),
            token_expires_at,
            success: true,
            user_agent: client_info.user_agent.clone(),
            ..Default::default()
        },
        client_info.client_ip,
    )
    .await
    {
        tracing::warn!("Failed to log AWS credential event: {e}");
    }

    crate::infra::metrics::record_credential_issuance("aws");

    Ok(Json(AwsTokenResponse {
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
pub(crate) async fn get_github_status(
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
#[expect(
    clippy::too_many_lines,
    reason = "sequential GitHub installation token validation and issuance"
)]
pub(crate) async fn get_github_token(
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
        .max(0)
        .unsigned_abs();

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

        // /v1/* requires a valid RFC 9421 signature; the unsigned request is
        // rejected by the signature middleware before the handler's CA check.
        let body =
            serde_json::json!({ "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test" });
        let (status, resp_body) =
            http_post_json(&app, "/v1/credentials/ssh", &body.to_string(), &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            resp_body.contains("signature"),
            "expected signature failure, got: {resp_body}"
        );
    }

    #[tokio::test]
    async fn test_ssh_cert_rejects_invalid_token() {
        let (app, _state) = test_app().await;

        // The garbage token has no resolvable client, so the signature
        // middleware rejects with 401 before the handler's CA check.
        let body =
            serde_json::json!({ "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test" });
        let (status, resp_body) = http_post_json(
            &app,
            "/v1/credentials/ssh",
            &body.to_string(),
            &[("Authorization", "Bearer garbage.token.value")],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            resp_body.contains("signature"),
            "expected signature failure, got: {resp_body}"
        );
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

        // /v1/* requires a valid RFC 9421 signature; an unsigned request is
        // rejected by the signature middleware before the handler runs.
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            body.contains("signature"),
            "expected signature failure, got: {body}"
        );
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

        // The garbage token has no resolvable client, so the signature
        // middleware rejects the request with 401 before the handler runs.
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            body.contains("signature"),
            "expected signature failure, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_aws_token_returns_token_for_valid_session() {
        use base64::Engine;

        let state = test_app_state_with_rsa_key().await;
        let config = state.config();
        let app = crate::infra::router::build_app(state.clone(), &config).expect("build app");

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
        assert!(resp["expires_in"].is_number());
        let id_token = resp["id_token"].as_str().expect("id_token string");

        // RS256, so the one token serves both AssumeRoleWithWebIdentity and
        // the Identity Center CreateTokenWithIAM assertion.
        let header_b64 = id_token.split('.').next().expect("jwt header");
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .expect("base64url header");
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("header JSON");
        assert_eq!(header["alg"], "RS256");
    }

    /// Without an RSA key in AppState the handler fails closed with 501.
    /// Startup always initializes the key, so this exercises the defensive
    /// branch rather than a reachable production state.
    #[tokio::test]
    async fn test_aws_token_without_rsa_key_returns_501() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "norsa@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "rsa_key_unavailable");
    }

    /// Regression for #451: a non-hardware-verified bootstrap session
    /// for a user who **already has a registered key** (so
    /// `authenticator_id = Some(_)` from the session record) must NOT
    /// be exchangeable for an AWS WIF token. The previous gate checked
    /// `authenticator_id.is_none()` and let this case through, allowing
    /// the handler to mint an ID token asserting `hardware_verified: true`.
    #[tokio::test]
    async fn test_aws_token_rejects_bootstrap_session_with_existing_key() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "bootstrap@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_bootstrap_session_with_authenticator(
            &state,
            &user.id,
            &user.email,
            &auth_id,
        )
        .await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "hardware_required");
    }

    /// A plain bootstrap session (no authenticator yet, `hardware_verified=false`)
    /// must also be rejected. Confirms the `#[serde(default)]` fail-closed
    /// behavior of the access-token claim end-to-end.
    #[tokio::test]
    async fn test_aws_token_rejects_bootstrap_session_without_key() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "newuser@example.com").await;
        let token = create_test_bootstrap_session(&state, &user.id, &user.email).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "hardware_required");
    }

    #[tokio::test]
    async fn test_aws_token_returns_token_for_org_user() {
        let state = test_app_state_with_rsa_key().await;
        let config = state.config();
        let app = crate::infra::router::build_app(state.clone(), &config).expect("build app");

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

    /// Decode a JWT payload (middle part) without signature verification.
    fn decode_jwt_payload(token: &str) -> serde_json::Value {
        use base64::Engine;
        let payload_b64 = token.split('.').nth(1).expect("jwt payload");
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("base64url payload");
        serde_json::from_slice(&payload_bytes).expect("payload JSON")
    }

    /// `?role_arn=` pins the token: the ARN must appear as a single-element
    /// array in the `https://aws.amazon.com/roles` claim.
    #[tokio::test]
    async fn test_aws_token_pins_role_from_query() {
        let state = test_app_state_with_rsa_key().await;
        let config = state.config();
        let app = crate::infra::router::build_app(state.clone(), &config).expect("build app");

        let user = create_test_user(&state.store, "pinned@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token?role_arn=arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2FExample",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        let claims = decode_jwt_payload(resp["id_token"].as_str().expect("id_token string"));
        assert_eq!(
            claims["https://aws.amazon.com/roles"],
            serde_json::json!(["arn:aws:iam::111122223333:role/Example"]),
        );
    }

    /// Without `?role_arn=` the roles claim is absent — the pre-pinning
    /// token shape older CLIs and the Identity Center path rely on.
    #[tokio::test]
    async fn test_aws_token_without_query_omits_roles_claim() {
        let state = test_app_state_with_rsa_key().await;
        let config = state.config();
        let app = crate::infra::router::build_app(state.clone(), &config).expect("build app");

        let user = create_test_user(&state.store, "unpinned@example.com").await;
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
        let claims = decode_jwt_payload(resp["id_token"].as_str().expect("id_token string"));
        assert!(
            claims.get("https://aws.amazon.com/roles").is_none(),
            "roles claim must be absent without a pin request"
        );
    }

    /// A `role_arn` that does not parse as an ARN is rejected with 400
    /// before any token is minted.
    #[tokio::test]
    async fn test_aws_token_rejects_malformed_role_arn() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "badarn@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token?role_arn=not-an-arn",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_role_arn");
    }

    /// A syntactically valid ARN that is not an IAM role (e.g. an IAM user)
    /// is rejected — the claim only makes sense for roles.
    #[tokio::test]
    async fn test_aws_token_rejects_non_role_arn() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "userarn@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token?role_arn=arn%3Aaws%3Aiam%3A%3A111122223333%3Auser%2FBob",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "invalid_role_arn");
    }

    /// An ARN at exactly the length cap passes; one byte over fails.
    #[test]
    fn test_validate_pinned_role_length_boundary() {
        let prefix = "arn:aws-us-gov:iam::123456789012:role/";
        let filler = "a".repeat(super::MAX_ROLE_ARN_LEN.saturating_sub(prefix.len()));
        let at_cap = format!("{prefix}{filler}");
        assert_eq!(at_cap.len(), super::MAX_ROLE_ARN_LEN);
        assert!(super::validate_pinned_role(&at_cap).is_ok());

        let over_cap = format!("{at_cap}a");
        assert!(super::validate_pinned_role(&over_cap).is_err());
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

        // /v1/* requires a valid RFC 9421 signature; the unsigned request is
        // rejected by the signature middleware before the handler's config check.
        let body = serde_json::json!({ "repositories": [] });
        let (status, resp_body) =
            http_post_json(&app, "/v1/credentials/github/token", &body.to_string(), &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            resp_body.contains("signature"),
            "expected signature failure, got: {resp_body}"
        );
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
