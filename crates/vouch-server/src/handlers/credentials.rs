// SPDX-License-Identifier: BUSL-1.1
//! Credential issuance handlers (SSH certificates, AWS tokens, etc.).

use crate::AppState;
use crate::db;
use axum::{Json, extract::State, http::StatusCode};
use jiff::{Span, Timestamp};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vouch_common::{
    ApiError, AwsTokenResponse, SshCaPublicKeyResponse, SshCertificateRequest,
    SshCertificateResponse,
};

use super::{extract_session_with_email, json_error};

/// Issue an SSH certificate for the authenticated user.
///
/// POST /v1/credentials/ssh
///
/// Requires Bearer token authentication. Signs the provided SSH public key
/// as a user certificate with principals extracted from the user's email.
pub async fn issue_ssh_certificate(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<SshCertificateRequest>,
) -> Result<Json<SshCertificateResponse>, (StatusCode, Json<ApiError>)> {
    // Validate session
    let (_claims, user_email) = extract_session_with_email(&state, &headers).await?;

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
    headers: axum::http::HeaderMap,
) -> Result<Json<AwsTokenResponse>, (StatusCode, Json<ApiError>)> {
    // Validate session
    let (claims, user_email) = extract_session_with_email(&state, &headers).await?;

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

    // Sign the token
    let id_token = encode(
        &Header::default(),
        &id_claims,
        &EncodingKey::from_secret(state.config.jwt_secret_bytes()),
    )
    .map_err(|e| {
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
