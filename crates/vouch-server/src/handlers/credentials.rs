//! Credential issuance handlers

use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;
use vouch_common::ApiError;

// ============================================================================
// GitHub
// ============================================================================

#[derive(Deserialize)]
pub struct GitHubCredentialRequest {
    repository: Option<String>,
}

#[derive(Serialize)]
pub struct GitHubCredentialResponse {
    token: String,
    expires_at: String,
    repositories: Vec<String>,
}

pub async fn github(
    State(_state): State<Arc<AppState>>,
    // TODO: Extract JWT and validate session
    Json(_req): Json<GitHubCredentialRequest>,
) -> Result<Json<GitHubCredentialResponse>, (StatusCode, Json<ApiError>)> {
    // TODO: 
    // 1. Validate session JWT
    // 2. Check if delegated (and validate scope)
    // 3. Generate GitHub App installation token
    // 4. Log to audit trail

    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiError::new("not_implemented", "GitHub integration pending")),
    ))
}

// ============================================================================
// AWS
// ============================================================================

#[derive(Deserialize)]
pub struct AwsCredentialRequest {
    role_arn: String,
    session_name: Option<String>,
}

#[derive(Serialize)]
pub struct AwsCredentialResponse {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expires_at: String,
}

pub async fn aws(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<AwsCredentialRequest>,
) -> Result<Json<AwsCredentialResponse>, (StatusCode, Json<ApiError>)> {
    // TODO:
    // 1. Validate session JWT
    // 2. Check if delegated (and validate role is in scope)
    // 3. Call AWS STS AssumeRoleWithWebIdentity
    // 4. Log to audit trail

    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiError::new("not_implemented", "AWS integration pending")),
    ))
}

// ============================================================================
// SSH
// ============================================================================

#[derive(Deserialize)]
pub struct SshCredentialRequest {
    public_key: String,
    principals: Vec<String>,
}

#[derive(Serialize)]
pub struct SshCredentialResponse {
    certificate: String,
    expires_at: String,
    principals: Vec<String>,
}

pub async fn ssh(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<SshCredentialRequest>,
) -> Result<Json<SshCredentialResponse>, (StatusCode, Json<ApiError>)> {
    // TODO:
    // 1. Validate session JWT
    // 2. Check if delegated (and validate principals are in scope)
    // 3. Sign SSH certificate with CA key
    // 4. Log to audit trail

    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiError::new("not_implemented", "SSH CA pending")),
    ))
}
