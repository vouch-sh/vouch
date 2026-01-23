//! Authentication handlers

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;
use vouch_common::{ApiError, SessionStatus};

// ============================================================================
// Register
// ============================================================================

#[derive(Deserialize)]
pub struct StartRegistrationRequest {
    name: Option<String>,
}

#[derive(Serialize)]
pub struct StartRegistrationResponse {
    registration_url: String,
    code: String,
}

pub async fn register_start(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartRegistrationRequest>,
) -> Result<Json<StartRegistrationResponse>, (StatusCode, Json<ApiError>)> {
    // Generate one-time registration code
    let code = generate_code();
    
    // TODO: Store registration challenge in database
    // TODO: Associate with pending user or require OIDC login first

    let registration_url = format!(
        "{}/auth/register?code={}",
        state.config.rp_origin, code
    );

    Ok(Json(StartRegistrationResponse {
        registration_url,
        code,
    }))
}

#[derive(Deserialize)]
pub struct CompleteRegistrationRequest {
    code: String,
}

#[derive(Serialize)]
pub struct CompleteRegistrationResponse {
    device_id: String,
    device_name: String,
}

pub async fn register_complete(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<CompleteRegistrationRequest>,
) -> Result<Json<CompleteRegistrationResponse>, (StatusCode, Json<ApiError>)> {
    // TODO: Look up registration by code
    // TODO: Verify WebAuthn response was received via browser
    // TODO: Store credential

    // For now, return pending status
    Err((
        StatusCode::ACCEPTED,
        Json(ApiError::new("pending", "registration not yet complete")),
    ))
}

// ============================================================================
// Login
// ============================================================================

#[derive(Serialize)]
pub struct StartLoginResponse {
    login_url: String,
    code: String,
}

pub async fn login_start(
    State(state): State<Arc<AppState>>,
) -> Result<Json<StartLoginResponse>, (StatusCode, Json<ApiError>)> {
    let code = generate_code();

    // TODO: Store login challenge

    let login_url = format!(
        "{}/auth/login?code={}",
        state.config.rp_origin, code
    );

    Ok(Json(StartLoginResponse {
        login_url,
        code,
    }))
}

#[derive(Deserialize)]
pub struct CompleteLoginRequest {
    code: String,
}

#[derive(Serialize)]
pub struct CompleteLoginResponse {
    token: String,
    user_email: String,
    expires_at: String,
}

pub async fn login_complete(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<CompleteLoginRequest>,
) -> Result<Json<CompleteLoginResponse>, (StatusCode, Json<ApiError>)> {
    // TODO: Verify login by code
    // TODO: Issue JWT

    Err((
        StatusCode::ACCEPTED,
        Json(ApiError::new("pending", "login not yet complete")),
    ))
}

// ============================================================================
// Status
// ============================================================================

pub async fn status(
    State(_state): State<Arc<AppState>>,
    // TODO: Extract JWT from Authorization header
) -> Result<Json<SessionStatus>, (StatusCode, Json<ApiError>)> {
    // TODO: Validate JWT and return session status

    Ok(Json(SessionStatus {
        authenticated: false,
        user_email: None,
        expires_in_seconds: None,
        device_name: None,
        active_delegations: 0,
    }))
}

// ============================================================================
// Helpers
// ============================================================================

fn generate_code() -> String {
    // 6 character alphanumeric code (easy to type)
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No 0, O, 1, I
    let mut rng = rand::thread_rng();
    (0..6)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
