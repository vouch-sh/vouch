//! Delegation management handlers

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;
use vouch_common::{ApiError, DelegationScope, DelegationSummary};

// ============================================================================
// Create
// ============================================================================

#[derive(Deserialize)]
pub struct CreateDelegationRequest {
    name: String,
    scope: DelegationScope,
    ttl_seconds: u64,
    max_uses: Option<u64>,
}

#[derive(Serialize)]
pub struct CreateDelegationResponse {
    delegation_id: String,
    token: String,
    expires_at: String,
}

pub async fn create(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<CreateDelegationRequest>,
) -> Result<Json<CreateDelegationResponse>, (StatusCode, Json<ApiError>)> {
    // TODO:
    // 1. Validate session JWT
    // 2. Validate scope (must be subset of user's permissions)
    // 3. Create delegation in database
    // 4. Generate delegation JWT
    // 5. Log to audit trail

    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiError::new("not_implemented", "Delegation creation pending")),
    ))
}

// ============================================================================
// List
// ============================================================================

#[derive(Serialize)]
pub struct ListDelegationsResponse {
    delegations: Vec<DelegationSummary>,
}

pub async fn list(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<ListDelegationsResponse>, (StatusCode, Json<ApiError>)> {
    // TODO:
    // 1. Validate session JWT
    // 2. Query delegations for user

    Ok(Json(ListDelegationsResponse {
        delegations: vec![],
    }))
}

// ============================================================================
// Show
// ============================================================================

#[derive(Serialize)]
pub struct DelegationDetails {
    id: String,
    name: String,
    scope: DelegationScope,
    created_at: String,
    expires_at: String,
    revoked: bool,
    use_count: u64,
    max_uses: Option<u64>,
    recent_uses: Vec<DelegationUse>,
}

#[derive(Serialize)]
pub struct DelegationUse {
    timestamp: String,
    action: String,
    target: String,
}

pub async fn show(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<DelegationDetails>, (StatusCode, Json<ApiError>)> {
    // TODO:
    // 1. Validate session JWT
    // 2. Query delegation by ID
    // 3. Verify ownership

    Err((
        StatusCode::NOT_FOUND,
        Json(ApiError::new("not_found", format!("Delegation {} not found", id))),
    ))
}

// ============================================================================
// Revoke
// ============================================================================

#[derive(Serialize)]
pub struct RevokeDelegationResponse {
    revoked: bool,
}

pub async fn revoke(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<RevokeDelegationResponse>, (StatusCode, Json<ApiError>)> {
    // TODO:
    // 1. Validate session JWT
    // 2. Find delegation
    // 3. Verify ownership
    // 4. Mark as revoked
    // 5. Log to audit trail

    Err((
        StatusCode::NOT_FOUND,
        Json(ApiError::new("not_found", format!("Delegation {} not found", id))),
    ))
}
