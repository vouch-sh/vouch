// SPDX-License-Identifier: BUSL-1.1
//! Device posture policy management API handlers.
//!
//! All endpoints require org admin auth via `extract_org_admin()`.
//! Manages preconfigured policy activation and custom CEL policies.

use crate::AppState;
use crate::db;
use crate::services::error::ServiceError;
use crate::services::posture::{self, MAX_ACTIVE_POLICIES, PRECONFIGURED_POLICIES};
use axum::extract::{OriginalUri, State};
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use axum::{Json, response::Response};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::ValidPath;
use super::session::extract_org_admin;

// ============================================================================
// Response Types
// ============================================================================

/// A policy entry in the list response (preconfigured or custom).
#[derive(Debug, Serialize)]
pub struct PolicyEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub cel_expression: String,
    pub active: bool,
    pub policy_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<Timestamp>,
}

/// Response for listing posture policies.
#[derive(Debug, Serialize)]
pub struct ListPoliciesResponse {
    pub policies: Vec<PolicyEntry>,
    pub posture_schema: serde_json::Value,
}

/// Response for creating a custom policy.
#[derive(Debug, Serialize)]
pub struct CreatePolicyResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub cel_expression: String,
    pub active: bool,
    pub policy_type: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// Response for validating a CEL expression.
#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_result: Option<TestResult>,
}

/// Test result from dry-running a CEL expression against sample posture.
#[derive(Debug, Serialize)]
pub struct TestResult {
    pub pass: bool,
}

// ============================================================================
// Request Types
// ============================================================================

/// Request to create a custom posture policy.
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub cel_expression: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Request to update a preconfigured policy's active state.
#[derive(Debug, Deserialize)]
pub struct UpdatePreconfiguredRequest {
    pub active: bool,
}

/// Request to update a custom policy.
#[derive(Debug, Deserialize)]
pub struct UpdateCustomPolicyRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<Option<String>>,
    #[serde(default)]
    pub cel_expression: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
}

/// Request to validate a CEL expression.
#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub cel_expression: String,
    #[serde(default)]
    pub test_posture: Option<vouch_common::posture::DevicePosture>,
}

// ============================================================================
// Handlers
// ============================================================================

/// List all posture policies (preconfigured + custom).
///
/// GET /api/v1/org/posture-policies
pub async fn list_policies(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
) -> Result<Json<ListPoliciesResponse>, ServiceError> {
    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    // Get active preconfigured slugs
    let active_slugs = db::get_active_preconfigured_slugs(&state.store, &org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to load posture config: {e}")))?;

    // Build preconfigured policy entries
    let mut policies: Vec<PolicyEntry> = PRECONFIGURED_POLICIES
        .iter()
        .map(|p| PolicyEntry {
            id: None,
            slug: Some(p.slug.to_string()),
            name: p.name.to_string(),
            description: Some(p.description.to_string()),
            cel_expression: p.cel_expression.to_string(),
            active: active_slugs.iter().any(|s| s == p.slug),
            policy_type: "preconfigured".to_string(),
            created_at: None,
            updated_at: None,
        })
        .collect();

    // Add custom policies
    let custom = db::list_custom_policies(&state.store, &org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to load custom policies: {e}")))?;

    for p in custom {
        policies.push(PolicyEntry {
            id: Some(p.id),
            slug: None,
            name: p.name,
            description: p.description,
            cel_expression: p.cel_expression,
            active: p.active,
            policy_type: "custom".to_string(),
            created_at: Some(p.created_at),
            updated_at: Some(p.updated_at),
        });
    }

    Ok(Json(ListPoliciesResponse {
        policies,
        posture_schema: posture::posture_schema(),
    }))
}

/// Create a custom posture policy.
///
/// POST /api/v1/org/posture-policies
pub async fn create_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<CreatePolicyResponse>), ServiceError> {
    // Validate inputs
    if req.name.is_empty() || req.name.len() > 100 {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Name must be between 1 and 100 characters",
        ));
    }

    if req.cel_expression.is_empty() || req.cel_expression.len() > 1024 {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CEL expression must be between 1 and 1024 characters",
        ));
    }

    if let Some(ref desc) = req.description
        && desc.len() > 500
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Description must be 500 characters or less",
        ));
    }

    // Validate CEL syntax
    posture::validate_cel_expression(&req.cel_expression)?;

    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let policy = db::create_custom_policy(
        &state.store,
        db::CreateCustomPolicyParams {
            name: &req.name,
            description: req.description.as_deref(),
            cel_expression: &req.cel_expression,
            org_id: &org_id,
        },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to create policy: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(CreatePolicyResponse {
            id: policy.id,
            name: policy.name,
            description: policy.description,
            cel_expression: policy.cel_expression,
            active: policy.active,
            policy_type: "custom".to_string(),
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        }),
    ))
}

/// Toggle a preconfigured policy's active state.
///
/// PATCH /api/v1/org/posture-policies/preconfigured/{slug}
pub async fn update_preconfigured(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    ValidPath(slug): ValidPath<String>,
    Json(req): Json<UpdatePreconfiguredRequest>,
) -> Result<Response, ServiceError> {
    // Validate slug
    if !posture::is_valid_preconfigured_slug(&slug) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("Unknown preconfigured policy: {slug}"),
        ));
    }

    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    // Check max active limit when activating
    if req.active {
        let current = db::count_active_policies(&state.store, &org_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to count policies: {e}")))?;

        // Check if this slug is already active (doesn't count toward new)
        let active_slugs = db::get_active_preconfigured_slugs(&state.store, &org_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to load posture config: {e}")))?;

        let already_active = active_slugs.iter().any(|s| s == &slug);

        if !already_active && current >= MAX_ACTIVE_POLICIES {
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "max_active_policies",
                format!(
                    "Maximum of {MAX_ACTIVE_POLICIES} active \
                     policies allowed"
                ),
            ));
        }
    }

    // Update the active slugs
    let mut active_slugs = db::get_active_preconfigured_slugs(&state.store, &org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to load posture config: {e}")))?;

    if req.active {
        if !active_slugs.iter().any(|s| s == &slug) {
            active_slugs.push(slug);
        }
    } else {
        active_slugs.retain(|s| s != &slug);
    }

    db::set_preconfigured_active(&state.store, &org_id, active_slugs)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to update posture config: {e}")))?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Update a custom policy.
///
/// PATCH /api/v1/org/posture-policies/{id}
pub async fn update_custom_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    ValidPath(id): ValidPath<String>,
    Json(req): Json<UpdateCustomPolicyRequest>,
) -> Result<Response, ServiceError> {
    // Validate inputs
    if let Some(ref name) = req.name
        && (name.is_empty() || name.len() > 100)
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Name must be between 1 and 100 characters",
        ));
    }

    if let Some(ref expr) = req.cel_expression {
        if expr.is_empty() || expr.len() > 1024 {
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CEL expression must be between 1 and \
                 1024 characters",
            ));
        }
        posture::validate_cel_expression(expr)?;
    }

    if let Some(Some(ref desc)) = req.description
        && desc.len() > 500
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Description must be 500 characters or less",
        ));
    }

    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    // Check max active limit when activating
    if req.active == Some(true) {
        let policy = db::get_custom_policy(&state.store, &id)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to get policy: {e}")))?;

        if let Some(ref p) = policy
            && !p.active
        {
            let current = db::count_active_policies(&state.store, &org_id)
                .await
                .map_err(|e| ServiceError::Internal(format!("Failed to count policies: {e}")))?;

            if current >= MAX_ACTIVE_POLICIES {
                return Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "max_active_policies",
                    format!(
                        "Maximum of {MAX_ACTIVE_POLICIES} \
                         active policies allowed"
                    ),
                ));
            }
        }
    }

    let description_param = req.description.as_ref().map(|d| d.as_deref());

    let result = db::update_custom_policy(
        &state.store,
        &id,
        &org_id,
        db::UpdateCustomPolicyParams {
            name: req.name.as_deref(),
            description: description_param,
            cel_expression: req.cel_expression.as_deref(),
            active: req.active,
        },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to update policy: {e}")))?;

    match result {
        Some(policy) => Ok(Json(CreatePolicyResponse {
            id: policy.id,
            name: policy.name,
            description: policy.description,
            cel_expression: policy.cel_expression,
            active: policy.active,
            policy_type: "custom".to_string(),
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        })
        .into_response()),
        None => Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Policy not found",
        )),
    }
}

/// Delete a custom policy.
///
/// DELETE /api/v1/org/posture-policies/{id}
pub async fn delete_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    ValidPath(id): ValidPath<String>,
) -> Result<Response, ServiceError> {
    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let deleted = db::delete_custom_policy(&state.store, &id, &org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to delete policy: {e}")))?;

    if deleted {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Policy not found",
        ))
    }
}

/// Validate a CEL expression and optionally test against sample posture.
///
/// POST /api/v1/org/posture-policies/validate
pub async fn validate_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, ServiceError> {
    // Auth check (any org admin can validate)
    let _auth = extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    if req.cel_expression.is_empty() || req.cel_expression.len() > 1024 {
        return Ok(Json(ValidateResponse {
            valid: false,
            error: Some(
                "CEL expression must be between 1 and \
                 1024 characters"
                    .to_string(),
            ),
            test_result: None,
        }));
    }

    // Try to compile
    if let Err(e) = posture::validate_cel_expression(&req.cel_expression) {
        return Ok(Json(ValidateResponse {
            valid: false,
            error: Some(format!("{e}")),
            test_result: None,
        }));
    }

    // If test posture provided, evaluate
    let test_result = if let Some(ref test_posture) = req.test_posture {
        match posture::test_cel_expression(&req.cel_expression, test_posture) {
            Ok(pass) => Some(TestResult { pass }),
            Err(_) => Some(TestResult { pass: false }),
        }
    } else {
        None
    };

    Ok(Json(ValidateResponse {
        valid: true,
        error: None,
        test_result,
    }))
}
