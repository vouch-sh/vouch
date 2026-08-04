// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture policies UI and API handlers.

use crate::AppState;
use crate::db;
use crate::error::ServiceError;
use crate::handlers::admin::flash;
use crate::impl_template_response;
use crate::services::posture;
use askama::Template;
use aws_lc_rs::digest::{self, SHA256};
use axum::Json;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use std::sync::Arc;

use crate::handlers::ValidPath;
use crate::handlers::browser_login::validate_origin;
use crate::handlers::session::{AuthContext, extract_org_admin, get_resource_auth_context};

const REDIRECT_BASE: &str = "/admin/policies";

fn redirect_error(jar: CookieJar, msg: impl Into<String>) -> Response {
    (flash::set_err(jar, msg), Redirect::to(REDIRECT_BASE)).into_response()
}

/// Maximum number of custom policies per org (active + inactive).
const MAX_CUSTOM_POLICIES: usize = 20;

/// A preconfigured policy row for the template.
pub(crate) struct PreconfiguredPolicyRow {
    pub slug: String,
    pub name: String,
    pub description: String,
    pub cel_expression: String,
    pub active: bool,
}

/// A custom policy row for the template.
pub(crate) struct CustomPolicyRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub cel_expression: String,
    pub active: bool,
}

/// Policies page template.
#[derive(Template)]
#[template(path = "admin/policies.html")]
pub(crate) struct AdminPoliciesTemplate {
    pub auth: AuthContext,
    pub preconfigured_policies: Vec<PreconfiguredPolicyRow>,
    pub custom_policies: Vec<CustomPolicyRow>,
    pub flash_message: Option<String>,
}

impl_template_response!(AdminPoliciesTemplate);

/// GET /admin/policies — Device posture policies page.
pub(crate) async fn admin_policies_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Response {
    let auth = get_resource_auth_context(&state, &jar).await;

    if !auth.authenticated {
        return Redirect::to("/enroll/start").into_response();
    }
    if !auth.is_org_admin {
        return Redirect::to("/integrations").into_response();
    }

    let user_id = match auth.user_id {
        Some(ref id) => id.clone(),
        None => return Redirect::to("/enroll/start").into_response(),
    };

    let org_id = match db::get_user_by_id(&state.store, &user_id).await {
        Ok(Some(user)) => match user.org_id {
            Some(id) => id,
            None => return Redirect::to("/integrations").into_response(),
        },
        _ => return Redirect::to("/integrations").into_response(),
    };

    let active_slugs = match db::get_active_preconfigured_slugs(&state.store, &org_id).await {
        Ok(slugs) => slugs,
        Err(e) => {
            tracing::error!("Failed to load posture config: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let preconfigured_policies: Vec<PreconfiguredPolicyRow> = posture::PRECONFIGURED_POLICIES
        .iter()
        .map(|p| PreconfiguredPolicyRow {
            slug: p.slug.to_string(),
            name: p.name.to_string(),
            description: p.description.to_string(),
            cel_expression: p.cel_expression.to_string(),
            active: active_slugs.iter().any(|s| s == p.slug.as_str()),
        })
        .collect();

    let custom_policies: Vec<CustomPolicyRow> =
        match db::list_custom_policies(&state.store, &org_id).await {
            Ok(policies) => policies
                .into_iter()
                .map(|p| CustomPolicyRow {
                    id: p.id,
                    name: p.name,
                    description: p.description,
                    cel_expression: p.cel_expression,
                    active: p.active,
                })
                .collect(),
            Err(e) => {
                tracing::error!("Failed to load custom policies: {e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    // Consume any flash messages set by a prior POST → redirect, then expire
    // the cookies in the response so a refresh doesn't re-show them.
    let messages = flash::read(&jar);
    let jar = flash::clear(jar);

    let body = AdminPoliciesTemplate {
        auth,
        preconfigured_policies,
        custom_policies,
        flash_message: messages.err,
    };
    (jar, body).into_response()
}

/// POST /admin/policies/preconfigured/{slug}/toggle
pub(crate) async fn toggle_preconfigured_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(slug): ValidPath<String>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    if !posture::is_valid_preconfigured_slug(&slug) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("Unknown preconfigured policy: {slug}"),
        ));
    }

    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    // Single read of active slugs — fixes TOCTOU from old handler
    let mut active_slugs = db::get_active_preconfigured_slugs(&state.store, &org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to load posture config: {e}")))?;

    let already_active = active_slugs.iter().any(|s| s == &slug);

    if already_active {
        active_slugs.retain(|s| s != &slug);
    } else {
        // Check max active limit (count custom active inline)
        let custom_active_count = db::get_active_custom_policies(&state.store, &org_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to count policies: {e}")))?
            .len();
        let total_active = active_slugs.len().saturating_add(custom_active_count);

        if total_active >= posture::MAX_ACTIVE_POLICIES {
            return Ok(redirect_error(
                jar,
                format!(
                    "Maximum of {} active policies allowed",
                    posture::MAX_ACTIVE_POLICIES
                ),
            ));
        }
        active_slugs.push(slug.clone());
    }

    db::set_preconfigured_active(&state.store, &org_id, active_slugs)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to update posture config: {e}")))?;

    let action = if already_active {
        "disabled"
    } else {
        "enabled"
    };
    let data = serde_json::json!({
        "action": format!("preconfigured_policy_{action}"),
        "slug": &slug,
        "admin_user_id": admin.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminPolicyToggle,
            Some(&admin.id),
            Some(&admin.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_policy_toggle audit event");
    }

    tracing::info!(
        "Admin {} {} preconfigured policy '{}'",
        admin.email,
        action,
        slug
    );

    Ok(Redirect::to("/admin/policies").into_response())
}

/// Form data for creating/updating a custom policy.
#[derive(Debug, Deserialize)]
pub(crate) struct CustomPolicyForm {
    #[serde(alias = "policy_name")]
    pub name: String,
    #[serde(default, alias = "policy_description")]
    pub description: Option<String>,
    pub cel_expression: String,
}

/// POST /admin/policies/custom — Create a new custom policy.
pub(crate) async fn create_custom_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    axum::Form(form): axum::Form<CustomPolicyForm>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    // Validate inputs before auth
    if form.name.is_empty() || form.name.len() > 100 {
        return Ok(redirect_error(
            jar,
            "Name must be between 1 and 100 characters",
        ));
    }

    if form.cel_expression.is_empty() || form.cel_expression.len() > 1024 {
        return Ok(redirect_error(
            jar,
            "CEL expression must be between 1 and 1024 characters",
        ));
    }

    if let Some(ref desc) = form.description
        && desc.len() > 500
    {
        return Ok(redirect_error(
            jar,
            "Description must be 500 characters or less",
        ));
    }

    // Auth before CEL compilation (fixes security finding F-04)
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    // Validate CEL syntax
    if let Err(e) = posture::validate_cel_expression(&form.cel_expression) {
        return Ok(redirect_error(jar, format!("Invalid CEL expression: {e}")));
    }

    // Check total custom policy count limit
    let custom_count = db::list_custom_policies(&state.store, &org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to count policies: {e}")))?
        .len();

    if custom_count >= MAX_CUSTOM_POLICIES {
        return Ok(redirect_error(
            jar,
            format!("Maximum of {MAX_CUSTOM_POLICIES} custom policies allowed"),
        ));
    }

    let description = form.description.filter(|d| !d.is_empty());

    let policy = db::create_custom_policy(
        &state.store,
        db::CreateCustomPolicyParams {
            name: &form.name,
            description: description.as_deref(),
            cel_expression: &form.cel_expression,
            org_id: &org_id,
        },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to create policy: {e}")))?;

    let cel_hash = cel_expression_hash(&form.cel_expression);
    let data = serde_json::json!({
        "action": "custom_policy_created",
        "policy_id": policy.id,
        "policy_name": policy.name,
        "admin_user_id": admin.id,
        "cel_expression_hash": cel_hash,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminPolicyCreate,
            Some(&admin.id),
            Some(&admin.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_policy_create audit event");
    }

    tracing::info!(
        "Admin {} created custom policy '{}'",
        admin.email,
        policy.name
    );

    Ok(Redirect::to("/admin/policies").into_response())
}

/// POST /admin/policies/custom/{id} — Update a custom policy.
pub(crate) async fn update_custom_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(id): ValidPath<String>,
    axum::Form(form): axum::Form<CustomPolicyForm>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    if form.name.is_empty() || form.name.len() > 100 {
        return Ok(redirect_error(
            jar,
            "Name must be between 1 and 100 characters",
        ));
    }

    if form.cel_expression.is_empty() || form.cel_expression.len() > 1024 {
        return Ok(redirect_error(
            jar,
            "CEL expression must be between 1 and 1024 characters",
        ));
    }

    // Auth before CEL compilation
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    if let Err(e) = posture::validate_cel_expression(&form.cel_expression) {
        return Ok(redirect_error(jar, format!("Invalid CEL expression: {e}")));
    }

    let description = form.description.filter(|d| !d.is_empty());

    let result = db::update_custom_policy(
        &state.store,
        &id,
        &org_id,
        db::UpdateCustomPolicyParams {
            name: Some(&form.name),
            description: description
                .as_deref()
                .map_or(db::FieldUpdate::Clear, db::FieldUpdate::Set),
            cel_expression: Some(&form.cel_expression),
            active: None,
        },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to update policy: {e}")))?;

    if result.is_none() {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Policy not found",
        ));
    }

    let cel_hash = cel_expression_hash(&form.cel_expression);
    let data = serde_json::json!({
        "action": "custom_policy_updated",
        "policy_id": &*id,
        "policy_name": form.name,
        "admin_user_id": admin.id,
        "cel_expression_hash": cel_hash,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminPolicyUpdate,
            Some(&admin.id),
            Some(&admin.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_policy_update audit event");
    }

    tracing::info!("Admin {} updated custom policy '{}'", admin.email, id);

    Ok(Redirect::to("/admin/policies").into_response())
}

/// POST /admin/policies/custom/{id}/delete — Delete a custom policy.
pub(crate) async fn delete_custom_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(id): ValidPath<String>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let deleted = db::delete_custom_policy(&state.store, &id, &org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to delete policy: {e}")))?;

    if !deleted {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Policy not found",
        ));
    }

    let data = serde_json::json!({
        "action": "custom_policy_deleted",
        "policy_id": &*id,
        "admin_user_id": admin.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminPolicyDelete,
            Some(&admin.id),
            Some(&admin.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_policy_delete audit event");
    }

    tracing::info!("Admin {} deleted custom policy '{}'", admin.email, id);

    Ok(Redirect::to("/admin/policies").into_response())
}

/// POST /admin/policies/custom/{id}/toggle — Toggle active state.
pub(crate) async fn toggle_custom_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(id): ValidPath<String>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let policy = db::get_custom_policy(&state.store, &id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to get policy: {e}")))?
        .ok_or_else(|| ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Policy not found"))?;

    if policy.org_id != org_id {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Policy not found",
        ));
    }

    let new_active = !policy.active;

    // Check max active limit when activating.
    // Read count and write in sequence — document-store operations are
    // serialized per-org so the window is narrow, and the worst case is
    // exceeding MAX by 1 (benign for a UI toggle).
    if new_active {
        let preconfigured_count = db::get_active_preconfigured_slugs(&state.store, &org_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to count policies: {e}")))?
            .len();
        let custom_active_count = db::get_active_custom_policies(&state.store, &org_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to count policies: {e}")))?
            .len();
        // Subtract 1 if this policy was already counted as active
        let other_active = preconfigured_count
            .saturating_add(custom_active_count)
            .saturating_sub(usize::from(policy.active));

        if other_active >= posture::MAX_ACTIVE_POLICIES {
            return Ok(redirect_error(
                jar,
                format!(
                    "Maximum of {} active policies allowed",
                    posture::MAX_ACTIVE_POLICIES
                ),
            ));
        }
    }

    db::update_custom_policy(
        &state.store,
        &id,
        &org_id,
        db::UpdateCustomPolicyParams {
            name: None,
            description: db::FieldUpdate::Keep,
            cel_expression: None,
            active: Some(new_active),
        },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to toggle policy: {e}")))?;

    let action = if new_active {
        "activated"
    } else {
        "deactivated"
    };
    let cel_hash = cel_expression_hash(&policy.cel_expression);
    let data = serde_json::json!({
        "action": format!("custom_policy_{action}"),
        "policy_id": &*id,
        "policy_name": policy.name,
        "admin_user_id": admin.id,
        "cel_expression_hash": cel_hash,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminPolicyToggle,
            Some(&admin.id),
            Some(&admin.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_policy_toggle audit event");
    }

    tracing::info!(
        "Admin {} {} custom policy '{}'",
        admin.email,
        action,
        policy.name
    );

    Ok(Redirect::to("/admin/policies").into_response())
}

/// SHA-256 hash of a CEL expression, truncated to 16 hex chars.
///
/// Included in audit events to trace which version of a policy was in
/// effect at the time of an admin action.
fn cel_expression_hash(expression: &str) -> String {
    let hash = digest::digest(&SHA256, expression.as_bytes());
    hash.as_ref()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Response for validating a CEL expression (JSON API for CEL playground).
#[derive(Debug, serde::Serialize)]
pub(crate) struct ValidateResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_result: Option<TestResult>,
}

/// Test result from dry-running a CEL expression against sample posture.
#[derive(Debug, serde::Serialize)]
pub(crate) struct TestResult {
    pub pass: bool,
}

/// Request to validate a CEL expression (JSON API for CEL playground).
#[derive(Debug, Deserialize)]
pub(crate) struct ValidateRequest {
    pub cel_expression: String,
    #[serde(default)]
    pub test_posture: Option<vouch_common::posture::DevicePosture>,
}

/// POST /api/v1/org/policies/validate — Validate CEL expression (JSON).
pub(crate) async fn validate_cel_api(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, ServiceError> {
    // Auth before CEL compilation (fixes security finding F-04)
    let _auth =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    if req.cel_expression.is_empty() || req.cel_expression.len() > 1024 {
        return Ok(Json(ValidateResponse {
            valid: false,
            error: Some("CEL expression must be between 1 and 1024 characters".to_string()),
            test_result: None,
        }));
    }

    if let Err(e) = posture::validate_cel_expression(&req.cel_expression) {
        return Ok(Json(ValidateResponse {
            valid: false,
            error: Some(format!("{e}")),
            test_result: None,
        }));
    }

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

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use crate::test_utils::*;
    use axum::http::StatusCode;

    fn admin_cookie(token: &str) -> String {
        format!("{}={token}", vouch_common::SESSION_COOKIE_NAME)
    }

    /// Helper: create an org with an admin user and return the session token.
    async fn setup_admin(state: &crate::AppState) -> (crate::db::User, String) {
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(state, &admin.id, &admin.email, &auth_id).await;
        (admin, token)
    }

    // ── CEL Validation API — Positive ────────────────────────────────────────

    #[tokio::test]
    async fn test_cel_validate_valid_expression() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({
            "cel_expression": "posture.os == \"macos\""
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Valid CEL should return 200: {resp}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "valid field must be true");
        assert!(
            json.get("error").is_none() || json["error"].is_null(),
            "no error for valid CEL"
        );
        assert!(
            json.get("test_result").is_none() || json["test_result"].is_null(),
            "no test_result without test_posture"
        );
    }

    #[tokio::test]
    async fn test_cel_validate_with_test_posture() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({
            "cel_expression": "posture.os == \"macos\"",
            "test_posture": {
                "type": "device_posture",
                "posture_version": 1,
                "os": "macos"
            }
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Valid CEL with matching posture should return 200: {resp}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "valid must be true");
        assert_eq!(
            json["test_result"]["pass"], true,
            "test_result.pass must be true when posture matches"
        );
    }

    #[tokio::test]
    async fn test_cel_validate_with_failing_test_posture() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        // Expression checks for macos but posture reports linux
        let body = serde_json::json!({
            "cel_expression": "posture.os == \"macos\"",
            "test_posture": {
                "type": "device_posture",
                "posture_version": 1,
                "os": "linux"
            }
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "Response should be 200: {resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "CEL itself is valid");
        assert_eq!(
            json["test_result"]["pass"], false,
            "test_result.pass must be false when posture does not match"
        );
    }

    // ── CEL Validation API — Negative ────────────────────────────────────────

    #[tokio::test]
    async fn test_cel_validate_requires_auth() {
        let (app, _state) = test_app().await;

        let body = serde_json::json!({"cel_expression": "posture.os == \"macos\""});
        let (status, _resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Unauthenticated request must return 401"
        );
    }

    #[tokio::test]
    async fn test_cel_validate_requires_org_admin() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let member =
            create_test_user_in_org(&state.store, "member@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &member.id).await;
        let token = create_test_session(&state, &member.id, &member.email, &auth_id).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({"cel_expression": "posture.os == \"macos\""});
        let (status, _resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Non-admin user must receive 403"
        );
    }

    #[tokio::test]
    async fn test_cel_validate_empty_expression() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({"cel_expression": ""});
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Empty expression returns 200: {resp}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            json["valid"], false,
            "valid must be false for empty expression"
        );
        assert!(
            json["error"].as_str().is_some(),
            "error message must be present"
        );
    }

    #[tokio::test]
    async fn test_cel_validate_too_long_expression() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        let long_expr = "a".repeat(1025);
        let body = serde_json::json!({"cel_expression": long_expr});
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Over-length expression returns 200: {resp}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            json["valid"], false,
            "valid must be false for >1024 char expression"
        );
        assert!(
            json["error"].as_str().is_some(),
            "error message must be present"
        );
    }

    #[tokio::test]
    async fn test_cel_validate_invalid_syntax() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        // Unterminated string literal is genuinely invalid CEL syntax
        let body = serde_json::json!({"cel_expression": "posture.os == \"unterminated"});
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "Invalid CEL returns 200: {resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            json["valid"], false,
            "valid must be false for invalid syntax"
        );
        assert!(
            json["error"].as_str().is_some(),
            "error message must be present for invalid CEL"
        );
    }

    // ── Admin UI Endpoints — Auth checks ─────────────────────────────────────

    #[tokio::test]
    async fn test_admin_policies_page_redirects_unauthenticated() {
        let (app, _state) = test_app().await;

        let (status, _body) = http_get(&app, "/admin/policies", &[]).await;

        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "Unauthenticated GET /admin/policies must redirect"
        );
    }

    #[tokio::test]
    async fn test_admin_policies_page_redirects_non_admin() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let member =
            create_test_user_in_org(&state.store, "member@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &member.id).await;
        let token = create_test_session(&state, &member.id, &member.email, &auth_id).await;
        let cookie = admin_cookie(&token);

        let (status, _body) = http_get(&app, "/admin/policies", &[("Cookie", &cookie)]).await;

        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "Non-admin GET /admin/policies must redirect"
        );
    }

    // ── Admin UI Endpoints — CSRF checks ─────────────────────────────────────

    #[tokio::test]
    async fn test_create_custom_policy_requires_origin() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);

        let (status, _body) = http_post_form(
            &app,
            "/admin/policies/custom",
            "policy_name=Test&cel_expression=posture.os+%3D%3D+%22macos%22",
            &[("Cookie", &cookie)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "POST without Origin header must be rejected with 403"
        );
    }

    #[tokio::test]
    async fn test_toggle_preconfigured_requires_origin() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);

        let (status, _body) = http_post_form(
            &app,
            "/admin/policies/preconfigured/disk_encryption/toggle",
            "",
            &[("Cookie", &cookie)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "POST without Origin header must be rejected with 403"
        );
    }

    // ── Input Validation ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_custom_policy_rejects_empty_name() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";

        let (status, _body) = http_post_form(
            &app,
            "/admin/policies/custom",
            "policy_name=&cel_expression=posture.os+%3D%3D+%22macos%22",
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;

        // Empty name triggers redirect with error query param
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "Empty name must result in redirect"
        );
    }

    #[tokio::test]
    async fn test_create_custom_policy_rejects_long_cel() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";

        let long_cel = "a".repeat(1025);
        let body = format!(
            "policy_name=Test&cel_expression={}",
            urlencoding::encode(&long_cel)
        );
        let (status, _body) = http_post_form(
            &app,
            "/admin/policies/custom",
            &body,
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "Over-length CEL must result in redirect"
        );
    }

    #[tokio::test]
    async fn test_toggle_preconfigured_invalid_slug() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";

        let (status, _body) = http_post_form(
            &app,
            "/admin/policies/preconfigured/nonexistent_slug_xyz/toggle",
            "",
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "Unknown preconfigured slug must return 404"
        );
    }
}
