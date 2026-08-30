// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture policies UI and API handlers.

use crate::AppState;
use crate::db;
use crate::db::documents::audit::{CustomPolicyAdminData, PreconfiguredPolicyToggleData};
use crate::error::ServiceError;
use crate::handlers::admin::flash;
use crate::impl_template_response;
use crate::services::policy as posture;
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

/// Maximum length of a policy name, in Unicode characters. Matches the
/// `maxlength` the admin form advertises, which the browser counts in
/// characters rather than UTF-8 bytes.
const MAX_POLICY_NAME_CHARS: usize = 100;

/// Maximum length of a policy description, in Unicode characters. Matches the
/// `maxlength` the admin form advertises.
const MAX_POLICY_DESCRIPTION_CHARS: usize = 500;

/// Size bound on a stored builder spec. A legitimate spec is well under
/// this; anything larger is dropped rather than stored.
const MAX_BUILDER_SPEC_LEN: usize = 8192;

/// One row of the merged policy list — built-in (code-defined) and custom
/// (admin-authored) policies together, active first.
pub(crate) struct PolicyRow {
    /// The preconfigured slug, or `"custom"` — selects the icon and the
    /// per-OS notes in the detail drawer.
    pub slug: String,
    /// Mutation target: the slug for built-ins, the document id for
    /// customs.
    pub key: String,
    pub name: String,
    pub description: String,
    pub policy_text: String,
    /// Seed text for the editor: the rule without its header comment for
    /// built-ins, the stored text for customs.
    pub editable_text: String,
    pub active: bool,
    pub builtin: bool,
    /// Whether the stored text still validates. A policy that does not
    /// denies every request while active, so the page flags it rather than
    /// letting an admin discover that through locked-out users.
    pub valid: bool,
    /// The stored builder spec, for customs authored with the builder.
    pub builder_spec: Option<String>,
}

/// Policies page template.
#[derive(Template)]
#[template(path = "admin/policies.html")]
pub(crate) struct AdminPoliciesTemplate {
    pub auth: AuthContext,
    pub policies: Vec<PolicyRow>,
    pub flash_message: Option<String>,
    /// The builder catalog, labels pre-translated, parsed by
    /// `policy-builder.js` from a `data-` attribute.
    pub catalog_json: String,
    pub field_groups: Vec<posture::catalog::FieldRefGroup>,
    pub event_groups: Vec<posture::catalog::EventRefGroup>,
    pub custom_count: usize,
    pub max_custom: usize,
    pub active_count: usize,
    pub max_active: usize,
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

    let mut policies: Vec<PolicyRow> = posture::PRECONFIGURED_POLICIES
        .iter()
        .map(|p| PolicyRow {
            slug: p.slug.to_string(),
            key: p.slug.to_string(),
            name: p.slug.name(),
            description: p.slug.description(),
            policy_text: p.policy_text.to_string(),
            editable_text: posture::as_editable(p.policy_text),
            active: active_slugs.iter().any(|s| s == p.slug.as_str()),
            builtin: true,
            valid: true,
            builder_spec: None,
        })
        .collect();

    let custom_count = match db::list_custom_policies(&state.store, &org_id).await {
        Ok(customs) => {
            let count = customs.len();
            policies.extend(customs.into_iter().map(|p| PolicyRow {
                slug: "custom".to_string(),
                key: p.id,
                name: p.name,
                description: p.description.unwrap_or_default(),
                valid: posture::validate_policy_text(&p.policy_text).is_ok(),
                editable_text: p.policy_text.clone(),
                policy_text: p.policy_text,
                active: p.active,
                builtin: false,
                builder_spec: p.builder_spec,
            }));
            count
        }
        Err(e) => {
            tracing::error!("Failed to load custom policies: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let active_count = policies.iter().filter(|p| p.active).count();
    // Active first; the sort is stable, so built-ins keep their catalog
    // order and customs their creation order within each half.
    policies.sort_by_key(|p| !p.active);

    // Consume any flash messages set by a prior POST → redirect, then expire
    // the cookies in the response so a refresh doesn't re-show them.
    let messages = flash::read(&jar);
    let jar = flash::clear(jar);

    let body = AdminPoliciesTemplate {
        auth,
        policies,
        flash_message: messages.err,
        catalog_json: posture::catalog::catalog_json(),
        field_groups: posture::catalog::field_reference_groups(),
        event_groups: posture::catalog::event_reference_groups(),
        custom_count,
        max_custom: MAX_CUSTOM_POLICIES,
        active_count,
        max_active: posture::MAX_ACTIVE_POLICIES,
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
    let data = PreconfiguredPolicyToggleData {
        action: format!("preconfigured_policy_{action}"),
        slug: &slug,
        admin_user_id: &admin.id,
    };
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminPolicyToggle,
            Some(&admin.id),
            Some(&admin.email),
            &data,
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
    pub policy_text: String,
    /// The serialized builder `RuleSpec` the text was generated from,
    /// absent when the admin edited the text directly.
    #[serde(default)]
    pub builder_spec: Option<String>,
}

/// Accept a submitted builder spec only if it regenerates exactly the
/// submitted text — a spec that disagrees would reopen the builder showing
/// conditions the saved policy does not enforce. A rejected spec is
/// dropped, not an error: the spec is advisory and the text is what is
/// enforced.
fn verified_builder_spec(form: &CustomPolicyForm) -> Option<&str> {
    let spec_json = form.builder_spec.as_deref()?;
    if spec_json.is_empty() {
        return None;
    }
    if spec_json.len() > MAX_BUILDER_SPEC_LEN {
        tracing::warn!("builder spec dropped: exceeds size bound");
        return None;
    }
    let spec: posture::rule::RuleSpec = match serde_json::from_str(spec_json) {
        Ok(spec) => spec,
        Err(e) => {
            tracing::warn!("builder spec dropped: does not parse: {e}");
            return None;
        }
    };
    match posture::rule::generate(&spec) {
        Ok(text) if text == form.policy_text => Some(spec_json),
        Ok(_) => {
            tracing::warn!("builder spec dropped: does not regenerate the submitted text");
            None
        }
        Err(e) => {
            tracing::warn!("builder spec dropped: does not generate: {e}");
            None
        }
    }
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
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > MAX_POLICY_NAME_CHARS {
        return Ok(redirect_error(
            jar,
            "Name must be between 1 and 100 characters",
        ));
    }

    if form.policy_text.is_empty()
        || form.policy_text.chars().count() > posture::catalog::MAX_POLICY_TEXT_LEN
    {
        return Ok(redirect_error(
            jar,
            format!(
                "Policy text must be between 1 and {} characters",
                posture::catalog::MAX_POLICY_TEXT_LEN
            ),
        ));
    }

    if let Some(ref desc) = form.description
        && desc.chars().count() > MAX_POLICY_DESCRIPTION_CHARS
    {
        return Ok(redirect_error(
            jar,
            "Description must be 500 characters or less",
        ));
    }

    // Authenticate before parsing: policy text is attacker-influenced
    // input, so only an authenticated org admin may reach the parser.
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    if let Err(e) = posture::validate_policy_text(&form.policy_text) {
        return Ok(redirect_error(jar, format!("Invalid policy: {e}")));
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

    let description = form.description.clone().filter(|d| !d.is_empty());

    let policy = db::create_custom_policy(
        &state.store,
        db::CreateCustomPolicyParams {
            name,
            description: description.as_deref(),
            policy_text: &form.policy_text,
            org_id: &org_id,
            builder_spec: verified_builder_spec(&form),
        },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to create policy: {e}")))?;

    let policy_hash = policy_text_hash(&form.policy_text);
    let data = CustomPolicyAdminData {
        action: "custom_policy_created".to_string(),
        policy_id: &policy.id,
        policy_name: Some(&policy.name),
        admin_user_id: &admin.id,
        policy_text_hash: Some(policy_hash),
    };
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminPolicyCreate,
            Some(&admin.id),
            Some(&admin.email),
            &data,
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

    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > MAX_POLICY_NAME_CHARS {
        return Ok(redirect_error(
            jar,
            "Name must be between 1 and 100 characters",
        ));
    }

    if form.policy_text.is_empty()
        || form.policy_text.chars().count() > posture::catalog::MAX_POLICY_TEXT_LEN
    {
        return Ok(redirect_error(
            jar,
            format!(
                "Policy text must be between 1 and {} characters",
                posture::catalog::MAX_POLICY_TEXT_LEN
            ),
        ));
    }

    if let Some(ref desc) = form.description
        && desc.chars().count() > MAX_POLICY_DESCRIPTION_CHARS
    {
        return Ok(redirect_error(
            jar,
            "Description must be 500 characters or less",
        ));
    }

    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    if let Err(e) = posture::validate_policy_text(&form.policy_text) {
        return Ok(redirect_error(jar, format!("Invalid policy: {e}")));
    }

    let description = form.description.clone().filter(|d| !d.is_empty());

    let result = db::update_custom_policy(
        &state.store,
        &id,
        &org_id,
        db::UpdateCustomPolicyParams {
            name: Some(name),
            description: description
                .as_deref()
                .map_or(db::FieldUpdate::Clear, db::FieldUpdate::Set),
            policy_text: Some(&form.policy_text),
            active: None,
            // The text is being replaced, so a stale spec must not
            // survive: set the verified one or clear.
            builder_spec: verified_builder_spec(&form)
                .map_or(db::FieldUpdate::Clear, db::FieldUpdate::Set),
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

    let policy_hash = policy_text_hash(&form.policy_text);
    let data = CustomPolicyAdminData {
        action: "custom_policy_updated".to_string(),
        policy_id: &id,
        policy_name: Some(&form.name),
        admin_user_id: &admin.id,
        policy_text_hash: Some(policy_hash),
    };
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminPolicyUpdate,
            Some(&admin.id),
            Some(&admin.email),
            &data,
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

    let data = CustomPolicyAdminData {
        action: "custom_policy_deleted".to_string(),
        policy_id: &id,
        policy_name: None,
        admin_user_id: &admin.id,
        policy_text_hash: None,
    };
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminPolicyDelete,
            Some(&admin.id),
            Some(&admin.email),
            &data,
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

    let result = db::update_custom_policy(
        &state.store,
        &id,
        &org_id,
        db::UpdateCustomPolicyParams {
            name: None,
            description: db::FieldUpdate::Keep,
            policy_text: None,
            active: Some(new_active),
            builder_spec: db::FieldUpdate::Keep,
        },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to toggle policy: {e}")))?;

    if result.is_none() {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Policy not found",
        ));
    }

    let action = if new_active {
        "activated"
    } else {
        "deactivated"
    };
    let policy_hash = policy_text_hash(&policy.policy_text);
    let data = CustomPolicyAdminData {
        action: format!("custom_policy_{action}"),
        policy_id: &id,
        policy_name: Some(&policy.name),
        admin_user_id: &admin.id,
        policy_text_hash: Some(policy_hash),
    };
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminPolicyToggle,
            Some(&admin.id),
            Some(&admin.email),
            &data,
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

/// SHA-256 hash of policy text, truncated to 16 hex chars. Audit
/// events record the hash so a policy change is attributable without
/// copying the policy itself into the log.
///
/// Included in audit events to trace which version of a policy was in
/// effect at the time of an admin action.
fn policy_text_hash(expression: &str) -> String {
    let hash = digest::digest(&SHA256, expression.as_bytes());
    hash.as_ref()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Response for the policy editor's validate call.
#[derive(Debug, serde::Serialize)]
pub(crate) struct ValidateResponse {
    pub valid: bool,
    /// The text that was validated — generated from `rule`, or echoed from
    /// `policy_text`. Absent only when generation itself failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_result: Option<TestResult>,
}

/// Result of dry-running policy text against the sample device.
#[derive(Debug, serde::Serialize)]
pub(crate) struct TestResult {
    pub pass: bool,
    /// True when the verdict reflects an empty event history rather than
    /// the policy's logic. The editor renders the explanation from the
    /// i18n catalog.
    pub reads_history: bool,
}

/// Request to validate a policy (JSON API for the policy editor): raw
/// `policy_text` or a builder `rule`, exactly one of the two.
#[derive(Debug, Deserialize)]
pub(crate) struct ValidateRequest {
    #[serde(default)]
    pub policy_text: Option<String>,
    #[serde(default)]
    pub rule: Option<posture::rule::RuleSpec>,
    /// Which decision point to dry-run `policy_text` against; a `rule`
    /// carries its own. Defaults to token issuance.
    #[serde(default)]
    pub decision: Option<posture::catalog::DecisionPoint>,
    /// Device the dry run evaluates; the built-in sample device when
    /// absent.
    #[serde(default)]
    pub test_posture: Option<vouch_common::posture::DevicePosture>,
}

fn invalid(text: Option<String>, error: String) -> Json<ValidateResponse> {
    Json(ValidateResponse {
        valid: false,
        policy_text: text,
        error: Some(error),
        test_result: None,
    })
}

/// POST /api/v1/org/policies/validate — validate a policy (JSON).
pub(crate) async fn validate_policy_api(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, ServiceError> {
    // Authenticate before parsing: policy text is attacker-influenced
    // input, so only an authenticated org admin may reach the parser.
    let _auth =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let (policy_text, decision) = match (req.policy_text, req.rule) {
        (Some(_), Some(_)) | (None, None) => {
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Provide exactly one of policy_text or rule",
            ));
        }
        (Some(text), None) => (
            text,
            req.decision
                .unwrap_or(posture::catalog::DecisionPoint::IssueToken),
        ),
        (None, Some(rule)) => match posture::rule::generate(&rule) {
            Ok(text) => (text, rule.decision),
            Err(e) => return Ok(invalid(None, e.to_string())),
        },
    };

    if policy_text.is_empty() || policy_text.chars().count() > posture::catalog::MAX_POLICY_TEXT_LEN
    {
        return Ok(invalid(
            Some(policy_text),
            format!(
                "Policy text must be between 1 and {} characters",
                posture::catalog::MAX_POLICY_TEXT_LEN
            ),
        ));
    }

    if let Err(e) = posture::validate_policy_text(&policy_text) {
        return Ok(invalid(Some(policy_text), format!("{e}")));
    }

    let test_posture = req
        .test_posture
        .unwrap_or_else(posture::catalog::sample_posture);
    let test_result = match posture::test_policy_text(&policy_text, &test_posture, decision) {
        Ok(result) => Some(TestResult {
            pass: result.pass,
            reads_history: result.reads_history,
        }),
        Err(_) => Some(TestResult {
            pass: false,
            reads_history: false,
        }),
    };

    Ok(Json(ValidateResponse {
        valid: true,
        policy_text: Some(policy_text),
        error: None,
        test_result,
    }))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::let_underscore_must_use,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::{MAX_POLICY_DESCRIPTION_CHARS, MAX_POLICY_NAME_CHARS, PolicyRow, posture};
    use crate::db;
    use crate::test_utils::*;
    use axum::http::StatusCode;
    use std::sync::Arc;

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

    /// Policy text that parses, for tests whose subject is a different field.
    const VALID_POLICY_TEXT: &str = "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };";

    // ── Validation API — accepted input ──────────────────────────────────────

    #[tokio::test]
    async fn test_policy_validate_valid_expression() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({
            "policy_text": "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };"
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
            "valid policy text should return 200: {resp}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "valid field must be true");
        assert!(
            json.get("error").is_none() || json["error"].is_null(),
            "no error for valid policy text"
        );
        assert_eq!(
            json["test_result"]["pass"], true,
            "without test_posture the built-in sample device is used, which runs macOS"
        );
        assert_eq!(
            json["policy_text"], body["policy_text"],
            "raw policy_text is echoed back"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_with_test_posture() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({
            "policy_text": "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };",
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
            "valid policy with matching posture should return 200: {resp}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "valid must be true");
        assert_eq!(
            json["test_result"]["pass"], true,
            "test_result.pass must be true when posture matches"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_with_failing_test_posture() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        // Expression checks for macos but posture reports linux
        let body = serde_json::json!({
            "policy_text": "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };",
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
        assert_eq!(json["valid"], true, "the policy text itself is valid");
        assert_eq!(
            json["test_result"]["pass"], false,
            "test_result.pass must be false when posture does not match"
        );
    }

    // ── Validation API — rejected input ──────────────────────────────────────

    #[tokio::test]
    async fn test_policy_validate_accepts_builder_rule() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({
            "rule": {
                "decision": "issue_token",
                "body": { "kind": "device", "conditions": [
                    { "kind": "field", "field": "disk_encryption_enabled", "op": "eq", "value": true }
                ]}
            }
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "builder rule must validate: {resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "{resp}");
        let text = json["policy_text"].as_str().expect("generated text");
        assert!(
            text.contains("unless {\n    context.device.disk_encryption_enabled\n}"),
            "generated text carries the condition: {text}"
        );
        assert_eq!(
            json["test_result"]["pass"], true,
            "the sample device has disk encryption on"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_rule_dry_runs_as_its_own_decision() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        // A step-up rule on exchange: with no history it must DENY when
        // evaluated as an exchange (as IssueToken it would trivially pass).
        let body = serde_json::json!({
            "rule": {
                "decision": "exchange_token",
                "body": { "kind": "history", "conditions": [
                    { "shape": "not_happened_within", "event": "login_success",
                      "window": { "amount": 15, "unit": "m" } }
                ]}
            }
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "{resp}");
        assert_eq!(
            json["test_result"]["reads_history"], true,
            "a temporal rule is history-dependent"
        );
        assert_eq!(
            json["test_result"]["pass"], false,
            "an exchange-scoped forbid must fire when dry-run as an exchange"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_rejects_both_or_neither_input() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        for body in [
            serde_json::json!({}),
            serde_json::json!({
                "policy_text": "permit (principal, action, resource);",
                "rule": {
                    "decision": "issue_token",
                    "body": { "kind": "device", "conditions": [
                        { "kind": "field", "field": "tty", "op": "eq", "value": true }
                    ]}
                }
            }),
        ] {
            let (status, resp) = http_post_json(
                &app,
                "/api/v1/org/policies/validate",
                &body.to_string(),
                &[("Authorization", &auth)],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "exactly one of policy_text/rule is required: {resp}"
            );
        }
    }

    #[tokio::test]
    async fn test_policy_validate_reports_rule_errors_as_invalid() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        // Device conditions on exchange cannot generate.
        let body = serde_json::json!({
            "rule": {
                "decision": "exchange_token",
                "body": { "kind": "device", "conditions": [
                    { "kind": "field", "field": "tty", "op": "eq", "value": true }
                ]}
            }
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], false, "{resp}");
        assert!(
            json["error"].as_str().unwrap().contains("token issuance"),
            "the error explains the device-on-exchange restriction: {resp}"
        );
    }

    #[tokio::test]
    async fn test_create_stores_verified_builder_spec_and_drops_mismatched() {
        let (app, state) = test_app().await;
        let (admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";
        let org_id = admin.org_id.clone().expect("admin has org");

        let spec = serde_json::json!({
            "decision": "issue_token",
            "body": { "kind": "device", "conditions": [
                { "kind": "field", "field": "firewall_enabled", "op": "eq", "value": true }
            ]}
        });
        let text = posture::rule::generate(&serde_json::from_value(spec.clone()).unwrap())
            .expect("spec generates");

        // Matching spec is stored.
        let form = format!(
            "policy_name={}&policy_text={}&builder_spec={}",
            urlencoding::encode("Firewall via builder"),
            urlencoding::encode(&text),
            urlencoding::encode(&spec.to_string()),
        );
        let (status, _body) = http_post_form(
            &app,
            "/admin/policies/custom",
            &form,
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let stored = db::list_custom_policies(&state.store, &org_id)
            .await
            .expect("list")
            .into_iter()
            .find(|p| p.name == "Firewall via builder")
            .expect("created");
        assert!(
            stored.builder_spec.is_some(),
            "a spec that regenerates the text must be stored"
        );

        // A spec that does not regenerate the submitted text is dropped.
        let form = format!(
            "policy_name={}&policy_text={}&builder_spec={}",
            urlencoding::encode("Hand-tweaked"),
            urlencoding::encode(
                "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) \
                 unless { context.device.tty };"
            ),
            urlencoding::encode(&spec.to_string()),
        );
        let (status, _body) = http_post_form(
            &app,
            "/admin/policies/custom",
            &form,
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let stored = db::list_custom_policies(&state.store, &org_id)
            .await
            .expect("list")
            .into_iter()
            .find(|p| p.name == "Hand-tweaked")
            .expect("created");
        assert!(
            stored.builder_spec.is_none(),
            "a spec that disagrees with the text must be dropped, not stored"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_requires_auth() {
        let (app, _state) = test_app().await;

        let body = serde_json::json!({"policy_text": "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };"});
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
    async fn test_policy_validate_requires_org_admin() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let member =
            create_test_user_in_org(&state.store, "member@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &member.id).await;
        let token = create_test_session(&state, &member.id, &member.email, &auth_id).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({"policy_text": "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };"});
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
    async fn test_policy_validate_empty_expression() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({"policy_text": ""});
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
    async fn test_policy_validate_too_long_expression() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        let long_expr = "a".repeat(4097);
        let body = serde_json::json!({"policy_text": long_expr});
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
            "valid must be false for >4096 char expression"
        );
        assert!(
            json["error"].as_str().is_some(),
            "error message must be present"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_invalid_syntax() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let auth = format!("Bearer {token}");

        // An unterminated string literal cannot parse
        let body = serde_json::json!({"policy_text": "posture.os == \"unterminated"});
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "Invalid policy returns 200: {resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            json["valid"], false,
            "valid must be false for invalid syntax"
        );
        assert!(
            json["error"].as_str().is_some(),
            "error message must be present for invalid policy text"
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

    /// The page renders for an org admin, carrying the builder's moving
    /// parts: the catalog data attribute, the three row templates, and the
    /// generated field reference — including the fields the old
    /// hand-written table had drifted away from.
    #[tokio::test]
    async fn test_admin_policies_page_renders_builder_scaffolding() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);

        let (status, body) = http_get(&app, "/admin/policies", &[("Cookie", &cookie)]).await;

        assert_eq!(status, StatusCode::OK, "org admin must get the page");
        for marker in [
            "id=\"policy-catalog\"",
            "data-catalog=",
            "id=\"tpl-device-row\"",
            "id=\"tpl-osfloor-row\"",
            "id=\"tpl-history-row\"",
            "id=\"policy-preview\"",
            "/static/js/policy-builder.js",
            // Generated reference covers the fields the 29-row table missed.
            "context.device.tpm_version",
            "context.device.collected_at",
            // The event reference for hand-written temporal rules.
            "input.user_agent",
            "Vouch::Action::\"IssueCredential\"::response",
        ] {
            assert!(body.contains(marker), "page must contain {marker}");
        }
        // All 11 built-ins render in the merged list.
        for policy in posture::PRECONFIGURED_POLICIES {
            assert!(
                body.contains(&policy.slug.name()),
                "built-in '{}' must appear in the merged list",
                policy.slug
            );
        }
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
            "policy_name=Test&policy_text=posture.os+%3D%3D+%22macos%22",
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
            "policy_name=&policy_text=posture.os+%3D%3D+%22macos%22",
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

    // The name and description guards count Unicode characters, not UTF-8
    // bytes, so a multibyte value within the limit the form advertises is
    // stored rather than rejected.
    #[tokio::test]
    async fn test_create_custom_policy_accepts_multibyte_name_and_description() {
        let (app, state) = test_app().await;
        let (admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";
        let org_id = admin.org_id.clone().expect("admin has org");

        // 90 CJK characters = 270 bytes; 400 CJK characters = 1200 bytes.
        let name = "名".repeat(90);
        let description = "説".repeat(400);
        assert!(name.len() > MAX_POLICY_NAME_CHARS);
        assert!(description.len() > MAX_POLICY_DESCRIPTION_CHARS);

        let form = format!(
            "policy_name={}&policy_description={}&policy_text={}",
            urlencoding::encode(&name),
            urlencoding::encode(&description),
            urlencoding::encode(VALID_POLICY_TEXT),
        );
        let (status, _body) = http_post_form(
            &app,
            "/admin/policies/custom",
            &form,
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let stored = db::list_custom_policies(&state.store, &org_id)
            .await
            .expect("list")
            .into_iter()
            .find(|p| p.name == name)
            .expect("multibyte name within the character limit must be stored");
        assert_eq!(stored.description.as_deref(), Some(description.as_str()));
    }

    #[tokio::test]
    async fn test_create_custom_policy_rejects_multibyte_name_over_char_limit() {
        let (app, state) = test_app().await;
        let (admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";
        let org_id = admin.org_id.clone().expect("admin has org");

        let name = "名".repeat(101);
        let form = format!(
            "policy_name={}&policy_text={}",
            urlencoding::encode(&name),
            urlencoding::encode(VALID_POLICY_TEXT),
        );
        let (status, _body) = http_post_form(
            &app,
            "/admin/policies/custom",
            &form,
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        assert!(
            db::list_custom_policies(&state.store, &org_id)
                .await
                .expect("list")
                .is_empty(),
            "a name over the character limit must not be stored"
        );
    }

    // A name of only whitespace is empty once trimmed, and the trimmed form is
    // what gets stored.
    #[tokio::test]
    async fn test_create_custom_policy_rejects_whitespace_only_name() {
        let (app, state) = test_app().await;
        let (admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";
        let org_id = admin.org_id.clone().expect("admin has org");

        let form = format!(
            "policy_name={}&policy_text={}",
            urlencoding::encode("   "),
            urlencoding::encode(VALID_POLICY_TEXT),
        );
        let (status, _body) = http_post_form(
            &app,
            "/admin/policies/custom",
            &form,
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        assert!(
            db::list_custom_policies(&state.store, &org_id)
                .await
                .expect("list")
                .is_empty(),
            "a whitespace-only name must not be stored"
        );
    }

    // The update path bounds the description too, so a policy cannot be given
    // an unbounded description after creation.
    #[tokio::test]
    async fn test_update_custom_policy_rejects_description_over_char_limit() {
        let (app, state) = test_app().await;
        let (admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";
        let org_id = admin.org_id.clone().expect("admin has org");

        let form = format!(
            "policy_name={}&policy_text={}",
            urlencoding::encode("Original"),
            urlencoding::encode(VALID_POLICY_TEXT),
        );
        let (status, _body) = http_post_form(
            &app,
            "/admin/policies/custom",
            &form,
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let created = db::list_custom_policies(&state.store, &org_id)
            .await
            .expect("list")
            .into_iter()
            .find(|p| p.name == "Original")
            .expect("created");

        let long_description = "x".repeat(501);
        let form = format!(
            "policy_name={}&policy_description={}&policy_text={}",
            urlencoding::encode("Renamed"),
            urlencoding::encode(&long_description),
            urlencoding::encode(VALID_POLICY_TEXT),
        );
        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/policies/custom/{}", created.id),
            &form,
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let after = db::list_custom_policies(&state.store, &org_id)
            .await
            .expect("list")
            .into_iter()
            .find(|p| p.id == created.id)
            .expect("still present");
        assert_eq!(
            after.name, "Original",
            "an over-long description must reject the whole update"
        );
        assert!(after.description.is_none());
    }

    #[tokio::test]
    async fn test_create_custom_policy_rejects_long_cel() {
        let (app, state) = test_app().await;
        let (_admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";

        let long_cel = "a".repeat(1025);
        let body = format!(
            "policy_name=Test&policy_text={}",
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
            "over-length policy text must result in redirect"
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

    // ── Custom policy toggle ─────────────────────────────────────────────────

    /// Helper: create a custom policy (inactive) owned by `setup_admin`'s org
    /// and return its id.
    async fn create_inactive_custom_policy(state: &crate::AppState, org_id: &str) -> String {
        let policy = db::create_custom_policy(
            &state.store,
            db::CreateCustomPolicyParams {
                name: "Toggle Me",
                description: None,
                policy_text: "posture.os == \"linux\"",
                org_id,
                builder_spec: None,
            },
        )
        .await
        .expect("create custom policy");
        policy.id
    }

    /// Count `admin_policy_toggle` audit events for `admin_id`.
    async fn count_toggle_audit_events(state: &crate::AppState, admin_id: &str) -> usize {
        let filter = db::AuditEventFilter {
            event_types: Some(vec![
                db::AuditEventKind::AdminPolicyToggle.as_str().to_string(),
            ]),
            user_id: Some(admin_id.to_string()),
            ..Default::default()
        };
        state
            .audit
            .query_events(&filter)
            .await
            .expect("query audit events")
            .len()
    }

    #[tokio::test]
    async fn test_toggle_custom_policy_activates_and_logs_audit_event() {
        let (app, state) = test_app().await;
        let (admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";

        let org_id = admin.org_id.clone().expect("admin has org");
        let policy_id = create_inactive_custom_policy(&state, &org_id).await;

        let before = count_toggle_audit_events(&state, &admin.id).await;
        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/policies/custom/{policy_id}/toggle"),
            "",
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "Successful toggle must redirect"
        );

        // The policy is now active in the DB.
        let updated = db::get_custom_policy(&state.store, &policy_id)
            .await
            .expect("get policy")
            .expect("policy exists");
        assert!(updated.active, "policy must be activated by the toggle");

        // Exactly one new toggle audit event was logged for the admin.
        let after = count_toggle_audit_events(&state, &admin.id).await;
        assert_eq!(
            after,
            before + 1,
            "exactly one audit event must follow a successful toggle"
        );
    }

    #[tokio::test]
    async fn test_toggle_custom_policy_unknown_id_returns_not_found() {
        let (app, state) = test_app().await;
        let (admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";

        let before = count_toggle_audit_events(&state, &admin.id).await;
        let (status, body) = http_post_form(
            &app,
            "/admin/policies/custom/does-not-exist/toggle",
            "",
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "Toggle of unknown policy id must return 404: {body}"
        );
        assert!(
            body.contains("not_found"),
            "404 body must carry the not_found code: {body}"
        );

        // No audit event may be logged for a failed toggle.
        let after = count_toggle_audit_events(&state, &admin.id).await;
        assert_eq!(
            after, before,
            "no audit event must be logged when the policy is not found"
        );
    }

    /// Regression: when the policy is deleted between the handler's initial
    /// GET and its `db::update_custom_policy` call (the OCC race window),
    /// `update_custom_policy` returns `Ok(None)`. The handler must return
    /// 404 NOT_FOUND and must NOT log an audit event.
    ///
    /// Before the fix the handler ignored the `None` result, logged a
    /// fraudulent `admin_policy_toggle` audit event, and returned a success
    /// redirect.
    #[tokio::test]
    async fn test_toggle_custom_policy_concurrent_delete_returns_not_found() {
        // Build the app with a `modify` hook that deletes whichever document
        // is being modified on the first OCC attempt. There is exactly one
        // custom policy in this test, so the hook deterministically deletes
        // it mid-flight, forcing `update_custom_policy` to return `Ok(None)`
        // exactly as it does in production when a policy is deleted
        // concurrently.
        //
        // The hook writes through a hookless clone of the store (mirroring the
        // pattern in `db::tests`) so the delete does not re-enter the hook.
        let (app, state) = test_app_with_modify_hook(|store| {
            let writer = store.clone();
            store.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
                let writer = writer.clone();
                let doc_id = doc_id.to_string();
                Box::pin(async move {
                    if attempt != 0 {
                        return;
                    }
                    // Delete the policy mid-flight so `modify` re-reads a
                    // missing document and `update_custom_policy` returns
                    // `Ok(None)`.
                    let _ = writer.delete(&doc_id).await;
                })
            }));
        })
        .await;

        let (admin, token) = setup_admin(&state).await;
        let cookie = admin_cookie(&token);
        let origin = "https://test.example.com";

        let org_id = admin.org_id.clone().expect("admin has org");
        let policy_id = create_inactive_custom_policy(&state, &org_id).await;

        let before = count_toggle_audit_events(&state, &admin.id).await;
        let (status, body) = http_post_form(
            &app,
            &format!("/admin/policies/custom/{policy_id}/toggle"),
            "",
            &[("Cookie", &cookie), ("Origin", origin)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "Toggle of a policy deleted mid-flight must return 404, not a success redirect: {body}"
        );
        assert!(
            body.contains("not_found"),
            "race-condition 404 body must carry the not_found code: {body}"
        );

        // The fraudulent audit event must NOT be logged.
        let after = count_toggle_audit_events(&state, &admin.id).await;
        assert_eq!(
            after, before,
            "no audit event must be logged when the update did not occur"
        );

        // Confirm the policy is really gone (the hook deleted it).
        let gone = db::get_custom_policy(&state.store, &policy_id)
            .await
            .expect("get policy");
        assert!(
            gone.is_none(),
            "policy must have been deleted by the OCC hook"
        );
    }
    /// A stored policy that fails validation is flagged on the page, so an
    /// admin sees it before users are locked out.
    #[tokio::test]
    async fn test_policies_page_flags_invalid_custom_policy() {
        let (app, state) = test_app().await;
        let (admin, _token) = setup_admin(&state).await;
        let org_id = admin.org_id.clone().expect("admin must have an org");

        // A bare boolean expression stores fine but is not a policy.
        db::create_custom_policy(
            &state.store,
            db::CreateCustomPolicyParams {
                name: "Unparseable",
                description: None,
                policy_text: "posture.disk_encryption_enabled == true",
                org_id: &org_id,
                builder_spec: None,
            },
        )
        .await
        .expect("create unparseable policy");

        let rows: Vec<PolicyRow> = db::list_custom_policies(&state.store, &org_id)
            .await
            .expect("list")
            .into_iter()
            .map(|p| PolicyRow {
                slug: "custom".to_string(),
                key: p.id,
                name: p.name,
                description: p.description.unwrap_or_default(),
                valid: posture::validate_policy_text(&p.policy_text).is_ok(),
                editable_text: p.policy_text.clone(),
                policy_text: p.policy_text,
                active: p.active,
                builtin: false,
                builder_spec: p.builder_spec,
            })
            .collect();

        let unparseable = rows
            .iter()
            .find(|r| r.name == "Unparseable")
            .expect("unparseable policy row");
        assert!(
            !unparseable.valid,
            "text that does not validate must be flagged on the policies page"
        );
        drop(app);
    }
}
