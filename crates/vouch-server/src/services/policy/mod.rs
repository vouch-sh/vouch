// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture policy evaluation using Dogwood (Cedar + temporal).
//!
//! Replaces the CEL engine: preconfigured policies are code-defined Cedar
//! `forbid … unless` rules, custom policies are admin-authored Cedar/Dogwood
//! text. The composed policy set always starts with one base `permit` for
//! the decision action; every active policy is a `forbid` that fires on
//! violation, so all active policies are ANDed (deny overrides permit),
//! matching the CEL engine's semantics. All error paths fail closed.
//!
//! Custom policies are evaluated one policy set per policy (base permit +
//! the candidate forbid): a policy that fails to lower — e.g. leftover CEL
//! text from before the migration — denies with that policy's name instead
//! of taking the whole org's policy set down.

pub(crate) mod engine;
pub(crate) mod events;
pub(crate) mod posture_input;
pub(crate) mod preconfigured;
pub(crate) mod remediation;
pub(crate) mod schema;

#[cfg(test)]
mod tests;

pub(crate) use preconfigured::{
    MAX_ACTIVE_POLICIES, PRECONFIGURED_POLICIES, PreconfiguredSlug, is_valid_preconfigured_slug,
};
pub(crate) use remediation::remediation_for_slug;

use crate::db;
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use dogwood_language::{Authorizer, Decision, Event, LoweredPolicySet, Validator, Value};
use preconfigured::BASE_ALLOW;
use vouch_common::posture::DevicePosture;

/// Outcome of one stateless policy-set evaluation (playground path; the
/// enforcement path's decisions carry rule attribution via
/// [`engine::OrgDecision`] instead).
enum EngineDecision {
    Allow,
    Deny,
}

/// Compose a policy set: the base permit followed by each policy text.
fn compose(policy_texts: &[&str]) -> String {
    let mut composed = String::from(BASE_ALLOW);
    for text in policy_texts {
        composed.push_str("\n\n");
        composed.push_str(text);
    }
    composed
}

/// Build the `IssueToken` decision event for one evaluation.
fn issue_token_request(posture: &DevicePosture, user_id: &str, org_id: &str) -> Event {
    let posture_value = posture_input::posture_record(posture);
    Event::builder("Vouch::Action::IssueToken", "request")
        .timestamp(0)
        .principal_for("Vouch::User", user_id)
        .resource_for("Vouch::Org", org_id)
        .request_context("input", "posture", posture_value)
        .request_context("input", "ip", Value::String(String::new()))
        .request_context("input", "client_id", Value::String(String::new()))
        .field("input", "ip", Value::String(String::new()))
        .field("input", "client_id", Value::String(String::new()))
        .build()
}

/// Lower a composed policy set and decide the given event with a fresh
/// authorizer (stateless: no event history — temporal atoms see an empty
/// trace and evaluate accordingly).
///
/// Returns `Err` only for engine-level failures (schema unavailable,
/// lowering error, no decision returned) — callers treat those as deny.
fn decide(policy_text: &str, event: &Event) -> Result<EngineDecision, String> {
    let policy_schema = schema::policy_schema().ok_or("policy schema unavailable")?;
    let lowered = LoweredPolicySet::from_str(policy_text, schema::service_schema(), policy_schema)
        .map_err(|e| format!("policy set failed to lower: {e}"))?;
    let mut authorizer = Authorizer::new(lowered);
    let response = authorizer
        .is_authorized(event)
        .ok_or("no decision returned for a request event")?;
    for error in response.diagnostics().errors() {
        tracing::warn!("policy evaluation error: {error}");
    }
    match response.decision() {
        Decision::Allow => Ok(EngineDecision::Allow),
        Decision::Deny => Ok(EngineDecision::Deny),
    }
}

// ============================================================
// Policy Text Validation (admin create/update + playground)
// ============================================================

/// Validate custom policy text: parse, lower against the Vouch schema, and
/// type-check. Returns a 400 `ServiceError` with the engine's diagnostic
/// message on failure.
pub(crate) fn validate_policy_text(text: &str) -> ServiceResult<()> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        tracing::debug!("policy validation rejected: empty text");
        return Err(ServiceError::api(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_policy_expression",
            "Policy text must not be empty",
        ));
    }
    let Some(policy_schema) = schema::policy_schema() else {
        return Err(ServiceError::Internal(
            "policy schema unavailable".to_string(),
        ));
    };
    let composed = compose(&[trimmed]);
    let lowered =
        match LoweredPolicySet::from_str(&composed, schema::service_schema(), policy_schema) {
            Ok(lowered) => lowered,
            Err(e) => {
                tracing::warn!("policy validation failed to lower: {e}");
                return Err(ServiceError::api(
                    axum::http::StatusCode::BAD_REQUEST,
                    "invalid_policy_expression",
                    format!("Invalid policy: {e}"),
                ));
            }
        };
    let report = Validator::new().validate(&lowered);
    let errors: Vec<String> = report.validation_errors().map(|e| e.to_string()).collect();
    if !errors.is_empty() {
        tracing::warn!("policy validation found type errors: {}", errors.join("; "));
        return Err(ServiceError::api(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_policy_expression",
            format!("Invalid policy: {}", errors.join("; ")),
        ));
    }
    tracing::debug!("policy text validated successfully");
    Ok(())
}

/// Evaluate a candidate policy against a sample `DevicePosture` (the admin
/// playground). Temporal conditions evaluate against an empty event history.
///
/// Returns `Ok(true)` if issuance would be allowed with only this policy
/// active, `Ok(false)` if it would be denied, or `Err` if the text is
/// invalid.
pub(crate) fn test_policy_text(text: &str, posture: &DevicePosture) -> ServiceResult<bool> {
    validate_policy_text(text)?;
    let composed = compose(&[text.trim()]);
    let event = issue_token_request(posture, "playground", "playground");
    match decide(&composed, &event) {
        Ok(EngineDecision::Allow) => Ok(true),
        Ok(EngineDecision::Deny) => Ok(false),
        Err(msg) => {
            tracing::error!("playground evaluation failed: {msg}");
            Err(ServiceError::Internal(
                "policy engine unavailable".to_string(),
            ))
        }
    }
}

// ============================================================
// Policy Enforcement (stateful, per-org engines)
// ============================================================

/// The decision being authorized.
enum DecisionKind<'a> {
    IssueToken {
        posture: &'a DevicePosture,
        ip: Option<std::net::IpAddr>,
        client_id: &'a str,
    },
    ExchangeToken {
        ip: Option<std::net::IpAddr>,
        client_id: &'a str,
        audience: Option<&'a str>,
    },
}

fn ip_string(ip: Option<std::net::IpAddr>) -> String {
    ip.map(|addr| addr.to_string()).unwrap_or_default()
}

fn decision_event(kind: &DecisionKind<'_>, user_id: &str, org_id: &str, ts: i64) -> Event {
    match kind {
        DecisionKind::IssueToken {
            posture,
            ip,
            client_id,
        } => {
            let ip = ip_string(*ip);
            Event::builder("Vouch::Action::IssueToken", "request")
                .timestamp(ts)
                .principal_for("Vouch::User", user_id)
                .resource_for("Vouch::Org", org_id)
                .request_context("input", "posture", posture_input::posture_record(posture))
                .request_context("input", "ip", Value::String(ip.clone()))
                .request_context(
                    "input",
                    "client_id",
                    Value::String((*client_id).to_string()),
                )
                .field("input", "ip", Value::String(ip))
                .field(
                    "input",
                    "client_id",
                    Value::String((*client_id).to_string()),
                )
                .build()
        }
        DecisionKind::ExchangeToken {
            ip,
            client_id,
            audience,
        } => {
            let ip = ip_string(*ip);
            let audience = audience.unwrap_or_default().to_string();
            Event::builder("Vouch::Action::ExchangeToken", "request")
                .timestamp(ts)
                .principal_for("Vouch::User", user_id)
                .resource_for("Vouch::Org", org_id)
                .request_context("input", "ip", Value::String(ip.clone()))
                .request_context(
                    "input",
                    "client_id",
                    Value::String((*client_id).to_string()),
                )
                .request_context("input", "audience", Value::String(audience.clone()))
                .field("input", "ip", Value::String(ip))
                .field(
                    "input",
                    "client_id",
                    Value::String((*client_id).to_string()),
                )
                .field("input", "audience", Value::String(audience))
                .build()
        }
    }
}

/// Build the composed policy set for an org: base permits, active
/// preconfigured forbids, then custom policies that individually lower.
/// Customs that do not lower (e.g. leftover CEL text) are returned as
/// `broken` — the engine denies while any exist (fail-closed, by name).
fn build_engine_parts(
    active_slugs: &[String],
    active_custom: &[db::CustomPosturePolicy],
) -> Result<(engine::EngineParts, Vec<String>), String> {
    let policy_schema = schema::policy_schema().ok_or("policy schema unavailable")?;
    let mut refs = vec![engine::PolicyRef::BasePermit; preconfigured::BASE_ALLOW_RULES];
    let mut texts: Vec<&str> = Vec::new();
    for slug_str in active_slugs {
        if let Ok(slug) = slug_str.parse::<PreconfiguredSlug>()
            && let Some(policy) = PRECONFIGURED_POLICIES.iter().find(|p| p.slug == slug)
        {
            texts.push(policy.policy_text);
            refs.push(engine::PolicyRef::Preconfigured(slug));
        }
    }
    let mut broken = Vec::new();
    for custom in active_custom {
        let alone = compose(&[custom.policy_text.as_str()]);
        match LoweredPolicySet::from_str(&alone, schema::service_schema(), policy_schema) {
            Ok(_) => {
                texts.push(custom.policy_text.as_str());
                refs.push(engine::PolicyRef::Custom {
                    name: custom.name.clone(),
                });
            }
            Err(e) => {
                tracing::warn!(
                    policy_name = custom.name,
                    "custom policy does not lower (fail-closed): {e}"
                );
                broken.push(custom.name.clone());
            }
        }
    }
    let composed = compose(&texts);
    let lowered = LoweredPolicySet::from_str(&composed, schema::service_schema(), policy_schema)
        .map_err(|e| format!("composed org policy set failed to lower: {e}"))?;
    Ok((engine::EngineParts { lowered, refs }, broken))
}

/// Deny message for a determining rule.
fn deny_error(denying: Option<engine::PolicyRef>, os: Option<&str>) -> ServiceError {
    let (name, remediation) = match denying {
        Some(engine::PolicyRef::Preconfigured(slug)) => {
            let name = PRECONFIGURED_POLICIES
                .iter()
                .find(|p| p.slug == slug)
                .map_or("policy", |p| p.name);
            (name.to_string(), remediation_for_slug(slug, os))
        }
        Some(engine::PolicyRef::Custom { name }) => (
            name,
            "Check your device settings to meet your organization's \
             compliance requirements"
                .to_string(),
        ),
        Some(engine::PolicyRef::BasePermit) | None => (
            "posture".to_string(),
            "Check your device settings to meet your organization's \
             compliance requirements"
                .to_string(),
        ),
    };
    tracing::debug!(policy = name, "policy denied");
    ServiceError::oauth(
        OAuthErrorCode::AccessDenied,
        format!("Device posture policy '{name}' not satisfied. {remediation}"),
    )
}

/// Run one decision through the org's stateful engine, building or
/// rebuilding it (with a 24h audit replay) when the org's policy
/// configuration changed.
async fn authorize_decision(
    state: &crate::AppState,
    org_id: &str,
    user_id: &str,
    active_slugs: &[String],
    active_custom: &[db::CustomPosturePolicy],
    kind: DecisionKind<'_>,
    os: Option<&str>,
) -> ServiceResult<()> {
    let custom_pairs: Vec<(String, String)> = active_custom
        .iter()
        .map(|c| (c.id.clone(), c.policy_text.clone()))
        .collect();
    let fingerprint = engine::fingerprint(active_slugs, &custom_pairs);
    let now = jiff::Timestamp::now().as_second();

    // Two passes: the first may find no current engine and install one; the
    // second decides. A concurrent policy change between passes surfaces as
    // another None — treated as unavailable rather than looping forever.
    for _attempt in 0_u8..2 {
        let Some(cursor) = state.policy.cursor_if_current(org_id, fingerprint) else {
            let (parts, broken) =
                build_engine_parts(active_slugs, active_custom).map_err(|msg| {
                    tracing::error!(org_id, "policy engine build failed: {msg}");
                    ServiceError::Internal("policy engine unavailable".to_string())
                })?;
            if let Some(name) = broken.first() {
                return Err(deny_error(
                    Some(engine::PolicyRef::Custom { name: name.clone() }),
                    os,
                ));
            }
            let replay = events::fetch_history(&state.audit, None)
                .await
                .map_err(|msg| {
                    tracing::error!(org_id, "policy history replay failed: {msg}");
                    ServiceError::Internal("policy engine unavailable".to_string())
                })?;
            state.policy.install(org_id, fingerprint, parts, &replay);
            continue;
        };
        let tail = events::fetch_history(&state.audit, cursor)
            .await
            .map_err(|msg| {
                tracing::error!(org_id, "policy history tail failed: {msg}");
                ServiceError::Internal("policy engine unavailable".to_string())
            })?;
        match state.policy.decide(org_id, fingerprint, &tail, now, |ts| {
            decision_event(&kind, user_id, org_id, ts)
        }) {
            Some(Ok(engine::OrgDecision::Allow)) => return Ok(()),
            Some(Ok(engine::OrgDecision::Deny(denying))) => return Err(deny_error(denying, os)),
            Some(Err(msg)) => {
                tracing::error!(org_id, "policy decision failed: {msg}");
                return Err(ServiceError::Internal(
                    "policy engine unavailable".to_string(),
                ));
            }
            None => {}
        }
    }
    tracing::error!(org_id, "policy engine unavailable after rebuild");
    Err(ServiceError::Internal(
        "policy engine unavailable".to_string(),
    ))
}

/// Evaluate all active posture policies for an org against device posture.
///
/// Called during FIDO2 token issuance (between assertion verification
/// and access token creation).
///
/// # Errors
///
/// Returns `ServiceError::OAuth { AccessDenied, ... }` if:
/// - Posture-requiring policies are active but no device posture was
///   provided
/// - Any active policy denies (or fails to evaluate — fail-closed)
///
/// Returns `ServiceError::Internal` if the engine itself is unavailable
/// (embedded schema broken, composed set fails to lower) — also
/// fail-closed: no token is issued.
pub(crate) async fn evaluate_posture_policies(
    state: &crate::AppState,
    org_id: &str,
    user_id: &str,
    client_ip: Option<std::net::IpAddr>,
    client_id: &str,
    authorization_details: Option<&serde_json::Value>,
) -> ServiceResult<()> {
    let active_slugs = db::get_active_preconfigured_slugs(&state.store, org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to load posture config: {e}")))?;
    let active_custom = db::get_active_custom_policies(&state.store, org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to load custom policies: {e}")))?;
    if active_slugs.is_empty() && active_custom.is_empty() {
        return Ok(());
    }

    // Posture data is demanded only when an active policy actually reads
    // it: any posture-requiring preconfigured slug, or any custom policy
    // (assumed posture-targeting). Orgs running only temporal policies do
    // not require clients to send posture.
    let posture_required = !active_custom.is_empty()
        || active_slugs
            .iter()
            .filter_map(|s| s.parse::<PreconfiguredSlug>().ok())
            .any(PreconfiguredSlug::requires_posture);
    let posture = if posture_required {
        extract_device_posture(authorization_details)?
    } else {
        match extract_device_posture(authorization_details) {
            Ok(posture) => posture,
            Err(_) => DevicePosture::new(),
        }
    };
    let os = posture
        .os
        .as_ref()
        .map(|o| o.as_str())
        .map(ToString::to_string);

    tracing::debug!(
        preconfigured_count = active_slugs.len(),
        custom_count = active_custom.len(),
        "Evaluating posture policies"
    );
    authorize_decision(
        state,
        org_id,
        user_id,
        &active_slugs,
        &active_custom,
        DecisionKind::IssueToken {
            posture: &posture,
            ip: client_ip,
            client_id,
        },
        os.as_deref(),
    )
    .await
}

/// Evaluate temporal policies gating RFC 8693 token exchange (the WIF /
/// agent credential path). No posture is involved — exchange requests
/// carry no device posture; only event-history policies apply.
///
/// # Errors
///
/// Returns `AccessDenied` when an active exchange policy denies, or
/// `Internal` when the engine is unavailable (fail-closed).
pub(crate) async fn evaluate_exchange_policies(
    state: &crate::AppState,
    org_id: &str,
    user_id: &str,
    client_ip: Option<std::net::IpAddr>,
    client_id: &str,
    audience: Option<&str>,
) -> ServiceResult<()> {
    let active_slugs = db::get_active_preconfigured_slugs(&state.store, org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to load posture config: {e}")))?;
    let active_custom = db::get_active_custom_policies(&state.store, org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to load custom policies: {e}")))?;
    if active_slugs.is_empty() && active_custom.is_empty() {
        return Ok(());
    }
    authorize_decision(
        state,
        org_id,
        user_id,
        &active_slugs,
        &active_custom,
        DecisionKind::ExchangeToken {
            ip: client_ip,
            client_id,
            audience,
        },
        None,
    )
    .await
}

/// Extract `DevicePosture` from the `authorization_details` JSON value.
///
/// Looks for an entry with `type: "device_posture"` in the RFC 9396 array.
fn extract_device_posture(ad_value: Option<&serde_json::Value>) -> ServiceResult<DevicePosture> {
    let value = ad_value.ok_or_else(|| {
        ServiceError::oauth(
            OAuthErrorCode::AccessDenied,
            "Device posture data is required by organization policy",
        )
    })?;

    let entries = value.as_array().ok_or_else(|| {
        ServiceError::oauth(
            OAuthErrorCode::AccessDenied,
            "Invalid authorization_details format: expected JSON array",
        )
    })?;

    for entry in entries {
        let type_name = entry.get("type").and_then(serde_json::Value::as_str);
        if type_name == Some(vouch_common::posture::POSTURE_TYPE) {
            let mut posture: DevicePosture =
                serde_json::from_value(entry.clone()).map_err(|e| {
                    tracing::warn!("Failed to deserialize device posture: {e}");
                    ServiceError::oauth(
                        OAuthErrorCode::AccessDenied,
                        format!("Invalid device posture data: {e}"),
                    )
                })?;
            posture.normalize();
            tracing::debug!(
                os = posture.os.as_ref().map(|o| o.as_str()),
                "Extracted device posture from authorization_details"
            );
            return Ok(posture);
        }
    }

    Err(ServiceError::oauth(
        OAuthErrorCode::AccessDenied,
        "Device posture data is required by organization policy",
    ))
}
