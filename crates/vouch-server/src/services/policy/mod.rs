// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture policy evaluation using Dogwood (Cedar + temporal).
//!
//! Replaces the CEL engine: preconfigured policies are code-defined Cedar
//! `forbid … unless` rules, custom policies are admin-authored Cedar/Dogwood
//! text. The composed policy set always starts with base `permit`s for the
//! decision actions; every active policy is a `forbid` that fires on
//! violation, so all active policies are ANDed (deny overrides permit),
//! matching the CEL engine's semantics. All error paths fail closed.
//!
//! Enforcement evaluates per decision: the org's composed set is prechecked
//! (lower + validate, cached by config fingerprint — a custom policy that
//! fails, e.g. leftover CEL text, denies with its name), then a fresh
//! authorizer replays the requesting principal's 24h audit history and
//! decides. See `engine` for why per-decision replay is sound and correct
//! across replicas.

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
use dogwood_language::{
    Authorizer, Decision, Event, EventBuilder, LoweredPolicySet, Validator, Value,
};
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

/// Write the posture fields into the request-only `device` context group.
/// The builder sets one `group.field` at a time, so the record's fields are
/// written individually — policies read `context.device.<field>`.
fn with_device_context(builder: EventBuilder, posture: &DevicePosture) -> EventBuilder {
    let mut builder = builder;
    for (name, value) in posture_input::posture_fields(posture) {
        builder = builder.request_context("device", &name, value);
    }
    builder
}

/// Build the `IssueToken` decision event for one evaluation.
fn issue_token_request(posture: &DevicePosture, user_id: &str, org_id: &str) -> Event {
    let builder = Event::builder("Vouch::Action::IssueToken", "request")
        .timestamp(0)
        .principal_for("Vouch::User", user_id)
        .resource_for("Vouch::Org", org_id)
        .request_context("input", "ip", Value::String(String::new()))
        .request_context("input", "client_id", Value::String(String::new()))
        .field("input", "ip", Value::String(String::new()))
        .field("input", "client_id", Value::String(String::new()));
    with_device_context(builder, posture).build()
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

/// Outcome of a playground evaluation.
pub(crate) struct PolicyTestResult {
    /// Whether issuance would be allowed with only this policy active.
    pub pass: bool,
    /// Set when the verdict depends on event history the playground cannot
    /// reproduce, so the caller can label the result rather than present a
    /// bare pass/fail the admin would misread.
    pub note: Option<&'static str>,
}

/// Evaluate a candidate policy against a sample `DevicePosture` (the admin
/// playground).
///
/// A temporal policy's verdict depends on the requesting user's audit
/// history, which the playground has none of. Evaluating one against an
/// empty trace would report a confident pass/fail that says nothing about
/// the policy's logic, so those results carry an explanatory note.
///
/// Returns `Err` if the text is invalid.
pub(crate) fn test_policy_text(
    text: &str,
    posture: &DevicePosture,
) -> ServiceResult<PolicyTestResult> {
    validate_policy_text(text)?;
    let trimmed = text.trim();
    let composed = compose(&[trimmed]);
    let event = issue_token_request(posture, "playground", "playground");
    let pass = match decide(&composed, &event) {
        Ok(EngineDecision::Allow) => true,
        Ok(EngineDecision::Deny) => false,
        Err(msg) => {
            tracing::error!("playground evaluation failed: {msg}");
            return Err(ServiceError::Internal(
                "policy engine unavailable".to_string(),
            ));
        }
    };
    let note = trimmed.contains("when temporal").then_some(
        "This policy reads event history, which the test device has none of. \
         The result below reflects an empty history, not the policy's logic.",
    );
    Ok(PolicyTestResult { pass, note })
}

// ============================================================
// Policy Enforcement (per-decision, principal-scoped)
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
            // Posture is request-only (`device` group): audit history
            // carries no posture, so it must not be temporally matchable.
            // `input` fields go to both bags — the Cedar request context
            // and the logged record temporal predicates match against.
            let builder = Event::builder("Vouch::Action::IssueToken", "request")
                .timestamp(ts)
                .principal_for("Vouch::User", user_id)
                .resource_for("Vouch::Org", org_id)
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
                );
            with_device_context(builder, posture).build()
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

/// The composed policy set for an org: the composed text plus the
/// rule-index → source map (base permits first, then active preconfigured
/// forbids, then customs, in composition order).
struct OrgPolicySet {
    composed: String,
    refs: Vec<engine::PolicyRef>,
}

fn compose_org_set(
    active_slugs: &[String],
    active_custom: &[db::CustomPosturePolicy],
) -> OrgPolicySet {
    let mut refs = vec![engine::PolicyRef::BasePermit; preconfigured::BASE_ALLOW_RULES];
    let mut texts: Vec<&str> = Vec::new();
    for slug_str in active_slugs {
        if let Ok(slug) = slug_str.parse::<PreconfiguredSlug>()
            && let Some(policy) = PRECONFIGURED_POLICIES.iter().find(|p| p.slug == slug)
        {
            texts.push(policy.policy_text);
            refs.push(engine::PolicyRef::Policy(
                engine::DenyingPolicy::Preconfigured(slug),
            ));
        }
    }
    for custom in active_custom {
        texts.push(custom.policy_text.as_str());
        refs.push(engine::PolicyRef::Policy(engine::DenyingPolicy::Custom {
            name: custom.name.clone(),
        }));
    }
    OrgPolicySet {
        composed: compose(&texts),
        refs,
    }
}

/// Static precheck of an org's composed set: it must lower AND validate.
/// On failure, bisect the custom policies (each alone with the base
/// permits) to attribute the failure to one policy by name — leftover CEL
/// text and schema drift across deploys both land here.
fn run_precheck(composed: &str, active_custom: &[db::CustomPosturePolicy]) -> engine::Precheck {
    let Some(policy_schema) = schema::policy_schema() else {
        return engine::Precheck::EngineError("policy schema unavailable".to_string());
    };
    let composed_result =
        LoweredPolicySet::from_str(composed, schema::service_schema(), policy_schema)
            .map_err(|e| format!("composed set failed to lower: {e}"))
            .and_then(|lowered| {
                let report = Validator::new().validate(&lowered);
                let errors: Vec<String> =
                    report.validation_errors().map(|e| e.to_string()).collect();
                if errors.is_empty() {
                    // A set with no temporal leaves needs no event history.
                    Ok(!lowered.is_self_contained_cedar())
                } else {
                    Err(format!(
                        "composed set failed validation: {}",
                        errors.join("; ")
                    ))
                }
            });
    let composed_error = match composed_result {
        Ok(uses_temporal) => return engine::Precheck::Ok { uses_temporal },
        Err(e) => e,
    };
    for custom in active_custom {
        let alone = compose(&[custom.policy_text.as_str()]);
        let ok = match LoweredPolicySet::from_str(&alone, schema::service_schema(), policy_schema) {
            Ok(lowered) => {
                Validator::new()
                    .validate(&lowered)
                    .validation_errors()
                    .count()
                    == 0
            }
            Err(_) => false,
        };
        if !ok {
            tracing::warn!(
                policy_name = custom.name,
                "custom policy fails precheck (fail-closed): {composed_error}"
            );
            return engine::Precheck::BrokenCustom(custom.name.clone());
        }
    }
    engine::Precheck::EngineError(composed_error)
}

/// Write the evidence trail for a denied decision. Best-effort, matching
/// the other login-path audit writes; `policy_denied` is deliberately not a
/// history kind (a denial feeding a count policy would amplify denials).
async fn record_denial(
    state: &crate::AppState,
    org_id: &str,
    user_id: &str,
    kind: &DecisionKind<'_>,
    policy: &str,
) {
    let action = match kind {
        DecisionKind::IssueToken { .. } => "issue_token",
        DecisionKind::ExchangeToken { .. } => "exchange_token",
    };
    let data = serde_json::json!({
        "action": action,
        "policy": policy,
        "org_id": org_id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::PolicyDenied,
            Some(user_id),
            None,
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write policy_denied audit event");
    }
}

/// Deny message for a determining rule.
fn deny_error(denying: Option<engine::DenyingPolicy>, os: Option<&str>) -> ServiceError {
    let generic = "Check your device settings to meet your organization's \
                   compliance requirements";
    let (name, remediation) = match denying {
        Some(engine::DenyingPolicy::Preconfigured(slug)) => {
            let name = PRECONFIGURED_POLICIES
                .iter()
                .find(|p| p.slug == slug)
                .map_or("policy", |p| p.name);
            (name.to_string(), remediation_for_slug(slug, os))
        }
        Some(engine::DenyingPolicy::Custom { name }) => (name, generic.to_string()),
        None => ("posture".to_string(), generic.to_string()),
    };
    tracing::debug!(policy = name, "policy denied");
    ServiceError::oauth(
        OAuthErrorCode::AccessDenied,
        format!("Device posture policy '{name}' not satisfied. {remediation}"),
    )
}

/// Run one decision: precheck the org's composed set (cached by config
/// fingerprint), fetch the requesting principal's 24h history from the
/// shared audit table, and evaluate with a fresh authorizer. Querying at
/// decision time is what makes the result correct across replicas.
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
    let set = compose_org_set(active_slugs, active_custom);
    let started = std::time::Instant::now();

    let needs_history = match state.policy.precheck(org_id, fingerprint, || {
        run_precheck(&set.composed, active_custom)
    }) {
        engine::Precheck::Ok { uses_temporal } => uses_temporal,
        engine::Precheck::BrokenCustom(name) => {
            crate::infra::metrics::record_policy_decision("deny", &name);
            return Err(deny_error(Some(engine::DenyingPolicy::Custom { name }), os));
        }
        engine::Precheck::EngineError(msg) => {
            tracing::error!(org_id, "policy precheck failed: {msg}");
            return Err(ServiceError::Internal(
                "policy engine unavailable".to_string(),
            ));
        }
    };

    // Orgs running only device-posture policies never read event history,
    // so they pay neither the audit query nor the replay.
    let history = if needs_history {
        events::fetch_user_history(&state.audit, user_id)
            .await
            .map_err(|msg| {
                tracing::error!(org_id, "policy history fetch failed: {msg}");
                ServiceError::Internal("policy engine unavailable".to_string())
            })?
    } else {
        Vec::new()
    };

    let Some(policy_schema) = schema::policy_schema() else {
        return Err(ServiceError::Internal(
            "policy schema unavailable".to_string(),
        ));
    };
    let lowered =
        LoweredPolicySet::from_str(&set.composed, schema::service_schema(), policy_schema)
            .map_err(|e| {
                tracing::error!(org_id, "composed org policy set failed to lower: {e}");
                ServiceError::Internal("policy engine unavailable".to_string())
            })?;

    let now = jiff::Timestamp::now().as_second();
    let decision = engine::evaluate(lowered, &set.refs, &history, org_id, now, |ts| {
        decision_event(&kind, user_id, org_id, ts)
    })
    .map_err(|msg| {
        tracing::error!(org_id, "policy decision failed: {msg}");
        ServiceError::Internal("policy engine unavailable".to_string())
    })?;
    crate::infra::metrics::record_policy_decision_duration(
        started.elapsed().as_secs_f64(),
        needs_history,
    );

    match decision {
        engine::OrgDecision::Allow => {
            crate::infra::metrics::record_policy_decision("allow", "none");
            Ok(())
        }
        engine::OrgDecision::Deny(denying) => {
            let label = match &denying {
                Some(engine::DenyingPolicy::Preconfigured(slug)) => slug.as_str(),
                Some(engine::DenyingPolicy::Custom { .. }) => "custom",
                None => "unattributed",
            };
            crate::infra::metrics::record_policy_decision("deny", label);
            record_denial(state, org_id, user_id, &kind, label).await;
            Err(deny_error(denying, os))
        }
    }
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

/// Fuzzing entry for the runtime evaluation path. Builds a trace from raw
/// row shapes and decides against the full preconfigured policy set — the
/// same `engine::evaluate` call the login and exchange paths make.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn fuzz_evaluate_history(rows: &[(String, String, String, i64)]) {
    let Some(policy_schema) = schema::policy_schema() else {
        return;
    };
    let slugs: Vec<String> = PRECONFIGURED_POLICIES
        .iter()
        .map(|p| p.slug.as_str().to_string())
        .collect();
    let set = compose_org_set(&slugs, &[]);
    let Ok(lowered) =
        LoweredPolicySet::from_str(&set.composed, schema::service_schema(), policy_schema)
    else {
        return;
    };
    let now = jiff::Timestamp::now();
    let history: Vec<db::AuditEvent> = rows
        .iter()
        .map(|(event_type, user_id, data, offset)| db::AuditEvent {
            id: format!("fuzz-{offset}"),
            event_type: event_type.clone(),
            user_id: Some(user_id.clone()),
            email_domain: None,
            email_hmac: None,
            data: data.clone(),
            created_at: now
                .checked_sub(jiff::Span::new().seconds(offset.rem_euclid(86_400)))
                .unwrap_or(now),
        })
        .collect();
    let posture = DevicePosture::new();
    let _decision = engine::evaluate(
        lowered,
        &set.refs,
        &history,
        "fuzz-org",
        now.as_second(),
        |ts| {
            decision_event(
                &DecisionKind::IssueToken {
                    posture: &posture,
                    ip: None,
                    client_id: "fuzz",
                },
                "fuzz-user",
                "fuzz-org",
                ts,
            )
        },
    );
}
