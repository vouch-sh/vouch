// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture and temporal policy evaluation.
//!
//! Policies are written in [Dogwood], a Cedar dialect that adds a past-only
//! temporal sublanguage over an event history. Built-in policies live in
//! `policies/*.dw`; admins may add their own.
//!
//! A composed set opens with the base `permit`s (`policies/base_allow.dw`)
//! and every policy is a `forbid` that fires when its requirement is not
//! met. Cedar denies by default and a forbid overrides any permit, so the
//! set as a whole means "allowed unless some policy objects" — the AND
//! across policies that Vouch requires. Every error path denies.
//!
//! One decision evaluates as: precheck the org's set (lower + validate,
//! cached by a fingerprint of its configuration), fetch the requesting
//! principal's recent audit history, then decide with a fresh authorizer.
//! [`engine`] explains why per-decision replay is both sound and correct
//! across replicas.
//!
//! [Dogwood]: https://dogwood-policy.github.io/dogwood/

pub(crate) mod catalog;
pub(crate) mod engine;
pub(crate) mod events;
pub(crate) mod posture_input;
pub(crate) mod preconfigured;
pub(crate) mod remediation;
pub(crate) mod rule;
pub(crate) mod schema;

#[cfg(test)]
mod tests;

pub(crate) use preconfigured::{
    MAX_ACTIVE_POLICIES, PRECONFIGURED_POLICIES, PreconfiguredSlug, as_editable,
    is_valid_preconfigured_slug,
};
pub(crate) use remediation::remediation_for_slug;

use crate::db;
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use dogwood_language::{
    Authorizer, Decision, Event, EventBuilder, LoweredPolicySet, ParsedPolicySet, Validator, Value,
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

/// Build the `IssueToken` decision event for one evaluation (test fixture;
/// the enforcement and playground paths build events via [`decision_event`]
/// directly).
#[cfg(test)]
fn issue_token_request(posture: &DevicePosture, user_id: &str, org_id: &str) -> Event {
    decision_event(
        &DecisionKind::IssueToken {
            posture,
            ip: None,
            client_id: "",
        },
        user_id,
        org_id,
        0,
    )
}

/// Lower a composed policy set and decide the given event with a fresh
/// authorizer (stateless: no event history — temporal atoms see an empty
/// trace and evaluate accordingly). Test fixture; production paths lower
/// once and use [`decide_lowered`].
///
/// Returns `Err` only for engine-level failures (schema unavailable,
/// lowering error, no decision returned) — callers treat those as deny.
#[cfg(test)]
fn decide(policy_text: &str, event: &Event) -> Result<EngineDecision, String> {
    let policy_schema = schema::policy_schema().ok_or("policy schema unavailable")?;
    let lowered = LoweredPolicySet::from_str(policy_text, schema::service_schema(), policy_schema)
        .map_err(|e| format!("policy set failed to lower: {e}"))?;
    decide_lowered(lowered, event)
}

/// Decide the given event against an already-lowered set with a fresh
/// authorizer (stateless — see [`decide`]).
fn decide_lowered(lowered: LoweredPolicySet, event: &Event) -> Result<EngineDecision, String> {
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
    lower_composed(text).map(|_| ())
}

/// Lower and type-check one policy's text composed with the base permits,
/// returning the lowered set so callers can also decide with it.
fn lower_composed(text: &str) -> ServiceResult<LoweredPolicySet> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        tracing::debug!("policy validation rejected: empty text");
        return Err(ServiceError::api(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_policy_expression",
            crate::infra::i18n::Tr::new("admin-policies-err-empty").to_string(),
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
                    crate::infra::i18n::Tr::new("admin-policies-err-invalid")
                        .arg("detail", e.to_string())
                        .to_string(),
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
            crate::infra::i18n::Tr::new("admin-policies-err-invalid")
                .arg("detail", errors.join("; "))
                .to_string(),
        ));
    }
    tracing::trace!("policy text validated successfully");
    Ok(lowered)
}

/// Outcome of a playground evaluation.
pub(crate) struct PolicyTestResult {
    /// Whether issuance would be allowed with only this policy active.
    pub pass: bool,
    /// Whether the verdict depends on event history the playground cannot
    /// reproduce. The UI labels those results instead of presenting a bare
    /// pass/fail the admin would misread; the wording lives in the i18n
    /// catalog, not here.
    pub reads_history: bool,
}

/// Evaluate a candidate policy against a sample `DevicePosture` (the admin
/// playground), as the decision point the admin is targeting — an
/// exchange-scoped forbid never fires on an `IssueToken` event, so testing
/// with the wrong event kind would report a meaningless pass.
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
    decision: catalog::DecisionPoint,
) -> ServiceResult<PolicyTestResult> {
    let lowered = lower_composed(text)?;
    // Structural, from the lowered set: temporal leaves are hoisted during
    // lowering, so a set with none left is plain Cedar.
    let reads_history = !lowered.is_self_contained_cedar();
    let kind = match decision {
        catalog::DecisionPoint::IssueToken => DecisionKind::IssueToken {
            posture,
            ip: None,
            client_id: "",
        },
        catalog::DecisionPoint::ExchangeToken => DecisionKind::ExchangeToken {
            ip: None,
            client_id: "",
            audience: None,
        },
    };
    let event = decision_event(&kind, "playground", "playground", 0);
    let pass = match decide_lowered(lowered, &event) {
        Ok(EngineDecision::Allow) => true,
        Ok(EngineDecision::Deny) => false,
        Err(msg) => {
            tracing::error!("playground evaluation failed: {msg}");
            return Err(ServiceError::Internal(
                "policy engine unavailable".to_string(),
            ));
        }
    };
    Ok(PolicyTestResult {
        pass,
        reads_history,
    })
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
            let builder =
                Event::builder(catalog::DecisionPoint::IssueToken.action_name(), "request")
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
            Event::builder(
                catalog::DecisionPoint::ExchangeToken.action_name(),
                "request",
            )
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

/// Count the Dogwood rules in one policy text by parsing it (the
/// schema-independent phase — needs only the static service schema, not the
/// action schema). Dogwood assigns a `rule_index` per rule in the composed
/// set, so `refs` must carry one entry per emitted rule, not one per text.
/// Returns 1 on parse failure: a stored policy that no longer parses is
/// caught by the precheck (which denies with its name), so a miscount here
/// never reaches evaluation. The 1-rule fallback matches the common case
/// and keeps `refs` aligned for any single-rule policies that follow.
fn rule_count(text: &str) -> usize {
    ParsedPolicySet::parse(text, schema::service_schema()).map_or(1, |p| p.policy_count())
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
            let ref_entry = engine::PolicyRef::Policy(engine::DenyingPolicy::Preconfigured(slug));
            // One ref per rule: a policy text with multiple `forbid`/`permit`
            // statements emits multiple rule indices, and each must map back
            // to the policy that authored it.
            for _ in 0..rule_count(policy.policy_text) {
                refs.push(ref_entry.clone());
            }
        }
    }
    for custom in active_custom {
        texts.push(custom.policy_text.as_str());
        let ref_entry = engine::PolicyRef::Policy(engine::DenyingPolicy::Custom {
            name: custom.name.clone(),
        });
        for _ in 0..rule_count(&custom.policy_text) {
            refs.push(ref_entry.clone());
        }
    }
    OrgPolicySet {
        composed: compose(&texts),
        refs,
    }
}

/// Static precheck of an org's composed set: it must lower AND validate.
/// On failure, bisect the custom policies (each alone with the base
/// permits) so the failure names a single policy the admin can fix.
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
                    Ok(engine::Precheck::Ok {
                        uses_temporal: !lowered.is_self_contained_cedar(),
                        // Posture is only demanded when some policy reads
                        // it. Checking the composed text is deliberate: a
                        // miss means posture arrives absent, its typed
                        // defaults apply, and the policy denies — the safe
                        // direction.
                        reads_device: composed.contains("context.device"),
                    })
                } else {
                    Err(format!(
                        "composed set failed validation: {}",
                        errors.join("; ")
                    ))
                }
            });
    let composed_error = match composed_result {
        Ok(verdict) => return verdict,
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
    user_email: &str,
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
            // The email sets `email_domain`, which is how the org audit
            // view scopes rows — without it a denial is invisible to the
            // admin it is evidence for.
            Some(user_email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write policy_denied audit event");
    }
}

/// The metrics label and audit policy identifier for a deny decision.
///
/// These differ only for custom policies: metrics use the generic `"custom"`
/// label (to avoid cardinality explosion from unbounded admin-chosen names),
/// while the audit record carries the actual policy name so admins can
/// identify which custom policy denied a request. Preconfigured policies and
/// unattributed denies use the same value for both.
///
/// Returns `(metrics_label, audit_policy)`:
/// - `metrics_label` is a static string suitable for a Prometheus label.
/// - `audit_policy` is the identifier stored in the `policy_denied` audit
///   record's `policy` field.
fn deny_attribution(denying: &Option<engine::DenyingPolicy>) -> (&'static str, String) {
    match denying {
        Some(engine::DenyingPolicy::Preconfigured(slug)) => {
            (slug.as_str(), slug.as_str().to_string())
        }
        Some(engine::DenyingPolicy::Custom { name }) => ("custom", name.clone()),
        None => ("unattributed", "unattributed".to_string()),
    }
}

/// Deny message for a determining rule.
fn deny_error(denying: Option<engine::DenyingPolicy>, os: Option<&str>) -> ServiceError {
    let (name, remediation) = match denying {
        Some(engine::DenyingPolicy::Preconfigured(slug)) => {
            (slug.name(), remediation_for_slug(slug, os))
        }
        Some(engine::DenyingPolicy::Custom { name }) => (
            name,
            crate::infra::i18n::Tr::new("admin-policies-deny-generic").to_string(),
        ),
        None => (
            crate::infra::i18n::Tr::new("admin-policies-deny-unattributed").to_string(),
            crate::infra::i18n::Tr::new("admin-policies-deny-generic").to_string(),
        ),
    };
    tracing::debug!(policy = name, "policy denied");
    ServiceError::oauth(
        OAuthErrorCode::AccessDenied,
        crate::infra::i18n::Tr::new("admin-policies-deny-message")
            .arg("policy", name.as_str())
            .arg("remediation", remediation.as_str())
            .to_string(),
    )
}

/// Run one decision: precheck the org's composed set (cached by config
/// fingerprint), fetch the requesting principal's 24h history from the
/// shared audit table, and evaluate with a fresh authorizer. Querying at
/// decision time is what makes the result correct across replicas.
/// Who is asking for what, for one decision.
struct DecisionRequest<'a> {
    org_id: &'a str,
    user_id: &'a str,
    /// Sets `email_domain` on a denial record, which is how the org audit
    /// view scopes rows.
    user_email: &'a str,
    kind: DecisionKind<'a>,
    /// Reported OS, for platform-specific remediation text.
    os: Option<&'a str>,
}

async fn authorize_decision(
    state: &crate::AppState,
    request: DecisionRequest<'_>,
    active_slugs: &[String],
    active_custom: &[db::CustomPosturePolicy],
) -> ServiceResult<()> {
    let DecisionRequest {
        org_id,
        user_id,
        user_email,
        kind,
        os,
    } = request;
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
        engine::Precheck::Ok {
            uses_temporal,
            reads_device: _,
        } => uses_temporal,
        engine::Precheck::BrokenCustom(name) => {
            // A policy that fails precheck denies every request in the org
            // until it is re-authored, so it needs the same evidence trail as
            // any other denial — and the same bounded metrics label. Passing
            // the admin-chosen name straight to Prometheus would make
            // cardinality a function of how many policies have been written.
            let denying = engine::DenyingPolicy::Custom { name };
            let (metrics_label, audit_policy) = deny_attribution(&Some(denying.clone()));
            crate::infra::metrics::record_policy_decision("deny", metrics_label);
            record_denial(state, org_id, user_id, user_email, &kind, &audit_policy).await;
            return Err(deny_error(Some(denying), os));
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
            let (metrics_label, audit_policy) = deny_attribution(&denying);
            crate::infra::metrics::record_policy_decision("deny", metrics_label);
            record_denial(state, org_id, user_id, user_email, &kind, &audit_policy).await;
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
    user_email: &str,
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

    // Posture is demanded only when some active policy reads it. The
    // precheck answers that for the composed set, custom policies
    // included, so an org whose rules are purely temporal — or whose
    // custom text only gates token exchange — does not force every client
    // to collect and send posture.
    let custom_pairs: Vec<(String, String)> = active_custom
        .iter()
        .map(|c| (c.id.clone(), c.policy_text.clone()))
        .collect();
    let set = compose_org_set(&active_slugs, &active_custom);
    let posture_required = match state.policy.precheck(
        org_id,
        engine::fingerprint(&active_slugs, &custom_pairs),
        || run_precheck(&set.composed, &active_custom),
    ) {
        engine::Precheck::Ok { reads_device, .. } => reads_device,
        // A set that does not precheck denies anyway; demanding posture
        // first would only replace that denial with a worse message.
        engine::Precheck::BrokenCustom(_) | engine::Precheck::EngineError(_) => false,
    };
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
        DecisionRequest {
            org_id,
            user_id,
            user_email,
            kind: DecisionKind::IssueToken {
                posture: &posture,
                ip: client_ip,
                client_id,
            },
            os: os.as_deref(),
        },
        &active_slugs,
        &active_custom,
    )
    .await
}

/// Evaluate the policies gating token exchange ([RFC 8693]), the path
/// workload-identity and agent credentials take. An exchange request
/// carries no device posture, so only event-history policies can apply.
///
/// [RFC 8693]: https://www.rfc-editor.org/rfc/rfc8693
///
/// # Errors
///
/// Returns `AccessDenied` when an active exchange policy denies, or
/// `Internal` when the engine is unavailable (fail-closed).
pub(crate) async fn evaluate_exchange_policies(
    state: &crate::AppState,
    org_id: &str,
    user_id: &str,
    user_email: &str,
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
        DecisionRequest {
            org_id,
            user_id,
            user_email,
            kind: DecisionKind::ExchangeToken {
                ip: client_ip,
                client_id,
                audience,
            },
            os: None,
        },
        &active_slugs,
        &active_custom,
    )
    .await
}

/// Extract `DevicePosture` from the `authorization_details` value, the
/// entry whose `type` is `device_posture`.
///
/// See [RFC 9396] for the authorization-details structure.
///
/// [RFC 9396]: https://www.rfc-editor.org/rfc/rfc9396
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
