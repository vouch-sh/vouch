// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Builder rule specs and the one structure→text composer.
//!
//! The admin UI's guided builder submits a [`RuleSpec`]; [`generate`] turns
//! it into Dogwood policy text, which then goes through the same
//! `validate_policy_text` path as hand-written text — generation never
//! bypasses validation, it is just another producer of text that must pass
//! it.
//!
//! A rule is device conditions *or* history conditions, never both.
//! Dogwood itself allows one policy to carry both an `unless { … }` and a
//! `when temporal { … }` clause (implicitly conjoined), but the builder
//! keeps the two apart: active policies AND together anyway, and one
//! condition family per rule keeps each policy readable and attributable.
//! Text editing remains the escape hatch for combined forms.

use super::catalog::{
    self, DecisionPoint, FieldKind, MAX_POLICY_TEXT_LEN, Operator, Pin, PinValue,
};
use super::posture_input::semver_num;
use crate::infra::i18n::Tr;
use serde::Deserialize;
use vouch_common::posture::OperatingSystem;

/// A builder-authored rule: which decision it gates and its conditions.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleSpec {
    pub decision: DecisionPoint,
    pub body: RuleBody,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RuleBody {
    /// "Allow the request only when ALL of these hold" — emitted as
    /// `forbid … unless { c1 && c2 }`.
    Device { conditions: Vec<DeviceCondition> },
    /// "Deny the request when ALL of these hold" — emitted as
    /// `forbid … when temporal { c1 && c2 }`.
    History { conditions: Vec<HistoryCondition> },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DeviceCondition {
    /// One typed check on a device field.
    Field {
        field: String,
        op: Operator,
        value: LiteralValue,
    },
    /// A per-OS minimum version, OR'd across the listed platforms and
    /// emitted against the derived numeric fields (`os_version_num` for
    /// macOS/Linux, `os_build_num` for Windows).
    OsFloor { floors: Vec<OsFloor> },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OsFloor {
    /// One of [`OperatingSystem::ALL`].
    pub os: String,
    /// Minimum version ("15.3") for macOS/Linux, minimum build number
    /// ("26100") for Windows.
    pub min: String,
}

/// A literal value from the builder's value control.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum LiteralValue {
    Bool(bool),
    Int(i64),
    Str(String),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "shape", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HistoryCondition {
    /// The event occurred at least once in the window.
    HappenedWithin { event: String, window: Window },
    /// The event did not occur in the window.
    NotHappenedWithin { event: String, window: Window },
    /// No `anchor` stands in the window that isn't followed by
    /// `cancelled_by` — e.g. "no successful login since the last logout".
    NotSince {
        anchor: String,
        cancelled_by: String,
        window: Window,
    },
    /// The event occurred at least `threshold` times in the window.
    CountAtLeast {
        event: String,
        window: Window,
        threshold: u32,
    },
}

/// A temporal window, valid by construction: deserialization rejects zero
/// and anything over the 24h cap, so no reachable `Window` can exceed it.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(try_from = "RawWindow")]
pub(crate) struct Window {
    amount: u32,
    unit: WindowUnit,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WindowUnit {
    S,
    M,
    H,
    D,
}

impl WindowUnit {
    const fn seconds(self) -> u64 {
        match self {
            Self::S => 1,
            Self::M => 60,
            Self::H => 3_600,
            Self::D => 86_400,
        }
    }

    const fn suffix(self) -> &'static str {
        match self {
            Self::S => "s",
            Self::M => "m",
            Self::H => "h",
            Self::D => "d",
        }
    }
}

#[derive(Deserialize)]
struct RawWindow {
    amount: u32,
    unit: WindowUnit,
}

impl TryFrom<RawWindow> for Window {
    type Error = String;

    fn try_from(raw: RawWindow) -> Result<Self, Self::Error> {
        let secs = u64::from(raw.amount).saturating_mul(raw.unit.seconds());
        if secs == 0 || secs > catalog::MAX_WINDOW_SECS {
            return Err(Tr::new("admin-policies-err-bad-window").to_string());
        }
        Ok(Self {
            amount: raw.amount,
            unit: raw.unit,
        })
    }
}

impl std::fmt::Display for Window {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.amount, self.unit.suffix())
    }
}

/// Why a spec cannot be turned into policy text. Messages are user-facing
/// (the builder shows them in the validation box) and come from the i18n
/// catalog.
#[derive(Debug)]
pub(crate) enum RuleError {
    Empty,
    DeviceOnExchange,
    UnknownField(String),
    BadOperator(String),
    BadValue(String),
    UnknownValue { field: String, value: String },
    UnknownEvent(String),
    BadVersion(String),
    BadThreshold,
    BadText,
    TooLong,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::Empty => Tr::new("admin-policies-err-rule-empty").to_string(),
            Self::DeviceOnExchange => Tr::new("admin-policies-err-device-on-exchange").to_string(),
            Self::UnknownField(field) => Tr::new("admin-policies-err-unknown-field")
                .arg("field", field.as_str())
                .to_string(),
            Self::BadOperator(field) => Tr::new("admin-policies-err-bad-operator")
                .arg("field", field.as_str())
                .to_string(),
            Self::BadValue(field) => Tr::new("admin-policies-err-bad-value")
                .arg("field", field.as_str())
                .to_string(),
            Self::UnknownValue { field, value } => Tr::new("admin-policies-err-unknown-value")
                .arg("field", field.as_str())
                .arg("value", value.as_str())
                .to_string(),
            Self::UnknownEvent(event) => Tr::new("admin-policies-err-unknown-event")
                .arg("event", event.as_str())
                .to_string(),
            Self::BadVersion(value) => Tr::new("admin-policies-err-bad-version")
                .arg("value", value.as_str())
                .to_string(),
            Self::BadThreshold => Tr::new("admin-policies-err-bad-threshold").to_string(),
            Self::BadText => Tr::new("admin-policies-err-bad-text").to_string(),
            Self::TooLong => Tr::new("admin-policies-err-too-long")
                .arg("max", MAX_POLICY_TEXT_LEN.to_string())
                .to_string(),
        };
        f.write_str(&msg)
    }
}

/// Turn a rule spec into Dogwood policy text.
///
/// # Errors
///
/// Returns a [`RuleError`] when the spec references unknown fields, events,
/// or values; pairs an operator with a field kind that does not admit it;
/// targets device state on token exchange; or would exceed the stored
/// policy length.
pub(crate) fn generate(spec: &RuleSpec) -> Result<String, RuleError> {
    let (clause, parts) = match &spec.body {
        RuleBody::Device { conditions } => {
            if !spec.decision.allows_device() {
                return Err(RuleError::DeviceOnExchange);
            }
            let parts = conditions
                .iter()
                .map(device_condition)
                .collect::<Result<Vec<_>, _>>()?;
            ("unless", parts)
        }
        RuleBody::History { conditions } => {
            let parts = conditions
                .iter()
                .map(history_condition)
                .collect::<Result<Vec<_>, _>>()?;
            ("when temporal", parts)
        }
    };
    if parts.is_empty() {
        return Err(RuleError::Empty);
    }

    let body = parts.join("\n    && ");
    let text = format!(
        "forbid (principal, action == {}, resource)\n{clause} {{\n    {body}\n}};",
        spec.decision.action_literal(),
    );
    if text.len() > MAX_POLICY_TEXT_LEN {
        return Err(RuleError::TooLong);
    }
    Ok(text)
}

fn device_condition(condition: &DeviceCondition) -> Result<String, RuleError> {
    match condition {
        DeviceCondition::Field { field, op, value } => device_field_check(field, *op, value),
        DeviceCondition::OsFloor { floors } => os_floor(floors),
    }
}

fn device_field_check(
    field: &str,
    op: Operator,
    value: &LiteralValue,
) -> Result<String, RuleError> {
    let meta =
        catalog::device_field(field).ok_or_else(|| RuleError::UnknownField(field.to_string()))?;
    if !Operator::allowed_for(meta.kind).contains(&op) {
        return Err(RuleError::BadOperator(field.to_string()));
    }
    let path = format!("context.device.{field}");
    match (meta.kind, value) {
        (FieldKind::Bool, LiteralValue::Bool(true)) => Ok(path),
        (FieldKind::Bool, LiteralValue::Bool(false)) => Ok(format!("{path} == false")),
        (FieldKind::Long | FieldKind::BuildNum { .. }, LiteralValue::Int(n)) => {
            let infix = infix_for(op, field)?;
            Ok(format!("{path} {infix} {n}"))
        }
        (FieldKind::VersionNum { .. }, LiteralValue::Str(version)) => {
            let encoded =
                semver_num(version).ok_or_else(|| RuleError::BadVersion(version.clone()))?;
            let infix = infix_for(op, field)?;
            Ok(format!("{path} {infix} {encoded}"))
        }
        (FieldKind::Text, LiteralValue::Str(s)) => {
            let quoted = quote_cedar_string(s)?;
            let infix = infix_for(op, field)?;
            Ok(format!("{path} {infix} \"{quoted}\""))
        }
        (FieldKind::TextEnum(values), LiteralValue::Str(s)) => {
            if !values.contains(&s.as_str()) {
                return Err(RuleError::UnknownValue {
                    field: field.to_string(),
                    value: s.clone(),
                });
            }
            let infix = infix_for(op, field)?;
            Ok(format!("{path} {infix} \"{s}\""))
        }
        (FieldKind::StringSet(values), LiteralValue::Str(s)) => {
            if !values.contains(&s.as_str()) {
                return Err(RuleError::UnknownValue {
                    field: field.to_string(),
                    value: s.clone(),
                });
            }
            let call = format!("{path}.contains(\"{s}\")");
            match op {
                Operator::Contains => Ok(call),
                Operator::NotContains => Ok(format!("!{call}")),
                Operator::Eq
                | Operator::Ne
                | Operator::Ge
                | Operator::Le
                | Operator::Gt
                | Operator::Lt => Err(RuleError::BadOperator(field.to_string())),
            }
        }
        (
            FieldKind::Bool
            | FieldKind::Long
            | FieldKind::Text
            | FieldKind::TextEnum(_)
            | FieldKind::StringSet(_)
            | FieldKind::VersionNum { .. }
            | FieldKind::BuildNum { .. },
            LiteralValue::Bool(_) | LiteralValue::Int(_) | LiteralValue::Str(_),
        ) => Err(RuleError::BadValue(field.to_string())),
    }
}

fn infix_for(op: Operator, field: &str) -> Result<&'static str, RuleError> {
    op.cedar_infix()
        .ok_or_else(|| RuleError::BadOperator(field.to_string()))
}

fn os_floor(floors: &[OsFloor]) -> Result<String, RuleError> {
    if floors.is_empty() {
        return Err(RuleError::Empty);
    }
    let mut branches = Vec::with_capacity(floors.len());
    for floor in floors {
        if !OperatingSystem::ALL.contains(&floor.os.as_str()) {
            return Err(RuleError::UnknownValue {
                field: "os".to_string(),
                value: floor.os.clone(),
            });
        }
        let branch = if floor.os == "windows" {
            // Windows reports a 4-part os_version the encoding rejects, so
            // its floor compares the numeric build instead.
            let build: i64 = floor
                .min
                .trim()
                .parse()
                .map_err(|_| RuleError::BadValue("os_build_num".to_string()))?;
            format!("(context.device.os == \"windows\" && context.device.os_build_num >= {build})")
        } else {
            let encoded =
                semver_num(&floor.min).ok_or_else(|| RuleError::BadVersion(floor.min.clone()))?;
            format!(
                "(context.device.os == \"{}\" && context.device.os_version_num >= {encoded})",
                floor.os
            )
        };
        branches.push(branch);
    }
    if branches.len() == 1 {
        // join() on one element is the element itself; the extra parens are
        // only needed to bind the ORs tighter than the surrounding &&s.
        return Ok(branches.join(""));
    }
    Ok(format!("({})", branches.join(" || ")))
}

fn history_condition(condition: &HistoryCondition) -> Result<String, RuleError> {
    match condition {
        HistoryCondition::HappenedWithin { event, window } => {
            Ok(format!("formerly within {window} {}", atom(event)?))
        }
        HistoryCondition::NotHappenedWithin { event, window } => {
            Ok(format!("!(formerly within {window} {})", atom(event)?))
        }
        HistoryCondition::NotSince {
            anchor,
            cancelled_by,
            window,
        } => Ok(format!(
            "!(\n        (!{})\n        since within {window}\n        {}\n    )",
            atom(cancelled_by)?,
            atom(anchor)?,
        )),
        HistoryCondition::CountAtLeast {
            event,
            window,
            threshold,
        } => {
            if *threshold == 0 {
                return Err(RuleError::BadThreshold);
            }
            Ok(format!(
                "exists (n: Long). (\n        (count_within({window}, {})) == n\n        && n >= {threshold}\n    )",
                atom(event)?,
            ))
        }
    }
}

/// Render a history atom: the action's `::response` events selected by the
/// event's pins. An atom needs a non-empty pin record; when the event has
/// no field pins, the principal pin (which the schema applies implicitly
/// anyway) fills it, matching the built-in policies.
fn atom(event_key: &str) -> Result<String, RuleError> {
    let meta = catalog::history_event_meta(event_key)
        .ok_or_else(|| RuleError::UnknownEvent(event_key.to_string()))?;
    let pins = if meta.pins.is_empty() {
        "callerPrincipal: principal".to_string()
    } else {
        meta.pins
            .iter()
            .map(|Pin { path, value }| match value {
                PinValue::Bool(b) => format!("{path}: {b}"),
                PinValue::Str(s) => format!("{path}: \"{s}\""),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    Ok(format!("{}::response{{ {pins} }}", meta.action_literal))
}

/// Escape a string for a Cedar string literal. Control characters are
/// rejected rather than escaped — no legitimate posture value contains
/// them, and rejecting is simpler to reason about than emitting `\n`.
fn quote_cedar_string(s: &str) -> Result<String, RuleError> {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            return Err(RuleError::BadText);
        }
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    Ok(out)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    fn spec(value: serde_json::Value) -> RuleSpec {
        serde_json::from_value(value).expect("spec deserializes")
    }

    fn device_spec(condition: serde_json::Value) -> RuleSpec {
        spec(serde_json::json!({
            "decision": "issue_token",
            "body": { "kind": "device", "conditions": [condition] }
        }))
    }

    #[test]
    fn bool_true_emits_bare_field_and_false_compares() {
        let text = generate(&device_spec(serde_json::json!({
            "kind": "field", "field": "disk_encryption_enabled", "op": "eq", "value": true
        })))
        .unwrap();
        assert_eq!(
            text,
            "forbid (principal, action == Vouch::Action::\"IssueToken\", resource)\n\
             unless {\n    context.device.disk_encryption_enabled\n};"
        );

        let text = generate(&device_spec(serde_json::json!({
            "kind": "field", "field": "elevated", "op": "eq", "value": false
        })))
        .unwrap();
        assert!(text.contains("context.device.elevated == false"), "{text}");
    }

    #[test]
    fn version_value_is_encoded_and_set_contains_renders_as_call() {
        let text = generate(&device_spec(serde_json::json!({
            "kind": "field", "field": "os_version_num", "op": "ge", "value": "15.3"
        })))
        .unwrap();
        assert!(
            text.contains("context.device.os_version_num >= 15003000"),
            "{text}"
        );

        let text = generate(&device_spec(serde_json::json!({
            "kind": "field", "field": "edr", "op": "not_contains", "value": "crowdstrike"
        })))
        .unwrap();
        assert!(
            text.contains("!context.device.edr.contains(\"crowdstrike\")"),
            "{text}"
        );
    }

    #[test]
    fn multiple_conditions_join_with_and() {
        let text = generate(&spec(serde_json::json!({
            "decision": "issue_token",
            "body": { "kind": "device", "conditions": [
                { "kind": "field", "field": "firewall_enabled", "op": "eq", "value": true },
                { "kind": "field", "field": "edr_count", "op": "ge", "value": 1 }
            ]}
        })))
        .unwrap();
        assert!(
            text.contains("context.device.firewall_enabled\n    && context.device.edr_count >= 1"),
            "{text}"
        );
    }

    #[test]
    fn os_floor_branches_are_ored_and_windows_uses_build() {
        let text = generate(&device_spec(serde_json::json!({
            "kind": "os_floor",
            "floors": [
                { "os": "macos", "min": "15.0" },
                { "os": "windows", "min": "26100" }
            ]
        })))
        .unwrap();
        assert!(
            text.contains(
                "((context.device.os == \"macos\" && context.device.os_version_num >= 15000000) \
                 || (context.device.os == \"windows\" && context.device.os_build_num >= 26100))"
            ),
            "{text}"
        );
    }

    #[test]
    fn history_shapes_render_the_documented_forms() {
        let text = generate(&spec(serde_json::json!({
            "decision": "exchange_token",
            "body": { "kind": "history", "conditions": [
                { "shape": "not_happened_within", "event": "login_success",
                  "window": { "amount": 15, "unit": "m" } }
            ]}
        })))
        .unwrap();
        assert_eq!(
            text,
            "forbid (principal, action == Vouch::Action::\"ExchangeToken\", resource)\n\
             when temporal {\n    \
             !(formerly within 15m Vouch::Action::\"Login\"::response{ output.result: true })\n\
             };"
        );

        let text = generate(&spec(serde_json::json!({
            "decision": "issue_token",
            "body": { "kind": "history", "conditions": [
                { "shape": "count_at_least", "event": "token_issued",
                  "window": { "amount": 1, "unit": "h" }, "threshold": 10 }
            ]}
        })))
        .unwrap();
        assert!(text.contains("count_within(1h, Vouch::Action::\"IssueToken\"::response{ callerPrincipal: principal })"), "{text}");
        assert!(text.contains("&& n >= 10"), "{text}");

        let text = generate(&spec(serde_json::json!({
            "decision": "exchange_token",
            "body": { "kind": "history", "conditions": [
                { "shape": "not_since", "anchor": "login_success", "cancelled_by": "logout",
                  "window": { "amount": 24, "unit": "h" } }
            ]}
        })))
        .unwrap();
        assert!(
            text.contains("since within 24h")
                && text.contains(
                    "(!Vouch::Action::\"Logout\"::response{ callerPrincipal: principal })"
                ),
            "{text}"
        );
    }

    #[test]
    fn device_on_exchange_is_rejected() {
        let err = generate(&spec(serde_json::json!({
            "decision": "exchange_token",
            "body": { "kind": "device", "conditions": [
                { "kind": "field", "field": "firewall_enabled", "op": "eq", "value": true }
            ]}
        })))
        .unwrap_err();
        assert!(matches!(err, RuleError::DeviceOnExchange), "{err:?}");
    }

    #[test]
    fn empty_conditions_and_zero_threshold_are_rejected() {
        let err = generate(&spec(serde_json::json!({
            "decision": "issue_token",
            "body": { "kind": "device", "conditions": [] }
        })))
        .unwrap_err();
        assert!(matches!(err, RuleError::Empty), "{err:?}");

        let err = generate(&spec(serde_json::json!({
            "decision": "issue_token",
            "body": { "kind": "history", "conditions": [
                { "shape": "count_at_least", "event": "token_issued",
                  "window": { "amount": 1, "unit": "h" }, "threshold": 0 }
            ]}
        })))
        .unwrap_err();
        assert!(matches!(err, RuleError::BadThreshold), "{err:?}");
    }

    #[test]
    fn windows_over_the_cap_or_zero_do_not_deserialize() {
        for window in [
            serde_json::json!({ "amount": 25, "unit": "h" }),
            serde_json::json!({ "amount": 2, "unit": "d" }),
            serde_json::json!({ "amount": 0, "unit": "m" }),
        ] {
            let result = serde_json::from_value::<Window>(window.clone());
            assert!(result.is_err(), "window {window} must be rejected");
        }
        assert!(
            serde_json::from_value::<Window>(serde_json::json!({ "amount": 24, "unit": "h" }))
                .is_ok()
        );
        assert!(
            serde_json::from_value::<Window>(serde_json::json!({ "amount": 1440, "unit": "m" }))
                .is_ok()
        );
    }

    #[test]
    fn free_text_values_are_escaped_and_control_chars_rejected() {
        let text = generate(&device_spec(serde_json::json!({
            "kind": "field", "field": "parent_process",
            "op": "eq", "value": "z\"sh\\x"
        })))
        .unwrap();
        assert!(
            text.contains("context.device.parent_process == \"z\\\"sh\\\\x\""),
            "{text}"
        );
        // The escaped text still validates — the quote cannot break out of
        // the string literal into policy syntax.
        super::super::validate_policy_text(&text).unwrap();

        let err = generate(&device_spec(serde_json::json!({
            "kind": "field", "field": "parent_process",
            "op": "eq", "value": "a\nb"
        })))
        .unwrap_err();
        assert!(matches!(err, RuleError::BadText), "{err:?}");
    }

    #[test]
    fn enum_values_outside_the_closed_set_are_rejected() {
        let err = generate(&device_spec(serde_json::json!({
            "kind": "field", "field": "os", "op": "eq", "value": "freebsd"
        })))
        .unwrap_err();
        assert!(matches!(err, RuleError::UnknownValue { .. }), "{err:?}");

        let err = generate(&device_spec(serde_json::json!({
            "kind": "field", "field": "edr", "op": "contains", "value": "homebrew av"
        })))
        .unwrap_err();
        assert!(matches!(err, RuleError::UnknownValue { .. }), "{err:?}");
    }

    #[test]
    fn oversized_generated_text_is_too_long() {
        let conditions: Vec<serde_json::Value> = (0..60)
            .map(|_| {
                serde_json::json!({
                    "kind": "field", "field": "parent_process",
                    "op": "eq", "value": "x".repeat(80)
                })
            })
            .collect();
        let err = generate(&spec(serde_json::json!({
            "decision": "issue_token",
            "body": { "kind": "device", "conditions": conditions }
        })))
        .unwrap_err();
        assert!(matches!(err, RuleError::TooLong), "{err:?}");
    }

    #[test]
    fn unknown_spec_fields_do_not_deserialize() {
        // deny_unknown_fields: an older or tampered spec fails cleanly and
        // the UI falls back to the text editor.
        let result = serde_json::from_value::<RuleSpec>(serde_json::json!({
            "decision": "issue_token",
            "body": { "kind": "device", "conditions": [] },
            "extra": true
        }));
        assert!(result.is_err());
    }
}
