// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Dogwood spike smoke test: pins the `dogwood-language` API surface the
//! policy engine is built on before anything depends on it.
//!
//! Covers the full pipeline on a Vouch-shaped schema: lowering, schema
//! validation (including that a typo'd field is a caught error — CEL had no
//! type environment), temporal evaluation (`formerly` recency window,
//! per-principal `callerPrincipal` slicing, `count_within` aggregation), and
//! deny diagnostics mapping back to source rule indices.

#![expect(
    clippy::panic_in_result_fn,
    reason = "tests assert with assert!/assert_eq! for expressive failures; Result carries setup errors"
)]

use dogwood_language::{
    Authorizer, Decision, Event, LoweredPolicySet, PolicySchema, ServiceSchema, Validator, Value,
};

/// Minimal Vouch-shaped action schema: one decision action (`IssueToken`),
/// one history action (`Login`).
const SCHEMA: &str = r#"
namespace Vouch {
  type LoginInput = { ip: String };
  type LoginOutput = { result: Bool };
  type IssueInput = { client_id: String };
  entity User;
  entity Org;
  action "Login" appliesTo {
    principal: [User], resource: [Org],
    context: { input: LoginInput, output?: LoginOutput }
  };
  action "IssueToken" appliesTo {
    principal: [User], resource: [Org],
    context: { input: IssueInput }
  };
}
"#;

/// Deny-by-default Cedar + one base permit; each Vouch policy is a forbid.
const STEP_UP_POLICIES: &str = r#"
@id("base_allow")
permit (principal, action == Vouch::Action::"IssueToken", resource);

@id("step_up_recency")
forbid (principal, action == Vouch::Action::"IssueToken", resource)
when temporal {
    !(formerly within 15m Vouch::Action::"Login"::response{ output.result: true })
};
"#;

const RATE_LIMIT_POLICIES: &str = r#"
@id("base_allow")
permit (principal, action == Vouch::Action::"IssueToken", resource);

@id("issuance_rate_limit")
forbid (principal, action == Vouch::Action::"IssueToken", resource)
when temporal {
    exists (n: Long). (
        (count_within(1h, Vouch::Action::"IssueToken"::response{ input.client_id: _ })) == n
        && n >= 3
    )
};
"#;

fn lower(policy: &str) -> Result<LoweredPolicySet, String> {
    let schema = PolicySchema::from_cedarschema_str(SCHEMA).map_err(|e| format!("{e:?}"))?;
    LoweredPolicySet::from_str(policy, &ServiceSchema::defaults(), &schema)
        .map_err(|e| format!("{e:?}"))
}

fn login_response(ts: i64, user: &str, ip: &str, result: bool) -> Event {
    Event::builder("Vouch::Action::Login", "response")
        .timestamp(ts)
        .principal_for("Vouch::User", user)
        .resource_for("Vouch::Org", "org1")
        .field("input", "ip", Value::String(ip.to_string()))
        .field("output", "result", Value::Bool(result))
        .build()
}

fn issue_token_response(ts: i64, user: &str, client_id: &str) -> Event {
    Event::builder("Vouch::Action::IssueToken", "response")
        .timestamp(ts)
        .principal_for("Vouch::User", user)
        .resource_for("Vouch::Org", "org1")
        .field("input", "client_id", Value::String(client_id.to_string()))
        .build()
}

fn issue_token_request(ts: i64, user: &str) -> Event {
    Event::builder("Vouch::Action::IssueToken", "request")
        .timestamp(ts)
        .principal_for("Vouch::User", user)
        .resource_for("Vouch::Org", "org1")
        .field("input", "client_id", Value::String("cli".to_string()))
        .request_context("input", "client_id", Value::String("cli".to_string()))
        .build()
}

#[test]
fn lowering_and_validation_pass_for_well_typed_policies() -> Result<(), String> {
    for src in [STEP_UP_POLICIES, RATE_LIMIT_POLICIES] {
        let policies = lower(src)?;
        let report = Validator::new().validate(&policies);
        let errors: Vec<String> = report
            .validation_errors()
            .map(|e| format!("{e:?}"))
            .collect();
        assert!(
            errors.is_empty(),
            "expected clean validation, got: {errors:?}"
        );
    }
    Ok(())
}

#[test]
fn syntax_error_is_a_lowering_error_not_a_panic() {
    let result = lower("permit (principal, action ==");
    assert!(result.is_err(), "truncated policy text must fail to lower");
}

#[test]
fn typoed_field_is_caught_by_the_validator() -> Result<(), String> {
    // `client_idz` does not exist on IssueInput. CEL silently evaluated this
    // kind of typo to a runtime miss; Dogwood's validator reports it.
    let policies = lower(
        r#"
        @id("typo")
        forbid (principal, action == Vouch::Action::"IssueToken", resource)
        when { context.input.client_idz == "x" };
        "#,
    )?;
    let report = Validator::new().validate(&policies);
    assert!(
        report.validation_errors().count() > 0,
        "a typo'd context field must produce a validation error"
    );
    Ok(())
}

#[test]
fn step_up_recency_allows_fresh_login_and_denies_stale_or_missing() -> Result<(), String> {
    let mut authorizer = Authorizer::new(lower(STEP_UP_POLICIES)?);

    // History: alice logs in successfully at t=0.
    assert!(
        authorizer
            .is_authorized(&login_response(0, "alice", "1.2.3.4", true))
            .is_none(),
        "a response event is history, not a decision point"
    );

    // t=60s: alice's login is 60s old — inside the 15m window.
    let fresh = authorizer
        .is_authorized(&issue_token_request(60, "alice"))
        .ok_or("expected a decision for a request event")?;
    assert_eq!(
        fresh.decision(),
        Decision::Allow,
        "fresh login must allow issuance"
    );

    // t=120s: bob never logged in — callerPrincipal slicing means alice's
    // login is invisible to bob's decision.
    let other_user = authorizer
        .is_authorized(&issue_token_request(120, "bob"))
        .ok_or("expected a decision for a request event")?;
    assert_eq!(
        other_user.decision(),
        Decision::Deny,
        "another principal's login must not satisfy the step-up window"
    );

    // t=1h: alice's login is now outside the 15m window.
    let stale = authorizer
        .is_authorized(&issue_token_request(3600, "alice"))
        .ok_or("expected a decision for a request event")?;
    assert_eq!(
        stale.decision(),
        Decision::Deny,
        "stale login must deny issuance"
    );

    // The deny's diagnostics name the forbid (source rule index 1) so a
    // caller can map it back to a slug and remediation string.
    let reasons: Vec<usize> = stale.diagnostics().reason().map(|r| r.rule_index).collect();
    assert_eq!(
        reasons,
        vec![1],
        "the step_up_recency forbid determined the deny"
    );
    Ok(())
}

#[test]
fn count_within_rate_limit_denies_at_threshold_per_principal() -> Result<(), String> {
    let mut authorizer = Authorizer::new(lower(RATE_LIMIT_POLICIES)?);

    // alice: three issuances inside the hour; carol: two.
    for (ts, user) in [
        (0, "alice"),
        (10, "alice"),
        (20, "alice"),
        (30, "carol"),
        (40, "carol"),
    ] {
        assert!(
            authorizer
                .is_authorized(&issue_token_response(ts, user, "cli"))
                .is_none()
        );
    }

    let alice = authorizer
        .is_authorized(&issue_token_request(100, "alice"))
        .ok_or("expected a decision")?;
    assert_eq!(
        alice.decision(),
        Decision::Deny,
        "3 issuances in 1h must trip the cap"
    );

    let carol = authorizer
        .is_authorized(&issue_token_request(110, "carol"))
        .ok_or("expected a decision")?;
    assert_eq!(
        carol.decision(),
        Decision::Allow,
        "2 issuances in 1h must not trip the cap"
    );
    Ok(())
}
