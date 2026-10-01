// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Per-decision policy evaluation.
//!
//! Every temporal predicate is sliced per principal: Dogwood's default
//! event schema declares a universal pin on `callerPrincipal`, so a
//! predicate only sees events from the deciding principal. A decision
//! therefore consults just the requesting user's history.
//! See <https://dogwood-policy.github.io/dogwood/guide/04-temporal-expressions.html>
//! ("key-local vs. global semantics"). Each decision therefore builds a fresh
//! authorizer, replays that user's last 24h of audit rows into it, and
//! decides — no shared mutable engine, no audit cursor, and cross-replica
//! correctness comes from querying the shared audit table at decision time.
//!
//! A decision reads history only when a temporal rule can apply to it:
//! [`history_needed`] asks the lowered set's leaf map which temporal leaves
//! the request's action can read, the same slicing the Dogwood local engine
//! uses, so an org whose only temporal rule gates token exchange does not
//! pay the audit query on every login.
//!
//! An evaluation error denies. Cedar skips a policy whose condition errors
//! at runtime (an integer overflow on a client-supplied posture value, for
//! one), so a `forbid` that errors would otherwise drop out and the base
//! permit would allow. [`evaluate`] turns an allow that carries evaluation
//! errors into a deny attributed to the policy that errored.
//!
//! Deny attribution maps a determining rule's index back to the policy that
//! authored it. [`check_attribution`] proves that map against the lowered
//! set once per configuration, and [`evaluate`] refuses a determining rule
//! whose Cedar id does not match, so a deny can never name the wrong policy.
//!
//! The one piece of shared state is a small per-org precheck cache: the
//! outcome of lowering + validating the org's composed policy set, keyed by
//! a fingerprint of the policy configuration. It caches only a verdict
//! about static policy text (never enforcement state), so a stale entry can
//! at worst skip re-validation, not change which policies are enforced.

use super::events;
use super::preconfigured::PreconfiguredSlug;
use crate::db::audit::AuditEvent as AuditRow;
use dogwood_language::{Authorizer, Decision, DogwoodRuleRef, Event, LoweredPolicySet};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

/// A policy a deny can be attributed to. Base permits are excluded by
/// construction, so a deny message can never name one.
#[derive(Debug, Clone)]
pub(crate) enum DenyingPolicy {
    Preconfigured(PreconfiguredSlug),
    Custom { name: String },
}

/// Identifies the source rule at a composed-set index, for deny messages.
#[derive(Debug, Clone)]
pub(crate) enum PolicyRef {
    /// One of the base permits — never a deny reason, present so rule
    /// indices line up with composition order.
    BasePermit,
    Policy(DenyingPolicy),
}

/// Outcome of one decision.
#[derive(Debug)]
pub(crate) enum OrgDecision {
    Allow,
    /// Denied; the first determining forbid, when it maps to a known rule.
    Deny(Option<DenyingPolicy>),
}

/// Cached verdict of the static precheck over an org's composed policy set.
#[derive(Debug, Clone)]
pub(crate) enum Precheck {
    /// The composed set lowers, validates, and its rule-to-policy map
    /// agrees with the lowered rules. `reads_device` false means the org's
    /// policies never consult device posture, so a client need not send
    /// any.
    Ok { reads_device: bool },
    /// A custom policy fails to lower or validate; decisions deny with its
    /// name until it is fixed (fail-closed, attributable).
    BrokenCustom(String),
    /// The set fails for a reason not attributable to a single custom
    /// policy — a server bug; decisions report the engine unavailable.
    EngineError(String),
}

#[derive(Default)]
pub(crate) struct PolicyEngine {
    prechecks: Mutex<HashMap<String, (u64, Precheck)>>,
}

/// Fingerprint of an org's policy configuration: active slugs plus custom
/// `(id, text)` pairs. Guards only the precheck cache — a collision would
/// skip re-validation of unchanged-looking config, never change which
/// policy text is enforced (the enforced set is rebuilt from the loaded
/// configuration on every decision).
pub(crate) fn fingerprint(active_slugs: &[String], custom: &[(String, String)]) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    let mut slugs: Vec<&String> = active_slugs.iter().collect();
    slugs.sort();
    slugs.hash(&mut hasher);
    let mut custom: Vec<&(String, String)> = custom.iter().collect();
    custom.sort();
    custom.hash(&mut hasher);
    hasher.finish()
}

impl PolicyEngine {
    /// The cached precheck verdict for this org+fingerprint, computing and
    /// caching it via `compute` on miss. `compute` runs outside the lock
    /// (concurrent misses may compute redundantly; last insert wins).
    pub(crate) fn precheck(
        &self,
        org_id: &str,
        fingerprint: u64,
        compute: impl FnOnce() -> Precheck,
    ) -> Precheck {
        {
            let prechecks = match self.prechecks.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some((cached_fp, verdict)) = prechecks.get(org_id)
                && *cached_fp == fingerprint
            {
                return verdict.clone();
            }
        }
        let verdict = compute();
        let mut prechecks = match self.prechecks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        prechecks.insert(org_id.to_string(), (fingerprint, verdict.clone()));
        verdict
    }
}

/// Whether deciding `request` can read any temporal leaf, and so needs the
/// principal's event history.
///
/// Asks the lowered set's [`DecisionLeafMap`](dogwood_language::DecisionLeafMap),
/// which indexes each temporal leaf by the request actions its rule's scope
/// expands to. `Some(empty)` means no leaf can affect this decision, so the
/// history query and replay are skipped; `None` means the map has no answer
/// for this action, and history is fetched. A leaf whose scope cannot be
/// resolved is widened to every action by the map itself, so both fallbacks
/// err toward fetching.
pub(crate) fn history_needed(lowered: &LoweredPolicySet, request: &Event) -> bool {
    lowered
        .leaf_map()
        .needed_for(request)
        .is_none_or(|leaves| !leaves.is_empty())
}

/// Prove that `refs` (built from per-text rule counts in composition order)
/// maps every lowered rule to the policy that authored it.
///
/// The lowered set must carry exactly one rule per ref, and each rule's
/// Cedar `@id` annotation must agree with its ref: a base permit carries a
/// `base_allow_` id and a preconfigured forbid carries its slug. Custom
/// policies choose their own annotations, so they are held only to the
/// count. A mismatch is a server bug; the precheck reports it as an engine
/// error so decisions fail closed instead of naming the wrong policy.
pub(crate) fn check_attribution(
    lowered: &LoweredPolicySet,
    refs: &[PolicyRef],
) -> Result<(), String> {
    let rules: Vec<DogwoodRuleRef> = lowered.rules().collect();
    if rules.len() != refs.len() {
        return Err(format!(
            "policy attribution: {} lowered rules but {} policy refs",
            rules.len(),
            refs.len()
        ));
    }
    let cedar = lowered.as_cedar();
    for (rule, policy_ref) in rules.iter().zip(refs) {
        let annotated_id = cedar
            .policies()
            .find(|policy| policy.id().to_string() == rule.cedar_policy_id)
            .ok_or_else(|| {
                format!(
                    "policy attribution: rule {} has no lowered Cedar policy",
                    rule.rule_index
                )
            })?
            .annotation("id")
            .map(ToString::to_string);
        let agrees = match policy_ref {
            PolicyRef::BasePermit => annotated_id
                .as_deref()
                .is_some_and(|id| id.starts_with("base_allow_")),
            PolicyRef::Policy(DenyingPolicy::Preconfigured(slug)) => {
                annotated_id.as_deref() == Some(slug.as_str())
            }
            PolicyRef::Policy(DenyingPolicy::Custom { .. }) => true,
        };
        if !agrees {
            return Err(format!(
                "policy attribution: rule {} carries @id {annotated_id:?}, \
                 which does not match its source policy",
                rule.rule_index
            ));
        }
    }
    Ok(())
}

/// Evaluate one decision: build a fresh authorizer from the lowered set,
/// replay the principal's history (sorted, timestamps non-decreasing), and
/// decide a request event whose timestamp never precedes the history.
///
/// `Err` is an engine-level failure (no verdict for a request event);
/// callers treat it as deny.
pub(crate) fn evaluate(
    lowered: LoweredPolicySet,
    refs: &[PolicyRef],
    history: &[AuditRow],
    org_id: &str,
    now: i64,
    make_request: impl FnOnce(i64) -> Event,
) -> Result<OrgDecision, String> {
    // Collected before the authorizer consumes the set: a determining rule
    // is attributed only when its Cedar id matches the rule at its index.
    let rules: Vec<DogwoodRuleRef> = lowered.rules().collect();
    let mut authorizer = Authorizer::new(lowered);
    let mut last_ts = 0_i64;
    for row in history {
        if let Some(event) = events::history_event(row, org_id, last_ts) {
            last_ts = event.timestamp().max(last_ts);
            authorizer.is_authorized(&event);
        }
    }
    let request = make_request(now.max(last_ts));
    let Some(response) = authorizer.is_authorized(&request) else {
        return Err("no decision returned for a request event".to_string());
    };
    let errors: Vec<&str> = response.diagnostics().errors().collect();
    for error in &errors {
        tracing::warn!(org_id, "policy evaluation error: {error}");
    }
    let erroring = erroring_policy(&errors, &rules, refs);
    match response.decision() {
        Decision::Allow if errors.is_empty() => Ok(OrgDecision::Allow),
        // A rule that errored was skipped, so this allow never heard from
        // it: fail closed.
        Decision::Allow => {
            tracing::warn!(
                org_id,
                "policy evaluation errored; denying the allow it would have produced"
            );
            Ok(OrgDecision::Deny(erroring))
        }
        Decision::Deny => {
            let mut denying = None;
            for reason in response.diagnostics().reason() {
                let aligned = rules
                    .get(reason.rule_index)
                    .is_some_and(|rule| rule.cedar_policy_id == reason.cedar_policy_id);
                let Some(policy_ref) = refs.get(reason.rule_index).filter(|_| aligned) else {
                    // The verdict is already a deny; refusing to attribute it
                    // keeps a broken map from naming the wrong policy (and
                    // its remediation) to the user.
                    return Err(format!(
                        "determining rule {} ({}) has no matching policy ref",
                        reason.rule_index, reason.cedar_policy_id
                    ));
                };
                if denying.is_none()
                    && let PolicyRef::Policy(policy) = policy_ref
                {
                    denying = Some(policy.clone());
                }
            }
            Ok(OrgDecision::Deny(denying.or(erroring)))
        }
    }
}

/// The non-base policy named by the first evaluation error that names one.
/// Cedar reports a failing condition as "error while evaluating policy
/// `<id>`: …"; the id is matched in backticks against the lowered rules, so
/// an error that names no rule (a temporal or provider failure) attributes
/// nothing rather than guessing.
fn erroring_policy(
    errors: &[&str],
    rules: &[DogwoodRuleRef],
    refs: &[PolicyRef],
) -> Option<DenyingPolicy> {
    errors.iter().find_map(|error| {
        rules
            .iter()
            .find(|rule| error.contains(&format!("`{}`", rule.cedar_policy_id)))
            .and_then(|rule| refs.get(rule.rule_index))
            .and_then(|policy_ref| match policy_ref {
                PolicyRef::BasePermit => None,
                PolicyRef::Policy(policy) => Some(policy.clone()),
            })
    })
}
