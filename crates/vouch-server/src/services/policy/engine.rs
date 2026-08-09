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
//! The one piece of shared state is a small per-org precheck cache: the
//! outcome of lowering + validating the org's composed policy set, keyed by
//! a fingerprint of the policy configuration. It caches only a verdict
//! about static policy text (never enforcement state), so a stale entry can
//! at worst skip re-validation, not change which policies are enforced.

use super::events;
use super::preconfigured::PreconfiguredSlug;
use crate::db::audit::AuditEvent as AuditRow;
use dogwood_language::{Authorizer, Decision, Event, LoweredPolicySet};
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
pub(crate) enum OrgDecision {
    Allow,
    /// Denied; the first determining forbid, when it maps to a known rule.
    Deny(Option<DenyingPolicy>),
}

/// Cached verdict of the static precheck over an org's composed policy set.
#[derive(Debug, Clone)]
pub(crate) enum Precheck {
    /// The composed set lowers and validates, with what it reads:
    /// `uses_temporal` false lets the decision path skip the audit query
    /// and replay, and `reads_device` false means the org's policies never
    /// consult device posture, so a client need not send any.
    Ok {
        uses_temporal: bool,
        reads_device: bool,
    },
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
    for error in response.diagnostics().errors() {
        tracing::warn!(org_id, "policy evaluation error: {error}");
    }
    match response.decision() {
        Decision::Allow => Ok(OrgDecision::Allow),
        Decision::Deny => {
            let denying = response
                .diagnostics()
                .reason()
                .map(|r| r.rule_index)
                .filter_map(|i| refs.get(i))
                .find_map(|r| match r {
                    PolicyRef::BasePermit => None,
                    PolicyRef::Policy(policy) => Some(policy.clone()),
                });
            Ok(OrgDecision::Deny(denying))
        }
    }
}
