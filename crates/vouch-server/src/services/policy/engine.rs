// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Per-org stateful Dogwood authorizers.
//!
//! Temporal operators need the accumulated event history, so each org gets
//! one long-lived [`Authorizer`] holding the last 24h of audit-derived
//! events. The audit table is the source of truth: an engine is rebuilt
//! (with a fresh replay) whenever the org's policy fingerprint changes and
//! on process restart, and tails new audit rows before each decision.
//!
//! Locking: a `std::sync::Mutex` guards the org map. All async work (policy
//! loads, audit queries) happens before the lock is taken; observation and
//! decision are sync and fast. The lock is never held across an `.await`.
//!
//! Multi-replica honesty (spike): each replica holds its own in-memory
//! history fed from the shared audit table, so cross-replica counts lag by
//! the audit-write/tail-poll delay and per-replica cursors can observe the
//! same row at most once per replica. Production options are catalogued in
//! the spike assessment.

use super::events;
use super::preconfigured::PreconfiguredSlug;
use crate::db::audit::AuditEvent as AuditRow;
use dogwood_language::{Authorizer, Decision, Event, LoweredPolicySet};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

/// Identifies the source rule at a composed-set index, for deny messages.
#[derive(Debug, Clone)]
pub(crate) enum PolicyRef {
    /// One of the base permits — never a deny reason, present so rule
    /// indices line up with composition order.
    BasePermit,
    Preconfigured(PreconfiguredSlug),
    Custom {
        name: String,
    },
}

/// Outcome of one stateful decision.
pub(crate) enum OrgDecision {
    Allow,
    /// Denied; the first determining forbid, when it maps to a known rule.
    Deny(Option<PolicyRef>),
}

struct OrgEngine {
    authorizer: Authorizer,
    refs: Vec<PolicyRef>,
    fingerprint: u64,
    /// Audit tail cursor: the last observed row id (UUIDv7).
    last_event_id: Option<String>,
    /// High-water timestamp for monotonic ingestion.
    last_ts: i64,
}

/// The parts a rebuild installs: the lowered set and its rule-index map.
pub(crate) struct EngineParts {
    pub lowered: LoweredPolicySet,
    pub refs: Vec<PolicyRef>,
}

#[derive(Default)]
pub(crate) struct PolicyEngine {
    orgs: Mutex<HashMap<String, OrgEngine>>,
}

/// Fingerprint of an org's policy configuration: active slugs plus custom
/// `(id, text, active)` triples. A change forces an engine rebuild.
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
    /// The audit cursor for an org's engine, or `None` when no engine with
    /// this fingerprint exists (caller must build + [`Self::install`]).
    /// The outer `Option` is presence; the inner is the cursor itself.
    #[expect(
        clippy::option_option,
        reason = "outer = engine presence, inner = cursor value"
    )]
    pub(crate) fn cursor_if_current(
        &self,
        org_id: &str,
        fingerprint: u64,
    ) -> Option<Option<String>> {
        let orgs = match self.orgs.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        orgs.get(org_id)
            .filter(|e| e.fingerprint == fingerprint)
            .map(|e| e.last_event_id.clone())
    }

    /// Build an org engine from lowered parts, replay history rows into it,
    /// and install it (replacing any previous engine for the org).
    pub(crate) fn install(
        &self,
        org_id: &str,
        fingerprint: u64,
        parts: EngineParts,
        replay_rows: &[AuditRow],
    ) {
        let mut engine = OrgEngine {
            authorizer: Authorizer::new(parts.lowered),
            refs: parts.refs,
            fingerprint,
            last_event_id: None,
            last_ts: 0,
        };
        observe_rows(&mut engine, org_id, replay_rows);
        tracing::debug!(
            org_id,
            replayed = replay_rows.len(),
            "installed org policy engine"
        );
        let mut orgs = match self.orgs.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        orgs.insert(org_id.to_string(), engine);
    }

    /// Observe new audit rows, then decide a request event built at a
    /// timestamp clamped against the engine's high-water mark (Dogwood
    /// requires non-decreasing ingestion order).
    ///
    /// Returns `None` when no engine with this fingerprint exists (a
    /// concurrent policy change dropped it — caller rebuilds and retries).
    /// `Err` is an engine-level failure (no verdict for a request event);
    /// callers treat it as deny.
    pub(crate) fn decide(
        &self,
        org_id: &str,
        fingerprint: u64,
        new_rows: &[AuditRow],
        now: i64,
        make_request: impl FnOnce(i64) -> Event,
    ) -> Option<Result<OrgDecision, String>> {
        let mut orgs = match self.orgs.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let engine = orgs
            .get_mut(org_id)
            .filter(|e| e.fingerprint == fingerprint)?;
        observe_rows(engine, org_id, new_rows);
        let ts = now.max(engine.last_ts);
        engine.last_ts = ts;
        let request = make_request(ts);
        let Some(response) = engine.authorizer.is_authorized(&request) else {
            return Some(Err("no decision returned for a request event".to_string()));
        };
        for error in response.diagnostics().errors() {
            tracing::warn!(org_id, "policy evaluation error: {error}");
        }
        let decision = match response.decision() {
            Decision::Allow => OrgDecision::Allow,
            Decision::Deny => {
                let denying = response
                    .diagnostics()
                    .reason()
                    .map(|r| r.rule_index)
                    .filter_map(|i| engine.refs.get(i))
                    .find(|r| !matches!(r, PolicyRef::BasePermit));
                OrgDecision::Deny(denying.cloned())
            }
        };
        Some(Ok(decision))
    }
}

/// Observe rows into an engine, mapping them to events (with monotonic
/// timestamp clamping) and advancing the max-id cursor.
///
/// The already-seen skip compares against the cursor as it was at ENTRY,
/// not per-row: rows arrive sorted by `created_at`, and a backdated row
/// (test seeds; cross-replica clock skew) can carry a LARGER UUIDv7 id
/// than a chronologically later row — a per-row cursor update would then
/// silently drop the rest of the batch. The entry snapshot still dedups
/// concurrent evaluators that fetched the same tail.
fn observe_rows(engine: &mut OrgEngine, org_id: &str, rows: &[AuditRow]) {
    let entry_cursor = engine.last_event_id.clone();
    for row in rows {
        // UUIDv7 ids are lexicographically ordered; same-length compare.
        if entry_cursor
            .as_deref()
            .is_some_and(|last| row.id.as_str() <= last)
        {
            continue;
        }
        if let Some(event) = events::history_event(row, org_id, engine.last_ts) {
            engine.last_ts = event.timestamp().max(engine.last_ts);
            engine.authorizer.is_authorized(&event);
        }
        if engine
            .last_event_id
            .as_deref()
            .is_none_or(|last| row.id.as_str() > last)
        {
            engine.last_event_id = Some(row.id.clone());
        }
    }
}
