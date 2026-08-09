// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Audit rows → Dogwood history events.
//!
//! The `audit_events` table is the durable source of truth for temporal
//! policy history. Each org engine replays the last 24 hours (Dogwood's
//! default `max_window`) at build time and tails new rows before each
//! decision. History events are `::response` kind — never decision points.
//!
//! Rows with a NULL `user_id` are skipped: every temporal predicate is
//! sliced per principal (the default event schema pins `callerPrincipal`),
//! so an event without a principal can never match. This also means
//! machine-only issuances (client-credentials tokens) are not counted.

use crate::db::audit::{AuditEvent as AuditRow, AuditEventFilter, AuditEventKind, AuditStore};
use dogwood_language::{Event, Value};

/// Audit kinds that feed the temporal history. Every kind here must have a
/// mapping arm in [`history_event`]; the parity test enforces both
/// directions.
pub(crate) const HISTORY_KINDS: &[AuditEventKind] = &[
    AuditEventKind::LoginSuccess,
    AuditEventKind::LoginFailed,
    AuditEventKind::Logout,
    AuditEventKind::OauthTokenIssued,
    AuditEventKind::OauthTokenRevoked,
    AuditEventKind::TokenExchange,
    AuditEventKind::SshCredential,
    AuditEventKind::AwsCredential,
    AuditEventKind::GitHubCredential,
];

/// How far back the replay looks. Matches Dogwood's default `max_window`
/// cap, so every legal `within` window is fully served after a replay.
const REPLAY_WINDOW_HOURS: i64 = 24;

/// Cap on rows fetched per replay/tail query. Exceeding it is logged —
/// never silently truncated.
const FETCH_LIMIT: u64 = 10_000;

/// Fetch one principal's history: their last 24h of mapped audit rows,
/// oldest-first (the order the authorizer must observe them in). Queried at
/// decision time against the shared audit table, so every replica sees the
/// same history modulo in-flight writes.
pub(crate) async fn fetch_user_history(
    audit: &AuditStore,
    user_id: &str,
) -> Result<Vec<AuditRow>, String> {
    let now = jiff::Timestamp::now();
    let floor = now
        .checked_sub(jiff::Span::new().hours(REPLAY_WINDOW_HOURS))
        .map_err(|e| format!("cannot compute replay window floor: {e}"))?;
    let filter = AuditEventFilter {
        event_types: Some(
            HISTORY_KINDS
                .iter()
                .map(|k| k.as_str().to_string())
                .collect(),
        ),
        user_id: Some(user_id.to_string()),
        since: Some(floor.to_string()),
        limit: Some(FETCH_LIMIT),
        ..AuditEventFilter::default()
    };
    let mut rows = audit
        .query_events(&filter)
        .await
        .map_err(|e| format!("audit history query failed: {e}"))?;
    if u64::try_from(rows.len()).unwrap_or(u64::MAX) >= FETCH_LIMIT {
        tracing::warn!(
            user_id,
            limit = FETCH_LIMIT,
            "audit history fetch hit its row cap; temporal history may be incomplete"
        );
    }
    // Oldest-first regardless of the query's ordering; UUIDv7 ids break
    // created_at ties in insertion order.
    rows.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    Ok(rows)
}

/// Map one audit row to a Dogwood history event. Returns `None` for rows
/// that carry no principal or an unmapped kind.
pub(crate) fn history_event(row: &AuditRow, org_id: &str, min_ts: i64) -> Option<Event> {
    let user_id = row.user_id.as_deref()?;
    let kind = AuditEventKind::from_wire(&row.event_type)?;
    let data: serde_json::Value = match serde_json::from_str(&row.data) {
        Ok(value) => value,
        Err(e) => {
            // Correlation fields (ip, client_id) are lost, so pinned
            // predicates stop matching — fail-closed, but never silent.
            tracing::warn!(
                event_id = row.id,
                event_type = row.event_type,
                "audit payload is not valid JSON; temporal correlation fields unavailable: {e}"
            );
            serde_json::Value::Null
        }
    };
    let str_field = |key: &str| -> Option<String> {
        data.get(key)
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
    };

    // Dogwood requires non-decreasing ingestion order; clamp against the
    // engine's high-water mark (cross-replica UUIDv7 skew can reorder).
    let ts = row.created_at.as_second().max(min_ts);

    // Every field the schema declares on an event's `input`/`output` groups
    // is written here, defaulting when the audit payload lacks it — a
    // declared-but-unwritten field would make temporal predicates over it
    // silently never match. `history_projection_matches_schema` is the
    // parity guard.
    let string_or_empty = |key: &str| Value::String(str_field(key).unwrap_or_default());
    let (action, fields): (&str, Vec<(&str, &str, Value)>) = match kind {
        AuditEventKind::LoginSuccess | AuditEventKind::LoginFailed => (
            "Vouch::Action::Login",
            vec![
                ("input", "ip", string_or_empty("client_ip")),
                ("input", "user_agent", string_or_empty("user_agent")),
                (
                    "output",
                    "result",
                    Value::Bool(kind == AuditEventKind::LoginSuccess),
                ),
            ],
        ),
        AuditEventKind::Logout => ("Vouch::Action::Logout", Vec::new()),
        AuditEventKind::OauthTokenIssued => (
            "Vouch::Action::IssueToken",
            vec![
                ("input", "ip", string_or_empty("client_ip")),
                ("input", "client_id", string_or_empty("oauth_client_id")),
            ],
        ),
        AuditEventKind::OauthTokenRevoked => ("Vouch::Action::RevokeToken", Vec::new()),
        AuditEventKind::TokenExchange => (
            "Vouch::Action::ExchangeToken",
            vec![
                ("input", "ip", string_or_empty("client_ip")),
                ("input", "client_id", string_or_empty("oauth_client_id")),
                ("input", "audience", string_or_empty("requested_audience")),
            ],
        ),
        AuditEventKind::SshCredential => (
            "Vouch::Action::IssueCredential",
            vec![("input", "kind", Value::String("ssh".to_string()))],
        ),
        AuditEventKind::AwsCredential => (
            "Vouch::Action::IssueCredential",
            vec![("input", "kind", Value::String("aws".to_string()))],
        ),
        AuditEventKind::GitHubCredential => (
            "Vouch::Action::IssueCredential",
            vec![("input", "kind", Value::String("github".to_string()))],
        ),
        // Not a history kind: HISTORY_KINDS is the single source of truth
        // for what is ingested, and it is derived from this same enum.
        _ => return None,
    };

    let mut builder = Event::builder(action, "response")
        .timestamp(ts)
        .principal_for("Vouch::User", user_id)
        .resource_for("Vouch::Org", org_id);
    for (group, name, value) in fields {
        builder = builder.field(group, name, value);
    }
    Some(builder.build())
}
