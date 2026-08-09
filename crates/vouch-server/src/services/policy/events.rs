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

use crate::db::audit::{AuditEvent as AuditRow, AuditEventFilter, AuditStore};
use dogwood_language::{Event, Value};

/// Audit kinds that feed the temporal history, with their Dogwood mapping.
pub(crate) const HISTORY_KINDS: &[&str] = &[
    "login_success",
    "login_failed",
    "logout",
    "oauth_token_issued",
    "oauth_token_revoked",
    "token_exchange",
    "ssh_credential",
    "aws_credential",
    "github_credential",
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
        event_types: Some(HISTORY_KINDS.iter().map(ToString::to_string).collect()),
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
    let data: serde_json::Value = serde_json::from_str(&row.data).unwrap_or_default();
    let str_field = |key: &str| -> Option<String> {
        data.get(key)
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
    };

    // Dogwood requires non-decreasing ingestion order; clamp against the
    // engine's high-water mark (cross-replica UUIDv7 skew can reorder).
    let ts = row.created_at.as_second().max(min_ts);

    let (action, fields): (&str, Vec<(&str, &str, Value)>) = match row.event_type.as_str() {
        "login_success" | "login_failed" => {
            let mut fields = vec![(
                "output",
                "result",
                Value::Bool(row.event_type == "login_success"),
            )];
            if let Some(ip) = str_field("client_ip") {
                fields.push(("input", "ip", Value::String(ip)));
            }
            if let Some(ua) = str_field("user_agent") {
                fields.push(("input", "user_agent", Value::String(ua)));
            }
            ("Vouch::Action::Login", fields)
        }
        "logout" => ("Vouch::Action::Logout", Vec::new()),
        "oauth_token_issued" => {
            let mut fields = Vec::new();
            if let Some(ip) = str_field("client_ip").or_else(|| str_field("ip_address")) {
                fields.push(("input", "ip", Value::String(ip)));
            }
            ("Vouch::Action::IssueToken", fields)
        }
        "oauth_token_revoked" => ("Vouch::Action::RevokeToken", Vec::new()),
        "token_exchange" => ("Vouch::Action::ExchangeToken", Vec::new()),
        "ssh_credential" => (
            "Vouch::Action::IssueCredential",
            vec![("input", "kind", Value::String("ssh".to_string()))],
        ),
        "aws_credential" => (
            "Vouch::Action::IssueCredential",
            vec![("input", "kind", Value::String("aws".to_string()))],
        ),
        "github_credential" => (
            "Vouch::Action::IssueCredential",
            vec![("input", "kind", Value::String("github".to_string()))],
        ),
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
