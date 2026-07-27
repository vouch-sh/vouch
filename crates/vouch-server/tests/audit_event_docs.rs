//! Completeness test binding the audit event registry to the operator docs.
//!
//! The "Audit Events" section of `docs/src/admin/audit.md` must
//! document every [`AuditEventKind`] the server can write, and must not
//! document event types that don't exist (phantom docs — the state this
//! table was found in before the registry existed). Checked both ways:
//!
//! 1. every `AuditEventKind::ALL` variant appears as a backticked token in
//!    the section, and
//! 2. every backticked snake_case token in the section's table rows is a
//!    registered kind.

#![allow(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use std::collections::BTreeSet;

use vouch_server::db::AuditEventKind;

/// Backticked tokens in table rows that are not event types.
const NON_EVENT_TOKENS: &[&str] = &["authenticator_id", "data", "role_arn", "vouch register"];

fn audit_events_section() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/src/admin/audit.md");
    let doc = std::fs::read_to_string(path).expect("read audit.md");
    let start = doc
        .find("## Audit Events")
        .expect("audit.md must have an '## Audit Events' section");
    let rest = doc.get(start..).expect("section start is a char boundary");
    let end = rest
        .get("## Audit Events".len()..)
        .and_then(|tail| tail.find("\n## "))
        .map_or(rest.len(), |i| i.saturating_add("## Audit Events".len()));
    rest.get(..end)
        .expect("section end is a char boundary")
        .to_string()
}

/// Backticked code spans in markdown table rows of the section.
fn table_code_spans(section: &str) -> Vec<String> {
    let mut spans = Vec::new();
    for line in section.lines().filter(|l| l.trim_start().starts_with('|')) {
        // Odd-indexed chunks of a backtick split are inside code spans.
        for (i, chunk) in line.split('`').enumerate() {
            if i % 2 == 1 {
                spans.push(chunk.to_string());
            }
        }
    }
    spans
}

#[test]
fn every_audit_event_kind_is_documented() {
    let section = audit_events_section();
    let mut missing = Vec::new();
    for kind in AuditEventKind::ALL {
        let token = format!("`{}`", kind.as_str());
        if !section.contains(&token) {
            missing.push(kind.as_str());
        }
    }
    assert!(
        missing.is_empty(),
        "audit event kinds missing from docs/src/admin/audit.md \
         'Audit Events' section: {missing:?}"
    );
}

#[test]
fn docs_do_not_list_phantom_event_types() {
    let known: BTreeSet<&str> = AuditEventKind::ALL.iter().map(|k| k.as_str()).collect();
    let section = audit_events_section();
    let mut phantom = Vec::new();
    for span in table_code_spans(&section) {
        let looks_like_event_type = !span.is_empty()
            && span
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if looks_like_event_type
            && !known.contains(span.as_str())
            && !NON_EVENT_TOKENS.contains(&span.as_str())
        {
            phantom.push(span);
        }
    }
    assert!(
        phantom.is_empty(),
        "docs/src/admin/audit.md documents event types that no code \
         writes (remove them or register the kind): {phantom:?}"
    );
}
