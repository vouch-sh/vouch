//! Generator + staleness check for the "Audit Events" section of the
//! operator docs.
//!
//! The section between the `generated:audit-events` markers in
//! `docs/src/admin/audit.md` is **derived**, not hand-written: one table row
//! per [`AuditEventKind`], grouped by [`AuditEventGroup`], with headings and
//! descriptions resolved from the `audit-event-*` / `audit-group-*` messages
//! in the en-US Fluent catalog (exact registry ↔ catalog correspondence is
//! enforced by the parity test in `infra::i18n`).
//!
//! By default this compares the committed block against the rendered one and
//! fails if they differ. With `VOUCH_REGEN=1` (the `make docs-gen` target) it
//! rewrites the block in place instead.

#![allow(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use vouch_server::db::{AuditEventGroup, AuditEventKind};
use vouch_server::infra::i18n::I18nContext;

const AUDIT_MD_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/src/admin/audit.md");

const BEGIN_MARKER: &str = "<!-- generated:audit-events:begin — do not edit by hand; generated \
                            from the AuditEventKind registry (crates/vouch-server/src/db/audit.rs) \
                            and i18n/en-US/vouch-server.ftl. Regenerate with `make docs-gen`. -->";
const END_MARKER: &str = "<!-- generated:audit-events:end -->";

/// Resolve a Fluent id against the pinned en-US context, failing loudly if
/// the catalog doesn't define it (the parity test names the missing kind;
/// this guard keeps a raw id or loader error message out of the docs).
fn resolve(ctx: &I18nContext, id: &str) -> String {
    let text = ctx.t(id);
    assert!(
        text != id && !text.contains("No localization"),
        "Fluent id {id:?} did not resolve against i18n/en-US/vouch-server.ftl"
    );
    text
}

/// Render the generated block exactly as it appears between the markers:
/// a leading blank line, then one `###` subsection per group with a
/// two-column table, one row per registered kind.
fn render_block() -> String {
    // Pinned en-US regardless of the developer's environment, so generated
    // output cannot vary by locale.
    let ctx = I18nContext::fallback();
    let mut out = String::new();
    for group in AuditEventGroup::ALL {
        out.push_str("\n### ");
        out.push_str(&resolve(&ctx, group.i18n_id()));
        out.push_str("\n\n| Event Type | Description |\n|------------|-------------|\n");
        for kind in AuditEventKind::ALL.iter().filter(|k| k.group() == *group) {
            out.push_str("| `");
            out.push_str(kind.as_str());
            out.push_str("` | ");
            out.push_str(&resolve(&ctx, &kind.i18n_id()));
            out.push_str(" |\n");
        }
    }
    out
}

/// Byte range of the text between the marker lines (exclusive of both).
fn generated_range(doc: &str) -> (usize, usize) {
    assert_eq!(
        doc.matches(BEGIN_MARKER).count(),
        1,
        "audit.md must contain the begin marker exactly once"
    );
    assert_eq!(
        doc.matches(END_MARKER).count(),
        1,
        "audit.md must contain the end marker exactly once"
    );
    let begin = doc.find(BEGIN_MARKER).expect("begin marker present");
    let block_start = begin
        .checked_add(BEGIN_MARKER.len())
        .and_then(|i| i.checked_add(1)) // the newline ending the marker line
        .expect("marker offset fits in usize");
    let block_end = doc.find(END_MARKER).expect("end marker present");
    assert!(
        block_start <= block_end,
        "begin marker must precede end marker"
    );
    (block_start, block_end)
}

#[test]
#[expect(
    clippy::print_stderr,
    reason = "under VOUCH_REGEN this acts as a generator and reports what it rewrote"
)]
fn audit_events_docs_are_current() {
    let doc = std::fs::read_to_string(AUDIT_MD_PATH).expect("read audit.md");
    let (start, end) = generated_range(&doc);
    let current = doc
        .get(start..end)
        .expect("marker offsets are char boundaries");
    let generated = render_block();

    if std::env::var_os("VOUCH_REGEN").is_some() {
        if current != generated {
            let mut updated = String::with_capacity(doc.len());
            updated.push_str(doc.get(..start).expect("prefix is a char boundary"));
            updated.push_str(&generated);
            updated.push_str(doc.get(end..).expect("suffix is a char boundary"));
            std::fs::write(AUDIT_MD_PATH, updated).expect("rewrite audit.md");
            eprintln!("regenerated the 'Audit Events' block in docs/src/admin/audit.md");
        }
        return;
    }

    assert_eq!(
        current, generated,
        "the generated 'Audit Events' block in docs/src/admin/audit.md is \
         stale — run `make docs-gen` and commit the result"
    );
}

/// Every table row in the `## Audit Events` section must lie between the
/// markers: rows added by hand outside the generated block would document
/// event types the registry doesn't guarantee (the phantom-docs failure
/// mode this generator replaced).
#[test]
fn no_table_rows_outside_generated_block() {
    let doc = std::fs::read_to_string(AUDIT_MD_PATH).expect("read audit.md");
    let section_start = doc
        .find("## Audit Events")
        .expect("audit.md must have an '## Audit Events' section");
    let section_end = doc
        .get(section_start..)
        .and_then(|rest| {
            rest.get("## Audit Events".len()..)
                .and_then(|tail| tail.find("\n## "))
                .map(|i| {
                    section_start
                        .saturating_add("## Audit Events".len())
                        .saturating_add(i)
                })
        })
        .unwrap_or(doc.len());
    let (block_start, block_end) = generated_range(&doc);

    let mut offset = section_start;
    let section = doc
        .get(section_start..section_end)
        .expect("section bounds are char boundaries");
    for line in section.lines() {
        let is_row = line.trim_start().starts_with('|');
        if is_row {
            assert!(
                offset >= block_start && offset < block_end,
                "table row outside the generated block in the 'Audit Events' \
                 section of docs/src/admin/audit.md (add the event to the \
                 registry and catalog instead): {line:?}"
            );
        }
        offset = offset.saturating_add(line.len()).saturating_add(1); // the newline consumed by lines()
    }
}
