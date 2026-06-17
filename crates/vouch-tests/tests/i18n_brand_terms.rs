// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cross-catalog brand-term parity.
//!
//! Brand terms (`-product`, `-cmd`, `-yubikey`) are defined in multiple
//! Fluent catalogs because Fluent has no cross-file term import. A rebrand
//! today requires editing every catalog; this test prevents drift between
//! them by asserting that every term defined in more than one catalog
//! expands to the same value across all catalogs that define it.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Per-catalog map of term name → value. Term lines are simple
/// `-term-name = value` assignments at the top of each FTL file.
fn parse_terms(path: &Path) -> HashMap<String, String> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let mut terms = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        // Terms must be left-aligned `-name = value` lines. Anything else
        // (messages, attributes, comments, blank lines) is skipped.
        if trimmed.len() != line.len() || !trimmed.starts_with('-') {
            continue;
        }
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim().to_owned();
        let value = value.trim().to_owned();
        if !name.is_empty() && !value.is_empty() {
            terms.insert(name, value);
        }
    }
    terms
}

fn workspace_catalog(relative: &str) -> PathBuf {
    // CARGO_MANIFEST_DIR is `crates/vouch-tests` at compile time; resolve
    // sibling crates by `../<crate>/i18n/...`.
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("..").join(relative)
}

#[test]
fn brand_terms_agree_across_catalogs() {
    let server = parse_terms(&workspace_catalog(
        "vouch-server/i18n/en-US/vouch-server.ftl",
    ));
    let cli = parse_terms(&workspace_catalog("vouch-cli/i18n/en-US/vouch-cli.ftl"));
    let agent = parse_terms(&workspace_catalog("vouch-agent/i18n/en-US/vouch-agent.ftl"));

    let catalogs: [(&str, &HashMap<String, String>); 3] =
        [("server", &server), ("cli", &cli), ("agent", &agent)];

    // Collect every term that appears in at least two catalogs.
    let mut all_names = std::collections::HashSet::new();
    for (_, terms) in &catalogs {
        all_names.extend(terms.keys().cloned());
    }

    for name in &all_names {
        let definitions: Vec<(&str, &str)> = catalogs
            .iter()
            .filter_map(|(catalog, terms)| terms.get(name).map(|v| (*catalog, v.as_str())))
            .collect();
        if definitions.len() < 2 {
            continue;
        }
        let (_, first_value) = definitions[0];
        for (catalog, value) in &definitions[1..] {
            assert_eq!(
                first_value, *value,
                "brand term `{name}` drift: server-side definition vs `{catalog}` differ \
                 (`{first_value}` vs `{value}`); update every catalog when renaming a brand term",
            );
        }
    }
}

/// Collect term references (`{ -term-name }`) from a single FTL line. Comment
/// lines (starting with `#`) are skipped by the caller so doc-comment examples
/// like `{ -term-name }` don't trigger false positives.
fn collect_term_refs(line: &str, out: &mut std::collections::HashSet<String>) {
    let mut rest = line;
    while let Some(open) = rest.find('{') {
        let after_open = rest
            .get(open.saturating_add(1)..)
            .unwrap_or("")
            .trim_start();
        if let Some(stripped) = after_open.strip_prefix('-')
            && let Some(close) = stripped.find('}')
        {
            let name = stripped.get(..close).unwrap_or("").trim();
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                out.insert(format!("-{name}"));
            }
        }
        rest = rest.get(open.saturating_add(1)..).unwrap_or("");
    }
}

/// Walk each catalog's message bodies and assert that every `{ -term }`
/// reference resolves to a term **defined in the same catalog**. Fluent
/// has no cross-file term import, so a message that references a term
/// missing from its own catalog renders the placeable unresolved (e.g.
/// "vouch: failed to get {-github} token: ..." instead of "GitHub").
/// Caught in PR #492 review — the CLI added a message using `{ -github }`
/// while `-github` was only defined in the server catalog.
#[test]
fn every_term_reference_has_a_definition() {
    let catalogs = [
        ("server", "vouch-server/i18n/en-US/vouch-server.ftl"),
        ("cli", "vouch-cli/i18n/en-US/vouch-cli.ftl"),
        ("agent", "vouch-agent/i18n/en-US/vouch-agent.ftl"),
    ];

    let mut failures = Vec::new();
    for (name, rel_path) in catalogs {
        let path = workspace_catalog(rel_path);
        let defined: std::collections::HashSet<String> = parse_terms(&path).into_keys().collect();
        let mut referenced = std::collections::HashSet::new();
        let text = fs::read_to_string(&path).unwrap();
        for line in text.lines() {
            // Skip comment lines so doc-comment examples (e.g.
            // `# Reference as { -term-name } in any message.`) don't count.
            if line.trim_start().starts_with('#') {
                continue;
            }
            collect_term_refs(line, &mut referenced);
        }
        for missing in referenced.difference(&defined) {
            failures.push(format!("{name}: `{missing}` referenced but not defined"));
        }
    }
    failures.sort();
    assert!(
        failures.is_empty(),
        "Fluent term references without a matching definition in the same \
         catalog (Fluent cannot import terms across files):\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn brand_terms_present_in_server_catalog() {
    // Sanity check: the server catalog is the canonical source. If a term
    // exists in CLI or agent but not in the server, that's a rebrand
    // outage waiting to happen.
    let server = parse_terms(&workspace_catalog(
        "vouch-server/i18n/en-US/vouch-server.ftl",
    ));
    let cli = parse_terms(&workspace_catalog("vouch-cli/i18n/en-US/vouch-cli.ftl"));
    let agent = parse_terms(&workspace_catalog("vouch-agent/i18n/en-US/vouch-agent.ftl"));

    for name in cli.keys().chain(agent.keys()) {
        assert!(
            server.contains_key(name),
            "term `{name}` defined in CLI/agent but missing from server catalog; \
             add it to crates/vouch-server/i18n/en-US/vouch-server.ftl",
        );
    }
}
