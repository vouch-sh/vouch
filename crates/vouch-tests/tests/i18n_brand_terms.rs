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
