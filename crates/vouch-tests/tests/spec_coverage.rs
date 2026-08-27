// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Ratchet gate on normative specification coverage.
//!
//! `specs/requirements.tsv` lists every MUST / MUST NOT / SHOULD / SHOULD NOT
//! statement in the cached specification corpus, extracted by
//! `scripts/audit-normative.py`. `specs/audit-scope.tsv` says which of those
//! specifications impose obligations on Vouch. This test links the two to the
//! test suite: a requirement counts as *cited* when some test function names
//! its specification and section in a comment or assertion message.
//!
//! Linkage is section-level and deliberately optimistic. It establishes that a
//! requirement is untested; it does not prove a cited one is tested well.
//!
//! `specs/coverage-baseline.tsv` records the requirements that are currently
//! uncited -- the accepted backlog. The gate is a ratchet, not a bar: the
//! existing backlog is tolerated, but
//!
//!   * a requirement that becomes uncited when it was not before fails, and
//!   * a baseline entry that is now cited, or that no longer exists in the
//!     corpus, also fails.
//!
//! The second rule is what makes it a ratchet: the backlog can only shrink.
//! Regenerate it after closing gaps with
//!
//! ```text
//! UPDATE_SPEC_COVERAGE_BASELINE=1 cargo test -p vouch-tests --test spec_coverage
//! ```
//!
//! This test owns the scan so the gate cannot drift from the baseline it
//! checks. `scripts/audit-coverage.py` renders the same data as a readable
//! report; when the two disagree, this test is authoritative.

#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::print_stderr,
    reason = "test code: panicking on an assertion failure is the point, and the \
              citation scanner slices byte ranges it has already bounds-checked"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/vouch-tests has a grandparent")
        .to_path_buf()
}

/// Prose names for specifications that have no RFC number, as they appear in
/// test comments. Longest first: "OIDC Discovery" must win over "OIDC Core"
/// never matching it, and "FAPI 2.0 Message Signing" over "FAPI".
const ALIASES: &[(&str, &str)] = &[
    (
        "OpenID Connect Dynamic Client Registration",
        "oidc-registration-1_0",
    ),
    ("OpenID Connect Discovery", "oidc-discovery-1_0"),
    ("OpenID Connect Core", "oidc-core-1_0"),
    ("FAPI 2.0 Message Signing", "fapi-2_0-message-signing"),
    ("OIDC Registration", "oidc-registration-1_0"),
    ("OIDC Discovery", "oidc-discovery-1_0"),
    ("RP-Initiated Logout", "oidc-rpinitiated-1_0"),
    ("Back-Channel Logout", "oidc-backchannel-1_0"),
    ("Front-Channel Logout", "oidc-frontchannel-1_0"),
    ("Session Management", "oidc-session-1_0"),
    ("Message Signing", "fapi-2_0-message-signing"),
    ("Exclusive C14N", "xml-exc-c14n"),
    ("SAML Metadata", "saml-metadata-2.0-os"),
    ("SAML Bindings", "saml-bindings-2.0-os"),
    ("SAML Profiles", "saml-profiles-2.0-os"),
    ("SAML Core", "saml-core-2.0-os"),
    ("OIDC Core", "oidc-core-1_0"),
    ("WebAuthn", "webauthn-2"),
    ("FAPI 2.0", "fapi-2_0-security-profile"),
    ("FAPI", "fapi-2_0-security-profile"),
    ("JARM", "jarm"),
    ("CTAP2", "ctap-2.0-ps-20190130"),
    ("CTAP", "ctap-2.0-ps-20190130"),
];

/// Which specification a bare "§4.3" refers to, keyed by test-file stem.
fn file_default(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    if let Some(rest) = stem.strip_prefix("rfc") {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.len() >= 3 {
            return Some(format!("rfc{digits}"));
        }
    }
    let spec = match stem {
        s if s.starts_with("oidc_core") || s.starts_with("oidc_userinfo") => "oidc-core-1_0",
        s if s.starts_with("oidc_discovery") => "oidc-discovery-1_0",
        s if s.starts_with("fapi") => "fapi-2_0-security-profile",
        s if s.starts_with("jarm") => "jarm",
        s if s.starts_with("webauthn") => "webauthn-2",
        s if s.starts_with("scim") => "rfc7644",
        s if s.starts_with("saml") => "saml-core-2.0-os",
        _ => return None,
    };
    Some(spec.to_string())
}

/// Read a dotted section number at `start`, e.g. "4.3.1". Returns the number
/// and the byte offset just past it.
fn read_section(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut i = start;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    let begin = i;
    let mut saw_digit = false;
    while i < bytes.len() {
        match bytes[i] {
            b'0'..=b'9' => {
                saw_digit = true;
                i += 1;
            }
            // A dot continues the number only when a digit follows it, so the
            // full stop ending "RFC 9449 §5." is not swallowed.
            b'.' if saw_digit && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() => i += 1,
            _ => break,
        }
    }
    if !saw_digit {
        return None;
    }
    Some((text[begin..i].to_string(), i))
}

/// Find a section marker ("§" or "Section ") starting at `from`, within
/// `window` bytes. Returns the offset just past the marker.
fn section_marker(text: &str, from: usize, window: usize) -> Option<usize> {
    let mut end = text.len().min(from.saturating_add(window));
    while end > from && !text.is_char_boundary(end) {
        end -= 1;
    }
    let slice = text.get(from..end)?;
    // Stop at a newline: a citation does not span lines.
    let slice = slice.split('\n').next()?;
    let mut best: Option<usize> = None;
    for (idx, marker) in [(slice.find('§'), "§"), (slice.find("Section "), "Section ")]
        .into_iter()
        .filter_map(|(i, m)| i.map(|i| (i, m)))
    {
        let past = from + idx + marker.len();
        best = Some(best.map_or(past, |b: usize| b.min(past)));
    }
    best
}

/// Every (spec, section) pair cited in one chunk of test source.
fn citations(source: &str, default_spec: Option<&str>) -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();

    // "RFC 9449 §4.3" / "RFC 9449 Section 4.3", plus ", §5.2" continuations.
    let mut search = 0;
    while let Some(rel) = source[search..].find("RFC") {
        let at = search + rel;
        search = at + 3;
        let after = &source[search..];
        let after = after.strip_prefix(' ').unwrap_or(after);
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        if digits.len() < 3 || digits.len() > 4 {
            continue;
        }
        let spec = format!("rfc{digits}");
        let mut pos = source.len() - after.len() + digits.len();
        let Some(marker) = section_marker(source, pos, 14) else {
            continue;
        };
        let Some((section, past)) = read_section(source, marker) else {
            continue;
        };
        found.insert((spec.clone(), section));
        pos = past;
        // "RFC 9421 §4.1, §4.2" cites two sections against one RFC.
        loop {
            let rest = source[pos..].trim_start_matches([' ', '\t']);
            let Some(rest) = rest.strip_prefix(',') else {
                break;
            };
            let rest = rest.trim_start_matches([' ', '\t']);
            let Some(rest) = rest.strip_prefix('§') else {
                break;
            };
            let offset = source.len() - rest.len();
            let Some((section, past)) = read_section(source, offset) else {
                break;
            };
            found.insert((spec.clone(), section));
            pos = past;
        }
    }

    // Prose-named specifications.
    for (name, spec) in ALIASES {
        let mut search = 0;
        while let Some(rel) = source[search..].find(name) {
            let at = search + rel;
            search = at + name.len();
            if let Some((section, _)) =
                section_marker(source, search, 14).and_then(|marker| read_section(source, marker))
            {
                found.insert((spec.to_string(), section));
            }
        }
    }

    // A bare "§4.3" in a file whose name names the specification.
    if let Some(default_spec) = default_spec {
        let mut search = 0;
        while let Some(rel) = source[search..].find('§') {
            let past = search + rel + '§'.len_utf8();
            search = past;
            if let Some((section, _)) = read_section(source, past) {
                found.insert((default_spec.to_string(), section));
            }
        }
    }

    found
}

/// Slice out each test function, from any comment block above the attribute
/// through the closing brace of the body.
fn test_blocks(text: &str) -> Vec<&str> {
    let mut blocks = Vec::new();
    for attr in ["#[test]", "#[tokio::test]"] {
        let mut search = 0;
        while let Some(rel) = text[search..].find(attr) {
            let at = search + rel;
            search = at + attr.len();
            let Some(brace_rel) = text[search..].find('{') else {
                break;
            };
            let open = search + brace_rel;
            let mut depth = 0usize;
            let mut end = open;
            for (i, ch) in text[open..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let start = text[..at].rfind("\n\n").map_or(0, |i| i + 2);
            blocks.push(&text[start..end]);
        }
    }
    blocks
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn read_tsv(path: &Path) -> Vec<Vec<String>> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

struct Requirement {
    id: String,
    spec: String,
    section: String,
    strength: String,
    text: String,
}

fn load_requirements(root: &Path) -> Vec<Requirement> {
    let scope: BTreeMap<String, String> = read_tsv(&root.join("specs/audit-scope.tsv"))
        .into_iter()
        .skip(1)
        .filter(|r| r.len() >= 2)
        .map(|r| (r[0].clone(), r[1].clone()))
        .collect();

    read_tsv(&root.join("specs/requirements.tsv"))
        .into_iter()
        .skip(1)
        .filter(|r| r.len() >= 7)
        .filter(|r| scope.get(&r[1]).is_some_and(|s| s != "reference"))
        .map(|r| Requirement {
            id: r[0].clone(),
            spec: r[1].clone(),
            section: r[2].clone(),
            strength: r[3].clone(),
            text: r[6].clone(),
        })
        .collect()
}

fn cited_sections(root: &Path) -> BTreeSet<(String, String)> {
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    let mut cited = BTreeSet::new();
    for path in files {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        // This file explains the citation format using real citations, so
        // scanning it would let the gate credit itself.
        if path.file_name().is_some_and(|n| n == "spec_coverage.rs") {
            continue;
        }
        // "#[tokio::test]" does not contain the substring "#[test", so both
        // spellings have to be checked or every async test file is skipped.
        if !text.contains("#[test]") && !text.contains("#[tokio::test") {
            continue;
        }
        let default = file_default(&path);
        for block in test_blocks(&text) {
            cited.extend(citations(block, default.as_deref()));
        }
    }
    cited
}

/// A requirement is cited when a test names its section or a subsection of it.
/// Citing only an ancestor section is too weak to claim coverage.
fn is_cited(req: &Requirement, cited: &BTreeSet<(String, String)>) -> bool {
    if cited.contains(&(req.spec.clone(), req.section.clone())) {
        return true;
    }
    let prefix = format!("{}.", req.section);
    cited
        .iter()
        .any(|(spec, section)| *spec == req.spec && section.starts_with(&prefix))
}

#[test]
fn normative_coverage_does_not_regress() {
    let root = repo_root();
    let requirements = load_requirements(&root);
    assert!(
        requirements.len() > 4000,
        "requirements.tsv looks truncated: {} in-scope statements",
        requirements.len()
    );

    let cited = cited_sections(&root);
    let uncited: BTreeSet<String> = requirements
        .iter()
        .filter(|r| !is_cited(r, &cited))
        .map(|r| r.id.clone())
        .collect();

    let baseline_path = root.join("specs/coverage-baseline.tsv");

    if std::env::var("UPDATE_SPEC_COVERAGE_BASELINE").is_ok() {
        let by_id: BTreeMap<&str, &Requirement> =
            requirements.iter().map(|r| (r.id.as_str(), r)).collect();
        let mut out = String::from(
            "# Normative statements with no citing test: the accepted backlog.\n\
             # Regenerate: UPDATE_SPEC_COVERAGE_BASELINE=1 cargo test -p vouch-tests \
             --test spec_coverage\n\
             # This list may only shrink -- see crates/vouch-tests/tests/spec_coverage.rs.\n\
             req_id\tstrength\ttext\n",
        );
        for id in &uncited {
            let req = by_id[id.as_str()];
            let text: String = req.text.chars().take(160).collect();
            out.push_str(&format!(
                "{id}\t{}\t{}\n",
                req.strength,
                text.replace('\t', " ")
            ));
        }
        fs::write(&baseline_path, out).expect("write baseline");
        eprintln!(
            "wrote {} entries to specs/coverage-baseline.tsv",
            uncited.len()
        );
        return;
    }

    let baseline: BTreeSet<String> = read_tsv(&baseline_path)
        .into_iter()
        .skip(1)
        .filter_map(|r| r.first().cloned())
        .collect();

    let known: BTreeSet<String> = requirements.iter().map(|r| r.id.clone()).collect();
    let by_id: BTreeMap<&str, &Requirement> =
        requirements.iter().map(|r| (r.id.as_str(), r)).collect();

    let new_gaps: Vec<&String> = uncited.difference(&baseline).collect();
    let now_cited: Vec<&String> = baseline
        .difference(&uncited)
        .filter(|id| known.contains(*id))
        .collect();
    let vanished: Vec<&String> = baseline.iter().filter(|id| !known.contains(*id)).collect();

    let mut failures = String::new();

    if !new_gaps.is_empty() {
        failures.push_str(&format!(
            "\n{} normative statement(s) lost their citing test.\nAdd a test that names \
             the section, or cite the section from an existing test:\n",
            new_gaps.len()
        ));
        for id in new_gaps.iter().take(20) {
            let req = by_id[id.as_str()];
            let text: String = req.text.chars().take(110).collect();
            failures.push_str(&format!(
                "  {} §{} [{}] {}\n",
                req.spec, req.section, req.strength, text
            ));
        }
        if new_gaps.len() > 20 {
            failures.push_str(&format!("  ... and {} more\n", new_gaps.len() - 20));
        }
    }

    if !now_cited.is_empty() {
        failures.push_str(&format!(
            "\n{} baseline entr(y/ies) are now cited by a test. The backlog may only \
             shrink, so prune them:\n  UPDATE_SPEC_COVERAGE_BASELINE=1 cargo test -p \
             vouch-tests --test spec_coverage\n",
            now_cited.len()
        ));
    }

    if !vanished.is_empty() {
        failures.push_str(&format!(
            "\n{} baseline entr(y/ies) no longer exist in specs/requirements.tsv, so the \
             requirement text changed or the spec was re-cached. Regenerate the corpus and \
             the baseline:\n  scripts/audit-normative.py\n  \
             UPDATE_SPEC_COVERAGE_BASELINE=1 cargo test -p vouch-tests --test spec_coverage\n",
            vanished.len()
        ));
    }

    assert!(failures.is_empty(), "{failures}");
}
