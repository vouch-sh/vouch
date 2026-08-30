// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Ratchet keeping outbound response bodies bounded.
//!
//! `reqwest`'s body accessors — `bytes`, `text`, `text_with_charset`, `json`,
//! and the `bytes_stream` collector — all read a whole response into memory
//! with no cap. A remote host therefore decides how much this process
//! allocates, and a `Content-Length` check written before one of them does not
//! change that: `content_length()` is `None` under `Transfer-Encoding:
//! chunked`, so the check is skipped and the body lands in memory before any
//! size check can reject it. That is issue #1105, and it was reachable at more
//! than one call site.
//!
//! So `infra::egress` is the only place allowed to await one of those
//! accessors. Everything else goes through its capped readers, which stream the
//! body and abort once the running length crosses a caller-supplied limit.
//!
//! Deliberate deviations live in [`EXCEPTIONS`] with a reason. The list is
//! currently empty and can only shrink: an exception that no longer matches a
//! real call fails the test, so a stale entry cannot rot in place.

use std::fs;
use std::path::{Path, PathBuf};

/// Body accessors that read without a cap, matched after whitespace removal.
///
/// `.json(&body)` on a `RequestBuilder` sets a *request* body and takes an
/// argument, so the empty-parens and turbofish forms here only match reads.
const UNCAPPED_ACCESSORS: &[&str] = &[
    ".bytes().await",
    ".text().await",
    ".text_with_charset(",
    ".json().await",
    ".json::<",
    ".bytes_stream()",
];

/// The one module allowed to call them, relative to `src/`.
const EGRESS_MODULE: &str = "infra/egress.rs";

struct Exception {
    /// Path relative to `src/`, `/`-separated on all platforms.
    file: &'static str,
    /// The accessor this file is allowed to await despite the rule.
    accessor: &'static str,
    reason: &'static str,
}

const EXCEPTIONS: &[Exception] = &[];

#[test]
fn outbound_bodies_are_read_through_egress() -> Result<(), Box<dyn std::error::Error>> {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_root, &mut files)?;
    files.sort();

    let mut violations = Vec::new();
    let mut used_exceptions = vec![false; EXCEPTIONS.len()];

    for path in &files {
        let rel = relative_slash_path(path, &src_root)?;
        if rel == EGRESS_MODULE {
            continue;
        }

        let content = fs::read_to_string(path)?;
        // Production code only: an accessor inside a `#[cfg(test)]` module is
        // driving a fixture, not reading an attacker's response.
        let production = content.get(..test_module_cutoff(&content)).unwrap_or("");
        let code = strip_comments_and_whitespace(production);

        for accessor in UNCAPPED_ACCESSORS {
            if !code.text.contains(accessor) {
                continue;
            }
            if let Some(idx) = EXCEPTIONS
                .iter()
                .position(|ex| ex.file == rel && ex.accessor == *accessor)
            {
                if let Some(slot) = used_exceptions.get_mut(idx) {
                    *slot = true;
                }
                continue;
            }
            let line = code.line_of(accessor).unwrap_or(0);
            violations.push(format!(
                "{rel}:{line}: `{accessor}` reads the whole body with no cap; \
                 use crate::infra::egress::read_capped_{{bytes,text,json}} instead"
            ));
        }
    }

    for (idx, ex) in EXCEPTIONS.iter().enumerate() {
        if !used_exceptions.get(idx).copied().unwrap_or(false) {
            violations.push(format!(
                "stale exception: {} -> `{}` ({}) no longer matches any call; remove it",
                ex.file, ex.accessor, ex.reason
            ));
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} uncapped response body read(s) — use crate::infra::egress:\n{}",
            violations.len(),
            violations.join("\n")
        )
        .into())
    }
}

/// Source with comment lines dropped and all whitespace removed, keeping a
/// mapping back to original line numbers.
///
/// Whitespace removal is what lets one pattern match both `.json().await` and
/// the rustfmt-wrapped form where `.json()` and `.await` land on separate
/// lines. Comment lines are dropped first so that prose *describing* an
/// uncapped read — of which this repo now has several — does not register as
/// one.
struct Code {
    text: String,
    /// `lines[i]` is the original 1-based line of `text`'s `i`-th byte.
    lines: Vec<usize>,
}

impl Code {
    /// The original line number where `needle` starts, if present.
    fn line_of(&self, needle: &str) -> Option<usize> {
        let idx = self.text.find(needle)?;
        self.lines.get(idx).copied()
    }
}

fn strip_comments_and_whitespace(content: &str) -> Code {
    let mut text = String::new();
    let mut lines = Vec::new();
    for (offset, line) in content.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let number = offset.saturating_add(1);
        for ch in line.chars().filter(|ch| !ch.is_whitespace()) {
            text.push(ch);
            for _ in 0..ch.len_utf8() {
                lines.push(number);
            }
        }
    }
    Code { text, lines }
}

/// Byte offset where the file's trailing `#[cfg(test)]` module begins, or the
/// full length when there is none.
fn test_module_cutoff(content: &str) -> usize {
    let mut offset = 0usize;
    let mut pending: Option<usize> = None;
    for line in content.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed == "#[cfg(test)]" {
            pending.get_or_insert(offset);
        } else if let Some(start) = pending {
            if trimmed.starts_with("mod ")
                || trimmed.starts_with("pub mod ")
                || trimmed.starts_with("pub(crate) mod ")
            {
                return start;
            }
            if !trimmed.starts_with("#[") && !trimmed.is_empty() {
                pending = None;
            }
        }
        offset = offset.saturating_add(line.len());
    }
    content.len()
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn relative_slash_path(path: &Path, root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    Ok(path
        .strip_prefix(root)?
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/"))
}

/// The ratchet must actually fire — a rule that cannot fail is not a rule.
#[test]
fn ratchet_detects_an_uncapped_read() {
    let sample =
        "async fn f(r: reqwest::Response) {\n    let b = r\n        .bytes()\n        .await;\n}\n";
    let code = strip_comments_and_whitespace(sample);
    assert!(
        code.text.contains(".bytes().await"),
        "a wrapped `.bytes()`/`.await` pair must match after whitespace removal"
    );
    assert_eq!(
        code.line_of(".bytes().await"),
        Some(3),
        "the report must point at the line the accessor starts on"
    );
}

/// Prose describing the bug must not be mistaken for the bug.
#[test]
fn ratchet_ignores_comments_and_test_modules() {
    let commented = "// `response.bytes().await` buffers the whole body.\nfn f() {}\n";
    assert!(
        !strip_comments_and_whitespace(commented)
            .text
            .contains(".bytes().await"),
        "a comment mentioning an uncapped read must not count as one"
    );

    let with_tests = "fn f() {}\n\n#[cfg(test)]\nmod tests {\n    async fn t(r: reqwest::Response) { r.bytes().await; }\n}\n";
    let cutoff = test_module_cutoff(with_tests);
    assert!(
        !with_tests
            .get(..cutoff)
            .unwrap_or("")
            .contains(".bytes().await"),
        "test-module fixtures are outside the scanned region"
    );
}
