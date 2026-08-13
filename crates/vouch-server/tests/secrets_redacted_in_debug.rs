//! Workspace-wide regression test: no struct that derives `Debug` holds a
//! plaintext credential in a bare `String`.
//!
//! A derived `Debug` prints every field verbatim, so any `{:?}` of such a
//! struct — a `tracing` field, an `anyhow` context, a test failure message —
//! writes the live credential into the log. The convention in this workspace
//! is a hand-written `impl Debug` that prints `[REDACTED]` for the secret
//! fields and leaves the rest visible (see `AuthCodeExchangeResult` in
//! `services/oidc/token.rs`), rather than `SecretString`, so the response
//! types keep their plain `String` fields for serde.
//!
//! Detection is by field name and type: a field whose name ends in `_token`,
//! `_secret`, or `_token_hint` (or is exactly `token`/`secret`) and whose
//! type is `String` or `Option<String>`. Suffix matching is what makes
//! `token_type`, `token_endpoint_auth_method`, and
//! `id_token_signing_alg_values_supported` non-matches; a field already
//! wrapped in `SecretString`/`Zeroizing` is a non-match because its type is
//! not a bare `String`.
//!
//! The scan covers every crate's `src/`, not just this one: the same response
//! and config types live in `vouch-cli` and `vouch-agent`. Runtime coverage
//! is not an option here — the leak only happens on the log line nobody
//! wrote yet, so the property has to hold for every type, including the ones
//! added tomorrow.
//!
//! Known limitation: each file is scanned only up to its first
//! `#[cfg(test)] mod tests`, so a type declared *after* a trailing test
//! module is not covered. Stopping there is deliberate — test fixtures hold
//! throwaway credentials and would otherwise all be flagged — and it holds
//! because test modules are file-final by convention here. Production items
//! belong above the test module.

#![allow(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use std::fs;
use std::path::{Path, PathBuf};

/// Substrings marking a field that holds a derived, non-recoverable value
/// rather than the credential itself, so printing it leaks nothing.
const DERIVED_VALUE_MARKERS: &[&str] = &["hash", "digest", "thumbprint", "fingerprint"];

/// `(struct, field)` pairs whose name matches the secret pattern but whose
/// value is not a credential. Each entry needs a reason; keep the list short.
const ALLOWED: &[(&str, &str, &str)] = &[];

#[test]
fn no_debug_derive_prints_a_plaintext_credential() {
    let crates_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ is the parent of this crate")
        .to_path_buf();

    let mut files = Vec::new();
    for entry in fs::read_dir(&crates_root).expect("read crates/") {
        let src = entry.expect("crates/ entry").path().join("src");
        if src.is_dir() {
            collect_rs_files(&src, &mut files).expect("walk src/");
        }
    }
    files.sort();
    assert!(
        !files.is_empty(),
        "found no sources to scan under crates/*/src"
    );

    let mut violations = Vec::new();
    for path in &files {
        // Standalone test files (`foo/tests.rs`, `foo/tests/*.rs`) are entirely
        // test code, which never reaches a production log.
        let in_tests_dir = path
            .parent()
            .and_then(|d| d.file_name())
            .is_some_and(|d| d == "tests");
        if path.file_name().is_some_and(|f| f == "tests.rs") || in_tests_dir {
            continue;
        }

        let content = fs::read_to_string(path).expect("read source file");
        let cutoff = test_module_cutoff(&content);
        let production = content.get(..cutoff).unwrap_or(&content);

        for hit in debug_derived_secret_fields(production) {
            if ALLOWED
                .iter()
                .any(|(s, f, _)| *s == hit.struct_name && *f == hit.field)
            {
                continue;
            }
            let rel = path.strip_prefix(&crates_root).map_or_else(
                |_| path.to_string_lossy().into_owned(),
                |p| p.to_string_lossy().into_owned(),
            );
            violations.push(format!(
                "{rel}:{} {}.{}: {}",
                hit.line, hit.struct_name, hit.field, hit.ty
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "found {} field(s) holding a plaintext credential in a struct that derives \
         Debug — replace the derive with an `impl Debug` printing \"[REDACTED]\" for \
         these fields and leaving the others visible:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// A secret-looking field on a `Debug`-deriving struct.
struct SecretField {
    line: usize,
    struct_name: String,
    field: String,
    ty: String,
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

/// Every secret-named `String`/`Option<String>` field declared in a struct
/// whose attribute block derives `Debug`.
///
/// Attributes are accumulated across lines (a `#[derive(` list may wrap) and
/// carried over intervening doc comments, then consumed by the next item
/// declaration. Tuple and unit structs have no field names to match, so only
/// brace-bodied structs are walked.
fn debug_derived_secret_fields(content: &str) -> Vec<SecretField> {
    let mut hits = Vec::new();
    let mut attrs = String::new();
    let mut attr_depth = 0usize;
    let mut current: Option<(String, usize)> = None;
    let mut brace_depth = 0usize;

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        let line_no = index.saturating_add(1);

        if let Some((struct_name, _)) = current.as_ref() {
            if brace_depth == 1
                && let Some((field, ty)) = parse_field(trimmed)
                && is_secret_field_name(&field)
                && is_bare_string(&ty)
            {
                hits.push(SecretField {
                    line: line_no,
                    struct_name: struct_name.clone(),
                    field,
                    ty,
                });
            }
            brace_depth = brace_depth
                .saturating_add(trimmed.matches('{').count())
                .saturating_sub(trimmed.matches('}').count());
            if brace_depth == 0 {
                current = None;
            }
            continue;
        }

        if attr_depth > 0 {
            attrs.push_str(trimmed);
            attr_depth = bracket_depth(attr_depth, trimmed);
            continue;
        }
        if trimmed.starts_with("#[") {
            attrs.push_str(trimmed);
            attr_depth = bracket_depth(0, trimmed);
            continue;
        }
        // Doc comments sit between the derive and the item; they neither add
        // to nor clear the pending attribute block.
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        if let Some(name) = struct_header_name(trimmed)
            && derives_debug(&attrs)
            && trimmed.contains('{')
        {
            current = Some((name, line_no));
            brace_depth = trimmed
                .matches('{')
                .count()
                .saturating_sub(trimmed.matches('}').count());
            if brace_depth == 0 {
                current = None;
            }
        }
        attrs.clear();
    }

    hits
}

/// The struct name in a declaration line, stripped of visibility, generics,
/// and the opening brace or paren.
fn struct_header_name(trimmed: &str) -> Option<String> {
    let rest = trimmed
        .strip_prefix("pub ")
        .or_else(|| trimmed.strip_prefix("pub(crate) "))
        .or_else(|| trimmed.strip_prefix("pub(super) "))
        .unwrap_or(trimmed);
    let rest = rest.strip_prefix("struct ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() { None } else { Some(name) }
}

/// Whether an accumulated attribute block contains a `derive` naming `Debug`.
fn derives_debug(attrs: &str) -> bool {
    let Some(start) = attrs.find("derive(") else {
        return false;
    };
    let list = attrs.get(start..).unwrap_or("");
    list.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|token| token == "Debug")
}

/// The `(name, type)` of a `name: Type,` field declaration.
fn parse_field(trimmed: &str) -> Option<(String, String)> {
    let rest = trimmed
        .strip_prefix("pub ")
        .or_else(|| trimmed.strip_prefix("pub(crate) "))
        .or_else(|| trimmed.strip_prefix("pub(super) "))
        .unwrap_or(trimmed);
    let colon = rest.find(':')?;
    let name = rest.get(..colon)?.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let ty = rest
        .get(colon.saturating_add(1)..)?
        .trim()
        .trim_end_matches(',')
        .trim();
    if ty.is_empty() {
        return None;
    }
    Some((name.to_string(), ty.to_string()))
}

/// Whether a field name names a live credential rather than a derived value.
fn is_secret_field_name(name: &str) -> bool {
    if DERIVED_VALUE_MARKERS.iter().any(|m| name.contains(m)) {
        return false;
    }
    name == "token"
        || name == "secret"
        || name.ends_with("_token")
        || name.ends_with("_secret")
        || name.ends_with("_token_hint")
}

/// Whether a type prints its contents under `Debug` — as opposed to
/// `SecretString`, `Zeroizing`, or any other redacting wrapper.
fn is_bare_string(ty: &str) -> bool {
    ty == "String" || ty == "Option<String>"
}

/// Byte offset where the trailing `#[cfg(test)] mod ...` section begins, or
/// the full length when the file has none. Test modules are file-final by
/// convention in this codebase. Mirrors `arch_boundaries.rs`'s helper of
/// the same name — duplicated rather than shared, since integration test
/// binaries in `tests/` can't import each other's private items.
fn test_module_cutoff(content: &str) -> usize {
    let mut offset = 0usize;
    let mut pending: Option<usize> = None;
    let mut attr_depth = 0usize;
    for line in content.split_inclusive('\n') {
        let trimmed = line.trim();
        if pending.is_some() && attr_depth > 0 {
            attr_depth = bracket_depth(attr_depth, trimmed);
        } else if trimmed == "#[cfg(test)]" {
            pending.get_or_insert(offset);
        } else if trimmed.starts_with("#[cfg(test)]") && trimmed.contains("mod ") {
            return offset;
        } else if let Some(start) = pending {
            if trimmed.starts_with("mod ")
                || trimmed.starts_with("pub mod ")
                || trimmed.starts_with("pub(crate) mod ")
            {
                return start;
            }
            if trimmed.starts_with("#[") {
                attr_depth = bracket_depth(0, trimmed);
            } else if !trimmed.is_empty() {
                pending = None;
            }
        }
        offset = offset.saturating_add(line.len());
    }
    content.len()
}

/// Running `[`/`]` nesting depth after processing `line`, starting at `depth`.
fn bracket_depth(depth: usize, line: &str) -> usize {
    let opens = line.matches('[').count();
    let closes = line.matches(']').count();
    depth.saturating_add(opens).saturating_sub(closes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(src: &str) -> Vec<String> {
        debug_derived_secret_fields(src)
            .into_iter()
            .map(|h| format!("{}.{}", h.struct_name, h.field))
            .collect()
    }

    #[test]
    fn flags_a_plaintext_token_on_a_debug_deriving_struct() {
        let src = "#[derive(Debug, Serialize)]\npub struct R {\n    pub access_token: String,\n    pub expires_in: u64,\n}\n";
        assert_eq!(names(src), vec!["R.access_token"]);
    }

    #[test]
    fn flags_an_optional_secret_and_reports_its_line() {
        let src = "#[derive(Debug)]\nstruct C {\n    id: String,\n    client_secret: Option<String>,\n}\n";
        let hits = debug_derived_secret_fields(src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits.first().map(|h| h.line), Some(4));
    }

    #[test]
    fn ignores_a_struct_without_a_debug_derive() {
        let src = "#[derive(Serialize)]\npub struct R {\n    pub access_token: String,\n}\n";
        assert!(names(src).is_empty());
    }

    #[test]
    fn finds_debug_in_a_wrapped_derive_list() {
        let src = "#[derive(\n    Clone,\n    Debug,\n)]\nstruct R {\n    token: String,\n}\n";
        assert_eq!(names(src), vec!["R.token"]);
    }

    #[test]
    fn carries_the_derive_across_doc_comments() {
        let src = "#[derive(Debug)]\n/// Doc.\n///\n/// More.\nstruct R {\n    token: String,\n}\n";
        assert_eq!(names(src), vec!["R.token"]);
    }

    #[test]
    fn ignores_redacting_wrapper_types() {
        let src = "#[derive(Debug)]\nstruct R {\n    client_secret: SecretString,\n    refresh_token: Option<SecretString>,\n    id_token: Zeroizing<String>,\n}\n";
        assert!(names(src).is_empty());
    }

    #[test]
    fn ignores_metadata_and_derived_value_fields() {
        let src = "#[derive(Debug)]\nstruct R {\n    token_type: String,\n    token_endpoint_auth_method: String,\n    id_token_signing_alg_values_supported: String,\n    refresh_token_hash: String,\n    hashed_secret: String,\n    token_id: String,\n}\n";
        assert!(names(src).is_empty());
    }

    #[test]
    fn attributes_do_not_leak_to_the_next_item() {
        let src = "#[derive(Debug)]\nstruct A {\n    ok: u8,\n}\n\nstruct B {\n    access_token: String,\n}\n";
        assert!(names(src).is_empty());
    }

    #[test]
    fn ignores_a_tuple_struct_with_no_named_fields() {
        let src =
            "#[derive(Debug)]\nstruct Token(String);\n\nstruct Other {\n    secret: String,\n}\n";
        assert!(names(src).is_empty());
    }

    #[test]
    fn test_module_cutoff_excludes_trailing_test_mod() {
        let src = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[derive(Debug)]\n    struct R {\n        token: String,\n    }\n}\n";
        let cutoff = test_module_cutoff(src);
        let production = src.get(..cutoff).expect("cutoff within bounds");
        assert!(debug_derived_secret_fields(production).is_empty());
    }
}
