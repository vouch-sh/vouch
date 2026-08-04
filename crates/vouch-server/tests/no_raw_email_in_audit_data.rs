//! Registry-wide regression test: no audit event `data` payload embeds a
//! raw email address field.
//!
//! Every `AuditEventKind` write site builds its `data`/`details` JSON
//! either through a typed struct (`OAuthUsageData`, `CredentialAuditEnvelope`,
//! `ScimAuditData`, ...) — which has no email field, so it can't leak one —
//! or through an ad hoc `serde_json::json!({ ... })` literal at the call
//! site. The bug this guards against (found twice: `handlers/admin/members.rs`'s
//! `target_email`, `handlers/scim/users.rs`'s `"email"`) is exactly that ad
//! hoc shape embedding a raw address, which then gets re-exposed verbatim to
//! `audit:read` API consumers even though the docs promise emails are
//! masked to domain-only.
//!
//! Runtime coverage of every one of the ~40 registered kinds would need a
//! live flow per kind (login, credential issuance, SCIM, org domain
//! lifecycle, ...) — expensive and still incomplete for future kinds. A
//! source scan is the shape that actually generalizes: it holds for every
//! call site today and for any new one added later, not just the ones a
//! test happens to exercise.

#![allow(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use std::fs;
use std::path::{Path, PathBuf};

/// JSON-key names that legitimately contain "email" because they hold a
/// derived, non-address value the docs already document as safe to store:
/// the domain portion, or the HMAC correlation digest.
const ALLOWED_EMAIL_KEYS: &[&str] = &["email_domain", "email_hmac"];

#[test]
fn no_audit_data_payload_embeds_a_raw_email_field() {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_root, &mut files).expect("walk src/");
    files.sort();

    let mut violations = Vec::new();
    for path in &files {
        let content = fs::read_to_string(path).expect("read source file");
        let cutoff = test_module_cutoff(&content);
        let production = content.get(..cutoff).unwrap_or(&content);

        for (line, key) in email_like_json_keys(production) {
            if ALLOWED_EMAIL_KEYS.contains(&key.as_str()) {
                continue;
            }
            let rel = path.strip_prefix(&src_root).map_or_else(
                |_| path.to_string_lossy().into_owned(),
                |p| p.to_string_lossy().into_owned(),
            );
            violations.push(format!("src/{rel}:{line} JSON key {key:?}"));
        }
    }

    assert!(
        violations.is_empty(),
        "found {} JSON key(s) that look like a raw email field in an audit-adjacent \
         payload — embed the domain/HMAC instead, or resolve the address at display \
         time from an id already in the payload:\n{}",
        violations.len(),
        violations.join("\n")
    );
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

/// Every `"key":` occurrence in `content` where `key` (case-insensitively)
/// contains "email" — the shape of a JSON object key in a
/// `serde_json::json!` literal, wherever the value expression came from
/// (a literal, a variable, a field access — source scanning can't see the
/// runtime value, only that an email-shaped field was wired up at all).
fn email_like_json_keys(content: &str) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel_start) = content.get(search_from..).and_then(|s| s.find('"')) {
        let start = search_from.saturating_add(rel_start);
        let Some(rel_end) = content
            .get(start.saturating_add(1)..)
            .and_then(|s| s.find('"'))
        else {
            break;
        };
        let end = start.saturating_add(1).saturating_add(rel_end);
        let Some(key) = content.get(start.saturating_add(1)..end) else {
            break;
        };

        let is_identifier_like =
            !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let after = content.get(end.saturating_add(1)..).unwrap_or("");
        let followed_by_colon = after.trim_start().starts_with(':');

        if is_identifier_like && followed_by_colon && key.to_ascii_lowercase().contains("email") {
            hits.push((line_number(content, start), key.to_string()));
        }

        search_from = end.saturating_add(1);
    }
    hits
}

fn line_number(content: &str, offset: usize) -> usize {
    content
        .get(..offset)
        .map_or(1, |before| before.matches('\n').count().saturating_add(1))
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

    #[test]
    fn detects_a_raw_email_key() {
        let src = r#"let data = serde_json::json!({ "target_email": target.email });"#;
        let hits = email_like_json_keys(src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits.first().map(|(_, k)| k.as_str()), Some("target_email"));
    }

    #[test]
    fn allows_the_documented_domain_and_hmac_keys() {
        let src = r#"json!({ "email_domain": d, "email_hmac": h })"#;
        // The scanner itself doesn't filter by the allowlist (the caller
        // does); it just needs to find both keys so the caller can exercise
        // its own filtering.
        let hits = email_like_json_keys(src);
        let keys: Vec<&str> = hits.iter().map(|(_, k)| k.as_str()).collect();
        assert_eq!(keys, vec!["email_domain", "email_hmac"]);
    }

    #[test]
    fn ignores_non_key_positions() {
        // A quoted string that isn't followed by a colon isn't a JSON key.
        let src = r#"tracing::warn!("failed to resolve email for user")"#;
        assert!(email_like_json_keys(src).is_empty());
    }

    #[test]
    fn test_module_cutoff_excludes_trailing_test_mod() {
        let src = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    const X: &str = \"email\";\n}\n";
        let cutoff = test_module_cutoff(src);
        let production = src.get(..cutoff).expect("cutoff within bounds");
        assert!(!production.contains("mod tests"));
    }
}
