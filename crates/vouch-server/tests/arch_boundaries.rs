//! Architecture boundary test enforcing the direction-only layering contract.
//!
//! Contract (see CLAUDE.md "Layer boundaries"): within `src/`, the five layer
//! directories may only import from the layers listed here:
//!
//! ```text
//! handlers -> services, db, infra, crypto
//! services -> db, infra, crypto
//! db       -> crypto
//! infra    -> crypto
//! crypto   -> (no other layer)
//! ```
//!
//! `services -> infra` is allowed because infra hosts technical primitives
//! (SSRF guards, DNS, metrics, CSP types) that business logic legitimately
//! consumes; the forbidden direction is infra knowing about business logic.
//!
//! Crate-root modules (`lib.rs`, `main.rs`, `config.rs`, `geo.rs`, ...) are
//! shared glue and composition roots, not a layer; they are not scanned.
//! Test code is exempt: `#[cfg(test)]` modules, `db/tests.rs`,
//! `test_utils.rs`, `handlers/oidc/tests/`, and
//! `handlers/api/org/scim_tokens/tests.rs`.
//!
//! Deliberate deviations live in [`EXCEPTIONS`] with a reason. The list can
//! only shrink: an exception that no longer matches a real import fails the
//! test so stale entries cannot rot in place.

use std::fs;
use std::path::{Path, PathBuf};

const LAYERS: [&str; 5] = ["handlers", "services", "db", "infra", "crypto"];

fn allowed_targets(layer: &str) -> Option<&'static [&'static str]> {
    match layer {
        "handlers" => Some(&["services", "db", "infra", "crypto"]),
        "services" => Some(&["db", "infra", "crypto"]),
        "db" => Some(&["crypto"]),
        "infra" => Some(&["crypto"]),
        "crypto" => Some(&[]),
        _ => None,
    }
}

struct Exception {
    /// Path relative to `src/`, `/`-separated on all platforms.
    file: &'static str,
    /// The layer this file is allowed to import despite the matrix.
    target: &'static str,
    reason: &'static str,
}

const EXCEPTIONS: &[Exception] = &[
    // Composition roots and documented designs — expected to stay.
    Exception {
        file: "infra/router.rs",
        target: "handlers",
        reason: "composition root: mounts every handler route",
    },
    Exception {
        file: "infra/startup.rs",
        target: "services",
        reason: "composition root: boot-time wiring of services",
    },
    Exception {
        file: "infra/startup.rs",
        target: "db",
        reason: "composition root: boot-time pool setup and migrations",
    },
    Exception {
        file: "infra/cleanup.rs",
        target: "db",
        reason: "background-job runner sweeping expired documents",
    },
    Exception {
        file: "infra/httpsig.rs",
        target: "db",
        reason: "RFC 9421 key resolver reads OAuth client JWKS from storage",
    },
    Exception {
        file: "infra/jwks.rs",
        target: "db",
        reason: "owns the JWKS cache freshness rule, so it reads and writes \
                 the cache rows it decides are stale",
    },
    Exception {
        file: "infra/org_host.rs",
        target: "db",
        reason: "pure domain-label validation fn, no I/O",
    },
    Exception {
        file: "infra/security_headers.rs",
        target: "services",
        reason: "CSP form-action origins are derived from configured IdPs",
    },
    Exception {
        file: "db/par.rs",
        target: "services",
        reason: "PAR chokepoint takes ParCreationProof, a witness only \
                 constructible from services client-auth verification — the \
                 upward type reference is what makes the db write unforgeable",
    },
];

/// Files under `src/` that contain only test code and are skipped entirely.
const TEST_FILES: &[&str] = &[
    "db/tests.rs",
    "test_utils.rs",
    "handlers/api/org/scim_tokens/tests.rs",
];
const TEST_DIRS: &[&str] = &["handlers/oidc/tests/"];

#[test]
fn layer_imports_respect_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_root, &mut files)?;
    files.sort();

    let mut violations = Vec::new();
    let mut used_exceptions = vec![false; EXCEPTIONS.len()];

    for path in &files {
        let rel = relative_slash_path(path, &src_root)?;
        if TEST_FILES.contains(&rel.as_str()) || TEST_DIRS.iter().any(|dir| rel.starts_with(dir)) {
            continue;
        }
        let Some(layer) = rel.split('/').next().filter(|first| LAYERS.contains(first)) else {
            continue; // crate-root module: shared glue, not a layer
        };
        let Some(allowed) = allowed_targets(layer) else {
            continue;
        };

        let content = fs::read_to_string(path)?;
        let cutoff = test_module_cutoff(&content);
        let scannable = content.get(..cutoff).unwrap_or(&content);

        for (line, target) in layer_references(scannable) {
            if target == layer || allowed.contains(&target.as_str()) {
                continue;
            }
            let excepted = EXCEPTIONS
                .iter()
                .enumerate()
                .find_map(|(idx, ex)| (ex.file == rel && ex.target == target).then_some(idx));
            if let Some(idx) = excepted {
                if let Some(slot) = used_exceptions.get_mut(idx) {
                    *slot = true;
                }
                continue;
            }
            violations.push(format!(
                "src/{rel}:{line} imports crate::{target} — layer '{layer}' may only import {allowed:?}"
            ));
        }
    }

    for (idx, ex) in EXCEPTIONS.iter().enumerate() {
        if used_exceptions.get(idx) != Some(&true) {
            violations.push(format!(
                "stale exception: {} -> crate::{} ({}) no longer matches any import; remove it",
                ex.file, ex.target, ex.reason
            ));
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} layer-boundary violation(s):\n{}",
            violations.len(),
            violations.join("\n")
        )
        .into())
    }
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
    let rel = path.strip_prefix(root)?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    Ok(parts.join("/"))
}

/// Byte offset where the trailing `#[cfg(test)] mod ...` section begins, or
/// the full length when the file has none. Test modules are file-final by
/// convention in this codebase.
fn test_module_cutoff(content: &str) -> usize {
    let mut offset = 0usize;
    let mut pending: Option<usize> = None;
    let mut attr_depth = 0usize;
    for line in content.split_inclusive('\n') {
        let trimmed = line.trim();
        if pending.is_some() && attr_depth > 0 {
            // Inside a multi-line attribute (e.g. #[expect(...)]) between
            // #[cfg(test)] and the mod declaration.
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

/// Every `(line_number, layer)` referenced as `crate::<layer>` in `content`,
/// covering plain paths, `use` statements, and `use crate::{...}` groups.
/// Comment-only lines are ignored.
fn layer_references(content: &str) -> Vec<(usize, String)> {
    let mut refs = Vec::new();
    for (idx, _) in content.match_indices("crate::") {
        // Reject `$crate::` (macro bodies) and identifiers ending in `crate`.
        let preceded_by_ident = content
            .get(..idx)
            .and_then(|before| before.chars().next_back())
            .is_some_and(|ch| ch == '$' || ch.is_alphanumeric() || ch == '_');
        if preceded_by_ident || line_is_comment(content, idx) {
            continue;
        }
        let Some(after) = content.get(idx.saturating_add("crate::".len())..) else {
            continue;
        };
        let line = line_number(content, idx);
        if after.starts_with('{') {
            for ident in brace_group_idents(after) {
                if LAYERS.contains(&ident.as_str()) {
                    refs.push((line, ident));
                }
            }
        } else {
            let ident: String = after
                .chars()
                .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
                .collect();
            if LAYERS.contains(&ident.as_str()) {
                refs.push((line, ident));
            }
        }
    }
    refs
}

fn line_is_comment(content: &str, offset: usize) -> bool {
    let line_start = content
        .get(..offset)
        .and_then(|before| before.rfind('\n').map(|pos| pos.saturating_add(1)))
        .unwrap_or(0);
    content
        .get(line_start..offset)
        .is_some_and(|prefix| prefix.trim_start().starts_with("//"))
}

fn line_number(content: &str, offset: usize) -> usize {
    content
        .get(..offset)
        .map_or(1, |before| before.matches('\n').count().saturating_add(1))
}

/// Identifier tokens inside a balanced `{...}` group starting at `group`
/// (whose first char is `{`). Tokens are whole identifiers, so a layer name
/// only matches an exact path segment.
fn brace_group_idents(group: &str) -> Vec<String> {
    let mut idents = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    for ch in group.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            current.push(ch);
            continue;
        }
        if !current.is_empty() {
            idents.push(std::mem::take(&mut current));
        }
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    idents
}

/// Credential handlers that legitimately run without proof of key possession.
///
/// Everything else in `handlers/credentials.rs` must take a
/// `HardwareVerifiedToken`. The list is deny-by-default on purpose: a new
/// credential endpoint fails this test until it either takes the strong token
/// or is named here, which puts the decision in front of a reviewer instead of
/// leaving it to a check someone remembered to write.
const CREDENTIAL_HANDLERS_WITHOUT_HARDWARE: &[(&str, &str)] = &[
    (
        "get_ssh_ca_public_key",
        "publishes the CA public key, unauthenticated",
    ),
    (
        "get_ssh_krl",
        "publishes the revocation list, unauthenticated",
    ),
    (
        "check_ssh_revocation",
        "revocation lookup by serial, unauthenticated",
    ),
    (
        "get_github_status",
        "reports whether the org has GitHub connected; issues no credential",
    ),
];

/// Every credential-issuing handler proves key possession through its type.
///
/// Requiring the type rather than a call means an endpoint cannot issue
/// credentials while silently omitting the check: the proof is part of the
/// signature, so a handler that wants the weaker token has to name it.
#[test]
fn credential_handlers_require_hardware_verified_token() -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers/credentials.rs");
    let content = fs::read_to_string(&path)?;
    let cutoff = test_module_cutoff(&content);
    let scannable = content.get(..cutoff).unwrap_or(&content);

    let mut violations = Vec::new();
    let mut used_exemptions = vec![false; CREDENTIAL_HANDLERS_WITHOUT_HARDWARE.len()];

    let mut rest = scannable;
    while let Some(pos) = rest.find("pub(crate) async fn ") {
        let after = rest
            .get(pos.saturating_add("pub(crate) async fn ".len())..)
            .unwrap_or("");
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        // Parameter list ends at the return arrow.
        let params = after.split("->").next().unwrap_or("");

        if let Some(idx) = CREDENTIAL_HANDLERS_WITHOUT_HARDWARE
            .iter()
            .position(|(exempt, _)| *exempt == name)
        {
            if let Some(flag) = used_exemptions.get_mut(idx) {
                *flag = true;
            }
            if params.contains("HardwareVerifiedToken") {
                violations.push(format!(
                    "{name} is listed as not needing hardware verification but takes \
                     HardwareVerifiedToken — remove it from the exemption list"
                ));
            }
        } else if !params.contains("HardwareVerifiedToken") {
            violations.push(format!(
                "{name} issues credentials but does not take HardwareVerifiedToken; \
                 add the extractor, or list it in CREDENTIAL_HANDLERS_WITHOUT_HARDWARE \
                 with a reason if it genuinely issues nothing"
            ));
        }

        rest = after;
    }

    for (idx, (name, reason)) in CREDENTIAL_HANDLERS_WITHOUT_HARDWARE.iter().enumerate() {
        if !used_exemptions.get(idx).copied().unwrap_or(false) {
            violations.push(format!(
                "stale exemption: handler '{name}' ({reason}) no longer exists"
            ));
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} credential-handler violation(s):\n{}",
            violations.len(),
            violations.join("\n")
        )
        .into())
    }
}
