// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Global git config access via the `git config --global` subprocess.
//!
//! vouch never parses git config in Rust — it only writes credential-helper
//! keys or reads a handful back to detect conflicts. `git config --global` is
//! authoritative: it honors `GIT_CONFIG_GLOBAL`, selects correctly between
//! `~/.gitconfig` and `~/.config/git/config`, and handles includes/locking.
//! This module is the single audited place vouch shells out to `git config`.

use anyhow::Result;
use std::process::{Command, Output};

/// Run `git config --global <args...>` and capture its output.
fn run(args: &[&str]) -> std::io::Result<Output> {
    Command::new("git")
        .args(["config", "--global"])
        .args(args)
        .output()
}

/// Set a key in the user's global git config.
///
/// Returns `Ok(true)` on success, `Ok(false)` when git ran but exited non-zero,
/// and `Err` only when git could not be spawned. Callers attach their own
/// translated context and map a `false` result to the appropriate `CliError`.
pub(crate) fn set_global(key: &str, value: &str) -> Result<bool> {
    Ok(run(&[key, value])?.status.success())
}

/// Read a single value from the global git config (`--get`).
///
/// Returns `None` when the key is unset, empty, or git is unavailable — all of
/// which the callers treat identically as "not configured".
pub(crate) fn get_global(key: &str) -> Option<String> {
    let out = run(&["--get", key]).ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// Read matching `key value` lines from the global git config (`--get-regexp`).
///
/// Returns an empty `Vec` when nothing matches or git is unavailable. Kept
/// alongside [`set_global`]/[`get_global`] so every `git config` invocation
/// flows through this module, even though it has a single caller today.
pub(crate) fn get_regexp_global(pattern: &str) -> Vec<String> {
    let Some(out) = run(&["--get-regexp", pattern])
        .ok()
        .filter(|o| o.status.success())
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic key/pattern that cannot exist in any real global config, so
    /// these reads are deterministic and mutate nothing.
    const ABSENT_KEY: &str = "credential.https://vouch-selftest.invalid.helper";
    const ABSENT_PATTERN: &str = r"credential\.vouch-selftest\.invalid\.helper";

    /// An unset key returns `None` (not `Some("")`) and a non-matching pattern
    /// returns an empty `Vec` — the module's "not configured" contract.
    ///
    /// The write round-trip cannot be unit-tested in-process: redirecting
    /// `--global` needs `GIT_CONFIG_GLOBAL` in the process environment, and
    /// `std::env::set_var` requires an `unsafe` block that the workspace denies.
    /// It is covered by the live verification steps for `vouch setup github`.
    #[test]
    fn absent_key_and_pattern_return_nothing() {
        // Skip cleanly if git is unavailable (e.g. minimal CI images).
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }

        assert!(get_global(ABSENT_KEY).is_none());
        assert!(get_regexp_global(ABSENT_PATTERN).is_empty());
    }
}
