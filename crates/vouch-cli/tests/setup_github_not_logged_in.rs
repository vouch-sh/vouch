// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Regression test for `vouch setup github` when the user is not logged in.
//!
//! The "not logged in" early-exit guard in `setup/github.rs` matches the typed
//! `CliError::NotAuthenticated` rather than a stale substring, so `--configure`
//! no longer writes the GitHub credential helper into the user's global
//! gitconfig for a logged-out user. This test drives the real `vouch` binary
//! in an isolated HOME (no config, no token, no agent socket) and asserts the
//! invariant end-to-end: nothing is written to gitconfig and the friendly
//! "Not logged in" block is shown.
//!
//! Unix-only, like the in-tree `git_executes_the_helper_command` test: on
//! Windows `dirs::home_dir()` ignores `HOME` (it asks `FOLDERID_Profile`),
//! so the startup `migrate_legacy_layout` could not be redirected away from
//! a developer's real `~/.vouch`. On Unix, `HOME` is honored, so the whole
//! process tree is safely isolated.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
// Own-crate items are imported with `use`; see `absolute-paths-allowed-crates`
// in `.clippy.toml`.
#![deny(clippy::absolute_paths)]

use std::process::Command;
use tempfile::TempDir;

/// The friendly early-exit block the fixed guard prints.
const NOT_LOGGED_IN: &str = "Login status: Not logged in";
/// The instruction line inside that block; `-cmd` resolves to `vouch`.
const LOGIN_INSTRUCTION: &str = "Run 'vouch login' first to authenticate";
/// The misleading success message the buggy path printed after writing gitconfig.
const GIT_CONFIGURED: &str = "Git configured for github.com";
/// The git config key that must NOT be written for a logged-out user.
const HELPER_KEY: &str = "credential.https://github.com.helper";

/// Run `vouch setup github --configure` with a fully isolated environment and
/// return the `TempDir` that backs it. The caller MUST hold the `TempDir` for
/// as long as the subprocess runs: when it drops, the `HOME` /
/// `XDG_CONFIG_HOME` / `XDG_RUNTIME_DIR` directories and the parent of the
/// gitconfig file are deleted out from under the child.
fn isolated_setup() -> (Command, std::path::PathBuf, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let config_home = dir.path().join("config");
    let runtime_dir = dir.path().join("run");
    let gitconfig = dir.path().join("gitconfig");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&config_home).unwrap();
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vouch"));
    cmd.arg("setup").arg("github").arg("--configure");
    // Isolate every directory vouch/git could touch. None of these leak to
    // other tests: they're set on the child only, not the current process.
    // `HOME` redirects both `dirs::home_dir()` (so the startup
    // `migrate_legacy_layout` finds no `~/.vouch`) and git's `~/.gitconfig`
    // fallback.
    cmd.env("HOME", &home);
    // Vouch config lives at `XDG_CONFIG_HOME/vouch/config.json`; an empty
    // dir here means no saved token, so `session::resolve_token` returns
    // `CliError::NotAuthenticated` without touching the network.
    cmd.env("XDG_CONFIG_HOME", &config_home);
    // The agent socket lives under `XDG_RUNTIME_DIR`; an empty dir here
    // means no agent, so `resolve_token` falls straight through to config.
    cmd.env("XDG_RUNTIME_DIR", &runtime_dir);
    // `git config --global` honors `GIT_CONFIG_GLOBAL` for both reads
    // (detect_existing_helper) and writes (set_global), so this single file
    // is the complete isolation boundary for gitconfig mutation.
    cmd.env("GIT_CONFIG_GLOBAL", &gitconfig);
    // Suppress any system-level git config (e.g. a distribution's
    // `credential.helper = osxkeychain`) so this test is reproducible.
    cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
    // No terminal: even if a code path fell through to prompting, fail
    // fast instead of hanging the test.
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    // Never inherit the developer's Vouch env: the default server is HTTPS,
    // so opt-in is irrelevant, but clearing it keeps the test reproducible
    // across machines.
    cmd.env_remove("VOUCH_SERVER");
    cmd.env_remove("VOUCH_ALLOW_INSECURE");
    cmd.env_remove("VOUCH_TOKEN");

    (cmd, gitconfig, dir)
}

/// True when `git` is on PATH. The buggy path's defining harm is mutating
/// gitconfig; without git the write simply fails (non-zero exit), so the
/// gitconfig assertion would be vacuous. Skip cleanly, matching the
/// convention in `git_config::tests::absent_key_and_pattern_return_nothing`.
fn git_is_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// `vouch setup github --configure` with no saved token must NOT write the
/// GitHub credential helper to the user's global gitconfig; it must print the
/// friendly "Not logged in" block and exit 0.
///
/// This guards the `setup/github.rs` early-exit invariant, which had no test
/// coverage before — the substring-based guard silently missed the common
/// logged-out path and let `--configure` fall through into the gitconfig
/// write. Holding the `TempDir` alive keeps the isolated gitconfig's parent
/// directory intact, so the buggy path's `set_global` would succeed and this
/// assertion catches the real harm rather than a vacuous failure.
#[test]
fn configure_does_not_write_gitconfig_when_not_logged_in() {
    if !git_is_available() {
        return;
    }

    // Hold `_dir` until after `cmd.output()` so the isolated dirs outlive
    // the subprocess (see `isolated_setup`).
    let (mut cmd, gitconfig, _dir) = isolated_setup();
    let output = cmd.output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "expected clean early-exit (exit 0), got status {:?}\n\
         stdout:\n{stdout}\n\
         stderr:\n{stderr}",
        output.status.code(),
    );

    // The friendly early-exit block is the user-facing fix.
    assert!(
        stdout.contains(NOT_LOGGED_IN),
        "expected the not-logged-in block in stdout, got:\n{stdout}"
    );
    assert!(
        stdout.contains(LOGIN_INSTRUCTION),
        "expected the 'Run vouch login first' instruction in stdout, got:\n{stdout}"
    );

    // The misleading success message only prints when the guard misses and
    // control falls through into the gitconfig write.
    assert!(
        !stdout.contains(GIT_CONFIGURED),
        "bug: 'Git configured for github.com' printed despite the user not \
         being logged in:\n{stdout}"
    );

    // The critical real-world harm: silent mutation of the global gitconfig
    // for a not-logged-in user. The helper key must not be present anywhere
    // in the isolated global config (whether or not the file was created).
    let cfg = std::fs::read_to_string(&gitconfig).unwrap_or_default();
    assert!(
        !cfg.contains(HELPER_KEY),
        "bug: credential helper was written to gitconfig for a not-logged-in \
         user:\n{cfg}"
    );
}
