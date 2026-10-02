// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Regression test for the cross-platform dispatch bug introduced in b2838ba8
//! (PR #66): `VOUCH_GIT_REMOTE_CODECOMMIT=1` was honored on every platform, so
//! any environment with it set hijacked the entire `vouch` CLI into the
//! CodeCommit remote-helper dispatch path — even `vouch --help` failed with a
//! `git-remote-codecommit <remote-name> <url>` usage error instead of printing
//! help. The env-var fallback is now gated to Windows, where the `.bat`
//! wrapper needs it (argv0 detection cannot see through a `.bat`).
//!
//! Drives the real `vouch` binary (`CARGO_BIN_EXE_vouch`) with the env var set
//! on the child only and in a fully isolated HOME/XDG environment, then asserts
//! a normal subcommand still reaches clap and succeeds end-to-end. Unix-only:
//! on Windows the variable is intentionally still honored so the `.bat` wrapper
//! can detect helper invocations, so the "must not hijack" assertions are gated
//! off there.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use std::process::Command;
use tempfile::TempDir;

/// Build a `vouch` `Command` whose `HOME` / `XDG_*` / `VOUCH_*` environment is
/// fully isolated to a tempdir, with `VOUCH_GIT_REMOTE_CODECOMMIT=1` set so the
/// regression guard is exercised. Isolation keeps config load and locale
/// resolution reproducible across machines. The `TempDir` MUST outlive the
/// subprocess: dropping it deletes the dirs out from under the child.
fn isolated_vouch(args: &[&str]) -> (Command, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let config_home = dir.path().join("config");
    let runtime_dir = dir.path().join("run");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&config_home).unwrap();
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vouch"));
    cmd.args(args);
    // dirs are set on the child only — none leak to other tests.
    cmd.env("HOME", &home);
    // Empty config dir => no saved token/config, so config load returns the
    // default without touching the network.
    cmd.env("XDG_CONFIG_HOME", &config_home);
    cmd.env("XDG_RUNTIME_DIR", &runtime_dir);
    // The bug under test: this must NOT trigger helper dispatch off-Windows.
    cmd.env("VOUCH_GIT_REMOTE_CODECOMMIT", "1");
    // Never inherit the developer's Vouch env; keeps the test reproducible.
    cmd.env_remove("VOUCH_SERVER");
    cmd.env_remove("VOUCH_ALLOW_INSECURE");
    cmd.env_remove("VOUCH_TOKEN");
    (cmd, dir)
}

/// `vouch --help` with `VOUCH_GIT_REMOTE_CODECOMMIT=1` set must not be hijacked
/// into the `git-remote-codecommit` remote-helper dispatch; it must reach clap,
/// print help to stdout, and exit 0. Before the fix the env var was read
/// unconditionally (ahead of clap parsing) and `--help` errored with a
/// remote-helper usage message and exit code 6.
#[test]
fn help_is_not_hijacked_by_remote_helper_env_var() {
    let (mut cmd, _dir) = isolated_vouch(&["--help"]);
    let output = cmd.output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "vouch --help with VOUCH_GIT_REMOTE_CODECOMMIT=1 must exit 0, got {:?}\n\
         stdout:\n{stdout}\n\
         stderr:\n{stderr}",
        output.status.code(),
    );
    assert!(
        stdout.contains("Usage:"),
        "vouch --help must print clap help to stdout, got:\n{stdout}"
    );
    assert!(
        !stderr.contains("git-remote-codecommit"),
        "remote-helper dispatch leaked into stderr:\n{stderr}"
    );
}

/// A two-token, remote-helper-shaped invocation must NOT be silently routed
/// into the CodeCommit helper merely because `VOUCH_GIT_REMOTE_CODECOMMIT=1`
/// is set on non-Windows. `vouch completions bash` is a normal, fully-local
/// subcommand; before the fix its `bash` operand was misread as a CodeCommit
/// URL and the command errored with exit 1 instead of printing completions.
#[test]
fn completions_not_hijacked_by_remote_helper_env_var() {
    let (mut cmd, _dir) = isolated_vouch(&["completions", "bash"]);
    let output = cmd.output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "vouch completions bash with VOUCH_GIT_REMOTE_CODECOMMIT=1 must exit 0, got {:?}\n\
         stdout:\n{stdout}\n\
         stderr:\n{stderr}",
        output.status.code(),
    );
    assert!(
        stdout.contains("vouch"),
        "vouch completions bash must print a completion script to stdout, got:\n{stdout}"
    );
    assert!(
        !stderr.contains("git-remote-codecommit"),
        "remote-helper dispatch leaked into stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("invalid CodeCommit URL"),
        "'bash' must not be parsed as a CodeCommit URL:\n{stderr}"
    );
}
