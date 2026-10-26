// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Regression test for offline commands aborting on a malformed server URL.
//!
//! `vouch` resolves and validates the server URL once in `run()` before
//! dispatching any subcommand. Before the fix, URL *syntax* validation ran
//! unconditionally, so purely local commands that never contact the server
//! (`vouch init`, `vouch completions`, `vouch posture`) aborted with
//! `Error: invalid server URL: relative URL without a base` when the configured
//! server URL was unparseable — the common typo of dropping the `https://`
//! scheme from `--server`/`VOUCH_SERVER`/config `server_url`.
//!
//! These tests drive the real `vouch` binary in a fully isolated HOME/XDG
//! environment, supplying the malformed server URL both via `VOUCH_SERVER` and
//! via a hand-edited `config.json` (whose nested `servers.<host>.server_url`
//! reaches `ServerUrl::parse` untouched — unlike the legacy flat field, which
//! the migration silently discards when it cannot be parsed into a hostname).
//! Each offline command must exit 0 and emit its output; a server-using
//! command (`doctor`) must still fail on the same malformed URL. Unix-only:
//! matches the repo's XDG-isolation test convention.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

/// The malformed server URL: a scheme-less (unparseable) value, the natural
/// typo of dropping `https://` from `VOUCH_SERVER=https://auth.internal`.
/// `url::Url::parse` rejects it as "relative URL without a base".
const MALFORMED_SERVER_URL: &str = "auth.internal";

/// A `config.json` whose nested `servers.bad.server_url` is unparseable, with
/// `current_server` pointing at it. `From<ConfigFile> for Config` stores nested
/// entries verbatim (no validation), so this reaches `ServerUrl::parse`.
const MALFORMED_CONFIG_JSON: &str =
    r#"{"current_server":"bad","servers":{"bad":{"server_url":"auth.internal"}}}"#;

/// Build a `vouch` `Command` whose `HOME` / `XDG_*` / `VOUCH_*` environment is
/// fully isolated to a tempdir. The `TempDir` MUST outlive the subprocess:
/// dropping it deletes the dirs out from under the child.
fn isolated_vouch(args: &[&str]) -> (Command, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let config_home = dir.path().join("config");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&config_home).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vouch"));
    cmd.args(args);
    cmd.env("HOME", &home);
    cmd.env("XDG_CONFIG_HOME", &config_home);
    cmd.env("XDG_DATA_HOME", dir.path().join("data"));
    cmd.env("XDG_CACHE_HOME", dir.path().join("cache"));
    cmd.env("XDG_STATE_HOME", dir.path().join("state"));
    cmd.env("XDG_RUNTIME_DIR", dir.path().join("run"));
    // Never inherit the developer's Vouch env; keeps the test reproducible.
    cmd.env_remove("VOUCH_SERVER");
    cmd.env_remove("VOUCH_ALLOW_INSECURE");
    cmd.env_remove("VOUCH_TOKEN");
    (cmd, dir)
}

/// Write a Vouch `config.json` into `<config_home>/vouch/`.
fn write_config(config_home: &Path, json: &str) {
    let vouch_dir = config_home.join("vouch");
    std::fs::create_dir_all(&vouch_dir).unwrap();
    std::fs::write(vouch_dir.join("config.json"), json).unwrap();
}

/// `vouch <args>` (an offline command) must exit 0, print `needle` to stdout,
/// and never surface "invalid server URL" on stderr — even when the server
/// URL is malformed. `setup` injects the malformed URL via the path under test.
fn assert_offline_succeeds(
    args: &[&str],
    needle: &str,
    case: &str,
    setup: impl FnOnce(&mut Command, &TempDir),
) {
    let (mut cmd, dir) = isolated_vouch(args);
    setup(&mut cmd, &dir);
    let output = cmd.output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "{case}: vouch {args:?} must exit 0 with a malformed configured server URL, got {:?}\n\
         stdout:\n{stdout}\n\
         stderr:\n{stderr}",
        output.status.code(),
    );
    assert!(
        stdout.contains(needle),
        "{case}: vouch {args:?} must print `{needle}` to stdout, got:\n{stdout}",
    );
    assert!(
        !stderr.contains("invalid server URL"),
        "{case}: a server URL the command never contacts must not surface as an error:\n{stderr}",
    );
}

// -- `VOUCH_SERVER` env-var path: dropping the `https://` scheme --
// One per offline command; proves each offline dispatch arm reaches its
// handler and emits output instead of aborting in URL resolution.

#[test]
fn completions_succeeds_with_malformed_vouch_server_env() {
    assert_offline_succeeds(
        &["completions", "bash"],
        "vouch",
        "completions via VOUCH_SERVER",
        |cmd, _| {
            cmd.env("VOUCH_SERVER", MALFORMED_SERVER_URL);
        },
    );
}

#[test]
fn init_succeeds_with_malformed_vouch_server_env() {
    assert_offline_succeeds(
        &["init", "bash"],
        "_vouch_hook",
        "init via VOUCH_SERVER",
        |cmd, _| {
            cmd.env("VOUCH_SERVER", MALFORMED_SERVER_URL);
        },
    );
}

#[test]
fn posture_succeeds_with_malformed_vouch_server_env() {
    // `--format json` output is locale-independent ("stays English regardless
    // of locale") and always serializes `posture_version`.
    assert_offline_succeeds(
        &["posture", "--format", "json"],
        "posture_version",
        "posture via VOUCH_SERVER",
        |cmd, _| {
            cmd.env("VOUCH_SERVER", MALFORMED_SERVER_URL);
        },
    );
}

// -- hand-edited `config.json` path: a nested `servers.<host>.server_url` --
// (unlike the legacy flat `server_url`, which the migration silently drops
// when `hostname_from_url` cannot parse it, a nested entry is stored verbatim
// and reaches `ServerUrl::parse` untouched.) One command suffices to prove the
// nested malformed entry is exempt for offline commands.

#[test]
fn init_succeeds_with_malformed_config_server_url() {
    assert_offline_succeeds(
        &["init", "bash"],
        "_vouch_hook",
        "init via config.json",
        |_, dir| {
            write_config(&dir.path().join("config"), MALFORMED_CONFIG_JSON);
        },
    );
}

// -- server-using commands must still validate the URL (no regression) --

/// `vouch doctor` is server-using (it takes the server URL and is deliberately
/// not on the offline exemption list), so a malformed configured server URL
/// must abort it inside `resolve_server_url` before any check runs. This guards
/// against the offline-skip fix accidentally relaxing validation for commands
/// that actually contact the server.
#[test]
fn doctor_still_fails_on_malformed_config_server_url() {
    let (mut cmd, dir) = isolated_vouch(&["doctor"]);
    write_config(&dir.path().join("config"), MALFORMED_CONFIG_JSON);
    let output = cmd.output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "vouch doctor must still fail on a malformed server URL, got {:?}\n\
         stdout:\n{stdout}\n\
         stderr:\n{stderr}",
        output.status.code(),
    );
    assert!(
        stderr.contains("invalid server URL"),
        "doctor is server-using; it must surface the invalid URL, not a later error:\n{stderr}",
    );
}
