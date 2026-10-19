// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `keyring`: the vouch binary linked under that name, as pip and uv run it.
//!
//! pip and uv run the `keyring` executable on `PATH` with keyring's own
//! argument grammar (jaraco/keyring `keyring/cli.py`). These tests run the real
//! binary through a `keyring` symlink with each call shape pip and uv send,
//! with an isolated home so no session exists and nothing touches the network.
//! A call that parses reaches the session lookup and fails there; one that
//! does not parse fails before it.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use std::process::{Command, Stdio};

use tempfile::TempDir;

const HOST: &str = "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com";

struct KeyringRun {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Run the vouch binary as `keyring` with `args`.
fn run_keyring(args: &[&str]) -> KeyringRun {
    let dir: TempDir = tempfile::tempdir().unwrap();
    let keyring = dir.path().join("keyring");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_vouch"), &keyring).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let output = Command::new(&keyring)
        .args(args)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("XDG_RUNTIME_DIR", dir.path().join("run"))
        .env_remove("VOUCH_SERVER")
        .env_remove("VOUCH_ALLOW_INSECURE")
        .env_remove("VOUCH_TOKEN")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    KeyringRun {
        success: output.status.success(),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

/// The call parsed and was routed to CodeArtifact, then stopped at the
/// missing session without printing a credential.
fn assert_reached_session_lookup(run: &KeyringRun, args: &[&str]) {
    assert!(!run.success, "{args:?}");
    assert!(run.stdout.is_empty(), "{args:?}: {}", run.stdout);
    assert!(
        run.stderr.contains("vouch enroll"),
        "{args:?}: {}",
        run.stderr
    );
}

// Call shapes pip and uv send:
// - pip 26.2+ `KeyringCLIProvider._get_creds` (pip/_internal/network/auth.py):
//   `[keyring, "--mode=creds", "--output=json", "get", service_name]` plus the
//   username when known; service_name is the index URL, then the netloc.
// - pip before 26.2: `[keyring, "get", service_name, username]`.
// - uv `fetch_subprocess` (crates/uv-auth/src/keyring.rs): `get <service>` plus
//   the username, or `--mode creds` after the service when there is none.
#[test]
fn every_pip_and_uv_call_shape_parses() {
    let index = format!("https://{HOST}/pypi/r/simple/");
    let root = format!("https://{HOST}");
    let calls: [Vec<&str>; 7] = [
        vec!["--mode=creds", "--output=json", "get", &index, "aws"],
        vec!["--mode=creds", "--output=json", "get", HOST, "aws"],
        vec!["--mode=creds", "--output=json", "get", &index],
        vec!["get", &index, "aws"],
        vec!["get", HOST, "aws"],
        vec!["get", &root, "aws"],
        vec!["get", &index, "--mode", "creds"],
    ];
    for args in &calls {
        assert_reached_session_lookup(&run_keyring(args), args);
    }
}

// A non-CodeArtifact service fails before any session lookup, with no output.
#[test]
fn non_codeartifact_service_prints_nothing() {
    let args = [
        "--mode=creds",
        "--output=json",
        "get",
        "https://pypi.org/simple/",
        "aws",
    ];
    let run = run_keyring(&args);
    assert!(!run.success);
    assert!(run.stdout.is_empty());
    assert!(
        run.stderr
            .contains("does not appear to be a CodeArtifact registry"),
        "{}",
        run.stderr
    );
}

// An option real keyring does not define is a usage error: vouch fails and
// prints nothing pip or uv could mistake for a credential.
#[test]
fn option_keyring_does_not_define_fails_without_output() {
    let run = run_keyring(&["--format=json", "get", HOST, "aws"]);
    assert!(!run.success);
    assert!(run.stdout.is_empty());
    assert!(run.stderr.contains("--format"), "{}", run.stderr);
}

// keyring's `set` and `del` are accepted and ignored.
#[test]
fn set_and_del_succeed_silently() {
    for op in ["set", "del"] {
        let run = run_keyring(&[op, HOST, "aws"]);
        assert!(run.success, "{op}: {}", run.stderr);
        assert!(run.stdout.is_empty());
    }
}
