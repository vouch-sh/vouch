// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch credential pip` must keep stdout pure for pip/uv.
//!
//! pip (26.2+) does `json.loads(stdout)` on the keyring helper's output and
//! older pip/uv split stdout into username/password lines. On Windows,
//! `vouch setup codeartifact --tool pip` installs a `keyring.bat` that runs
//! `vouch.exe credential pip %*` — the normal clap subcommand path, which
//! initializes its `tracing_subscriber::fmt()` subscriber *before* the
//! credential command runs. The subscriber's default writer is **stdout**
//! (default filter `warn`), so any `tracing::warn!` reached during token
//! fetching landed ahead of the credential and corrupted pip/uv's parsing.
//!
//! This is the one place that exercises the **clap subcommand path**
//! (`vouch credential pip …`, argv0 = `vouch`) and pins that a tracing event
//! emitted mid-fetch lands on stderr, never stdout. The Unix `keyring`
//! symlink (argv0 dispatch) returns before the subscriber is installed, so
//! it was already silent; this test guards the route that was not.
//!
//! Determinism: the fetch always calls `load_client_key`, which always emits
//! exactly one `vouch_cli::fapi::key_store` tracing line (debug when the
//! keychain has a valid key or no entry, warn on a parse/access/disk error)
//! before the flow errors on the unreachable loopback server. So with
//! `RUST_LOG=debug` that line is guaranteed to fire regardless of the host's
//! keychain state, and the assertions only need to check which stream it
//! landed on.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use std::process::{Command, Stdio};

use tempfile::TempDir;

/// A CodeArtifact index URL as pip writes it into `pip.conf`.
const INDEX_URL: &str =
    "https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/pypi/r/simple/";

/// A vouch-managed AWS role profile, the sole one in `~/.aws/config` so
/// `resolve_vouch_profile(None, …)` resolves to it and the flow reaches
/// `load_client_key` (where a tracing line always fires).
const AWS_CONFIG: &str = "\
[profile vouch]
credential_process = vouch credential aws --role arn:aws:iam::123456789012:role/MyRole
region = us-east-1
";

/// Vouch config with a stored session for an unreachable loopback server, so
/// `resolve_session` succeeds and the fetch proceeds to `load_client_key`,
/// which emits a tracing line before the flow errors on the dead server.
const VOUCH_CONFIG: &str = "\
{
  \"current_server\": \"127.0.0.1:1\",
  \"servers\": {
    \"127.0.0.1:1\": {
      \"server_url\": \"https://127.0.0.1:1\",
      \"token\": \"stored-session-token\"
    }
  }
}
";

struct Run {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Build an isolated environment that drives a credential fetch far enough to
/// call `load_client_key`. Writes a stored session and a single vouch-managed
/// role profile. The loopback server (`127.0.0.1:1`) is deliberately
/// unreachable, so no credential is ever printed and the flow errors after
/// `load_client_key` emits its tracing line.
fn isolated_env() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().join("config");
    let data_dir = dir.path().join("data");
    let aws = dir.path().join("aws");
    for d in [
        &config_dir,
        &data_dir,
        &dir.path().join("cache"),
        &dir.path().join("state"),
        &dir.path().join("run"),
        &aws,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::create_dir_all(config_dir.join("vouch")).unwrap();
    std::fs::write(config_dir.join("vouch").join("config.json"), VOUCH_CONFIG).unwrap();
    std::fs::write(aws.join("config"), AWS_CONFIG).unwrap();
    dir
}

/// Run `vouch credential pip get <index> aws` (the clap subcommand path).
fn run_clap_route(args: &[&str]) -> Run {
    let dir = isolated_env();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vouch"));
    cmd.args(args);
    cmd.env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("XDG_RUNTIME_DIR", dir.path().join("run"))
        .env("AWS_CONFIG_FILE", dir.path().join("aws").join("config"))
        // `debug` makes `load_client_key` emit its tracing line even when the
        // host keychain has a valid key (it prints `Loaded FAPI key from
        // keychain`, not a warn), so the test is deterministic regardless of
        // keychain state.
        .env("RUST_LOG", "debug")
        .env_remove("VOUCH_SERVER")
        .env_remove("VOUCH_ALLOW_INSECURE")
        .env_remove("VOUCH_TOKEN")
        .env_remove("VOUCH_LANG")
        // The host's ambient AWS_PROFILE must not steer profile resolution.
        .env_remove("AWS_PROFILE")
        .env_remove("AWS_DEFAULT_PROFILE")
        .stdin(Stdio::null());
    let output = cmd.output().unwrap();
    Run {
        success: output.status.success(),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

/// `vouch credential pip` prints the credential to stdout, so a
/// `tracing::warn!`/`debug!` emitted mid-fetch must land on stderr, never
/// stdout. On Windows the `keyring.bat` helper reaches this clap route
/// (after the subscriber is installed); the tracing line would otherwise
/// land ahead of the credential and corrupt pip's `json.loads(stdout)` /
/// uv's line-split parsing. `load_client_key` always emits one
/// `vouch_cli::fapi::key_store` line on this path, so the assertion is
/// deterministic. This is the regression that would reappear if the
/// `.with_writer(std::io::stderr)` on the CLI's tracing subscriber is
/// dropped.
#[test]
fn clap_route_tracing_goes_to_stderr_not_stdout() {
    let run = run_clap_route(&["credential", "pip", "get", INDEX_URL, "aws"]);
    assert!(
        !run.success,
        "the fetch should error (the loopback server is unreachable)"
    );

    // The `load_client_key` line is guaranteed to fire; it must be on stderr.
    let key_store = "vouch_cli::fapi::key_store: ";
    assert!(
        run.stderr.contains(key_store),
        "expected a vouch_cli::fapi::key_store tracing line on stderr; stderr={:?}",
        run.stderr
    );
    assert!(
        !run.stdout.contains(key_store),
        "tracing leaked to stdout on the `vouch credential pip` clap route \
         (pip/uv would parse this as the credential): {:?}",
        run.stdout
    );
}
