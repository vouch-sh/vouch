// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration tests for graceful shutdown of the `vouch-agent` binary.
//!
//! These tests spawn the real `vouch-agent` binary in an isolated
//! `XDG_RUNTIME_DIR` / `XDG_CACHE_HOME`, connect over the Unix socket, send
//! SIGTERM or SIGINT, and assert that:
//!
//! 1. The process exits with status 0 (clean shutdown).
//! 2. An in-flight request that was sent *before* the signal is still
//!    answered (the connection is not cancelled mid-response).

#![cfg(unix)]
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_wrap,
    clippy::let_underscore_must_use,
    reason = "integration test code: panics, unwraps, and indexing are acceptable in tests"
)]

use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// A spawned `vouch-agent` process plus the temp dirs that must outlive it.
struct AgentProcess {
    child: Child,
    /// Kept alive so the socket file is not removed while the child runs.
    _dirs: Dirs,
}

struct Dirs {
    runtime: TempDir,
    cache: TempDir,
    config: TempDir,
    state: TempDir,
    data: TempDir,
    home: TempDir,
}

impl AgentProcess {
    fn socket_path(&self) -> std::path::PathBuf {
        self._dirs.runtime.path().join("vouch").join("agent.sock")
    }
}

/// Spawn `vouch-agent --foreground` in an isolated environment so it does
/// not interfere with the real agent.
fn spawn_agent() -> AgentProcess {
    let dirs = Dirs {
        runtime: TempDir::new().expect("runtime tempdir"),
        cache: TempDir::new().expect("cache tempdir"),
        config: TempDir::new().expect("config tempdir"),
        state: TempDir::new().expect("state tempdir"),
        data: TempDir::new().expect("data tempdir"),
        home: TempDir::new().expect("home tempdir"),
    };

    // Cargo substitutes the built binary's path at compile time. This must be
    // `env!`, not `std::env::var`: `CARGO_BIN_EXE_*` is not set at runtime, so
    // a lookup silently falls through to a hardcoded `target/debug` path that
    // is wrong under `CARGO_TARGET_DIR` or `--release`.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vouch-agent"));
    // Every path the agent resolves must land in a temp dir. HOME matters
    // because `migrate_legacy_layout` *moves* a real `~/.vouch/` into the XDG
    // locations, which would destroy the developer's config when the temp dirs
    // are deleted.
    cmd.arg("--foreground")
        .env("XDG_RUNTIME_DIR", dirs.runtime.path())
        .env("XDG_CACHE_HOME", dirs.cache.path())
        .env("XDG_CONFIG_HOME", dirs.config.path())
        .env("XDG_STATE_HOME", dirs.state.path())
        .env("XDG_DATA_HOME", dirs.data.path())
        .env("HOME", dirs.home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = cmd.spawn().expect("spawn vouch-agent");
    AgentProcess { child, _dirs: dirs }
}

/// Wait for the IPC socket to appear (max ~10 s).
async fn wait_for_socket(agent: &AgentProcess) -> std::path::PathBuf {
    let socket = agent.socket_path();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if socket.exists() {
            return socket;
        }
        if std::time::Instant::now() > deadline {
            panic!("socket {} did not appear within 10 s", socket.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Encode a JSON-RPC ping as a length-prefixed wire message.
fn encode_ping() -> Vec<u8> {
    let payload = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut buf = Vec::with_capacity(payload.len() + 4);
    buf.extend_from_slice(&len);
    buf.extend_from_slice(payload);
    buf
}

/// Read one length-prefixed JSON-RPC response from the stream.
async fn read_response(stream: &mut UnixStream) -> serde_json::Value {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .expect("response length");
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .await
        .expect("response body");
    serde_json::from_slice(&resp_buf).expect("valid JSON response")
}

/// Send SIGTERM to a child process.
#[expect(
    unsafe_code,
    reason = "libc::kill sends a signal to a child PID we own"
)]
fn send_sigterm(child: &Child) {
    // SAFETY: kill() sends a signal to a PID we own (the child).
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
}

/// Send SIGINT (Ctrl+C) to a child process.
#[expect(
    unsafe_code,
    reason = "libc::kill sends a signal to a child PID we own"
)]
fn send_sigint(child: &Child) {
    // SAFETY: kill() sends a signal to a PID we own (the child).
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
}

/// Wait for the child to exit, polling every 50 ms (max ~15 s).
fn wait_for_exit(child: &mut Child) -> ExitStatus {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => return status,
            None => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    panic!("agent did not exit within 15 s");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// The agent exits cleanly (status 0) when it receives SIGTERM.
#[tokio::test]
async fn agent_exits_cleanly_on_sigterm() {
    let mut agent = spawn_agent();
    let socket = wait_for_socket(&agent).await;

    // Verify the agent is responsive before signalling.
    let mut client = UnixStream::connect(&socket).await.expect("connect");
    client.write_all(&encode_ping()).await.expect("write ping");
    let resp = read_response(&mut client).await;
    assert_eq!(resp["result"], "pong");
    drop(client);

    send_sigterm(&agent.child);
    let status = wait_for_exit(&mut agent.child);
    assert!(status.success(), "agent should exit with status 0");
}

/// The agent exits cleanly (status 0) when it receives SIGINT (Ctrl+C).
#[tokio::test]
async fn agent_exits_cleanly_on_sigint() {
    let mut agent = spawn_agent();
    let socket = wait_for_socket(&agent).await;

    // Verify the agent is responsive.
    let mut client = UnixStream::connect(&socket).await.expect("connect");
    client.write_all(&encode_ping()).await.expect("write ping");
    let resp = read_response(&mut client).await;
    assert_eq!(resp["result"], "pong");
    drop(client);

    send_sigint(&agent.child);
    let status = wait_for_exit(&mut agent.child);
    assert!(status.success(), "agent should exit with status 0");
}

/// An in-flight ping request sent *before* SIGTERM still receives a
/// response — proving the graceful drain lets connections finish.
#[tokio::test]
async fn inflight_request_completes_on_sigterm() {
    let mut agent = spawn_agent();
    let socket = wait_for_socket(&agent).await;

    // Connect and send a ping, but do NOT read the response yet.
    let mut client = UnixStream::connect(&socket).await.expect("connect");
    client.write_all(&encode_ping()).await.expect("write ping");

    // Send SIGTERM immediately — the request is in-flight.
    send_sigterm(&agent.child);

    // The response should still arrive (drain lets the handler finish).
    let resp = tokio::time::timeout(Duration::from_secs(10), read_response(&mut client))
        .await
        .expect("response should arrive within 10 s");
    assert_eq!(resp["result"], "pong");

    drop(client);
    let status = wait_for_exit(&mut agent.child);
    assert!(status.success(), "agent should exit with status 0");
}

/// The agent cleans up its socket file on graceful shutdown.
#[tokio::test]
async fn socket_removed_on_shutdown() {
    let mut agent = spawn_agent();
    let socket = wait_for_socket(&agent).await;
    assert!(
        socket.exists(),
        "socket should exist while agent is running"
    );

    send_sigterm(&agent.child);
    let status = wait_for_exit(&mut agent.child);
    assert!(status.success(), "agent should exit with status 0");

    // Give the OS a moment to finalise file removal.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !socket.exists(),
        "socket should be removed after graceful shutdown"
    );
}

/// The agent removes its PID file on graceful shutdown. A stale PID file makes
/// the next `vouch-agent` start refuse with "already running", so this is as
/// load-bearing as socket removal.
#[tokio::test]
async fn pid_file_removed_on_shutdown() {
    let mut agent = spawn_agent();
    wait_for_socket(&agent).await;

    let pid_file = agent._dirs.cache.path().join("vouch").join("agent.pid");
    assert!(
        pid_file.exists(),
        "PID file should exist at {} while the agent is running",
        pid_file.display()
    );

    send_sigterm(&agent.child);
    let status = wait_for_exit(&mut agent.child);
    assert!(status.success(), "agent should exit with status 0");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !pid_file.exists(),
        "PID file should be removed after graceful shutdown"
    );
}
