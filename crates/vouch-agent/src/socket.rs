// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Socket path, lifecycle, and peer-authorization utilities.

use crate::audit::{self, AuditEvent};
use crate::error::{AgentError, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, warn};

/// Default socket filename.
const SOCKET_FILENAME: &str = "agent.sock";

/// Get the vouch runtime directory (`$XDG_RUNTIME_DIR/vouch`, or a `0700`
/// cache fallback when `XDG_RUNTIME_DIR` is unset, e.g. on macOS).
///
/// Used for Unix sockets, which belong in the runtime directory: a private,
/// user-owned location cleared on logout.
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if the directory cannot be determined.
pub(crate) fn vouch_dir() -> Result<PathBuf> {
    vouch_common::paths::runtime_dir()
        .ok_or_else(|| AgentError::SocketPath("could not determine runtime directory".to_string()))
}

/// Get the socket path (`$XDG_RUNTIME_DIR/vouch/agent.sock`).
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if the home directory cannot be determined.
pub fn socket_path() -> Result<PathBuf> {
    Ok(vouch_dir()?.join(SOCKET_FILENAME))
}

/// Prepare the vouch runtime directory: validated lstat-first, `0700`, owned
/// by the current user. Must run once at startup, before either the IPC or
/// SSH agent socket binds into it — a hijacked path is rejected without
/// being modified.
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if the directory cannot be created or
/// fails validation (symlink, foreign owner, not a directory).
pub fn prepare_vouch_dir() -> Result<()> {
    let dir = vouch_dir()?;
    vouch_common::paths::prepare_private_dir(&dir)
        .map_err(|e| AgentError::SocketPath(format!("runtime directory {}: {e}", dir.display())))
}

/// Remove the socket file if it exists.
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if the socket cannot be removed.
pub fn remove_socket() -> Result<()> {
    let path = socket_path()?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| {
            AgentError::SocketPath(format!("failed to remove {}: {e}", path.display()))
        })?;
    }
    Ok(())
}

/// Bind a Unix socket at the given path, removing stale socket if needed.
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if the socket cannot be bound.
pub(crate) async fn bind_socket(path: &Path) -> Result<UnixListener> {
    // Remove stale socket if it exists
    if path.exists() {
        std::fs::remove_file(path).ok();
    }

    let listener = UnixListener::bind(path).map_err(|e| {
        AgentError::SocketPath(format!("failed to bind to {}: {e}", path.display()))
    })?;

    // Set socket permissions to 0600 (owner read/write only)
    set_socket_permissions(path)?;

    Ok(listener)
}

/// Set socket permissions to 0600 (owner read/write only).
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if permissions cannot be set.
pub(crate) fn set_socket_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| {
        AgentError::SocketPath(format!(
            "failed to set permissions on {}: {e}",
            path.display()
        ))
    })
}

/// Get the current process's real UID.
#[expect(
    unsafe_code,
    reason = "libc::getuid is always safe with no side effects"
)]
pub(crate) fn current_uid() -> u32 {
    // SAFETY: getuid() is always safe — it reads the process's real UID
    // with no side effects.
    unsafe { libc::getuid() }
}

/// Peer credential information extracted from a Unix socket connection.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerCredentials {
    /// UID of the connecting process.
    pub uid: u32,
    /// PID of the connecting process (0 if unavailable).
    pub pid: u32,
}

/// Get the peer credentials (UID/PID) of a connected Unix stream.
///
/// Uses the stdlib's `peer_cred()` which wraps `SO_PEERCRED` on Linux
/// and `getpeereid` on macOS — no unsafe needed.
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if peer credentials cannot be retrieved.
pub(crate) fn get_peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    let cred = stream
        .peer_cred()
        .map_err(|e| AgentError::SocketPath(format!("failed to get peer credentials: {e}")))?;

    Ok(PeerCredentials {
        uid: cred.uid(),
        pid: cred.pid().map_or(0, |p| p.cast_unsigned()),
    })
}

/// Which agent listener a connection arrived on.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketKind {
    /// JSON-RPC IPC socket (`agent.sock`).
    Ipc,
    /// SSH agent protocol socket (`ssh-agent.sock`).
    SshAgent,
}

impl SocketKind {
    /// Stable label used in log messages (matches the serialized form).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SocketKind::Ipc => "ipc",
            SocketKind::SshAgent => "ssh_agent",
        }
    }
}

/// A connection whose peer UID has been verified to match this process.
///
/// Constructible only via [`accept_authorized`], so connection handlers
/// cannot be handed an unverified stream.
pub(crate) struct AuthorizedStream(UnixStream);

impl AuthorizedStream {
    /// Unwrap the verified connection for protocol handling.
    pub(crate) fn into_stream(self) -> UnixStream {
        self.0
    }
}

/// Why a peer failed [`authorize_peer`].
#[derive(Debug)]
enum PeerRejection {
    /// Peer UID differs from the expected UID.
    UidMismatch(PeerCredentials),
    /// Peer credentials could not be retrieved (fail closed).
    CredentialsUnavailable(AgentError),
}

/// Verify that the connecting peer's UID matches `expected_uid`.
fn authorize_peer(
    stream: &UnixStream,
    expected_uid: u32,
) -> std::result::Result<PeerCredentials, PeerRejection> {
    let peer = get_peer_credentials(stream).map_err(PeerRejection::CredentialsUnavailable)?;
    if peer.uid != expected_uid {
        return Err(PeerRejection::UidMismatch(peer));
    }
    Ok(peer)
}

/// Accept one connection on `listener` and verify the peer's UID matches this
/// process (like gpg-agent/libassuan). The 0600 socket mode is the primary
/// gate; the UID check is the defense-in-depth layer against permission
/// misconfiguration, so credential-retrieval failure fails closed.
///
/// Rejections are logged and audited as `connection_rejected`, then yield
/// `None` (dropping the stream closes it); accept errors are logged and also
/// yield `None`, so callers simply `continue` their loop. Cancel-safe for
/// `tokio::select!`: the only await point is `UnixListener::accept`, which is
/// itself cancel-safe.
pub(crate) async fn accept_authorized(
    listener: &UnixListener,
    kind: SocketKind,
) -> Option<AuthorizedStream> {
    let stream = match listener.accept().await {
        Ok((stream, _addr)) => stream,
        Err(e) => {
            error!("{} accept error: {e}", kind.as_str());
            return None;
        }
    };
    match authorize_peer(&stream, current_uid()) {
        Ok(_peer) => Some(AuthorizedStream(stream)),
        Err(PeerRejection::UidMismatch(peer)) => {
            warn!(
                socket = kind.as_str(),
                peer_uid = peer.uid,
                peer_pid = peer.pid,
                expected_uid = current_uid(),
                "Rejecting connection: UID mismatch"
            );
            audit::log_event(AuditEvent::ConnectionRejected {
                socket: kind,
                peer_uid: peer.uid,
                peer_pid: peer.pid,
                reason: "uid mismatch".to_string(),
            });
            None
        }
        Err(PeerRejection::CredentialsUnavailable(e)) => {
            warn!(
                socket = kind.as_str(),
                "Rejecting connection: could not verify peer credentials: {e}"
            );
            audit::log_event(AuditEvent::ConnectionRejected {
                socket: kind,
                peer_uid: 0,
                peer_pid: 0,
                reason: "peer credential retrieval failed".to_string(),
            });
            None
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_path() {
        let path = socket_path();
        assert!(path.is_ok());
        let path = path.ok();
        assert!(path.is_some());
        assert!(path.is_some_and(|p| p.ends_with("agent.sock")));
    }

    #[tokio::test]
    async fn authorize_peer_accepts_same_uid() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let peer = authorize_peer(&a, current_uid()).expect("same-UID peer is authorized");
        assert_eq!(peer.uid, current_uid());
    }

    #[tokio::test]
    async fn authorize_peer_rejects_uid_mismatch() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        match authorize_peer(&a, current_uid().wrapping_add(1)) {
            Err(PeerRejection::UidMismatch(peer)) => assert_eq!(peer.uid, current_uid()),
            other => panic!("expected UidMismatch, got {other:?}"),
        }
    }
}
