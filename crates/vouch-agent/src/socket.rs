// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Socket path and lifecycle utilities.

use crate::error::{AgentError, Result};
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};

/// Default socket filename.
const SOCKET_FILENAME: &str = "agent.sock";

/// Get the vouch directory (~/.vouch).
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if the home directory cannot be determined.
pub(crate) fn vouch_dir() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| AgentError::SocketPath("could not determine home directory".to_string()))?;
    Ok(home.join(".vouch"))
}

/// Get the socket path (~/.vouch/agent.sock).
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if the home directory cannot be determined.
pub fn socket_path() -> Result<PathBuf> {
    Ok(vouch_dir()?.join(SOCKET_FILENAME))
}

/// Ensure the vouch directory exists with proper permissions.
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if the directory cannot be created or permissions cannot be set.
pub(crate) fn ensure_vouch_dir() -> Result<()> {
    let dir = vouch_dir()?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| AgentError::SocketPath(format!("failed to create {}: {e}", dir.display())))?;

    // Always set directory permissions to 0700, even if the directory already existed
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(&dir, perms).map_err(|e| {
        AgentError::SocketPath(format!(
            "failed to set permissions on {}: {e}",
            dir.display()
        ))
    })?;

    Ok(())
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
#[allow(unsafe_code)]
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
/// Uses `SO_PEERCRED` on Linux and `getpeereid` on macOS, following the same
/// pattern as GnuPG's libassuan for socket peer verification.
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if peer credentials cannot be retrieved.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(crate) fn get_peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();

    // SAFETY: `ucred` is a plain-data struct; zero-init is valid.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `getsockopt` reads kernel-managed peer credentials into `cred`.
    // The fd is a valid connected Unix socket (guaranteed by the caller).
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if ret != 0 {
        return Err(AgentError::SocketPath(format!(
            "SO_PEERCRED failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    #[allow(clippy::cast_sign_loss)]
    Ok(PeerCredentials {
        uid: cred.uid,
        pid: cred.pid as u32,
    })
}

/// Get the peer credentials (UID/PID) of a connected Unix stream.
///
/// Uses `getpeereid` on macOS/FreeBSD. PID is not available via this API
/// and is set to 0.
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if peer credentials cannot be retrieved.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) fn get_peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;

    // SAFETY: `getpeereid` writes the peer's effective UID and GID into the
    // provided pointers. The fd is a valid connected Unix socket.
    let ret = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if ret != 0 {
        return Err(AgentError::SocketPath(format!(
            "getpeereid failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(PeerCredentials { uid, pid: 0 })
}

/// Validate that the vouch directory is safe to use.
///
/// Checks that `~/.vouch/` is not a symlink and is owned by the current user.
/// Prevents symlink attacks where an attacker pre-creates the directory pointing
/// to an attacker-controlled location.
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if the directory fails validation.
pub(crate) fn validate_vouch_dir_ownership() -> Result<()> {
    let dir = vouch_dir()?;

    // Use symlink_metadata (lstat) — does NOT follow symlinks
    let metadata = std::fs::symlink_metadata(&dir).map_err(|e| {
        AgentError::SocketPath(format!("cannot stat {}: {e}", dir.display()))
    })?;

    // Reject symlinks
    if metadata.file_type().is_symlink() {
        return Err(AgentError::SocketPath(format!(
            "{} is a symlink — refusing to use it (possible symlink attack)",
            dir.display()
        )));
    }

    // Verify ownership matches current user
    use std::os::unix::fs::MetadataExt;
    let dir_uid = metadata.uid();
    let my_uid = current_uid();
    if dir_uid != my_uid {
        return Err(AgentError::SocketPath(format!(
            "{} is owned by UID {dir_uid}, but agent is running as UID {my_uid}",
            dir.display()
        )));
    }

    Ok(())
}

#[cfg(test)]
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
}
