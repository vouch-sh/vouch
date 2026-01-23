//! Socket path utilities.

use crate::error::{AgentError, Result};
use std::path::PathBuf;

/// Default socket filename.
const SOCKET_FILENAME: &str = "agent.sock";

/// Get the vouch directory (~/.vouch).
///
/// # Errors
///
/// Returns `AgentError::SocketPath` if the home directory cannot be determined.
pub fn vouch_dir() -> Result<PathBuf> {
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
pub fn ensure_vouch_dir() -> Result<()> {
    let dir = vouch_dir()?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| {
            AgentError::SocketPath(format!("failed to create {}: {e}", dir.display()))
        })?;

        // Set directory permissions to 0700 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&dir, perms).map_err(|e| {
                AgentError::SocketPath(format!(
                    "failed to set permissions on {}: {e}",
                    dir.display()
                ))
            })?;
        }
    }
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
