// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Daemon lifecycle management.
//!
//! This module handles:
//! - PID file creation and cleanup
//! - Process daemonization (fork, setsid, etc.)
//! - Checking if agent is already running

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process;

use crate::error::{AgentError, Result};

/// Result of the daemonize operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonizeResult {
    /// This is the parent process and should exit with code 0.
    Parent,
    /// This is the child (daemon) process and should continue.
    Child,
    /// Daemonization was skipped (e.g., non-Unix platform).
    Skipped,
}

/// Get the path to the PID file.
pub fn pid_file_path() -> Result<PathBuf> {
    let cache_dir = dirs::cache_dir()
        .ok_or_else(|| AgentError::Config("Could not determine cache directory".to_string()))?;
    let vouch_dir = cache_dir.join("vouch");
    Ok(vouch_dir.join("agent.pid"))
}

/// Get the path to the log file.
pub(crate) fn log_file_path() -> Result<PathBuf> {
    let cache_dir = dirs::cache_dir()
        .ok_or_else(|| AgentError::Config("Could not determine cache directory".to_string()))?;
    let vouch_dir = cache_dir.join("vouch");
    Ok(vouch_dir.join("agent.log"))
}

/// Check if an agent is already running.
pub fn is_running() -> Result<bool> {
    let pid_path = pid_file_path()?;

    if !pid_path.exists() {
        return Ok(false);
    }

    // Read the PID file
    let mut file = match fs::File::open(&pid_path) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };

    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_err() {
        return Ok(false);
    }

    let pid: i32 = match contents.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            // Invalid PID file, remove it
            let _ = fs::remove_file(&pid_path);
            return Ok(false);
        }
    };

    // Check if the process is still running
    if is_process_running(pid) {
        Ok(true)
    } else {
        // Stale PID file, remove it
        let _ = fs::remove_file(&pid_path);
        Ok(false)
    }
}

/// Check if a process with the given PID is running.
#[cfg(unix)]
#[expect(unsafe_code, reason = "libc::kill(pid, 0) probe; safety documented inline")]
fn is_process_running(pid: i32) -> bool {
    // Send signal 0 to check if process exists
    // SAFETY: kill(pid, 0) is a standard Unix API to check if a process exists
    unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(not(unix))]
fn is_process_running(_pid: i32) -> bool {
    // On non-Unix systems, assume not running if we can't check
    false
}

/// Write the current PID to the PID file atomically.
///
/// Writes to a temporary file first, then renames to the final path
/// to prevent TOCTOU races with concurrent readers.
pub fn write_pid_file() -> Result<()> {
    let pid_path = pid_file_path()?;

    // Ensure parent directory exists
    if let Some(parent) = pid_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| AgentError::Config(format!("Failed to create cache directory: {e}")))?;
    }

    let pid = process::id();

    // Write to a temp file in the same directory, then rename atomically
    let tmp_path = pid_path.with_extension("tmp");
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| AgentError::Config(format!("Failed to create temp PID file: {e}")))?;

    write!(file, "{pid}")
        .map_err(|e| AgentError::Config(format!("Failed to write temp PID file: {e}")))?;

    fs::rename(&tmp_path, &pid_path)
        .map_err(|e| AgentError::Config(format!("Failed to rename PID file: {e}")))?;

    Ok(())
}

/// Remove the PID file.
pub fn remove_pid_file() -> Result<()> {
    let pid_path = pid_file_path()?;
    if pid_path.exists() {
        fs::remove_file(&pid_path)
            .map_err(|e| AgentError::Config(format!("Failed to remove PID file: {e}")))?;
    }
    Ok(())
}

/// Daemonize the current process.
///
/// This function:
/// 1. Forks and returns `Parent` in the parent (caller should exit)
/// 2. Creates a new session (setsid)
/// 3. Forks again to prevent acquiring a controlling terminal
/// 4. Redirects stdin/stdout/stderr to /dev/null or log file
/// 5. Changes working directory to /
///
/// Returns `Ok(DaemonizeResult::Child)` in the daemon process,
/// `Ok(DaemonizeResult::Parent)` in parent processes (caller should exit with code 0).
#[cfg(unix)]
#[expect(unsafe_code, reason = "POSIX double-fork daemonization; safety documented inline")]
pub fn daemonize() -> Result<DaemonizeResult> {
    use std::os::unix::io::AsRawFd;

    // First fork
    // SAFETY: fork() is a standard Unix API for creating child processes
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(AgentError::Config("First fork failed".to_string()));
    }
    if pid > 0 {
        // Parent process - caller should exit
        return Ok(DaemonizeResult::Parent);
    }

    // Create new session
    // SAFETY: setsid() is a standard Unix API for creating a new session
    if unsafe { libc::setsid() } < 0 {
        return Err(AgentError::Config("setsid failed".to_string()));
    }

    // Second fork (to prevent acquiring controlling terminal)
    // SAFETY: fork() is a standard Unix API for creating child processes
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(AgentError::Config("Second fork failed".to_string()));
    }
    if pid > 0 {
        // Intermediate parent - caller should exit
        return Ok(DaemonizeResult::Parent);
    }

    // Change working directory to root
    let _ = std::env::set_current_dir("/");

    // Close standard file descriptors and redirect to /dev/null or log file
    let log_path = log_file_path()?;
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).ok();
    }

    // Open /dev/null for stdin
    let dev_null = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| AgentError::Config(format!("Failed to open /dev/null: {e}")))?;

    // Open log file for stdout/stderr, fall back to /dev/null
    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .or_else(|_| dev_null.try_clone())
        .map_err(|e| AgentError::Config(format!("Failed to open log file or /dev/null: {e}")))?;

    // Redirect file descriptors
    // SAFETY: dup2() is a standard Unix API for duplicating file descriptors
    unsafe {
        if libc::dup2(dev_null.as_raw_fd(), libc::STDIN_FILENO) < 0 {
            return Err(AgentError::Config("dup2 stdin failed".to_string()));
        }
        if libc::dup2(log_file.as_raw_fd(), libc::STDOUT_FILENO) < 0 {
            return Err(AgentError::Config("dup2 stdout failed".to_string()));
        }
        if libc::dup2(log_file.as_raw_fd(), libc::STDERR_FILENO) < 0 {
            return Err(AgentError::Config("dup2 stderr failed".to_string()));
        }
    }

    // Write PID file
    write_pid_file()?;

    Ok(DaemonizeResult::Child)
}

/// Daemonize is not supported on non-Unix systems.
#[cfg(not(unix))]
pub fn daemonize() -> Result<DaemonizeResult> {
    // Just write the PID file and continue in foreground
    write_pid_file()?;
    Ok(DaemonizeResult::Skipped)
}
