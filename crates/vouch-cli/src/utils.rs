// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared utility functions for the CLI.

#![allow(dead_code)]

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Ensure a directory exists with secure permissions (0o700 on Unix).
///
/// Creates the directory and all parent directories if they don't exist.
/// On Unix systems, always enforces permissions to 0o700 (owner read/write/execute only),
/// even if the directory already exists, to guard against directories created
/// by another process with permissive modes.
pub fn ensure_secure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Unix file permission mode for atomic writes.
///
/// On non-Unix platforms, this value is accepted but ignored.
pub(crate) enum FileMode {
    /// Use default permissions (no explicit chmod).
    Default,
    /// Restrictive: owner read/write only (0o600 on Unix).
    Secure,
    /// Executable: owner rwx, group/other rx (0o755 on Unix).
    Executable,
}

/// Atomically write content to a file with the given permission mode.
///
/// Writes to a temporary file in the same directory, then renames it
/// to the target path. This ensures the file is never left in a
/// partially-written state if the process is interrupted.
///
/// Creates parent directories if they don't exist.
/// On Unix, sets file permissions on the temp file before the rename
/// so the file is never visible with incorrect permissions.
fn atomic_write_impl(path: &Path, content: &[u8], mode: FileMode) -> Result<()> {
    let parent = path.parent().context("file path has no parent directory")?;

    // create_dir_all is idempotent — no existence check needed.
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temp file in {}", parent.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let unix_mode = match mode {
            FileMode::Default => None,
            FileMode::Secure => Some(0o600),
            FileMode::Executable => Some(0o755),
        };
        if let Some(m) = unix_mode {
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(m))?;
        }
    }

    #[cfg(not(unix))]
    let _ = mode;

    tmp.write_all(content)
        .with_context(|| format!("failed to write temp file for {}", path.display()))?;
    tmp.flush()
        .with_context(|| format!("failed to flush temp file for {}", path.display()))?;

    // Ensure data is durable on disk before the atomic rename.
    // Without this, a power failure after rename could leave a zero-length file.
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("failed to sync temp file for {}", path.display()))?;

    tmp.persist(path)
        .with_context(|| format!("failed to persist temp file to {}", path.display()))?;

    Ok(())
}

/// Atomically write content to a file.
///
/// Writes to a temporary file in the same directory, then renames it
/// to the target path. This ensures the file is never left in a
/// partially-written state if the process is interrupted.
///
/// Creates parent directories if they don't exist.
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    atomic_write_impl(path, content, FileMode::Default)
}

/// Atomically write content to a file with secure permissions (0o600 on Unix).
///
/// Same as [`atomic_write`], but sets restrictive file permissions before
/// the rename, so the file is never visible with default (world-readable)
/// permissions.
pub fn atomic_write_secure(path: &Path, content: &[u8]) -> Result<()> {
    atomic_write_impl(path, content, FileMode::Secure)
}

/// Atomically write content to a file with executable permissions (0o755 on Unix).
///
/// Same as [`atomic_write`], but sets executable permissions.
pub fn atomic_write_executable(path: &Path, content: &[u8]) -> Result<()> {
    atomic_write_impl(path, content, FileMode::Executable)
}

/// Write content to a file with secure permissions (0o600 on Unix).
///
/// Creates parent directories if they don't exist.
/// On Unix systems, sets file permissions to 0o600 (owner read/write only).
///
/// This is a convenience wrapper around [`atomic_write_secure`] that
/// accepts a string slice.
pub fn write_secure_file(path: &Path, content: &str) -> Result<()> {
    atomic_write_secure(path, content.as_bytes())
}

/// Create a symlink (Unix) or batch file wrapper (Windows) pointing to the vouch binary.
///
/// On Unix: creates a symlink at `symlink_path` → `vouch_path`, checks PATH.
/// On Windows: creates a `.bat` wrapper with the given `windows_batch_content`,
/// checks PATH using `split_paths`.
///
/// Both platforms: ensures the parent directory exists, removes existing files,
/// and warns if the directory is not in PATH.
pub(crate) fn create_symlink_with_fallback(
    vouch_path: &Path,
    symlink_path: &Path,
    #[allow(unused_variables)] windows_batch_content: &str,
) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = symlink_path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
        println!("Created directory: {}", parent.display());
    }

    #[cfg(unix)]
    {
        // Remove existing symlink if present
        if symlink_path.exists() || symlink_path.is_symlink() {
            fs::remove_file(symlink_path)
                .with_context(|| format!("failed to remove existing {}", symlink_path.display()))?;
        }

        std::os::unix::fs::symlink(vouch_path, symlink_path)
            .with_context(|| format!("failed to create symlink at {}", symlink_path.display()))?;

        println!(
            "Created symlink: {} -> {}",
            symlink_path.display(),
            vouch_path.display()
        );

        // Check if the symlink directory is in PATH
        if let Some(parent) = symlink_path.parent()
            && let Ok(path_var) = std::env::var("PATH")
            && !std::env::split_paths(&path_var).any(|p| p == parent)
        {
            println!();
            println!("Note: {} is not in your PATH.", parent.display());
            println!("Add it to your shell profile:");
            println!("  export PATH=\"$PATH:{}\"", parent.display());
        }
    }

    #[cfg(windows)]
    {
        let bat_path = symlink_path.with_extension("bat");

        if bat_path.exists() {
            fs::remove_file(&bat_path)
                .with_context(|| format!("failed to remove existing {}", bat_path.display()))?;
        }

        atomic_write(&bat_path, windows_batch_content.as_bytes())
            .with_context(|| format!("failed to create {}", bat_path.display()))?;

        println!("Created: {}", bat_path.display());

        if let Some(parent) = bat_path.parent() {
            if let Ok(path_var) = std::env::var("PATH")
                && !std::env::split_paths(&path_var).any(|p| p == parent)
            {
                println!();
                println!("Note: {} is not in your PATH.", parent.display());
                println!("Add it to your system PATH environment variable.");
            }
        }
    }

    Ok(())
}

/// Acquire an exclusive advisory lock on a file using `flock(2)`.
///
/// This is the only `unsafe` call in the CLI crate. `flock` is a well-defined
/// POSIX API and the file descriptor is guaranteed valid by the borrow of `File`.
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn flock_exclusive(file: &fs::File) -> Result<(), std::io::Error> {
    use std::os::unix::io::{AsFd, AsRawFd};
    let ret = unsafe { libc::flock(file.as_fd().as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// Tests for these utilities are in vouch-tests integration tests
// since they require filesystem access with tempfile.
