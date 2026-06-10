// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared utility functions for the CLI.

#![allow(
    dead_code,
    reason = "shared utilities used selectively across binary and test targets"
)]

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Ensure a directory exists with secure permissions (0o700 on Unix).
///
/// Creates the directory and all parent directories if they don't exist.
/// On Unix systems, always enforces permissions to 0o700 (owner read/write/execute only),
/// even if the directory already exists, to guard against directories created
/// by another process with permissive modes.
pub(crate) fn ensure_secure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Get the path for a vouch helper binary in `~/.local/bin/`.
///
/// All vouch helper symlinks (docker-credential-vouch, git-remote-codecommit,
/// keyring, vouch-pnpm-tokenhelper) live in `~/.local/bin/`.
pub(crate) fn vouch_helper_path(name: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".local").join("bin").join(name))
}

/// Check if a path is a symlink pointing to a vouch binary.
///
/// Returns `true` if the path is a symlink whose target filename is `vouch`.
pub(crate) fn is_vouch_symlink(path: &Path) -> bool {
    std::fs::read_link(path).is_ok_and(|target| {
        let s = target.to_string_lossy();
        s.ends_with("/vouch") || s.ends_with("\\vouch")
    })
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
    #[cfg_attr(
        not(unix),
        expect(unused_variables, reason = "parameter consumed only under cfg(unix)")
    )]
    vouch_path: &Path,
    symlink_path: &Path,
    #[cfg_attr(
        not(target_os = "windows"),
        expect(
            unused_variables,
            reason = "parameter consumed only under cfg(windows)"
        )
    )]
    windows_batch_content: &str,
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
        // A relative symlink target is stored verbatim and resolved by the
        // kernel relative to the symlink's *parent directory*, not via
        // $PATH lookup. `resolve_install_path()` has a Tier 3 fallback that
        // returns a bare `"vouch"` when `canonicalize()` fails — that works
        // for config files that exec via PATH, but produces a dangling
        // symlink here. Fail fast (#453).
        if !vouch_path.is_absolute() {
            anyhow::bail!(
                "refusing to create symlink at {} with relative target {:?}: \
                 a symlink stores its target verbatim and is resolved by the \
                 kernel relative to the symlink's directory, not via $PATH. \
                 Pass an absolute path to the vouch binary.",
                symlink_path.display(),
                vouch_path.display(),
            );
        }

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

        vouch_common::fs::atomic_write(&bat_path, windows_batch_content.as_bytes())
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
#[expect(
    unsafe_code,
    reason = "POSIX flock; safety documented inline above call site"
)]
pub(crate) fn flock_exclusive(file: &fs::File) -> Result<(), std::io::Error> {
    use std::os::unix::io::{AsFd, AsRawFd};
    let ret = unsafe { libc::flock(file.as_fd().as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    // -- vouch_helper_path --

    #[test]
    fn test_vouch_helper_path_ends_with_name() -> anyhow::Result<()> {
        let path = vouch_helper_path("keyring")?;
        let expected: PathBuf = [".local", "bin", "keyring"].iter().collect();
        assert!(path.ends_with(&expected), "got: {}", path.display());
        Ok(())
    }

    #[test]
    fn test_vouch_helper_path_all_helpers() -> anyhow::Result<()> {
        let names = [
            "keyring",
            "vouch-pnpm-tokenhelper",
            "docker-credential-vouch",
            "git-remote-codecommit",
        ];
        for name in names {
            let path = vouch_helper_path(name)?;
            assert_eq!(
                path.file_name().and_then(|n| n.to_str()),
                Some(name),
                "filename mismatch for {name}"
            );
            let parent = path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str());
            assert_eq!(parent, Some("bin"), "parent mismatch for {name}");
        }
        Ok(())
    }

    // -- is_vouch_symlink --

    #[cfg(unix)]
    #[test]
    fn test_is_vouch_symlink_pointing_to_vouch() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let vouch = dir.path().join("vouch");
        fs::write(&vouch, b"")?;
        let link = dir.path().join("keyring");
        std::os::unix::fs::symlink(&vouch, &link)?;
        assert!(is_vouch_symlink(&link));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_is_vouch_symlink_non_vouch_target() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let other = dir.path().join("keyring-real");
        fs::write(&other, b"")?;
        let link = dir.path().join("keyring");
        std::os::unix::fs::symlink(&other, &link)?;
        assert!(!is_vouch_symlink(&link));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_is_vouch_symlink_regular_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("vouch");
        fs::write(&file, b"")?;
        assert!(!is_vouch_symlink(&file));
        Ok(())
    }

    #[test]
    fn test_is_vouch_symlink_nonexistent_path() {
        let path = Path::new("/tmp/vouch_test_nonexistent_99999");
        assert!(!is_vouch_symlink(path));
    }

    #[cfg(unix)]
    #[test]
    fn test_is_vouch_symlink_dangling_link_to_vouch() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let link = dir.path().join("keyring");
        std::os::unix::fs::symlink("/nonexistent/path/vouch", &link)?;
        assert!(is_vouch_symlink(&link));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_is_vouch_symlink_dangling_link_not_vouch() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let link = dir.path().join("keyring");
        std::os::unix::fs::symlink("/nonexistent/other-binary", &link)?;
        assert!(!is_vouch_symlink(&link));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_is_vouch_symlink_target_contains_vouch_not_suffix() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let link = dir.path().join("keyring");
        std::os::unix::fs::symlink("/opt/vouch-server", &link)?;
        assert!(!is_vouch_symlink(&link));
        Ok(())
    }

    // -- create_symlink_with_fallback --

    /// Regression for #453: a relative target (e.g. bare `"vouch"`) would
    /// create a dangling symlink because the kernel resolves it relative
    /// to the symlink's directory, not via $PATH. Fail fast instead.
    #[cfg(unix)]
    #[test]
    fn test_create_symlink_rejects_relative_target() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let link = dir.path().join("keyring");
        let err = create_symlink_with_fallback(Path::new("vouch"), &link, "")
            .err()
            .ok_or_else(|| anyhow::anyhow!("expected error"))?;
        let msg = format!("{err}");
        assert!(msg.contains("relative"), "got: {msg}");
        // No dangling artifact must be left behind.
        assert!(!link.exists() && !link.is_symlink());
        Ok(())
    }

    /// Same guard for multi-segment relative paths (e.g. `bin/vouch`).
    #[cfg(unix)]
    #[test]
    fn test_create_symlink_rejects_relative_nested_target() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let link = dir.path().join("keyring");
        let result = create_symlink_with_fallback(Path::new("bin/vouch"), &link, "");
        assert!(result.is_err());
        assert!(!link.exists() && !link.is_symlink());
        Ok(())
    }

    /// Happy path: an absolute target still works.
    #[cfg(unix)]
    #[test]
    fn test_create_symlink_accepts_absolute_target() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("vouch");
        fs::write(&target, b"")?;
        let link = dir.path().join("keyring");
        create_symlink_with_fallback(&target, &link, "")?;
        assert!(link.is_symlink());
        assert_eq!(fs::read_link(&link)?, target);
        Ok(())
    }
}
