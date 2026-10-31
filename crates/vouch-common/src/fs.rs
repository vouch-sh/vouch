// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Atomic, permission-aware file writes shared across the CLI and agent.

use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Unix file permission mode for atomic writes.
///
/// On non-Unix platforms, this value is accepted but ignored.
pub enum FileMode {
    /// Use default permissions (no explicit chmod).
    Default,
    /// Restrictive: owner read/write only (0o600 on Unix).
    Secure,
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
///
/// When `path` is a symlink, the file at the end of the link is replaced and
/// the link is kept (see [`write_target`]).
fn atomic_write_impl(path: &Path, content: &[u8], mode: FileMode) -> Result<()> {
    let target = write_target(path)?;
    let parent = target
        .parent()
        .context("file path has no parent directory")?;

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

    #[expect(
        clippy::disallowed_methods,
        reason = "the sanctioned rename: `target` is the end of the symlink chain"
    )]
    tmp.persist(&target)
        .with_context(|| format!("failed to persist temp file to {}", target.display()))?;

    Ok(())
}

/// Linux's `MAXSYMLINKS`: a longer chain is treated as a loop.
const MAX_SYMLINK_HOPS: usize = 40;

/// The file a write to `path` replaces: `path` itself, or the end of its
/// symlink chain.
///
/// A rename over a symlink replaces the link, so a dotfile managed by stow,
/// chezmoi, or home-manager would become a regular file and stop tracking its
/// source. A dangling link resolves to the path it names, so the write creates
/// that file, as `std::fs::write` does.
fn write_target(path: &Path) -> Result<PathBuf> {
    let mut target = path.to_path_buf();
    for _ in 0..MAX_SYMLINK_HOPS {
        let is_link = fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink());
        if !is_link {
            return Ok(target);
        }
        let link = fs::read_link(&target)
            .with_context(|| format!("failed to read symlink {}", target.display()))?;
        target = match target.parent() {
            Some(dir) => dir.join(link),
            None => link,
        };
    }
    bail!("too many levels of symbolic links at {}", path.display())
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

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_write_secure_creates_file_with_content() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("nested").join("secret.txt");
        atomic_write_secure(&path, b"hunter2")?;
        assert_eq!(fs::read(&path)?, b"hunter2");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_atomic_write_secure_sets_0600() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("secret.txt");
        atomic_write_secure(&path, b"data")?;
        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
        Ok(())
    }

    #[test]
    fn test_write_secure_file_accepts_str() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("cert.pub");
        write_secure_file(&path, "ssh-ed25519 AAAA...\n")?;
        assert_eq!(fs::read_to_string(&path)?, "ssh-ed25519 AAAA...\n");
        Ok(())
    }

    #[test]
    fn test_atomic_write_replaces_regular_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config");
        fs::write(&path, b"old")?;
        atomic_write(&path, b"new")?;
        assert_eq!(fs::read(&path)?, b"new");
        assert!(!fs::symlink_metadata(&path)?.file_type().is_symlink());
        Ok(())
    }

    #[cfg(unix)]
    fn assert_link(link: &Path, points_at: &Path) -> Result<()> {
        assert!(
            fs::symlink_metadata(link)?.file_type().is_symlink(),
            "{} must still be a symlink",
            link.display()
        );
        assert_eq!(fs::read_link(link)?, points_at, "link target unchanged");
        Ok(())
    }

    // A dotfiles manager links `~/.ssh/config` into a repository. The write
    // lands in the repository file and the link survives.
    #[cfg(unix)]
    #[test]
    fn test_atomic_write_keeps_absolute_symlink() -> Result<()> {
        use std::os::unix::fs::symlink;
        let home = tempfile::tempdir()?;
        let dotfiles = tempfile::tempdir()?;
        let source = dotfiles.path().join("ssh-config");
        fs::write(&source, b"old")?;
        let link = home.path().join("config");
        symlink(&source, &link)?;

        atomic_write(&link, b"new")?;

        assert_link(&link, &source)?;
        assert_eq!(fs::read(&source)?, b"new");
        Ok(())
    }

    // A relative link target is relative to the link's directory, not the
    // process's working directory.
    #[cfg(unix)]
    #[test]
    fn test_atomic_write_secure_keeps_relative_symlink() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir()?;
        fs::create_dir(dir.path().join("dotfiles"))?;
        let source = dir.path().join("dotfiles").join("npmrc");
        fs::write(&source, b"old")?;
        let link = dir.path().join(".npmrc");
        symlink(Path::new("dotfiles/npmrc"), &link)?;

        atomic_write_secure(&link, b"new")?;

        assert_link(&link, Path::new("dotfiles/npmrc"))?;
        assert_eq!(fs::read(&source)?, b"new");
        let mode = fs::metadata(&source)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secure mode applies to the real file");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_atomic_write_follows_symlink_chain() -> Result<()> {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir()?;
        let source = dir.path().join("real");
        fs::write(&source, b"old")?;
        let middle = dir.path().join("middle");
        symlink(&source, &middle)?;
        let link = dir.path().join("config");
        symlink(&middle, &link)?;

        atomic_write(&link, b"new")?;

        assert_link(&link, &middle)?;
        assert_link(&middle, &source)?;
        assert_eq!(fs::read(&source)?, b"new");
        Ok(())
    }

    // A dangling link names the file to create, as `std::fs::write` treats it.
    #[cfg(unix)]
    #[test]
    fn test_atomic_write_creates_dangling_symlink_target() -> Result<()> {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir()?;
        let source = dir.path().join("dotfiles").join("aws-config");
        let link = dir.path().join("config");
        symlink(&source, &link)?;

        atomic_write(&link, b"new")?;

        assert_link(&link, &source)?;
        assert_eq!(fs::read(&source)?, b"new");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_atomic_write_rejects_symlink_loop() -> Result<()> {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir()?;
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        symlink(&b, &a)?;
        symlink(&a, &b)?;

        let err = atomic_write(&a, b"new").err().context("a loop must fail")?;

        assert!(
            err.to_string()
                .contains("too many levels of symbolic links"),
            "{err}"
        );
        assert_link(&a, &b)?;
        assert_link(&b, &a)?;
        Ok(())
    }
}
