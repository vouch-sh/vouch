// SPDX-License-Identifier: Apache-2.0 OR MIT
//! XDG Base Directory resolution for vouch-owned files.
//!
//! This module is the single source of truth for every path vouch reads or
//! writes under the user's home directory. It follows the
//! [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/)
//! and resolves XDG-style paths on **all** platforms — including macOS, where
//! `~/.config` is used rather than `~/Library/Application Support`. This
//! matches the convention of modern developer CLIs (`gh`, `git`, `starship`).
//!
//! | Data | Base (env → default) | Path |
//! |------|----------------------|------|
//! | config | `XDG_CONFIG_HOME` → `~/.config` | `<base>/vouch/` |
//! | state (cookies, audit log) | `XDG_STATE_HOME` → `~/.local/state` | `<base>/vouch/` |
//! | data (keyring fallback key) | `XDG_DATA_HOME` → `~/.local/share` | `<base>/vouch/` |
//! | cache (pid, agent log) | `XDG_CACHE_HOME` → `~/.cache` | `<base>/vouch/` |
//! | runtime (sockets) | `XDG_RUNTIME_DIR` → cache fallback | `<base>/vouch/` |
//!
//! Per the spec, `XDG_*` values that are not absolute paths are ignored and the
//! default is used instead.
//!
//! Earlier versions of vouch stored everything flat in `~/.vouch/`.
//! [`migrate_legacy_layout`] relocates those files into the directories above
//! on first run.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Application sub-directory created under each XDG base directory.
const APP_DIR: &str = "vouch";

/// Resolve an XDG base directory from an env value and home directory.
///
/// If `env_val` is an absolute path it is used verbatim; otherwise the base is
/// `home` joined with `default_components`. Returns `None` only when a home
/// directory is required (env unset/relative) but cannot be determined.
fn resolve_base(
    env_val: Option<OsString>,
    home: Option<&Path>,
    default_components: &[&str],
) -> Option<PathBuf> {
    if let Some(val) = env_val {
        let candidate = PathBuf::from(val);
        if candidate.is_absolute() {
            return Some(candidate);
        }
    }
    let mut base = home?.to_path_buf();
    for component in default_components {
        base.push(component);
    }
    Some(base)
}

/// Resolve `<base>/vouch` for the given XDG variable and default location.
fn vouch_subdir(var: &str, default_components: &[&str]) -> Option<PathBuf> {
    let base = resolve_base(
        std::env::var_os(var),
        dirs::home_dir().as_deref(),
        default_components,
    )?;
    Some(base.join(APP_DIR))
}

/// Configuration directory: `<XDG_CONFIG_HOME|~/.config>/vouch`.
#[must_use]
pub fn config_dir() -> Option<PathBuf> {
    vouch_subdir("XDG_CONFIG_HOME", &[".config"])
}

/// State directory: `<XDG_STATE_HOME|~/.local/state>/vouch`.
///
/// Holds files that should persist between runs but are not user-edited
/// configuration: session cookies and the audit log.
#[must_use]
pub fn state_dir() -> Option<PathBuf> {
    vouch_subdir("XDG_STATE_HOME", &[".local", "state"])
}

/// Data directory: `<XDG_DATA_HOME|~/.local/share>/vouch`.
#[must_use]
pub fn data_dir() -> Option<PathBuf> {
    vouch_subdir("XDG_DATA_HOME", &[".local", "share"])
}

/// Cache directory: `<XDG_CACHE_HOME|~/.cache>/vouch`.
#[must_use]
pub fn cache_dir() -> Option<PathBuf> {
    vouch_subdir("XDG_CACHE_HOME", &[".cache"])
}

/// Runtime directory: `<XDG_RUNTIME_DIR>/vouch`, used for Unix sockets.
///
/// `XDG_RUNTIME_DIR` is the correct home for sockets — it is a private,
/// `0700`, user-owned tmpfs cleared on logout. It is, however, only set on
/// Linux sessions managed by a login manager; on macOS and headless logins it
/// is absent, so we fall back to the cache directory (a short path that avoids
/// the ~104-byte `sun_path` limit on macOS).
#[must_use]
pub fn runtime_dir() -> Option<PathBuf> {
    if let Some(val) = std::env::var_os("XDG_RUNTIME_DIR") {
        let candidate = PathBuf::from(val);
        if candidate.is_absolute() {
            return Some(candidate.join(APP_DIR));
        }
    }
    cache_dir()
}

/// Path to the CLI configuration file (`<config>/vouch/config.json`).
#[must_use]
pub fn config_file() -> Option<PathBuf> {
    config_dir().map(|d| d.join("config.json"))
}

/// Path to the session cookie file (`<state>/vouch/cookie.txt`).
#[must_use]
pub fn cookie_file() -> Option<PathBuf> {
    state_dir().map(|d| d.join("cookie.txt"))
}

/// Path to the audit log (`<state>/vouch/audit.log`).
#[must_use]
pub fn audit_log_file() -> Option<PathBuf> {
    state_dir().map(|d| d.join("audit.log"))
}

/// Path to the FAPI client key fallback file (`<data>/vouch/client_key.json`).
///
/// The OS keychain remains the primary store; this file is only used when the
/// keychain is unavailable (CI, headless).
#[must_use]
pub fn client_key_file() -> Option<PathBuf> {
    data_dir().map(|d| d.join("client_key.json"))
}

/// Create `dir` (and parents) with owner-only `0700` permissions on Unix.
pub(crate) fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Move `from` to `to`, preserving permission bits.
///
/// Prefers an atomic `rename`. Falls back to copy + remove *only* when the
/// source and destination live on different filesystems (`EXDEV`). Any other
/// `rename` failure (permissions, transient I/O) is propagated so the source is
/// never deleted after a failed or partial move.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    if let Some(parent) = to.parent() {
        ensure_private_dir(parent)?;
    }
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            // Cross-device rename: copy (preserves mode bits) then remove.
            std::fs::copy(from, to)?;
            std::fs::remove_file(from)
        }
        Err(e) => Err(e),
    }
}

/// Core migration routine: move each `(filename, destination)` out of
/// `legacy_dir`, skipping files that are absent or whose destination already
/// exists. Returns `true` if anything was moved.
fn migrate_layout(legacy_dir: &Path, dests: &[(&str, PathBuf)]) -> bool {
    let mut moved_any = false;
    for (name, dest) in dests {
        let src = legacy_dir.join(name);
        if !src.exists() || dest.exists() {
            continue;
        }
        match move_file(&src, dest) {
            Ok(()) => moved_any = true,
            Err(e) => {
                tracing::warn!(
                    "failed to migrate {} → {}: {e}",
                    src.display(),
                    dest.display()
                );
            }
        }
    }
    moved_any
}

/// Migrate legacy file layouts into the XDG directories.
///
/// Idempotent and best-effort. Covers two cases:
/// 1. The flat `~/.vouch/` directory used by older versions (config, cookie,
///    audit log, client key).
/// 2. The cache directory: older versions resolved `agent.pid`/`agent.log`
///    via `dirs::cache_dir()` (e.g. `~/Library/Caches` on macOS), which differs
///    from the XDG cache dir now used. Migrating the PID file lets an upgraded
///    agent detect a still-running old agent instead of starting a second one.
///
/// Sockets are intentionally *not* moved — they are runtime artifacts that are
/// recreated, and a running agent may still hold them. Safe to call
/// concurrently from the CLI and agent: each move is an atomic `rename` guarded
/// by a destination-exists check.
pub fn migrate_legacy_layout() {
    migrate_legacy_vouch_dir();
    migrate_legacy_cache_dir();
}

/// Migrate the legacy flat `~/.vouch/` directory (case 1 above).
fn migrate_legacy_vouch_dir() {
    let Some(home) = dirs::home_dir() else {
        return;
    };
    let legacy_dir = home.join(".vouch");
    if !legacy_dir.exists() {
        return;
    }

    let Some(state) = state_dir() else { return };
    let mut dests: Vec<(&str, PathBuf)> = Vec::new();
    if let Some(p) = config_file() {
        dests.push(("config.json", p));
    }
    if let Some(p) = cookie_file() {
        dests.push(("cookie.txt", p));
    }
    dests.push(("audit.log", state.join("audit.log")));
    dests.push(("audit.log.1", state.join("audit.log.1")));
    if let Some(p) = client_key_file() {
        dests.push(("client_key.json", p));
    }

    let moved = migrate_layout(&legacy_dir, &dests);

    // Best-effort cleanup: remove the legacy directory if it is now empty.
    // `remove_dir` fails (and is ignored) when sockets or other files remain.
    let _empty_removed = std::fs::remove_dir(&legacy_dir);

    if moved {
        eprintln!(
            "vouch: migrated files from {} to XDG base directories (~/.config/vouch, \
             ~/.local/state/vouch, ~/.local/share/vouch).",
            legacy_dir.display()
        );
    }
}

/// The cache directory used by older versions, via `dirs::cache_dir()`.
///
/// Equals [`cache_dir`] on Linux, but differs on macOS (`~/Library/Caches`) and
/// Windows (`%LOCALAPPDATA%`).
fn legacy_cache_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|c| c.join(APP_DIR))
}

/// Migrate `agent.pid`/`agent.log` from the legacy cache dir (case 2 above).
///
/// A no-op when the legacy and current cache directories are the same (Linux)
/// or when the legacy directory does not exist.
fn migrate_legacy_cache_dir() {
    let (Some(legacy), Some(new)) = (legacy_cache_dir(), cache_dir()) else {
        return;
    };
    migrate_cache_files(&legacy, &new);
}

/// Core cache migration: move `agent.pid`/`agent.log` from `legacy_cache` to
/// `new_cache` when the two differ. Returns `true` if anything was moved.
fn migrate_cache_files(legacy_cache: &Path, new_cache: &Path) -> bool {
    if legacy_cache == new_cache || !legacy_cache.exists() {
        return false;
    }
    let dests = [
        ("agent.pid", new_cache.join("agent.pid")),
        ("agent.log", new_cache.join("agent.log")),
    ];
    migrate_layout(legacy_cache, &dests)
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn resolve_base_prefers_absolute_env() {
        let home = PathBuf::from("/home/alice");
        // `is_absolute()` is platform-specific: on Windows a path needs a drive
        // (or UNC) prefix, so use a platform-appropriate absolute path.
        #[cfg(unix)]
        let abs = "/custom/config";
        #[cfg(windows)]
        let abs = r"C:\custom\config";
        let got = resolve_base(Some(OsString::from(abs)), Some(&home), &[".config"]);
        assert_eq!(got, Some(PathBuf::from(abs)));
    }

    #[test]
    fn resolve_base_ignores_relative_env() {
        let home = PathBuf::from("/home/alice");
        let got = resolve_base(
            Some(OsString::from("relative/path")),
            Some(&home),
            &[".config"],
        );
        assert_eq!(got, Some(PathBuf::from("/home/alice/.config")));
    }

    #[test]
    fn resolve_base_uses_default_when_env_unset() {
        let home = PathBuf::from("/home/alice");
        let got = resolve_base(None, Some(&home), &[".local", "state"]);
        assert_eq!(got, Some(PathBuf::from("/home/alice/.local/state")));
    }

    #[test]
    fn resolve_base_none_without_home() {
        assert_eq!(resolve_base(None, None, &[".config"]), None);
    }

    #[test]
    fn migrate_moves_files_and_preserves_mode() -> std::io::Result<()> {
        let tmp = tempfile::tempdir()?;
        let legacy = tmp.path().join(".vouch");
        std::fs::create_dir_all(&legacy)?;
        std::fs::write(legacy.join("config.json"), b"{}")?;
        std::fs::write(legacy.join("cookie.txt"), b"cookie")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                legacy.join("config.json"),
                std::fs::Permissions::from_mode(0o600),
            )?;
        }

        let config_dest = tmp.path().join(".config/vouch/config.json");
        let cookie_dest = tmp.path().join(".local/state/vouch/cookie.txt");
        let dests = vec![
            ("config.json", config_dest.clone()),
            ("cookie.txt", cookie_dest.clone()),
        ];

        assert!(migrate_layout(&legacy, &dests));
        assert!(config_dest.exists());
        assert!(cookie_dest.exists());
        assert!(!legacy.join("config.json").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&config_dest)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "config mode should survive migration");
            let dir_mode = std::fs::metadata(config_dest.parent().expect("parent"))?
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700, "created dir should be 0700");
        }

        // Second run is a no-op.
        assert!(!migrate_layout(&legacy, &dests));
        Ok(())
    }

    #[test]
    fn migrate_skips_when_destination_exists() -> std::io::Result<()> {
        let tmp = tempfile::tempdir()?;
        let legacy = tmp.path().join(".vouch");
        std::fs::create_dir_all(&legacy)?;
        std::fs::write(legacy.join("config.json"), b"new")?;

        let dest = tmp.path().join(".config/vouch/config.json");
        std::fs::create_dir_all(dest.parent().expect("parent"))?;
        std::fs::write(&dest, b"existing")?;

        let dests = vec![("config.json", dest.clone())];
        assert!(!migrate_layout(&legacy, &dests));
        // Existing destination is left untouched; source remains.
        assert_eq!(std::fs::read(&dest)?, b"existing");
        assert!(legacy.join("config.json").exists());
        Ok(())
    }

    #[test]
    fn migrate_cache_files_moves_pid_and_log() -> std::io::Result<()> {
        let tmp = tempfile::tempdir()?;
        let legacy = tmp.path().join("Library/Caches/vouch");
        let new = tmp.path().join(".cache/vouch");
        std::fs::create_dir_all(&legacy)?;
        std::fs::write(legacy.join("agent.pid"), b"4242")?;
        std::fs::write(legacy.join("agent.log"), b"log")?;

        assert!(migrate_cache_files(&legacy, &new));
        assert_eq!(std::fs::read(new.join("agent.pid"))?, b"4242");
        assert!(new.join("agent.log").exists());
        assert!(!legacy.join("agent.pid").exists());
        Ok(())
    }

    #[test]
    fn migrate_cache_files_noop_when_dirs_equal() -> std::io::Result<()> {
        let tmp = tempfile::tempdir()?;
        let cache = tmp.path().join(".cache/vouch");
        std::fs::create_dir_all(&cache)?;
        std::fs::write(cache.join("agent.pid"), b"1")?;

        // Linux case: legacy and current cache dirs are identical -> no move.
        assert!(!migrate_cache_files(&cache, &cache));
        assert!(cache.join("agent.pid").exists());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn ensure_private_dir_sets_owner_only_permissions() -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("state/vouch");

        ensure_private_dir(&dir)?;

        let mode = std::fs::metadata(&dir)?.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "directory should be owner-only, got {mode:04o}"
        );
        Ok(())
    }
}
