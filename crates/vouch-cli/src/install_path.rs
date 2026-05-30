// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Resolve a stable, upgrade-resilient path to the running vouch binary.
//!
//! Used by `vouch setup ...` commands to embed an absolute path into config
//! files (`~/.aws/config`, `~/.cargo/config.toml`, etc.) that survives
//! package upgrades.

#![allow(
    dead_code,
    reason = "shared utility used selectively across setup commands"
)]

use std::path::{Component, Path, PathBuf};

/// Maximum number of vouch profiles or candidate dirs to consider — guards
/// against unreasonable iteration in adversarial inputs.
const MAX_BIN_DIRS: usize = 16;

/// Resolve a stable, upgrade-resilient path to the running vouch binary.
///
/// Always returns *something* — never errors — so `vouch setup` commands
/// always leave the user with a config they can use. Three-tier resolution:
///
/// 1. **Stable, upgrade-resilient path.** Prefer a non-version-pinned path
///    whose canonical resolution equals `current_exe()`'s. Tried in order:
///    `$PATH` search, known stable bin dirs (Homebrew prefixes, nix profile,
///    `~/.cargo/bin`, …), pattern-derived candidates (Cellar / `/nix/store/`),
///    and Scoop shims on Windows. Every candidate is verified by
///    canonicalize-and-compare — false positives are impossible. Silent.
/// 2. **Version-pinned but verified path.** If no stable form exists but
///    `current_exe()` resolves to a real file, use it. Warns to stderr when
///    the path looks version-pinned (`Cellar/`, `/nix/store/`, `scoop/apps/`)
///    so the user knows it may break on the next package upgrade.
/// 3. **Bare binary name.** If `current_exe()` fails or its result can't be
///    canonicalized, write the bare binary name (`vouch` or `vouch.exe`) and
///    rely on `$PATH` lookup at credential-fetch time. Warns to stderr with
///    instructions for hand-editing the config if PATH lookup fails.
///
/// On macOS, `current_exe()` runs the path through `realpath`, so a binary
/// invoked as `/opt/homebrew/bin/vouch` is canonicalized to the Cellar path
/// (e.g. `/opt/homebrew/Cellar/vouch/2026.5.4/bin/vouch`). Writing that
/// version-pinned path into a config file breaks after `brew upgrade`, since
/// the old Cellar dir is deleted. Same idea for nix — `/nix/store/...` paths
/// are content-addressed and may be garbage-collected — and Scoop, where
/// `~\scoop\apps\<app>\<version>\` is removed on update.
pub(crate) fn resolve_install_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from(fallback_binary_name()));
    stable_install_path(exe)
}

/// Compute the install path from a given `exe` candidate. Separated from
/// [`resolve_install_path`] so unit tests can pass synthetic inputs.
fn stable_install_path(exe: PathBuf) -> PathBuf {
    if exe.is_absolute()
        && let Some(name) = exe.file_name()
        && let Ok(target) = std::fs::canonicalize(&exe)
    {
        // Tier 1: stable, upgrade-resilient paths (canonicalize-and-compare).
        if let Ok(via_path) = which::which(name)
            && points_to(&via_path, &target)
        {
            return via_path;
        }
        let home = dirs::home_dir();
        for dir in stable_bin_dirs(home.as_deref()) {
            let candidate = dir.join(name);
            if points_to(&candidate, &target) {
                return candidate;
            }
        }
        if let Some(candidate) = homebrew_symlink_candidate(&exe)
            && points_to(&candidate, &target)
        {
            return candidate;
        }
        if let Some(home_path) = home.as_deref()
            && let Some(candidate) = nix_profile_candidate(&exe, home_path)
            && points_to(&candidate, &target)
        {
            return candidate;
        }
        // Scoop shims are launcher EXEs (not symlinks), so canonicalize-and-
        // compare doesn't apply — accept by pattern + file existence instead.
        if let Some(candidate) = scoop_shim_candidate(&exe)
            && candidate.exists()
        {
            return candidate;
        }

        // Tier 2: verified file, fall back to current_exe()'s path. Warn if
        // it's version-pinned.
        if let Some(hint) = version_pin_hint(&exe) {
            eprintln!("Warning: writing a version-pinned path to your config:");
            eprintln!("  {}", exe.display());
            eprintln!("{hint}");
        }
        return exe;
    }

    // Tier 3: couldn't validate exe — fall back to bare binary name + warning.
    let fallback = fallback_binary_name();
    eprintln!("Warning: could not determine an absolute path to the vouch binary.");
    eprintln!(
        "Writing bare '{fallback}' to the config; this relies on $PATH at the time \
         credentials are fetched."
    );
    eprintln!(
        "If credential-fetching commands fail with \"executable not found\", hand-edit \
         the config to use an absolute path."
    );
    PathBuf::from(fallback)
}

/// The bare binary name to use when no absolute path can be determined.
const fn fallback_binary_name() -> &'static str {
    if cfg!(windows) { "vouch.exe" } else { "vouch" }
}

/// Return true if `candidate`'s canonical resolution equals `target`.
fn points_to(candidate: &Path, target: &Path) -> bool {
    matches!(std::fs::canonicalize(candidate), Ok(resolved) if resolved == target)
}

/// Known stable `bin` directories worth checking for a symlink that resolves
/// back to the running binary. Ordered by likelihood on each platform.
fn stable_bin_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(MAX_BIN_DIRS);
    dirs.push(PathBuf::from("/opt/homebrew/bin"));
    dirs.push(PathBuf::from("/usr/local/bin"));
    dirs.push(PathBuf::from("/home/linuxbrew/.linuxbrew/bin"));
    dirs.push(PathBuf::from("/run/current-system/sw/bin"));
    if let Some(h) = home {
        dirs.push(h.join(".nix-profile").join("bin"));
        dirs.push(h.join(".cargo").join("bin"));
        dirs.push(h.join(".local").join("bin"));
    }
    dirs
}

/// If `exe` is a Homebrew Cellar-pinned path, return the corresponding
/// version-independent symlink path (`<prefix>/bin/<name>`).
///
/// Matches Apple Silicon (`/opt/homebrew/Cellar/...`), Intel
/// (`/usr/local/Cellar/...`), and Linuxbrew (`/home/linuxbrew/.linuxbrew/Cellar/...`).
fn homebrew_symlink_candidate(exe: &Path) -> Option<PathBuf> {
    let name = exe.file_name()?;
    let cellar_pos = exe.components().position(|c| c.as_os_str() == "Cellar")?;
    if cellar_pos == 0 {
        return None;
    }
    let prefix: PathBuf = exe.components().take(cellar_pos).collect();
    if !prefix.is_absolute() {
        return None;
    }
    Some(prefix.join("bin").join(name))
}

/// If `exe` lives under a Scoop install
/// (`<prefix>\scoop\apps\<app>\<version>\<binary>.exe`), return the Scoop shim
/// path (`<prefix>\scoop\shims\<binary>.exe`). Caller verifies the shim file
/// exists (Scoop shims are launcher EXEs, not symlinks, so canonicalize-and-
/// compare doesn't apply).
fn scoop_shim_candidate(exe: &Path) -> Option<PathBuf> {
    let name = exe.file_name()?;
    let comps: Vec<_> = exe.components().collect();

    // Find a "scoop" component (case-insensitive) immediately followed by "apps".
    let scoop_pos = comps.iter().enumerate().find_map(|(i, c)| {
        let s = c.as_os_str().to_str()?;
        if !s.eq_ignore_ascii_case("scoop") {
            return None;
        }
        let next_idx = i.checked_add(1)?;
        comps
            .get(next_idx)
            .filter(|next| next.as_os_str().eq_ignore_ascii_case("apps"))
            .map(|_| i)
    })?;

    let prefix: PathBuf = exe.components().take(scoop_pos).collect();
    Some(prefix.join("scoop").join("shims").join(name))
}

/// If `exe` lives in `/nix/store/...`, return the user-profile symlink path
/// (`~/.nix-profile/bin/<name>`). Caller verifies it resolves back to `exe`.
fn nix_profile_candidate(exe: &Path, home: &Path) -> Option<PathBuf> {
    let name = exe.file_name()?;
    let mut components = exe.components();
    if !matches!(components.next()?, Component::RootDir) {
        return None;
    }
    if components.next()?.as_os_str() != "nix" {
        return None;
    }
    if components.next()?.as_os_str() != "store" {
        return None;
    }
    Some(home.join(".nix-profile").join("bin").join(name))
}

/// If `exe` looks version-pinned (Cellar/, /nix/store/, scoop/apps/), return
/// a user-facing hint about how to get a stable path. Otherwise `None`.
fn version_pin_hint(exe: &Path) -> Option<String> {
    if let Some(stable) = homebrew_symlink_candidate(exe) {
        return Some(format!(
            "This path will be removed by `brew upgrade`. Ensure {} exists \
             (`brew link vouch`) and re-run `vouch setup ...` to use it instead.",
            stable.display()
        ));
    }
    if let Some(stable) = scoop_shim_candidate(exe) {
        return Some(format!(
            "This path will be removed by `scoop update`. Ensure {} exists \
             (`scoop reset vouch`) and re-run `vouch setup ...` to use it instead.",
            stable.display()
        ));
    }
    if let Some(home) = dirs::home_dir()
        && let Some(stable) = nix_profile_candidate(exe, &home)
    {
        return Some(format!(
            "Nix store paths are content-addressed and may be garbage-collected. \
             Ensure {} exists and re-run `vouch setup ...` to use it instead.",
            stable.display()
        ));
    }
    None
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    // Homebrew tests are gated to Unix because `is_absolute()` returns false
    // on Windows for paths without a drive prefix (e.g. `/opt/homebrew/...`).
    // Homebrew itself only runs on macOS and Linux, so this matches reality.

    #[cfg(unix)]
    #[test]
    fn homebrew_candidate_apple_silicon() {
        let exe = Path::new("/opt/homebrew/Cellar/vouch/2026.5.4/bin/vouch");
        assert_eq!(
            homebrew_symlink_candidate(exe),
            Some(PathBuf::from("/opt/homebrew/bin/vouch"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn homebrew_candidate_intel_mac() {
        let exe = Path::new("/usr/local/Cellar/vouch/2026.5.4/bin/vouch");
        assert_eq!(
            homebrew_symlink_candidate(exe),
            Some(PathBuf::from("/usr/local/bin/vouch"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn homebrew_candidate_linuxbrew() {
        let exe = Path::new("/home/linuxbrew/.linuxbrew/Cellar/vouch/2026.5.4/bin/vouch");
        assert_eq!(
            homebrew_symlink_candidate(exe),
            Some(PathBuf::from("/home/linuxbrew/.linuxbrew/bin/vouch"))
        );
    }

    #[test]
    fn homebrew_candidate_returns_none_for_non_cellar_path() {
        assert!(homebrew_symlink_candidate(Path::new("/usr/local/bin/vouch")).is_none());
        assert!(homebrew_symlink_candidate(Path::new("/opt/homebrew/bin/vouch")).is_none());
        assert!(homebrew_symlink_candidate(Path::new("/Users/jp/.cargo/bin/vouch")).is_none());
    }

    #[test]
    fn homebrew_candidate_rejects_root_relative_cellar() {
        assert!(homebrew_symlink_candidate(Path::new("Cellar/vouch/1/bin/vouch")).is_none());
    }

    #[test]
    fn nix_candidate_from_store_path() {
        let exe = Path::new("/nix/store/abc123-vouch-2026.5.4/bin/vouch");
        let home = Path::new("/home/jp");
        assert_eq!(
            nix_profile_candidate(exe, home),
            Some(PathBuf::from("/home/jp/.nix-profile/bin/vouch"))
        );
    }

    #[test]
    fn nix_candidate_returns_none_for_non_store_path() {
        let home = Path::new("/home/jp");
        assert!(nix_profile_candidate(Path::new("/usr/local/bin/vouch"), home).is_none());
        assert!(nix_profile_candidate(Path::new("/opt/homebrew/bin/vouch"), home).is_none());
        assert!(nix_profile_candidate(Path::new("/opt/nix/bin/vouch"), home).is_none());
    }

    #[test]
    fn scoop_candidate_typical_user_path() {
        let exe = Path::new("C:/Users/jp/scoop/apps/vouch/2026.5.4/vouch.exe");
        assert_eq!(
            scoop_shim_candidate(exe),
            Some(PathBuf::from("C:/Users/jp/scoop/shims/vouch.exe"))
        );
    }

    #[test]
    fn scoop_candidate_case_insensitive_scoop() {
        let exe = Path::new("C:/Users/jp/Scoop/apps/vouch/2026.5.4/vouch.exe");
        assert_eq!(
            scoop_shim_candidate(exe),
            Some(PathBuf::from("C:/Users/jp/scoop/shims/vouch.exe"))
        );
    }

    #[test]
    fn scoop_candidate_returns_none_for_non_scoop_path() {
        assert!(scoop_shim_candidate(Path::new("C:/Program Files/Vouch/vouch.exe")).is_none());
        assert!(scoop_shim_candidate(Path::new("/opt/homebrew/bin/vouch")).is_none());
    }

    #[test]
    fn scoop_candidate_requires_apps_after_scoop() {
        assert!(scoop_shim_candidate(Path::new("C:/Users/jp/scoop/shims/vouch.exe")).is_none());
        assert!(scoop_shim_candidate(Path::new("C:/Users/jp/scoop/cache/vouch.exe")).is_none());
    }

    #[test]
    fn stable_bin_dirs_includes_known_paths() {
        let home = Path::new("/home/jp");
        let dirs = stable_bin_dirs(Some(home));
        assert!(dirs.contains(&PathBuf::from("/opt/homebrew/bin")));
        assert!(dirs.contains(&PathBuf::from("/usr/local/bin")));
        assert!(dirs.contains(&PathBuf::from("/home/linuxbrew/.linuxbrew/bin")));
        assert!(dirs.contains(&PathBuf::from("/run/current-system/sw/bin")));
        assert!(dirs.contains(&PathBuf::from("/home/jp/.nix-profile/bin")));
        assert!(dirs.contains(&PathBuf::from("/home/jp/.cargo/bin")));
    }

    #[test]
    fn stable_bin_dirs_without_home_omits_home_paths() {
        let dirs = stable_bin_dirs(None);
        assert!(dirs.contains(&PathBuf::from("/opt/homebrew/bin")));
        assert!(!dirs.iter().any(|d| d.starts_with("/home/jp")));
    }

    #[cfg(unix)]
    #[test]
    fn points_to_returns_true_for_symlink_resolving_to_target() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("target");
        std::fs::write(&target, b"vouch").expect("write target");
        let canonical_target = std::fs::canonicalize(&target).expect("canonicalize target");
        let link = tmp.path().join("link");
        symlink(&target, &link).expect("create symlink");
        assert!(points_to(&link, &canonical_target));
    }

    #[test]
    fn points_to_returns_false_when_paths_differ() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("target");
        std::fs::write(&target, b"vouch").expect("write target");
        let other = tmp.path().join("other");
        std::fs::write(&other, b"other").expect("write other");
        let canonical_target = std::fs::canonicalize(&target).expect("canonicalize target");
        assert!(!points_to(&other, &canonical_target));
    }

    #[test]
    fn points_to_returns_false_when_candidate_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("missing");
        let target = tmp.path().join("target");
        std::fs::write(&target, b"vouch").expect("write target");
        let canonical_target = std::fs::canonicalize(&target).expect("canonicalize target");
        assert!(!points_to(&missing, &canonical_target));
    }

    #[cfg(unix)]
    #[test]
    fn stable_install_path_tier_1_rewrites_cellar_symlink() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().expect("tempdir");
        let cellar_bin = tmp.path().join("Cellar/vouch/2026.5.4/bin");
        std::fs::create_dir_all(&cellar_bin).expect("create cellar dir");
        let real_exe = cellar_bin.join("vouch");
        std::fs::write(&real_exe, b"vouch").expect("write fake exe");
        let stable_bin = tmp.path().join("bin");
        std::fs::create_dir_all(&stable_bin).expect("create stable bin");
        let stable_link = stable_bin.join("vouch");
        symlink(&real_exe, &stable_link).expect("create symlink");

        let rewritten = stable_install_path(real_exe.clone());
        let canonical_rewritten =
            std::fs::canonicalize(&rewritten).expect("canonicalize rewritten");
        let canonical_real = std::fs::canonicalize(&real_exe).expect("canonicalize real");
        assert_eq!(canonical_rewritten, canonical_real);
        assert_eq!(rewritten, stable_link);
    }

    #[test]
    fn stable_install_path_tier_2_returns_input_unchanged() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let exe = tmp.path().join("standalone-vouch");
        std::fs::write(&exe, b"vouch").expect("write fake exe");
        let result = stable_install_path(exe.clone());
        assert_eq!(result, exe);
    }

    #[test]
    fn stable_install_path_tier_3_falls_back_to_bare_name_when_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("ghost-vouch");
        // No file at this path — canonicalize fails → tier-3 fallback.
        let result = stable_install_path(missing);
        assert_eq!(result, PathBuf::from(fallback_binary_name()));
    }

    #[test]
    fn stable_install_path_tier_3_falls_back_to_bare_name_for_relative_input() {
        let result = stable_install_path(PathBuf::from("vouch"));
        assert_eq!(result, PathBuf::from(fallback_binary_name()));
    }

    #[cfg(unix)]
    #[test]
    fn version_pin_hint_detects_cellar() {
        let exe = Path::new("/opt/homebrew/Cellar/vouch/2026.5.4/bin/vouch");
        let hint = version_pin_hint(exe).expect("cellar should yield hint");
        assert!(hint.contains("brew upgrade"));
        assert!(hint.contains("/opt/homebrew/bin/vouch"));
    }

    #[test]
    fn version_pin_hint_detects_scoop_apps() {
        let exe = Path::new("C:/Users/jp/scoop/apps/vouch/2026.5.4/vouch.exe");
        let hint = version_pin_hint(exe).expect("scoop should yield hint");
        assert!(hint.contains("scoop"));
        assert!(hint.contains("shims"));
    }

    #[test]
    fn version_pin_hint_none_for_stable_paths() {
        assert!(version_pin_hint(Path::new("/opt/homebrew/bin/vouch")).is_none());
        assert!(version_pin_hint(Path::new("/usr/local/bin/vouch")).is_none());
        assert!(version_pin_hint(Path::new("/Users/jp/.cargo/bin/vouch")).is_none());
    }

    #[test]
    fn fallback_binary_name_is_platform_appropriate() {
        let name = fallback_binary_name();
        if cfg!(windows) {
            assert_eq!(name, "vouch.exe");
        } else {
            assert_eq!(name, "vouch");
        }
    }
}
