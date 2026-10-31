// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo config file (`$CARGO_HOME/config` or `$CARGO_HOME/config.toml`)
//! parsing utilities.
//!
//! Uses proper TOML parsing instead of fragile string manipulation.
//! This preserves existing configuration when adding/modifying settings.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use toml_edit::{Array, DocumentMut, Item, Table, Value};
use vouch_cli::{tr, tr_args};
use vouch_common::{fs, paths};

/// Cargo config file parser and writer.
///
/// Uses toml_edit to properly parse and modify the Cargo config file,
/// preserving existing sections, keys, and formatting when making changes.
pub(crate) struct CargoConfig {
    doc: DocumentMut,
    path: PathBuf,
}

impl CargoConfig {
    /// Load the Cargo config file Cargo itself loads; see [`Self::default_path`].
    pub(crate) fn load() -> Result<Self> {
        Self::load_from(Self::default_path()?.path)
    }

    /// Load Cargo config from a specific path.
    pub(crate) fn load_from(path: PathBuf) -> Result<Self> {
        let doc = if path.exists() {
            let content = std::fs::read_to_string(&path).with_context(|| {
                tr_args!("err-failed-read-2", value = path.display().to_string())
            })?;
            content
                .parse::<DocumentMut>()
                .with_context(|| tr_args!("err-failed-parse", value = path.display().to_string()))?
        } else {
            DocumentMut::new()
        };
        Ok(Self { doc, path })
    }

    /// Check if vouch is configured for a specific registry.
    #[must_use]
    pub(crate) fn has_registry_vouch(&self, registry: &str) -> bool {
        self.doc
            .get("registries")
            .and_then(|r| r.get(registry))
            .and_then(|r| r.get("credential-provider"))
            .is_some_and(Self::item_contains_vouch)
    }

    /// Get the index URL for a specific registry.
    #[must_use]
    pub(crate) fn get_registry_index(&self, registry: &str) -> Option<String> {
        self.doc
            .get("registries")
            .and_then(|r| r.get(registry))
            .and_then(|r| r.get("index"))
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// Names of the registries whose `credential-provider` mentions vouch.
    #[must_use]
    pub(crate) fn vouch_registries(&self) -> Vec<String> {
        let Some(registries) = self.doc.get("registries").and_then(|r| r.as_table()) else {
            return Vec::new();
        };
        registries
            .iter()
            .filter(|(_, config)| {
                config
                    .get("credential-provider")
                    .is_some_and(Self::item_contains_vouch)
            })
            .map(|(name, _)| name.to_string())
            .collect()
    }

    /// Set the index URL for a specific registry.
    ///
    /// This sets `[registries.<name>].index`.
    pub(crate) fn set_registry_index(&mut self, registry: &str, index_url: &str) {
        // Ensure [registries] section exists
        if self.doc.get("registries").is_none() {
            self.doc.insert("registries", Item::Table(Table::new()));
        }

        // Ensure [registries.<name>] section exists and set index
        if let Some(registries) = self
            .doc
            .get_mut("registries")
            .and_then(|r| r.as_table_mut())
        {
            if registries.get(registry).is_none() {
                registries.insert(registry, Item::Table(Table::new()));
            }
            if let Some(reg_table) = registries.get_mut(registry).and_then(|r| r.as_table_mut()) {
                reg_table.insert(
                    "index",
                    Item::Value(Value::String(toml_edit::Formatted::new(
                        index_url.to_string(),
                    ))),
                );
            }
        }
    }

    /// Set the credential provider for a specific registry.
    ///
    /// This sets `[registries.<name>].credential-provider`.
    pub(crate) fn set_registry_provider(&mut self, registry: &str, command: &[&str]) {
        // Ensure [registries] section exists
        if self.doc.get("registries").is_none() {
            self.doc.insert("registries", Item::Table(Table::new()));
        }

        // Ensure [registries.<name>] section exists and set credential-provider
        if let Some(registries) = self
            .doc
            .get_mut("registries")
            .and_then(|r| r.as_table_mut())
        {
            if registries.get(registry).is_none() {
                registries.insert(registry, Item::Table(Table::new()));
            }
            if let Some(reg_table) = registries.get_mut(registry).and_then(|r| r.as_table_mut()) {
                let array = Self::command_to_array(command);
                reg_table.insert("credential-provider", Item::Value(Value::Array(array)));
            }
        }
    }

    /// Save the config to its file path.
    ///
    /// Uses atomic write (temp file + rename) to prevent corruption
    /// if the process is interrupted mid-write.
    pub(crate) fn save(&self) -> Result<()> {
        fs::atomic_write(&self.path, self.doc.to_string().as_bytes()).with_context(|| {
            tr_args!(
                "err-failed-write-5",
                value = self.path.display().to_string()
            )
        })
    }

    /// Get the path to this config file.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Locate the Cargo config file in `$CARGO_HOME` (default `~/.cargo`).
    ///
    /// Follows Cargo's precedence. The Cargo Book, *Configuration →
    /// Hierarchical structure*: "Cargo also reads config files without the
    /// `.toml` extension, such as `.cargo/config`. ... If both files exist,
    /// Cargo will use the file without the extension." When neither exists,
    /// `config.toml` is chosen and created on [`Self::save`].
    pub(crate) fn default_path() -> Result<ConfigLocation> {
        let cargo_home = cargo_dir()?;
        Ok(config_path_in(
            &cargo_home.join("config"),
            &cargo_home.join("config.toml"),
        ))
    }

    /// Convert a command array to a TOML array.
    fn command_to_array(command: &[&str]) -> Array {
        let mut array = Array::new();
        for part in command {
            array.push(*part);
        }
        array
    }

    /// Check if a TOML item contains "vouch".
    fn item_contains_vouch(item: &Item) -> bool {
        match item {
            Item::Value(Value::String(s)) => s.value().contains("vouch"),
            Item::Value(Value::Array(arr)) => Self::value_array_contains_vouch(arr),
            _ => false,
        }
    }

    /// Check if a TOML array value contains "vouch" in any element.
    fn value_array_contains_vouch(arr: &Array) -> bool {
        arr.iter()
            .any(|val| val.as_str().is_some_and(|s| s.contains("vouch")))
    }
}

/// The Cargo config file Cargo loads, and the `config.toml` beside it that
/// Cargo ignores, if any.
pub(crate) struct ConfigLocation {
    /// The file to read and write.
    pub(crate) path: PathBuf,
    /// A distinct `config.toml` that Cargo ignores because an extensionless
    /// `config` exists beside it.
    pub(crate) ignored: Option<PathBuf>,
}

/// `$CARGO_HOME` when set, otherwise `~/.cargo`.
fn cargo_dir() -> Result<PathBuf> {
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        return Ok(PathBuf::from(cargo_home));
    }
    let home = paths::home_dir().context(tr!("err-could-not-determine-home-directory"))?;
    Ok(home.join(".cargo"))
}

/// Choose between the extensionless `legacy` and `modern` (`config.toml`)
/// with Cargo's precedence.
///
/// Symlinks need no handling here: [`CargoConfig::save`] writes through a
/// symlinked path and keeps the link. A hardlinked pair is split by the save,
/// because a rename cannot preserve a hardlink.
///
/// Takes both paths so tests need not set `CARGO_HOME` (`std::env::set_var`
/// is `unsafe` under edition 2024).
fn config_path_in(legacy: &Path, modern: &Path) -> ConfigLocation {
    if !legacy.exists() {
        return ConfigLocation {
            path: modern.to_path_buf(),
            ignored: None,
        };
    }
    let ignored = (modern.exists() && !same_file(legacy, modern)).then(|| modern.to_path_buf());
    ConfigLocation {
        path: legacy.to_path_buf(),
        ignored,
    }
}

/// Whether `a` and `b` refer to the same file.
///
/// Follows symlinks. On Unix, `(st_dev, st_ino)` also catches hardlinks;
/// elsewhere the canonical paths are compared.
fn same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::metadata(a), std::fs::metadata(b)) {
            (Ok(ma), Ok(mb)) => ma.dev() == mb.dev() && ma.ino() == mb.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        match (std::fs::metadata(a), std::fs::metadata(b)) {
            (Ok(_), Ok(_)) => std::fs::canonicalize(a).ok() == std::fs::canonicalize(b).ok(),
            _ => false,
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// Wrapper that writes config content to a file inside a temporary directory.
    /// The file handle is released immediately, but the directory (and file) persist
    /// until this struct is dropped. This avoids Windows "Access is denied" errors
    /// when `atomic_write` tries to rename over an open file handle.
    struct TempConfig {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl TempConfig {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    fn create_temp_config(content: &str) -> TempConfig {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, content).expect("failed to write temp config");
        TempConfig { _dir: dir, path }
    }

    #[test]
    fn test_empty_config() {
        let file = create_temp_config("");
        let config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.vouch_registries().is_empty());
    }

    #[test]
    fn test_has_registry_vouch() {
        let content = r#"
[registries.my-registry]
index = "sparse+https://my-registry.example.com/"
credential-provider = ["/usr/local/bin/vouch"]
"#;
        let file = create_temp_config(content);
        let config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.has_registry_vouch("my-registry"));
        assert!(!config.has_registry_vouch("other-registry"));
        assert_eq!(config.vouch_registries(), ["my-registry"]);
    }

    #[test]
    fn test_no_vouch() {
        let content = r#"
[registry]
global-credential-providers = ["cargo:token"]

[registries.crates-io]
index = "sparse+https://index.crates.io/"
"#;
        let file = create_temp_config(content);
        let config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.vouch_registries().is_empty());
    }

    #[test]
    fn test_set_registry_provider_round_trips_awkward_paths() {
        let file = create_temp_config("");
        let mut config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();
        let command = [r"C:\Program Files\vouch\vouch.exe", r#"a"b"#];

        config.set_registry_provider("my-registry", &command);
        config.save().unwrap();

        let reloaded = CargoConfig::load_from(file.path().to_path_buf()).unwrap();
        let stored: Vec<&str> = reloaded
            .doc
            .get("registries")
            .and_then(|r| r.get("my-registry"))
            .and_then(|r| r.get("credential-provider"))
            .and_then(Item::as_array)
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(stored, command);
    }

    #[test]
    fn test_set_registry_provider() {
        let file = create_temp_config("");
        let mut config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        config.set_registry_provider("my-registry", &["/usr/local/bin/vouch"]);
        config.save().unwrap();

        // Reload and verify
        let reloaded = CargoConfig::load_from(file.path().to_path_buf()).unwrap();
        assert!(reloaded.has_registry_vouch("my-registry"));
    }

    #[test]
    fn test_preserves_existing_config() {
        let content = r#"
[build]
jobs = 4
target-dir = "/custom/target"

[registries.existing]
index = "sparse+https://existing.example.com/"
token = "secret"

[net]
git-fetch-with-cli = true
"#;
        let file = create_temp_config(content);
        let mut config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        // Add vouch provider
        config.set_registry_provider("new", &["/usr/local/bin/vouch"]);
        config.save().unwrap();

        // Reload and verify existing config is preserved
        let content = std::fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("jobs = 4"));
        assert!(content.contains("target-dir"));
        assert!(content.contains("git-fetch-with-cli = true"));
        assert!(content.contains("registries.existing"));
        assert!(content.contains("sparse+https://existing.example.com/"));

        // And vouch is added
        let reloaded = CargoConfig::load_from(file.path().to_path_buf()).unwrap();
        assert!(reloaded.has_registry_vouch("new"));
    }

    #[test]
    fn test_add_registry_preserves_existing_registries() {
        let content = r#"
[registries.existing]
index = "sparse+https://existing.example.com/"
credential-provider = ["cargo:token"]
"#;
        let file = create_temp_config(content);
        let mut config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        // Add a new registry with vouch
        config.set_registry_provider("new-registry", &["/usr/local/bin/vouch"]);
        config.save().unwrap();

        // Reload and verify
        let content = std::fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("registries.existing"));
        assert!(content.contains("registries.new-registry"));

        let reloaded = CargoConfig::load_from(file.path().to_path_buf()).unwrap();
        assert!(reloaded.has_registry_vouch("new-registry"));
        assert!(!reloaded.has_registry_vouch("existing")); // existing still uses cargo:token
    }

    #[test]
    fn test_load_nonexistent_file() {
        let path = PathBuf::from("/tmp/nonexistent_cargo_config_test_12345/config.toml");
        let config = CargoConfig::load_from(path).unwrap();

        assert!(config.vouch_registries().is_empty());
    }

    #[test]
    fn test_multiple_registries_with_vouch() {
        let content = r#"
[registries.registry-a]
credential-provider = ["/usr/local/bin/vouch"]

[registries.registry-b]
credential-provider = ["cargo:token"]

[registries.registry-c]
credential-provider = ["/usr/local/bin/vouch"]
"#;
        let file = create_temp_config(content);
        let config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.has_registry_vouch("registry-a"));
        assert!(!config.has_registry_vouch("registry-b"));
        assert!(config.has_registry_vouch("registry-c"));

        let mut found = config.vouch_registries();
        found.sort();
        assert_eq!(found, ["registry-a", "registry-c"]);
    }

    // =========================================================================
    // load_from error propagation
    //
    // `load_from` returns an empty document for a *missing* file, but must
    // return Err for a *present* file that fails to parse or cannot be read.
    // The CodeArtifact setup flow relies on this to avoid silently overwriting
    // a malformed or unreadable Cargo config.
    // =========================================================================

    #[test]
    fn test_load_from_propagates_parse_error() {
        // Malformed TOML (unclosed table header) must surface a parse error,
        // not be silently replaced with an empty document.
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[build\njobs = 4\n").expect("failed to write");

        let result = CargoConfig::load_from(path.clone());
        assert!(result.is_err(), "malformed TOML should fail to parse");
        let err = result.err().unwrap();
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "parse error should name the file: {err}",
        );
    }

    #[test]
    fn test_load_from_propagates_read_error_for_directory() {
        // A path that is a directory cannot be read as a file and must surface
        // a read error, not an empty document.
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("config.toml");
        std::fs::create_dir(&path).expect("failed to create dir-as-file");

        let result = CargoConfig::load_from(path.clone());
        assert!(result.is_err(), "a directory should fail to read");
        let err = result.err().unwrap();
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "read error should name the file: {err}",
        );
    }

    // Cargo Book, Configuration → Hierarchical structure: "If both files
    // exist, Cargo will use the file without the extension."

    /// Build the two candidate config paths inside `dir`, mirroring `default_path`.
    fn candidates(dir: &std::path::Path) -> (PathBuf, PathBuf) {
        (dir.join("config"), dir.join("config.toml"))
    }

    #[test]
    fn config_path_uses_config_toml_when_neither_exists() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert_eq!(path, modern, "config.toml is Cargo's recommended new name");
        assert!(ignored.is_none(), "no note when neither file exists");
    }

    #[test]
    fn config_path_uses_config_toml_when_only_modern_exists() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&modern, "").expect("write config.toml");
        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert_eq!(path, modern);
        assert!(ignored.is_none(), "no legacy file means no split");
    }

    #[test]
    fn config_path_uses_legacy_when_only_legacy_exists() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&legacy, "").expect("write legacy config");
        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert_eq!(path, legacy, "Cargo loads `config` when it is the only one");
        assert!(ignored.is_none(), "only one file exists — nothing is split");
        assert!(
            !modern.exists(),
            "must not create config.toml just by resolving"
        );
    }

    #[test]
    fn config_path_prefers_legacy_and_warns_when_both_exist_distinct() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&legacy, "legacy").expect("write legacy config");
        std::fs::write(&modern, "modern").expect("write config.toml");
        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert_eq!(
            path, legacy,
            "Cargo loads `config` and ignores `config.toml`"
        );
        assert_eq!(
            ignored.as_ref(),
            Some(&modern),
            "a split Cargo silently ignores must be surfaced"
        );
    }

    #[cfg(unix)]
    #[test]
    fn config_path_treats_symlinked_config_as_same_file() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&modern, "").expect("write config.toml");
        symlink(&modern, &legacy).expect("symlink config -> config.toml");
        // One file under two names: nothing is ignored.
        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert_eq!(path, legacy, "Cargo loads `config`");
        assert!(
            ignored.is_none(),
            "a symlinked pair is a single file, not a split"
        );
    }

    #[cfg(unix)]
    #[test]
    fn config_path_writes_real_file_for_reverse_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&legacy, "").expect("write legacy config (real file)");
        symlink(&legacy, &modern).expect("symlink config.toml -> config");
        // `config.toml` is now a symlink to `config`. `config` is the real
        // file Cargo loads; returning `legacy` keeps the `config.toml` symlink.
        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert_eq!(
            path, legacy,
            "write the real file (`config`) so the `config.toml -> config` symlink survives"
        );
        assert!(ignored.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn config_path_treats_hardlinked_pair_as_same_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&modern, "").expect("write config.toml");
        std::fs::hard_link(&modern, &legacy).expect("hardlink config -> config.toml");
        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert_eq!(path, legacy);
        assert!(ignored.is_none(), "a hardlinked pair is a single file");
    }

    #[cfg(unix)]
    #[test]
    fn same_file_detects_symlinked_pair() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&modern, "").expect("write config.toml");
        symlink(&modern, &legacy).expect("symlink");
        assert!(same_file(&legacy, &modern));
        assert!(same_file(&modern, &legacy), "symmetric");
    }

    #[cfg(unix)]
    #[test]
    fn same_file_detects_hardlinked_pair() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&modern, "").expect("write config.toml");
        std::fs::hard_link(&modern, &legacy).expect("hardlink");
        assert!(same_file(&legacy, &modern));
    }

    #[test]
    fn same_file_false_for_distinct_files() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&legacy, "a").expect("write legacy");
        std::fs::write(&modern, "b").expect("write modern");
        assert!(!same_file(&legacy, &modern));
    }

    // The setup flow: resolve with `config_path_in`, then load, edit, save.

    #[test]
    fn setup_writes_to_legacy_config_that_cargo_loads() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&legacy, "[build]\njobs = 4\n").expect("write legacy config");

        // What `configure_cargo_registry` would resolve via `default_path`.
        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert_eq!(path, legacy);
        assert!(
            ignored.is_none(),
            "only the legacy file exists, so no split note"
        );

        let mut config = CargoConfig::load_from(path).unwrap();
        config.set_registry_provider("codeartifact-test", &["/usr/local/bin/vouch"]);
        config.set_registry_index(
            "codeartifact-test",
            "sparse+https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/test/",
        );
        config.save().unwrap();

        // The file Cargo loads holds the entry, and no `config.toml` appears.
        let written = std::fs::read_to_string(&legacy).unwrap();
        assert!(
            written.contains("codeartifact-test"),
            "entry in legacy config"
        );
        assert!(written.contains("vouch"), "provider references vouch");
        assert!(written.contains("jobs = 4"), "existing config is preserved");
        assert!(!modern.exists(), "config.toml must not be created");

        // `vouch status` reads the same file and sees the registry as served.
        let reloaded = CargoConfig::load_from(legacy).unwrap();
        assert!(reloaded.has_registry_vouch("codeartifact-test"));
        assert_eq!(
            reloaded.get_registry_index("codeartifact-test").as_deref(),
            Some(
                "sparse+https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/test/"
            ),
        );
    }

    #[test]
    fn setup_writes_to_config_toml_when_no_legacy_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        // neither exists
        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert_eq!(path, modern, "config.toml is the recommended new name");
        assert!(ignored.is_none());

        let mut config = CargoConfig::load_from(path).unwrap();
        config.set_registry_provider("codeartifact-test", &["/usr/local/bin/vouch"]);
        config.save().unwrap();

        assert!(modern.exists(), "config.toml created on save");
        assert!(!legacy.exists(), "legacy config not created");
        let written = std::fs::read_to_string(&modern).unwrap();
        assert!(written.contains("vouch"));
    }

    #[test]
    fn setup_writes_to_legacy_when_both_exist_distinct() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&legacy, "[build]\njobs = 4\n").expect("write legacy");
        std::fs::write(&modern, "[build]\njobs = 8\n").expect("write modern");

        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert_eq!(
            path, legacy,
            "Cargo loads `config` and ignores `config.toml`"
        );
        assert_eq!(ignored.as_ref(), Some(&modern));

        let mut config = CargoConfig::load_from(path).unwrap();
        config.set_registry_provider("codeartifact-test", &["/usr/local/bin/vouch"]);
        config.save().unwrap();

        // The edit lands in the legacy file (what Cargo loads); the stale
        // `config.toml` is left untouched so no silent divergence is created.
        let legacy_written = std::fs::read_to_string(&legacy).unwrap();
        assert!(
            legacy_written.contains("vouch"),
            "entry written to legacy config"
        );
        let modern_written = std::fs::read_to_string(&modern).unwrap();
        assert!(
            !modern_written.contains("vouch"),
            "config.toml (ignored by Cargo) must not be the one written",
        );
        assert_eq!(
            modern_written, "[build]\njobs = 8\n",
            "config.toml unchanged"
        );
    }

    fn is_symlink(path: &std::path::Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
    }

    // A dotfiles manager links `~/.cargo/config` to a file outside
    // `$CARGO_HOME`, with no `config.toml` beside it.
    #[cfg(unix)]
    #[test]
    fn setup_preserves_legacy_config_symlink_to_dotfiles() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let dotfiles = tempfile::tempdir().expect("failed to create dotfiles dir");
        let (legacy, modern) = candidates(dir.path());
        let source = dotfiles.path().join("cargo-config");
        std::fs::write(&source, "[build]\njobs = 4\n").expect("write dotfiles source");
        symlink(&source, &legacy).expect("symlink config -> dotfiles");

        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert!(ignored.is_none());
        let mut config = CargoConfig::load_from(path).unwrap();
        config.set_registry_provider("codeartifact-test", &["/usr/local/bin/vouch"]);
        config.save().unwrap();

        assert!(is_symlink(&legacy), "`config` must still be a symlink");
        assert_eq!(std::fs::read_link(&legacy).unwrap(), source);
        let written = std::fs::read_to_string(&source).unwrap();
        assert!(
            written.contains("vouch"),
            "entry written to the dotfiles source"
        );
        assert!(written.contains("jobs = 4"), "existing config preserved");
        assert!(!modern.exists(), "config.toml must not be created");
    }

    #[cfg(unix)]
    #[test]
    fn setup_preserves_config_symlink_pointing_at_config_toml() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let (legacy, modern) = candidates(dir.path());
        std::fs::write(&modern, "[build]\njobs = 4\n").expect("write config.toml");
        symlink(&modern, &legacy).expect("symlink config -> config.toml");

        let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
        assert!(ignored.is_none());

        let mut config = CargoConfig::load_from(path).unwrap();
        config.set_registry_provider("codeartifact-test", &["/usr/local/bin/vouch"]);
        config.save().unwrap();

        // The symlink must still be a symlink (atomic rename wrote through to
        // `config.toml`, not over `config`).
        assert!(is_symlink(&legacy), "`config` must still be a symlink");
        assert_eq!(
            std::fs::read_link(&legacy).unwrap(),
            modern,
            "symlink target unchanged",
        );

        // Both names see the new content: Cargo loads `config` (following the
        // symlink to `config.toml`), and `config.toml` is the file that was
        // written.
        let via_legacy = std::fs::read_to_string(&legacy).unwrap();
        let via_modern = std::fs::read_to_string(&modern).unwrap();
        assert!(via_legacy.contains("vouch"), "entry visible via symlink");
        assert!(via_modern.contains("vouch"), "entry written to config.toml");
        assert!(
            via_modern.contains("jobs = 4"),
            "pre-existing config preserved"
        );
        assert_eq!(via_legacy, via_modern, "both names see the same content");
    }

    // Round-trips the vouch registry set through an extensionless `config`.
    mod roundtrip {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Adding a vouch provider for an arbitrary registry name, saving
            /// to the legacy `config` path `config_path_in` selects, and
            /// reloading preserves the registry as vouch-served.
            #[test]
            fn vouch_registry_survives_legacy_round_trip(
                registry in "[a-z][a-z0-9-]{0,30}",
            ) {
                let dir = tempfile::tempdir().unwrap();
                let (legacy, modern) = candidates(dir.path());
                std::fs::write(&legacy, "").unwrap();

                let ConfigLocation { path, ignored } = config_path_in(&legacy, &modern);
                prop_assert!(path == legacy, "only legacy exists → select legacy");
                prop_assert!(ignored.is_none());

                let mut config = CargoConfig::load_from(path).unwrap();
                config.set_registry_provider(&registry, &["/usr/local/bin/vouch"]);
                config.save().unwrap();

                // `config.toml` must not have been created as a side effect.
                prop_assert!(!modern.exists(), "config.toml must not be created");

                let reloaded = CargoConfig::load_from(legacy).unwrap();
                prop_assert!(reloaded.has_registry_vouch(&registry));
                prop_assert_eq!(reloaded.vouch_registries(), vec![registry]);
            }
        }
    }
}
