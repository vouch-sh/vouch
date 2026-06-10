// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo config file (~/.cargo/config.toml) parsing utilities.
//!
//! Uses proper TOML parsing instead of fragile string manipulation.
//! This preserves existing configuration when adding/modifying settings.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

/// Cargo config file parser and writer.
///
/// Uses toml_edit to properly parse and modify ~/.cargo/config.toml files,
/// preserving existing sections, keys, and formatting when making changes.
pub(crate) struct CargoConfig {
    doc: DocumentMut,
    path: PathBuf,
}

impl CargoConfig {
    /// Load Cargo config from the default path.
    ///
    /// Checks `$CARGO_HOME/config.toml` first, then falls back to `~/.cargo/config.toml`.
    pub(crate) fn load() -> Result<Self> {
        let path = Self::default_path()?;
        Self::load_from(path)
    }

    /// Load Cargo config from a specific path.
    pub(crate) fn load_from(path: PathBuf) -> Result<Self> {
        let doc = if path.exists() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            content
                .parse::<DocumentMut>()
                .with_context(|| format!("failed to parse {}", path.display()))?
        } else {
            DocumentMut::new()
        };
        Ok(Self { doc, path })
    }

    /// Create an empty config for a specific path.
    #[must_use]
    pub(crate) fn empty(path: PathBuf) -> Self {
        Self {
            doc: DocumentMut::new(),
            path,
        }
    }

    /// Check if vouch is configured as a global credential provider.
    #[must_use]
    pub(crate) fn has_global_vouch(&self) -> bool {
        self.doc
            .get("registry")
            .and_then(|r| r.get("global-credential-providers"))
            .is_some_and(Self::array_contains_vouch)
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

    /// Find the first registry that uses vouch.
    #[must_use]
    pub(crate) fn find_vouch_registry(&self) -> Option<String> {
        if let Some(registries) = self.doc.get("registries").and_then(|r| r.as_table()) {
            for (name, config) in registries.iter() {
                if let Some(provider) = config.get("credential-provider")
                    && Self::item_contains_vouch(provider)
                {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    /// Set the global credential providers.
    ///
    /// This sets the `[registry].global-credential-providers` array.
    pub(crate) fn set_global_provider(&mut self, command: &[&str]) {
        // Ensure [registry] section exists
        if self.doc.get("registry").is_none() {
            self.doc.insert("registry", Item::Table(Table::new()));
        }

        let array = Self::command_to_array(command);
        if let Some(registry) = self.doc.get_mut("registry").and_then(|r| r.as_table_mut()) {
            registry.insert(
                "global-credential-providers",
                Item::Value(Value::Array(array)),
            );
        }
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
        vouch_common::fs::atomic_write(&self.path, self.doc.to_string().as_bytes())
            .with_context(|| format!("failed to write {}", self.path.display()))
    }

    /// Get the path to this config file.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Get the default Cargo config path.
    ///
    /// Checks `$CARGO_HOME/config.toml` first, then falls back to `~/.cargo/config.toml`.
    pub(crate) fn default_path() -> Result<PathBuf> {
        // Check for CARGO_HOME environment variable
        if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
            return Ok(PathBuf::from(cargo_home).join("config.toml"));
        }

        // Default to ~/.cargo/config.toml
        let home = dirs::home_dir().context("could not determine home directory")?;
        Ok(home.join(".cargo").join("config.toml"))
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

    /// Check if a TOML array contains "vouch" in any element.
    fn array_contains_vouch(item: &Item) -> bool {
        item.as_array()
            .is_some_and(Self::value_array_contains_vouch)
    }

    /// Check if a TOML array value contains "vouch" in any element.
    fn value_array_contains_vouch(arr: &Array) -> bool {
        arr.iter()
            .any(|val| val.as_str().is_some_and(|s| s.contains("vouch")))
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

        assert!(!config.has_global_vouch());
        assert!(config.find_vouch_registry().is_none());
    }

    #[test]
    fn test_has_global_vouch() {
        let content = r#"
[registry]
global-credential-providers = ["/usr/local/bin/vouch", "credential", "cargo", "--"]
"#;
        let file = create_temp_config(content);
        let config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.has_global_vouch());
    }

    #[test]
    fn test_has_registry_vouch() {
        let content = r#"
[registries.my-registry]
index = "sparse+https://my-registry.example.com/"
credential-provider = ["/usr/local/bin/vouch", "credential", "cargo", "--"]
"#;
        let file = create_temp_config(content);
        let config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(!config.has_global_vouch());
        assert!(config.has_registry_vouch("my-registry"));
        assert!(!config.has_registry_vouch("other-registry"));
        assert_eq!(
            config.find_vouch_registry(),
            Some("my-registry".to_string())
        );
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

        assert!(!config.has_global_vouch());
        assert!(config.find_vouch_registry().is_none());
    }

    #[test]
    fn test_set_global_provider() {
        let file = create_temp_config("");
        let mut config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        config.set_global_provider(&["/usr/local/bin/vouch", "credential", "cargo", "--"]);
        config.save().unwrap();

        // Reload and verify
        let reloaded = CargoConfig::load_from(file.path().to_path_buf()).unwrap();
        assert!(reloaded.has_global_vouch());
    }

    #[test]
    fn test_set_registry_provider() {
        let file = create_temp_config("");
        let mut config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        config.set_registry_provider(
            "my-registry",
            &["/usr/local/bin/vouch", "credential", "cargo", "--"],
        );
        config.save().unwrap();

        // Reload and verify
        let reloaded = CargoConfig::load_from(file.path().to_path_buf()).unwrap();
        assert!(reloaded.has_registry_vouch("my-registry"));
        assert!(!reloaded.has_global_vouch());
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
        config.set_global_provider(&["/usr/local/bin/vouch", "credential", "cargo", "--"]);
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
        assert!(reloaded.has_global_vouch());
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
        config.set_registry_provider(
            "new-registry",
            &["/usr/local/bin/vouch", "credential", "cargo", "--"],
        );
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

        assert!(!config.has_global_vouch());
        assert!(config.find_vouch_registry().is_none());
    }

    #[test]
    fn test_multiple_registries_with_vouch() {
        let content = r#"
[registries.registry-a]
credential-provider = ["/usr/local/bin/vouch", "credential", "cargo", "--"]

[registries.registry-b]
credential-provider = ["cargo:token"]

[registries.registry-c]
credential-provider = ["/usr/local/bin/vouch", "credential", "cargo", "--"]
"#;
        let file = create_temp_config(content);
        let config = CargoConfig::load_from(file.path().to_path_buf()).unwrap();

        assert!(config.has_registry_vouch("registry-a"));
        assert!(!config.has_registry_vouch("registry-b"));
        assert!(config.has_registry_vouch("registry-c"));

        // find_vouch_registry returns first match
        let found = config.find_vouch_registry().unwrap();
        assert!(found == "registry-a" || found == "registry-c");
    }
}
