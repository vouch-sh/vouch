// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CodeArtifact setup command.
//!
//! Configures package managers (Cargo, pip, npm) to use Vouch for
//! AWS CodeArtifact registry authentication.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use secrecy::ExposeSecret;

use crate::commands::credential::codeartifact::resolve_codeartifact_params;
use crate::config::{CodeArtifactProfile, Config};
use crate::integrations::aws::codeartifact::{CodeArtifactRegistry, parse_codeartifact_url};
use crate::integrations::aws::get_local_aws_role;
use crate::integrations::aws::sts::Arn;
use crate::integrations::cargo::CargoConfig;

/// Supported package manager tools for CodeArtifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Tool {
    /// Rust Cargo package manager.
    Cargo,
    /// Python pip package manager.
    Pip,
    /// Node.js npm package manager.
    Npm,
    /// pnpm package manager (dynamic tokenHelper).
    Pnpm,
    /// Python uv package manager (keyring subprocess).
    Uv,
}

/// Run the CodeArtifact setup command.
///
/// Configures the specified package manager to use a CodeArtifact repository
/// authenticated via Vouch.
///
/// # Arguments
/// * `server` - Vouch server URL
/// * `tool` - Package manager to configure ("cargo", "pip", "npm", "pnpm", "uv")
/// * `domain` - CodeArtifact domain name (optional if profile configured)
/// * `domain_owner` - AWS account ID that owns the domain (optional if profile configured)
/// * `region` - AWS region (optional if profile configured)
/// * `repository` - CodeArtifact repository name
/// * `profile` - Named profile to use/save
pub async fn run(
    server: &str,
    tool: Tool,
    domain: Option<&str>,
    domain_owner: Option<&str>,
    region: Option<&str>,
    repository: &str,
    profile: Option<&str>,
) -> Result<()> {
    let (domain, domain_owner, region) =
        resolve_codeartifact_params(domain, domain_owner, region, profile)?;

    println!("CodeArtifact Setup");
    println!("==================\n");

    // Save profile to config (using file lock for concurrent safety)
    let profile_name = profile.unwrap_or("default");
    {
        let name = profile_name.to_string();
        let ca_profile = CodeArtifactProfile {
            domain: domain.clone(),
            domain_owner: domain_owner.clone(),
            region: region.clone(),
        };
        Config::modify(|config| {
            config.set_codeartifact_profile(&name, ca_profile);
        })
        .context("failed to save CodeArtifact profile")?;
    }
    println!("Saved CodeArtifact profile '{profile_name}' to config.\n");

    // Derive domain suffix from the AWS config's role ARN partition
    // to support China, GovCloud, and other partitions.
    let domain_suffix = get_local_aws_role()
        .and_then(|role| {
            Arn::parse_role_arn(&role)
                .ok()
                .map(|arn| arn.partition.dns_suffix())
        })
        .unwrap_or("amazonaws.com");

    let ca_host = format!("{domain}-{domain_owner}.d.codeartifact.{region}.{domain_suffix}");

    match tool {
        Tool::Cargo => setup_cargo(&ca_host, repository),
        Tool::Pip => setup_pip(&ca_host, repository),
        Tool::Npm => {
            setup_npm(
                server,
                &domain,
                &domain_owner,
                &region,
                &ca_host,
                repository,
            )
            .await
        }
        Tool::Pnpm => setup_pnpm(&ca_host, repository),
        Tool::Uv => setup_uv(&ca_host, repository),
    }
}

/// Configure Cargo for CodeArtifact.
///
/// Sets up `~/.cargo/config.toml` with Vouch as the credential provider
/// for a named registry pointing to a CodeArtifact Cargo repository.
/// Cargo uses the credential provider protocol, so tokens are fetched
/// automatically on each operation — no static token embedding needed.
fn setup_cargo(ca_host: &str, repository: &str) -> Result<()> {
    let index_url = format!("sparse+https://{ca_host}/cargo/{repository}/");

    // Get vouch binary path
    let vouch_path = std::env::current_exe().context("could not determine vouch binary path")?;
    let vouch_path_str = vouch_path.display().to_string();

    let registry_name = format!("codeartifact-{repository}");

    configure_cargo_registry(&registry_name, &index_url, &vouch_path_str)?;

    println!();
    println!("Usage:");
    println!("  cargo build --registry {}", registry_name);
    println!("  cargo publish --registry {}", registry_name);
    println!();
    println!("Cargo will automatically call Vouch to obtain a fresh CodeArtifact");
    println!("token each time it needs to authenticate.");

    Ok(())
}

/// Configure Cargo registry in ~/.cargo/config.toml.
fn configure_cargo_registry(registry_name: &str, index_url: &str, vouch_path: &str) -> Result<()> {
    let config_path = CargoConfig::default_path()?;
    let mut config = CargoConfig::load_from(config_path.clone())
        .unwrap_or_else(|_| CargoConfig::empty(config_path));

    if config.has_registry_vouch(registry_name) {
        println!(
            "Vouch is already configured for registry '{}'\n",
            registry_name
        );
        println!("Configuration file: {}", config.path().display());
        return Ok(());
    }

    // Set the credential provider and index URL for this registry
    config.set_registry_provider(registry_name, &[vouch_path, "credential", "cargo", "--"]);
    config.set_registry_index(registry_name, index_url);

    config.save()?;
    println!(
        "Cargo configured for CodeArtifact registry '{}'",
        registry_name
    );
    println!("Configuration written to: {}", config.path().display());

    Ok(())
}

/// Configure pip for CodeArtifact using the keyring credential helper.
///
/// Instead of embedding a static token that expires in ~12h, this sets up
/// pip to use `vouch credential pip` as a keyring backend. pip will call
/// vouch on each request to get a fresh token transparently.
fn setup_pip(ca_host: &str, repository: &str) -> Result<()> {
    let index_url = format!("https://aws@{ca_host}/pypi/{repository}/simple/");

    write_pip_config(&index_url)?;
    install_keyring_wrapper()?;

    println!();
    println!("pip will automatically call Vouch to obtain a fresh CodeArtifact");
    println!("token each time it needs to authenticate. No more 12-hour token expiry!");

    Ok(())
}

/// Install a `keyring` symlink pointing to the vouch binary.
///
/// pip calls `keyring get <url> <username>` when `keyring-provider = subprocess`
/// is configured. The symlink makes vouch detect argv[0] == "keyring" and
/// handle those calls.
fn install_keyring_wrapper() -> Result<()> {
    let vouch_path = std::env::current_exe().context("could not determine vouch binary path")?;
    let keyring_path = crate::utils::vouch_helper_path("keyring")?;

    // Don't overwrite if it exists and isn't a vouch symlink
    if (keyring_path.exists() || keyring_path.is_symlink())
        && !crate::utils::is_vouch_symlink(&keyring_path)
    {
        println!(
            "Note: {} already exists (not managed by vouch).",
            keyring_path.display()
        );
        println!("To use vouch for CodeArtifact authentication, you can:");
        println!("  1. Rename the existing keyring and re-run this command:");
        println!(
            "     mv {} {}.bak",
            keyring_path.display(),
            keyring_path.display()
        );
        println!("  2. Or manually create a symlink to vouch:");
        println!(
            "     ln -sf \"{}\" \"{}\"",
            vouch_path.display(),
            keyring_path.display()
        );
        return Ok(());
    }

    let batch_content = format!(
        "@echo off\r\n\"{}\" credential pip %*\r\n",
        vouch_path.display()
    );
    crate::utils::create_symlink_with_fallback(&vouch_path, &keyring_path, &batch_content)?;

    Ok(())
}

/// Write pip configuration file using proper INI parsing.
///
/// Loads the existing pip.conf (if any), updates the `[global]` section
/// with `index-url` and `keyring-provider`, preserving any other settings.
fn write_pip_config(index_url: &str) -> Result<()> {
    let config_dir = get_pip_config_dir()?;
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("failed to create {}", config_dir.display()))?;

    let config_path = config_dir.join("pip.conf");

    // Load existing config or create new
    let mut ini = if config_path.exists() {
        ini::Ini::load_from_file(&config_path)
            .with_context(|| format!("failed to parse {}", config_path.display()))?
    } else {
        ini::Ini::new()
    };

    // Update [global] section, preserving other keys
    ini.with_section(Some("global"))
        .set("index-url", index_url)
        .set("keyring-provider", "subprocess");

    // Serialize INI to a buffer, then atomically write
    let mut buf = Vec::new();
    ini.write_to(&mut buf).with_context(|| {
        format!(
            "failed to serialize pip config for {}",
            config_path.display()
        )
    })?;
    crate::utils::atomic_write_secure(&config_path, &buf)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    println!("Wrote pip config: {}", config_path.display());

    Ok(())
}

/// Get the pip config directory path.
fn get_pip_config_dir() -> Result<std::path::PathBuf> {
    // Respect PIP_CONFIG_FILE if set
    if let Ok(pip_config) = std::env::var("PIP_CONFIG_FILE") {
        let path = std::path::PathBuf::from(pip_config);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            return Ok(parent.to_path_buf());
        }
    }

    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".config").join("pip"))
}

/// Configure uv for CodeArtifact using the keyring credential helper.
///
/// uv supports the same `keyring` subprocess protocol as pip, but does NOT
/// read `pip.conf`. Instead, it uses its own `uv.toml` configuration file.
/// This sets up `keyring-provider = "subprocess"` and configures the
/// CodeArtifact index in `~/.config/uv/uv.toml`, then reuses the same
/// `~/.local/bin/keyring` wrapper that pip setup installs.
fn setup_uv(ca_host: &str, repository: &str) -> Result<()> {
    let index_url = format!("https://aws@{ca_host}/pypi/{repository}/simple/");

    write_uv_config(&index_url, repository)?;
    install_keyring_wrapper()?;

    println!();
    println!("uv will automatically call Vouch to obtain a fresh CodeArtifact");
    println!("token each time it needs to authenticate. No more 12-hour token expiry!");
    println!();
    println!("Note: If you also use pip, run `vouch setup codeartifact --tool pip` to");
    println!("configure pip separately (uv does not read pip.conf).");

    Ok(())
}

/// Write uv configuration file (`~/.config/uv/uv.toml`).
///
/// Loads the existing uv.toml (if any) via `toml_edit` to preserve other
/// settings, then sets `keyring-provider = "subprocess"` and adds (or
/// updates) a CodeArtifact index entry.
fn write_uv_config(index_url: &str, repository: &str) -> Result<()> {
    let config_dir = get_uv_config_dir()?;
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("failed to create {}", config_dir.display()))?;

    let config_path = config_dir.join("uv.toml");

    // Load existing config or create new
    let content = if config_path.exists() {
        std::fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?
    } else {
        String::new()
    };

    let mut doc = content
        .parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("failed to parse {}", config_path.display()))?;

    // Set keyring-provider = "subprocess"
    doc.insert("keyring-provider", toml_edit::value("subprocess"));

    // Find or create the [[index]] array entry for our CodeArtifact repo
    let index_name = format!("codeartifact-{repository}");

    if doc.get("index").is_none() {
        doc.insert(
            "index",
            toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()),
        );
    }

    if let Some(array) = doc
        .get_mut("index")
        .and_then(|i| i.as_array_of_tables_mut())
    {
        // Look for an existing entry with our name
        let mut found = false;
        for table in array.iter_mut() {
            if table.get("name").and_then(|v| v.as_str()) == Some(&index_name) {
                table.insert("url", toml_edit::value(index_url));
                table.insert("default", toml_edit::value(true));
                found = true;
                break;
            }
        }
        if !found {
            let mut entry = toml_edit::Table::new();
            entry.insert("name", toml_edit::value(&index_name));
            entry.insert("url", toml_edit::value(index_url));
            entry.insert("default", toml_edit::value(true));
            array.push(entry);
        }
    }

    let serialized = doc.to_string();
    crate::utils::atomic_write_secure(&config_path, serialized.as_bytes())
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    println!("Wrote uv config: {}", config_path.display());

    Ok(())
}

/// Get the uv config directory path.
fn get_uv_config_dir() -> Result<std::path::PathBuf> {
    // Respect UV_CONFIG_FILE if set
    if let Ok(uv_config) = std::env::var("UV_CONFIG_FILE") {
        let path = std::path::PathBuf::from(uv_config);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            return Ok(parent.to_path_buf());
        }
    }

    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".config").join("uv"))
}

/// Configure npm for CodeArtifact.
///
/// Gets a fresh token and writes `~/.npmrc` with the CodeArtifact
/// npm registry URL and bearer token.
async fn setup_npm(
    server: &str,
    domain: &str,
    domain_owner: &str,
    region: &str,
    ca_host: &str,
    repository: &str,
) -> Result<()> {
    let result =
        crate::commands::credential::codeartifact::get_token(server, domain, domain_owner, region)
            .await
            .context("failed to get CodeArtifact token")?;

    let registry_url = format!("https://{ca_host}/npm/{repository}/");

    write_npmrc(
        ca_host,
        repository,
        result.authorization_token.expose_secret(),
    )?;

    println!();
    println!("Registry URL: {}", registry_url);
    println!();
    println!("Note: Unlike Cargo and pip, npm does not support dynamic credential");
    println!("helpers. The token written to ~/.npmrc expires in ~12 hours.");
    println!("To refresh: vouch setup codeartifact --tool npm --repository {repository}");
    println!();
    println!("Tip: pnpm supports dynamic credential helpers. Use --tool pnpm for");
    println!("automatic token refresh without manual re-login.");

    Ok(())
}

/// Write npm configuration file (~/.npmrc).
///
/// Preserves existing entries while updating/adding CodeArtifact-specific lines.
/// Only lines matching this specific host/repo are replaced.
fn write_npmrc(ca_host: &str, repository: &str, token: &str) -> Result<()> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let npmrc_path = home.join(".npmrc");

    let existing = if npmrc_path.exists() {
        std::fs::read_to_string(&npmrc_path)
            .with_context(|| format!("failed to read {}", npmrc_path.display()))?
    } else {
        String::new()
    };

    let content = build_npmrc_content(&existing, ca_host, repository, token);

    crate::utils::atomic_write_secure(&npmrc_path, content.as_bytes())
        .with_context(|| format!("failed to write {}", npmrc_path.display()))?;

    println!("Wrote npm config: {}", npmrc_path.display());

    Ok(())
}

/// Configure pnpm for CodeArtifact using `tokenHelper`.
///
/// pnpm supports a `tokenHelper` directive in `.npmrc` that points to an
/// executable which outputs an auth token to stdout. This is equivalent to
/// Cargo's credential provider and pip's keyring helper — tokens are fetched
/// dynamically on each `pnpm install`, so they never go stale.
fn setup_pnpm(ca_host: &str, repository: &str) -> Result<()> {
    let helper_path = install_pnpm_token_helper()?;
    write_npmrc_pnpm(ca_host, repository, &helper_path)?;

    println!();
    println!("pnpm will automatically call Vouch to obtain a fresh CodeArtifact");
    println!("token each time it needs to authenticate. No more 12-hour token expiry!");

    Ok(())
}

/// Install a `vouch-pnpm-tokenhelper` symlink pointing to the vouch binary.
///
/// pnpm's `tokenHelper` requires an absolute path with no arguments.
/// The symlink makes vouch detect argv[0] == "vouch-pnpm-tokenhelper"
/// and dispatch to the codeartifact credential command.
fn install_pnpm_token_helper() -> Result<std::path::PathBuf> {
    let vouch_path = std::env::current_exe().context("could not determine vouch binary path")?;
    let helper_path = crate::utils::vouch_helper_path("vouch-pnpm-tokenhelper")?;

    // Don't overwrite if it exists and isn't a vouch symlink
    if (helper_path.exists() || helper_path.is_symlink())
        && !crate::utils::is_vouch_symlink(&helper_path)
    {
        println!(
            "Note: {} already exists (not managed by vouch).",
            helper_path.display()
        );
        println!("To use vouch for pnpm CodeArtifact authentication, either:");
        println!("  1. Rename the existing file and re-run this command:");
        println!(
            "     mv {} {}.bak",
            helper_path.display(),
            helper_path.display()
        );
        println!("  2. Or manually create a symlink to vouch:");
        println!(
            "     ln -sf \"{}\" \"{}\"",
            vouch_path.display(),
            helper_path.display()
        );
        return Ok(helper_path);
    }

    let batch_content = format!(
        "@echo off\r\n\"{}\" credential codeartifact %*\r\n",
        vouch_path.display()
    );
    crate::utils::create_symlink_with_fallback(&vouch_path, &helper_path, &batch_content)?;

    Ok(helper_path)
}

/// Write pnpm `tokenHelper` configuration to `~/.npmrc`.
///
/// Preserves existing entries while updating/adding the `tokenHelper`
/// directive for the given CodeArtifact registry.
fn write_npmrc_pnpm(ca_host: &str, repository: &str, helper_path: &std::path::Path) -> Result<()> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let npmrc_path = home.join(".npmrc");

    let existing = if npmrc_path.exists() {
        std::fs::read_to_string(&npmrc_path)
            .with_context(|| format!("failed to read {}", npmrc_path.display()))?
    } else {
        String::new()
    };

    let content = build_npmrc_pnpm_content(&existing, ca_host, repository, helper_path);

    crate::utils::atomic_write_secure(&npmrc_path, content.as_bytes())
        .with_context(|| format!("failed to write {}", npmrc_path.display()))?;

    println!("Wrote pnpm config: {}", npmrc_path.display());

    Ok(())
}

/// Parse CodeArtifact entries from `.npmrc` content.
///
/// Scans for `_authToken` lines whose prefix contains a CodeArtifact host,
/// returning `(line_prefix, registry)` pairs. The `line_prefix` is the
/// portion before `:_authToken=` (e.g., `//host/npm/repo/`) so callers
/// can match lines during rewrite.
fn parse_npmrc_codeartifact_entries(content: &str) -> Vec<(String, CodeArtifactRegistry)> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        // Skip comments (npmrc spec: lines starting with # or ;)
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        // Match lines like: //{ca_host}/npm/{repo}/:_authToken={token}
        if let Some((prefix, token)) = trimmed.split_once(":_authToken=") {
            // Skip env-var-substituted tokens (e.g. ${NPM_TOKEN}) to avoid
            // clobbering the indirection with a raw token value.
            if token.contains("${") {
                continue;
            }
            // prefix is e.g. "//host/npm/repo/"
            let host_and_path = prefix.strip_prefix("//").unwrap_or(prefix);
            if let Some(registry) = parse_codeartifact_url(host_and_path) {
                entries.push((prefix.to_string(), registry));
            }
        }
    }
    entries
}

/// Auto-refresh any CodeArtifact npm tokens found in `~/.npmrc`.
///
/// Parses `~/.npmrc` for `_authToken` lines pointing at CodeArtifact hosts,
/// fetches a fresh token for each unique domain, and rewrites the tokens
/// in place. Best-effort: logs errors via `tracing` but never fails the
/// login flow.
pub(crate) async fn auto_refresh_npmrc(server: &str) {
    if let Err(e) = try_refresh_npmrc(server).await {
        tracing::debug!("CodeArtifact npmrc refresh skipped: {e}");
    }
}

/// Inner implementation for `auto_refresh_npmrc` that returns `Result`
/// for ergonomic error handling.
async fn try_refresh_npmrc(server: &str) -> Result<()> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let npmrc_path = home.join(".npmrc");

    let content = match std::fs::read_to_string(&npmrc_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("failed to read ~/.npmrc"),
    };

    let entries = parse_npmrc_codeartifact_entries(&content);
    if entries.is_empty() {
        return Ok(());
    }

    // Deduplicate by (domain, owner, region) — multiple repos share one token
    let mut tokens: BTreeMap<String, secrecy::SecretString> = BTreeMap::new();
    for (_prefix, registry) in &entries {
        let key = registry.token_cache_key();
        if tokens.contains_key(&key) {
            continue;
        }
        match crate::commands::credential::codeartifact::get_token(
            server,
            &registry.domain,
            &registry.domain_owner,
            &registry.region,
        )
        .await
        {
            Ok(token) => {
                tokens.insert(key, token.authorization_token);
            }
            Err(e) => {
                tracing::debug!(
                    "Failed to refresh CodeArtifact token for {}-{}: {e}",
                    registry.domain,
                    registry.domain_owner
                );
            }
        }
    }

    if tokens.is_empty() {
        return Ok(());
    }

    // Build a lookup from line prefix to the fresh token
    let mut prefix_to_token: BTreeMap<&str, &secrecy::SecretString> = BTreeMap::new();
    for (prefix, registry) in &entries {
        let key = registry.token_cache_key();
        if let Some(token) = tokens.get(&key) {
            prefix_to_token.insert(prefix.as_str(), token);
        }
    }

    // Build a plain string map for the pure rewrite function
    let plain_map: BTreeMap<&str, &str> = prefix_to_token
        .iter()
        .map(|(k, v)| (*k, v.expose_secret()))
        .collect();

    let (new_content, refreshed) = rewrite_npmrc_tokens(&content, &plain_map);

    if refreshed {
        crate::utils::atomic_write_secure(&npmrc_path, new_content.as_bytes())
            .with_context(|| format!("failed to write {}", npmrc_path.display()))?;
        println!("Refreshed CodeArtifact token in ~/.npmrc");
    }

    Ok(())
}

/// Rewrite `.npmrc` content, replacing `_authToken` values for matched prefixes.
///
/// Returns the rewritten content and whether any replacements were made.
/// Lines not matching any prefix are preserved verbatim.
fn rewrite_npmrc_tokens(content: &str, prefix_to_token: &BTreeMap<&str, &str>) -> (String, bool) {
    let mut new_lines: Vec<String> = Vec::new();
    let mut changed = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some((prefix, _old_token)) = trimmed.split_once(":_authToken=")
            && let Some(new_token) = prefix_to_token.get(prefix)
        {
            new_lines.push(format!("{prefix}:_authToken={new_token}"));
            changed = true;
            continue;
        }
        new_lines.push(line.to_string());
    }
    let result = new_lines.join("\n") + "\n";
    (result, changed)
}

/// Build the content for an npm `.npmrc` with a static `_authToken`.
///
/// Returns the file content as a string. Existing lines not related to the
/// given CodeArtifact registry are preserved.
fn build_npmrc_content(existing: &str, ca_host: &str, repository: &str, token: &str) -> String {
    let ca_prefix = format!("//{ca_host}/npm/{repository}/");
    let ca_registry = format!("registry=https://{ca_host}/npm/{repository}/");
    let mut lines: Vec<String> = existing
        .lines()
        .filter(|line| !line.starts_with(&ca_prefix) && !line.starts_with(&ca_registry))
        .map(String::from)
        .collect();

    lines.push(format!("{ca_prefix}:_authToken={token}"));
    lines.push(format!("registry=https://{ca_host}/npm/{repository}/"));

    lines.join("\n") + "\n"
}

/// Build the content for a pnpm `.npmrc` with a `tokenHelper` directive.
///
/// Returns the file content as a string. Existing lines not related to the
/// given CodeArtifact registry are preserved.
fn build_npmrc_pnpm_content(
    existing: &str,
    ca_host: &str,
    repository: &str,
    helper_path: &std::path::Path,
) -> String {
    let ca_prefix = format!("//{ca_host}/npm/{repository}/");
    let ca_registry = format!("registry=https://{ca_host}/npm/{repository}/");
    let mut lines: Vec<String> = existing
        .lines()
        .filter(|line| !line.starts_with(&ca_prefix) && !line.starts_with(&ca_registry))
        .map(String::from)
        .collect();

    lines.push(format!("{ca_prefix}:tokenHelper={}", helper_path.display()));
    lines.push(format!("registry=https://{ca_host}/npm/{repository}/"));

    lines.join("\n") + "\n"
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use clap::ValueEnum;
    use proptest::prelude::*;

    #[test]
    fn test_tool_value_enum() {
        // ValueEnum::from_str is case-insensitive by default
        assert_eq!(Tool::from_str("cargo", true), Ok(Tool::Cargo));
        assert_eq!(Tool::from_str("Cargo", true), Ok(Tool::Cargo));
        assert_eq!(Tool::from_str("pip", true), Ok(Tool::Pip));
        assert_eq!(Tool::from_str("npm", true), Ok(Tool::Npm));
        assert_eq!(Tool::from_str("pnpm", true), Ok(Tool::Pnpm));
        assert_eq!(Tool::from_str("uv", true), Ok(Tool::Uv));
        assert!(Tool::from_str("maven", true).is_err());
        assert!(Tool::from_str("", true).is_err());
    }

    #[test]
    fn test_parse_npmrc_codeartifact_entries_basic() {
        let content = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/my-repo/:_authToken=old-token\n\
                        registry=https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/my-repo/\n";
        let entries = parse_npmrc_codeartifact_entries(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].0,
            "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/my-repo/"
        );
        assert_eq!(entries[0].1.domain, "my-domain");
        assert_eq!(entries[0].1.domain_owner, "123456789012");
        assert_eq!(entries[0].1.region, "us-east-1");
    }

    #[test]
    fn test_parse_npmrc_codeartifact_entries_no_matches() {
        let content = "//registry.npmjs.org/:_authToken=some-token\n\
                        registry=https://registry.npmjs.org/\n";
        let entries = parse_npmrc_codeartifact_entries(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_npmrc_codeartifact_entries_multiple_repos_same_domain() {
        let content = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo-a/:_authToken=tok-a\n\
                        //my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo-b/:_authToken=tok-b\n";
        let entries = parse_npmrc_codeartifact_entries(content);
        assert_eq!(entries.len(), 2);
        // Both share the same domain/owner/region
        assert_eq!(entries[0].1.domain, entries[1].1.domain);
        assert_eq!(entries[0].1.domain_owner, entries[1].1.domain_owner);
        assert_eq!(entries[0].1.region, entries[1].1.region);
        // But have different prefixes (different repos)
        assert_ne!(entries[0].0, entries[1].0);
    }

    #[test]
    fn test_parse_npmrc_codeartifact_entries_mixed_content() {
        let content = "# A comment\n\
                        \n\
                        //registry.npmjs.org/:_authToken=npm-token\n\
                        //my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/my-repo/:_authToken=ca-token\n\
                        registry=https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/my-repo/\n\
                        save-exact=true\n";
        let entries = parse_npmrc_codeartifact_entries(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.domain, "my-domain");
    }

    #[test]
    fn test_parse_npmrc_skips_commented_out_entries() {
        let content = "\
            # //my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/:_authToken=old\n\
            ; //my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo2/:_authToken=old2\n\
            //my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/active/:_authToken=live\n";
        let entries = parse_npmrc_codeartifact_entries(content);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].0.contains("/active/"));
    }

    #[test]
    fn test_parse_npmrc_skips_env_var_tokens() {
        let content = "\
            //my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/:_authToken=${CODEARTIFACT_AUTH_TOKEN}\n\
            //other-111111111111.d.codeartifact.eu-west-1.amazonaws.com/npm/pkg/:_authToken=raw-token\n";
        let entries = parse_npmrc_codeartifact_entries(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.domain, "other");
        assert_eq!(entries[0].1.region, "eu-west-1");
    }

    #[test]
    fn test_parse_npmrc_empty_string() {
        let entries = parse_npmrc_codeartifact_entries("");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_npmrc_no_trailing_newline() {
        let content = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/:_authToken=tok";
        let entries = parse_npmrc_codeartifact_entries(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.domain, "my-domain");
    }

    #[test]
    fn test_parse_npmrc_token_containing_equals() {
        let content = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/:_authToken=abc=def=\n";
        let entries = parse_npmrc_codeartifact_entries(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.domain, "my-domain");
    }

    #[test]
    fn test_parse_npmrc_pnpm_token_helper_produces_no_entries() {
        let content = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/:tokenHelper=/usr/local/bin/vouch-pnpm-tokenhelper\n\
             registry=https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/\n";
        let entries = parse_npmrc_codeartifact_entries(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_rewrite_npmrc_tokens_single_replacement() {
        let content = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/:_authToken=old-token\n\
                        registry=https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/\n";
        let prefix = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/";
        let map = BTreeMap::from([(prefix, "new-token")]);
        let (result, changed) = rewrite_npmrc_tokens(content, &map);
        assert!(changed);
        assert!(result.contains(":_authToken=new-token"));
        assert!(!result.contains("old-token"));
        assert!(result.contains("registry="));
    }

    #[test]
    fn test_rewrite_npmrc_tokens_multiple_repos() {
        let content = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo-a/:_authToken=tok-a\n\
                        //my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo-b/:_authToken=tok-b\n";
        let prefix_a =
            "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo-a/";
        let prefix_b =
            "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo-b/";
        let map = BTreeMap::from([(prefix_a, "fresh-a"), (prefix_b, "fresh-b")]);
        let (result, changed) = rewrite_npmrc_tokens(content, &map);
        assert!(changed);
        assert!(result.contains("_authToken=fresh-a"));
        assert!(result.contains("_authToken=fresh-b"));
    }

    #[test]
    fn test_rewrite_npmrc_tokens_preserves_non_ca_lines() {
        let content = "# global config\n\
                        //registry.npmjs.org/:_authToken=npm-tok\n\
                        //my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/:_authToken=old\n\
                        save-exact=true\n";
        let prefix = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/";
        let map = BTreeMap::from([(prefix, "new")]);
        let (result, changed) = rewrite_npmrc_tokens(content, &map);
        assert!(changed);
        assert!(result.contains("# global config"));
        assert!(result.contains("//registry.npmjs.org/:_authToken=npm-tok"));
        assert!(result.contains("save-exact=true"));
        assert!(result.contains("_authToken=new"));
    }

    #[test]
    fn test_rewrite_npmrc_tokens_with_leading_whitespace() {
        let content = "  //my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/:_authToken=old\n";
        let prefix = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/";
        let map = BTreeMap::from([(prefix, "new")]);
        let (result, changed) = rewrite_npmrc_tokens(content, &map);
        assert!(changed);
        assert!(result.contains("_authToken=new"));
    }

    #[test]
    fn test_rewrite_npmrc_tokens_no_matches() {
        let content = "//registry.npmjs.org/:_authToken=npm-tok\nsave-exact=true\n";
        let prefix = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/";
        let map = BTreeMap::from([(prefix, "new")]);
        let (result, _changed) = rewrite_npmrc_tokens(content, &map);
        assert!(result.contains("//registry.npmjs.org/:_authToken=npm-tok"));
        assert!(result.contains("save-exact=true"));
    }

    #[test]
    fn test_rewrite_npmrc_tokens_empty_map() {
        let content = "//my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/repo/:_authToken=old\n";
        let map: BTreeMap<&str, &str> = BTreeMap::new();
        let (_result, changed) = rewrite_npmrc_tokens(content, &map);
        assert!(!changed);
    }

    #[test]
    fn test_build_npmrc_content_fresh() {
        let host = "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com";
        let content = build_npmrc_content("", host, "my-repo", "the-token");
        assert!(content.contains(":_authToken=the-token"));
        assert!(content.contains(&format!("registry=https://{host}/npm/my-repo/")));
    }

    #[test]
    fn test_build_npmrc_content_idempotent() {
        let host = "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com";
        let first = build_npmrc_content("", host, "my-repo", "tok1");
        let second = build_npmrc_content(&first, host, "my-repo", "tok2");
        assert!(second.contains("_authToken=tok2"));
        assert!(!second.contains("tok1"));
        let token_count = second.matches("_authToken").count();
        assert_eq!(token_count, 1, "should not duplicate entries");
    }

    #[test]
    fn test_build_npmrc_pnpm_content_fresh() {
        let host = "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com";
        let helper = std::path::PathBuf::from("/usr/local/bin/vouch-pnpm-tokenhelper");
        let content = build_npmrc_pnpm_content("", host, "my-repo", &helper);
        assert!(content.contains(":tokenHelper=/usr/local/bin/vouch-pnpm-tokenhelper"));
        assert!(content.contains(&format!("registry=https://{host}/npm/my-repo/")));
    }

    #[test]
    fn test_build_npmrc_pnpm_content_idempotent() {
        let host = "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com";
        let helper = std::path::PathBuf::from("/usr/local/bin/vouch-pnpm-tokenhelper");
        let first = build_npmrc_pnpm_content("", host, "my-repo", &helper);
        let second = build_npmrc_pnpm_content(&first, host, "my-repo", &helper);
        let helper_count = second.matches("tokenHelper").count();
        assert_eq!(helper_count, 1, "should not duplicate entries");
    }

    #[test]
    fn test_token_cache_key() {
        let registry = CodeArtifactRegistry {
            domain: "my-domain".to_string(),
            domain_owner: "123456789012".to_string(),
            region: "us-east-1".to_string(),
            domain_suffix: "amazonaws.com".to_string(),
        };
        assert_eq!(
            registry.token_cache_key(),
            "my-domain:123456789012:us-east-1"
        );
    }

    proptest! {
        #[test]
        fn prop_parse_npmrc_entries_no_panic(content in "\\PC*") {
            let _ = parse_npmrc_codeartifact_entries(&content);
        }

        #[test]
        fn prop_rewrite_npmrc_tokens_no_panic(content in "\\PC*") {
            let map: BTreeMap<&str, &str> = BTreeMap::new();
            let _ = rewrite_npmrc_tokens(&content, &map);
        }
    }
}
