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
}

/// Run the CodeArtifact setup command.
///
/// Configures the specified package manager to use a CodeArtifact repository
/// authenticated via Vouch.
///
/// # Arguments
/// * `server` - Vouch server URL
/// * `tool` - Package manager to configure ("cargo", "pip", "npm")
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

/// Install a `keyring` wrapper script that delegates to `vouch credential pip`.
///
/// pip calls `keyring get <url> <username>` when `keyring-provider = subprocess`
/// is configured. This wrapper makes vouch handle those calls.
fn install_keyring_wrapper() -> Result<()> {
    let vouch_path = std::env::current_exe().context("could not determine vouch binary path")?;
    let vouch_path_str = vouch_path.display();

    // Determine the install directory
    let home = dirs::home_dir().context("could not determine home directory")?;
    let bin_dir = home.join(".local").join("bin");
    std::fs::create_dir_all(&bin_dir)
        .with_context(|| format!("failed to create {}", bin_dir.display()))?;

    let keyring_path = bin_dir.join("keyring");

    // Don't overwrite if it exists and isn't ours
    if keyring_path.exists() {
        let existing = std::fs::read_to_string(&keyring_path)
            .with_context(|| format!("failed to read {}", keyring_path.display()))?;
        if !existing.contains("vouch credential pip") {
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
            println!("  2. Or manually create a wrapper that delegates to vouch:");
            println!("     exec {vouch_path_str} credential pip \"$@\"");
            return Ok(());
        }
    }

    let script = format!("#!/bin/sh\nexec \"{vouch_path_str}\" credential pip \"$@\"\n");

    crate::utils::atomic_write_executable(&keyring_path, script.as_bytes())
        .with_context(|| format!("failed to write {}", keyring_path.display()))?;

    println!("Installed keyring wrapper: {}", keyring_path.display());

    // Check if the bin directory is in PATH
    let bin_dir_str = bin_dir.display().to_string();
    let in_path = std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .any(|p| p == bin_dir_str);
    if !in_path {
        println!();
        println!("WARNING: {} is not in your PATH.", bin_dir.display());
        println!("Add it to your shell profile:");
        println!("  export PATH=\"{}:$PATH\"", bin_dir.display());
    }

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
        if let Some(parent) = path.parent() {
            return Ok(parent.to_path_buf());
        }
    }

    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".config").join("pip"))
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

    Ok(())
}

/// Write npm configuration file (~/.npmrc).
///
/// Preserves existing entries while updating/adding CodeArtifact-specific lines.
/// Only lines matching this specific host/repo are replaced.
fn write_npmrc(ca_host: &str, repository: &str, token: &str) -> Result<()> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let npmrc_path = home.join(".npmrc");

    // Read existing content, preserving lines not related to this registry
    let ca_prefix = format!("//{ca_host}/npm/{repository}/");
    let ca_registry = format!("registry=https://{ca_host}/npm/{repository}/");
    let mut lines: Vec<String> = if npmrc_path.exists() {
        std::fs::read_to_string(&npmrc_path)
            .with_context(|| format!("failed to read {}", npmrc_path.display()))?
            .lines()
            .filter(|line| !line.starts_with(&ca_prefix) && !line.starts_with(&ca_registry))
            .map(String::from)
            .collect()
    } else {
        Vec::new()
    };

    // Append the new CodeArtifact entries
    lines.push(format!("{ca_prefix}:_authToken={token}"));
    lines.push(format!("registry=https://{ca_host}/npm/{repository}/"));

    let content = lines.join("\n") + "\n";

    crate::utils::atomic_write_secure(&npmrc_path, content.as_bytes())
        .with_context(|| format!("failed to write {}", npmrc_path.display()))?;

    println!("Wrote npm config: {}", npmrc_path.display());

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
        // Match lines like: //{ca_host}/npm/{repo}/:_authToken={token}
        if let Some((prefix, _token)) = trimmed.split_once(":_authToken=") {
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
        let key = format!("{}:{}:{}", registry.domain, registry.domain_owner, registry.region);
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
        let key = format!("{}:{}:{}", registry.domain, registry.domain_owner, registry.region);
        if let Some(token) = tokens.get(&key) {
            prefix_to_token.insert(prefix.as_str(), token);
        }
    }

    // Rewrite ~/.npmrc line by line, replacing matched _authToken values
    let mut new_lines: Vec<String> = Vec::new();
    let mut refreshed = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some((prefix, _old_token)) = trimmed.split_once(":_authToken=")
            && let Some(new_token) = prefix_to_token.get(prefix)
        {
            new_lines.push(format!("{prefix}:_authToken={}", new_token.expose_secret()));
            refreshed = true;
            continue;
        }
        new_lines.push(line.to_string());
    }

    if refreshed {
        let new_content = new_lines.join("\n") + "\n";
        crate::utils::atomic_write_secure(&npmrc_path, new_content.as_bytes())
            .with_context(|| format!("failed to write {}", npmrc_path.display()))?;
        println!("Refreshed CodeArtifact token in ~/.npmrc");
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    #[test]
    fn test_tool_value_enum() {
        // ValueEnum::from_str is case-insensitive by default
        assert_eq!(Tool::from_str("cargo", true), Ok(Tool::Cargo));
        assert_eq!(Tool::from_str("Cargo", true), Ok(Tool::Cargo));
        assert_eq!(Tool::from_str("pip", true), Ok(Tool::Pip));
        assert_eq!(Tool::from_str("npm", true), Ok(Tool::Npm));
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
}
