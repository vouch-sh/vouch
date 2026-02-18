// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CodeArtifact setup command.
//!
//! Configures package managers (Cargo, pip, npm) to use Vouch for
//! AWS CodeArtifact registry authentication.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;

use crate::commands::credential::codeartifact::resolve_codeartifact_params;
use crate::config::{CodeArtifactProfile, Config};
use crate::integrations::aws::get_local_aws_role;
use crate::integrations::aws::sts::{
    extract_partition_from_role_arn, get_domain_suffix_for_partition,
};
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

    // Save profile to config
    let profile_name = profile.unwrap_or("default");
    let mut config = Config::load().context("failed to load config")?;
    config.save_codeartifact_profile(
        profile_name,
        CodeArtifactProfile {
            domain: domain.clone(),
            domain_owner: domain_owner.clone(),
            region: region.clone(),
        },
    )?;
    println!("Saved CodeArtifact profile '{profile_name}' to config.\n");

    // Derive domain suffix from the AWS config's role ARN partition
    // to support China, GovCloud, and other partitions.
    let partition = get_local_aws_role()
        .and_then(|role| extract_partition_from_role_arn(&role).map(String::from));
    let domain_suffix = get_domain_suffix_for_partition(partition.as_deref().unwrap_or("aws"));

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

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o755)
            .open(&keyring_path)
            .with_context(|| format!("failed to write {}", keyring_path.display()))?;
        file.write_all(script.as_bytes())
            .with_context(|| format!("failed to write {}", keyring_path.display()))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&keyring_path, &script)
            .with_context(|| format!("failed to write {}", keyring_path.display()))?;
    }

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

    // Write with restrictive permissions
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&config_path)
            .with_context(|| format!("failed to write {}", config_path.display()))?;
        ini.write_to(&mut file)
            .with_context(|| format!("failed to write {}", config_path.display()))?;
        file.flush()
            .with_context(|| format!("failed to flush {}", config_path.display()))?;
    }

    #[cfg(not(unix))]
    {
        ini.write_to_file(&config_path)
            .with_context(|| format!("failed to write {}", config_path.display()))?;
    }

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
    lines.push(format!("{ca_prefix}:always-auth=true"));
    lines.push(format!("registry=https://{ca_host}/npm/{repository}/"));

    let content = lines.join("\n") + "\n";

    // Write with restrictive permissions
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&npmrc_path)
            .with_context(|| format!("failed to write {}", npmrc_path.display()))?;
        file.write_all(content.as_bytes())
            .with_context(|| format!("failed to write {}", npmrc_path.display()))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&npmrc_path, &content)
            .with_context(|| format!("failed to write {}", npmrc_path.display()))?;
    }

    println!("Wrote npm config: {}", npmrc_path.display());

    Ok(())
}

#[cfg(test)]
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
}
