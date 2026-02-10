// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CodeArtifact setup command.
//!
//! Configures package managers (Cargo, pip, npm) to use Vouch for
//! AWS CodeArtifact registry authentication.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;

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
/// * `domain` - CodeArtifact domain name
/// * `domain_owner` - AWS account ID that owns the domain
/// * `region` - AWS region
/// * `repository` - CodeArtifact repository name
pub async fn run(
    server: &str,
    tool: Tool,
    domain: &str,
    domain_owner: &str,
    region: &str,
    repository: &str,
) -> Result<()> {
    println!("CodeArtifact Setup");
    println!("==================\n");

    // Derive domain suffix from the AWS config's role ARN partition
    // to support China, GovCloud, and other partitions.
    let partition = get_local_aws_role()
        .and_then(|role| extract_partition_from_role_arn(&role).map(String::from));
    let domain_suffix =
        get_domain_suffix_for_partition(partition.as_deref().unwrap_or("aws"));

    let ca_host = format!(
        "{domain}-{domain_owner}.d.codeartifact.{region}.{domain_suffix}"
    );

    match tool {
        Tool::Cargo => setup_cargo(&ca_host, repository),
        Tool::Pip => setup_pip(server, domain, domain_owner, region, &ca_host, repository).await,
        Tool::Npm => setup_npm(server, domain, domain_owner, region, &ca_host, repository).await,
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
    println!(
        "Cargo will automatically call Vouch to obtain a fresh CodeArtifact"
    );
    println!("token each time it needs to authenticate.");

    Ok(())
}

/// Configure Cargo registry in ~/.cargo/config.toml.
fn configure_cargo_registry(
    registry_name: &str,
    index_url: &str,
    vouch_path: &str,
) -> Result<()> {
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
    config.set_registry_provider(
        registry_name,
        &[vouch_path, "credential", "cargo", "--"],
    );
    config.set_registry_index(registry_name, index_url);

    config.save()?;
    println!("Cargo configured for CodeArtifact registry '{}'", registry_name);
    println!("Configuration written to: {}", config.path().display());

    Ok(())
}

/// Configure pip for CodeArtifact.
///
/// Gets a fresh token and writes `~/.config/pip/pip.conf` with the
/// CodeArtifact PyPI repository URL including the embedded token.
async fn setup_pip(
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

    let index_url = format!(
        "https://aws:{}@{ca_host}/pypi/{repository}/simple/",
        result.authorization_token.expose_secret()
    );

    write_pip_config(&index_url)?;

    println!();
    println!("Note: The pip token expires in ~12 hours.");
    println!("Re-run this command to refresh it.");

    Ok(())
}

/// Write pip configuration file.
fn write_pip_config(index_url: &str) -> Result<()> {
    let config_dir = get_pip_config_dir()?;
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("failed to create {}", config_dir.display()))?;

    let config_path = config_dir.join("pip.conf");
    let content = format!("[global]\nindex-url = {index_url}\n");

    // Create file with restrictive permissions atomically (avoids TOCTOU)
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
        file.write_all(content.as_bytes())
            .with_context(|| format!("failed to write {}", config_path.display()))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&config_path, &content)
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

    write_npmrc(ca_host, repository, result.authorization_token.expose_secret())?;

    println!();
    println!("Registry URL: {}", registry_url);
    println!();
    println!("Note: The npm token expires in ~12 hours.");
    println!("Re-run this command to refresh it.");

    Ok(())
}

/// Write npm configuration file (~/.npmrc).
fn write_npmrc(ca_host: &str, repository: &str, token: &str) -> Result<()> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let npmrc_path = home.join(".npmrc");

    let content = format!(
        "//{ca_host}/npm/{repository}/:_authToken={token}\n\
         //{ca_host}/npm/{repository}/:always-auth=true\n\
         registry=https://{ca_host}/npm/{repository}/\n"
    );

    // Create file with restrictive permissions atomically (avoids TOCTOU)
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
