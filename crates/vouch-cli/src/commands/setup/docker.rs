// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Docker setup command.
//!
//! Configures Docker to use Vouch for container registry authentication.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vouch_cli::{tr, tr_args, tr_println};

use crate::config::Config;
use crate::install_path::resolve_install_path;

/// Docker config.json structure (partial).
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DockerConfig {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    cred_helpers: HashMap<String, String>,
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

/// Run the Docker setup command.
///
/// This command:
/// 1. Checks if the user is logged in
/// 2. Creates symlink for docker-credential-vouch
/// 3. Optionally configures ~/.docker/config.json
///
/// # Arguments
/// * `registries` - Registry URLs to configure (e.g., "ghcr.io", "123456789012.dkr.ecr.us-east-1.amazonaws.com")
/// * `configure` - If true, automatically configure Docker; if false, just show instructions
pub(crate) async fn run(registries: &[String], configure: bool) -> Result<()> {
    // Load config to verify enrollment
    let config = Config::load().with_context(|| tr!("setup-err-load-config"))?;
    let _server = config
        .server_url()
        .with_context(|| tr!("setup-err-not-configured"))?;

    tr_println!("setup-docker-header");
    println!();

    // Get vouch binary path
    let vouch_path = resolve_install_path();

    // Determine where to create the symlink
    let symlink_path = crate::utils::vouch_helper_path("docker-credential-vouch")?;

    if configure {
        // Create symlink
        create_credential_helper_symlink(&vouch_path, &symlink_path)?;

        // Configure Docker if registries provided
        if !registries.is_empty() {
            configure_docker_config(registries)?;
        }

        tr_println!("setup-docker-configured");
        println!();

        if registries.is_empty() {
            tr_println!("setup-docker-no-registries-add");
            print_example_config();
        } else {
            tr_println!("setup-docker-configured-registries-header");
            for registry in registries {
                tr_println!(
                    "setup-docker-registry-line",
                    indent = "  ",
                    registry = registry
                );
            }
        }
    } else {
        // Show manual instructions
        tr_println!(
            "setup-docker-step1-block",
            vouch_path = vouch_path.display().to_string(),
            symlink_path = symlink_path.display().to_string(),
        );
        println!();

        tr_println!("setup-docker-step2-header");
        print_example_config();

        println!();
        tr_println!("setup-docker-tail-block");
    }

    println!();
    tr_println!("setup-docker-supported-block");

    Ok(())
}

/// Create the docker-credential-vouch symlink or wrapper script.
fn create_credential_helper_symlink(
    vouch_path: &std::path::Path,
    symlink_path: &std::path::Path,
) -> Result<()> {
    let batch_content = format!(
        "@echo off\r\n\"{}\" credential docker %1\r\n",
        vouch_path.display()
    );
    crate::utils::create_symlink_with_fallback(vouch_path, symlink_path, &batch_content)
}

/// Configure ~/.docker/config.json with the credential helper.
fn configure_docker_config(registries: &[String]) -> Result<()> {
    let home = dirs::home_dir().with_context(|| tr!("setup-err-no-home"))?;
    let docker_config_path = home.join(".docker/config.json");

    // Load existing config or create new
    let mut config: DockerConfig = if docker_config_path.exists() {
        let content = std::fs::read_to_string(&docker_config_path).with_context(|| {
            tr_args!(
                "setup-docker-err-read",
                path = docker_config_path.display().to_string()
            )
        })?;
        serde_json::from_str(&content).with_context(|| {
            tr_args!(
                "setup-docker-err-parse",
                path = docker_config_path.display().to_string()
            )
        })?
    } else {
        DockerConfig::default()
    };

    // Add registries
    for registry in registries {
        config
            .cred_helpers
            .insert(registry.clone(), "vouch".to_string());
    }

    // Ensure .docker directory exists
    if let Some(parent) = docker_config_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).with_context(|| {
            tr_args!(
                "setup-docker-err-create-dir",
                path = parent.display().to_string()
            )
        })?;
    }

    // Write config atomically to avoid corruption if interrupted
    let json =
        serde_json::to_string_pretty(&config).with_context(|| tr!("setup-docker-err-serialize"))?;
    vouch_common::fs::atomic_write(&docker_config_path, json.as_bytes()).with_context(|| {
        tr_args!(
            "setup-docker-err-write",
            path = docker_config_path.display().to_string()
        )
    })?;

    tr_println!(
        "setup-docker-updated-file",
        path = docker_config_path.display().to_string()
    );

    Ok(())
}

/// Print example Docker config.json.
///
/// JSON snippet: machine-readable, stays English so users can paste it
/// verbatim into `~/.docker/config.json`.
fn print_example_config() {
    println!("  {{");
    println!("    \"credHelpers\": {{");
    println!("      \"ghcr.io\": \"vouch\",");
    println!("      \"123456789012.dkr.ecr.us-east-1.amazonaws.com\": \"vouch\"");
    println!("    }}");
    println!("  }}");
}

/// Check if Docker credential helper is configured.
pub(crate) fn check_docker_config() -> DockerSetupStatus {
    // Check for symlink or batch file
    let symlink_exists =
        crate::utils::vouch_helper_path("docker-credential-vouch").is_ok_and(|p| {
            #[cfg(unix)]
            {
                p.exists() || p.is_symlink()
            }
            #[cfg(windows)]
            {
                // On Windows, check for the .bat file
                p.with_extension("bat").exists()
            }
        });

    // Check Docker config
    let configured_registries = get_configured_registries().unwrap_or_default();

    DockerSetupStatus {
        symlink_exists,
        configured_registries,
    }
}

/// Docker setup status.
pub(crate) struct DockerSetupStatus {
    pub symlink_exists: bool,
    pub configured_registries: Vec<String>,
}

/// Get registries configured to use vouch in Docker config.
fn get_configured_registries() -> Result<Vec<String>> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let docker_config_path = home.join(".docker/config.json");

    if !docker_config_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&docker_config_path)?;
    let config: DockerConfig = serde_json::from_str(&content)?;

    let registries: Vec<String> = config
        .cred_helpers
        .iter()
        .filter(|(_, helper)| *helper == "vouch")
        .map(|(registry, _)| registry.clone())
        .collect();

    Ok(registries)
}
