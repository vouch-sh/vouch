// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Docker setup command.
//!
//! Configures Docker to use Vouch for container registry authentication.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::config::Config;

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
    let config = Config::load().context("failed to load config - run 'vouch enroll' first")?;
    let _server = config
        .server_url()
        .context("not configured - run 'vouch enroll' first")?;

    println!("Docker Credential Helper Setup");
    println!("==============================\n");

    // Get vouch binary path
    let vouch_path = std::env::current_exe().context("could not determine vouch binary path")?;

    // Determine where to create the symlink
    let symlink_path = crate::utils::vouch_helper_path("docker-credential-vouch")?;

    if configure {
        // Create symlink
        create_credential_helper_symlink(&vouch_path, &symlink_path)?;

        // Configure Docker if registries provided
        if !registries.is_empty() {
            configure_docker_config(registries)?;
        }

        println!("Docker credential helper configured successfully.\n");

        if registries.is_empty() {
            println!("To configure registries, add them to ~/.docker/config.json:");
            print_example_config();
        } else {
            println!("Configured registries:");
            for registry in registries {
                println!("  - {registry}");
            }
        }
    } else {
        // Show manual instructions
        println!("Step 1: Create symlink for docker-credential-vouch\n");
        println!(
            "  ln -sf \"{}\" \"{}\"",
            vouch_path.display(),
            symlink_path.display()
        );
        println!();

        println!("Step 2: Configure Docker to use the credential helper\n");
        println!("  Add to ~/.docker/config.json:\n");
        print_example_config();

        println!("\nOr run: vouch setup docker --configure [REGISTRIES...]");
        println!();
        println!("Examples:");
        println!("  vouch setup docker --configure ghcr.io");
        println!("  vouch setup docker --configure 123456789012.dkr.ecr.us-east-1.amazonaws.com");
        println!("  vouch setup docker --configure 123456789012.dkr.ecr.us-west-2.amazonaws.com");
    }

    println!();
    println!("Supported registries:");
    println!("  - AWS ECR:     *.dkr.ecr.*.amazonaws.com");
    println!("  - GitHub:      ghcr.io");

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
    let home = dirs::home_dir().context("could not determine home directory")?;
    let docker_config_path = home.join(".docker/config.json");

    // Load existing config or create new
    let mut config: DockerConfig = if docker_config_path.exists() {
        let content = std::fs::read_to_string(&docker_config_path)
            .with_context(|| format!("failed to read {}", docker_config_path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("failed to parse {}", docker_config_path.display()))?
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
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    // Write config atomically to avoid corruption if interrupted
    let json =
        serde_json::to_string_pretty(&config).context("failed to serialize Docker config")?;
    crate::utils::atomic_write(&docker_config_path, json.as_bytes())
        .with_context(|| format!("failed to write {}", docker_config_path.display()))?;

    println!("Updated: {}", docker_config_path.display());

    Ok(())
}

/// Print example Docker config.json.
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
