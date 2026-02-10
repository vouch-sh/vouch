// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Docker setup command.
//!
//! Configures Docker to use Vouch for container registry authentication.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

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
pub async fn run(registries: &[String], configure: bool) -> Result<()> {
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
    let symlink_path = get_symlink_path()?;

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

/// Get the path where docker-credential-vouch should be created.
fn get_symlink_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;

    #[cfg(unix)]
    {
        // On Unix, use ~/.local/bin
        let local_bin = home.join(".local/bin");
        Ok(local_bin.join("docker-credential-vouch"))
    }

    #[cfg(windows)]
    {
        // On Windows, use %USERPROFILE%\.local\bin (we'll create a .bat file)
        // This matches the Unix convention but Docker will find .bat files
        let local_bin = home.join(".local").join("bin");
        Ok(local_bin.join("docker-credential-vouch"))
    }
}

/// Create the docker-credential-vouch symlink or wrapper script.
fn create_credential_helper_symlink(vouch_path: &PathBuf, symlink_path: &PathBuf) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = symlink_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
        println!("Created directory: {}", parent.display());
    }

    #[cfg(unix)]
    {
        // Remove existing symlink if present
        if symlink_path.exists() || symlink_path.is_symlink() {
            std::fs::remove_file(symlink_path)
                .with_context(|| format!("failed to remove existing {}", symlink_path.display()))?;
        }

        // Create symlink
        std::os::unix::fs::symlink(vouch_path, symlink_path)
            .with_context(|| format!("failed to create symlink at {}", symlink_path.display()))?;

        println!(
            "Created symlink: {} -> {}",
            symlink_path.display(),
            vouch_path.display()
        );

        // Check if the symlink directory is in PATH
        if let Some(parent) = symlink_path.parent() {
            let parent_str = parent.to_string_lossy().to_string();
            if let Ok(path) = std::env::var("PATH")
                && !path.contains(&parent_str)
            {
                println!();
                println!("Note: {} is not in your PATH.", parent.display());
                println!("Add it to your shell profile:");
                println!("  export PATH=\"$PATH:{}\"", parent.display());
            }
        }
    }

    #[cfg(windows)]
    {
        // On Windows, create a batch file wrapper
        // Docker looks for docker-credential-vouch.exe or docker-credential-vouch.bat
        let bat_path = symlink_path.with_extension("bat");

        // Remove existing batch file if present
        if bat_path.exists() {
            std::fs::remove_file(&bat_path)
                .with_context(|| format!("failed to remove existing {}", bat_path.display()))?;
        }

        // Create batch file that calls vouch with the docker credential subcommand
        let batch_content = format!(
            "@echo off\r\n\"{}\" credential docker %1\r\n",
            vouch_path.display()
        );
        std::fs::write(&bat_path, &batch_content)
            .with_context(|| format!("failed to create {}", bat_path.display()))?;

        println!("Created: {}", bat_path.display());

        // Check if the directory is in PATH
        if let Some(parent) = bat_path.parent() {
            let parent_str = parent.to_string_lossy().to_string();
            if let Ok(path) = std::env::var("PATH") {
                // Windows PATH uses semicolons
                if !path.split(';').any(|p| p.eq_ignore_ascii_case(&parent_str)) {
                    println!();
                    println!("Note: {} is not in your PATH.", parent.display());
                    println!("Add it to your system PATH environment variable.");
                }
            }
        }
    }

    Ok(())
}

/// Configure ~/.docker/config.json with the credential helper.
fn configure_docker_config(registries: &[String]) -> Result<()> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let docker_config_path = home.join(".docker/config.json");

    // Load existing config or create new
    let mut config: DockerConfig = if docker_config_path.exists() {
        let content = std::fs::read_to_string(&docker_config_path)
            .with_context(|| format!("failed to read {}", docker_config_path.display()))?;
        serde_json::from_str(&content).unwrap_or_default()
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

    // Write config
    let json =
        serde_json::to_string_pretty(&config).context("failed to serialize Docker config")?;
    std::fs::write(&docker_config_path, json)
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
pub fn check_docker_config() -> DockerSetupStatus {
    // Check for symlink or batch file
    let symlink_exists = get_symlink_path()
        .map(|p| {
            #[cfg(unix)]
            {
                p.exists() || p.is_symlink()
            }
            #[cfg(windows)]
            {
                // On Windows, check for the .bat file
                p.with_extension("bat").exists()
            }
        })
        .unwrap_or(false);

    // Check Docker config
    let configured_registries = get_configured_registries().unwrap_or_default();

    DockerSetupStatus {
        symlink_exists,
        configured_registries,
    }
}

/// Docker setup status.
pub struct DockerSetupStatus {
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
