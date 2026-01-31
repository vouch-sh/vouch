// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo setup command.
//!
//! Configures Cargo to use Vouch for private registry authentication.

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

/// Run the Cargo setup command.
///
/// This command:
/// 1. Shows/configures Cargo credential provider settings
///
/// # Arguments
/// * `registry` - Optional registry name to configure (default: all registries)
/// * `configure` - If true, automatically configure Cargo; if false, just show instructions
pub async fn run(registry: Option<&str>, configure: bool) -> Result<()> {
    println!("Cargo Credential Provider Setup");
    println!("================================\n");

    // Get vouch binary path
    let vouch_path = std::env::current_exe().context("could not determine vouch binary path")?;
    let vouch_path_str = vouch_path.display().to_string();

    // Build the provider command (the trailing `--` is required for Cargo)
    let provider_command = format!("\"{}\" credential cargo --", vouch_path_str);

    if configure {
        configure_cargo(registry, &provider_command)?;
    } else {
        show_instructions(registry, &provider_command);
    }

    println!();
    println!("For more information, see:");
    println!("  https://doc.rust-lang.org/cargo/reference/registry-authentication.html");

    Ok(())
}

/// Show manual configuration instructions.
fn show_instructions(registry: Option<&str>, provider_command: &str) {
    println!("Add to ~/.cargo/config.toml:\n");

    if let Some(reg) = registry {
        // Configure specific registry
        println!("[registries.{}]", reg);
        println!(
            "credential-provider = [{}]",
            format_toml_array(provider_command)
        );
    } else {
        // Configure as global provider
        println!("[registry]");
        println!(
            "global-credential-providers = [{}]",
            format_toml_array(provider_command)
        );
        println!();
        println!("# Or for a specific registry:");
        println!("# [registries.my-private-registry]");
        println!(
            "# credential-provider = [{}]",
            format_toml_array(provider_command)
        );
    }

    println!();
    println!("Or run: vouch setup cargo --configure");
}

/// Format a command as a TOML array of strings.
/// Input: "\"path/to/vouch\" credential cargo --"
/// Output: "\"path/to/vouch\", \"credential\", \"cargo\", \"--\""
fn format_toml_array(command: &str) -> String {
    // Split the command into parts, handling quoted paths
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in command.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }

    // Format each part as a TOML string
    parts
        .iter()
        .map(|p| {
            if p.starts_with('"') && p.ends_with('"') {
                p.clone() // Already quoted
            } else {
                format!("\"{}\"", p)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Automatically configure Cargo to use Vouch.
fn configure_cargo(registry: Option<&str>, provider_command: &str) -> Result<()> {
    let config_path = cargo_config_path()?;

    // Ensure parent directory exists
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    // Read existing config or create new
    let existing_content = if config_path.exists() {
        fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?
    } else {
        String::new()
    };

    // Check if already configured
    if existing_content.contains("vouch") && existing_content.contains("credential") {
        println!("Vouch is already configured in {}", config_path.display());
        println!();
        println!("Current configuration:");
        for line in existing_content.lines() {
            if line.contains("vouch")
                || line.contains("credential-provider")
                || line.contains("global-credential-providers")
            {
                println!("  {}", line);
            }
        }
        return Ok(());
    }

    // Build new configuration block
    let new_config = if let Some(reg) = registry {
        format!(
            "\n[registries.{}]\ncredential-provider = [{}]\n",
            reg,
            format_toml_array(provider_command)
        )
    } else {
        format!(
            "\n[registry]\nglobal-credential-providers = [{}]\n",
            format_toml_array(provider_command)
        )
    };

    // Append to existing config
    let updated_content = if existing_content.is_empty() {
        new_config.trim_start().to_string()
    } else {
        format!("{}{}", existing_content.trim_end(), new_config)
    };

    // Write config
    fs::write(&config_path, updated_content)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    if let Some(reg) = registry {
        println!("Cargo configured for registry '{}'", reg);
    } else {
        println!("Cargo configured with global credential provider");
    }
    println!();
    println!("Configuration added to: {}", config_path.display());

    Ok(())
}

/// Get the path to Cargo's config.toml.
fn cargo_config_path() -> Result<PathBuf> {
    // Check for CARGO_HOME environment variable
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        return Ok(PathBuf::from(cargo_home).join("config.toml"));
    }

    // Default to ~/.cargo/config.toml
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".cargo").join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_toml_array_simple() {
        let result = format_toml_array("vouch credential cargo --");
        assert_eq!(result, r#""vouch", "credential", "cargo", "--""#);
    }

    #[test]
    fn test_format_toml_array_with_quoted_path() {
        let result = format_toml_array("\"/path/to/vouch\" credential cargo --");
        assert_eq!(result, r#""/path/to/vouch", "credential", "cargo", "--""#);
    }

    #[test]
    fn test_format_toml_array_with_spaces_in_path() {
        let result = format_toml_array("\"/path with spaces/vouch\" credential cargo --");
        assert_eq!(
            result,
            r#""/path with spaces/vouch", "credential", "cargo", "--""#
        );
    }
}
