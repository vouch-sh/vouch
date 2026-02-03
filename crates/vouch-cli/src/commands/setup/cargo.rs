// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo setup command.
//!
//! Configures Cargo to use Vouch for private registry authentication.

use anyhow::{Context, Result};

use crate::integrations::cargo::CargoConfig;

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

    // Build the provider command as array parts
    let command: Vec<&str> = vec![&vouch_path_str, "credential", "cargo", "--"];

    if configure {
        configure_cargo(registry, &command)?;
    } else {
        show_instructions(registry, &command);
    }

    println!();
    println!("For more information, see:");
    println!("  https://doc.rust-lang.org/cargo/reference/registry-authentication.html");

    Ok(())
}

/// Show manual configuration instructions.
fn show_instructions(registry: Option<&str>, command: &[&str]) {
    println!("Add to ~/.cargo/config.toml:\n");

    let formatted = format_toml_array(command);

    if let Some(reg) = registry {
        // Configure specific registry
        println!("[registries.{}]", reg);
        println!("credential-provider = {}", formatted);
    } else {
        // Configure as global provider
        println!("[registry]");
        println!("global-credential-providers = {}", formatted);
        println!();
        println!("# Or for a specific registry:");
        println!("# [registries.my-private-registry]");
        println!("# credential-provider = {}", formatted);
    }

    println!();
    println!("Or run: vouch setup cargo --configure");
}

/// Format a command as a TOML array.
fn format_toml_array(command: &[&str]) -> String {
    let parts: Vec<String> = command.iter().map(|s| format!("\"{}\"", s)).collect();
    format!("[{}]", parts.join(", "))
}

/// Automatically configure Cargo to use Vouch.
fn configure_cargo(registry: Option<&str>, command: &[&str]) -> Result<()> {
    let config_path = CargoConfig::default_path()?;
    let mut config = CargoConfig::load_from(config_path.clone())
        .unwrap_or_else(|_| CargoConfig::empty(config_path));

    // Check if already configured
    if let Some(reg) = registry {
        if config.has_registry_vouch(reg) {
            println!("Vouch is already configured for registry '{}'\n", reg);
            println!("Configuration file: {}", config.path().display());
            return Ok(());
        }
    } else if config.has_global_vouch() {
        println!("Vouch is already configured as global credential provider\n");
        println!("Configuration file: {}", config.path().display());
        return Ok(());
    }

    // Configure based on registry option
    if let Some(reg) = registry {
        config.set_registry_provider(reg, command);
        config.save()?;
        println!("Cargo configured for registry '{}'", reg);
    } else {
        config.set_global_provider(command);
        config.save()?;
        println!("Cargo configured with global credential provider");
    }

    println!();
    println!("Configuration added to: {}", config.path().display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_toml_array_simple() {
        let result = format_toml_array(&["vouch", "credential", "cargo", "--"]);
        assert_eq!(result, r#"["vouch", "credential", "cargo", "--"]"#);
    }

    #[test]
    fn test_format_toml_array_with_path() {
        let result = format_toml_array(&["/usr/local/bin/vouch", "credential", "cargo", "--"]);
        assert_eq!(
            result,
            r#"["/usr/local/bin/vouch", "credential", "cargo", "--"]"#
        );
    }
}
