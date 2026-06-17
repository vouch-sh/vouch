// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo setup command.
//!
//! Configures Cargo to use Vouch for private registry authentication.

use anyhow::Result;
use vouch_cli::tr_println;

use crate::install_path::resolve_install_path;
use crate::integrations::cargo::CargoConfig;

/// Run the Cargo setup command.
///
/// This command:
/// 1. Shows/configures Cargo credential provider settings
///
/// # Arguments
/// * `registry` - Optional registry name to configure (default: all registries)
/// * `configure` - If true, automatically configure Cargo; if false, just show instructions
pub(crate) async fn run(registry: Option<&str>, configure: bool) -> Result<()> {
    tr_println!("setup-cargo-header");
    println!();

    // Get vouch binary path
    let vouch_path = resolve_install_path();
    let vouch_path_str = vouch_path.display().to_string();

    // Build the provider command as array parts
    let command: Vec<&str> = vec![&vouch_path_str, "credential", "cargo", "--"];

    if configure {
        configure_cargo(registry, &command)?;
    } else {
        show_instructions(registry, &command);
    }

    println!();
    tr_println!("setup-cargo-more-info");

    Ok(())
}

/// Show manual configuration instructions.
fn show_instructions(registry: Option<&str>, command: &[&str]) {
    let formatted = format_toml_array(command);
    match registry {
        Some(reg) => tr_println!(
            "setup-cargo-instructions-specific",
            registry = reg,
            command = formatted.as_str(),
        ),
        None => tr_println!(
            "setup-cargo-instructions-global",
            command = formatted.as_str(),
        ),
    }
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
            tr_println!("setup-cargo-already-registry", name = reg);
            println!();
            tr_println!(
                "setup-cargo-config-file",
                path = config.path().display().to_string()
            );
            return Ok(());
        }
    } else if config.has_global_vouch() {
        tr_println!("setup-cargo-already-global");
        println!();
        tr_println!(
            "setup-cargo-config-file",
            path = config.path().display().to_string()
        );
        return Ok(());
    }

    // Configure based on registry option
    if let Some(reg) = registry {
        config.set_registry_provider(reg, command);
        config.save()?;
        tr_println!("setup-cargo-configured-registry", name = reg);
    } else {
        config.set_global_provider(command);
        config.save()?;
        tr_println!("setup-cargo-configured-global");
    }

    println!();
    tr_println!(
        "setup-cargo-config-added",
        path = config.path().display().to_string()
    );

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
