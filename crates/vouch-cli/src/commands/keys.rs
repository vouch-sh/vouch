// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Key management commands - list, rename, and remove registered security keys.

use anyhow::{Result, bail};
use inquire::{
    Confirm, Select,
    ui::{RenderConfig, Styled},
};
use vouch_common::{
    DeleteKeyResponse, KeyInfo, ListKeysResponse, RenameKeyRequest, RenameKeyResponse,
};

use crate::client::VouchClient;

/// Interactive key management.
pub async fn interactive(server: &str) -> Result<()> {
    let client = VouchClient::new(server)?;

    loop {
        // Fetch current keys
        let response: ListKeysResponse = client.get_authenticated("/v1/keys").await?;

        if response.keys.is_empty() {
            println!("No keys registered.");
            return Ok(());
        }

        // Build display options
        let options: Vec<String> = response.keys.iter().map(format_key_for_display).collect();

        // Add quit option
        let mut menu_options = options.clone();
        menu_options.push("Exit".to_string());

        // Print prompt on its own line
        println!("\nSelect a key to manage:\n");

        // Configure render to remove all prefixes for clean alignment
        let render_config = RenderConfig::default()
            .with_prompt_prefix(Styled::new(""))
            .with_highlighted_option_prefix(Styled::new(">"));

        // Show interactive menu (disable filtering to prevent accidental key presses)
        let selection = Select::new("\n", menu_options)
            .with_render_config(render_config)
            .with_help_message("↑↓ to move, Enter to select, Esc to exit")
            .without_filtering()
            .prompt();

        match selection {
            Ok(selected) => {
                if selected == "Exit" {
                    return Ok(());
                }

                // Find the selected key
                let selected_idx = options.iter().position(|o| o == &selected);
                if let Some(idx) = selected_idx
                    && let Some(key) = response.keys.get(idx)
                {
                    // Show action menu for selected key
                    if !handle_key_action(&client, key).await? {
                        return Ok(());
                    }
                }
            }
            Err(inquire::InquireError::OperationCanceled) => {
                // User pressed Esc
                return Ok(());
            }
            Err(inquire::InquireError::OperationInterrupted) => {
                // User pressed Ctrl+C
                return Ok(());
            }
            Err(e) => {
                bail!("Selection error: {e}");
            }
        }
    }
}

/// Handle action on a selected key.
/// Returns false if we should exit the interactive loop.
async fn handle_key_action(client: &VouchClient, key: &KeyInfo) -> Result<bool> {
    let current_marker = if key.is_current_session {
        " (current session)"
    } else {
        ""
    };

    let actions = vec!["Delete this key", "Back to list", "Quit"];

    let prompt = format!("Key: {}{}", key.name, current_marker);
    let selection = Select::new(&prompt, actions)
        .with_help_message("Select an action")
        .prompt();

    match selection {
        Ok("Delete this key") => {
            delete_key_interactive(client, key).await?;
            Ok(true) // Continue loop to refresh list
        }
        Ok("Quit") => Ok(false),
        Ok(_) => Ok(true), // Back to list
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => {
            Ok(true) // Back to list on Esc
        }
        Err(e) => bail!("Selection error: {e}"),
    }
}

/// Delete a key with confirmation.
async fn delete_key_interactive(client: &VouchClient, key: &KeyInfo) -> Result<()> {
    let warning = if key.is_current_session {
        "\nWARNING: This is the key used for your current session. Your session will be invalidated."
    } else {
        ""
    };

    let prompt = format!("Delete key '{}'?{}", key.name, warning);

    let confirmed = Confirm::new(&prompt)
        .with_default(false)
        .with_help_message("This action cannot be undone")
        .prompt();

    match confirmed {
        Ok(true) => {
            let response: DeleteKeyResponse = client
                .delete_authenticated(&format!("/v1/keys/{}", key.id))
                .await?;

            println!("\n{}", response.message);
            if response.sessions_revoked > 0 {
                println!("  {} session(s) revoked.", response.sessions_revoked);
            }
            println!();
        }
        Ok(false) => {
            println!("Cancelled.\n");
        }
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => {
            println!("Cancelled.\n");
        }
        Err(e) => bail!("Confirmation error: {e}"),
    }

    Ok(())
}

/// Format a key for display in the interactive menu.
fn format_key_for_display(key: &KeyInfo) -> String {
    let current = if key.is_current_session {
        "(current)"
    } else {
        ""
    };
    let created = format_timestamp(&key.created_at);
    // Show device model if available, otherwise fall back to name
    let display_name = key.device_model.as_deref().unwrap_or(key.name.as_str());
    format!("{:<22} {:<18} {}", display_name, created, current)
}

/// List all registered keys (non-interactive).
pub async fn list(server: &str, json: bool) -> Result<()> {
    let client = VouchClient::new(server)?;

    let response: ListKeysResponse = client.get_authenticated("/v1/keys").await?;

    if json {
        let json_str =
            serde_json::to_string_pretty(&response.keys).unwrap_or_else(|_| "[]".to_string());
        println!("{json_str}");
        return Ok(());
    }

    if response.keys.is_empty() {
        println!("No keys registered.");
        return Ok(());
    }

    println!("Registered keys:\n");
    let header = format!(
        "{:<36}  {:<20}  {:<20}  {:<20}  {}",
        "ID", "NAME", "MODEL", "CREATED", "CURRENT"
    );
    println!("{header}");
    println!("{}", "-".repeat(115));

    for key in response.keys {
        let current = if key.is_current_session { "*" } else { "" };
        let model = key.device_model.as_deref().unwrap_or("-");
        // Parse and format the created_at timestamp for display
        let created = format_timestamp(&key.created_at);
        println!(
            "{:<36}  {:<20}  {:<20}  {:<20}  {}",
            key.id, key.name, model, created, current
        );
    }

    println!("\n* = key used for current session");

    Ok(())
}

/// Remove a registered key (non-interactive).
pub async fn remove(server: &str, key_id: &str, force: bool) -> Result<()> {
    let client = VouchClient::new(server)?;

    // First, get key info to show the name
    let keys_response: ListKeysResponse = client.get_authenticated("/v1/keys").await?;
    let key = keys_response.keys.iter().find(|k| k.id == key_id);

    let key_name = match key {
        Some(k) => k.name.clone(),
        None => {
            bail!("Key not found: {key_id}");
        }
    };

    // Prompt for confirmation unless --force is used
    if !force {
        println!("You are about to remove the key '{key_name}' (ID: {key_id}).");
        if key.map(|k| k.is_current_session).unwrap_or(false) {
            println!("WARNING: This is the key used for your current session.");
            println!("         Your session will be invalidated.");
        }
        println!();
        print!("Are you sure? [y/N] ");
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        if input != "y" && input != "yes" {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Delete the key
    let response: DeleteKeyResponse = client
        .delete_authenticated(&format!("/v1/keys/{key_id}"))
        .await?;

    println!("{}", response.message);
    if response.sessions_revoked > 0 {
        println!("  {} session(s) revoked.", response.sessions_revoked);
    }

    Ok(())
}

/// Rename a registered key (non-interactive).
pub async fn rename(server: &str, key_id: &str, new_name: &str) -> Result<()> {
    let client = VouchClient::new(server)?;

    // Validate name
    let new_name = new_name.trim();
    if new_name.is_empty() {
        bail!("Name cannot be empty");
    }
    if new_name.len() > 100 {
        bail!("Name must be 100 characters or less");
    }

    // First, verify the key exists
    let keys_response: ListKeysResponse = client.get_authenticated("/v1/keys").await?;
    let key = keys_response.keys.iter().find(|k| k.id == key_id);

    if key.is_none() {
        bail!("Key not found: {key_id}");
    }

    // Rename the key
    let req = RenameKeyRequest {
        name: new_name.to_string(),
    };
    let response: RenameKeyResponse = client
        .patch_authenticated(&format!("/v1/keys/{key_id}"), &req)
        .await?;

    println!("{}", response.message);

    Ok(())
}

/// Format a timestamp for display.
fn format_timestamp(timestamp: &str) -> String {
    // SQLite datetime format is "YYYY-MM-DD HH:MM:SS"
    // Just truncate to "YYYY-MM-DD HH:MM" by taking first 16 chars
    if timestamp.len() >= 16 {
        return timestamp.chars().take(16).collect();
    }
    // Fall back to showing the raw timestamp
    timestamp.to_string()
}
