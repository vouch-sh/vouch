// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Key management commands - list, rename, and remove registered security keys.

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use inquire::{
    Confirm, Select,
    ui::{RenderConfig, Styled},
};
use vouch_common::{
    DeleteKeyResponse, KeyInfo, ListKeysResponse, RenameKeyRequest, RenameKeyResponse,
};

use crate::client::VouchClient;
use crate::exit_code::CliError;
use vouch_cli::{tr, tr_args, tr_println};

/// Keys subcommands.
#[derive(Subcommand)]
pub(crate) enum KeysCommands {
    /// List all registered keys (non-interactive).
    List {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove a registered key (non-interactive).
    Remove {
        /// Key ID to remove.
        id: String,
        /// Skip confirmation prompt.
        #[arg(short, long)]
        force: bool,
    },
    /// Rename a registered key.
    Rename {
        /// Key ID to rename.
        id: String,
        /// New name for the key.
        name: String,
    },
}

/// Interactive key management.
pub(crate) async fn interactive(server: &str) -> Result<()> {
    let client = VouchClient::new(server).await?;

    loop {
        // Fetch current keys
        let response: ListKeysResponse = client.get_authenticated("/v1/keys").await?;

        if response.keys.is_empty() {
            tr_println!("keys-none");
            return Ok(());
        }

        // Build display options
        let options: Vec<String> = response.keys.iter().map(format_key_for_display).collect();
        let exit_label = tr!("keys-action-exit");

        // Add quit option
        let mut menu_options = options.clone();
        menu_options.push(exit_label.clone());

        // Print prompt on its own line
        println!();
        tr_println!("keys-prompt-select");
        println!();

        // Configure render to remove all prefixes for clean alignment
        let render_config = RenderConfig::default()
            .with_prompt_prefix(Styled::new(""))
            .with_highlighted_option_prefix(Styled::new(">"));

        let nav_help = tr!("keys-help-navigation");
        // Show interactive menu (disable filtering to prevent accidental key presses)
        let selection = Select::new("\n", menu_options)
            .with_render_config(render_config)
            .with_help_message(&nav_help)
            .without_filtering()
            .prompt();

        match selection {
            Ok(selected) => {
                if selected == exit_label {
                    return Ok(());
                }

                // Find the selected key
                let selected_idx = options.iter().position(|o| o == &selected);
                if let Some(idx) = selected_idx
                    && let Some(key) = response.keys.get(idx)
                {
                    // Show action menu for selected key
                    if !handle_key_action(server, &client, key).await? {
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
                bail!(tr_args!("keys-err-selection", reason = e.to_string()));
            }
        }
    }
}

/// Handle action on a selected key.
/// Returns false if we should exit the interactive loop.
async fn handle_key_action(server: &str, client: &VouchClient, key: &KeyInfo) -> Result<bool> {
    let current_marker = if key.is_current_session {
        tr!("keys-marker-current")
    } else {
        String::new()
    };

    let delete_label = tr!("keys-action-delete");
    let back_label = tr!("keys-action-back");
    let quit_label = tr!("keys-action-quit");
    let actions = vec![
        delete_label.as_str(),
        back_label.as_str(),
        quit_label.as_str(),
    ];

    let prompt = tr_args!(
        "keys-action-prompt",
        name = key.name.as_str(),
        marker = current_marker.as_str(),
    );
    let help = tr!("keys-help-action");
    let selection = Select::new(&prompt, actions)
        .with_help_message(&help)
        .prompt();

    match selection {
        Ok(choice) if choice == delete_label => {
            delete_key_interactive(server, client, key).await?;
            Ok(true) // Continue loop to refresh list
        }
        Ok(choice) if choice == quit_label => Ok(false),
        Ok(_) => Ok(true), // Back to list
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => {
            Ok(true) // Back to list on Esc
        }
        Err(e) => bail!(tr_args!("keys-err-selection", reason = e.to_string())),
    }
}

/// Delete a key with confirmation.
async fn delete_key_interactive(server: &str, client: &VouchClient, key: &KeyInfo) -> Result<()> {
    let warning = if key.is_current_session {
        format!("\n{}", tr!("keys-warn-current-session"))
    } else {
        String::new()
    };

    let prompt = tr_args!(
        "keys-confirm-delete",
        name = key.name.as_str(),
        warning = warning.as_str()
    );

    let undo_help = tr!("keys-help-undo");
    let confirmed = Confirm::new(&prompt)
        .with_default(false)
        .with_help_message(&undo_help)
        .prompt();

    match confirmed {
        Ok(true) => {
            let response = delete_with_step_up(server, client, &key.id).await?;

            println!("\n{}", response.message);
            if response.sessions_revoked > 0 {
                println!(
                    "  {}",
                    tr_args!("keys-sessions-revoked", count = response.sessions_revoked),
                );
            }
            println!();
        }
        Ok(false) => {
            tr_println!("keys-cancelled");
            println!();
        }
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => {
            tr_println!("keys-cancelled");
            println!();
        }
        Err(e) => bail!(tr_args!("keys-err-confirmation", reason = e.to_string())),
    }

    Ok(())
}

/// Attempt to delete a key, handling step-up authentication if required.
///
/// If the server returns a step-up challenge (RFC 9470), prompts the user to
/// re-authenticate via FIDO2, then retries the delete with a fresh session.
async fn delete_with_step_up(
    server: &str,
    client: &VouchClient,
    key_id: &str,
) -> Result<DeleteKeyResponse> {
    match client
        .delete_authenticated::<DeleteKeyResponse>(&format!("/v1/keys/{key_id}"))
        .await
    {
        Ok(resp) => Ok(resp),
        Err(e) => {
            if let Some(cli_err) = e.downcast_ref::<CliError>()
                && matches!(cli_err, CliError::StepUpRequired { .. })
            {
                println!();
                tr_println!("keys-step-up-needed");
                crate::commands::login::run(server, 30)
                    .await
                    .context("step-up re-authentication failed")?;

                let fresh_client = VouchClient::new(server).await?;
                Ok(fresh_client
                    .delete_authenticated(&format!("/v1/keys/{key_id}"))
                    .await?)
            } else {
                Err(e)
            }
        }
    }
}

/// Format a key for display in the interactive menu.
fn format_key_for_display(key: &KeyInfo) -> String {
    let current = if key.is_current_session {
        tr!("keys-marker-current-short")
    } else {
        String::new()
    };
    let created = format_timestamp(&key.created_at);
    // Show device model if available, otherwise fall back to name
    let display_name = key.device_model.as_deref().unwrap_or(key.name.as_str());
    format!("{:<22} {:<18} {}", display_name, created, current)
}

/// List all registered keys (non-interactive).
pub(crate) async fn list(server: &str, json: bool) -> Result<()> {
    let client = VouchClient::new(server).await?;

    let response: ListKeysResponse = client.get_authenticated("/v1/keys").await?;

    if json {
        let json_str =
            serde_json::to_string_pretty(&response.keys).unwrap_or_else(|_| "[]".to_string());
        println!("{json_str}");
        return Ok(());
    }

    if response.keys.is_empty() {
        tr_println!("keys-none");
        return Ok(());
    }

    tr_println!("keys-header");
    println!();
    let header = format!(
        "{:<36}  {:<20}  {:<20}  {:<20}  {}",
        tr!("keys-table-id"),
        tr!("keys-table-name"),
        tr!("keys-table-model"),
        tr!("keys-table-created"),
        tr!("keys-table-current"),
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

    println!();
    tr_println!("keys-legend");

    Ok(())
}

/// Remove a registered key (non-interactive).
pub(crate) async fn remove(server: &str, key_id: &str, force: bool) -> Result<()> {
    let client = VouchClient::new(server).await?;

    // First, get key info to show the name
    let keys_response: ListKeysResponse = client.get_authenticated("/v1/keys").await?;
    let key = keys_response.keys.iter().find(|k| k.id == key_id);

    let key_name = match key {
        Some(k) => k.name.clone(),
        None => {
            bail!(tr_args!("keys-err-not-found", id = key_id));
        }
    };

    // Prompt for confirmation unless --force is used
    if !force {
        tr_println!(
            "keys-confirm-remove-line",
            name = key_name.as_str(),
            id = key_id
        );
        if key.is_some_and(|k| k.is_current_session) {
            tr_println!("keys-warn-remove-current-session");
        }
        println!();
        print!("{} ", tr!("keys-confirm-y-n"));
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        if input != "y" && input != "yes" {
            tr_println!("keys-cancelled");
            return Ok(());
        }
    }

    // Delete the key (with step-up re-authentication if required)
    let response = delete_with_step_up(server, &client, key_id).await?;

    println!("{}", response.message);
    if response.sessions_revoked > 0 {
        println!(
            "  {}",
            tr_args!("keys-sessions-revoked", count = response.sessions_revoked),
        );
    }

    Ok(())
}

/// Rename a registered key (non-interactive).
pub(crate) async fn rename(server: &str, key_id: &str, new_name: &str) -> Result<()> {
    let client = VouchClient::new(server).await?;

    // Validate name
    let new_name = new_name.trim();
    if new_name.is_empty() {
        bail!(tr!("keys-err-name-empty"));
    }
    if new_name.len() > 100 {
        bail!(tr!("keys-err-name-long"));
    }

    // First, verify the key exists
    let keys_response: ListKeysResponse = client.get_authenticated("/v1/keys").await?;
    let key = keys_response.keys.iter().find(|k| k.id == key_id);

    if key.is_none() {
        bail!(tr_args!("keys-err-not-found", id = key_id));
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
fn format_timestamp(timestamp: &jiff::Timestamp) -> String {
    let s = timestamp.to_string();
    // Truncate to "YYYY-MM-DDTHH:MM" (first 16 chars of RFC 3339).
    if s.len() >= 16 {
        return s.chars().take(16).collect();
    }
    s
}
