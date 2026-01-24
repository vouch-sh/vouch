//! Key management commands - list and remove registered security keys.

use anyhow::Result;
use vouch_common::{DeleteKeyResponse, ListKeysResponse};

use crate::client::VouchClient;

/// List all registered keys.
pub async fn list(server: &str) -> Result<()> {
    let client = VouchClient::new(server)?;

    let response: ListKeysResponse = client.get_authenticated("/v1/keys").await?;

    if response.keys.is_empty() {
        println!("No keys registered.");
        return Ok(());
    }

    println!("Registered keys:\n");
    let header = format!(
        "{:<36}  {:<20}  {:<20}  {}",
        "ID", "NAME", "CREATED", "CURRENT"
    );
    println!("{header}");
    println!("{}", "-".repeat(90));

    for key in response.keys {
        let current = if key.is_current_session { "*" } else { "" };
        // Parse and format the created_at timestamp for display
        let created = format_timestamp(&key.created_at);
        println!(
            "{:<36}  {:<20}  {:<20}  {}",
            key.id, key.name, created, current
        );
    }

    println!("\n* = key used for current session");

    Ok(())
}

/// Remove a registered key.
pub async fn remove(server: &str, key_id: &str, force: bool) -> Result<()> {
    let client = VouchClient::new(server)?;

    // First, get key info to show the name
    let keys_response: ListKeysResponse = client.get_authenticated("/v1/keys").await?;
    let key = keys_response.keys.iter().find(|k| k.id == key_id);

    let key_name = match key {
        Some(k) => k.name.clone(),
        None => {
            anyhow::bail!("Key not found: {key_id}");
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

/// Format a timestamp for display.
fn format_timestamp(timestamp: &str) -> String {
    // Try to parse as jiff timestamp and format nicely
    if let Ok(ts) = timestamp.parse::<jiff::Timestamp>() {
        // Format as YYYY-MM-DD HH:MM
        let dt = ts.to_zoned(jiff::tz::TimeZone::system());
        return format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute()
        );
    }
    // Fall back to showing the raw timestamp
    timestamp.to_string()
}
