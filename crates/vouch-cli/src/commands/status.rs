//! Show current session status

use anyhow::Result;
use colored::Colorize;
use vouch_common::SessionStatus;

use crate::client::VouchClient;
use crate::config::Config;

pub async fn run(client: &VouchClient, config: &Config) -> Result<()> {
    let token = match &config.session_token {
        Some(t) => t,
        None => {
            println!("{}", "Not authenticated".yellow());
            println!();
            println!("Run {} to authenticate.", "vouch login".cyan());
            return Ok(());
        }
    };

    let status: SessionStatus = client
        .get("/v1/auth/status", Some(token))
        .await?;

    if status.authenticated {
        println!("{}", "✓ Authenticated".green().bold());
        println!();
        
        if let Some(email) = status.user_email {
            println!("  User:        {}", email);
        }
        
        if let Some(device) = status.device_name {
            println!("  Device:      {}", device);
        }
        
        if let Some(secs) = status.expires_in_seconds {
            let hours = secs / 3600;
            let mins = (secs % 3600) / 60;
            if hours > 0 {
                println!("  Expires in:  {}h {}m", hours, mins);
            } else {
                println!("  Expires in:  {}m", mins);
            }
        }

        if status.active_delegations > 0 {
            println!(
                "  Delegations: {} active",
                status.active_delegations.to_string().cyan()
            );
        }
    } else {
        println!("{}", "Session expired".yellow());
        println!();
        println!("Run {} to re-authenticate.", "vouch login".cyan());
    }

    Ok(())
}
