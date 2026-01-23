//! Manage the local credential agent

use anyhow::Result;
use colored::Colorize;

use crate::config::Config;

pub async fn start(foreground: bool) -> Result<()> {
    let socket_path = Config::agent_socket_path()?;

    if foreground {
        println!("Starting vouch agent in foreground...");
        println!("Socket: {:?}", socket_path);
        println!();
        println!("Press Ctrl+C to stop.");
        println!();

        // TODO: Actually start the agent
        // For now, just show what we would do
        println!("{}", "Agent implementation pending".yellow());
        println!();
        println!("The agent will:");
        println!("  • Listen on unix socket for credential requests");
        println!("  • Cache credentials in memory (never on disk)");
        println!("  • Handle git credential helper protocol");
        println!("  • Handle AWS credential_process protocol");

        // Keep running until Ctrl+C
        tokio::signal::ctrl_c().await?;
        println!();
        println!("Agent stopped.");
    } else {
        // Daemonize
        println!("Starting vouch agent...");

        // TODO: Fork and daemonize
        println!("{}", "Daemon mode implementation pending".yellow());
        println!();
        println!("For now, use: {}", "vouch agent start --foreground".cyan());
    }

    Ok(())
}

pub async fn stop() -> Result<()> {
    let socket_path = Config::agent_socket_path()?;

    if !socket_path.exists() {
        println!("Agent is not running.");
        return Ok(());
    }

    // TODO: Send shutdown signal via socket
    println!("{}", "Agent stop implementation pending".yellow());

    Ok(())
}

pub async fn status() -> Result<()> {
    let socket_path = Config::agent_socket_path()?;

    if socket_path.exists() {
        // TODO: Actually ping the agent
        println!("{}", "Agent is running".green());
        println!("  Socket: {:?}", socket_path);
    } else {
        println!("{}", "Agent is not running".yellow());
        println!();
        println!("Start with: {}", "vouch agent start".cyan());
    }

    Ok(())
}
