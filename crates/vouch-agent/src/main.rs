//! Vouch agent daemon binary.

use clap::Parser;
use std::process::ExitCode;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use vouch_agent::server::AgentServer;
use vouch_agent::socket::remove_socket;
use vouch_agent::state::AgentState;

/// Vouch credential agent daemon.
#[derive(Parser)]
#[command(name = "vouch-agent", version, about)]
struct Args {
    /// Run in foreground (don't daemonize).
    #[arg(short, long)]
    foreground: bool,

    /// Enable verbose logging.
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose {
        EnvFilter::new("vouch_agent=debug")
    } else {
        EnvFilter::new("vouch_agent=info")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Note: For MVP, we always run in foreground mode.
    // Daemonization can be added later if needed.
    if !args.foreground {
        info!("Note: Running in foreground mode (daemonization not yet implemented)");
    }

    // Create agent state
    let state = AgentState::new();

    // Create and run server
    let server = AgentServer::new(state);

    tokio::select! {
        result = server.run() => {
            match result {
                Ok(()) => {
                    info!("Agent stopped");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    error!("Agent error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        result = tokio::signal::ctrl_c() => {
            match result {
                Ok(()) => {
                    info!("Received shutdown signal, shutting down...");
                }
                Err(e) => {
                    warn!("Failed to listen for Ctrl+C: {e}");
                }
            }
            // Clean up socket
            if let Err(e) = remove_socket() {
                error!("Failed to remove socket: {e}");
            }
            ExitCode::SUCCESS
        }
    }
}
