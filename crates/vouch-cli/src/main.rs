//! Vouch CLI - Hardware-backed identity for developers.

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod client;
mod commands;
mod config;
mod fido2;

/// Hardware-backed identity for developers.
#[derive(Parser)]
#[command(
    name = "vouch",
    about = "Hardware-backed identity for developers",
    version
)]
struct Cli {
    /// Vouch server URL.
    #[arg(long, env = "VOUCH_SERVER", global = true)]
    server: Option<String>,

    /// Enable verbose output.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Enroll with browser-based OIDC + `WebAuthn` (recommended for new users).
    Enroll,
    /// Register a new `YubiKey` with the server.
    Register {
        /// Human-readable name for this `YubiKey` (e.g., "My `YubiKey` 5").
        /// Defaults to "`YubiKey`" if not specified.
        #[arg(long)]
        name: Option<String>,
        /// Your email address.
        #[arg(long)]
        email: String,
    },
    /// Authenticate with your `YubiKey`.
    Login {
        /// Your email address.
        #[arg(long)]
        email: String,
    },
    /// Show current session status.
    Status,
    /// End your current session.
    Logout,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Load config
    let config = config::Config::load()?;
    let server = cli
        .server
        .or_else(|| config.server_url().map(String::from))
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    match cli.command {
        Commands::Enroll => commands::enroll::run(&server).await,
        Commands::Register { name, email } => {
            commands::register::run(&server, name.as_deref(), &email).await
        }
        Commands::Login { email } => commands::login::run(&server, &email).await,
        Commands::Status => commands::status::run(&server).await,
        Commands::Logout => commands::logout::run().await,
    }
}
