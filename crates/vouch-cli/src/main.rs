//! Vouch CLI - Hardware-backed identity for developers.

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
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
    Login,
    /// Show current session status.
    Status,
    /// End your current session.
    Logout,
    /// Manage registered security keys.
    ///
    /// Without a subcommand, opens an interactive menu.
    Keys {
        #[command(subcommand)]
        command: Option<KeysCommands>,
    },
    /// Obtain credentials for various services.
    Credential {
        #[command(subcommand)]
        command: CredentialCommands,
    },
    /// Configure integrations.
    Setup {
        #[command(subcommand)]
        command: SetupCommands,
    },
    /// Generate shell completions.
    Completions(commands::completions::CompletionsArgs),
    /// Check your Vouch environment for common issues.
    Doctor,
}

#[derive(Subcommand)]
enum KeysCommands {
    /// List all registered keys (non-interactive).
    List,
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

#[derive(Subcommand)]
enum CredentialCommands {
    /// Obtain temporary AWS credentials.
    Aws {
        /// AWS IAM role ARN to assume.
        #[arg(long)]
        role: String,
        /// Session name for the assumed role.
        #[arg(long)]
        session_name: Option<String>,
    },
    /// Obtain an SSH certificate.
    Ssh {
        /// Path to SSH private key (default: ~/.ssh/id_ed25519_vouch).
        #[arg(long)]
        key: Option<String>,
    },
}

#[derive(Subcommand)]
enum SetupCommands {
    /// Configure AWS CLI/SDK to use Vouch credentials.
    Aws {
        /// AWS profile name to configure.
        #[arg(long, default_value = "vouch")]
        profile: String,
        /// AWS IAM role ARN to assume.
        #[arg(long)]
        role: String,
        /// Add the profile to ~/.aws/config.
        #[arg(long)]
        add_profile: bool,
    },
    /// Configure SSH to use Vouch certificates.
    Ssh {
        /// Host patterns to trust with this CA (e.g., "*.example.com").
        /// If specified, adds entry to ~/.ssh/known_hosts.
        #[arg(long)]
        hosts: Option<String>,
    },
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
        Commands::Login => commands::login::run(&server).await,
        Commands::Status => commands::status::run(&server).await,
        Commands::Logout => commands::logout::run().await,
        Commands::Keys { command } => match command {
            None => commands::keys::interactive(&server).await,
            Some(KeysCommands::List) => commands::keys::list(&server).await,
            Some(KeysCommands::Remove { id, force }) => {
                commands::keys::remove(&server, &id, force).await
            }
            Some(KeysCommands::Rename { id, name }) => {
                commands::keys::rename(&server, &id, &name).await
            }
        },
        Commands::Credential { command } => match command {
            CredentialCommands::Aws { role, session_name } => {
                commands::credential::aws::run(&server, &role, session_name.as_deref()).await
            }
            CredentialCommands::Ssh { key } => {
                commands::credential::ssh::run(&server, key.as_deref()).await
            }
        },
        Commands::Setup { command } => match command {
            SetupCommands::Aws {
                profile,
                role,
                add_profile,
            } => commands::setup::aws::run(&profile, &role, add_profile).await,
            SetupCommands::Ssh { hosts } => {
                commands::setup::ssh::run(&server, hosts.as_deref()).await
            }
        },
        Commands::Completions(args) => {
            let mut cmd = Cli::command();
            commands::completions::run(&args, &mut cmd);
            Ok(())
        }
        Commands::Doctor => commands::doctor::run(&server).await,
    }
}
