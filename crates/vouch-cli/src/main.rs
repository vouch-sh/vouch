//! vouch - Hardware-backed identity for developers
//!
//! One tap. Any credential. Full audit trail.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;
mod config;
mod client;

#[derive(Parser)]
#[command(name = "vouch")]
#[command(author, version, about = "Hardware-backed identity for developers")]
#[command(propagate_version = true)]
struct Cli {
    /// Server URL (default: https://api.vouch.sh)
    #[arg(long, env = "VOUCH_SERVER_URL")]
    server: Option<String>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new authenticator (YubiKey or Touch ID)
    Register {
        /// Name for this authenticator
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Authenticate and start a session
    Login,

    /// Show current session status
    Status,

    /// Log out and clear session
    Logout,

    /// Get credentials for a service
    Get {
        #[command(subcommand)]
        target: GetTarget,
    },

    /// Manage delegations for agents
    Delegate {
        #[command(subcommand)]
        action: DelegateAction,
    },

    /// Manage the local credential agent
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

    /// Configure git credential helper
    GitConfig {
        /// Install globally (default: current repo only)
        #[arg(long)]
        global: bool,
    },

    /// Configure AWS credential process
    AwsConfig {
        /// AWS profile name
        #[arg(long, default_value = "default")]
        profile: String,

        /// IAM role ARN to assume
        #[arg(long)]
        role_arn: String,
    },
}

#[derive(Subcommand)]
enum GetTarget {
    /// Get GitHub installation access token
    Github {
        /// Specific repository (optional)
        #[arg(short, long)]
        repo: Option<String>,
    },

    /// Get AWS STS credentials
    Aws {
        /// IAM role ARN to assume
        #[arg(long)]
        role: String,

        /// Session name (optional)
        #[arg(long)]
        session_name: Option<String>,

        /// Output format
        #[arg(long, default_value = "env")]
        format: AwsOutputFormat,
    },

    /// Get SSH certificate
    Ssh {
        /// Public key file to sign
        #[arg(short, long)]
        key: Option<String>,

        /// Principals to request
        #[arg(short, long)]
        principal: Vec<String>,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum AwsOutputFormat {
    /// Export as environment variables
    Env,
    /// JSON for credential_process
    Json,
    /// INI format for ~/.aws/credentials
    Ini,
}

#[derive(Subcommand)]
enum DelegateAction {
    /// Create a new delegation
    Create {
        /// Name for this delegation
        #[arg(short, long)]
        name: String,

        /// Time to live (e.g., "1h", "30m", "1d")
        #[arg(long, default_value = "1h")]
        ttl: String,

        /// Maximum uses (optional)
        #[arg(long)]
        max_uses: Option<u64>,

        /// Allowed GitHub repos (glob pattern)
        #[arg(long)]
        github_repo: Vec<String>,

        /// Allowed GitHub branches (glob pattern)
        #[arg(long)]
        github_branch: Vec<String>,

        /// Allowed AWS role ARNs
        #[arg(long)]
        aws_role: Vec<String>,
    },

    /// List active delegations
    List,

    /// Revoke a delegation
    Revoke {
        /// Delegation ID to revoke
        id: String,
    },

    /// Show delegation details
    Show {
        /// Delegation ID
        id: String,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// Start the local credential agent
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
    },

    /// Stop the local credential agent
    Stop,

    /// Show agent status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| level.into()),
        )
        .with_target(false)
        .init();

    // Load config
    let config = config::Config::load()?;
    let server_url = cli
        .server
        .or(config.server_url.clone())
        .unwrap_or_else(|| "https://api.vouch.sh".to_string());

    // Create API client
    let client = client::VouchClient::new(&server_url)?;

    // Dispatch command
    match cli.command {
        Commands::Register { name } => {
            commands::register::run(&client, name).await
        }
        Commands::Login => {
            commands::login::run(&client, &config).await
        }
        Commands::Status => {
            commands::status::run(&client, &config).await
        }
        Commands::Logout => {
            commands::logout::run(&config).await
        }
        Commands::Get { target } => match target {
            GetTarget::Github { repo } => {
                commands::get::github(&client, &config, repo).await
            }
            GetTarget::Aws { role, session_name, format } => {
                commands::get::aws(&client, &config, role, session_name, format).await
            }
            GetTarget::Ssh { key, principal } => {
                commands::get::ssh(&client, &config, key, principal).await
            }
        },
        Commands::Delegate { action } => match action {
            DelegateAction::Create {
                name,
                ttl,
                max_uses,
                github_repo,
                github_branch,
                aws_role,
            } => {
                commands::delegate::create(
                    &client, &config, name, ttl, max_uses,
                    github_repo, github_branch, aws_role,
                ).await
            }
            DelegateAction::List => {
                commands::delegate::list(&client, &config).await
            }
            DelegateAction::Revoke { id } => {
                commands::delegate::revoke(&client, &config, id).await
            }
            DelegateAction::Show { id } => {
                commands::delegate::show(&client, &config, id).await
            }
        },
        Commands::Agent { action } => match action {
            AgentAction::Start { foreground } => {
                commands::agent::start(foreground).await
            }
            AgentAction::Stop => {
                commands::agent::stop().await
            }
            AgentAction::Status => {
                commands::agent::status().await
            }
        },
        Commands::GitConfig { global } => {
            commands::config::git_config(global).await
        }
        Commands::AwsConfig { profile, role_arn } => {
            commands::config::aws_config(profile, role_arn).await
        }
    }
}
