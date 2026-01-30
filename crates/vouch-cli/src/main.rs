// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch CLI - Hardware-backed identity for developers.

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod client;
mod commands;
mod config;
mod fido2;
mod utils;

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

    /// Allow insecure HTTP connections to non-localhost servers.
    #[arg(long, env = "VOUCH_ALLOW_INSECURE", global = true, hide = true)]
    allow_insecure: bool,

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
    /// Register an additional `YubiKey` (requires login first).
    Register {
        /// Human-readable name for this `YubiKey` (e.g., "My `YubiKey` 5").
        /// Defaults to "`YubiKey`" if not specified.
        #[arg(long)]
        name: Option<String>,
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
    /// Run diagnostic test of YubiKey registration + authentication (bypasses server).
    #[command(hide = true)]
    Diag(commands::diag::DiagArgs),
}

impl Commands {
    /// Whether this command contacts the server (and thus needs URL security checks).
    fn uses_server(&self) -> bool {
        !matches!(
            self,
            Commands::Completions(_) | Commands::Diag(_) | Commands::Logout
        )
    }
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
    /// Obtain a GCP identity token (executable-sourced credential format).
    ///
    /// This is used by GCP libraries as an executable credential source.
    /// Users should not call this directly.
    /// Instead, use `vouch setup gcp` to configure GCP.
    #[command(hide = true)]
    Gcp {
        /// Workload Identity Pool provider audience URL.
        #[arg(long)]
        audience: String,
    },
    /// Obtain a Kubernetes identity token (ExecCredential format).
    ///
    /// This is used by kubectl as an exec credential plugin.
    /// Users should not call this directly.
    /// Instead, use `vouch setup k8s` to configure kubectl.
    #[command(hide = true)]
    K8s {
        /// Kubernetes cluster audience (matches --oidc-client-id on API server).
        #[arg(long)]
        audience: String,
    },
    /// Obtain an SSH certificate.
    Ssh {
        /// Path to SSH private key (default: ~/.ssh/id_ed25519_vouch).
        #[arg(long)]
        key: Option<String>,
    },
    /// Git credential helper for GitHub.
    ///
    /// This is used by git as a credential helper. Users should not call this directly.
    /// Instead, use `vouch setup github` to configure git.
    #[command(hide = true)]
    Github {
        /// Git credential operation (get, store, erase).
        operation: String,
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
    /// Configure GCP to use Vouch credentials via Workload Identity Federation.
    ///
    /// If no options are provided, configuration is fetched from the server.
    /// This requires your organization admin to have configured GCP integration.
    Gcp {
        /// Profile name for the credential file (e.g., "prod", "staging").
        /// Creates vouch-credentials-{profile}.json instead of vouch-credentials.json.
        #[arg(long)]
        profile: Option<String>,
        /// GCP project number (numeric, not project ID).
        /// If not provided, uses server configuration.
        #[arg(long)]
        project_number: Option<String>,
        /// Workload Identity Pool ID.
        /// If not provided, uses server configuration.
        #[arg(long)]
        pool_id: Option<String>,
        /// Provider ID within the Workload Identity Pool.
        /// If not provided, uses server configuration.
        #[arg(long)]
        provider_id: Option<String>,
        /// Service account email to impersonate (optional).
        /// Overrides server configuration if provided.
        #[arg(long)]
        service_account: Option<String>,
        /// Output path for credential configuration file.
        #[arg(long)]
        output: Option<String>,
        /// Write the configuration file (otherwise just show instructions).
        #[arg(long)]
        configure: bool,
    },
    /// Configure SSH to use Vouch certificates.
    Ssh {
        /// Host patterns to trust with this CA (e.g., "*.example.com").
        /// If specified, adds entry to ~/.ssh/known_hosts.
        #[arg(long)]
        hosts: Option<String>,
    },
    /// Configure Git to use Vouch for GitHub credentials.
    Github {
        /// GitHub host to configure (default: github.com).
        #[arg(long, default_value = "github.com")]
        host: String,
        /// Automatically configure git (otherwise just show instructions).
        #[arg(long)]
        configure: bool,
    },
    /// Configure kubectl to use Vouch for Kubernetes OIDC authentication.
    K8s {
        /// Cluster name from kubeconfig (prompts if not provided).
        #[arg(long)]
        cluster: Option<String>,
        /// Audience/client-id for OIDC (defaults to cluster name).
        #[arg(long)]
        audience: Option<String>,
        /// Path to kubeconfig file (defaults to ~/.kube/config).
        #[arg(long)]
        kubeconfig: Option<String>,
        /// Write the configuration (otherwise just show instructions).
        #[arg(long)]
        configure: bool,
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

    // Enforce HTTPS for non-localhost servers
    if cli.command.uses_server() {
        match vouch_common::check_url_security(&server) {
            vouch_common::UrlSecurity::Secure => {}
            vouch_common::UrlSecurity::InsecureHttp { url } => {
                if cli.allow_insecure {
                    eprintln!(
                        "WARNING: Using insecure HTTP connection to {url}.\n\
                         Credentials will be transmitted in plaintext.\n"
                    );
                } else {
                    anyhow::bail!(
                        "Server URL uses plain HTTP ({url}).\n\
                         Credentials would be sent in plaintext.\n\n\
                         Use an https:// URL, or set --allow-insecure / VOUCH_ALLOW_INSECURE=1 for development."
                    );
                }
            }
        }
    }

    match cli.command {
        Commands::Enroll => commands::enroll::run(&server).await,
        Commands::Register { name } => commands::register::run(&server, name.as_deref()).await,
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
            CredentialCommands::Gcp { audience } => {
                commands::credential::gcp::run(&server, &audience).await
            }
            CredentialCommands::K8s { audience } => {
                commands::credential::k8s::run(&server, &audience).await
            }
            CredentialCommands::Ssh { key } => {
                commands::credential::ssh::run(&server, key.as_deref()).await
            }
            CredentialCommands::Github { operation } => {
                commands::credential::github::run(&operation).await
            }
        },
        Commands::Setup { command } => match command {
            SetupCommands::Aws {
                profile,
                role,
                add_profile,
            } => commands::setup::aws::run(&profile, &role, add_profile).await,
            SetupCommands::Gcp {
                profile,
                project_number,
                pool_id,
                provider_id,
                service_account,
                output,
                configure,
            } => {
                commands::setup::gcp::run(
                    &server,
                    profile.as_deref(),
                    project_number.as_deref(),
                    pool_id.as_deref(),
                    provider_id.as_deref(),
                    service_account.as_deref(),
                    output.as_deref(),
                    configure,
                )
                .await
            }
            SetupCommands::Ssh { hosts } => {
                commands::setup::ssh::run(&server, hosts.as_deref()).await
            }
            SetupCommands::Github { host, configure } => {
                commands::setup::github::run(&host, configure).await
            }
            SetupCommands::K8s {
                cluster,
                audience,
                kubeconfig,
                configure,
            } => {
                commands::setup::k8s::run(
                    &server,
                    cluster.as_deref(),
                    audience.as_deref(),
                    kubeconfig.as_deref(),
                    configure,
                )
                .await
            }
        },
        Commands::Completions(args) => {
            let mut cmd = Cli::command();
            commands::completions::run(&args, &mut cmd);
            Ok(())
        }
        Commands::Doctor => commands::doctor::run(&server).await,
        Commands::Diag(args) => commands::diag::run(args),
    }
}
