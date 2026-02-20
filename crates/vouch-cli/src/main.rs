// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch CLI - Hardware-backed identity for developers.

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

mod client;
mod commands;
mod config;
mod exit_code;
mod fido2;
mod integrations;
mod session;
mod style;
mod utils;

/// Check if invoked as docker-credential-vouch and handle accordingly.
/// Returns `Ok(true)` if this was a Docker credential helper invocation (handled),
/// `Ok(false)` if not, or an error if the Docker credential helper failed.
async fn check_docker_credential_invocation() -> Result<bool> {
    let argv0 = std::env::args().next().unwrap_or_default();

    // Check if invoked as docker-credential-vouch (via symlink or direct call)
    if argv0.ends_with("docker-credential-vouch") || argv0.ends_with("docker-credential-vouch.exe")
    {
        // Docker passes the operation as the first argument
        let operation = std::env::args().nth(1).unwrap_or_default();

        // Run the Docker credential helper
        commands::credential::docker::run(&operation)
            .await
            .map_err(|e| anyhow::anyhow!("docker-credential-vouch: {e}"))?;

        return Ok(true);
    }

    Ok(false)
}

/// Check if invoked as git-remote-codecommit and handle accordingly.
/// Returns `Ok(true)` if this was a git remote helper invocation (handled),
/// `Ok(false)` if not, or an error if the remote helper failed.
///
/// Git invokes remote helpers as: `git-remote-codecommit <remote-name> <url>`
///
/// Detection works via:
/// - **Unix**: argv\[0\] ends with `git-remote-codecommit` (symlink)
/// - **Windows**: `VOUCH_GIT_REMOTE_CODECOMMIT=1` env var (set by batch wrapper)
async fn check_git_remote_codecommit_invocation() -> Result<bool> {
    let argv0 = std::env::args().next().unwrap_or_default();

    let is_remote_helper = argv0.ends_with("git-remote-codecommit")
        || argv0.ends_with("git-remote-codecommit.exe")
        || std::env::var("VOUCH_GIT_REMOTE_CODECOMMIT").is_ok_and(|v| v == "1");

    if is_remote_helper {
        let remote_name = std::env::args().nth(1).unwrap_or_default();
        let url = std::env::args().nth(2).unwrap_or_default();

        if remote_name.is_empty() || url.is_empty() {
            anyhow::bail!(
                "usage: git-remote-codecommit <remote-name> <url>\n\
                 This is a git remote helper. Use it via:\n  \
                 git clone codecommit://[profile@]repo-name\n  \
                 git clone codecommit::region://[profile@]repo-name"
            );
        }

        commands::credential::codecommit::run_remote_helper(&remote_name, &url)
            .await
            .map_err(|e| anyhow::anyhow!("git-remote-codecommit: {e}"))?;

        return Ok(true);
    }

    Ok(false)
}

/// Hardware-backed identity for developers.
#[derive(Parser)]
#[command(
    name = "vouch",
    about = "Hardware-backed identity for developers",
    version,
    after_help = "Exit codes:\n  \
        0  Success\n  \
        1  General error\n  \
        2  Not authenticated (session expired or missing)\n  \
        3  Hardware key not detected\n  \
        4  Network/server unreachable\n  \
        5  Permission denied\n  \
        6  Configuration error"
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

    /// Control color output.
    #[arg(long, global = true, default_value = "auto")]
    color: style::ColorChoice,

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
        /// Timeout in seconds for YubiKey detection (0 for no timeout).
        #[arg(long, default_value = "60")]
        timeout: u64,
    },
    /// Authenticate with your `YubiKey`.
    Login {
        /// Timeout in seconds for YubiKey detection (0 for no timeout).
        #[arg(long, default_value = "60")]
        timeout: u64,
    },
    /// Show current session status.
    Status {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// End your current session.
    Logout,
    /// Output credential environment variables for `eval`.
    ///
    /// Usage: `eval "$(vouch env --type aws --shell bash --role <ARN>)"`
    Env {
        /// Credential type to export.
        #[arg(long = "type")]
        credential_type: commands::exec::CredentialType,
        /// Shell syntax to emit.
        #[arg(long, default_value = "bash")]
        shell: commands::env::Shell,
        /// AWS IAM role ARN (required for --type aws).
        #[arg(long)]
        role: Option<String>,
        /// Session name for AWS assumed role.
        #[arg(long)]
        session_name: Option<String>,
        /// CodeArtifact domain name (required for --type codeartifact unless profile is set).
        #[arg(long)]
        ca_domain: Option<String>,
        /// AWS account ID that owns the CodeArtifact domain (required for --type codeartifact unless profile is set).
        #[arg(long)]
        ca_domain_owner: Option<String>,
        /// AWS region for CodeArtifact (required for --type codeartifact unless profile is set).
        #[arg(long)]
        ca_region: Option<String>,
        /// Named CodeArtifact profile from config (for --type codeartifact).
        #[arg(long)]
        ca_profile: Option<String>,
    },
    /// Output a shell hook for ambient auth status.
    ///
    /// Add `eval "$(vouch init bash)"` to your shell profile.
    Init {
        /// Shell to generate hook for.
        shell: commands::init::Shell,
    },
    /// Manage registered security keys.
    ///
    /// Without a subcommand, opens an interactive menu.
    Keys {
        #[command(subcommand)]
        command: Option<KeysCommands>,
    },
    /// Run a command with Vouch-provided credentials in the environment.
    Exec {
        /// Credential type to inject.
        #[arg(long = "type", value_enum)]
        credential_type: commands::exec::CredentialType,
        /// AWS IAM role ARN (required for --type aws).
        #[arg(long)]
        role: Option<String>,
        /// Session name for the assumed role.
        #[arg(long)]
        session_name: Option<String>,
        /// CodeArtifact domain name (required for --type codeartifact unless profile is set).
        #[arg(long)]
        ca_domain: Option<String>,
        /// AWS account ID that owns the CodeArtifact domain (required for --type codeartifact unless profile is set).
        #[arg(long)]
        ca_domain_owner: Option<String>,
        /// AWS region for CodeArtifact (required for --type codeartifact unless profile is set).
        #[arg(long)]
        ca_region: Option<String>,
        /// Named CodeArtifact profile from config (for --type codeartifact).
        #[arg(long)]
        ca_profile: Option<String>,
        /// Command and arguments to execute.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
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
    Doctor {
        /// Suppress output (exit code only).
        #[arg(short, long)]
        quiet: bool,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run diagnostic test of YubiKey registration + authentication (bypasses server).
    #[command(hide = true)]
    Diag(commands::diag::DiagArgs),
}

impl Commands {
    /// Whether this command contacts the server (and thus needs URL security checks).
    fn uses_server(&self) -> bool {
        !matches!(
            self,
            Commands::Completions(_) | Commands::Diag(_) | Commands::Logout | Commands::Init { .. }
        )
    }
}

#[derive(Subcommand)]
enum KeysCommands {
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
    /// Git credential helper for GitHub.
    ///
    /// This is used by git as a credential helper. Users should not call this directly.
    /// Instead, use `vouch setup github` to configure git.
    #[command(hide = true)]
    Github {
        /// Git credential operation (get, store, erase).
        operation: String,
    },
    /// Docker credential helper for container registries.
    ///
    /// This is used by Docker as a credential helper. Users should not call this directly.
    /// Instead, use `vouch setup docker` to configure Docker.
    #[command(hide = true)]
    Docker {
        /// Docker credential operation (get, store, erase, list).
        operation: String,
    },
    /// Cargo credential provider for private registries.
    ///
    /// This implements Cargo's credential provider protocol.
    /// Users should not call this directly.
    /// Instead, use `vouch setup cargo` to configure Cargo.
    #[command(hide = true)]
    Cargo {
        /// Cargo plugin marker (always passed by Cargo).
        #[arg(long = "cargo-plugin", hide = true)]
        _cargo_plugin: bool,
    },
    /// Git credential helper for AWS CodeCommit.
    ///
    /// This is used by git as a credential helper. Users should not call this directly.
    /// Instead, use `vouch setup codecommit` to configure git.
    #[command(hide = true)]
    Codecommit {
        /// Git credential operation (get, store, erase).
        operation: String,
    },
    /// pip keyring credential helper for CodeArtifact.
    ///
    /// Implements the keyring CLI protocol (`keyring get/set/del`) so pip can
    /// dynamically fetch fresh CodeArtifact tokens. This command is called by
    /// pip when `keyring-provider = subprocess` is configured.
    ///
    /// Users should not call this directly.
    /// Run `vouch setup codeartifact --tool pip` to configure pip.
    #[command(hide = true)]
    Pip {
        /// Keyring operation (get, set, del).
        operation: String,
        /// Service URL passed by pip (the CodeArtifact index URL).
        service_url: Option<String>,
        /// Username passed by pip (typically "aws").
        username: Option<String>,
    },
    /// Obtain a CodeArtifact authorization token.
    Codeartifact {
        /// CodeArtifact domain name (or use --profile / saved default).
        #[arg(long)]
        domain: Option<String>,
        /// AWS account ID that owns the domain.
        #[arg(long)]
        domain_owner: Option<String>,
        /// AWS region.
        #[arg(long)]
        region: Option<String>,
        /// Named CodeArtifact profile from config.
        #[arg(long)]
        profile: Option<String>,
    },
}

#[derive(Subcommand)]
enum SetupCommands {
    /// Configure AWS CLI/SDK to use Vouch credentials.
    Aws {
        /// AWS profile name to configure. Defaults to "vouch" if not specified.
        #[arg(long)]
        profile: Option<String>,
        /// AWS IAM role ARN to assume.
        #[arg(long)]
        role: String,
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
    /// Configure kubectl to use Vouch credentials for Amazon EKS clusters.
    Eks {
        /// EKS cluster name.
        #[arg(long)]
        cluster: String,
        /// AWS region (auto-detected from AWS profile or environment if not specified).
        #[arg(long)]
        region: Option<String>,
        /// AWS profile to use (defaults to auto-detected vouch profile).
        #[arg(long)]
        profile: Option<String>,
        /// Path to kubeconfig file (defaults to ~/.kube/config).
        #[arg(long)]
        kubeconfig: Option<String>,
    },
    /// Configure Docker to use Vouch for container registry authentication.
    Docker {
        /// Container registries to configure (e.g., ghcr.io).
        #[arg(trailing_var_arg = true)]
        registries: Vec<String>,
        /// Automatically configure Docker (otherwise just show instructions).
        #[arg(long)]
        configure: bool,
    },
    /// Configure Cargo to use Vouch for private registry authentication.
    Cargo {
        /// Registry name to configure (if not specified, configures global provider).
        #[arg(long)]
        registry: Option<String>,
        /// Write the configuration (otherwise just show instructions).
        #[arg(long)]
        configure: bool,
    },
    /// Configure Git to use Vouch for AWS CodeCommit credentials.
    Codecommit {
        /// AWS region (default: wildcard matching all regions).
        #[arg(long)]
        region: Option<String>,
        /// AWS profile to use (defaults to auto-detected vouch profile).
        #[arg(long)]
        profile: Option<String>,
        /// Automatically configure git (otherwise just show instructions).
        #[arg(long)]
        configure: bool,
    },
    /// Configure SSH for AWS Systems Manager Session Manager.
    Ssm {
        /// AWS profile to use (defaults to auto-detected vouch profile).
        #[arg(long)]
        profile: Option<String>,
        /// AWS region (auto-detected from AWS profile or environment if not specified).
        #[arg(long)]
        region: Option<String>,
        /// SSH host patterns for SSM proxying (i-* = EC2 instances, mi-* = managed
        /// instances).
        #[arg(long, default_value = crate::commands::setup::ssm::DEFAULT_HOST_PATTERN)]
        hosts: String,
        /// Replace existing Vouch SSM configuration if present.
        #[arg(long)]
        force: bool,
    },
    /// Configure a package manager for AWS CodeArtifact.
    Codeartifact {
        /// Package manager to configure (cargo, pip, npm).
        #[arg(long)]
        tool: crate::commands::setup::codeartifact::Tool,
        /// CodeArtifact domain name (or use --profile / saved default).
        #[arg(long)]
        domain: Option<String>,
        /// AWS account ID that owns the domain.
        #[arg(long)]
        domain_owner: Option<String>,
        /// AWS region.
        #[arg(long)]
        region: Option<String>,
        /// CodeArtifact repository name.
        #[arg(long)]
        repository: String,
        /// Named CodeArtifact profile to use / save.
        #[arg(long)]
        profile: Option<String>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err:#}");
            exit_code::classify(&err)
        }
    }
}

/// Inner entry point that returns `anyhow::Result`.
async fn run() -> Result<()> {
    // Check if invoked as docker-credential-vouch (via symlink)
    if check_docker_credential_invocation().await? {
        return Ok(());
    }

    // Check if invoked as git-remote-codecommit (via symlink)
    if check_git_remote_codecommit_invocation().await? {
        return Ok(());
    }

    let cli = Cli::parse();

    style::init(cli.color);

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
        Commands::Register { name, timeout } => {
            commands::register::run(&server, name.as_deref(), timeout).await
        }
        Commands::Login { timeout } => commands::login::run(&server, timeout).await,
        Commands::Status { json } => commands::status::run(&server, json).await,
        Commands::Logout => commands::logout::run().await,
        Commands::Env {
            credential_type,
            shell,
            role,
            session_name,
            ca_domain,
            ca_domain_owner,
            ca_region,
            ca_profile,
        } => {
            let ca_opts = commands::exec::CodeArtifactOptions {
                domain: ca_domain.as_deref(),
                domain_owner: ca_domain_owner.as_deref(),
                region: ca_region.as_deref(),
                profile: ca_profile.as_deref(),
            };
            commands::env::run(
                &server,
                &credential_type,
                &shell,
                role.as_deref(),
                session_name.as_deref(),
                ca_opts,
            )
            .await
        }
        Commands::Init { shell } => commands::init::run(&shell),
        Commands::Keys { command } => match command {
            None => commands::keys::interactive(&server).await,
            Some(KeysCommands::List { json }) => commands::keys::list(&server, json).await,
            Some(KeysCommands::Remove { id, force }) => {
                commands::keys::remove(&server, &id, force).await
            }
            Some(KeysCommands::Rename { id, name }) => {
                commands::keys::rename(&server, &id, &name).await
            }
        },
        Commands::Exec {
            credential_type,
            role,
            session_name,
            ca_domain,
            ca_domain_owner,
            ca_region,
            ca_profile,
            command,
        } => {
            let ca_opts = commands::exec::CodeArtifactOptions {
                domain: ca_domain.as_deref(),
                domain_owner: ca_domain_owner.as_deref(),
                region: ca_region.as_deref(),
                profile: ca_profile.as_deref(),
            };
            commands::exec::run(
                &server,
                &credential_type,
                role.as_deref(),
                session_name.as_deref(),
                &command,
                ca_opts,
            )
            .await
        }
        Commands::Credential { command } => match command {
            CredentialCommands::Aws { role, session_name } => {
                commands::credential::aws::run(&server, &role, session_name.as_deref()).await
            }
            CredentialCommands::Ssh { key } => {
                commands::credential::ssh::run(&server, key.as_deref()).await
            }
            CredentialCommands::Github { operation } => {
                commands::credential::github::run(&operation).await
            }
            CredentialCommands::Docker { operation } => {
                commands::credential::docker::run(&operation).await
            }
            CredentialCommands::Cargo { .. } => commands::credential::cargo::run().await,
            CredentialCommands::Codecommit { operation } => {
                commands::credential::codecommit::run(&operation).await
            }
            CredentialCommands::Pip {
                operation,
                service_url,
                username,
            } => {
                commands::credential::pip::run(
                    &operation,
                    service_url.as_deref(),
                    username.as_deref(),
                )
                .await
            }
            CredentialCommands::Codeartifact {
                domain,
                domain_owner,
                region,
                profile,
            } => {
                commands::credential::codeartifact::run(
                    &server,
                    domain.as_deref(),
                    domain_owner.as_deref(),
                    region.as_deref(),
                    profile.as_deref(),
                )
                .await
            }
        },
        Commands::Setup { command } => match command {
            SetupCommands::Aws { profile, role } => {
                commands::setup::aws::run(profile.as_deref(), &role).await
            }
            SetupCommands::Ssh { hosts } => {
                commands::setup::ssh::run(&server, hosts.as_deref()).await
            }
            SetupCommands::Github { host, configure } => {
                commands::setup::github::run(&host, configure).await
            }
            SetupCommands::Eks {
                cluster,
                region,
                profile,
                kubeconfig,
            } => {
                commands::setup::eks::run(
                    &cluster,
                    region.as_deref(),
                    profile.as_deref(),
                    kubeconfig.as_deref(),
                )
                .await
            }
            SetupCommands::Ssm {
                profile,
                region,
                hosts,
                force,
            } => {
                commands::setup::ssm::run(profile.as_deref(), region.as_deref(), &hosts, force)
                    .await
            }
            SetupCommands::Docker {
                registries,
                configure,
            } => commands::setup::docker::run(&registries, configure).await,
            SetupCommands::Cargo {
                registry,
                configure,
            } => commands::setup::cargo::run(registry.as_deref(), configure).await,
            SetupCommands::Codecommit {
                region,
                profile,
                configure,
            } => {
                commands::setup::codecommit::run(region.as_deref(), profile.as_deref(), configure)
                    .await
            }
            SetupCommands::Codeartifact {
                tool,
                domain,
                domain_owner,
                region,
                repository,
                profile,
            } => {
                commands::setup::codeartifact::run(
                    &server,
                    tool,
                    domain.as_deref(),
                    domain_owner.as_deref(),
                    region.as_deref(),
                    &repository,
                    profile.as_deref(),
                )
                .await
            }
        },
        Commands::Completions(args) => {
            let mut cmd = Cli::command();
            commands::completions::run(&args, &mut cmd);
            Ok(())
        }
        Commands::Doctor { quiet, json } => commands::doctor::run(&server, quiet, json).await,
        Commands::Diag(args) => commands::diag::run(args),
    }
}
