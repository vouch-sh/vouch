// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch CLI - Hardware-backed identity for developers.

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

mod client;
mod commands;
mod config;
mod exit_code;
#[allow(unreachable_pub)] // Items are pub for lib.rs re-exports used by vouch-tests
mod fido2;
mod integrations;
mod server_url;
mod session;
mod style;
mod utils;

/// Test if argv0 indicates invocation as `docker-credential-vouch`.
fn is_docker_credential_argv0(argv0: &str) -> bool {
    argv0.ends_with("docker-credential-vouch") || argv0.ends_with("docker-credential-vouch.exe")
}

/// Test if argv0 indicates invocation as `git-remote-codecommit`.
fn is_git_remote_codecommit_argv0(argv0: &str) -> bool {
    argv0.ends_with("git-remote-codecommit") || argv0.ends_with("git-remote-codecommit.exe")
}

/// Test if argv0 indicates invocation as `keyring`.
fn is_keyring_argv0(argv0: &str) -> bool {
    argv0.ends_with("/keyring")
        || argv0.ends_with("\\keyring")
        || argv0 == "keyring"
        || argv0.ends_with("/keyring.exe")
        || argv0.ends_with("\\keyring.exe")
}

/// Test if argv0 indicates invocation as `vouch-pnpm-tokenhelper`.
fn is_pnpm_tokenhelper_argv0(argv0: &str) -> bool {
    argv0.ends_with("vouch-pnpm-tokenhelper") || argv0.ends_with("vouch-pnpm-tokenhelper.exe")
}

/// Check if invoked as docker-credential-vouch and handle accordingly.
/// Returns `Ok(true)` if this was a Docker credential helper invocation (handled),
/// `Ok(false)` if not, or an error if the Docker credential helper failed.
async fn check_docker_credential_invocation(argv0: &str) -> Result<bool> {
    if is_docker_credential_argv0(argv0) {
        let operation = std::env::args().nth(1).unwrap_or_default();

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
async fn check_git_remote_codecommit_invocation(argv0: &str) -> Result<bool> {
    let is_remote_helper = is_git_remote_codecommit_argv0(argv0)
        || std::env::var("VOUCH_GIT_REMOTE_CODECOMMIT").is_ok_and(|v| v == "1");

    if is_remote_helper {
        let remote_name = std::env::args().nth(1).unwrap_or_default();
        let url = std::env::args().nth(2).unwrap_or_default();

        if remote_name.is_empty() || url.is_empty() {
            return Err(crate::exit_code::CliError::ConfigError(
                "usage: git-remote-codecommit <remote-name> <url>\n\
                 This is a git remote helper. Use it via:\n  \
                 git clone codecommit://[profile@]repo-name\n  \
                 git clone codecommit::region://[profile@]repo-name"
                    .to_string(),
            )
            .into());
        }

        commands::credential::codecommit::run_remote_helper(&remote_name, &url)
            .await
            .map_err(|e| anyhow::anyhow!("git-remote-codecommit: {e}"))?;

        return Ok(true);
    }

    Ok(false)
}

/// Check if invoked as `keyring` (pip/uv keyring subprocess protocol).
///
/// pip/uv call `keyring get <url> <username>` when `keyring-provider = subprocess`
/// is configured. When invoked via symlink, argv[0] ends with "keyring".
async fn check_keyring_invocation(argv0: &str) -> Result<bool> {
    if is_keyring_argv0(argv0) {
        let operation = std::env::args().nth(1).unwrap_or_default();
        let service_url = std::env::args().nth(2);
        let username = std::env::args().nth(3);

        commands::credential::pip::run(&operation, service_url.as_deref(), username.as_deref())
            .await
            .map_err(|e| anyhow::anyhow!("keyring: {e}"))?;

        return Ok(true);
    }

    Ok(false)
}

/// Check if invoked as `vouch-pnpm-tokenhelper` (pnpm tokenHelper protocol).
///
/// pnpm calls the tokenHelper executable with no arguments. It should print
/// a CodeArtifact bearer token to stdout.
async fn check_pnpm_tokenhelper_invocation(argv0: &str) -> Result<bool> {
    if is_pnpm_tokenhelper_argv0(argv0) {
        // Parse optional flags for `vouch credential codeartifact`
        let args: Vec<String> = std::env::args().skip(1).collect();
        let flag = |name: &str| {
            args.iter()
                .position(|a| a == name)
                .and_then(|i| args.get(i + 1))
        };
        let domain = flag("--domain");
        let domain_owner = flag("--domain-owner");
        let region = flag("--region");
        let profile = flag("--profile");

        // Resolve session to get server URL
        let session = crate::session::resolve_session()
            .await
            .map_err(|e| anyhow::anyhow!("vouch-pnpm-tokenhelper: {e}"))?;

        commands::credential::codeartifact::run(
            &session.server_url,
            domain.map(String::as_str),
            domain_owner.map(String::as_str),
            region.map(String::as_str),
            profile.map(String::as_str),
        )
        .await
        .map_err(|e| anyhow::anyhow!("vouch-pnpm-tokenhelper: {e}"))?;

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

/// Shared CodeArtifact CLI arguments for exec/env commands.
#[derive(clap::Args)]
struct CodeArtifactArgs {
    /// CodeArtifact domain name (required for --type codeartifact unless profile is set).
    #[arg(long)]
    codeartifact_domain: Option<String>,
    /// AWS account ID that owns the CodeArtifact domain (required for --type codeartifact unless profile is set).
    #[arg(long)]
    codeartifact_domain_owner: Option<String>,
    /// AWS region for CodeArtifact (required for --type codeartifact unless profile is set).
    #[arg(long)]
    codeartifact_region: Option<String>,
    /// Named CodeArtifact profile from config (for --type codeartifact).
    #[arg(long)]
    codeartifact_profile: Option<String>,
}

impl CodeArtifactArgs {
    fn to_options(&self) -> commands::exec::CodeArtifactOptions<'_> {
        commands::exec::CodeArtifactOptions {
            domain: self.codeartifact_domain.as_deref(),
            domain_owner: self.codeartifact_domain_owner.as_deref(),
            region: self.codeartifact_region.as_deref(),
            profile: self.codeartifact_profile.as_deref(),
        }
    }
}

/// Shared RDS CLI arguments for exec/env commands.
#[derive(clap::Args)]
struct RdsArgs {
    /// RDS instance hostname (required for --type rds).
    #[arg(long)]
    rds_hostname: Option<String>,
    /// Database port (default: 5432, for --type rds).
    #[arg(long, default_value = "5432")]
    rds_port: u16,
    /// Database username (required for --type rds).
    #[arg(long)]
    rds_username: Option<String>,
    /// AWS region (auto-detected from AWS profile or env if not specified, for --type rds).
    #[arg(long)]
    rds_region: Option<String>,
}

impl RdsArgs {
    fn to_options(&self) -> commands::exec::RdsOptions<'_> {
        commands::exec::RdsOptions {
            hostname: self.rds_hostname.as_deref(),
            port: self.rds_port,
            username: self.rds_username.as_deref(),
            region: self.rds_region.as_deref(),
        }
    }
}

/// Shared Redshift CLI arguments for exec/env commands.
#[derive(clap::Args)]
struct RedshiftArgs {
    /// Redshift provisioned cluster ID (for --type redshift).
    #[arg(long, conflicts_with = "redshift_workgroup")]
    redshift_cluster_id: Option<String>,
    /// Redshift Serverless workgroup name (for --type redshift).
    #[arg(long, conflicts_with = "redshift_cluster_id")]
    redshift_workgroup: Option<String>,
    /// Redshift database name (for --type redshift).
    #[arg(long)]
    redshift_db_name: Option<String>,
    /// Credential duration in seconds, 900-3600 (for --type redshift provisioned).
    #[arg(long, value_parser = clap::value_parser!(u32).range(900..=3600))]
    redshift_duration: Option<u32>,
    /// AWS region (auto-detected from AWS profile or env if not specified, for --type redshift).
    #[arg(long)]
    redshift_region: Option<String>,
}

impl RedshiftArgs {
    fn to_options(&self) -> commands::exec::RedshiftOptions<'_> {
        commands::exec::RedshiftOptions {
            cluster_id: self.redshift_cluster_id.as_deref(),
            workgroup: self.redshift_workgroup.as_deref(),
            db_name: self.redshift_db_name.as_deref(),
            duration: self.redshift_duration,
            region: self.redshift_region.as_deref(),
        }
    }
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
        /// Output format.
        #[arg(long, value_enum)]
        format: Option<commands::status::OutputFormat>,
    },
    /// End your current session.
    Logout,
    /// Output credential environment variables for `eval`.
    ///
    /// Usage: `eval "$(vouch env --type aws --shell bash --role <ARN>)"`
    Env {
        /// Credential type to export.
        #[arg(long = "type")]
        credential_type: commands::CredentialType,
        /// Shell syntax to emit.
        #[arg(long, default_value = "bash")]
        shell: commands::env::Shell,
        /// AWS IAM role ARN (required for --type aws).
        #[arg(long)]
        role: Option<String>,
        #[command(flatten)]
        codeartifact: CodeArtifactArgs,
        #[command(flatten)]
        rds: RdsArgs,
        #[command(flatten)]
        redshift: RedshiftArgs,
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
        credential_type: commands::CredentialType,
        /// AWS IAM role ARN (required for --type aws).
        #[arg(long)]
        role: Option<String>,
        #[command(flatten)]
        codeartifact: CodeArtifactArgs,
        #[command(flatten)]
        rds: RdsArgs,
        #[command(flatten)]
        redshift: RedshiftArgs,
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
    /// AWS Identity Center commands for multi-account management.
    Aws {
        #[command(subcommand)]
        command: AwsCommands,
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
    /// Show device posture signals (what the CLI detects about this machine).
    Posture {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: commands::posture::OutputFormat,
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
            Commands::Aws { .. }
                | Commands::Completions(_)
                | Commands::Diag(_)
                | Commands::Logout
                | Commands::Init { .. }
                | Commands::Posture { .. }
        )
    }
}

use commands::aws::AwsCommands;
use commands::credential::CredentialCommands;
use commands::keys::KeysCommands;
use commands::setup::SetupCommands;

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
    let argv0 = std::env::args().next().unwrap_or_default();

    // Check if invoked via symlink as a helper binary
    if check_docker_credential_invocation(&argv0).await? {
        return Ok(());
    }
    if check_git_remote_codecommit_invocation(&argv0).await? {
        return Ok(());
    }
    if check_keyring_invocation(&argv0).await? {
        return Ok(());
    }
    if check_pnpm_tokenhelper_invocation(&argv0).await? {
        return Ok(());
    }

    let cli = Cli::parse();

    style::init(cli.color);

    // Initialize logging: --verbose → debug, else RUST_LOG env → default warn
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"))
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Load config and resolve server URL
    let config = config::Config::load()?;
    let server_raw = cli
        .server
        .or_else(|| config.server_url().map(String::from))
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    // Validate and normalize URL for commands that contact the server.
    // Offline commands (completions, init, logout, diag) skip validation
    // but still normalize for consistency.
    let server = server_url::ServerUrl::parse(
        &server_raw,
        cli.allow_insecure || !cli.command.uses_server(),
    )?;
    let server = server.as_str();

    match cli.command {
        Commands::Enroll => commands::enroll::run(server).await,
        Commands::Register { name, timeout } => {
            commands::register::run(server, name.as_deref(), timeout).await
        }
        Commands::Login { timeout } => commands::login::run(server, timeout).await,
        Commands::Status { format } => {
            commands::status::run(server, format.unwrap_or_default()).await
        }
        Commands::Logout => commands::logout::run(server).await,
        Commands::Env {
            credential_type,
            shell,
            role,
            codeartifact,
            rds,
            redshift,
        } => {
            commands::env::run(
                server,
                &credential_type,
                &shell,
                role.as_deref(),
                codeartifact.to_options(),
                rds.to_options(),
                redshift.to_options(),
            )
            .await
        }
        Commands::Init { shell } => commands::init::run(&shell),
        Commands::Keys { command } => match command {
            None => commands::keys::interactive(server).await,
            Some(KeysCommands::List { json }) => commands::keys::list(server, json).await,
            Some(KeysCommands::Remove { id, force }) => {
                commands::keys::remove(server, &id, force).await
            }
            Some(KeysCommands::Rename { id, name }) => {
                commands::keys::rename(server, &id, &name).await
            }
        },
        Commands::Exec {
            credential_type,
            role,
            codeartifact,
            rds,
            redshift,
            command,
        } => {
            commands::exec::run(
                server,
                &credential_type,
                role.as_deref(),
                &command,
                codeartifact.to_options(),
                rds.to_options(),
                redshift.to_options(),
            )
            .await
        }
        Commands::Credential { command } => match command {
            CredentialCommands::Aws { role } => commands::credential::aws::run(server, &role).await,
            CredentialCommands::Ssh { key } => {
                commands::credential::ssh::run(server, key.as_deref()).await
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
            CredentialCommands::Eks {
                cluster_name,
                region,
                role,
            } => {
                commands::credential::eks::run(
                    server,
                    &cluster_name,
                    region.as_deref(),
                    role.as_deref(),
                )
                .await
            }
            CredentialCommands::K8s { cluster, audience } => {
                commands::credential::kubernetes::run(server, &cluster, audience.as_deref()).await
            }
            CredentialCommands::Rds {
                hostname,
                port,
                username,
                region,
                role,
            } => {
                commands::credential::rds::run(
                    server,
                    &hostname,
                    port,
                    &username,
                    region.as_deref(),
                    role.as_deref(),
                )
                .await
            }
            CredentialCommands::Redshift {
                cluster_id,
                workgroup,
                db_name,
                region,
                role,
                duration,
            } => {
                let target = commands::credential::redshift::resolve_target(
                    cluster_id.as_deref(),
                    workgroup.as_deref(),
                    duration,
                )?;
                commands::credential::redshift::run(
                    server,
                    target,
                    db_name.as_deref(),
                    region.as_deref(),
                    role.as_deref(),
                )
                .await
            }
            CredentialCommands::Token {} => commands::credential::token::run().await,
            CredentialCommands::Codeartifact {
                domain,
                domain_owner,
                region,
                profile,
            } => {
                commands::credential::codeartifact::run(
                    server,
                    domain.as_deref(),
                    domain_owner.as_deref(),
                    region.as_deref(),
                    profile.as_deref(),
                )
                .await
            }
        },
        Commands::Setup { command } => match command {
            SetupCommands::Aws {
                profile,
                role,
                region,
                discover,
            } => {
                commands::setup::aws::run(
                    profile.as_deref(),
                    role.as_deref(),
                    region.as_deref(),
                    discover,
                )
                .await
            }
            SetupCommands::Ssh { hosts } => {
                commands::setup::ssh::run(server, hosts.as_deref()).await
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
                    server,
                    &cluster,
                    region.as_deref(),
                    profile.as_deref(),
                    kubeconfig.as_deref(),
                )
                .await
            }
            SetupCommands::K8s {
                cluster,
                server: k8s_server,
                certificate_authority,
                audience,
                kubeconfig,
            } => {
                commands::setup::kubernetes::run(
                    server,
                    &cluster,
                    &k8s_server,
                    certificate_authority.as_deref(),
                    audience.as_deref(),
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
                    server,
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
        Commands::Aws { command } => match command {
            AwsCommands::Login(args) => commands::aws::login::run(args).await,
            AwsCommands::Accounts(args) => commands::aws::accounts::run(args).await,
            AwsCommands::Roles(args) => commands::aws::roles::run(args).await,
        },
        Commands::Completions(args) => {
            let mut cmd = Cli::command();
            commands::completions::run(&args, &mut cmd);
            Ok(())
        }
        Commands::Doctor { quiet, json } => commands::doctor::run(server, quiet, json).await,
        Commands::Posture { format } => commands::posture::run(format),
        Commands::Diag(args) => commands::diag::run(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- docker-credential-vouch --

    #[test]
    fn test_docker_credential_argv0_unix_path() {
        assert!(is_docker_credential_argv0(
            "/home/user/.local/bin/docker-credential-vouch"
        ));
    }

    #[test]
    fn test_docker_credential_argv0_bare_name() {
        assert!(is_docker_credential_argv0("docker-credential-vouch"));
    }

    #[test]
    fn test_docker_credential_argv0_windows_exe() {
        assert!(is_docker_credential_argv0("docker-credential-vouch.exe"));
    }

    #[test]
    fn test_docker_credential_argv0_no_match() {
        assert!(!is_docker_credential_argv0("vouch"));
        assert!(!is_docker_credential_argv0("docker-credential-ecr"));
        assert!(!is_docker_credential_argv0(""));
    }

    // -- git-remote-codecommit --

    #[test]
    fn test_git_remote_codecommit_argv0_unix_path() {
        assert!(is_git_remote_codecommit_argv0(
            "/home/user/.local/bin/git-remote-codecommit"
        ));
    }

    #[test]
    fn test_git_remote_codecommit_argv0_bare_name() {
        assert!(is_git_remote_codecommit_argv0("git-remote-codecommit"));
    }

    #[test]
    fn test_git_remote_codecommit_argv0_no_match() {
        assert!(!is_git_remote_codecommit_argv0("vouch"));
        assert!(!is_git_remote_codecommit_argv0("codecommit"));
        assert!(!is_git_remote_codecommit_argv0(""));
    }

    // -- keyring --

    #[test]
    fn test_keyring_argv0_bare_name() {
        assert!(is_keyring_argv0("keyring"));
    }

    #[test]
    fn test_keyring_argv0_unix_full_path() {
        assert!(is_keyring_argv0("/home/user/.local/bin/keyring"));
    }

    #[test]
    fn test_keyring_argv0_windows_backslash() {
        assert!(is_keyring_argv0(r"C:\Users\user\.local\bin\keyring"));
    }

    #[test]
    fn test_keyring_argv0_exe_suffix() {
        assert!(is_keyring_argv0("/usr/local/bin/keyring.exe"));
        assert!(is_keyring_argv0(r"C:\bin\keyring.exe"));
    }

    #[test]
    fn test_keyring_argv0_no_match_vouch() {
        assert!(!is_keyring_argv0("vouch"));
    }

    #[test]
    fn test_keyring_argv0_no_match_substring() {
        assert!(!is_keyring_argv0("keyring-extra"));
        assert!(!is_keyring_argv0("/bin/keyring-extra"));
        assert!(!is_keyring_argv0("python-keyring"));
    }

    #[test]
    fn test_keyring_argv0_no_match_empty() {
        assert!(!is_keyring_argv0(""));
    }

    // -- vouch-pnpm-tokenhelper --

    #[test]
    fn test_pnpm_tokenhelper_argv0_unix_full_path() {
        assert!(is_pnpm_tokenhelper_argv0(
            "/home/user/.local/bin/vouch-pnpm-tokenhelper"
        ));
    }

    #[test]
    fn test_pnpm_tokenhelper_argv0_bare_name() {
        assert!(is_pnpm_tokenhelper_argv0("vouch-pnpm-tokenhelper"));
    }

    #[test]
    fn test_pnpm_tokenhelper_argv0_exe_suffix() {
        assert!(is_pnpm_tokenhelper_argv0("vouch-pnpm-tokenhelper.exe"));
    }

    #[test]
    fn test_pnpm_tokenhelper_argv0_no_match_partial() {
        assert!(!is_pnpm_tokenhelper_argv0("pnpm-tokenhelper"));
        assert!(!is_pnpm_tokenhelper_argv0("tokenhelper"));
        assert!(!is_pnpm_tokenhelper_argv0("vouch"));
        assert!(!is_pnpm_tokenhelper_argv0(""));
    }
}
