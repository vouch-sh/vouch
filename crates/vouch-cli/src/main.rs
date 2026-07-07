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
// Bring the i18n macros into the binary crate root so submodules under the
// `vouch` binary (e.g. `fido2/unix.rs`, which is compiled into both the lib
// and the bin) can reference them as `crate::tr!` regardless of compilation
// context.
pub(crate) use vouch_cli::{tr, tr_args, tr_eprintln, tr_println};

mod client;
mod commands;
mod config;
mod dns;
mod exit_code;
#[expect(
    unreachable_pub,
    reason = "items pub for lib.rs re-exports used by vouch-tests"
)]
mod fido2;
mod install_path;
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
                .and_then(|i| args.get(i.saturating_add(1)))
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
    about = tr!("cli-about"),
    long_about = tr!("cli-long-about"),
    version,
    after_help = tr!("cli-after-help"),
)]
struct Cli {
    /// Vouch server URL.
    #[arg(long, env = "VOUCH_SERVER", global = true, help = tr!("cli-server-help"))]
    server: Option<String>,

    /// Allow insecure HTTP connections to non-localhost servers.
    #[arg(long, env = "VOUCH_ALLOW_INSECURE", global = true, hide = true)]
    allow_insecure: bool,

    /// Enable verbose output.
    #[arg(short, long, global = true, help = tr!("cli-verbose-help"))]
    verbose: bool,

    /// Override the user-facing language (BCP-47, e.g. en-US, fr-FR).
    #[arg(long, env = "VOUCH_LANG", global = true, help = tr!("cli-lang-help"))]
    lang: Option<String>,

    /// Control color output.
    #[arg(long, global = true, default_value = "auto", help = tr!("cli-color-help"))]
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
    #[command(about = tr!("cmd-enroll-about"))]
    Enroll,
    /// Register an additional `YubiKey` (requires login first).
    #[command(about = tr!("cmd-register-about"))]
    Register {
        /// Human-readable name for this `YubiKey` (e.g., "My `YubiKey` 5").
        /// Defaults to "`YubiKey`" if not specified.
        #[arg(long, help = tr!("arg-register-name-help"))]
        name: Option<String>,
        /// Timeout in seconds for YubiKey detection (0 for no timeout).
        #[arg(long, default_value = "60", help = tr!("arg-register-timeout-help"))]
        timeout: u64,
    },
    /// Authenticate with your `YubiKey`.
    #[command(about = tr!("cmd-login-about"))]
    Login {
        /// Timeout in seconds for YubiKey detection (0 for no timeout).
        #[arg(long, default_value = "60", help = tr!("arg-login-timeout-help"))]
        timeout: u64,
    },
    /// Show current session status.
    #[command(about = tr!("cmd-status-about"))]
    Status {
        /// Output format.
        #[arg(long, value_enum, help = tr!("arg-status-format-help"))]
        format: Option<commands::status::OutputFormat>,
    },
    /// End your current session.
    #[command(about = tr!("cmd-logout-about"))]
    Logout,
    /// Output credential environment variables for `eval`.
    ///
    /// Usage: `eval "$(vouch env --type aws --shell bash --role <ARN>)"`
    #[command(about = tr!("cmd-env-about"), long_about = tr!("cmd-env-long-about"))]
    Env {
        /// Credential type to export.
        #[arg(long = "type", help = tr!("arg-env-type-help"))]
        credential_type: commands::CredentialType,
        /// Shell syntax to emit.
        #[arg(long, default_value = "bash", help = tr!("arg-env-shell-help"))]
        shell: commands::env::Shell,
        /// AWS IAM role ARN (required for --type aws).
        #[arg(long, help = tr!("arg-env-role-help"))]
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
    #[command(about = tr!("cmd-init-about"), long_about = tr!("cmd-init-long-about"))]
    Init {
        /// Shell to generate hook for.
        #[arg(help = tr!("arg-init-shell-help"))]
        shell: commands::init::Shell,
    },
    /// Manage registered security keys.
    ///
    /// Without a subcommand, opens an interactive menu.
    #[command(about = tr!("cmd-keys-about"), long_about = tr!("cmd-keys-long-about"))]
    Keys {
        #[command(subcommand)]
        command: Option<KeysCommands>,
    },
    /// Run a command with Vouch-provided credentials in the environment.
    #[command(about = tr!("cmd-exec-about"))]
    Exec {
        /// Credential type to inject.
        #[arg(long = "type", value_enum, help = tr!("arg-exec-type-help"))]
        credential_type: commands::CredentialType,
        /// AWS IAM role ARN (required for --type aws).
        #[arg(long, help = tr!("arg-exec-role-help"))]
        role: Option<String>,
        #[command(flatten)]
        codeartifact: CodeArtifactArgs,
        #[command(flatten)]
        rds: RdsArgs,
        #[command(flatten)]
        redshift: RedshiftArgs,
        /// Command and arguments to execute.
        #[arg(trailing_var_arg = true, required = true, help = tr!("arg-exec-command-help"))]
        command: Vec<String>,
    },
    /// Obtain credentials for various services.
    #[command(about = tr!("cmd-credential-about"))]
    Credential {
        #[command(subcommand)]
        command: CredentialCommands,
    },
    /// Configure integrations.
    #[command(about = tr!("cmd-setup-about"))]
    Setup {
        #[command(subcommand)]
        command: SetupCommands,
    },
    /// AWS Management Console access.
    #[command(about = tr!("cmd-aws-about"))]
    Aws {
        #[command(subcommand)]
        command: AwsCommands,
    },
    /// Generate shell completions.
    #[command(about = tr!("cmd-completions-about"))]
    Completions(commands::completions::CompletionsArgs),
    /// Check your Vouch environment for common issues.
    #[command(about = tr!("cmd-doctor-about"))]
    Doctor {
        /// Suppress output (exit code only).
        #[arg(short, long, help = tr!("arg-doctor-quiet-help"))]
        quiet: bool,
        /// Output as JSON.
        #[arg(long, help = tr!("arg-doctor-json-help"))]
        json: bool,
    },
    /// Show device posture signals (what the CLI detects about this machine).
    #[command(about = tr!("cmd-posture-about"))]
    Posture {
        /// Output format.
        #[arg(long, value_enum, default_value = "text", help = tr!("arg-posture-format-help"))]
        format: commands::posture::OutputFormat,
    },
    /// Run diagnostic test of YubiKey registration + authentication (bypasses server).
    ///
    /// Not available on Windows: depends on the CTAP2 protocol which Windows
    /// blocks for non-elevated processes.
    #[cfg(not(target_os = "windows"))]
    #[command(
        about = tr!("cmd-diag-about"),
        long_about = tr!("cmd-diag-long-about"),
        hide = true,
    )]
    Diag(commands::diag::DiagArgs),
}

impl Commands {
    /// Whether this command contacts the server (and thus needs URL security checks).
    fn uses_server(&self) -> bool {
        match self {
            Commands::Aws { command } => {
                matches!(command, AwsCommands::Console(_))
            }
            #[cfg(not(target_os = "windows"))]
            Commands::Diag(_) => false,
            // Logout POSTs token + client_assertion to /oauth/revoke — it
            // contacts the server and must receive HTTPS enforcement.
            Commands::Completions(_) | Commands::Init { .. } | Commands::Posture { .. } => false,
            _ => true,
        }
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
            vouch_cli::tr_eprintln!("cli-error-prefix", error = format!("{err:#}"));
            exit_code::classify(&err)
        }
    }
}

/// Process-wide initialization plus helper-binary dispatch.
///
/// Initializes DNS-over-HTTPS and the keyring store, then checks whether
/// the process was invoked via symlink as one of the helper binaries
/// (docker credential helper, git-remote-codecommit, keyring, pnpm token
/// helper). Returns `true` if a helper handled the invocation and the
/// process should exit.
async fn init_and_dispatch_helper_binaries(config: Option<&config::Config>) -> Result<bool> {
    let argv0 = std::env::args().next().unwrap_or_default();

    // Initialize the process-wide DNS-over-HTTPS resolver from config + env
    // before any HTTP client is constructed (including from helper-binary
    // dispatch below). Hard-fails if DoH is configured but unavailable.
    dns::init(config)?;

    // Register the platform-native keyring store. Non-fatal: keychain access
    // already falls back to file storage in fapi::key_store when unavailable.
    if let Err(e) = vouch_cli::fapi::key_store::init_default_store() {
        tracing::debug!("Could not initialize keyring store: {e}");
    }

    if check_docker_credential_invocation(&argv0).await? {
        return Ok(true);
    }
    if check_git_remote_codecommit_invocation(&argv0).await? {
        return Ok(true);
    }
    if check_keyring_invocation(&argv0).await? {
        return Ok(true);
    }
    if check_pnpm_tokenhelper_invocation(&argv0).await? {
        return Ok(true);
    }
    Ok(false)
}

/// Resolve the server URL from `--server`, config, or the default, and
/// validate/normalize it.
///
/// Offline commands (completions, init, logout, diag) skip validation but
/// still normalize for consistency.
fn resolve_server_url(cli: &Cli, config: &config::Config) -> Result<server_url::ServerUrl> {
    let server_raw = cli
        .server
        .clone()
        .or_else(|| config.server_url().map(String::from))
        .unwrap_or_else(|| "https://us.vouch.sh".to_string());

    Ok(server_url::ServerUrl::parse(
        &server_raw,
        cli.allow_insecure || !cli.command.uses_server(),
    )?)
}

/// Inner entry point that returns `anyhow::Result`.
#[expect(
    clippy::too_many_lines,
    reason = "single dispatch match over all CLI subcommands"
)]
async fn run() -> Result<()> {
    // Relocate any legacy ~/.vouch/ files into the XDG base directories before
    // the config is read. Idempotent and a no-op once migrated / for new installs.
    vouch_common::paths::migrate_legacy_layout();

    let config = config::Config::load();

    if init_and_dispatch_helper_binaries(config.as_ref().ok()).await? {
        return Ok(());
    }

    // Install the negotiated locale into the OnceLock before `Cli::parse()`
    // expands the `tr!()` calls embedded in the clap derive attributes. The
    // pre-scan honors `--lang` from argv since clap hasn't parsed it yet.
    let preferred = vouch_cli::i18n::preresolve_lang_from_argv_and_env();
    vouch_cli::i18n::init(preferred)?;

    let cli = Cli::parse();

    style::init(cli.color);

    // Initialize logging: RUST_LOG env wins if set (so trace/per-target filters
    // work for debugging); otherwise --verbose → debug, default warn.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if cli.verbose {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("warn")
        }
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let config = config?;
    let server = resolve_server_url(&cli, &config)?;
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
            CredentialCommands::Aws {
                role,
                account,
                permission_set,
                via,
                idc_application,
            } => {
                commands::credential::aws::run(
                    server,
                    role.as_deref(),
                    account.as_deref(),
                    permission_set.as_deref(),
                    via.as_deref(),
                    idc_application.as_deref(),
                )
                .await
            }
            CredentialCommands::Ssh { key, force } => {
                commands::credential::ssh::run(server, key.as_deref(), force).await
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
            CredentialCommands::Anthropic {} => commands::credential::anthropic::run(server).await,
            CredentialCommands::Openai {} => commands::credential::openai::run(server).await,
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
                management_role,
                identity_center_application,
                region,
                discover,
            } => {
                commands::setup::aws::run(commands::setup::aws::SetupAwsArgs {
                    profile: profile.as_deref(),
                    role_arn: role.as_deref(),
                    management_role: management_role.as_deref(),
                    identity_center_application: identity_center_application.as_deref(),
                    region: region.as_deref(),
                    discover,
                    server,
                })
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
            SetupCommands::Anthropic {
                federation_rule_id,
                organization_id,
                service_account_id,
                workspace_id,
                audience,
                token_endpoint,
            } => {
                commands::setup::anthropic::run(commands::setup::anthropic::SetupArgs {
                    federation_rule_id: &federation_rule_id,
                    organization_id: &organization_id,
                    service_account_id: &service_account_id,
                    workspace_id: &workspace_id,
                    audience: audience.as_deref(),
                    token_endpoint: token_endpoint.as_deref(),
                })
                .await
            }
            SetupCommands::Openai {
                identity_provider_id,
                service_account_id,
                audience,
                token_endpoint,
                force,
            } => {
                commands::setup::openai::run(commands::setup::openai::SetupArgs {
                    identity_provider_id: &identity_provider_id,
                    service_account_id: &service_account_id,
                    audience: audience.as_deref(),
                    token_endpoint: token_endpoint.as_deref(),
                    force,
                })
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
            AwsCommands::Console(args) => commands::aws::console::run(server, args).await,
        },
        Commands::Completions(args) => {
            let mut cmd = Cli::command();
            commands::completions::run(&args, &mut cmd);
            Ok(())
        }
        Commands::Doctor { quiet, json } => commands::doctor::run(server, quiet, json).await,
        Commands::Posture { format } => commands::posture::run(format),
        #[cfg(not(target_os = "windows"))]
        Commands::Diag(args) => commands::diag::run(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- uses_server --

    /// Regression for #548: logout contacts /oauth/revoke and must be subject
    /// to HTTPS enforcement (`uses_server` must return `true`).
    #[test]
    fn test_logout_uses_server() {
        assert!(
            Commands::Logout.uses_server(),
            "Logout posts to /oauth/revoke; uses_server() must be true"
        );
    }

    /// Completions is a purely local operation and must not require a server URL.
    #[test]
    fn test_completions_does_not_use_server() {
        let args = commands::completions::CompletionsArgs {
            shell: clap_complete::Shell::Bash,
        };
        assert!(
            !Commands::Completions(args).uses_server(),
            "Completions is local; uses_server() must be false"
        );
    }

    // -- posture does not use server --

    #[test]
    fn test_posture_does_not_use_server() {
        assert!(
            !Commands::Posture {
                format: commands::posture::OutputFormat::Text
            }
            .uses_server(),
            "Posture is local; uses_server() must be false"
        );
    }

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
