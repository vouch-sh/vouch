// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch identity server.

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::ffi::OsString;

use anyhow::Result;
use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser};

use vouch_server::{
    config,
    infra::{bootstrap, generate_document_key, i18n, router, serve, startup, telemetry},
};

// ============================================================================
// CLI
// ============================================================================

/// Bare invocation runs the server (the mode every launcher uses: systemd
/// units, Docker entrypoint, Helm chart); subcommands are auxiliary utilities.
#[derive(Parser)]
#[command(name = "vouch-server", about = "Vouch identity server")]
struct Cli {
    #[command(flatten)]
    args: config::Args,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Generate a P-384 document encryption key pair via KMS.
    GenerateDocumentKey(generate_document_key::GenerateDocumentKeyArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the aws-lc-rs crypto provider for rustls before any TLS usage;
    // rustls requires an explicitly installed CryptoProvider.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls CryptoProvider"))?;

    // Load .env file if present (before anything else so env vars are available)
    dotenvy::dotenv().ok();

    let matches = Cli::command().get_matches();
    match matches.subcommand() {
        Some(("generate-document-key", sub_matches)) => {
            let args =
                generate_document_key::GenerateDocumentKeyArgs::from_arg_matches(sub_matches)?;
            init_stderr_logging();
            generate_document_key::run(args).await
        }
        Some((other, _)) => Err(anyhow::anyhow!(
            "vouch-server: unknown subcommand '{other}'"
        )),
        None => {
            let (args, instance) = prepare_serve(&matches).await?;
            Box::pin(run_server(args, instance)).await
        }
    }
}

/// Initialize logging to stderr so stdout remains pure JSON for subcommands.
fn init_stderr_logging() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

/// Initialize tracing, print the startup banner, validate i18n catalogs, run
/// EC2 instance bootstrap (IMDS + SSM, see `infra::bootstrap`), and resolve
/// the final server `Args`.
///
/// `matches` is the already-parsed top-level `ArgMatches` (the server args
/// are flattened into `Cli`). When a blob value needs to fill a gap the
/// first parse left as `None`/`DefaultValue`, argv is re-parsed with the
/// overlay tokens appended; both `matches` and the eventual `args` therefore
/// reflect the *same* CLI invocation, just before and after the overlay.
///
/// Tracing is initialized from the first parse's `log_format` (before
/// bootstrap runs) so a bootstrap failure is itself logged; the one accepted
/// gap is an operator setting `VOUCH_LOG_FORMAT` only in the bootstrap
/// parameter, never in real CLI/env — symmetric with the same accepted gap
/// for `RUST_LOG`.
///
/// # Errors
///
/// Returns an error if tracing or i18n fail to initialize, if bootstrap
/// discovery fails (IMDS reachable but SSM failed), or if the overlaid
/// re-parse fails.
async fn prepare_serve(
    matches: &ArgMatches,
) -> Result<(config::Args, Option<bootstrap::Bootstrap>)> {
    let preliminary = config::Args::from_arg_matches(matches)?;

    let log_format = match preliminary.log_format.trim().to_lowercase().as_str() {
        "json" => config::LogFormat::Json,
        _ => config::LogFormat::Text,
    };
    telemetry::init_tracing(log_format)?;
    router::print_startup_banner();
    i18n::validate_startup()?;

    let instance = if preliminary.s3_config_bucket.is_some() {
        tracing::debug!("s3_config_bucket already configured; skipping IMDS/SSM bootstrap");
        None
    } else {
        bootstrap::discover().await.inspect_err(|e| {
            tracing::error!("VOUCH_BOOTSTRAP_FAILED: {e:#}");
        })?
    };
    let Some(instance) = instance else {
        return Ok((preliminary, None));
    };

    let overlay = config::bootstrap_overlay_args(matches, &instance.params);
    if overlay.is_empty() {
        return Ok((preliminary, Some(instance)));
    }

    let mut argv: Vec<OsString> = std::env::args_os().collect();
    argv.extend(overlay);
    let reparsed = Cli::command().try_get_matches_from(argv)?;
    let args = config::Args::from_arg_matches(&reparsed)?;
    Ok((args, Some(instance)))
}

async fn run_server(args: config::Args, instance: Option<bootstrap::Bootstrap>) -> Result<()> {
    // Initialize all server components (config, database, state, background tasks)
    let components = startup::initialize(args, instance.as_ref()).await?;

    // Build the HTTP router with all routes, middleware, and state
    let app = components.build_app()?;

    // Run the server (TLS or non-TLS) with graceful shutdown
    serve::serve(components, app).await
}
