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
// Subcommand Dispatch
// ============================================================================

/// Top-level CLI with subcommands.
#[derive(Parser)]
#[command(name = "vouch-server", about = "Vouch identity server")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "clap::Subcommand variants vary in payload size by command"
)]
enum Commands {
    /// Start the identity server.
    Serve(config::Args),
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

    // Two-pass CLI parse for backwards compatibility:
    // If the first argument is a known subcommand or help flag, parse with Cli struct
    // (so subcommands appear in --help). Otherwise, parse with config::Args directly
    // (legacy: `vouch-server --listen-addr ...`).
    let first_arg = std::env::args().nth(1).unwrap_or_default();
    match first_arg.as_str() {
        "serve" | "generate-document-key" | "help" | "--help" | "-h" => {
            let matches = Cli::command().get_matches();
            match matches.subcommand() {
                Some(("serve", sub_matches)) => {
                    let (args, instance) = prepare_serve(sub_matches, |argv| {
                        let matches = Cli::command().try_get_matches_from(argv)?;
                        let Some(("serve", serve_matches)) = matches.subcommand() else {
                            return Err(clap::Error::raw(
                                clap::error::ErrorKind::MissingSubcommand,
                                "bootstrap overlay re-parse lost the 'serve' subcommand",
                            ));
                        };
                        config::Args::from_arg_matches(serve_matches)
                    })
                    .await?;
                    Box::pin(run_server(args, instance)).await
                }
                Some(("generate-document-key", sub_matches)) => {
                    let args = generate_document_key::GenerateDocumentKeyArgs::from_arg_matches(
                        sub_matches,
                    )?;
                    init_stderr_logging();
                    generate_document_key::run(args).await
                }
                _ => Err(anyhow::anyhow!("vouch-server: no subcommand matched")),
            }
        }
        _ => {
            let matches = config::Args::command().get_matches();
            let (args, instance) = prepare_serve(&matches, |argv| {
                let matches = config::Args::command().try_get_matches_from(argv)?;
                config::Args::from_arg_matches(&matches)
            })
            .await?;
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
/// the final `serve` `Args`.
///
/// `matches` is the already-parsed `ArgMatches` for `Args` — the top-level
/// matches in legacy invocation, or the `serve` subcommand's matches when
/// invoked as `vouch-server serve`. `reparse` performs the mode-specific
/// second parse (from the bootstrap-overlaid argv) when a blob value needs
/// to fill a gap that the first parse left as `None`/`DefaultValue`; both
/// `matches` and the eventual `args` therefore reflect the *same* CLI
/// invocation, just before and after the overlay is applied.
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
    reparse: impl FnOnce(Vec<OsString>) -> clap::error::Result<config::Args>,
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
    let args = reparse(argv)?;
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
