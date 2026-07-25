// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch identity server.

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::Result;
use clap::Parser;

use vouch_server::{
    config,
    infra::{generate_document_key, i18n, router, serve, startup, telemetry},
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
            let cli = Cli::parse();
            match cli.command {
                Commands::Serve(args) => Box::pin(run_server(args)).await,
                Commands::GenerateDocumentKey(args) => {
                    init_stderr_logging();
                    generate_document_key::run(args).await
                }
            }
        }
        _ => {
            // Legacy mode: no subcommand, parse as direct server args
            let args = config::Args::parse();
            Box::pin(run_server(args)).await
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

async fn run_server(args: config::Args) -> Result<()> {
    // Parse log format early (before full config parsing) so logging is
    // initialized before any other work that might emit log messages.
    let log_format = match args.log_format.trim().to_lowercase().as_str() {
        "json" => config::LogFormat::Json,
        _ => config::LogFormat::Text,
    };
    telemetry::init_tracing(log_format)?;

    router::print_startup_banner();

    // Verify the embedded i18n catalogs loaded — refuses to start if the UI
    // would render with raw Fluent message ids.
    i18n::validate_startup()?;

    // Initialize all server components (config, database, state, background tasks)
    let components = startup::initialize(args).await?;

    // Build the HTTP router with all routes, middleware, and state
    let app = components.build_app()?;

    // Run the server (TLS or non-TLS) with graceful shutdown
    serve::serve(components, app).await
}
