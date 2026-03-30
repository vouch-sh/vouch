// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch identity server.

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::Result;
use clap::Parser;

// Prevent test-utils from being enabled in release builds. The feature gates
// functions that bypass security invariants (e.g. upsert_user without FIDO2,
// TestCoseVerifier that accepts any signature). If a CI pipeline or Docker build
// accidentally enables --all-features, this halts compilation.
#[cfg(all(feature = "test-utils", not(debug_assertions)))]
compile_error!("test-utils feature must not be enabled in release builds");

use vouch_server::{
    config,
    infra::{generate_client_cert_ca, generate_document_key, router, serve, startup, telemetry},
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
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Start the identity server.
    Serve(config::Args),
    /// Generate a P-384 document encryption key pair via KMS.
    GenerateDocumentKey(generate_document_key::GenerateDocumentKeyArgs),
    /// Generate a Client Certificate CA for mTLS (RFC 8705).
    GenerateClientCertCa(generate_client_cert_ca::GenerateClientCertCaArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the aws-lc-rs crypto provider for rustls before any TLS usage.
    // Required by rustls 0.23+ which no longer auto-selects a provider.
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
        "serve"
        | "generate-document-key"
        | "generate-client-cert-ca"
        | "help"
        | "--help"
        | "-h" => {
            let cli = Cli::parse();
            match cli.command {
                Commands::Serve(args) => run_server(args).await,
                Commands::GenerateDocumentKey(args) => {
                    init_stderr_logging();
                    generate_document_key::run(args).await
                }
                Commands::GenerateClientCertCa(args) => {
                    init_stderr_logging();
                    generate_client_cert_ca::run(args).await
                }
            }
        }
        _ => {
            // Legacy mode: no subcommand, parse as direct server args
            let args = config::Args::parse();
            run_server(args).await
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

    // Initialize all server components (config, database, state, background tasks)
    let components = startup::initialize(args).await?;

    // Build the HTTP router with all routes, middleware, and state
    let app = components.build_app()?;

    // Run the server (TLS or non-TLS) with graceful shutdown
    serve::serve(components, app).await
}
