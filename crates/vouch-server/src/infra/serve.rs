// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server lifecycle management.
//!
//! Handles TLS vs non-TLS server binding, HTTP->HTTPS redirect, SIGHUP
//! certificate hot reload, S3 config polling, and graceful shutdown.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::serve::ListenerExt;
use axum_server::accept::NoDelayAcceptor;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::AppState;
use crate::config::ServerConfig;
use crate::infra::s3_config;

use super::startup::ServerComponents;

/// Optional S3 config source (client, source settings, initial ETag).
type S3ConfigParts = (
    Option<aws_sdk_s3::Client>,
    Option<s3_config::S3ConfigSource>,
    Option<String>,
);

/// Run the server with the given components and router.
///
/// Handles both TLS and non-TLS modes, including:
/// - TLS: HTTPS on port 443, HTTP redirect on port 80, SIGHUP cert reload
/// - Non-TLS: HTTP on the configured listen address
/// - S3 config polling (if configured)
/// - Graceful shutdown on Ctrl+C or SIGTERM
/// - Background task cleanup on shutdown
///
/// # Errors
///
/// Returns an error if the server fails to bind or encounters a fatal error.
pub async fn serve(components: ServerComponents, app: Router) -> Result<()> {
    let ServerComponents {
        config,
        db,
        state,
        s3_client,
        s3_source,
        initial_etag,
        cleanup_handle,
    } = components;

    let s3_parts = (s3_client, s3_source, initial_etag);

    // Run until shutdown; each mode returns its S3 polling handle (if any)
    // so cleanup stays shared below.
    let s3_poll_handle = if config.tls_configured() {
        serve_tls(&config, &state, app, s3_parts).await?
    } else {
        serve_plain(&config, &state, app, s3_parts).await?
    };

    // Clean up background tasks
    if let Some(handle) = s3_poll_handle {
        tracing::info!("Shutting down S3 config polling task");
        handle.abort();
    }
    if let Some(handle) = cleanup_handle {
        tracing::info!("Shutting down cleanup task");
        handle.abort();
    }

    // Close database pool (signals DSQL token refresh task to stop)
    tracing::info!("Closing database pool");
    db.close().await;

    // Flush pending OpenTelemetry spans before exit
    super::telemetry::shutdown_tracing();

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Start the S3 config polling task if all S3 config parts are present.
///
/// `tls_config` enables hot reload of certificates delivered via S3.
fn start_s3_polling(
    state: &Arc<AppState>,
    s3_parts: S3ConfigParts,
    tls_config: Option<axum_server::tls_rustls::RustlsConfig>,
) -> Option<JoinHandle<()>> {
    let (Some(client), Some(source), Some(etag)) = s3_parts else {
        return None;
    };
    tracing::info!(
        "Starting S3 config polling task (interval: {}s)",
        source.poll_interval_seconds
    );
    Some(s3_config::start_s3_config_task(
        client,
        source,
        state.config.clone(),
        tls_config,
        etag,
    ))
}

/// Run in TLS mode: HTTPS on 443, HTTP redirect on 80, mTLS listener,
/// SIGHUP certificate hot reload. Blocks until shutdown.
///
/// Returns the S3 config polling task handle (if S3 config is in use) so the
/// caller can abort it during cleanup.
async fn serve_tls(
    config: &ServerConfig,
    state: &Arc<AppState>,
    app: Router,
    s3_parts: S3ConfigParts,
) -> Result<Option<JoinHandle<()>>> {
    let tls_config = crate::infra::tls::build_tls_config(config)?;

    // TLS mode: always listen on 443 (HTTPS) and 80 (HTTP redirect)
    let https_addr: std::net::SocketAddr =
        "[::]:443".parse().context("Invalid HTTPS listen address")?;
    let http_addr: std::net::SocketAddr =
        "[::]:80".parse().context("Invalid HTTP listen address")?;

    tracing::info!(
        "TLS enabled - listening on https://{} and http://{} (redirect)",
        https_addr,
        http_addr
    );
    tracing::info!("Send SIGHUP to reload TLS certificates");

    // Create shared cancellation token for coordinated shutdown
    let shutdown_token = CancellationToken::new();

    // Spawn shutdown signal handler that cancels the token
    let shutdown_token_for_signal = shutdown_token.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown_token_for_signal.cancel();
    });

    // Start S3 config polling task if configured (with TLS config for hot reload)
    let s3_poll_handle = start_s3_polling(state, s3_parts, Some(tls_config.clone()));

    spawn_sighup_cert_reload(tls_config.clone(), state.config.clone());

    // Start mTLS listener whenever TLS is configured (mTLS port always has a value).
    let mtls_port = config.mtls_port;
    let mtls_addr: std::net::SocketAddr = format!("[::]:{mtls_port}")
        .parse()
        .context("Invalid mTLS listen address")?;

    let mtls_handle: Option<JoinHandle<()>> =
        match start_mtls_listener(config, mtls_addr, app.clone(), shutdown_token.clone()).await {
            Ok(handle) => {
                tracing::info!("mTLS listener started on port {}", mtls_port);
                Some(handle)
            }
            Err(e) => {
                return Err(e.context("Failed to start mTLS listener"));
            }
        };

    // Create handle for graceful shutdown of HTTPS server
    let handle = axum_server::Handle::new();
    let handle_for_shutdown = handle.clone();

    // Spawn HTTPS shutdown handler (uses cancellation token)
    let token_for_https = shutdown_token.clone();
    tokio::spawn(async move {
        token_for_https.cancelled().await;
        tracing::info!("Initiating graceful shutdown (30s timeout)");
        handle_for_shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });

    // Build HTTP redirect router (with state for Host validation)
    let redirect_app = crate::build_redirect_router(state.clone());

    // Spawn HTTP redirect server (port 80) - best effort, not fatal if fails
    let token_for_http = shutdown_token.clone();
    let http_handle = tokio::spawn(async move {
        match tokio::net::TcpListener::bind(http_addr).await {
            Ok(listener) => {
                let listener = listener.tap_io(|tcp| {
                    if let Err(err) = tcp.set_nodelay(true) {
                        tracing::trace!(
                            "failed to set TCP_NODELAY on incoming connection: {err:#}"
                        );
                    }
                });
                if let Err(e) = axum::serve(listener, redirect_app)
                    .with_graceful_shutdown(token_for_http.cancelled_owned())
                    .await
                {
                    tracing::error!("HTTP redirect server error: {e}");
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Could not bind HTTP redirect on {}: {e} (continuing without redirect)",
                    http_addr
                );
                tracing::warn!("Hint: Ports below 1024 require CAP_NET_BIND_SERVICE capability");
            }
        }
    });

    // Run HTTPS server (port 443) - this blocks until shutdown
    axum_server::bind_rustls(https_addr, tls_config)
        .map(|acceptor| acceptor.acceptor(NoDelayAcceptor::new()))
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await?;

    // Wait for HTTP redirect server to finish; ignore JoinError on shutdown.
    let _http = http_handle.await;

    // Wait for mTLS listener to finish; ignore JoinError on shutdown.
    if let Some(handle) = mtls_handle {
        let _mtls = handle.await;
    }

    Ok(s3_poll_handle)
}

/// Run in plain HTTP mode on the configured listen address. Blocks until
/// shutdown.
///
/// Returns the S3 config polling task handle (if S3 config is in use) so the
/// caller can abort it during cleanup.
async fn serve_plain(
    config: &ServerConfig,
    state: &Arc<AppState>,
    app: Router,
    s3_parts: S3ConfigParts,
) -> Result<Option<JoinHandle<()>>> {
    // Start S3 config polling task if configured (no TLS config to reload)
    let s3_poll_handle = start_s3_polling(state, s3_parts, None);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Listening on http://{}", config.listen_addr);

    let listener = listener.tap_io(|tcp| {
        if let Err(err) = tcp.set_nodelay(true) {
            tracing::trace!("failed to set TCP_NODELAY on incoming connection: {err:#}");
        }
    });
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(s3_poll_handle)
}

/// Spawn the SIGHUP handler for TLS certificate hot reload.
///
/// Reads cert/key from the current (possibly S3-merged) config on each
/// signal, not from the values captured at startup.
fn spawn_sighup_cert_reload(
    tls_config: axum_server::tls_rustls::RustlsConfig,
    config: Arc<arc_swap::ArcSwap<ServerConfig>>,
) {
    tokio::spawn(async move {
        let Ok(mut sighup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            tracing::warn!("Failed to register SIGHUP handler, TLS hot reload disabled");
            return;
        };

        loop {
            sighup.recv().await;
            tracing::info!("Received SIGHUP, reloading TLS certificates...");

            // Read from current config (supports both env vars and S3 config)
            let cfg = config.load();
            match (&cfg.tls_cert, &cfg.tls_key) {
                (Some(cert), Some(key)) => {
                    match crate::infra::tls::reload_tls_from_config(&tls_config, cert, key) {
                        Ok(()) => tracing::info!("TLS certificates reloaded successfully"),
                        Err(e) => tracing::error!("Failed to reload TLS certificates: {e:#}"),
                    }
                }
                _ => tracing::warn!("TLS not configured, nothing to reload"),
            }
        }
    });
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.ok();
    };

    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };

    tokio::select! {
        () = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown");
        }
        () = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        }
    }
}

/// Start the mTLS listener on a separate port.
///
/// Uses the same server TLS certificate as the main HTTPS listener,
/// with a custom client cert verifier that accepts any certificate
/// (including self-signed) and delegates validation to the application layer.
async fn start_mtls_listener(
    config: &crate::config::ServerConfig,
    addr: std::net::SocketAddr,
    app: Router,
    shutdown_token: CancellationToken,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    use super::mtls_listener::{MtlsListener, PeerClientCert, build_mtls_server_config};

    // Parse server cert/key for the mTLS listener (same identity)
    let (certs, key) = super::tls::parse_server_cert_and_key(config)?;

    let mtls_config = build_mtls_server_config(certs, key)?;
    let mtls_config_swap = std::sync::Arc::new(arc_swap::ArcSwap::from(mtls_config));

    // Bind before spawning so the caller learns of port conflicts immediately.
    let tcp = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind mTLS listener on {addr}"))?;

    let handle = tokio::spawn(async move {
        let listener = MtlsListener::new(tcp, mtls_config_swap);
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<PeerClientCert>(),
        )
        .with_graceful_shutdown(shutdown_token.cancelled_owned())
        .await
        {
            tracing::error!("mTLS server error: {e}");
        }
    });

    Ok(handle)
}
