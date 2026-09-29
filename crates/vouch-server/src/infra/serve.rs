// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server lifecycle management.
//!
//! Handles TLS vs non-TLS server binding, HTTP->HTTPS redirect, SIGHUP
//! certificate hot reload, S3 config polling, and graceful shutdown.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::AppState;
use crate::config::ServerConfig;
use crate::infra::s3_config;

use super::accept::{self, ConnLimits, PlainHandshake, ProxyProtocol, TlsHandshake};
use super::conn_caps::ConnCaps;
use super::mtls_listener::MtlsHandshake;
use super::startup::ServerComponents;
use crate::infra::tls;

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
    // so cleanup stays shared below. A startup error (a port already in use)
    // still runs the cleanup before it is returned.
    let served = if config.tls_configured() {
        serve_tls(&config, &state, app, s3_parts).await
    } else {
        serve_plain(&config, &state, app, s3_parts).await
    };

    // Clean up background tasks
    if let Ok(Some(handle)) = &served {
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

    served?;
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
    mtls_config: Option<super::mtls_listener::MtlsConfigSwap>,
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
        mtls_config,
        etag,
    ))
}

/// Listen addresses for TLS mode.
struct TlsAddrs {
    https: std::net::SocketAddr,
    http_redirect: std::net::SocketAddr,
    mtls: std::net::SocketAddr,
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
    let addrs = TlsAddrs {
        https: "[::]:443".parse().context("Invalid HTTPS listen address")?,
        http_redirect: "[::]:80".parse().context("Invalid HTTP listen address")?,
        mtls: format!("[::]:{}", config.mtls_port)
            .parse()
            .context("Invalid mTLS listen address")?,
    };
    serve_tls_on(config, state, app, s3_parts, &addrs).await
}

async fn serve_tls_on(
    config: &ServerConfig,
    state: &Arc<AppState>,
    app: Router,
    s3_parts: S3ConfigParts,
    addrs: &TlsAddrs,
) -> Result<Option<JoinHandle<()>>> {
    // Everything that can fail happens before anything is started, so an
    // error here returns with no task running and no port held.
    let tls_config = tls::build_tls_config(config)?;
    let (mtls_listener, mtls_config_swap) = bind_mtls_listener(config, addrs.mtls)
        .await
        .context("Failed to start mTLS listener")?;
    let https_listener = tokio::net::TcpListener::bind(addrs.https)
        .await
        .with_context(|| format!("Failed to bind HTTPS listener on {}", addrs.https))?;

    // Nothing below can fail.
    let caps = ConnCaps::for_config(config);
    tracing::info!(
        "TLS enabled - listening on https://{} and http://{} (redirect)",
        addrs.https,
        addrs.http_redirect
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

    let mtls_handle = tokio::spawn(accept::serve(
        mtls_listener,
        ProxyProtocol::from_config(config),
        MtlsHandshake::new(mtls_config_swap.clone()),
        app.clone(),
        ConnLimits::DEFAULT,
        Arc::clone(&caps),
        shutdown_token.clone(),
    ));
    tracing::info!("mTLS listener started on port {}", addrs.mtls.port());

    // Start S3 config polling task if configured (with TLS config for hot reload)
    let s3_poll_handle = start_s3_polling(
        state,
        s3_parts,
        Some(tls_config.clone()),
        Some(mtls_config_swap.clone()),
    );

    spawn_sighup_cert_reload(
        tls_config.clone(),
        mtls_config_swap,
        state.config.clone(),
        shutdown_token.clone(),
    );

    // Build HTTP redirect router (with state for Host validation)
    let redirect_app = crate::build_redirect_router(state.clone());

    // Spawn HTTP redirect server (port 80) - best effort, not fatal if fails
    let http_addr = addrs.http_redirect;
    let token_for_http = shutdown_token.clone();
    let caps_for_http = Arc::clone(&caps);
    let http_handle = tokio::spawn(async move {
        match tokio::net::TcpListener::bind(http_addr).await {
            Ok(listener) => {
                // Never takes the PROXY protocol, so a readiness probe that
                // sends no header can reach `/health/ready` here.
                accept::serve(
                    listener,
                    ProxyProtocol::off(),
                    PlainHandshake,
                    redirect_app,
                    ConnLimits::DEFAULT,
                    caps_for_http,
                    token_for_http,
                )
                .await;
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
    accept::serve(
        https_listener,
        ProxyProtocol::from_config(config),
        TlsHandshake(tls_config),
        app,
        ConnLimits::DEFAULT,
        caps,
        shutdown_token,
    )
    .await;

    // Wait for HTTP redirect server to finish; ignore JoinError on shutdown.
    let _http = http_handle.await;

    // Wait for mTLS listener to finish; ignore JoinError on shutdown.
    let _mtls = mtls_handle.await;

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
    // The PROXY protocol applies to the HTTPS and mTLS listeners, which only
    // run with TLS; ignoring it here would leave an operator believing the
    // header was required.
    if config.proxy_protocol {
        anyhow::bail!(
            "VOUCH_PROXY_PROTOCOL applies to the TLS listeners; configure VOUCH_TLS_CERT and \
             VOUCH_TLS_KEY or unset it"
        );
    }
    // Bind before starting anything, so a port conflict leaves nothing running.
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Listening on http://{}", config.listen_addr);

    // Start S3 config polling task if configured (no TLS config to reload)
    let s3_poll_handle = start_s3_polling(state, s3_parts, None, None);

    let shutdown_token = CancellationToken::new();
    let token_for_signal = shutdown_token.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        token_for_signal.cancel();
    });
    accept::serve(
        listener,
        ProxyProtocol::off(),
        PlainHandshake,
        app,
        ConnLimits::DEFAULT,
        ConnCaps::for_config(config),
        shutdown_token,
    )
    .await;

    Ok(s3_poll_handle)
}

/// Spawn the SIGHUP handler for TLS certificate hot reload.
///
/// Reads cert/key from the current (possibly S3-merged) config on each
/// signal, not from the values captured at startup.
fn spawn_sighup_cert_reload(
    tls_config: axum_server::tls_rustls::RustlsConfig,
    mtls_config: super::mtls_listener::MtlsConfigSwap,
    config: Arc<arc_swap::ArcSwap<ServerConfig>>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let Ok(mut sighup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            tracing::warn!("Failed to register SIGHUP handler, TLS hot reload disabled");
            return;
        };

        loop {
            tokio::select! {
                () = shutdown.cancelled() => return,
                _ = sighup.recv() => {}
            }
            tracing::info!("Received SIGHUP, reloading TLS certificates...");

            // Read from current config (supports both env vars and S3 config)
            let cfg = config.load();
            match (&cfg.tls_cert, &cfg.tls_key) {
                (Some(cert), Some(key)) => {
                    match tls::reload_tls_from_config(&tls_config, cert, key) {
                        Ok(()) => tracing::info!("TLS certificates reloaded successfully"),
                        Err(e) => tracing::error!("Failed to reload TLS certificates: {e:#}"),
                    }
                    // Reload the mTLS listener independently: a failure here
                    // must not undo the successful HTTPS reload above.
                    match super::mtls_listener::reload_mtls_from_config(&mtls_config, cert, key) {
                        Ok(()) => {
                            tracing::info!("mTLS listener certificates reloaded successfully");
                        }
                        Err(e) => {
                            tracing::error!("Failed to reload mTLS listener certificates: {e:#}");
                        }
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

/// Bind the mTLS listener's port and build its TLS config, without starting
/// it.
///
/// Uses the same server TLS certificate as the main HTTPS listener,
/// with a custom client cert verifier that accepts any certificate
/// (including self-signed) and delegates validation to the application layer.
/// The returned config handle is what certificate hot reload swaps.
async fn bind_mtls_listener(
    config: &ServerConfig,
    addr: std::net::SocketAddr,
) -> Result<(
    tokio::net::TcpListener,
    super::mtls_listener::MtlsConfigSwap,
)> {
    use super::mtls_listener::build_mtls_server_config;

    // Parse server cert/key for the mTLS listener (same identity)
    let (certs, key) = super::tls::parse_server_cert_and_key(config)?;

    let mtls_config = build_mtls_server_config(certs, key)?;
    let mtls_config_swap = std::sync::Arc::new(arc_swap::ArcSwap::from(mtls_config));

    let tcp = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind mTLS listener on {addr}"))?;

    Ok((tcp, mtls_config_swap))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    use secrecy::SecretString;
    use tokio::net::TcpListener;

    use crate::test_utils::{TEST_TLS_CERT_PEM, TEST_TLS_KEY_PEM, test_app_state, test_config};

    /// A TLS startup that fails to bind the HTTPS port must return with nothing
    /// running. The mTLS listener used to be started first, so it kept serving
    /// (and holding its port) after `serve_tls` had already returned the error.
    #[tokio::test]
    async fn failed_https_bind_leaves_nothing_running() {
        let mut config = test_config();
        config.tls_cert = Some(TEST_TLS_CERT_PEM.to_string());
        config.tls_key = Some(SecretString::from(TEST_TLS_KEY_PEM));
        let state = test_app_state().await;

        let https_taken = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let mtls = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind")
            .local_addr()
            .expect("local addr");
        let addrs = TlsAddrs {
            https: https_taken.local_addr().expect("local addr"),
            http_redirect: "127.0.0.1:0".parse().expect("addr"),
            mtls,
        };

        let err = serve_tls_on(&config, &state, Router::new(), (None, None, None), &addrs)
            .await
            .expect_err("the HTTPS port is taken");
        assert!(
            format!("{err:#}").contains("Failed to bind HTTPS listener"),
            "unexpected error: {err:#}"
        );

        TcpListener::bind(mtls)
            .await
            .expect("the mTLS port must be free once serve_tls has returned");
    }
}
