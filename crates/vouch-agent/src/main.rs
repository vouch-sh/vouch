// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch agent daemon binary.

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::Parser;
use std::process::ExitCode;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use vouch_agent::daemon;
use vouch_agent::recovery;
use vouch_agent::server::AgentServer;
use vouch_agent::socket::{prepare_vouch_dir, remove_socket};
use vouch_agent::ssh_agent::{SshAgentServer, ssh_agent_socket_path};
use vouch_agent::state::AgentState;
#[expect(
    unused_imports,
    reason = "re-exported so dual-compiled submodules can use `crate::tr*!`"
)]
use vouch_agent::{tr, tr_args, tr_eprintln, tr_println};

/// Vouch credential agent daemon.
#[derive(Parser)]
#[command(name = "vouch-agent", version, about)]
struct Args {
    /// Run in foreground (don't daemonize).
    #[arg(short, long)]
    foreground: bool,

    /// Enable verbose logging.
    #[arg(short, long)]
    verbose: bool,

    /// Enable SSH agent.
    #[arg(long, default_value = "true")]
    ssh_agent: bool,

    /// Stop a running agent.
    #[arg(long)]
    stop: bool,

    /// Check if agent is running.
    #[arg(long)]
    status: bool,
}

#[expect(
    clippy::print_stderr,
    reason = "an i18n init failure has to report itself without i18n or tracing"
)]
fn main() -> ExitCode {
    let args = Args::parse();

    // Relocate any legacy ~/.vouch/ files into the XDG base directories before
    // reading config or binding sockets. Runs before daemonization so the
    // one-time notice reaches the user's terminal rather than the daemon log.
    vouch_common::paths::migrate_legacy_layout();

    // `--status` and `--stop` are operator controls for an already-running
    // daemon, so they intentionally run before i18n init: a packaging bug
    // that corrupts the catalog must not strand the operator with no way to
    // inspect or stop the agent. The `tr_*!` macros fall back to a fresh
    // en-US loader when `init()` hasn't been called, so the messages still
    // render — they just skip locale negotiation.
    if args.status {
        match daemon::is_running() {
            Ok(true) => {
                tr_println!("agent-running");
                return ExitCode::SUCCESS;
            }
            Ok(false) => {
                tr_println!("agent-not-running");
                return ExitCode::FAILURE;
            }
            Err(e) => {
                tr_eprintln!("agent-status-err", reason = format!("{e:#}"));
                return ExitCode::FAILURE;
            }
        }
    }

    if args.stop {
        return stop_agent();
    }

    if let Err(e) = vouch_agent::i18n::init() {
        eprintln!("Error initializing i18n: {e}");
        return ExitCode::FAILURE;
    }

    // Check if already running
    match daemon::is_running() {
        Ok(true) => {
            tr_eprintln!("agent-already-running");
            return ExitCode::FAILURE;
        }
        Ok(false) => {}
        Err(e) => {
            tr_eprintln!("agent-check-running-err", reason = format!("{e:#}"));
            return ExitCode::FAILURE;
        }
    }

    // Initialize logging (before daemonization so we see startup messages)
    let filter = if args.verbose {
        EnvFilter::new("vouch_agent=debug")
    } else {
        EnvFilter::new("vouch_agent=info")
    };

    // Handle daemonization
    if !args.foreground {
        match daemon::daemonize() {
            Ok(daemon::DaemonizeResult::Child) => {
                // Re-initialize logging after fork (stdout/stderr redirected)
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_target(false)
                    .with_ansi(false)
                    .init();
            }
            Ok(daemon::DaemonizeResult::Parent) => {
                // Parent process after fork - exit successfully
                return ExitCode::SUCCESS;
            }
            Ok(daemon::DaemonizeResult::Skipped) => {
                // Daemonization skipped (non-Unix)
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_target(false)
                    .init();
                info!("Running in foreground mode (daemonization not available)");
            }
            Err(e) => {
                tr_eprintln!("agent-daemonize-err", reason = format!("{e:#}"));
                return ExitCode::FAILURE;
            }
        }
    } else {
        // Foreground mode
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .init();

        // Write PID file even in foreground mode
        if let Err(e) = daemon::write_pid_file() {
            warn!("Failed to write PID file: {e}");
        }
    }

    // Initialize the process-wide DNS-over-HTTPS resolver from config + env
    // before any HTTP traffic. Validates the configuration eagerly; the
    // hickory resolver itself is built lazily on first use.
    if let Err(e) = vouch_agent::dns::init() {
        error!("DNS-over-HTTPS initialization failed: {e:#}");
        return ExitCode::FAILURE;
    }

    // Run the server using a tokio runtime
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(run_agent_server(args.ssh_agent))
}

/// Run the agent servers.
async fn run_agent_server(enable_ssh_agent: bool) -> ExitCode {
    // Prepare the runtime directory before either listener binds a socket
    // into it: lstat-first validation rejects a hijacked path without
    // modifying it.
    if let Err(e) = prepare_vouch_dir() {
        error!("Runtime directory validation failed: {e}");
        return ExitCode::FAILURE;
    }

    // Create agent state, shared by both servers so a credential and the
    // session authorizing it are always read and cleared together.
    let state = AgentState::new();

    // Try to recover session from disk (best-effort)
    if recovery::try_recover_session(&state).await {
        info!("Session recovered from disk");
    }

    // Shutdown signal channel for graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Create servers — each gets its own receiver from the shutdown channel
    let agent_shutdown_rx = shutdown_rx.clone();
    let server = AgentServer::new(Arc::clone(&state), agent_shutdown_rx);
    let ssh_server = SshAgentServer::new(Arc::clone(&state), shutdown_rx);

    info!("Agent starting");

    // Spawn session expiry monitor (background task)
    tokio::spawn(vouch_agent::expiry_monitor::run(Arc::clone(&state)));

    // Spawn the signal handler as a separate task so the server futures are
    // not dropped before they can observe the shutdown signal.  When SIGTERM
    // or Ctrl+C arrives the handler sends `true` on the watch channel; both
    // servers poll `shutdown.changed()` in their accept loops and exit
    // cleanly instead of being cancelled mid-request.
    let shutdown_tx_for_signal = shutdown_tx.clone();
    tokio::spawn(async move {
        let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                match result {
                    Ok(()) => info!("Received Ctrl+C, initiating graceful shutdown"),
                    Err(e) => warn!("Failed to listen for Ctrl+C: {e}"),
                }
            }
            Some(()) = async {
                match sigterm {
                    Ok(mut s) => s.recv().await,
                    Err(_) => std::future::pending().await,
                }
            } => {
                info!("Received SIGTERM, initiating graceful shutdown");
            }
        }
        let _signaled = shutdown_tx_for_signal.send(true);
    });

    // Run both servers concurrently.  The signal-handler task runs
    // independently and signals shutdown via the watch channel — the servers
    // observe it in their accept loops and stop accepting new connections,
    // then drain in-flight requests before returning.  When either server
    // finishes (shutdown or error) it also sends the shutdown signal so the
    // other exits as well.
    let result = if enable_ssh_agent {
        let (ipc_result, ssh_result) = tokio::join!(
            async {
                let result = server.run().await;
                let _signaled = shutdown_tx.send(true);
                match &result {
                    Ok(()) => info!("Agent stopped"),
                    Err(e) => error!("Agent error: {e}"),
                }
                result
            },
            async {
                let result = ssh_server.run().await;
                let _signaled = shutdown_tx.send(true);
                match &result {
                    Ok(()) => info!("SSH agent stopped"),
                    Err(e) => error!("SSH agent error: {e}"),
                }
                result
            },
        );
        match (ipc_result, ssh_result) {
            (Ok(()), Ok(())) => ExitCode::SUCCESS,
            _ => ExitCode::FAILURE,
        }
    } else {
        match server.run().await {
            Ok(()) => {
                info!("Agent stopped");
                ExitCode::SUCCESS
            }
            Err(e) => {
                error!("Agent error: {e}");
                ExitCode::FAILURE
            }
        }
    };

    // Clean up
    cleanup();
    result
}

/// Stop a running agent.
#[expect(
    unsafe_code,
    reason = "libc::kill sends SIGTERM to a PID we own; safety documented inline"
)]
fn stop_agent() -> ExitCode {
    // Read PID file
    let pid_path = match daemon::pid_file_path() {
        Ok(p) => p,
        Err(e) => {
            tr_eprintln!("agent-pid-file-err", reason = format!("{e:#}"));
            return ExitCode::FAILURE;
        }
    };

    if !pid_path.exists() {
        tr_eprintln!("agent-not-running-no-pid");
        return ExitCode::FAILURE;
    }

    let pid_str = match std::fs::read_to_string(&pid_path) {
        Ok(s) => s,
        Err(e) => {
            tr_eprintln!("agent-pid-read-err", reason = e.to_string());
            return ExitCode::FAILURE;
        }
    };

    let pid: i32 = match pid_str.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            tr_eprintln!("agent-pid-invalid");
            // Best-effort cleanup of the stale PID file.
            let _removed = std::fs::remove_file(&pid_path);
            return ExitCode::FAILURE;
        }
    };

    // Send SIGTERM to the process
    #[cfg(unix)]
    {
        // SAFETY: kill() is a standard Unix API for sending signals to processes
        if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
            tr_println!("agent-stop-signal-sent", pid = pid.to_string());

            // Wait a bit and check if it stopped
            std::thread::sleep(std::time::Duration::from_millis(500));

            // SAFETY: kill(pid, 0) checks if process exists
            if unsafe { libc::kill(pid, 0) } != 0 {
                tr_println!("agent-stopped");
                // Best-effort cleanup of the PID file.
                let _removed = daemon::remove_pid_file();
            } else {
                tr_println!("agent-shutting-down");
            }
            ExitCode::SUCCESS
        } else {
            tr_eprintln!("agent-stop-signal-failed", pid = pid.to_string());
            // Remove stale PID file if process doesn't exist
            // SAFETY: kill(pid, 0) checks if process exists
            if unsafe { libc::kill(pid, 0) } != 0 {
                // Best-effort cleanup of the stale PID file.
                let _removed = daemon::remove_pid_file();
            }
            ExitCode::FAILURE
        }
    }

    #[cfg(not(unix))]
    {
        tr_eprintln!("agent-stop-unsupported");
        ExitCode::FAILURE
    }
}

/// Clean up on shutdown.
fn cleanup() {
    // Remove sockets
    if let Err(e) = remove_socket() {
        error!("Failed to remove socket: {e}");
    }
    if let Ok(path) = ssh_agent_socket_path() {
        std::fs::remove_file(path).ok();
    }

    // Remove PID file
    if let Err(e) = daemon::remove_pid_file() {
        error!("Failed to remove PID file: {e}");
    }

    info!("Cleanup complete");
}
