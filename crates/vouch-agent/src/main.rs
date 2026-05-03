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
use vouch_agent::socket::remove_socket;
use vouch_agent::ssh_agent::{SshAgentServer, SshAgentState, ssh_agent_socket_path};
use vouch_agent::state::AgentState;

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

fn main() -> ExitCode {
    let args = Args::parse();

    // Handle status check (no logging needed)
    if args.status {
        match daemon::is_running() {
            Ok(true) => {
                println!("Agent is running");
                return ExitCode::SUCCESS;
            }
            Ok(false) => {
                println!("Agent is not running");
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("Error checking status: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Handle stop command
    if args.stop {
        return stop_agent();
    }

    // Check if already running
    match daemon::is_running() {
        Ok(true) => {
            eprintln!("Agent is already running. Use --stop to stop it.");
            return ExitCode::FAILURE;
        }
        Ok(false) => {}
        Err(e) => {
            eprintln!("Error checking if agent is running: {e}");
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
                eprintln!("Failed to daemonize: {e}");
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
    // Create agent state
    let state = AgentState::new();

    // Create SSH agent state
    let ssh_state = SshAgentState::new();

    // Try to recover session from disk (best-effort)
    if recovery::try_recover_session(&state, &ssh_state).await {
        info!("Session recovered from disk");
    }

    // Shutdown signal channel for graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Create servers — each gets its own receiver from the shutdown channel
    let agent_shutdown_rx = shutdown_rx.clone();
    let server = AgentServer::new(
        Arc::clone(&state),
        Arc::clone(&ssh_state),
        agent_shutdown_rx,
    );
    // Create SSH agent server with access to main agent state for certificate refresh
    let ssh_server =
        SshAgentServer::with_agent_state(Arc::clone(&ssh_state), Arc::clone(&state), shutdown_rx);

    info!("Agent starting");

    // Spawn session expiry monitor (background task)
    tokio::spawn(vouch_agent::expiry_monitor::run(Arc::clone(&state)));

    // Set up SIGTERM handler before select!
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());

    // Run both servers
    let result = tokio::select! {
        result = server.run() => {
            match result {
                Ok(()) => {
                    info!("Agent stopped");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    error!("Agent error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        result = ssh_server.run(), if enable_ssh_agent => {
            match result {
                Ok(()) => {
                    info!("SSH agent stopped");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    error!("SSH agent error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        result = tokio::signal::ctrl_c() => {
            match result {
                Ok(()) => {
                    info!("Received shutdown signal, shutting down...");
                }
                Err(e) => {
                    warn!("Failed to listen for Ctrl+C: {e}");
                }
            }
            // Signal SSH agent to stop accepting new connections; receiver may already be gone.
            let _signaled = shutdown_tx.send(true);
            ExitCode::SUCCESS
        }
        Some(()) = async {
            match &mut sigterm {
                Ok(s) => s.recv().await,
                Err(_) => std::future::pending().await,
            }
        } => {
            info!("Received SIGTERM, shutting down...");
            // Signal SSH agent to stop accepting new connections; receiver may already be gone.
            let _signaled = shutdown_tx.send(true);
            ExitCode::SUCCESS
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
            eprintln!("Error getting PID file path: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !pid_path.exists() {
        eprintln!("Agent is not running (no PID file)");
        return ExitCode::FAILURE;
    }

    let pid_str = match std::fs::read_to_string(&pid_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read PID file: {e}");
            return ExitCode::FAILURE;
        }
    };

    let pid: i32 = match pid_str.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Invalid PID in file");
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
            println!("Sent stop signal to agent (PID {pid})");

            // Wait a bit and check if it stopped
            std::thread::sleep(std::time::Duration::from_millis(500));

            // SAFETY: kill(pid, 0) checks if process exists
            if unsafe { libc::kill(pid, 0) } != 0 {
                println!("Agent stopped");
                // Best-effort cleanup of the PID file.
                let _removed = daemon::remove_pid_file();
            } else {
                println!("Agent is shutting down...");
            }
            ExitCode::SUCCESS
        } else {
            eprintln!("Failed to send signal to agent (PID {pid})");
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
        eprintln!("Stop command not supported on this platform");
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
