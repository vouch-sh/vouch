// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch local credential agent.
//!
//! This crate provides the vouch-agent daemon that manages session state
//! and credentials via IPC over Unix domain sockets.
//!
//! # Architecture
//!
//! The agent runs as a background daemon listening on
//! `$XDG_RUNTIME_DIR/vouch/agent.sock`.
//! It uses a JSON-RPC 2.0 protocol with 4-byte length-prefixed messages.
//!
//! # Example (CLI usage)
//!
//! ```no_run
//! use vouch_agent::client::AgentClient;
//!
//! async fn example() -> Result<(), vouch_agent::error::AgentError> {
//!     let mut client = AgentClient::connect().await?;
//!
//!     // Check if authenticated
//!     match client.get_session().await {
//!         Ok(session) => println!("Logged in as {}", session.user_email),
//!         Err(_) => println!("Not authenticated"),
//!     }
//!
//!     Ok(())
//! }
//! ```

// File replacement goes through `vouch_common::fs::atomic_write`, which keeps
// symlinks. `disallowed_methods` is configured in `.clippy.toml` and left at
// `allow` workspace-wide; this is where it is switched on. Clock reads carry an
// `#[expect]`: a client has no request instant to anchor to.
#![warn(clippy::disallowed_methods)]
// Tests build fixtures and stamp clocks freely; the non-test build still lints
// every production site.
#![cfg_attr(
    test,
    expect(
        clippy::disallowed_methods,
        reason = "tests build fixtures and stamp clocks; the lint targets production code"
    )
)]

pub mod audit;
#[cfg(unix)]
pub mod client;
pub mod daemon;
pub mod error;
#[cfg(unix)]
pub mod expiry_monitor;
pub mod i18n;
pub mod protocol;
#[cfg(unix)]
#[cfg(unix)]
pub mod server;
pub mod socket;
#[cfg(unix)]
pub mod ssh_agent;
pub mod state;
pub mod transport;
pub mod wire;

// Re-export commonly used types
#[cfg(unix)]
pub use client::AgentClient;
pub use error::{AgentError, Result};
#[cfg(unix)]
pub use ssh_agent::ssh_agent_socket_path;
pub use state::SessionInfo;

#[cfg(any(test, feature = "test-utils"))]
pub use transport::{TestTransport, TestTransportPair};

#[cfg(test)]
mod ipc_tests;
