//! Vouch local credential agent.
//!
//! This crate provides the vouch-agent daemon that manages session state
//! and credentials via IPC over Unix domain sockets.
//!
//! # Architecture
//!
//! The agent runs as a background daemon listening on `~/.vouch/agent.sock`.
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

pub mod client;
pub mod error;
pub mod protocol;
pub mod server;
pub mod socket;
pub mod state;

// Re-export commonly used types
pub use client::AgentClient;
pub use error::{AgentError, Result};
pub use state::SessionInfo;
