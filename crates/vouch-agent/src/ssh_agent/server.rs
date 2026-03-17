// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH Agent server.

use crate::error::{AgentError, Result};
use crate::socket::bind_socket;
use crate::wire;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::{Semaphore, watch};
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent SSH agent connections.
const MAX_SSH_CONNECTIONS: usize = 64;

use super::provisioning::{handle_request_identities, handle_sign_request};
use super::state::SshAgentState;
use super::{
    SSH_AGENT_FAILURE, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST,
    ssh_agent_socket_path,
};

/// SSH Agent server with graceful shutdown support.
pub struct SshAgentServer {
    state: Arc<SshAgentState>,
    agent_state: Option<Arc<crate::state::AgentState>>,
    shutdown_rx: watch::Receiver<bool>,
}

impl SshAgentServer {
    /// Create a new SSH agent server with a shutdown signal.
    pub fn new(state: Arc<SshAgentState>, shutdown_rx: watch::Receiver<bool>) -> Self {
        Self {
            state,
            agent_state: None,
            shutdown_rx,
        }
    }

    /// Create a new SSH agent server with access to the main agent state (for refresh).
    pub fn with_agent_state(
        state: Arc<SshAgentState>,
        agent_state: Arc<crate::state::AgentState>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Self {
        Self {
            state,
            agent_state: Some(agent_state),
            shutdown_rx,
        }
    }

    /// Run the SSH agent server.
    ///
    /// Stops accepting new connections when the shutdown signal is received.
    /// In-flight connections continue until they complete naturally.
    pub async fn run(&self) -> Result<()> {
        let path = ssh_agent_socket_path()?;
        let listener = bind_socket(&path).await?;

        info!("SSH agent listening on {}", path.display());

        let mut shutdown = self.shutdown_rx.clone();
        let semaphore = Arc::new(Semaphore::new(MAX_SSH_CONNECTIONS));

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    warn!("SSH connection limit reached ({MAX_SSH_CONNECTIONS}), rejecting");
                                    continue;
                                }
                            };
                            let state = Arc::clone(&self.state);
                            let agent_state = self.agent_state.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(e) = handle_ssh_connection(stream, state, agent_state).await {
                                    debug!("SSH agent connection error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            error!("SSH agent accept error: {e}");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    info!("SSH agent received shutdown signal, stopping listener");
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Handle a single SSH agent connection.
async fn handle_ssh_connection(
    mut stream: UnixStream,
    state: Arc<SshAgentState>,
    agent_state: Option<Arc<crate::state::AgentState>>,
) -> Result<()> {
    loop {
        // Read length-prefixed message
        let buf = match wire::read_message(&mut stream).await? {
            Some(buf) => buf,
            None => return Ok(()), // Clean disconnect
        };

        // Validate message size for SSH agent (more restrictive than general wire protocol)
        if buf.len() > 256 * 1024 {
            warn!("Invalid SSH agent message length: {}", buf.len());
            return Err(AgentError::Protocol("invalid message length".to_string()));
        }

        // Get message type (first byte)
        let msg_type = buf.first().copied().unwrap_or(0);
        debug!("SSH agent message type: {msg_type}");

        // Handle message
        let response = match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                handle_request_identities(&state, agent_state.as_ref()).await
            }
            SSH_AGENTC_SIGN_REQUEST => {
                handle_sign_request(&buf, &state, agent_state.as_ref()).await
            }
            _ => {
                debug!("Unknown SSH agent message type: {msg_type}");
                Ok(vec![SSH_AGENT_FAILURE])
            }
        };

        // Send response
        let response_data = response.unwrap_or_else(|e| {
            warn!("SSH agent error: {e}");
            vec![SSH_AGENT_FAILURE]
        });
        wire::write_message(&mut stream, &response_data).await?;
    }
}

impl Drop for SshAgentServer {
    fn drop(&mut self) {
        // Clean up socket on drop
        if let Ok(path) = ssh_agent_socket_path() {
            std::fs::remove_file(path).ok();
        }
    }
}
