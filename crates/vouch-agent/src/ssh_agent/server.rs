// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH Agent server.

use crate::error::{AgentError, Result};
use crate::socket::{AuthorizedStream, SocketKind, accept_authorized, bind_socket};
use crate::wire;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

/// Maximum number of concurrent SSH agent connections.
const MAX_SSH_CONNECTIONS: usize = 64;

/// Maximum time to wait for in-flight connections to finish during shutdown
/// before aborting them.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Create a new SSH agent server with access to the main agent state, used
    /// to session-gate lazy disk loading of certificates.
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
    /// In-flight connections continue until they complete naturally or the
    /// drain timeout expires.
    pub async fn run(&self) -> Result<()> {
        let path = ssh_agent_socket_path()?;
        let listener = bind_socket(&path).await?;

        info!("SSH agent listening on {}", path.display());

        self.run_listener(listener).await
    }

    /// Accept loop and graceful-drain core, separated from [`run`](Self::run)
    /// so tests can drive it against a temporary listener without touching
    /// `XDG_RUNTIME_DIR`.
    async fn run_listener(&self, listener: UnixListener) -> Result<()> {
        let mut shutdown = self.shutdown_rx.clone();
        let semaphore = Arc::new(Semaphore::new(MAX_SSH_CONNECTIONS));
        let mut tasks: JoinSet<()> = JoinSet::new();

        loop {
            tokio::select! {
                conn = accept_authorized(&listener, SocketKind::SshAgent) => {
                    let Some(conn) = conn else { continue };
                    let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!("SSH connection limit reached ({MAX_SSH_CONNECTIONS}), rejecting");
                            continue;
                        }
                    };
                    let state = Arc::clone(&self.state);
                    let agent_state = self.agent_state.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(e) = handle_ssh_connection(conn, state, agent_state).await {
                            debug!("SSH agent connection error: {e}");
                        }
                    });
                }
                _ = shutdown.changed() => {
                    info!("SSH agent received shutdown signal, stopping listener");
                    break;
                }
            }
        }

        drain_connections(&mut tasks).await;

        Ok(())
    }
}

/// Wait for in-flight connection tasks to finish, aborting any that do not
/// complete within [`SHUTDOWN_DRAIN_TIMEOUT`].
async fn drain_connections(tasks: &mut JoinSet<()>) {
    if tasks.is_empty() {
        return;
    }
    info!(
        count = tasks.len(),
        "Waiting for in-flight SSH connections to complete"
    );
    let drain = async { while tasks.join_next().await.is_some() {} };
    match tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, drain).await {
        Ok(()) => info!("All in-flight SSH connections completed gracefully"),
        Err(_) => {
            let remaining = tasks.len();
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            warn!(
                count = remaining,
                "Shutdown drain timed out, aborted remaining SSH connections"
            );
        }
    }
}

/// Handle a single SSH agent connection whose peer has been verified.
async fn handle_ssh_connection(
    conn: AuthorizedStream,
    state: Arc<SshAgentState>,
    agent_state: Option<Arc<crate::state::AgentState>>,
) -> Result<()> {
    let mut stream = conn.into_stream();
    loop {
        // Read length-prefixed message, bounding how long an idle or
        // stalled client can hold this connection task open.
        let buf = match wire::read_message_timeout(&mut stream, wire::IDLE_READ_TIMEOUT).await? {
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
            SSH_AGENTC_SIGN_REQUEST => handle_sign_request(&buf, &state).await,
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

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::state::AgentState;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::watch;

    /// Build an `SshAgentServer` backed by a temp-dir listener.
    fn make_server(shutdown_rx: watch::Receiver<bool>) -> Arc<SshAgentServer> {
        Arc::new(SshAgentServer::with_agent_state(
            SshAgentState::new(),
            AgentState::new(),
            shutdown_rx,
        ))
    }

    /// End-to-end over a real socket: a same-UID client passes
    /// `accept_authorized` and gets an identities reply, proving the peer
    /// check does not break the happy path.
    #[tokio::test]
    async fn same_uid_client_gets_identities_reply() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ssh-agent-test.sock");
        let listener = bind_socket(&path).await.expect("bind socket");
        let state = SshAgentState::new();

        let server = tokio::spawn(async move {
            if let Some(conn) = accept_authorized(&listener, SocketKind::SshAgent).await {
                let _connection = handle_ssh_connection(conn, state, None).await;
            }
        });

        let mut client = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connect to socket");
        wire::write_message(&mut client, &[SSH_AGENTC_REQUEST_IDENTITIES])
            .await
            .expect("write request");
        let reply = wire::read_message(&mut client)
            .await
            .expect("read reply")
            .expect("reply present");
        assert!(!reply.is_empty(), "expected an identities answer");

        drop(client);
        server.abort();
    }

    /// The SSH agent accept loop breaks and `run_listener` returns `Ok(())`
    /// when the shutdown watch channel is signaled.
    #[tokio::test]
    async fn run_listener_stops_on_shutdown() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("ssh-shutdown.sock");
        let listener = bind_socket(&path).await.expect("bind");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = make_server(shutdown_rx);
        let server_clone = Arc::clone(&server);
        let task = tokio::spawn(async move { server_clone.run_listener(listener).await });

        tokio::time::sleep(Duration::from_millis(50)).await;

        shutdown_tx.send(true).expect("send shutdown");

        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("run_listener should return within 5s")
            .expect("task should not panic");
        assert!(result.is_ok(), "run_listener should return Ok");
    }

    /// An in-flight SSH agent request completes even when shutdown arrives
    /// immediately after the request is written.
    #[tokio::test]
    async fn inflight_request_completes_on_shutdown() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("ssh-drain.sock");
        let listener = bind_socket(&path).await.expect("bind");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = make_server(shutdown_rx);
        let server_clone = Arc::clone(&server);
        let task = tokio::spawn(async move { server_clone.run_listener(listener).await });

        // Connect and verify the server is accepting and processing.
        let mut client = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connect");
        wire::write_message(&mut client, &[SSH_AGENTC_REQUEST_IDENTITIES])
            .await
            .expect("write first request");
        let reply = wire::read_message(&mut client)
            .await
            .expect("read first reply")
            .expect("reply present");
        assert!(!reply.is_empty(), "expected an identities answer");

        // Send a second request and immediately signal shutdown.
        wire::write_message(&mut client, &[SSH_AGENTC_REQUEST_IDENTITIES])
            .await
            .expect("write second request");
        shutdown_tx.send(true).expect("send shutdown");

        // The in-flight response should still arrive during drain.
        let reply = tokio::time::timeout(Duration::from_secs(10), wire::read_message(&mut client))
            .await
            .expect("reply should arrive within 10 s")
            .expect("read second reply")
            .expect("reply present");
        assert!(!reply.is_empty(), "expected an identities answer");

        drop(client);

        let result = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("run_listener should return within 10s")
            .expect("task should not panic");
        assert!(result.is_ok(), "run_listener should return Ok");
    }
}
