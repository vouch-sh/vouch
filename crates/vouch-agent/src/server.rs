// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent server with Unix socket listener.

use crate::audit::{self, AuditEvent};
use crate::error::Result;
use crate::protocol::{
    CacheCredentialParams, GetCachedCredentialParams, JSONRPC_VERSION, Method, Request, Response,
    StoreSessionParams, StoreSshCredentialsParams,
};
use crate::socket::{AuthorizedStream, SocketKind, accept_authorized, bind_socket, socket_path};
use crate::ssh_agent::{SshAgentState, SshCredentials};
use crate::state::{AgentState, CachedCredential, Session, SessionInfo};
use crate::wire;
use serde::de::DeserializeOwned;

use jiff::Timestamp;
use secrecy::ExposeSecret;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent IPC connections.
const MAX_CONNECTIONS: usize = 64;

/// Maximum time to wait for in-flight connections to finish during shutdown
/// before aborting them.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Grace window for a request already in flight when shutdown is signalled.
///
/// Bounds how long an otherwise-idle connection delays shutdown, so stopping
/// the agent costs this rather than [`SHUTDOWN_DRAIN_TIMEOUT`] per connection.
const SHUTDOWN_READ_GRACE: Duration = Duration::from_millis(250);

/// Agent server with graceful shutdown support.
pub struct AgentServer {
    state: Arc<AgentState>,
    ssh_state: Arc<SshAgentState>,
    shutdown_rx: watch::Receiver<bool>,
}

impl AgentServer {
    /// Create a new agent server with a shutdown signal.
    pub fn new(
        state: Arc<AgentState>,
        ssh_state: Arc<SshAgentState>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Self {
        Self {
            state,
            ssh_state,
            shutdown_rx,
        }
    }

    /// Run the server, listening on the Unix socket.
    ///
    /// Stops accepting new connections when the shutdown signal is received.
    /// In-flight connections continue until they complete naturally or the
    /// drain timeout expires.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::SocketPath` if the socket cannot be created.
    pub async fn run(&self) -> Result<()> {
        // The runtime directory is prepared (validated + 0700) once at
        // startup in main, before either listener binds into it.
        let path = socket_path()?;
        let listener = bind_socket(&path).await?;

        info!("Agent listening on {}", path.display());

        // Surface the insecure-URL override at boot, not just when an insecure
        // URL is actually stored — a set-but-unused flag is still a misconfiguration.
        if std::env::var_os("VOUCH_ALLOW_INSECURE").is_some() {
            warn!(
                "VOUCH_ALLOW_INSECURE is set: insecure (plain HTTP) server URLs will be accepted. Do not use in production."
            );
        }

        self.run_listener(listener).await
    }

    /// Accept loop and graceful-drain core, separated from [`run`](Self::run)
    /// so tests can drive it against a temporary listener without touching
    /// `XDG_RUNTIME_DIR`.
    async fn run_listener(&self, listener: UnixListener) -> Result<()> {
        let mut shutdown = self.shutdown_rx.clone();
        let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut tasks: JoinSet<()> = JoinSet::new();

        loop {
            tokio::select! {
                conn = accept_authorized(&listener, SocketKind::Ipc) => {
                    let Some(conn) = conn else { continue };
                    let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!("Connection limit reached ({MAX_CONNECTIONS}), rejecting");
                            continue;
                        }
                    };
                    let state = Arc::clone(&self.state);
                    let ssh_state = Arc::clone(&self.ssh_state);
                    let conn_shutdown = self.shutdown_rx.clone();
                    tasks.spawn(async move {
                        // Hold the permit for the full connection task; it auto-releases on drop.
                        let _permit = permit;
                        if let Err(e) = handle_connection(conn, state, ssh_state, conn_shutdown).await
                        {
                            debug!("Connection error: {e}");
                        }
                    });
                }
                // Reap finished tasks so the set does not grow for the life of
                // the daemon. The guard keeps an empty set from busy-looping,
                // since `join_next` on an empty JoinSet returns immediately.
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                _ = shutdown.changed() => {
                    info!("Agent received shutdown signal, stopping listener");
                    break;
                }
            }
        }

        drain_connections(&mut tasks).await;

        Ok(())
    }
}

/// Intermediate request type for wire deserialization.
///
/// Keeps `method` as a raw string so we can distinguish "valid JSON but unknown
/// method" (→ `method_not_found`) from "malformed JSON" (→ `parse_error`).
#[derive(serde::Deserialize)]
struct RawRequest {
    #[expect(
        dead_code,
        reason = "deserialized for JSON-RPC 2.0 conformance, value not consumed"
    )]
    jsonrpc: String,
    id: u64,
    method: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
}

/// Handle a single client connection whose peer has been verified.
async fn handle_connection(
    conn: AuthorizedStream,
    state: Arc<AgentState>,
    ssh_state: Arc<SshAgentState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut stream = conn.into_stream();
    loop {
        // Read length-prefixed message, bounding how long an idle or
        // stalled client can hold this connection task open.
        //
        // Shutdown is only honoured here, between requests. A request already
        // being served runs to completion; a connection merely parked waiting
        // for the next one closes immediately, so stopping the agent does not
        // wait out the drain timeout for every idle ssh session.
        let buf = tokio::select! {
            // Biased: poll the read first so a request that has already
            // arrived is served even if shutdown fires in the same tick.
            // Unbiased selection picks randomly between ready branches and
            // would drop such a request.
            biased;
            read = wire::read_message_timeout(&mut stream, wire::IDLE_READ_TIMEOUT) => {
                match read? {
                    Some(buf) => Some(buf),
                    None => return Ok(()), // Client disconnected
                }
            }
            // `None` signals shutdown. The grace read must happen outside the
            // select: `wait_for` yields a borrow guard that is not `Send`, and
            // holding it across an await would make this task unspawnable.
            _ = shutdown.wait_for(|&stop| stop) => None,
        };

        let buf = match buf {
            Some(buf) => buf,
            None => {
                // A request the client has already written may not have reached
                // the reactor yet — signalling the watch channel wakes this task
                // synchronously, ahead of the I/O readiness event — so poll once
                // more with a short grace window instead of dropping it.
                debug!("Shutdown signalled while connection idle");
                match wire::read_message_timeout(&mut stream, SHUTDOWN_READ_GRACE).await {
                    Ok(Some(buf)) => buf,
                    // Clean disconnect, grace expired, or a malformed final
                    // message: the connection is closing regardless.
                    Ok(None) | Err(_) => return Ok(()),
                }
            }
        };

        // Parse as RawRequest first to separate parse errors from unknown methods
        let raw: RawRequest = match serde_json::from_slice(&buf) {
            Ok(req) => req,
            Err(e) => {
                warn!("Invalid request: {e}");
                let response = Response::error(0, crate::protocol::PARSE_ERROR, "parse error");
                send_response(&mut stream, &response).await?;
                continue;
            }
        };

        // Try to resolve the method string into a known Method variant
        let method: Method =
            match serde_json::from_value(serde_json::Value::String(raw.method.clone())) {
                Ok(m) => m,
                Err(_) => {
                    warn!("Unknown method: {}", raw.method);
                    let response = Response::method_not_found(raw.id);
                    send_response(&mut stream, &response).await?;
                    continue;
                }
            };

        let request = Request {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: raw.id,
            method,
            params: raw.params,
        };

        debug!("Request: method={:?}", request.method);

        // Handle request
        let response = handle_request(&request, &state, &ssh_state).await;
        send_response(&mut stream, &response).await?;
    }
}

/// Convert a `Response::success()` result to a `Response`, falling back to
/// an internal error if serialization fails.
fn success_or_internal_error(
    id: u64,
    result: std::result::Result<Response, serde_json::Error>,
) -> Response {
    result.unwrap_or_else(|e| {
        error!("Failed to serialize response: {e}");
        Response::error(id, crate::protocol::INTERNAL_ERROR, "serialization failed")
    })
}

/// Handle a JSON-RPC request.
async fn handle_request(
    request: &Request,
    state: &Arc<AgentState>,
    ssh_state: &Arc<SshAgentState>,
) -> Response {
    match request.method {
        Method::Ping => handle_ping(request),
        Method::GetSession => handle_get_session(request, state, ssh_state).await,
        Method::StoreSession => handle_store_session(request, state, ssh_state).await,
        Method::ClearSession => handle_clear_session(request, state, ssh_state).await,
        Method::GetToken => handle_get_token(request, state).await,
        Method::StoreSshCredentials => handle_store_ssh_credentials(request, ssh_state).await,
        Method::ClearSshCredentials => handle_clear_ssh_credentials(request, ssh_state).await,
        Method::HasSshCredentials => handle_has_ssh_credentials(request, ssh_state).await,
        Method::CacheCredential => handle_cache_credential(request, state).await,
        Method::GetCachedCredential => handle_get_cached_credential(request, state).await,
        Method::ClearCredentialCache => handle_clear_credential_cache(request, state).await,
    }
}

/// Extract and deserialize parameters from a JSON-RPC request.
///
/// Returns the error `Response` directly so callers can return it to the client.
fn extract_params<T: DeserializeOwned>(request: &Request) -> Option<T> {
    let value = request.params.as_ref()?;
    serde_json::from_value(value.clone()).ok()
}

/// Handle ping request (health check).
fn handle_ping(request: &Request) -> Response {
    success_or_internal_error(request.id, Response::success(request.id, "pong"))
}

/// Handle `get_session` request.
async fn handle_get_session(
    request: &Request,
    state: &Arc<AgentState>,
    ssh_state: &Arc<SshAgentState>,
) -> Response {
    // `get_session()` already filters out expired sessions (returns None).
    match state.get_session().await {
        Some(session) => {
            let mut info = SessionInfo::from(&session);
            info.server_url = ssh_state.get_server_url().await;
            success_or_internal_error(request.id, Response::success(request.id, info))
        }
        None => Response::not_authenticated(request.id),
    }
}

/// Handle `store_session` request.
async fn handle_store_session(
    request: &Request,
    state: &Arc<AgentState>,
    ssh_state: &Arc<SshAgentState>,
) -> Response {
    let Some(params): Option<StoreSessionParams> = extract_params(request) else {
        return Response::invalid_params(request.id, "missing or invalid params");
    };

    // Parse expiration timestamp
    let expires_at: Timestamp = match params.expires_at.parse() {
        Ok(ts) => ts,
        Err(e) => return Response::invalid_params(request.id, &format!("invalid expires_at: {e}")),
    };

    let user_email = params.user_email;
    let session = Session::new(params.token, user_email.clone(), expires_at);

    state.store_session(session).await;

    // Store server URL in SSH agent state for lazy provisioning/refresh
    if let Some(url) = params.server_url {
        // Validate: must be a valid URL; reject insecure HTTP for non-localhost
        if let Ok(parsed) = url::Url::parse(&url) {
            if parsed.scheme() == "https" || parsed.scheme() == "http" {
                match vouch_common::check_url_security(&url) {
                    vouch_common::UrlSecurity::Secure => {
                        ssh_state.set_server_url(url).await;
                    }
                    vouch_common::UrlSecurity::InsecureHttp { url: insecure_url } => {
                        if std::env::var("VOUCH_ALLOW_INSECURE").is_ok() {
                            warn!(
                                "Using insecure HTTP server URL: {insecure_url}. VOUCH_ALLOW_INSECURE is set."
                            );
                            ssh_state.set_server_url(url).await;
                        } else {
                            warn!(
                                "Rejecting insecure HTTP server URL: {insecure_url}. Set VOUCH_ALLOW_INSECURE=1 to override."
                            );
                        }
                    }
                }
            } else {
                debug!(
                    "Ignoring server_url with unsupported scheme: {}",
                    parsed.scheme()
                );
            }
        } else {
            debug!("Ignoring invalid server_url");
        }
    }

    info!("Session stored");
    audit::log_event(AuditEvent::SessionStored { email: user_email });

    success_or_internal_error(request.id, Response::success(request.id, true))
}

/// Handle `clear_session` request.
async fn handle_clear_session(
    request: &Request,
    state: &Arc<AgentState>,
    ssh_state: &Arc<SshAgentState>,
) -> Response {
    state.clear_session().await;
    ssh_state.clear_credentials().await;
    info!("Session and SSH credentials cleared");
    audit::log_event(AuditEvent::SessionCleared);
    success_or_internal_error(request.id, Response::success(request.id, true))
}

/// Handle `get_token` request.
async fn handle_get_token(request: &Request, state: &Arc<AgentState>) -> Response {
    match state.get_token().await {
        Some(token) => success_or_internal_error(
            request.id,
            Response::success(request.id, token.expose_secret()),
        ),
        None => Response::not_authenticated(request.id),
    }
}

/// Handle `store_ssh_credentials` request.
async fn handle_store_ssh_credentials(
    request: &Request,
    ssh_state: &Arc<SshAgentState>,
) -> Response {
    let Some(params): Option<StoreSshCredentialsParams> = extract_params(request) else {
        return Response::invalid_params(request.id, "missing or invalid params");
    };

    // Load credentials from files
    let key_path = std::path::Path::new(&params.key_path);
    let cert_path = std::path::Path::new(&params.cert_path);

    match SshCredentials::load(key_path, cert_path) {
        Ok(creds) => {
            // Parse session expiration if provided
            let session_expires_at = params
                .session_expires_at
                .as_ref()
                .and_then(|s| s.parse::<Timestamp>().ok());

            // Store credentials with session linkage
            ssh_state
                .store_credentials(creds, session_expires_at, params.server_url)
                .await;

            info!("SSH credentials stored with session linkage");
            audit::log_event(AuditEvent::SshCertProvisioned {
                key_path: params.key_path,
                cert_path: params.cert_path,
            });
            success_or_internal_error(request.id, Response::success(request.id, true))
        }
        Err(e) => {
            warn!("Failed to load SSH credentials: {e}");
            Response::invalid_params(request.id, &format!("failed to load credentials: {e}"))
        }
    }
}

/// Handle `clear_ssh_credentials` request.
async fn handle_clear_ssh_credentials(
    request: &Request,
    ssh_state: &Arc<SshAgentState>,
) -> Response {
    ssh_state.clear_credentials().await;
    info!("SSH credentials cleared");
    success_or_internal_error(request.id, Response::success(request.id, true))
}

/// Handle `has_ssh_credentials` request.
async fn handle_has_ssh_credentials(request: &Request, ssh_state: &Arc<SshAgentState>) -> Response {
    let has_creds = ssh_state.has_credentials().await;
    success_or_internal_error(request.id, Response::success(request.id, has_creds))
}

/// Handle `cache_credential` request.
async fn handle_cache_credential(request: &Request, state: &Arc<AgentState>) -> Response {
    let Some(params): Option<CacheCredentialParams> = extract_params(request) else {
        return Response::invalid_params(request.id, "missing or invalid params");
    };

    // Parse expiration timestamp
    let expires_at: Timestamp = match params.expires_at.parse() {
        Ok(ts) => ts,
        Err(e) => return Response::invalid_params(request.id, &format!("invalid expires_at: {e}")),
    };

    let credential = CachedCredential::new(params.data, expires_at);
    let credential_type = params.credential_type;

    state
        .cache_credential(credential_type.clone(), credential)
        .await;

    info!("Cached credential: {credential_type}");
    audit::log_event(AuditEvent::CredentialCached { credential_type });
    success_or_internal_error(request.id, Response::success(request.id, true))
}

/// Handle `get_cached_credential` request.
async fn handle_get_cached_credential(request: &Request, state: &Arc<AgentState>) -> Response {
    let Some(params): Option<GetCachedCredentialParams> = extract_params(request) else {
        return Response::invalid_params(request.id, "missing or invalid params");
    };

    match state.get_cached_credential(&params.credential_type).await {
        Some(credential) => {
            success_or_internal_error(request.id, Response::success(request.id, credential))
        }
        None => Response::cache_miss(request.id),
    }
}

/// Handle `clear_credential_cache` request.
async fn handle_clear_credential_cache(request: &Request, state: &Arc<AgentState>) -> Response {
    state.clear_credential_cache().await;
    info!("Credential cache cleared");
    audit::log_event(AuditEvent::CredentialCacheCleared);
    success_or_internal_error(request.id, Response::success(request.id, true))
}

/// Send a response over the stream.
async fn send_response(stream: &mut UnixStream, response: &Response) -> Result<()> {
    let json = serde_json::to_vec(response)?;
    wire::write_message(stream, &json).await
}

/// Wait for in-flight connection tasks to finish, aborting any that do not
/// complete within [`SHUTDOWN_DRAIN_TIMEOUT`].
async fn drain_connections(tasks: &mut JoinSet<()>) {
    if tasks.is_empty() {
        return;
    }
    info!(
        count = tasks.len(),
        "Waiting for in-flight connections to complete"
    );
    let drain = async { while tasks.join_next().await.is_some() {} };
    match tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, drain).await {
        Ok(()) => info!("All in-flight connections completed gracefully"),
        Err(_) => {
            let remaining = tasks.len();
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            warn!(
                count = remaining,
                "Shutdown drain timed out, aborted remaining connections"
            );
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::ssh_agent::SshAgentState;
    use crate::state::AgentState;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::sync::watch;

    /// Build an `AgentServer` backed by a temp-dir listener.
    fn make_server(shutdown_rx: watch::Receiver<bool>) -> Arc<AgentServer> {
        Arc::new(AgentServer::new(
            AgentState::new(),
            SshAgentState::new(),
            shutdown_rx,
        ))
    }

    /// Helper: encode a JSON-RPC ping as a length-prefixed wire message.
    fn encode_ping() -> Vec<u8> {
        let payload = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
        let mut buf = Vec::with_capacity(payload.len().saturating_add(4));
        buf.extend_from_slice(&len);
        buf.extend_from_slice(payload);
        buf
    }

    /// Helper: read one length-prefixed JSON-RPC response from the stream.
    async fn read_jsonrpc_response(stream: &mut UnixStream) -> serde_json::Value {
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .expect("response length");
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .await
            .expect("response body");
        serde_json::from_slice(&resp_buf).expect("valid JSON response")
    }

    /// The accept loop breaks and `run_listener` returns `Ok(())` as soon as
    /// the shutdown watch channel is signaled — proving the
    /// `shutdown.changed()` branch is reachable.
    #[tokio::test]
    async fn run_listener_stops_on_shutdown() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test-listener.sock");
        let listener = bind_socket(&path).await.expect("bind");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = make_server(shutdown_rx);
        let server = Arc::clone(&server);
        let task = tokio::spawn(async move { server.run_listener(listener).await });

        // Give the listener a moment to enter the accept loop.
        tokio::time::sleep(Duration::from_millis(50)).await;

        shutdown_tx.send(true).expect("send shutdown");

        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("run_listener should return within 5s")
            .expect("task should not panic");
        assert!(result.is_ok(), "run_listener should return Ok");
    }

    /// An in-flight ping request completes even when the shutdown signal
    /// arrives immediately after the request is written — proving the drain
    /// phase lets connections finish naturally.
    #[tokio::test]
    async fn inflight_request_completes_on_shutdown() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test-drain.sock");
        let listener = bind_socket(&path).await.expect("bind");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = make_server(shutdown_rx);
        let server_clone = Arc::clone(&server);
        let task = tokio::spawn(async move { server_clone.run_listener(listener).await });

        // Connect and verify the server is accepting and processing.
        let mut client = UnixStream::connect(&path).await.expect("connect");
        client
            .write_all(&encode_ping())
            .await
            .expect("write first ping");
        let resp = read_jsonrpc_response(&mut client).await;
        assert_eq!(resp.get("result"), Some(&serde_json::json!("pong")));

        // Send a second ping and immediately signal shutdown — the request
        // is now genuinely in-flight on an already-accepted connection.
        client
            .write_all(&encode_ping())
            .await
            .expect("write second ping");
        shutdown_tx.send(true).expect("send shutdown");

        // The in-flight response should still arrive during the drain phase.
        let resp =
            tokio::time::timeout(Duration::from_secs(10), read_jsonrpc_response(&mut client))
                .await
                .expect("response should arrive within 10 s");
        assert_eq!(resp.get("result"), Some(&serde_json::json!("pong")));

        // Disconnect so the handler exits promptly during drain.
        drop(client);

        let result = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("run_listener should return within 10s")
            .expect("task should not panic");
        assert!(result.is_ok(), "run_listener should return Ok");
    }

    /// A connection parked waiting for its next request closes as soon as
    /// shutdown is signalled, instead of being waited out for the full drain
    /// timeout and then aborted. This is the common case: clients hold the
    /// socket open between requests, so without it every agent stop would
    /// stall for [`SHUTDOWN_DRAIN_TIMEOUT`].
    #[tokio::test]
    async fn idle_connection_closes_promptly_on_shutdown() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test-idle.sock");
        let listener = bind_socket(&path).await.expect("bind");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = make_server(shutdown_rx);
        let server_clone = Arc::clone(&server);
        let task = tokio::spawn(async move { server_clone.run_listener(listener).await });

        // Establish the connection and complete one request, so the handler is
        // parked on the read for the *next* request.
        let mut client = UnixStream::connect(&path).await.expect("connect");
        client.write_all(&encode_ping()).await.expect("write ping");
        let resp = read_jsonrpc_response(&mut client).await;
        assert_eq!(resp.get("result"), Some(&serde_json::json!("pong")));

        // Hold the connection open and idle. The client never disconnects, so
        // the only thing that can end the handler task is the shutdown signal.
        let start = std::time::Instant::now();
        shutdown_tx.send(true).expect("send shutdown");

        let result = tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, task)
            .await
            .expect("run_listener must return before the drain timeout")
            .expect("task should not panic");
        assert!(result.is_ok(), "run_listener should return Ok");

        let elapsed = start.elapsed();
        assert!(
            elapsed < SHUTDOWN_DRAIN_TIMEOUT / 2,
            "idle connection should close promptly, took {elapsed:?}"
        );

        drop(client);
    }

    /// The drain helper finishes quickly when all tasks have already
    /// completed.
    #[tokio::test]
    async fn drain_returns_quickly_when_tasks_done() {
        let mut tasks: JoinSet<()> = JoinSet::new();
        // Spawn two tasks that complete immediately.
        tasks.spawn(async {});
        tasks.spawn(async {});
        drain_connections(&mut tasks).await;
        assert!(tasks.is_empty());
    }

    /// The drain helper aborts tasks that do not finish within the timeout.
    #[tokio::test]
    async fn drain_aborts_unresponsive_tasks() {
        let mut tasks: JoinSet<()> = JoinSet::new();
        // A task that never completes.
        tasks.spawn(async { std::future::pending::<()>().await });

        let start = std::time::Instant::now();
        drain_connections(&mut tasks).await;
        let elapsed = start.elapsed();

        assert!(tasks.is_empty(), "task should have been aborted");
        assert!(
            elapsed >= SHUTDOWN_DRAIN_TIMEOUT,
            "drain should have waited for the timeout"
        );
    }
}
