// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent server with Unix socket listener.

use crate::audit::{self, AuditEvent};
use crate::error::Result;
use crate::protocol::{
    CacheCredentialParams, GetCachedCredentialParams, INTERNAL_ERROR, JSONRPC_VERSION, Method,
    PARSE_ERROR, Request, Response, StoreSessionParams, StoreSshCredentialsParams,
};
use crate::socket::{AuthorizedStream, SocketKind, accept_authorized, bind_socket, socket_path};
use crate::ssh_agent::SshCredentials;
use crate::state::{
    AgentState, CacheRefusal, CachedCredential, Session, SessionInfo, SshStoreRefusal,
};
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
use vouch_common::UrlSecurity;

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
    shutdown_rx: watch::Receiver<bool>,
}

impl AgentServer {
    /// Create a new agent server with a shutdown signal.
    pub fn new(state: Arc<AgentState>, shutdown_rx: watch::Receiver<bool>) -> Self {
        Self { state, shutdown_rx }
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
        if allow_insecure() {
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
                    let conn_shutdown = self.shutdown_rx.clone();
                    tasks.spawn(async move {
                        // Hold the permit for the full connection task; it auto-releases on drop.
                        let _permit = permit;
                        if let Err(e) = handle_connection(conn, state, conn_shutdown).await
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
                let response = Response::error(0, PARSE_ERROR, "parse error");
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
        let response = handle_request(&request, &state).await;
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
        Response::error(id, INTERNAL_ERROR, "serialization failed")
    })
}

/// Handle a JSON-RPC request.
async fn handle_request(request: &Request, state: &Arc<AgentState>) -> Response {
    match request.method {
        Method::Ping => handle_ping(request),
        Method::GetSession => handle_get_session(request, state).await,
        Method::StoreSession => handle_store_session(request, state).await,
        Method::ClearSession => handle_clear_session(request, state).await,
        Method::GetToken => handle_get_token(request, state).await,
        Method::StoreSshCredentials => handle_store_ssh_credentials(request, state).await,
        Method::ClearSshCredentials => handle_clear_ssh_credentials(request, state).await,
        Method::HasSshCredentials => handle_has_ssh_credentials(request, state).await,
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
async fn handle_get_session(request: &Request, state: &Arc<AgentState>) -> Response {
    // `get_session()` already filters out expired sessions (returns None).
    match state.get_session().await {
        Some(session) => {
            let mut info = SessionInfo::from(&session);
            info.server_url = state.get_server_url().await;
            success_or_internal_error(request.id, Response::success(request.id, info))
        }
        None => Response::not_authenticated(request.id),
    }
}

/// Whether `VOUCH_ALLOW_INSECURE` allows plain-HTTP server URLs, read with
/// the parser the CLI uses. An unrecognized value is reported and refused.
pub(crate) fn allow_insecure() -> bool {
    vouch_common::allow_insecure_from_env().unwrap_or_else(|e| {
        warn!("{e}; treating it as off");
        false
    })
}

/// Handle `store_session` request.
async fn handle_store_session(request: &Request, state: &Arc<AgentState>) -> Response {
    let Some(params): Option<StoreSessionParams> = extract_params(request) else {
        return Response::invalid_params(request.id, "missing or invalid params");
    };

    // Parse expiration timestamp
    let expires_at: Timestamp = match params.expires_at.parse() {
        Ok(ts) => ts,
        Err(e) => return Response::invalid_params(request.id, &format!("invalid expires_at: {e}")),
    };

    // The server URL is judged before anything is stored: a session is kept
    // only together with its own server, never beside a previous session's.
    let server_url = match params.server_url {
        Some(url) => match url::Url::parse(&url) {
            Ok(parsed) if parsed.scheme() == "https" || parsed.scheme() == "http" => {
                match vouch_common::check_url_security(&url) {
                    UrlSecurity::Secure => Some(url),
                    UrlSecurity::InsecureHttp { url: insecure_url } => {
                        if allow_insecure() {
                            warn!(
                                "Using insecure HTTP server URL: {insecure_url}. VOUCH_ALLOW_INSECURE is set."
                            );
                            Some(url)
                        } else {
                            // The caller logged in elsewhere, so the previous
                            // session is no longer the current one either.
                            state.clear_session().await;
                            warn!(
                                "Rejecting insecure HTTP server URL: {insecure_url}. Set VOUCH_ALLOW_INSECURE=1 to override."
                            );
                            return Response::invalid_params(
                                request.id,
                                &format!(
                                    "insecure HTTP server URL {insecure_url} refused; set \
                                     VOUCH_ALLOW_INSECURE=1 for the agent to allow it"
                                ),
                            );
                        }
                    }
                }
            }
            Ok(parsed) => {
                debug!(
                    "Ignoring server_url with unsupported scheme: {}",
                    parsed.scheme()
                );
                None
            }
            Err(_) => {
                debug!("Ignoring invalid server_url");
                None
            }
        },
        None => None,
    };

    let user_email = params.user_email;
    let session = Session::new(params.token, user_email.clone(), expires_at);
    state.store_session(session, server_url).await;

    info!("Session stored");
    audit::log_event(AuditEvent::SessionStored { email: user_email });

    success_or_internal_error(request.id, Response::success(request.id, true))
}

/// Handle `clear_session` request.
async fn handle_clear_session(request: &Request, state: &Arc<AgentState>) -> Response {
    state.clear_session().await;
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
async fn handle_store_ssh_credentials(request: &Request, state: &Arc<AgentState>) -> Response {
    let Some(params): Option<StoreSshCredentialsParams> = extract_params(request) else {
        return Response::invalid_params(request.id, "missing or invalid params");
    };

    // Load credentials from files
    let key_path = std::path::Path::new(&params.key_path);
    let cert_path = std::path::Path::new(&params.cert_path);

    match SshCredentials::load(key_path, cert_path) {
        Ok(creds) => {
            // Validity is gated on the live session, so the caller-supplied
            // expiry is no longer recorded, and the server URL is the
            // session's own, so the caller-supplied one is not either.
            match state.store_ssh_credentials(creds).await {
                Ok(()) => {}
                Err(SshStoreRefusal::NoSession) => {
                    return Response::error(request.id, INTERNAL_ERROR, "no active session");
                }
                Err(SshStoreRefusal::NotIssuedToSession) => {
                    return Response::invalid_params(
                        request.id,
                        "certificate was not issued to the current session",
                    );
                }
            }

            info!("SSH credentials stored");
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
async fn handle_clear_ssh_credentials(request: &Request, state: &Arc<AgentState>) -> Response {
    state.clear_ssh_credentials().await;
    info!("SSH credentials cleared");
    success_or_internal_error(request.id, Response::success(request.id, true))
}

/// Handle `has_ssh_credentials` request.
async fn handle_has_ssh_credentials(request: &Request, state: &Arc<AgentState>) -> Response {
    let has_creds = state.has_ssh_credentials().await;
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

    match state
        .cache_credential(credential_type.clone(), credential)
        .await
    {
        Ok(()) => {}
        // Oversized `credential_type` is a caller-supplied value rejected by an
        // input-length limit — invalid_params (-32602), not INTERNAL_ERROR.
        Err(CacheRefusal::KeyTooLong) => {
            return Response::invalid_params(request.id, "credential_type exceeds maximum length");
        }
        Err(CacheRefusal::NoSession) => return Response::not_authenticated(request.id),
    }

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
    use crate::protocol::{INVALID_PARAMS, NOT_AUTHENTICATED};
    use crate::state::AgentState;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::sync::watch;

    /// Serialises tests that mutate process environment variables. A
    /// `tokio::sync::Mutex` so it can be held across `.await` without
    /// tripping `await_holding_lock`.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Build an `AgentServer` backed by a temp-dir listener.
    fn make_server(shutdown_rx: watch::Receiver<bool>) -> Arc<AgentServer> {
        Arc::new(AgentServer::new(AgentState::new(), shutdown_rx))
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

        // The listener's receiver is a clone of the one handed to the server,
        // which has never observed a value, so a signal sent before the task
        // is first polled is still seen by `changed()`.
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

    /// An oversized `credential_type` is rejected by the state layer, so the
    /// IPC handler must surface it as an `invalid_params` (-32602) error and
    /// must not report success or cache anything. This is the IPC half of the
    /// fix: before it, the handler returned `{"result": true}` on rejection.
    #[tokio::test]
    async fn cache_credential_rejects_oversized_key_as_invalid_params() {
        let state = AgentState::new();

        let oversized_type = "x".repeat(257);
        let params = CacheCredentialParams {
            credential_type: oversized_type.clone(),
            data: serde_json::json!({"secret": "data"}),
            expires_at: Timestamp::now()
                .checked_add(jiff::Span::new().hours(1))
                .unwrap()
                .to_string(),
        };
        let request = Request {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: 42,
            method: Method::CacheCredential,
            params: Some(serde_json::to_value(&params).unwrap()),
        };

        let response = handle_request(&request, &state).await;

        let error = response
            .error
            .as_ref()
            .expect("oversized key should produce an error response");
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(
            response.result.is_none(),
            "rejected credential must not return a result"
        );
        assert!(
            state.get_cached_credential(&oversized_type).await.is_none(),
            "rejected credential must not be cached"
        );
    }

    /// The audit stream must agree with the actual cache state: a stored
    /// credential emits `CredentialCached`, while a rejected oversized key
    /// emits nothing. Before the fix the handler wrote `event:
    /// "credential_cached"` even when the state layer refused the entry.
    #[tokio::test]
    #[expect(
        unsafe_code,
        reason = "env mutation to redirect the audit log to a tempdir in an isolated test; the var is restored before assertions"
    )]
    async fn cache_credential_audit_reflects_caching_outcome() {
        let _guard = ENV_LOCK.lock().await;

        let dir = tempdir().expect("tempdir");
        let prior = std::env::var_os("XDG_STATE_HOME");
        // SAFETY: `ENV_LOCK` serialises this test against any other env
        // mutation in the test binary; the var is restored below, before any
        // assertion can panic, so a failing test cannot leak the redirect.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
        }

        let state = AgentState::new();
        state.store_session(live_session(), None).await;

        // Accepted key: handler returns success, caches, and audits.
        let valid_type = "aws:arn:aws:iam::123456789012:role/Example".to_string();
        let valid_params = CacheCredentialParams {
            credential_type: valid_type.clone(),
            data: serde_json::json!({"AccessKeyId": "AKIAEXAMPLE"}),
            expires_at: Timestamp::now()
                .checked_add(jiff::Span::new().hours(1))
                .unwrap()
                .to_string(),
        };
        let valid_request = Request {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: 1,
            method: Method::CacheCredential,
            params: Some(serde_json::to_value(&valid_params).unwrap()),
        };
        let valid_response = handle_request(&valid_request, &state).await;
        let valid_cached = state.get_cached_credential(&valid_type).await;

        // Rejected key: handler returns invalid_params, caches nothing, and
        // emits no audit event.
        let oversized_type = "x".repeat(257);
        let reject_params = CacheCredentialParams {
            credential_type: oversized_type.clone(),
            data: serde_json::json!({"secret": "data"}),
            expires_at: Timestamp::now()
                .checked_add(jiff::Span::new().hours(1))
                .unwrap()
                .to_string(),
        };
        let reject_request = Request {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: 2,
            method: Method::CacheCredential,
            params: Some(serde_json::to_value(&reject_params).unwrap()),
        };
        let reject_response = handle_request(&reject_request, &state).await;
        let reject_cached = state.get_cached_credential(&oversized_type).await;

        // Restore the env before asserting so a failing assertion cannot leak
        // the redirect into other tests.
        // SAFETY: the lock is still held; the prior value (if any) is restored.
        unsafe {
            match &prior {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
        }

        // Accepted path: success, cached, audited.
        assert!(valid_response.error.is_none(), "valid key should succeed");
        assert_eq!(valid_response.result, Some(serde_json::json!(true)));
        assert!(valid_cached.is_some(), "valid key should be cached");

        // Rejected path: invalid_params, not cached, not audited.
        let error = reject_response
            .error
            .as_ref()
            .expect("oversized key should produce an error response");
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(reject_response.result.is_none());
        assert!(reject_cached.is_none(), "oversized key must not be cached");

        // Audit discriminator must match reality: the accepted key is recorded
        // as cached; the rejected key is absent from the audit stream entirely.
        let audit_path = dir.path().join("vouch").join("audit.log");
        let audit_text =
            std::fs::read_to_string(&audit_path).expect("audit log should exist after a cache");
        assert!(
            audit_text.contains("\"event\":\"credential_cached\""),
            "accepted key should emit a credential_cached event: {audit_text}"
        );
        assert!(
            audit_text.contains(valid_type.as_str()),
            "audit log should record the accepted credential_type: {audit_text}"
        );
        assert!(
            !audit_text.contains(oversized_type.as_str()),
            "rejected key must not appear in the audit log as cached: {audit_text}"
        );
    }

    /// A session for `user@example.com` that expires in an hour.
    fn live_session() -> Session {
        Session::new(
            secrecy::SecretString::from("token"),
            "user@example.com".to_string(),
            Timestamp::now()
                .checked_add(jiff::Span::new().hours(1))
                .unwrap(),
        )
    }

    /// With no session there is no identity to bind a cache entry to, so the
    /// agent refuses it as unauthenticated and keeps nothing: an entry cached
    /// here would be served to whoever logs in next.
    #[tokio::test]
    async fn cache_credential_without_a_session_is_refused() {
        let state = AgentState::new();
        let params = CacheCredentialParams {
            credential_type: "aws:role".to_string(),
            data: serde_json::json!({"AccessKeyId": "AKIAEXAMPLE"}),
            expires_at: Timestamp::now()
                .checked_add(jiff::Span::new().hours(1))
                .unwrap()
                .to_string(),
        };
        let request = Request {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: 7,
            method: Method::CacheCredential,
            params: Some(serde_json::to_value(&params).unwrap()),
        };

        let response = handle_request(&request, &state).await;

        let error = response.error.expect("refused without a session");
        assert_eq!(error.code, NOT_AUTHENTICATED);
        state.store_session(live_session(), None).await;
        assert!(state.get_cached_credential("aws:role").await.is_none());
    }

    /// A `store_session` request for `token` with `server_url`.
    fn store_session_request(id: u64, token: &str, server_url: &str) -> Request {
        let params = StoreSessionParams {
            token: secrecy::SecretString::from(token),
            user_email: format!("{token}@example.com"),
            expires_at: Timestamp::now()
                .checked_add(jiff::Span::new().hours(1))
                .unwrap()
                .to_string(),
            server_url: Some(server_url.to_string()),
        };
        Request {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method: Method::StoreSession,
            params: Some(serde_json::to_value(&params).unwrap()),
        }
    }

    /// Set (or remove) the env vars the store_session tests read, returning
    /// the prior values to restore.
    #[expect(unsafe_code, reason = "test env mutation; callers hold ENV_LOCK")]
    fn set_env(
        vars: &[(&'static str, Option<&std::ffi::OsStr>)],
    ) -> Vec<(&'static str, Option<std::ffi::OsString>)> {
        let prior = vars
            .iter()
            .map(|(k, _)| (*k, std::env::var_os(k)))
            .collect();
        for (key, value) in vars {
            // SAFETY: callers hold ENV_LOCK, and restore the prior values
            // before asserting.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
        prior
    }

    fn restore_env(prior: Vec<(&'static str, Option<std::ffi::OsString>)>) {
        let prior: Vec<_> = prior.iter().map(|(k, v)| (*k, v.as_deref())).collect();
        set_env(&prior);
    }

    /// A session is stored only with its own server URL. When the agent
    /// refuses a plain-HTTP URL, the caller gets an error, no session is kept
    /// (so the new token cannot be paired with the previous session's server),
    /// and no `session_stored` event is written for it.
    #[tokio::test]
    async fn store_session_refused_url_keeps_no_session() {
        let _guard = ENV_LOCK.lock().await;
        let dir = tempdir().expect("tempdir");
        let prior = set_env(&[
            ("XDG_STATE_HOME", Some(dir.path().as_os_str())),
            ("VOUCH_ALLOW_INSECURE", None),
        ]);

        let state = AgentState::new();
        let prod = handle_request(
            &store_session_request(1, "prod", "https://prod.example.com"),
            &state,
        )
        .await;
        let prod_url = state.get_server_url().await;
        let dev = handle_request(
            &store_session_request(2, "dev", "http://dev.example.com"),
            &state,
        )
        .await;
        let session_after = state.get_session().await;
        let url_after = state.get_server_url().await;
        let audit_path = dir.path().join("vouch").join("audit.log");
        let audit_text = std::fs::read_to_string(&audit_path).unwrap_or_default();

        restore_env(prior);

        assert!(prod.error.is_none(), "an https URL is accepted: {prod:?}");
        assert_eq!(prod_url.as_deref(), Some("https://prod.example.com"));
        let error = dev
            .error
            .expect("a refused URL must be an error, not success");
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(
            session_after.is_none(),
            "no session is kept after the refusal"
        );
        assert!(
            url_after.is_none(),
            "no server URL is kept after the refusal"
        );
        assert_eq!(
            audit_text.matches("\"event\":\"session_stored\"").count(),
            1,
            "only the accepted session is audited: {audit_text}"
        );
    }

    /// `VOUCH_ALLOW_INSECURE` is read with the parser the CLI uses: `false` and
    /// `0` refuse a plain-HTTP URL, and `1` allows it.
    #[tokio::test]
    async fn store_session_reads_allow_insecure_values() {
        let _guard = ENV_LOCK.lock().await;
        let dir = tempdir().expect("tempdir");
        let mut outcomes = Vec::new();
        for value in ["false", "0", "1"] {
            let prior = set_env(&[
                ("XDG_STATE_HOME", Some(dir.path().as_os_str())),
                ("VOUCH_ALLOW_INSECURE", Some(std::ffi::OsStr::new(value))),
            ]);
            let state = AgentState::new();
            let response = handle_request(
                &store_session_request(1, "dev", "http://dev.example.com"),
                &state,
            )
            .await;
            let url = state.get_server_url().await;
            restore_env(prior);
            outcomes.push((value, response.error.is_none(), url));
        }

        assert_eq!(
            outcomes,
            vec![
                ("false", false, None),
                ("0", false, None),
                ("1", true, Some("http://dev.example.com".to_string())),
            ]
        );
    }
}
