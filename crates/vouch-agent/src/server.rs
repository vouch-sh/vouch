//! Agent server with Unix socket listener.

use crate::error::{AgentError, Result};
use crate::protocol::{
    INVALID_PARAMS, METHOD_NOT_FOUND, NOT_AUTHENTICATED, Request, Response, SESSION_EXPIRED,
    StoreSessionParams,
};
use crate::socket::{ensure_vouch_dir, remove_socket, socket_path};
use crate::state::{AgentState, Session, SessionInfo};

use jiff::Timestamp;
use secrecy::SecretString;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

/// Agent server.
pub struct AgentServer {
    state: Arc<AgentState>,
}

impl AgentServer {
    /// Create a new agent server.
    pub fn new(state: Arc<AgentState>) -> Self {
        Self { state }
    }

    /// Run the server, listening on the Unix socket.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::SocketPath` if the socket cannot be created.
    pub async fn run(&self) -> Result<()> {
        // Ensure vouch directory exists
        ensure_vouch_dir()?;

        // Remove stale socket if it exists
        remove_socket()?;

        let path = socket_path()?;
        let listener = UnixListener::bind(&path).map_err(|e| {
            AgentError::SocketPath(format!("failed to bind to {}: {e}", path.display()))
        })?;

        // Set socket permissions to 0600 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms).map_err(|e| {
                AgentError::SocketPath(format!(
                    "failed to set permissions on {}: {e}",
                    path.display()
                ))
            })?;
        }

        info!("Agent listening on {}", path.display());

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, state).await {
                            debug!("Connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {e}");
                }
            }
        }
    }
}

/// Handle a single client connection.
async fn handle_connection(mut stream: UnixStream, state: Arc<AgentState>) -> Result<()> {
    loop {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client disconnected
                return Ok(());
            }
            Err(e) => return Err(AgentError::Connection(e)),
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 1024 * 1024 {
            // Reject messages larger than 1MB
            warn!("Message too large: {len} bytes");
            return Err(AgentError::Protocol("message too large".to_string()));
        }

        // Read message body
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        // Parse request
        let request: Request = match serde_json::from_slice(&buf) {
            Ok(req) => req,
            Err(e) => {
                warn!("Invalid request: {e}");
                let response = Response::error(0, crate::protocol::PARSE_ERROR, "parse error");
                send_response(&mut stream, &response).await?;
                continue;
            }
        };

        debug!("Request: method={}", request.method);

        // Handle request
        let response = handle_request(&request, &state).await;
        send_response(&mut stream, &response).await?;
    }
}

/// Handle a JSON-RPC request.
async fn handle_request(request: &Request, state: &Arc<AgentState>) -> Response {
    match request.method.as_str() {
        "ping" => handle_ping(request),
        "get_session" => handle_get_session(request, state).await,
        "store_session" => handle_store_session(request, state).await,
        "clear_session" => handle_clear_session(request, state).await,
        "get_token" => handle_get_token(request, state).await,
        _ => Response::error(request.id, METHOD_NOT_FOUND, "method not found"),
    }
}

/// Handle ping request (health check).
fn handle_ping(request: &Request) -> Response {
    Response::success(request.id, "pong")
}

/// Handle `get_session` request.
async fn handle_get_session(request: &Request, state: &Arc<AgentState>) -> Response {
    match state.get_session().await {
        Some(session) => {
            if session.is_expired() {
                Response::error(request.id, SESSION_EXPIRED, "session expired")
            } else {
                let info = SessionInfo::from(&session);
                Response::success(request.id, info)
            }
        }
        None => Response::error(request.id, NOT_AUTHENTICATED, "not authenticated"),
    }
}

/// Handle `store_session` request.
async fn handle_store_session(request: &Request, state: &Arc<AgentState>) -> Response {
    let params: StoreSessionParams = match &request.params {
        Some(p) => match serde_json::from_value(p.clone()) {
            Ok(params) => params,
            Err(e) => {
                return Response::error(
                    request.id,
                    INVALID_PARAMS,
                    &format!("invalid params: {e}"),
                );
            }
        },
        None => return Response::error(request.id, INVALID_PARAMS, "missing params"),
    };

    // Parse expiration timestamp
    let expires_at: Timestamp = match params.expires_at.parse() {
        Ok(ts) => ts,
        Err(e) => {
            return Response::error(
                request.id,
                INVALID_PARAMS,
                &format!("invalid expires_at: {e}"),
            );
        }
    };

    let session = Session::new(
        SecretString::from(params.token),
        params.user_email,
        expires_at,
    );

    state.store_session(session).await;
    info!("Session stored");

    Response::success(request.id, true)
}

/// Handle `clear_session` request.
async fn handle_clear_session(request: &Request, state: &Arc<AgentState>) -> Response {
    state.clear_session().await;
    info!("Session cleared");
    Response::success(request.id, true)
}

/// Handle `get_token` request.
async fn handle_get_token(request: &Request, state: &Arc<AgentState>) -> Response {
    match state.get_token().await {
        Some(token) => Response::success(request.id, token),
        None => Response::error(request.id, NOT_AUTHENTICATED, "not authenticated"),
    }
}

/// Send a response over the stream.
async fn send_response(stream: &mut UnixStream, response: &Response) -> Result<()> {
    let json = serde_json::to_vec(response)?;
    #[allow(clippy::cast_possible_truncation)]
    let len = (json.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&json).await?;
    Ok(())
}

impl Drop for AgentServer {
    fn drop(&mut self) {
        // Clean up socket on drop
        let _ = remove_socket();
    }
}
