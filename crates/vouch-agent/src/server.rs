// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent server with Unix socket listener.

use crate::error::{AgentError, Result};
use crate::protocol::{
    INVALID_PARAMS, METHOD_NOT_FOUND, NOT_AUTHENTICATED, Request, Response, SESSION_EXPIRED,
    StoreSessionParams, StoreSshCredentialsParams,
};
use crate::socket::{ensure_vouch_dir, remove_socket, socket_path};
use crate::ssh_agent::{SshAgentState, SshCredentials};
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
    ssh_state: Arc<SshAgentState>,
}

impl AgentServer {
    /// Create a new agent server.
    pub fn new(state: Arc<AgentState>, ssh_state: Arc<SshAgentState>) -> Self {
        Self { state, ssh_state }
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
                    let ssh_state = Arc::clone(&self.ssh_state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, state, ssh_state).await {
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
async fn handle_connection(
    mut stream: UnixStream,
    state: Arc<AgentState>,
    ssh_state: Arc<SshAgentState>,
) -> Result<()> {
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
        let response = handle_request(&request, &state, &ssh_state).await;
        send_response(&mut stream, &response).await?;
    }
}

/// Handle a JSON-RPC request.
async fn handle_request(
    request: &Request,
    state: &Arc<AgentState>,
    ssh_state: &Arc<SshAgentState>,
) -> Response {
    match request.method.as_str() {
        "ping" => handle_ping(request),
        "get_session" => handle_get_session(request, state).await,
        "store_session" => handle_store_session(request, state, ssh_state).await,
        "clear_session" => handle_clear_session(request, state, ssh_state).await,
        "get_token" => handle_get_token(request, state).await,
        "store_ssh_credentials" => handle_store_ssh_credentials(request, ssh_state).await,
        "clear_ssh_credentials" => handle_clear_ssh_credentials(request, ssh_state).await,
        "has_ssh_credentials" => handle_has_ssh_credentials(request, ssh_state).await,
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
async fn handle_store_session(
    request: &Request,
    state: &Arc<AgentState>,
    ssh_state: &Arc<SshAgentState>,
) -> Response {
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

    Response::success(request.id, true)
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
    Response::success(request.id, true)
}

/// Handle `get_token` request.
async fn handle_get_token(request: &Request, state: &Arc<AgentState>) -> Response {
    match state.get_token().await {
        Some(token) => Response::success(request.id, token),
        None => Response::error(request.id, NOT_AUTHENTICATED, "not authenticated"),
    }
}

/// Handle `store_ssh_credentials` request.
async fn handle_store_ssh_credentials(
    request: &Request,
    ssh_state: &Arc<SshAgentState>,
) -> Response {
    let params: StoreSshCredentialsParams = match &request.params {
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
            Response::success(request.id, true)
        }
        Err(e) => {
            warn!("Failed to load SSH credentials: {e}");
            Response::error(
                request.id,
                INVALID_PARAMS,
                &format!("failed to load credentials: {e}"),
            )
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
    Response::success(request.id, true)
}

/// Handle `has_ssh_credentials` request.
async fn handle_has_ssh_credentials(request: &Request, ssh_state: &Arc<SshAgentState>) -> Response {
    let has_creds = ssh_state.has_credentials().await;
    Response::success(request.id, has_creds)
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
