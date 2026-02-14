// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent server with Unix socket listener.

use crate::error::Result;
use crate::protocol::{
    CacheCredentialParams, GetCachedCredentialParams, Request, Response, StoreSessionParams,
    StoreSshCredentialsParams,
};
use crate::socket::{bind_socket, ensure_vouch_dir, remove_socket, socket_path};
use crate::ssh_agent::{SshAgentState, SshCredentials};
use crate::state::{AgentState, CachedCredential, Session, SessionInfo};
use crate::wire;

use jiff::Timestamp;
use secrecy::SecretString;
use std::sync::Arc;
use tokio::net::UnixStream;
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
        let listener = bind_socket(&path).await?;

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
        // Read length-prefixed message
        let buf = match wire::read_message(&mut stream).await? {
            Some(buf) => buf,
            None => return Ok(()), // Client disconnected
        };

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
        "cache_credential" => handle_cache_credential(request, state).await,
        "get_cached_credential" => handle_get_cached_credential(request, state).await,
        "clear_credential_cache" => handle_clear_credential_cache(request, state).await,
        _ => Response::method_not_found(request.id),
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
                Response::session_expired(request.id)
            } else {
                let info = SessionInfo::from(&session);
                Response::success(request.id, info)
            }
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
    let params: StoreSessionParams = match &request.params {
        Some(p) => match serde_json::from_value(p.clone()) {
            Ok(params) => params,
            Err(e) => return Response::invalid_params(request.id, &e.to_string()),
        },
        None => return Response::invalid_params(request.id, "missing params"),
    };

    // Parse expiration timestamp
    let expires_at: Timestamp = match params.expires_at.parse() {
        Ok(ts) => ts,
        Err(e) => return Response::invalid_params(request.id, &format!("invalid expires_at: {e}")),
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
        None => Response::not_authenticated(request.id),
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
            Err(e) => return Response::invalid_params(request.id, &e.to_string()),
        },
        None => return Response::invalid_params(request.id, "missing params"),
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
    Response::success(request.id, true)
}

/// Handle `has_ssh_credentials` request.
async fn handle_has_ssh_credentials(request: &Request, ssh_state: &Arc<SshAgentState>) -> Response {
    let has_creds = ssh_state.has_credentials().await;
    Response::success(request.id, has_creds)
}

/// Handle `cache_credential` request.
async fn handle_cache_credential(request: &Request, state: &Arc<AgentState>) -> Response {
    let params: CacheCredentialParams = match &request.params {
        Some(p) => match serde_json::from_value(p.clone()) {
            Ok(params) => params,
            Err(e) => return Response::invalid_params(request.id, &e.to_string()),
        },
        None => return Response::invalid_params(request.id, "missing params"),
    };

    let credential = CachedCredential {
        data: params.data,
        expires_at: params.expires_at,
        cached_at: jiff::Timestamp::now().to_string(),
    };

    state
        .cache_credential(params.credential_type.clone(), credential)
        .await;

    info!("Cached credential: {}", params.credential_type);
    Response::success(request.id, true)
}

/// Handle `get_cached_credential` request.
async fn handle_get_cached_credential(request: &Request, state: &Arc<AgentState>) -> Response {
    let params: GetCachedCredentialParams = match &request.params {
        Some(p) => match serde_json::from_value(p.clone()) {
            Ok(params) => params,
            Err(e) => return Response::invalid_params(request.id, &e.to_string()),
        },
        None => return Response::invalid_params(request.id, "missing params"),
    };

    match state.get_cached_credential(&params.credential_type).await {
        Some(credential) => Response::success(request.id, credential),
        None => Response::not_authenticated(request.id),
    }
}

/// Handle `clear_credential_cache` request.
async fn handle_clear_credential_cache(request: &Request, state: &Arc<AgentState>) -> Response {
    state.clear_credential_cache().await;
    info!("Credential cache cleared");
    Response::success(request.id, true)
}

/// Send a response over the stream.
async fn send_response(stream: &mut UnixStream, response: &Response) -> Result<()> {
    let json = serde_json::to_vec(response)?;
    wire::write_message(stream, &json).await
}

impl Drop for AgentServer {
    fn drop(&mut self) {
        // Clean up socket on drop
        let _ = remove_socket();
    }
}
