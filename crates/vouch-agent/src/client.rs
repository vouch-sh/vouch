// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent client for CLI communication.

use crate::error::{AgentError, Result};
use crate::protocol::{
    NOT_AUTHENTICATED, Request, Response, SESSION_EXPIRED, StoreSessionParams,
    StoreSshCredentialsParams,
};
use crate::socket::socket_path;
use crate::state::SessionInfo;
use crate::wire;

use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UnixStream;

/// Client for communicating with the agent.
pub struct AgentClient {
    stream: UnixStream,
    next_id: AtomicU64,
}

impl AgentClient {
    /// Connect to the agent.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::NotRunning` if the agent is not running.
    /// Returns `AgentError::Connection` for other socket errors.
    pub async fn connect() -> Result<Self> {
        let path = socket_path()?;

        let stream = UnixStream::connect(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::ConnectionRefused
                || e.kind() == std::io::ErrorKind::NotFound
            {
                AgentError::NotRunning
            } else {
                AgentError::Connection(e)
            }
        })?;

        Ok(Self {
            stream,
            next_id: AtomicU64::new(1),
        })
    }

    /// Send a request and receive a response.
    async fn call(&mut self, method: &str, params: Option<serde_json::Value>) -> Result<Response> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let request = Request {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.to_string(),
            params,
        };

        // Serialize and send request
        let json = serde_json::to_vec(&request)?;
        wire::write_message(&mut self.stream, &json).await?;

        // Read response
        let buf = wire::read_message(&mut self.stream)
            .await?
            .ok_or_else(|| AgentError::Protocol("unexpected disconnect".to_string()))?;

        // Parse response
        let response: Response = serde_json::from_slice(&buf)?;

        Ok(response)
    }

    /// Ping the agent (health check).
    ///
    /// # Errors
    ///
    /// Returns `AgentError::Protocol` if ping fails.
    pub async fn ping(&mut self) -> Result<()> {
        let response = self.call("ping", None).await?;

        if response.error.is_some() {
            return Err(AgentError::Protocol("ping failed".to_string()));
        }

        Ok(())
    }

    /// Get the current session.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::NotAuthenticated` if no session exists.
    /// Returns `AgentError::SessionExpired` if the session has expired.
    pub async fn get_session(&mut self) -> Result<SessionInfo> {
        let response = self.call("get_session", None).await?;

        if let Some(error) = response.error {
            return match error.code {
                NOT_AUTHENTICATED => Err(AgentError::NotAuthenticated),
                SESSION_EXPIRED => Err(AgentError::SessionExpired),
                _ => Err(AgentError::Protocol(error.message)),
            };
        }

        let result = response
            .result
            .ok_or_else(|| AgentError::Protocol("missing result".to_string()))?;

        serde_json::from_value(result).map_err(AgentError::from)
    }

    /// Store a session.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::Protocol` if the request fails.
    pub async fn store_session(
        &mut self,
        token: &str,
        user_email: &str,
        expires_at: &str,
        server_url: Option<&str>,
    ) -> Result<()> {
        let params = StoreSessionParams {
            token: token.to_string(),
            user_email: user_email.to_string(),
            expires_at: expires_at.to_string(),
            server_url: server_url.map(String::from),
        };

        let response = self
            .call("store_session", Some(serde_json::to_value(params)?))
            .await?;

        if let Some(error) = response.error {
            return Err(AgentError::Protocol(error.message));
        }

        Ok(())
    }

    /// Clear the current session.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::Protocol` if the request fails.
    pub async fn clear_session(&mut self) -> Result<()> {
        let response = self.call("clear_session", None).await?;

        if let Some(error) = response.error {
            return Err(AgentError::Protocol(error.message));
        }

        Ok(())
    }

    /// Get the raw JWT token.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::NotAuthenticated` if no session exists.
    /// Returns `AgentError::SessionExpired` if the session has expired.
    pub async fn get_token(&mut self) -> Result<String> {
        let response = self.call("get_token", None).await?;

        if let Some(error) = response.error {
            return match error.code {
                NOT_AUTHENTICATED => Err(AgentError::NotAuthenticated),
                SESSION_EXPIRED => Err(AgentError::SessionExpired),
                _ => Err(AgentError::Protocol(error.message)),
            };
        }

        let result = response
            .result
            .ok_or_else(|| AgentError::Protocol("missing result".to_string()))?;

        result
            .as_str()
            .map(ToString::to_string)
            .ok_or_else(|| AgentError::Protocol("invalid token".to_string()))
    }

    /// Store SSH credentials in the agent.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::Protocol` if the request fails.
    pub async fn store_ssh_credentials(&mut self, key_path: &str, cert_path: &str) -> Result<()> {
        self.store_ssh_credentials_with_session(key_path, cert_path, None, None)
            .await
    }

    /// Store SSH credentials in the agent with session linkage.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::Protocol` if the request fails.
    pub async fn store_ssh_credentials_with_session(
        &mut self,
        key_path: &str,
        cert_path: &str,
        session_expires_at: Option<&str>,
        server_url: Option<&str>,
    ) -> Result<()> {
        let params = StoreSshCredentialsParams {
            key_path: key_path.to_string(),
            cert_path: cert_path.to_string(),
            session_expires_at: session_expires_at.map(String::from),
            server_url: server_url.map(String::from),
        };

        let response = self
            .call("store_ssh_credentials", Some(serde_json::to_value(params)?))
            .await?;

        if let Some(error) = response.error {
            return Err(AgentError::Protocol(error.message));
        }

        Ok(())
    }

    /// Clear SSH credentials from the agent.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::Protocol` if the request fails.
    pub async fn clear_ssh_credentials(&mut self) -> Result<()> {
        let response = self.call("clear_ssh_credentials", None).await?;

        if let Some(error) = response.error {
            return Err(AgentError::Protocol(error.message));
        }

        Ok(())
    }

    /// Check if SSH credentials are loaded.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::Protocol` if the request fails.
    pub async fn has_ssh_credentials(&mut self) -> Result<bool> {
        let response = self.call("has_ssh_credentials", None).await?;

        if let Some(error) = response.error {
            return Err(AgentError::Protocol(error.message));
        }

        let result = response
            .result
            .ok_or_else(|| AgentError::Protocol("missing result".to_string()))?;

        result
            .as_bool()
            .ok_or_else(|| AgentError::Protocol("invalid result".to_string()))
    }
}

/// Check if the agent is running.
pub async fn is_agent_running() -> bool {
    AgentClient::connect().await.is_ok()
}
