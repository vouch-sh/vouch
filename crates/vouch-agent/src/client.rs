// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent client for CLI communication.

use crate::error::{AgentError, Result};
use crate::protocol::{
    CACHE_MISS, CacheCredentialParams, GetCachedCredentialParams, JSONRPC_VERSION, Method,
    NOT_AUTHENTICATED, Request, Response, SESSION_EXPIRED, StoreSessionParams,
    StoreSshCredentialsParams,
};
use crate::socket::socket_path;
use crate::state::CachedCredential;
use crate::state::SessionInfo;
use crate::wire;

use secrecy::SecretString;
use tokio::net::UnixStream;

/// Map a JSON-RPC auth-related error code to the appropriate `AgentError`.
fn check_auth_error(error: &crate::protocol::RpcError) -> AgentError {
    match error.code {
        NOT_AUTHENTICATED => AgentError::NotAuthenticated,
        SESSION_EXPIRED => AgentError::SessionExpired,
        _ => AgentError::Protocol(error.message.clone()),
    }
}

/// Client for communicating with the agent.
pub struct AgentClient {
    stream: UnixStream,
    next_id: u64,
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

        Ok(Self { stream, next_id: 1 })
    }

    /// Send a request and receive a response.
    async fn call(
        &mut self,
        method: Method,
        params: Option<serde_json::Value>,
    ) -> Result<Response> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let request = Request {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method,
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
        let response = self.call(Method::Ping, None).await?;

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
        let response = self.call(Method::GetSession, None).await?;

        if let Some(error) = &response.error {
            return Err(check_auth_error(error));
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
            token: secrecy::SecretString::from(token),
            user_email: user_email.to_string(),
            expires_at: expires_at.to_string(),
            server_url: server_url.map(String::from),
        };

        let response = self
            .call(Method::StoreSession, Some(serde_json::to_value(params)?))
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
        let response = self.call(Method::ClearSession, None).await?;

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
    pub async fn get_token(&mut self) -> Result<SecretString> {
        let response = self.call(Method::GetToken, None).await?;

        if let Some(error) = &response.error {
            return Err(check_auth_error(error));
        }

        let result = response
            .result
            .ok_or_else(|| AgentError::Protocol("missing result".to_string()))?;

        result
            .as_str()
            .map(|s| SecretString::from(s.to_string()))
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
            .call(
                Method::StoreSshCredentials,
                Some(serde_json::to_value(params)?),
            )
            .await?;

        if let Some(error) = response.error {
            return Err(AgentError::Protocol(error.message));
        }

        Ok(())
    }

    /// Cache a credential in the agent.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::Protocol` if the request fails.
    pub async fn cache_credential(
        &mut self,
        credential_type: &str,
        data: serde_json::Value,
        expires_at: &str,
    ) -> Result<()> {
        let params = CacheCredentialParams {
            credential_type: credential_type.to_string(),
            data,
            expires_at: expires_at.to_string(),
        };

        let response = self
            .call(Method::CacheCredential, Some(serde_json::to_value(params)?))
            .await?;

        if let Some(error) = response.error {
            return Err(AgentError::Protocol(error.message));
        }

        Ok(())
    }

    /// Get a cached credential from the agent.
    ///
    /// Returns `None` if no valid cached credential exists for this type.
    ///
    /// # Errors
    ///
    /// Returns `AgentError::Protocol` if the request fails.
    pub async fn get_cached_credential(
        &mut self,
        credential_type: &str,
    ) -> Result<Option<CachedCredential>> {
        let params = GetCachedCredentialParams {
            credential_type: credential_type.to_string(),
        };

        let response = self
            .call(
                Method::GetCachedCredential,
                Some(serde_json::to_value(params)?),
            )
            .await?;

        if let Some(error) = &response.error {
            if error.code == CACHE_MISS {
                return Ok(None);
            }
            return Err(AgentError::Protocol(error.message.clone()));
        }

        let result = response
            .result
            .ok_or_else(|| AgentError::Protocol("missing result".to_string()))?;

        let credential: CachedCredential =
            serde_json::from_value(result).map_err(AgentError::from)?;
        Ok(Some(credential))
    }
}
