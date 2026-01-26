//! SSH Agent Protocol implementation.
//!
//! This module implements the SSH agent protocol (draft-miller-ssh-agent)
//! to provide seamless SSH authentication using Vouch-issued certificates.
//!
//! The agent listens on `~/.vouch/ssh-agent.sock` and handles:
//! - `SSH_AGENTC_REQUEST_IDENTITIES` - Returns available SSH certificates
//! - `SSH_AGENTC_SIGN_REQUEST` - Signs data with the user's private key

use crate::error::{AgentError, Result};
use crate::socket::vouch_dir;
use jiff::Timestamp;
use ssh_key::{PrivateKey, certificate::Certificate};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// SSH Agent Protocol Constants (draft-miller-ssh-agent)
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

// Signature flags
#[allow(dead_code)]
const SSH_AGENT_RSA_SHA2_256: u32 = 2;
#[allow(dead_code)]
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// Refresh threshold in seconds (30 minutes before expiration).
const REFRESH_THRESHOLD_SECONDS: i64 = 30 * 60;

/// Minimum interval between refresh attempts (5 minutes).
const MIN_REFRESH_INTERVAL_SECONDS: i64 = 5 * 60;

/// Certificate metadata for cache management.
#[derive(Clone, Debug)]
pub struct CertificateMetadata {
    /// When the certificate was issued.
    pub issued_at: Timestamp,
    /// When the certificate expires.
    pub expires_at: Timestamp,
    /// Certificate serial number.
    pub serial: u64,
    /// Principals (users) the certificate is valid for.
    pub principals: Vec<String>,
    /// Path to the private key file.
    pub key_path: PathBuf,
    /// Path to the certificate file.
    pub cert_path: PathBuf,
}

impl CertificateMetadata {
    /// Create metadata from a certificate and file paths.
    pub fn from_certificate(
        cert: &Certificate,
        key_path: PathBuf,
        cert_path: PathBuf,
    ) -> Result<Self> {
        // Extract validity times from certificate
        let valid_after = cert.valid_after();
        let valid_before = cert.valid_before();

        // Convert Unix timestamps to jiff::Timestamp
        let issued_at = Timestamp::from_second(i64::try_from(valid_after).unwrap_or(0))
            .map_err(|e| AgentError::Protocol(format!("invalid valid_after timestamp: {e}")))?;
        let expires_at = Timestamp::from_second(i64::try_from(valid_before).unwrap_or(i64::MAX))
            .map_err(|e| AgentError::Protocol(format!("invalid valid_before timestamp: {e}")))?;

        // Extract principals
        let principals = cert
            .valid_principals()
            .iter()
            .map(|s| s.to_string())
            .collect();

        Ok(Self {
            issued_at,
            expires_at,
            serial: cert.serial(),
            principals,
            key_path,
            cert_path,
        })
    }

    /// Check if the certificate has expired.
    pub fn is_expired(&self) -> bool {
        let now = Timestamp::now();
        self.expires_at < now
    }

    /// Check if the certificate is expiring soon (within threshold).
    pub fn is_expiring_soon(&self) -> bool {
        let now = Timestamp::now();
        let threshold =
            Timestamp::from_second(now.as_second() + REFRESH_THRESHOLD_SECONDS).unwrap_or(now);
        self.expires_at < threshold
    }

    /// Get remaining validity in seconds.
    pub fn remaining_seconds(&self) -> i64 {
        let now = Timestamp::now();
        self.expires_at.as_second() - now.as_second()
    }
}

/// SSH credentials stored by the agent.
#[derive(Clone)]
pub struct SshCredentials {
    /// User's SSH private key.
    private_key: PrivateKey,
    /// SSH certificate (signed by Vouch CA).
    /// Kept for future certificate validation and metadata access.
    #[allow(dead_code)]
    certificate: Certificate,
    /// Certificate in OpenSSH format (for returning to clients).
    certificate_blob: Vec<u8>,
    /// Comment for the key.
    comment: String,
    /// Certificate metadata for cache management.
    pub metadata: CertificateMetadata,
}

impl SshCredentials {
    /// Create new SSH credentials with explicit paths.
    pub fn new(
        private_key: PrivateKey,
        certificate: Certificate,
        comment: String,
        key_path: PathBuf,
        cert_path: PathBuf,
    ) -> Result<Self> {
        // Get the certificate blob for the identities response
        let cert_openssh = certificate
            .to_openssh()
            .map_err(|e| AgentError::Protocol(format!("failed to serialize certificate: {e}")))?;
        let certificate_blob = parse_openssh_public_key(&cert_openssh)?;

        // Create metadata from certificate
        let metadata = CertificateMetadata::from_certificate(&certificate, key_path, cert_path)?;

        Ok(Self {
            private_key,
            certificate,
            certificate_blob,
            comment,
            metadata,
        })
    }

    /// Load credentials from files.
    pub fn load(key_path: &std::path::Path, cert_path: &std::path::Path) -> Result<Self> {
        // Load private key
        let key_data = std::fs::read_to_string(key_path)
            .map_err(|e| AgentError::Protocol(format!("failed to read private key: {e}")))?;
        let private_key = PrivateKey::from_openssh(&key_data)
            .map_err(|e| AgentError::Protocol(format!("failed to parse private key: {e}")))?;

        // Load certificate
        let cert_data = std::fs::read_to_string(cert_path)
            .map_err(|e| AgentError::Protocol(format!("failed to read certificate: {e}")))?;
        let certificate = Certificate::from_openssh(&cert_data)
            .map_err(|e| AgentError::Protocol(format!("failed to parse certificate: {e}")))?;

        // Generate comment from certificate key ID
        let comment = certificate.key_id().to_string();

        Self::new(
            private_key,
            certificate,
            comment,
            key_path.to_path_buf(),
            cert_path.to_path_buf(),
        )
    }

    /// Check if the certificate has expired.
    pub fn is_expired(&self) -> bool {
        self.metadata.is_expired()
    }

    /// Check if the certificate is expiring soon.
    pub fn is_expiring_soon(&self) -> bool {
        self.metadata.is_expiring_soon()
    }

    /// Get remaining validity in seconds.
    pub fn remaining_seconds(&self) -> i64 {
        self.metadata.remaining_seconds()
    }

    /// Get the public key in OpenSSH format.
    pub fn public_key_openssh(&self) -> Result<String> {
        let pub_key = self.private_key.public_key();
        pub_key
            .to_openssh()
            .map_err(|e| AgentError::Protocol(format!("failed to serialize public key: {e}")))
    }
}

/// SSH Agent state with session linkage.
pub struct SshAgentState {
    /// Current SSH credentials (if loaded).
    credentials: RwLock<Option<SshCredentials>>,
    /// Session expiration timestamp (linked to Vouch session).
    session_expires_at: RwLock<Option<Timestamp>>,
    /// Server URL for credential refresh.
    server_url: RwLock<Option<String>>,
    /// Last refresh attempt timestamp (for rate limiting).
    last_refresh_at: RwLock<Option<Timestamp>>,
}

impl Default for SshAgentState {
    fn default() -> Self {
        Self {
            credentials: RwLock::new(None),
            session_expires_at: RwLock::new(None),
            server_url: RwLock::new(None),
            last_refresh_at: RwLock::new(None),
        }
    }
}

impl SshAgentState {
    /// Create a new SSH agent state.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Store SSH credentials with session linkage.
    pub async fn store_credentials(
        &self,
        creds: SshCredentials,
        session_expires_at: Option<Timestamp>,
        server_url: Option<String>,
    ) {
        let mut cred_guard = self.credentials.write().await;
        *cred_guard = Some(creds);

        if let Some(expires) = session_expires_at {
            let mut session_guard = self.session_expires_at.write().await;
            *session_guard = Some(expires);
        }

        if let Some(url) = server_url {
            let mut url_guard = self.server_url.write().await;
            *url_guard = Some(url);
        }
    }

    /// Store SSH credentials without session info (backwards compatibility).
    pub async fn store_credentials_simple(&self, creds: SshCredentials) {
        let mut guard = self.credentials.write().await;
        *guard = Some(creds);
    }

    /// Clear SSH credentials and session linkage.
    pub async fn clear_credentials(&self) {
        let mut cred_guard = self.credentials.write().await;
        *cred_guard = None;

        let mut session_guard = self.session_expires_at.write().await;
        *session_guard = None;

        let mut url_guard = self.server_url.write().await;
        *url_guard = None;

        let mut refresh_guard = self.last_refresh_at.write().await;
        *refresh_guard = None;
    }

    /// Get current credentials (if any).
    pub async fn get_credentials(&self) -> Option<SshCredentials> {
        let guard = self.credentials.read().await;
        guard.clone()
    }

    /// Get valid credentials (not expired, session not expired).
    pub async fn get_valid_credentials(&self) -> Option<SshCredentials> {
        let creds = self.get_credentials().await?;

        // Check if certificate is expired
        if creds.is_expired() {
            debug!("Certificate has expired");
            return None;
        }

        // Check if session is expired
        let session_expires = self.session_expires_at.read().await;
        if let Some(expires) = *session_expires
            && Timestamp::now() >= expires
        {
            debug!("Session has expired");
            return None;
        }

        Some(creds)
    }

    /// Check if credentials are loaded.
    pub async fn has_credentials(&self) -> bool {
        let guard = self.credentials.read().await;
        guard.is_some()
    }

    /// Check if certificate needs refresh.
    pub async fn needs_refresh(&self) -> bool {
        let guard = self.credentials.read().await;
        guard.as_ref().is_some_and(|c| c.is_expiring_soon())
    }

    /// Check if we can attempt refresh (rate limiting).
    pub async fn can_attempt_refresh(&self) -> bool {
        let guard = self.last_refresh_at.read().await;
        match *guard {
            Some(last) => {
                let now = Timestamp::now();
                let elapsed = now.as_second() - last.as_second();
                elapsed >= MIN_REFRESH_INTERVAL_SECONDS
            }
            None => true,
        }
    }

    /// Record refresh attempt time.
    pub async fn record_refresh_attempt(&self) {
        let mut guard = self.last_refresh_at.write().await;
        *guard = Some(Timestamp::now());
    }

    /// Get the server URL for refresh.
    pub async fn get_server_url(&self) -> Option<String> {
        let guard = self.server_url.read().await;
        guard.clone()
    }

    /// Clean up expired credentials.
    pub async fn cleanup_expired(&self) {
        let should_clear = {
            let guard = self.credentials.read().await;
            guard.as_ref().is_some_and(|c| c.is_expired())
        };

        if should_clear {
            info!("Cleaning up expired SSH credentials");
            self.clear_credentials().await;
        }
    }
}

/// Get the SSH agent socket path (~/.vouch/ssh-agent.sock).
pub fn ssh_agent_socket_path() -> Result<PathBuf> {
    Ok(vouch_dir()?.join("ssh-agent.sock"))
}

/// SSH Agent server.
pub struct SshAgentServer {
    state: Arc<SshAgentState>,
    agent_state: Option<Arc<crate::state::AgentState>>,
}

impl SshAgentServer {
    /// Create a new SSH agent server.
    pub fn new(state: Arc<SshAgentState>) -> Self {
        Self {
            state,
            agent_state: None,
        }
    }

    /// Create a new SSH agent server with access to the main agent state (for refresh).
    pub fn with_agent_state(
        state: Arc<SshAgentState>,
        agent_state: Arc<crate::state::AgentState>,
    ) -> Self {
        Self {
            state,
            agent_state: Some(agent_state),
        }
    }

    /// Run the SSH agent server.
    pub async fn run(&self) -> Result<()> {
        let path = ssh_agent_socket_path()?;

        // Remove stale socket
        if path.exists() {
            std::fs::remove_file(&path).ok();
        }

        let listener = UnixListener::bind(&path).map_err(|e| {
            AgentError::SocketPath(format!(
                "failed to bind SSH agent socket {}: {e}",
                path.display()
            ))
        })?;

        // Set socket permissions
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

        info!("SSH agent listening on {}", path.display());

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let state = Arc::clone(&self.state);
                    let agent_state = self.agent_state.clone();
                    tokio::spawn(async move {
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
    }
}

/// Handle a single SSH agent connection.
async fn handle_ssh_connection(
    mut stream: UnixStream,
    state: Arc<SshAgentState>,
    agent_state: Option<Arc<crate::state::AgentState>>,
) -> Result<()> {
    loop {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(e) => return Err(AgentError::Connection(e)),
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 256 * 1024 {
            warn!("Invalid SSH agent message length: {len}");
            return Err(AgentError::Protocol("invalid message length".to_string()));
        }

        // Read message body
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        // Get message type (first byte)
        let msg_type = buf.first().copied().unwrap_or(0);
        debug!("SSH agent message type: {msg_type}");

        // Handle message
        let response = match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => handle_request_identities(&state).await,
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
        send_ssh_response(&mut stream, &response_data).await?;
    }
}

/// Handle SSH_AGENTC_REQUEST_IDENTITIES.
async fn handle_request_identities(state: &Arc<SshAgentState>) -> Result<Vec<u8>> {
    let creds = state.get_credentials().await;

    let mut response = Vec::new();
    response.push(SSH_AGENT_IDENTITIES_ANSWER);

    match creds {
        Some(c) => {
            // Number of keys (1)
            response.extend_from_slice(&1u32.to_be_bytes());

            // Key blob length + data
            let blob_len = u32::try_from(c.certificate_blob.len())
                .map_err(|_| AgentError::Protocol("certificate too large".to_string()))?;
            response.extend_from_slice(&blob_len.to_be_bytes());
            response.extend_from_slice(&c.certificate_blob);

            // Comment length + data
            let comment_bytes = c.comment.as_bytes();
            let comment_len = u32::try_from(comment_bytes.len())
                .map_err(|_| AgentError::Protocol("comment too large".to_string()))?;
            response.extend_from_slice(&comment_len.to_be_bytes());
            response.extend_from_slice(comment_bytes);

            debug!("Returning 1 identity");
        }
        None => {
            // No keys
            response.extend_from_slice(&0u32.to_be_bytes());
            debug!("Returning 0 identities");
        }
    }

    Ok(response)
}

/// Handle SSH_AGENTC_SIGN_REQUEST.
async fn handle_sign_request(
    buf: &[u8],
    state: &Arc<SshAgentState>,
    agent_state: Option<&Arc<crate::state::AgentState>>,
) -> Result<Vec<u8>> {
    // Parse sign request:
    // byte    SSH_AGENTC_SIGN_REQUEST
    // string  key_blob
    // string  data
    // uint32  flags

    // Check if we need to refresh the certificate (best-effort, don't block on failure)
    if state.needs_refresh().await
        && state.can_attempt_refresh().await
        && let Some(agent) = agent_state
    {
        // Attempt refresh in the background
        let state_clone = Arc::clone(state);
        let agent_clone = Arc::clone(agent);
        tokio::spawn(async move {
            if let Err(e) = refresh_certificate(&state_clone, &agent_clone).await {
                debug!("Certificate refresh failed (non-fatal): {e}");
            }
        });
    }

    let creds = state
        .get_credentials()
        .await
        .ok_or_else(|| AgentError::Protocol("no credentials loaded".to_string()))?;

    // Skip message type byte
    let mut offset = 1;

    // Read key blob
    let key_blob_len = read_u32(buf, &mut offset)?;
    let key_blob_end = offset + key_blob_len as usize;
    let _key_blob = buf
        .get(offset..key_blob_end)
        .ok_or_else(|| AgentError::Protocol("invalid key blob length".to_string()))?;
    offset = key_blob_end;

    // Read data to sign
    let data_len = read_u32(buf, &mut offset)?;
    let data_end = offset + data_len as usize;
    let data = buf
        .get(offset..data_end)
        .ok_or_else(|| AgentError::Protocol("invalid data length".to_string()))?;
    offset = data_end;

    // Read flags (optional)
    let _flags = if offset + 4 <= buf.len() {
        read_u32(buf, &mut offset)?
    } else {
        0
    };

    debug!("Signing {} bytes of data", data.len());

    // Sign the data (returns encoded signature blob)
    let sig_blob = sign_data(&creds.private_key, data)?;

    // Build response
    let mut response = Vec::new();
    response.push(SSH_AGENT_SIGN_RESPONSE);

    // Signature blob
    let sig_len = u32::try_from(sig_blob.len())
        .map_err(|_| AgentError::Protocol("signature too large".to_string()))?;
    response.extend_from_slice(&sig_len.to_be_bytes());
    response.extend_from_slice(&sig_blob);

    Ok(response)
}

/// Refresh the SSH certificate from the server.
async fn refresh_certificate(
    state: &Arc<SshAgentState>,
    agent_state: &Arc<crate::state::AgentState>,
) -> Result<()> {
    // Record the refresh attempt
    state.record_refresh_attempt().await;

    // Get the server URL
    let server_url = state
        .get_server_url()
        .await
        .ok_or_else(|| AgentError::Protocol("no server URL configured for refresh".to_string()))?;

    // Get the session token
    let token = agent_state.get_token().await.ok_or_else(|| {
        AgentError::Protocol("no session token available for refresh".to_string())
    })?;

    // Get the current public key
    let creds = state
        .get_credentials()
        .await
        .ok_or_else(|| AgentError::Protocol("no credentials to refresh".to_string()))?;

    let public_key = creds.public_key_openssh()?;

    info!("Refreshing SSH certificate from {}", server_url);

    // Make the refresh request
    let client = reqwest::Client::new();
    let request = vouch_common::SshCertificateRequest { public_key };

    let response = client
        .post(format!("{}/v1/credentials/ssh", server_url))
        .bearer_auth(token)
        .json(&request)
        .send()
        .await
        .map_err(|e| AgentError::Protocol(format!("refresh request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(AgentError::Protocol(format!(
            "refresh request returned {}",
            response.status()
        )));
    }

    let cert_response: vouch_common::SshCertificateResponse = response
        .json()
        .await
        .map_err(|e| AgentError::Protocol(format!("failed to parse refresh response: {e}")))?;

    // Write the new certificate to the file
    let cert_path = &creds.metadata.cert_path;
    std::fs::write(cert_path, format!("{}\n", cert_response.certificate))
        .map_err(|e| AgentError::Protocol(format!("failed to write refreshed certificate: {e}")))?;

    // Reload credentials from files
    let new_creds = SshCredentials::load(&creds.metadata.key_path, cert_path)?;

    // Get session expiration (keep existing if not available)
    let session_expires_at = {
        let guard = agent_state.get_session().await;
        guard.map(|s| s.expires_at)
    };

    // Store the refreshed credentials
    state
        .store_credentials(new_creds, session_expires_at, Some(server_url))
        .await;

    info!(
        "SSH certificate refreshed successfully (serial: {}, valid for: {}s)",
        cert_response.serial, cert_response.valid_for_seconds
    );

    Ok(())
}

/// Send an SSH agent response.
async fn send_ssh_response(stream: &mut UnixStream, data: &[u8]) -> Result<()> {
    #[allow(clippy::cast_possible_truncation)]
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    Ok(())
}

/// Read a u32 from a buffer.
fn read_u32(buf: &[u8], offset: &mut usize) -> Result<u32> {
    if *offset + 4 > buf.len() {
        return Err(AgentError::Protocol("buffer underflow".to_string()));
    }
    let bytes: [u8; 4] = buf
        .get(*offset..*offset + 4)
        .ok_or_else(|| AgentError::Protocol("buffer underflow".to_string()))?
        .try_into()
        .map_err(|_| AgentError::Protocol("buffer underflow".to_string()))?;
    *offset += 4;
    Ok(u32::from_be_bytes(bytes))
}

/// Parse an OpenSSH public key/certificate to get the binary blob.
fn parse_openssh_public_key(openssh: &str) -> Result<Vec<u8>> {
    // Format: "ssh-ed25519-cert-v01@openssh.com AAAA... comment"
    let parts: Vec<&str> = openssh.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(AgentError::Protocol(
            "invalid OpenSSH key format".to_string(),
        ));
    }

    let blob = parts
        .get(1)
        .ok_or_else(|| AgentError::Protocol("missing key data".to_string()))?;

    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(blob)
        .map_err(|e| AgentError::Protocol(format!("invalid base64: {e}")))
}

/// Sign data with the private key and return the encoded signature.
fn sign_data(private_key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>> {
    // For SSH agent protocol, we need to sign the data directly and return
    // the signature in SSH wire format: string algorithm + string signature

    let (alg_name, sig_bytes) = match private_key.key_data() {
        ssh_key::private::KeypairData::Ed25519(keypair) => {
            // Get the signing key bytes and create a signature
            let signing_key_bytes = keypair.private.to_bytes();
            let public_key_bytes = keypair.public.0;

            // Combine private + public for ed25519-dalek format (64 bytes)
            let mut full_key = [0u8; 64];
            full_key[..32].copy_from_slice(&signing_key_bytes);
            full_key[32..].copy_from_slice(&public_key_bytes);

            // Use ed25519 signing
            use ed25519_dalek::{Signer, SigningKey};
            let signing_key = SigningKey::from_keypair_bytes(&full_key)
                .map_err(|e| AgentError::Protocol(format!("invalid ed25519 key: {e}")))?;
            let signature = signing_key.sign(data);

            ("ssh-ed25519", signature.to_bytes().to_vec())
        }
        _ => {
            return Err(AgentError::Protocol(
                "unsupported key algorithm".to_string(),
            ));
        }
    };

    // Encode in SSH wire format
    let mut buf = Vec::new();

    // Algorithm name
    let alg_bytes = alg_name.as_bytes();
    let alg_len = u32::try_from(alg_bytes.len())
        .map_err(|_| AgentError::Protocol("algorithm name too long".to_string()))?;
    buf.extend_from_slice(&alg_len.to_be_bytes());
    buf.extend_from_slice(alg_bytes);

    // Signature blob
    let sig_len = u32::try_from(sig_bytes.len())
        .map_err(|_| AgentError::Protocol("signature too large".to_string()))?;
    buf.extend_from_slice(&sig_len.to_be_bytes());
    buf.extend_from_slice(&sig_bytes);

    Ok(buf)
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_agent_socket_path() {
        let path = ssh_agent_socket_path();
        assert!(path.is_ok());
        let path = path.unwrap();
        assert!(path.ends_with("ssh-agent.sock"));
    }

    #[test]
    fn test_parse_openssh_public_key() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKtVCCk2pTkSR/wP3nXdjT4WKXV2+d3pvhYbYUV4Z/Kc test@example.com";
        let result = parse_openssh_public_key(key);
        assert!(result.is_ok());
        let blob = result.unwrap();
        assert!(!blob.is_empty());
    }
}
