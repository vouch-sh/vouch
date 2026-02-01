// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH credential provisioning and refresh.

use crate::error::{AgentError, Result};
use std::sync::Arc;
use tracing::{debug, info};

use super::DEFAULT_KEY_NAME;
use super::credentials::SshCredentials;
use super::protocol::{
    build_identities_response, build_sign_response, parse_sign_request, sign_data,
};
use super::state::SshAgentState;

/// Handle SSH_AGENTC_REQUEST_IDENTITIES with lazy loading.
pub(super) async fn handle_request_identities(
    state: &Arc<SshAgentState>,
    agent_state: Option<&Arc<crate::state::AgentState>>,
) -> Result<Vec<u8>> {
    // First check in-memory credentials
    let creds = state.get_valid_credentials().await;

    if let Some(c) = creds {
        return build_identities_response(Some(&c));
    }

    // No valid credentials in memory — try lazy loading from disk
    if let Some(loaded) = try_load_from_disk(state, agent_state).await {
        return build_identities_response(Some(&loaded));
    }

    // No valid cert on disk either — try background provisioning
    spawn_lazy_provision(state, agent_state);

    // Return 0 identities immediately (don't block the SSH connection)
    build_identities_response(None)
}

/// Handle SSH_AGENTC_SIGN_REQUEST.
pub(super) async fn handle_sign_request(
    buf: &[u8],
    state: &Arc<SshAgentState>,
    agent_state: Option<&Arc<crate::state::AgentState>>,
) -> Result<Vec<u8>> {
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

    let data = parse_sign_request(buf)?;

    debug!("Signing {} bytes of data", data.len());

    // Sign the data (returns encoded signature blob)
    let sig_blob = sign_data(&creds.private_key, &data)?;

    build_sign_response(&sig_blob)
}

/// Try to load SSH credentials from disk (lazy loading after agent restart).
///
/// Only loads if the agent has a valid session (prevents stale certs after logout).
async fn try_load_from_disk(
    state: &Arc<SshAgentState>,
    agent_state: Option<&Arc<crate::state::AgentState>>,
) -> Option<SshCredentials> {
    // Require a valid agent session to prevent serving stale certs
    let agent = agent_state?;
    let session = agent.get_session().await?;

    // Check for default key and cert files on disk
    let home = dirs::home_dir()?;
    let ssh_dir = home.join(".ssh");
    let key_path = ssh_dir.join(DEFAULT_KEY_NAME);
    let cert_path = ssh_dir.join(format!("{DEFAULT_KEY_NAME}-cert.pub"));

    if !key_path.exists() || !cert_path.exists() {
        debug!("No SSH key/cert files found on disk for lazy loading");
        return None;
    }

    // Load credentials from disk
    let creds = match SshCredentials::load(&key_path, &cert_path) {
        Ok(c) => c,
        Err(e) => {
            debug!("Failed to load SSH credentials from disk: {e}");
            return None;
        }
    };

    // Check if the certificate is still valid
    if creds.is_expired() {
        debug!("Disk certificate is expired, not loading");
        return None;
    }

    info!("Lazy-loaded SSH credentials from disk");

    // Store in agent state with session linkage
    let server_url = state.get_server_url().await;
    state
        .store_credentials(creds.clone(), Some(session.expires_at), server_url)
        .await;

    Some(creds)
}

/// Spawn a non-blocking background task to provision SSH certificate from server.
///
/// This does NOT block the current SSH connection. The next identity request
/// will pick up the newly provisioned cert.
fn spawn_lazy_provision(
    state: &Arc<SshAgentState>,
    agent_state: Option<&Arc<crate::state::AgentState>>,
) {
    let Some(agent) = agent_state else {
        return;
    };

    // Check for existing keypair (agent does NOT generate keypairs)
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return,
    };
    let key_path = home.join(".ssh").join(DEFAULT_KEY_NAME);
    let pub_path = key_path.with_extension("pub");

    if !key_path.exists() || !pub_path.exists() {
        debug!("No SSH keypair on disk, cannot lazy-provision");
        return;
    }

    let state_clone = Arc::clone(state);
    let agent_clone = Arc::clone(agent);

    tokio::spawn(async move {
        // Rate-limit provisioning attempts
        if !state_clone.can_attempt_refresh().await {
            debug!("Lazy provisioning rate-limited");
            return;
        }
        state_clone.record_refresh_attempt().await;

        // Need a valid session and server URL
        let Some(session) = agent_clone.get_session().await else {
            debug!("No valid session for lazy provisioning");
            return;
        };
        let Some(server_url) = state_clone.get_server_url().await else {
            debug!("No server URL for lazy provisioning");
            return;
        };

        // Read the public key from disk
        let pub_key_str = match std::fs::read_to_string(&pub_path) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                debug!("Failed to read public key for lazy provisioning: {e}");
                return;
            }
        };

        info!("Lazy-provisioning SSH certificate from {server_url}");

        // Make the HTTP request with a short timeout
        let client = match vouch_common::http::agent_client(&format!(
            "vouch-agent/{}",
            env!("CARGO_PKG_VERSION")
        )) {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to create HTTP client for lazy provisioning: {e}");
                return;
            }
        };

        let token = match agent_clone.get_token().await {
            Some(t) => t,
            None => {
                debug!("No token available for lazy provisioning");
                return;
            }
        };

        let request = vouch_common::SshCertificateRequest {
            public_key: pub_key_str,
        };

        let response = match client
            .post(format!("{server_url}/v1/credentials/ssh"))
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                debug!("Lazy provisioning request failed: {e}");
                return;
            }
        };

        if !response.status().is_success() {
            debug!("Lazy provisioning returned status {}", response.status());
            return;
        }

        let cert_response: vouch_common::SshCertificateResponse = match response.json().await {
            Ok(r) => r,
            Err(e) => {
                debug!("Failed to parse lazy provisioning response: {e}");
                return;
            }
        };

        // Write certificate to disk
        let cert_path = home
            .join(".ssh")
            .join(format!("{DEFAULT_KEY_NAME}-cert.pub"));
        if let Err(e) = std::fs::write(&cert_path, format!("{}\n", cert_response.certificate)) {
            debug!("Failed to write lazy-provisioned certificate: {e}");
            return;
        }

        // Load credentials into agent state
        match SshCredentials::load(&key_path, &cert_path) {
            Ok(creds) => {
                state_clone
                    .store_credentials(creds, Some(session.expires_at), Some(server_url))
                    .await;
                info!(
                    "Lazy-provisioned SSH certificate (serial: {}, valid for: {}s)",
                    cert_response.serial, cert_response.valid_for_seconds
                );
            }
            Err(e) => {
                debug!("Failed to load lazy-provisioned credentials: {e}");
            }
        }
    });
}

/// Refresh the SSH certificate from the server.
pub(super) async fn refresh_certificate(
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
    let client =
        vouch_common::http::agent_client(&format!("vouch-agent/{}", env!("CARGO_PKG_VERSION")))
            .map_err(|e| AgentError::Protocol(format!("failed to create HTTP client: {e}")))?;
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
