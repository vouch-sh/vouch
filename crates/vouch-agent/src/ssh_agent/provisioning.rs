// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH credential loading for the agent.
//!
//! The agent never provisions or refreshes certificates from the server itself
//! — that path requires DPoP + RFC 9421 request signing with the FAPI private
//! key, which lives with the CLI. Certificates are issued by the CLI's signed
//! `vouch credential ssh` path and pushed to the agent over IPC. The agent only
//! serves what it has in memory or can reload from disk.

use crate::error::{AgentError, Result};
use std::sync::Arc;
use tracing::{debug, info};

use super::DEFAULT_KEY_NAME;
use super::credentials::SshCredentials;
use super::protocol::{
    build_identities_response, build_sign_response, parse_sign_request, sign_data,
};
use super::state::SshAgentState;

/// Handle SSH_AGENTC_REQUEST_IDENTITIES.
pub(super) async fn handle_request_identities(
    state: &Arc<SshAgentState>,
    agent_state: Option<&Arc<crate::state::AgentState>>,
) -> Result<Vec<u8>> {
    // First check in-memory credentials
    let creds = state.get_valid_credentials().await;

    if let Some(c) = creds {
        return build_identities_response(Some(&c));
    }

    // No valid credentials in memory — try reloading a still-valid cert from
    // disk (written by the CLI's `vouch credential ssh`).
    if let Some(loaded) = try_load_from_disk(state, agent_state).await {
        return build_identities_response(Some(&loaded));
    }

    // Nothing to serve. Return 0 identities immediately (don't block the SSH
    // connection); the user re-provisions with `vouch credential ssh`.
    build_identities_response(None)
}

/// Handle SSH_AGENTC_SIGN_REQUEST.
pub(super) async fn handle_sign_request(buf: &[u8], state: &Arc<SshAgentState>) -> Result<Vec<u8>> {
    let creds = state
        .get_valid_credentials()
        .await
        .ok_or_else(|| AgentError::Protocol("no valid credentials available".to_string()))?;

    let data = parse_sign_request(buf)?;

    debug!("Signing {} bytes of data", data.len());

    // Sign the data (returns encoded signature blob)
    let sig_blob = sign_data(&creds.private_key, &data)?;

    crate::audit::log_event(crate::audit::AuditEvent::SshSigning);

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
