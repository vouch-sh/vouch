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
use crate::state::AgentState;

/// Handle SSH_AGENTC_REQUEST_IDENTITIES.
pub(super) async fn handle_request_identities(state: &Arc<AgentState>) -> Result<Vec<u8>> {
    // First check in-memory credentials
    let creds = state.get_valid_ssh_credentials().await;

    if let Some(c) = creds {
        return build_identities_response(Some(&c));
    }

    // No valid credentials in memory — try reloading a still-valid cert from
    // disk (written by the CLI's `vouch credential ssh`).
    if let Some(loaded) = try_load_from_disk(state).await {
        return build_identities_response(Some(&loaded));
    }

    // Nothing to serve. Return 0 identities immediately (don't block the SSH
    // connection); the user re-provisions with `vouch credential ssh`.
    build_identities_response(None)
}

/// Handle SSH_AGENTC_SIGN_REQUEST.
pub(super) async fn handle_sign_request(buf: &[u8], state: &Arc<AgentState>) -> Result<Vec<u8>> {
    let creds = state
        .get_valid_ssh_credentials()
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
/// Only loads if the agent has a valid session (prevents stale certs after
/// logout). `vouch logout` leaves the on-disk key and certificate in place, so
/// without this gate a cleared session could be undone by the next signature
/// request.
async fn try_load_from_disk(state: &Arc<AgentState>) -> Option<SshCredentials> {
    // Require a valid agent session to prevent serving stale certs
    state.get_session().await?;

    // Check for default key and cert files on disk
    let home = std::env::home_dir()?;
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

    // Re-check the session under the same call that stores: the filesystem work
    // above is slow enough for a concurrent logout to land in between, and
    // storing afterwards would resurrect credentials that logout just cleared.
    let server_url = state.get_ssh_server_url().await;
    if !state.store_ssh_credentials(creds.clone(), server_url).await {
        return None;
    }

    Some(creds)
}
