// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session recovery from persisted credentials on disk.
//!
//! On startup, the agent attempts to restore a valid session by reading
//! `~/.vouch/config.json` (primary) or `~/.vouch/cookie.txt` (fallback),
//! validating the token against the server, and populating in-memory state.
//!
//! This is best-effort: all errors are logged and never block startup.

use crate::ssh_agent::SshAgentState;
use crate::state::{AgentState, Session};

use jiff::Timestamp;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tracing::{debug, info};

/// Try to recover a session from credentials persisted on disk.
///
/// Returns `true` if a valid session was recovered and stored in state.
/// Returns `false` if no token was found, validation failed, or any error occurred.
///
/// This function is best-effort: it logs errors at `debug` level and never panics.
pub async fn try_recover_session(state: &Arc<AgentState>, ssh_state: &Arc<SshAgentState>) -> bool {
    match try_recover_inner(state, ssh_state).await {
        Ok(true) => true,
        Ok(false) => false,
        Err(e) => {
            debug!("Session recovery failed: {e}");
            false
        }
    }
}

/// Inner recovery logic that returns errors for logging.
async fn try_recover_inner(
    state: &Arc<AgentState>,
    ssh_state: &Arc<SshAgentState>,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Try config.json first, then fall back to cookie.txt
    let (token, server_url) = match read_credentials_from_config()? {
        Some((t, url)) => (SecretString::from(t), url),
        None => match read_credentials_from_cookie() {
            Some((t, url)) => (SecretString::from(t), url),
            None => {
                debug!("No persisted credentials found for recovery");
                return Ok(false);
            }
        },
    };

    // Reject insecure server URLs (unless explicitly allowed)
    if vouch_common::check_url_security(&server_url).is_insecure() {
        if std::env::var("VOUCH_ALLOW_INSECURE").is_ok() {
            tracing::warn!(
                "Recovering session over insecure HTTP: {server_url}. VOUCH_ALLOW_INSECURE is set."
            );
        } else {
            tracing::warn!(
                "Refusing to recover session over insecure HTTP: {server_url}. Set VOUCH_ALLOW_INSECURE=1 to override."
            );
            return Ok(false);
        }
    }

    debug!("Found persisted token, validating with server");

    // Validate token with the server
    let client =
        vouch_common::http::agent_client(&format!("vouch-agent/{}", env!("CARGO_PKG_VERSION")))?;

    let response = client
        .get(format!("{server_url}/v1/auth/status"))
        .bearer_auth(token.expose_secret())
        .send()
        .await?;

    if !response.status().is_success() {
        debug!("Token validation returned status {}", response.status());
        return Ok(false);
    }

    let status: vouch_common::SessionStatus = response.json().await?;

    if !status.authenticated {
        debug!("Server reports token is not authenticated");
        return Ok(false);
    }

    // Extract email (required for session)
    let email = match status.email {
        Some(e) => e,
        None => {
            debug!("Server returned authenticated but no email");
            return Ok(false);
        }
    };

    // Compute expiration
    let expires_in = status.expires_in_seconds.unwrap_or(0);
    let expires_in_i64 = i64::try_from(expires_in).unwrap_or(0);
    let expires_at = Timestamp::now()
        .as_second()
        .checked_add(expires_in_i64)
        .and_then(|s| Timestamp::from_second(s).ok())
        .unwrap_or_else(Timestamp::now);

    // Store session in agent state
    let session = Session::new(token, email.clone(), expires_at);
    state.store_session(session).await;

    // Store server URL in SSH agent state (enables lazy loading)
    ssh_state.set_server_url(server_url).await;

    let hours = expires_in / 3600;
    let minutes = (expires_in % 3600) / 60;
    info!("Session recovered for {email} (expires in {hours}h {minutes}m)");

    Ok(true)
}

/// Read token and server URL from `~/.vouch/config.json`.
///
/// Returns `Some((token, server_url))` if both are present, `None` otherwise.
fn read_credentials_from_config() -> Result<Option<(String, String)>, Box<dyn std::error::Error>> {
    let config = match vouch_common::read_config() {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(None),
        Err(e) => {
            debug!("Failed to read config.json: {e}");
            return Ok(None);
        }
    };

    match (config.token, config.server_url) {
        (Some(token), Some(url)) if !token.is_empty() && !url.is_empty() => Ok(Some((token, url))),
        _ => Ok(None),
    }
}

/// Read token and server URL from `~/.vouch/cookie.txt`.
///
/// Derives `https://{domain}` from the cookie's domain field.
/// Returns `None` if the file is missing, invalid, or expired.
fn read_credentials_from_cookie() -> Option<(String, String)> {
    let cookie = match vouch_common::read_cookie() {
        Ok(Some(c)) => c,
        Ok(None) => return None,
        Err(e) => {
            debug!("Failed to read cookie.txt: {e}");
            return None;
        }
    };

    if vouch_common::is_cookie_expired(&cookie) {
        debug!("Cookie is expired, skipping");
        return None;
    }

    let server_url = format!("https://{}", cookie.domain);
    Some((cookie.value, server_url))
}
