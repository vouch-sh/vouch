//! Login command - authenticate with your `YubiKey`.

use anyhow::{Context, Result};
use vouch_agent::{AgentClient, AgentError};
use vouch_common::{
    ClientContext, LoginCompleteRequest, LoginCompleteResponse, LoginStartRequest,
    LoginStartResponse, SessionCookie, write_cookie,
};

use crate::client::VouchClient;
use crate::commands::credential;
use crate::config::Config;
use crate::fido2::{self, YubiKey};

/// Run the login command.
/// Uses discoverable credentials - the YubiKey identifies the user.
pub async fn run(server: &str) -> Result<()> {
    // Check for existing valid session and warn
    if let Some(remaining_secs) = check_existing_session(server).await {
        let remaining = jiff::SignedDuration::from_mins((remaining_secs / 60) as i64);
        println!("Already logged in (expires in {remaining:#}). Re-authenticating...\n");
    } else {
        println!("Logging in...\n");
    }

    // Step 1: Wait for YubiKey to be inserted
    let key = YubiKey::wait_for_device()?;

    // Step 2: Start authentication with server (no email needed)
    print!("Contacting server ({server})... ");
    let client = VouchClient::new(server)?;
    let start_resp: LoginStartResponse = client
        .post("/v1/auth/login/start", &LoginStartRequest {})
        .await
        .context("failed to start login")?;
    println!("ok");

    // Step 3: Ensure PIN is configured and get it
    let pin = fido2::ensure_pin_configured(&key)?;

    // Step 4: Perform FIDO2 authentication using discoverable credential
    println!("\nTouch your YubiKey...");
    let result = key.authenticate(&start_resp.rp_id, &start_resp.challenge, &pin)?;

    // Step 5: Complete authentication with server
    let complete_resp: LoginCompleteResponse = client
        .post(
            "/v1/auth/login/complete",
            &LoginCompleteRequest {
                state: start_resp.state,
                credential_id: result.credential_id,
                authenticator_data: result.authenticator_data,
                signature: result.signature,
                client_data_json: result.client_data_json,
                user_handle: result.user_handle,
                client_context: Some(ClientContext::current()),
            },
        )
        .await
        .context("failed to complete login")?;

    // Step 6: Store session in agent (if running) and config
    // Use email from response (server identifies user from user_handle)
    let agent_stored = store_session_in_agent(&complete_resp.email, &complete_resp, server).await;

    // Also save to config as fallback
    let mut config = Config::load()?;
    config.save_token(&complete_resp.token)?;

    // Step 7: Write cookie file for CLI tools
    if let Err(e) = write_session_cookie(server, &complete_resp) {
        tracing::debug!("Failed to write cookie file: {e}");
    }

    println!("Login successful as {}!", complete_resp.email);
    println!(
        "Session expires: {}",
        format_expiry(&complete_resp.expires_at)
    );

    // Step 8: Auto-provision SSH certificate
    credential::ssh::auto_provision(server, &complete_resp.expires_at).await;

    if agent_stored {
        println!("\nYour identity is now available. Check with: vouch status");
    } else {
        println!("\nNote: Agent not running. Start it with: vouch-agent --foreground");
        println!("Your identity is stored locally. Check with: vouch status");
    }

    Ok(())
}

/// Store session in the agent (if running).
async fn store_session_in_agent(
    email: &str,
    response: &LoginCompleteResponse,
    server: &str,
) -> bool {
    match AgentClient::connect().await {
        Ok(mut agent) => {
            match agent
                .store_session(&response.token, email, &response.expires_at, Some(server))
                .await
            {
                Ok(()) => true,
                Err(e) => {
                    tracing::debug!("Failed to store session in agent: {e}");
                    false
                }
            }
        }
        Err(AgentError::NotRunning) => {
            tracing::debug!("Agent not running, session stored in config only");
            false
        }
        Err(e) => {
            tracing::debug!("Failed to connect to agent: {e}");
            false
        }
    }
}

/// Write the session cookie file for CLI tools.
fn write_session_cookie(server: &str, response: &LoginCompleteResponse) -> Result<()> {
    // Extract domain from server URL
    let url = url::Url::parse(server).context("failed to parse server URL")?;
    let domain = url
        .host_str()
        .context("server URL has no host")?
        .to_string();

    // Parse expiration time
    let expires_at: jiff::Timestamp = response
        .expires_at
        .parse()
        .context("failed to parse expiration time")?;
    let expires_unix = expires_at.as_second();

    // Create and write cookie
    let cookie = SessionCookie::new(&domain, &response.token, expires_unix);
    write_cookie(&cookie)?;

    tracing::debug!("Cookie written to ~/.vouch/cookie.txt");
    Ok(())
}

/// Format an ISO 8601 expiry timestamp as a human-readable relative time.
///
/// Example: "in 8h (2026-01-27 12:25 UTC)"
fn format_expiry(expires_at: &str) -> String {
    let Ok(ts) = expires_at.parse::<jiff::Timestamp>() else {
        return expires_at.to_string();
    };

    let secs = ts.duration_since(jiff::Timestamp::now()).as_secs().max(0);
    let remaining = jiff::SignedDuration::from_mins(secs / 60);
    let datetime = ts.strftime("%Y-%m-%d %H:%M UTC");

    format!("in {remaining:#} ({datetime})")
}

/// Check if there's an existing valid session.
///
/// Returns `Some(seconds_remaining)` if a valid session exists, `None` otherwise.
/// This is best-effort - failures are silently ignored.
async fn check_existing_session(server: &str) -> Option<u64> {
    // Try agent first
    if let Ok(mut agent) = AgentClient::connect().await
        && let Ok(session) = agent.get_session().await
    {
        return Some(session.expires_in_seconds);
    }

    // Fall back to server check
    let config = Config::load().ok()?;
    config.token()?;
    let client = VouchClient::new(server).ok()?;
    let status = client
        .get_authenticated::<vouch_common::SessionStatus>("/v1/auth/status")
        .await
        .ok()?;
    if status.authenticated {
        status.expires_in_seconds
    } else {
        None
    }
}
